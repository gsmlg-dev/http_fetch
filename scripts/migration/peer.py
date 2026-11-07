#!/usr/bin/env python3
"""aioquic 1.2.0 client and retained-socket UDP relay for the M1 traffic gate."""

import argparse
import asyncio
import hashlib
from importlib.metadata import version
import json
import math
import socket
import sys

PHASES = ("initial", "port", "ip")
PINNED_AIOQUIC = "1.2.0"
ALPN = "ex-quic-test"
CID_LENGTH = 8


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def phase_payload(label, phase):
    return f"migration/{label}/{phase}\0".encode() + bytes(range(256)) * 8


def validate_cid_bindings(backends):
    initial, port, ip = backends
    assert port["dcids"] and port["dcids"][0] in initial["dcids"], "NAT phase changed incoming CID"
    assert ip["dcids"] and ip["dcids"][0] != port["dcids"][0], "IP phase did not rotate incoming CID"
    assert all(item["server_dcids"] for item in backends), "missing outgoing destination CID observations"
    old = set(initial["server_dcids"]) | set(port["server_dcids"])
    assert set(ip["server_dcids"]).isdisjoint(old), "outgoing CID reused across IP addresses"
    phases = port["server_dcids_by_phase"]
    assert phases[2], "missing retained old-path traffic during IP migration"
    assert set(phases[2]) <= set(phases[0] + phases[1]), "old-path probe changed its outgoing CID binding"


class Receipts:
    """Acceptance follows exact application receipts, never elapsed quiet time."""

    def __init__(self, label, stream_id):
        self.label, self.stream_id = label, stream_id
        self.expected = b"".join(phase_payload(label, phase) for phase in PHASES)
        self.received = b""
        self.fin = False
        self.observed = [set() for _ in PHASES]

    def markers(self, phase):
        return [f"datagram/{self.label}/{PHASES[phase]}/{attempt}".encode()
                for attempt in range(3)]

    def stream_data(self, stream_id, data, fin):
        assert stream_id == self.stream_id, "replacement or unexpected stream"
        assert not self.fin, "stream data after FIN"
        self.received += data
        assert self.expected.startswith(self.received), "stream byte mismatch"
        if fin:
            assert self.received == self.expected, "premature FIN"
            self.fin = True

    def datagram(self, data):
        for phase in range(len(PHASES)):
            if data in self.markers(phase):
                self.observed[phase].add(data)
                return
        raise AssertionError("unexpected DATAGRAM payload")

    def phase_complete(self, phase):
        end = sum(len(phase_payload(self.label, item)) for item in PHASES[:phase + 1])
        return (len(self.received) >= end and bool(self.observed[phase])
                and (phase < len(PHASES) - 1 or self.fin))

    def proof(self):
        assert self.phase_complete(2), "missing final stream/DATAGRAM receipts"
        return {"label": self.label, "stream_id": self.stream_id,
                "bytes": len(self.received), "sha256": hashlib.sha256(self.received).hexdigest(),
                "fin": self.fin, "datagrams_sent": [3, 3, 3],
                "datagrams_observed": [len(items) for items in self.observed]}


class Backend(asyncio.DatagramProtocol):
    def __init__(self, relay, index):
        self.relay, self.index = relay, index
        self.transport = None
        self.sent = self.received = self.late_received = 0
        self.dcids = []
        self.server_dcids = []
        self.server_dcids_by_phase = [[] for _ in PHASES]

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if address != self.relay.server or self.relay.client is None:
            return
        self.received += 1
        if len(data) >= 1 + CID_LENGTH and not data[0] & 0x80:
            cid = data[1:1 + CID_LENGTH].hex()
            if cid not in self.server_dcids:
                self.server_dcids.append(cid)
            phase = self.server_dcids_by_phase[self.relay.selected]
            if cid not in phase:
                phase.append(cid)
        if self.index != self.relay.selected:
            self.late_received += 1
        # Retain every old backend: an old-path challenge still reaches the
        # client, whose PATH_RESPONSE may return through the selected new one.
        self.relay.transport.sendto(data, self.relay.client)

    def error_received(self, error):
        self.relay.errors.append(str(error))

    def proof(self):
        return {"address": list(self.transport.get_extra_info("sockname")),
                "sent": self.sent, "received": self.received,
                "received_after_switch": self.late_received, "dcids": self.dcids,
                "server_dcids": self.server_dcids,
                "server_dcids_by_phase": self.server_dcids_by_phase}


class Relay(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server
        self.transport = None
        self.client = None
        self.backends = []
        self.selected = 0
        self.errors = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if self.client is None:
            self.client = address
        if address != self.client:
            return
        backend = self.backends[self.selected]
        backend.sent += 1
        # Engine CIDs have the fixed eight-byte routing length. This observes
        # encrypted wire headers; it does not infer authentication or readiness.
        if len(data) >= 1 + CID_LENGTH and not data[0] & 0x80:
            cid = data[1:1 + CID_LENGTH].hex()
            if cid not in backend.dcids:
                backend.dcids.append(cid)
        backend.transport.sendto(data, self.server)

    def switch(self, index):
        assert 0 <= index < len(self.backends)
        self.selected = index

    def error_received(self, error):
        self.errors.append(str(error))

    def close(self):
        for backend in self.backends:
            backend.transport.close()
        if self.transport:
            self.transport.close()

    @classmethod
    async def start(cls, server):
        loop = asyncio.get_running_loop()
        relay = cls(server)
        try:
            await loop.create_datagram_endpoint(lambda: relay,
                                                local_addr=("127.0.0.1", 0),
                                                family=socket.AF_INET)
            for index, ip in enumerate(("127.0.0.1", "127.0.0.1", "127.0.0.2")):
                backend = Backend(relay, index)
                await loop.create_datagram_endpoint(lambda: backend, local_addr=(ip, 0),
                                                    family=socket.AF_INET)
                relay.backends.append(backend)
            return relay
        except BaseException:
            relay.close()
            raise


def peer_type():
    # Lazy imports keep relay/receipt controls and --help independent of aioquic.
    actual = version("aioquic")
    if actual != PINNED_AIOQUIC:
        raise RuntimeError(f"requires aioquic=={PINNED_AIOQUIC}; installed {actual}")
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.events import (ConnectionTerminated, DatagramFrameReceived,
                                    HandshakeCompleted, StreamDataReceived, StreamReset)

    class Peer(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.receipts = None
            self.handshakes = 0
            self.changed = asyncio.Event()
            self.failure = None
            self.ending = False

        def quic_event_received(self, event):
            try:
                if isinstance(event, HandshakeCompleted):
                    self.handshakes += 1
                    assert event.alpn_protocol == ALPN, "unexpected ALPN"
                    assert self.handshakes == 1, "replacement handshake"
                elif isinstance(event, StreamDataReceived):
                    assert self.receipts is not None, "unsolicited server stream"
                    self.receipts.stream_data(event.stream_id, event.data, event.end_stream)
                elif isinstance(event, DatagramFrameReceived):
                    assert self.receipts is not None, "unsolicited server DATAGRAM"
                    self.receipts.datagram(event.data)
                elif isinstance(event, StreamReset):
                    raise AssertionError("stream reset during migration")
                elif isinstance(event, ConnectionTerminated) and not self.ending:
                    raise AssertionError(f"connection terminated: {event.error_code} {event.reason_phrase}")
            except AssertionError as error:
                self.failure = str(error)
            self.changed.set()

        def bind_stream(self, label):
            self.receipts = Receipts(label, self._quic.get_next_available_stream_id(False))

        def datagram_received(self, data, address):
            super().datagram_received(data, address)
            # Receiving NEW_CONNECTION_ID need not produce an application event.
            self.changed.set()

        async def await_spare_cid(self, deadline):
            # Test-only inspection is pinned to aioquic 1.2.0. A no-op
            # change_connection_id() must never count as successful migration.
            while True:
                self.changed.clear()
                if self.failure:
                    raise AssertionError(self.failure)
                count = len(self._quic._peer_cid_available)
                if count:
                    emit("spare_cid", available=count)
                    return
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError("server supplied no spare CID before IP switch")
                await asyncio.wait_for(self.changed.wait(), remaining)

        async def phase(self, index, deadline):
            payload = phase_payload(self.receipts.label, PHASES[index])
            self._quic.send_stream_data(self.receipts.stream_id, payload,
                                        end_stream=index == len(PHASES) - 1)
            for marker in self.receipts.markers(index):
                self._quic.send_datagram_frame(marker)
            self.transmit()
            while True:
                self.changed.clear()
                if self.failure:
                    raise AssertionError(self.failure)
                if self.receipts.phase_complete(index):
                    break
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError(f"{self.receipts.label} {PHASES[index]} receipts missing")
                await asyncio.wait_for(self.changed.wait(), remaining)
            emit("phase", label=self.receipts.label, phase=PHASES[index],
                 stream_id=self.receipts.stream_id, received_bytes=len(self.receipts.received),
                 fin=self.receipts.fin,
                 datagrams_observed=len(self.receipts.observed[index]))

    return Peer


async def exercise(args):
    Peer = peer_type()
    from aioquic.asyncio.client import connect
    from aioquic.quic.configuration import QuicConfiguration

    def configuration():
        config = QuicConfiguration(is_client=True, alpn_protocols=[ALPN],
                                   connection_id_length=CID_LENGTH,
                                   max_datagram_frame_size=1200, max_datagram_size=1200)
        config.server_name = "example.test"
        config.load_verify_locations(cafile=args.ca)
        return config

    relay = await Relay.start((args.host, args.port))
    deadline = asyncio.get_running_loop().time() + args.timeout
    input_transport = None
    try:
        front = relay.transport.get_extra_info("sockname")
        emit("relay_ready", backends=[list(backend.transport.get_extra_info("sockname"))
                                      for backend in relay.backends], frontend=list(front))
        if args.controlled:
            commands = asyncio.StreamReader()
            input_transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(commands), sys.stdin)
        async with connect(front[0], front[1], configuration=configuration(),
                           create_protocol=Peer) as migrating:
            async with connect(args.host, args.port, configuration=configuration(),
                               create_protocol=Peer) as control:
                migrating.bind_stream("migrating")
                control.bind_stream("control")
                for index in range(len(PHASES)):
                    if index == 2:
                        await migrating.await_spare_cid(deadline)
                    relay.switch(index)
                    emit("path_switch", phase=PHASES[index],
                         address=list(relay.backends[index].transport.get_extra_info("sockname")))
                    if index == 2:
                        # Port-only rebinding retains the CID. The IP phase also
                        # exercises use of a newly supplied server CID.
                        migrating.change_connection_id()
                    await migrating.phase(index, deadline)
                    await control.phase(index, deadline)
                    if args.controlled:
                        command = await asyncio.wait_for(commands.readline(),
                                                         max(0.001, deadline - asyncio.get_running_loop().time()))
                        assert command == b"continue\n", "missing gate path-validation approval"
                assert migrating.handshakes == control.handshakes == 1
                connections = [peer.receipts.proof() | {"handshakes": peer.handshakes}
                               for peer in (migrating, control)]
                migrating.ending = control.ending = True
        backends = [backend.proof() for backend in relay.backends]
        assert all(item["sent"] > 0 and item["received"] > 0 for item in backends)
        assert backends[0]["address"][0] == backends[1]["address"][0] == "127.0.0.1"
        assert backends[0]["address"][1] != backends[1]["address"][1]
        assert backends[2]["address"][0] == "127.0.0.2"
        validate_cid_bindings(backends)
        assert not relay.errors, relay.errors
        return {"connections": connections, "backends": backends,
                "retained_backend_sockets": len(backends), "frontend": list(front),
                "same_stream_across_phases": True}
    finally:
        if input_transport:
            input_transport.close()
        relay.close()


def positive_timeout(value):
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("a finite positive timeout is required")
    return parsed


async def main(args):
    try:
        proof = await asyncio.wait_for(exercise(args), args.timeout)
    except Exception as error:
        emit("result", passed=False, peer_version=PINNED_AIOQUIC,
             reason=f"{type(error).__name__}: {error}")
        return 1
    emit("result", passed=True, peer_version=PINNED_AIOQUIC, proof=proof)
    return 0


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("the acceptance peer requires Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--timeout", type=positive_timeout, default=30)
    parser.add_argument("--controlled", action="store_true",
                        help="wait for gate stdin approval after each phase")
    arguments = parser.parse_args()
    if not 1 <= arguments.port <= 65535:
        parser.error("port must be between 1 and 65535")
    raise SystemExit(asyncio.run(main(arguments)))

#!/usr/bin/env python3
"""Pinned aioquic 1.2.0 stream peer for the Phase 1 acceptance harness.

This is a test peer, never a production fallback. It uses ``phase1-streams``
as a dedicated ALPN and writes JSON observations only; it does not log keys.
"""
import argparse
import asyncio
import hashlib
import json
import os
import random
import struct
import time

from aioquic import tls

from aioquic.asyncio import serve
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamDataReceived, StreamReset

ALPN = "phase1-streams"
DEADLINE_SECONDS = 15
CHUNK_SIZE = 16384
STREAM_BYTES = 262144


def emit(event, **fields):
    print(json.dumps({"event": event, "at_ns": time.monotonic_ns(), **fields}), flush=True)


class Impairment:
    """One post-handshake drop, duplicate, and reorder in each direction."""

    def __init__(self, scenario, seed):
        self.enabled = scenario == "impaired"
        self.rng = random.Random(seed)
        self.seed = seed
        self.next_action = 0
        self.actions = [(action, direction) for action in range(3) for direction in ("send", "receive")]
        self.rng.shuffle(self.actions)
        self.counters = {"drop": 0, "duplicate": 0, "reorder": 0, "reorder_timeout": 0}
        self.active = False
        self.held = None
        self.held_timer = None

    def activate(self):
        self.active = self.enabled

    def route(self, direction, data, addr, deliver):
        if self.held is not None:
            if direction == self.held[0]:
                self.finish_reorder(data, addr, deliver)
            else:
                deliver(data, addr)
            return
        if not data or (data[0] & 0x80) or len(data) <= 512:
            deliver(data, addr)
            return
        if not self.active or self.next_action == len(self.actions) or direction != self.actions[self.next_action][1]:
            deliver(data, addr)
            return

        action = self.actions[self.next_action][0]
        self.next_action += 1
        if action == 0:
            self.counters["drop"] += 1
            emit("impairment", action="drop", direction=direction, packet_bytes=len(data))
            return
        if action == 1:
            self.counters["duplicate"] += 1
            emit("impairment", action="duplicate", direction=direction, packet_bytes=len(data))
            deliver(data, addr)
            deliver(data, addr)
            return

        self.held = (direction, data, addr, deliver)
        self.held_timer = asyncio.get_running_loop().call_later(0.5, self.release_held)
        self.counters["reorder"] += 1
        emit("impairment", action="reorder_hold", direction=direction, packet_bytes=len(data))

    def release_held(self):
        if self.held is None:
            return
        _direction, data, addr, deliver = self.held
        self.held = None
        self.held_timer = None
        self.counters["reorder_timeout"] += 1
        emit("impairment", action="reorder_timeout")
        deliver(data, addr)

    def finish_reorder(self, data, addr, deliver):
        _direction, held_data, held_addr, held_deliver = self.held
        self.held = None
        self.held_timer.cancel()
        self.held_timer = None
        emit("impairment", action="reorder_release")
        deliver(data, addr)
        held_deliver(held_data, held_addr)

    def complete(self):
        return (not self.enabled or
                self.counters == {"drop": 2, "duplicate": 2, "reorder": 2, "reorder_timeout": 0})


class ImpairedTransport:
    def __init__(self, transport, impairment):
        self.transport = transport
        self.impairment = impairment

    def sendto(self, data, addr=None):
        self.impairment.route("send", data, addr, self.transport.sendto)

    def __getattr__(self, name):
        return getattr(self.transport, name)


def payload(stream_id):
    return b"".join(struct.pack("!II", stream_id, index) for index in range(STREAM_BYTES // 8))


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, initiator=False, impairment=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.initiator = initiator
        self.impairment = impairment
        self.handshake = False
        self.received = {}
        self.cancelled = False
        self.max_received = 0
        self.finals = set()
        self.resets = set()
        self.expected = {}
        self.digests = {}
        self.started = False
        self.summarized = False
        self.ticket_sent = False
        self.local_uni_finished = False

    def connection_made(self, transport):
        if self.impairment is not None:
            transport = ImpairedTransport(transport, self.impairment)
        super().connection_made(transport)

    def datagram_received(self, data, addr):
        if self.impairment is None:
            super().datagram_received(data, addr)
            return
        if self.impairment.held is not None and self.impairment.next_action == 3:
            self.impairment.finish_reorder(data, addr, self._deliver_datagram)
            return
        self.impairment.route("receive", data, addr, self._deliver_datagram)

    def _deliver_datagram(self, data, addr):
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = True
            emit("handshake", alpn=event.alpn_protocol)
            if not self.initiator:
                self.send_test_ticket()
            self.start_matrix()
        elif isinstance(event, StreamDataReceived):
            self.received[event.stream_id] = self.received.get(event.stream_id, 0) + len(event.data)
            self.digests.setdefault(event.stream_id, hashlib.sha256()).update(event.data)
            self.max_received = max(self.max_received, sum(self.received.values()))
            if event.end_stream:
                self.finals.add(event.stream_id)
                emit("stream_fin", stream_id=event.stream_id, bytes=self.received[event.stream_id])
            # A peer-initiated unidirectional stream has no return direction.
            local_bit = 0 if self.initiator else 1
            if (event.data or event.end_stream) and (event.stream_id & 0x01) != local_bit and (event.stream_id & 0x02) == 0:
                self._quic.send_stream_data(event.stream_id, event.data, end_stream=event.end_stream)
                self.transmit()
            self.maybe_finish_unidirectional()
            self.maybe_summary()
        elif isinstance(event, StreamReset):
            self.resets.add(event.stream_id)
            emit("stream_reset", stream_id=event.stream_id, code=event.error_code)
            self.maybe_summary()
        elif isinstance(event, ConnectionTerminated):
            emit("terminated", code=event.error_code, reason=event.reason_phrase)

    def send_test_ticket(self):
        """Emit one valid post-handshake ticket for the ex_quic client test."""
        if self.ticket_sent:
            return
        ticket = tls.NewSessionTicket(
            ticket_lifetime=86400,
            ticket_age_add=int.from_bytes(os.urandom(4), "big"),
            ticket_nonce=os.urandom(8),
            ticket=os.urandom(64),
        )
        buffer = self._quic._crypto_buffers[tls.Epoch.ONE_RTT]
        tls.push_new_session_ticket(buffer, ticket)
        self._quic._push_crypto_data()
        self.ticket_sent = True
        self.transmit()
        emit("session_ticket_sent", bytes=len(ticket.ticket), lifetime=ticket.ticket_lifetime)

    def start_matrix(self):
        if self.started:
            return
        self.started = True
        if self.impairment is not None:
            self.impairment.activate()
        # Four bidirectional 256KiB streams: sixteen 16KiB writes each.
        for _ in range(4):
            stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
            value = payload(stream_id)
            self.expected[stream_id] = value
            for sequence in range(16):
                chunk = value[sequence * CHUNK_SIZE:(sequence + 1) * CHUNK_SIZE]
                self._quic.send_stream_data(stream_id, chunk, end_stream=sequence == 15)
        for _ in range(3):
            stream_id = self._quic.get_next_available_stream_id(is_unidirectional=True)
            value = ("uni:%d" % stream_id).encode()
            self.expected[stream_id] = value
            self._quic.send_stream_data(stream_id, value, end_stream=False)
        # One stream is cancelled without affecting the preceding streams.
        cancelled = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._quic.send_stream_data(cancelled, b"cancel", end_stream=False)
        self._quic.reset_stream(cancelled, 0x51)
        self.cancelled = True
        self.transmit()
        emit("matrix_sent", bidi=4, uni=3, write_bytes=CHUNK_SIZE, cumulative_bidi=1048576,
             cancelled=cancelled)

    def maybe_finish_unidirectional(self):
        if self.local_uni_finished:
            return
        local_bit = 0 if self.initiator else 1
        local_uni = [stream_id for stream_id in self.expected if (stream_id & 3) == (local_bit | 2)]
        remote_uni = [stream_id for stream_id in self.received if (stream_id & 1) != local_bit and (stream_id & 2) != 0]
        remote_payloads_received = len(remote_uni) == 3 and all(
            self.received[stream_id] >= len(("uni:%d" % stream_id).encode())
            for stream_id in remote_uni
        )
        if not remote_payloads_received:
            return
        for stream_id in local_uni:
            self._quic.send_stream_data(stream_id, b"", end_stream=True)
        self.local_uni_finished = True
        self.transmit()
        emit("uni_fin_barrier", local_uni=sorted(local_uni), remote_uni=sorted(remote_uni))

    def maybe_summary(self):
        if self.summarized or len(self.finals) < 11 or not self.resets:
            return
        local_bit = 0 if self.initiator else 1
        normal_bidi = [stream_id for stream_id in self.expected if (stream_id & 3) == local_bit]
        local_uni = [stream_id for stream_id in self.expected if (stream_id & 3) == (local_bit | 2)]
        echoed = all(stream_id in self.finals and self.digests[stream_id].digest() == hashlib.sha256(self.expected[stream_id]).digest() for stream_id in normal_bidi)
        remote_bidi = [stream_id for stream_id in self.received if (stream_id & 1) != local_bit and (stream_id & 2) == 0 and stream_id < 16]
        remote_uni = [stream_id for stream_id in self.received if (stream_id & 1) != local_bit and (stream_id & 2) != 0]
        remote_fin = all(stream_id in self.finals for stream_id in remote_bidi + remote_uni)
        remote_valid = all(
            self.digests[stream_id].digest() == hashlib.sha256(
                payload(stream_id) if stream_id in remote_bidi else ("uni:%d" % stream_id).encode()
            ).digest()
            for stream_id in remote_bidi + remote_uni
        )

        complete_impairment = self.impairment is None or self.impairment.complete()
        if not self.summarized and len(normal_bidi) == 4 and len(local_uni) == 3 and echoed and len(remote_bidi) == 4 and len(remote_uni) == 3 and remote_fin and remote_valid and (16 + (1 - local_bit)) in self.resets and complete_impairment:
            self.summarized = True
            digest = hashlib.sha256()
            for stream_id in sorted(normal_bidi):
                digest.update(self.expected[stream_id])
            emit("summary", role="peer", passed=True, bidi=8, uni=3, checksum=digest.hexdigest(),
                 highwater=self.max_received, cancelled=self.cancelled, resets=len(self.resets),
                 impairment=(self.impairment.counters if self.impairment is not None else None))


async def client(args):
    ticket_state = {"received": 0}

    def session_ticket_received(ticket):
        ticket_state["received"] += 1
        emit("session_ticket_received", lifetime=ticket.not_valid_after.isoformat())

    impairment = Impairment(args.scenario, args.seed)
    configuration = QuicConfiguration(is_client=True, alpn_protocols=[ALPN], max_data=CHUNK_SIZE, max_stream_data=CHUNK_SIZE)
    configuration.server_name = args.hostname
    configuration.load_verify_locations(args.ca)
    async with connect("127.0.0.1", args.port, configuration=configuration,
                       create_protocol=lambda *a, **k: Peer(*a, initiator=True, impairment=impairment, **k),
                       session_ticket_handler=session_ticket_received, wait_connected=False) as protocol:
        protocol.transmit()
        await asyncio.sleep(DEADLINE_SECONDS)
        emit("peer_exit", role="client", handshake=protocol.handshake,
             received_bytes=sum(protocol.received.values()), highwater=protocol.max_received,
             ticket_received=ticket_state["received"], impairment=impairment.counters)


async def server(args):
    impairment = Impairment(args.scenario, args.seed)

    def session_ticket_issued(ticket):
        emit("session_ticket_issued", lifetime=ticket.not_valid_after.isoformat())

    configuration = QuicConfiguration(is_client=False, alpn_protocols=[ALPN], max_data=CHUNK_SIZE, max_stream_data=CHUNK_SIZE)
    configuration.load_cert_chain(args.cert, args.key)
    server = await serve("127.0.0.1", args.port, configuration=configuration,
                         create_protocol=lambda *a, **k: Peer(*a, initiator=False, impairment=impairment, **k),
                         session_ticket_handler=session_ticket_issued)
    port = server._transport.get_extra_info("sockname")[1]
    emit("listening", port=port, alpn=ALPN)
    await asyncio.sleep(DEADLINE_SECONDS)
    server.close()


parser = argparse.ArgumentParser()
parser.add_argument("--role", choices=["client", "server"], required=True)
parser.add_argument("--port", type=int, default=0)
parser.add_argument("--ca")
parser.add_argument("--cert")
parser.add_argument("--key")
parser.add_argument("--hostname", default="example.test")
parser.add_argument("--scenario", choices=["baseline", "impaired"], default="baseline")
parser.add_argument("--seed", type=int, default=28092026)
args = parser.parse_args()

if args.role == "client" and not args.ca:
    parser.error("--ca is required for client mode")
if args.role == "server" and (not args.cert or not args.key):
    parser.error("--cert and --key are required for server mode")

asyncio.run(client(args) if args.role == "client" else server(args))

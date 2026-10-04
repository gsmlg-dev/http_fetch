#!/usr/bin/env python3
"""Pinned independent QUIC peer. Never disables certificate verification.

Capture JSONL records exact UDP payloads at the transport boundary, not TLS
secrets. Addresses and monotonic times identify each direction. This is not a
kernel/pcap capture and includes packets before decryption.
"""
import argparse
import asyncio
import base64
import json
import sys
import time

import aioquic
from aioquic.buffer import Buffer
from aioquic.quic.packet import pull_quic_header, pull_ack_frame, QuicPacketType
from aioquic.tls import Epoch
from aioquic.quic.crypto import CryptoError, KeyUnavailableError
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, ConnectionTerminated


def emit(**fields):
    print(json.dumps(fields), flush=True)


class Capture:
    def __init__(self, path, mode, scenario):
        self.file = open(path, "w")
        self.mode, self.scenario = mode, scenario
        self.applied = False
        self.connections = []
        self.held = None
        self.hold_timer = None

    def route(self, direction, data, addr, deliver):
        self.packet(direction, data, addr)
        if self.held and direction == self.held[0]:
            _, old, old_addr, old_deliver = self.held
            self.held = None
            self.hold_timer.cancel()
            self.output(direction, data, addr, deliver)
            self.output(direction, old, old_addr, old_deliver)
            emit(event="impairment", action="reorder", direction=direction)
            return
        sender = self.mode if direction == "send" else ("client" if self.mode == "server" else "server")
        packets = []
        try:
            buf = Buffer(data=data)
            while not buf.eof():
                start = buf.tell()
                header = pull_quic_header(buf, host_cid_length=8)
                end = start + header.packet_length
                packets.append((header.packet_type, end))
                buf.seek(end)
        except ValueError:
            pass
        initial = sender == "client" and any(t == QuicPacketType.INITIAL for t, _ in packets)
        handshake = sender == "server" and any(t == QuicPacketType.HANDSHAKE for t, _ in packets)
        if self.scenario == "drop_handshake_done":
            target = sender == "server" and self.handshake_done(data, direction)
        else:
            target = initial if self.scenario == "drop_initial" else handshake
        if not self.applied and target and self.scenario != "baseline":
            self.applied = True
            action = self.scenario
            if action == "reorder":
                self.held = (direction, data, addr, deliver)
                self.hold_timer = asyncio.get_running_loop().call_later(1.0, self.release)
                return
            emit(event="impairment", action=action, direction=direction,
                 packet_types=[t.name for t, _ in packets])
            if action in ("drop_initial", "drop_handshake", "drop_handshake_done"):
                return
            if action == "duplicate":
                self.output(direction, data, addr, deliver)
            if action == "corrupt":
                end = next(end for t, end in packets if t == QuicPacketType.HANDSHAKE)
                data = data[:end-1] + bytes([data[end-1] ^ 1]) + data[end:]
        self.output(direction, data, addr, deliver)

    def handshake_done(self, data, direction):
        # Test-only inspection through the pinned independent peer. Decrypt is
        # read-only; do not log keys or plaintext and do not feed a dropped packet.
        for connection in self.connections:
            try:
                buf = Buffer(data=data)
                while not buf.eof():
                    start = buf.tell()
                    header = pull_quic_header(buf, host_cid_length=8)
                    end = start + header.packet_length
                    if header.packet_type == QuicPacketType.ONE_RTT:
                        pair = connection._cryptos[Epoch.ONE_RTT]
                        crypto = pair.send if direction == "send" else pair.recv
                        expected = (connection._packet_number if direction == "send" else
                                    connection._spaces[Epoch.ONE_RTT].expected_packet_number)
                        _, payload, _, changed = crypto.decrypt_packet(data[start:end], buf.tell()-start, expected)
                        if changed:
                            return False
                        frames = Buffer(data=payload)
                        while not frames.eof():
                            kind = frames.pull_uint_var()
                            if kind == 0x1E:
                                return True
                            if kind in (0, 1):
                                continue
                            if kind in (2, 3):
                                pull_ack_frame(frames)
                                if kind == 3:
                                    for _ in range(3):
                                        frames.pull_uint_var()
                            elif kind == 0x18:
                                frames.pull_uint_var()
                                frames.pull_uint_var()
                                frames.pull_bytes(frames.pull_uint8() + 16)
                            elif kind == 0x19:
                                frames.pull_uint_var()
                            else:
                                break
                    buf.seek(end)
            except (ValueError, CryptoError, KeyUnavailableError):
                continue
        return False

    def output(self, direction, data, addr, deliver):
        self.packet("wire_send" if direction == "send" else "protocol_receive", data, addr)
        deliver(data, addr)

    def release(self):
        if self.held:
            direction, data, addr, deliver = self.held
            self.held = None
            emit(event="reorder_timeout", direction=direction)
            self.output(direction, data, addr, deliver)

    def packet(self, direction, data, peer):
        if data and data[0] & 0xF0 == 0xF0:
            emit(event="retry", direction=direction)
        self.file.write(json.dumps(dict(time_ns=time.monotonic_ns(), direction=direction,
            peer=peer, payload=base64.b64encode(data).decode())) + "\n")
        self.file.flush()


class Transport:
    def __init__(self, transport, capture):
        self.transport, self.capture = transport, capture

    def sendto(self, data, addr=None):
        return self.capture.route("send", data, addr, self.transport.sendto)

    def __getattr__(self, name):
        return getattr(self.transport, name)


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, capture=None, inspection=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.capture = capture
        self.confirmation_reported = False
        if inspection or capture:
            (inspection or capture).connections.append(self._quic)

    def connection_made(self, transport):
        super().connection_made(Transport(transport, self.capture) if self.capture else transport)

    def datagram_received(self, data, addr):
        if self.capture:
            self.capture.route("receive", data, addr, self.receive_delivered)
        else:
            self.receive_delivered(data, addr)

    def receive_delivered(self, data, addr):
        super().datagram_received(data, addr)
        if self._quic._handshake_confirmed and not self.confirmation_reported:
            self.confirmation_reported = True
            emit(event="quic_confirmed")

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            emit(event="handshake_complete", alpn=event.alpn_protocol)
        elif isinstance(event, ConnectionTerminated):
            emit(event="terminated", error_code=event.error_code, reason=event.reason_phrase)
        super().quic_event_received(event)


class Server(QuicServer):
    def __init__(self, *args, capture, **kwargs):
        super().__init__(*args, **kwargs)
        self.capture = capture

    def connection_made(self, transport):
        super().connection_made(Transport(transport, self.capture))

    def datagram_received(self, data, addr):
        self.capture.route("receive", data, addr, super().datagram_received)


async def main(args):
    emit(event="version", aioquic=aioquic.__version__, python=sys.version.split()[0])
    capture = Capture(args.capture, args.mode, args.scenario)
    config = QuicConfiguration(is_client=args.mode == "client", alpn_protocols=[args.alpn])
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_reader(sys.stdin.fileno(), lambda: (sys.stdin.readline(), stop.set()))
    loop.call_later(args.timeout, stop.set)
    if args.mode == "server":
        config.load_cert_chain(args.cert, args.key)
        transport, server = await loop.create_datagram_endpoint(
            lambda: Server(configuration=config, create_protocol=lambda *a, **kw: Peer(*a, inspection=capture, **kw),
                           retry=args.retry, capture=capture),
            local_addr=("127.0.0.1", args.port))
        emit(event="listening", port=transport.get_extra_info("sockname")[1])
        await stop.wait()
        server.close()
    else:
        config.server_name = args.hostname
        config.load_verify_locations(cafile=args.ca)
        async with connect("127.0.0.1", args.port, configuration=config,
                           create_protocol=lambda *a, **kw: Peer(*a, capture=capture, **kw),
                           wait_connected=False) as peer:
            peer.transmit()
            emit(event="started")
            await stop.wait()
    capture.file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["client", "server"], required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--ca")
    parser.add_argument("--hostname", default="example.test")
    parser.add_argument("--alpn", default="ex-quic-test")
    parser.add_argument("--retry", action="store_true")
    parser.add_argument("--scenario", default="baseline", choices=["baseline", "drop_initial", "drop_handshake", "reorder", "duplicate", "corrupt", "drop_handshake_done"])
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--capture", required=True)
    asyncio.run(main(parser.parse_args()))

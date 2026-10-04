#!/usr/bin/env python3
"""Independent aioquic 1.2.0 h3 ALPN / RFC 9221 DATAGRAM peer."""
import argparse
import asyncio
from collections import Counter
import json

from aioquic.asyncio import serve
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    HandshakeCompleted,
    StreamDataReceived,
)

PEER_DATAGRAM = b"aioquic-datagram-h3"
PEER_STREAM = b"aioquic-stream-h3"
ENGINE_DATAGRAM = b"elixir-datagram-h3"
ENGINE_STREAM = b"elixir-stream-h3"
PEER_BOUNDARY = bytes([0xBC]) * 1100
COMPLETE = b"elixir-complete-h3"


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake = False
        self.datagrams = []
        self.streams = {}
        self.stream_fins = set()
        self.verified = False
        self.finished = asyncio.get_running_loop().create_future()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = event.alpn_protocol == "h3"
            emit("handshake", alpn=event.alpn_protocol)
            if self.handshake:
                for payload in (b"", PEER_DATAGRAM, PEER_DATAGRAM, PEER_BOUNDARY):
                    self._quic.send_datagram_frame(payload)
                stream_id = self._quic.get_next_available_stream_id(False)
                self._quic.send_stream_data(stream_id, PEER_STREAM, end_stream=True)
                self.transmit()
        elif isinstance(event, DatagramFrameReceived):
            if event.data == COMPLETE:
                if self.verified and not self.finished.done():
                    self.finished.set_result(True)
            else:
                self.datagrams.append(event.data)
                self.check_complete()
        elif isinstance(event, StreamDataReceived):
            self.streams[event.stream_id] = self.streams.get(event.stream_id, b"") + event.data
            if event.end_stream:
                self.stream_fins.add(event.stream_id)
            self.check_complete()
        elif isinstance(event, ConnectionTerminated):
            if not self.finished.done():
                self.finished.set_result(False)

    def check_complete(self):
        boundary = [data for data in self.datagrams if data and set(data) == {0xAB}]
        ordinary = Counter(self.datagrams) - Counter(boundary)
        if (self.handshake and len(self.datagrams) == 4 and len(boundary) == 1
                and len(boundary[0]) >= 1000
                and ordinary == Counter([b"", ENGINE_DATAGRAM, ENGINE_DATAGRAM])
                and list(self.streams.values()) == [ENGINE_STREAM]
                and self.stream_fins == set(self.streams)
                and not self.verified):
            self.verified = True
            emit("verified", datagrams=4, streams=1, boundary_bytes=len(boundary[0]))


async def client(args):
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], max_datagram_frame_size=1200)
    config.server_name = "example.test"
    config.load_verify_locations(cafile=args.ca)
    async with connect("127.0.0.1", args.port, configuration=config,
                       create_protocol=Peer, wait_connected=True) as peer:
        await asyncio.wait_for(peer.finished, args.timeout)
        return peer.finished.result()


async def server(args):
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], max_datagram_frame_size=1200)
    config.load_cert_chain(args.cert, args.key)
    accepted = asyncio.get_running_loop().create_future()

    def create_protocol(*protocol_args, **protocol_kwargs):
        peer = Peer(*protocol_args, **protocol_kwargs)
        if not accepted.done():
            accepted.set_result(peer)
        return peer

    listener = await serve("127.0.0.1", 0, configuration=config, create_protocol=create_protocol)
    emit("listening", port=listener._transport.get_extra_info("sockname")[1])
    try:
        peer = await asyncio.wait_for(accepted, args.timeout)
        await asyncio.wait_for(peer.finished, args.timeout)
        return peer.finished.result()
    finally:
        listener.close()


async def main(args):
    try:
        passed = await (client(args) if args.role == "client" else server(args))
    except Exception as error:
        emit("failure", reason=type(error).__name__)
        passed = False
    emit("result", passed=passed, role=args.role)
    if not passed:
        raise SystemExit(1)


parser = argparse.ArgumentParser()
parser.add_argument("--role", choices=["client", "server"], required=True)
parser.add_argument("--port", type=int)
parser.add_argument("--ca")
parser.add_argument("--cert")
parser.add_argument("--key")
parser.add_argument("--timeout", type=float, default=10)
asyncio.run(main(parser.parse_args()))

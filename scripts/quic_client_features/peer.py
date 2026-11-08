#!/usr/bin/env python3
"""Independent aioquic 1.2.0 QUIC echo server; application receipts expose paths."""
import argparse
import asyncio
import hashlib
import json
from importlib.metadata import version
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, DatagramFrameReceived


def emit(**values):
    print(json.dumps(values), flush=True)


class Echo(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.payload = b""
        self.handshakes = 0
        self.paths = []

    def datagram_received(self, data, addr):
        if addr not in self.paths:
            self.paths.append(addr)
            emit(event="path", address=addr)
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshakes += 1
            emit(event="handshake", count=self.handshakes, alpn=event.alpn_protocol)
        elif isinstance(event, StreamDataReceived):
            self.payload += event.data
            self._quic.send_stream_data(event.stream_id, event.data, event.end_stream)
            emit(event="stream", stream=event.stream_id, bytes=len(self.payload),
                 sha256=hashlib.sha256(self.payload).hexdigest(), fin=event.end_stream,
                 paths=self.paths, handshakes=self.handshakes)
        elif isinstance(event, DatagramFrameReceived):
            self._quic.send_datagram_frame(event.data)
        self.transmit()


async def main(args):
    assert version("aioquic") == "1.2.0"
    config = QuicConfiguration(is_client=False, alpn_protocols=["ex-quic-m2"],
                               max_datagram_frame_size=1200, connection_id_length=8)
    config.load_cert_chain(args.cert, args.key)
    server = await serve("127.0.0.1", args.port, configuration=config, create_protocol=Echo)
    emit(event="listening", port=server._transport.get_extra_info("sockname")[1], peer="aioquic-1.2.0")
    try:
        await asyncio.sleep(args.timeout)
    finally:
        server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=45)
    asyncio.run(main(parser.parse_args()))

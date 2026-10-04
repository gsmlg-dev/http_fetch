#!/usr/bin/env python3
"""Independent aioquic client that sends two FIN-terminated streams."""
import argparse
import asyncio
import json

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived


class StreamClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake = False

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake = True
            print(json.dumps({"event": "handshake"}), flush=True)
            for payload in (b"independent-stream-one", b"independent-stream-two"):
                stream_id = self._quic.get_next_available_stream_id(False)
                self._quic.send_stream_data(stream_id, payload, end_stream=True)
            self.transmit()
        elif isinstance(event, StreamDataReceived):
            print(json.dumps({"event": "stream_received", "id": event.stream_id}), flush=True)
        elif isinstance(event, ConnectionTerminated):
            print(json.dumps({"event": "terminated", "code": event.error_code, "reason": event.reason_phrase}), flush=True)
        super().quic_event_received(event)


async def main(args):
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["ex-quic-test"])
    configuration.server_name = "example.test"
    configuration.load_verify_locations(cafile=args.ca)
    async with connect(
        "127.0.0.1",
        args.port,
        configuration=configuration,
        create_protocol=StreamClient,
        wait_connected=False,
    ) as peer:
        peer.transmit()
        await asyncio.sleep(args.timeout)
    print(json.dumps({"passed": peer.handshake, "streams": 2}), flush=True)


parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--ca", required=True)
parser.add_argument("--timeout", type=float, default=2.0)
asyncio.run(main(parser.parse_args()))

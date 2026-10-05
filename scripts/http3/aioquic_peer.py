"""Independent HTTP/3 echo peer. Run with pinned aioquic==1.2.0."""

import argparse
import asyncio

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class Peer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.bodies = {}

    def quic_event_received(self, event):
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                self.bodies[item.stream_id] = bytearray()
            elif isinstance(item, DataReceived):
                self.bodies[item.stream_id].extend(item.data)
            if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_ended:
                body = bytes(self.bodies.pop(item.stream_id)) or b"aioquic HTTP/3"
                self.http.send_headers(item.stream_id, [
                    (b":status", b"200"),
                    (b"content-length", str(len(body)).encode()),
                    (b"x-peer", b"aioquic-1.2.0"),
                ])
                self.http.send_data(item.stream_id, body, end_stream=True)
                self.transmit()


async def main(args):
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    config.load_cert_chain(args.cert, args.key)
    peer = await serve("127.0.0.1", args.port, configuration=config, create_protocol=Peer)
    print(peer._transport.get_extra_info("sockname")[1], flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("--port", type=int, default=0)
    asyncio.run(main(parser.parse_args()))

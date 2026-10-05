"""Independent HTTP/3 echo peer. Run with pinned aioquic==1.2.0."""

import argparse
import asyncio
import hashlib
import itertools

from aioquic.buffer import encode_uint_var
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset


class Peer(QuicConnectionProtocol):
    identities = itertools.count(1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.bodies = {}
        self.headers = {}
        self.identity = next(self.identities)

    def quic_event_received(self, event):
        if isinstance(event, StreamReset):
            self.bodies.pop(event.stream_id, None)
            self.headers.pop(event.stream_id, None)
        elif isinstance(event, ConnectionTerminated):
            self.bodies.clear()
            self.headers.clear()
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                self.bodies[item.stream_id] = bytearray()
                self.headers[item.stream_id] = dict(item.headers)
                path = self.headers[item.stream_id].get(b":path", b"/")
                if path == b"/early":
                    self.respond(item.stream_id, b"early", status=b"413")
                    self._quic.stop_stream(item.stream_id, 0x10C)
                    self.bodies.pop(item.stream_id, None)
                    self.headers.pop(item.stream_id, None)
                    self.transmit()
                    continue
                if path == b"/reset":
                    self._quic.reset_stream(item.stream_id, 0x10C)
                    self.bodies.pop(item.stream_id, None)
                    self.headers.pop(item.stream_id, None)
                    self.transmit()
                    continue
            elif isinstance(item, DataReceived):
                if item.stream_id not in self.bodies:
                    continue
                self.bodies[item.stream_id].extend(item.data)
            if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_ended:
                fields = self.headers.pop(item.stream_id)
                path = fields.get(b":path", b"/")
                body = bytes(self.bodies.pop(item.stream_id))
                if path == b"/hold":
                    continue
                if path == b"/empty":
                    body = b""
                elif path == b"/digest":
                    body = hashlib.sha256(body).hexdigest().encode()
                elif path == b"/large":
                    body = bytes(range(256)) * 32768
                elif path == b"/sse":
                    body = b"id: 42\ndata: h3-event\n\n"
                elif path == b"/trailers":
                    body = b"abc"
                else:
                    body = body or b"aioquic HTTP/3"
                if path == b"/informational":
                    # aioquic 1.2.0's high-level send_headers treats a second block
                    # as trailers. Encode the informational block with its QPACK
                    # implementation without advancing the final-response state.
                    block = self.http._encode_headers(item.stream_id, [(b":status", b"103"), (b"link", b"</style.css>; rel=preload")])
                    self._quic.send_stream_data(item.stream_id,
                                               encode_uint_var(1) + encode_uint_var(len(block)) + block)
                self.respond(item.stream_id, body, path=path,
                             head=fields.get(b":method") == b"HEAD")
                if path == b"/goaway":
                    payload = encode_uint_var(item.stream_id + 4)
                    self._quic.send_stream_data(self.http._local_control_stream_id,
                                                encode_uint_var(7) + encode_uint_var(len(payload)) + payload)
                    self.transmit()

    def respond(self, stream, body, *, status=b"200", path=b"/", head=False):
        fields = [(b":status", status), (b"content-length", str(len(body)).encode()),
                  (b"x-peer", b"aioquic-1.2.0"), (b"x-connection", str(self.identity).encode())]
        if path == b"/sse":
            fields.append((b"content-type", b"text/event-stream"))
        self.http.send_headers(stream, fields)
        trailers = path == b"/trailers"
        self.http.send_data(stream, b"" if head else body, end_stream=not trailers)
        if trailers:
            self.http.send_headers(stream, [(b"x-checksum", hashlib.sha256(body).hexdigest().encode())], end_stream=True)
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

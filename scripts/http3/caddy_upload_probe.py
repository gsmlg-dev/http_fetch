"""Independent client regression for unknown-length HTTP/3 request forwarding."""
import asyncio
import hashlib
import os

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.result = None
        self.body = bytearray()
        self.status = None

    def quic_event_received(self, event):
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                self.status = dict(item.headers).get(b":status", self.status)
            elif isinstance(item, DataReceived):
                self.body.extend(item.data)
                if len(self.body) > 1024:
                    self.result.set_exception(RuntimeError("Caddy digest response exceeds bound"))
            if (isinstance(item, (HeadersReceived, DataReceived)) and item.stream_ended
                    and self.result is not None and not self.result.done()):
                self.result.set_result((self.status, bytes(self.body)))

    async def digest(self, payload, known_length):
        self.result = asyncio.get_running_loop().create_future()
        stream = self._quic.get_next_available_stream_id()
        fields = [(b":method", b"POST"), (b":scheme", b"https"),
                  (b":authority", b"example.test"), (b":path", b"/digest"),
                  (b"content-type", b"application/octet-stream")]
        if known_length:
            fields.append((b"content-length", str(len(payload)).encode()))
        self.http.send_headers(stream, fields, end_stream=False)
        self.http.send_data(stream, payload, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self.result, 30)


async def main():
    payload = bytes([0, 255, 13, 10]) * 524288
    expected = hashlib.sha256(payload).hexdigest().encode()
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"],
                                      server_name="example.test")
    configuration.load_verify_locations(cafile=os.environ["HTTP3_PEER_CA_FILE"])
    for known_length in [False, True]:
        async with connect("127.0.0.1", int(os.environ["HTTP3_CADDY_PORT"]),
                           configuration=configuration, create_protocol=Client) as client:
            status, body = await client.digest(payload, known_length)
            if status != b"200" or body != expected:
                raise RuntimeError(f"Caddy independent upload integrity failed: content-length={known_length}")
    print("Independent Caddy 2MiB absent/explicit Content-Length integrity: PASS", flush=True)


if __name__ == "__main__":
    asyncio.run(main())

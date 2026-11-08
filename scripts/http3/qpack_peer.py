"""Independent HTTP/3 peer whose responses exercise the dynamic QPACK table.

Run with pinned aioquic==1.2.0. pylsqpack encodes against the dynamic table the
client advertises. `/qpack?id=N` returns repeated, large and per-request fields;
`/qpack-stats` returns the aggregate QPACK stream byte counters as JSON.
"""

import argparse
import asyncio
import json
from urllib.parse import parse_qs, urlsplit

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration

from aioquic_peer import Peer

LARGE = (b"abcdefghijklmnopqrstuvwxyz0123456789-_" * 100)[:3000]


def qpack_fields(request_id):
    fields = [(b"x-qpack-static", b"s" * 64), (b"x-qpack-large", LARGE),
              (b"x-qpack-request", request_id),
              (b"cache-control", b"private, max-age=" + request_id)]
    fields.extend((b"x-qpack-repeat-%d" % index, b"repeat-value-%d" % index) for index in range(20))
    return fields


class QpackPeer(Peer):
    connections = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connections.append(self.http)

    def respond(self, stream, body, *, status=b"200", path=b"/", head=False):
        target = urlsplit(path.decode())
        if target.path == "/qpack-stats":
            body = json.dumps({
                "connections": len(self.connections),
                "encoder_bytes_sent": sum(h._encoder_bytes_sent for h in self.connections),
                "decoder_bytes_received": sum(h._decoder_bytes_received for h in self.connections),
            }).encode()
            extra = []
        elif target.path == "/qpack":
            request_id = parse_qs(target.query).get("id", ["0"])[0].encode()
            body = b"qpack-" + request_id
            extra = qpack_fields(request_id)
        else:
            return super().respond(stream, body, status=status, path=path, head=head)
        fields = [(b":status", status), (b"content-length", str(len(body)).encode()),
                  (b"x-peer", b"aioquic-1.2.0"), (b"x-connection", str(self.identity).encode())]
        self.http.send_headers(stream, fields + extra)
        self.http.send_data(stream, body, end_stream=True)
        self.transmit()


async def main(args):
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], max_stream_data=1_048_576)
    config.load_cert_chain(args.cert, args.key)
    peer = await serve("127.0.0.1", 0, configuration=config, create_protocol=QpackPeer)
    print(peer._transport.get_extra_info("sockname")[1], flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    asyncio.run(main(parser.parse_args()))

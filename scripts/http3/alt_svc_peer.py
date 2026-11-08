"""aioquic 1.2.0 HTTP/3 peer for the Alt-Svc gate.

Extends the shared echo peer with `/authority`, which returns the request's
`:authority` pseudo-header so the gate can prove Alt-Svc routing kept the
origin authority while connecting to the alternative UDP port.
"""

import argparse
import asyncio

from aioquic.asyncio import serve
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

from aioquic_peer import Peer


class AltSvcPeer(Peer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authorities = {}
        handle_event = self.http.handle_event

        def recording(event):
            items = handle_event(event)
            for item in items:
                if isinstance(item, HeadersReceived):
                    self.authorities[item.stream_id] = dict(item.headers).get(b":authority", b"")
            return items

        self.http.handle_event = recording

    def respond(self, stream, body, *, status=b"200", path=b"/", head=False):
        authority = self.authorities.pop(stream, b"")
        if path == b"/authority":
            body = authority
        return super().respond(stream, body, status=status, path=path, head=head)


async def main(args):
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], max_stream_data=1_048_576)
    config.load_cert_chain(args.cert, args.key)
    peer = await serve("127.0.0.1", 0, configuration=config, create_protocol=AltSvcPeer)
    print(peer._transport.get_extra_info("sockname")[1], flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    asyncio.run(main(parser.parse_args()))

"""Independent HTTP/3 peer for session resumption and 0-RTT. Run with pinned aioquic==1.2.0.

The unmodified aioquic server issues 0-RTT-capable session tickets and accepts
early data on resumption. Its transport limits are lowered to the 64 KiB /
eight-stream envelope the QUIC client admits for remembered 0-RTT parameters.
Responses report `x-early: 1` when the request headers arrived before the
handshake completed, i.e. in 0-RTT. Paths:

- `/r` echoes `ok:<id>`.
- `/too-early` answers 425 to a request received in 0-RTT and 200 otherwise.
- `/always-425` always answers 425.
- `/reject-next` makes the next resumption attempt miss its ticket, so the
  handshake is full and 0-RTT is rejected.
- `/stats` returns JSON connection and request records.
"""

import argparse
import asyncio
import itertools
import json

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted

TICKETS = {}
STATE = {"reject_next": False}
CONNECTIONS = []
REQUESTS = []


def ticket_stored(ticket):
    TICKETS[ticket.ticket] = ticket


def ticket_fetched(identity):
    ticket = TICKETS.pop(identity, None)
    if STATE["reject_next"]:
        STATE["reject_next"] = False
        return None
    return ticket


class Peer(QuicConnectionProtocol):
    identities = itertools.count(1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.identity = next(self.identities)
        self.record = {"id": self.identity, "resumed": None, "early_accepted": None}
        CONNECTIONS.append(self.record)

    def connection_made(self, transport):
        # aioquic exposes connection/stream credit in configuration; its stream
        # count limits are these connection-owned values.
        self._quic._local_max_streams_bidi.value = 8
        self._quic._local_max_streams_uni.value = 8
        super().connection_made(transport)

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.record["resumed"] = event.session_resumed
            self.record["early_accepted"] = event.early_data_accepted
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived) and item.stream_ended:
                fields = dict(item.headers)
                early = not self._quic._handshake_complete
                path = fields.get(b":path", b"/").decode()
                REQUESTS.append({"connection": self.identity, "path": path,
                                 "method": fields.get(b":method", b"").decode(), "early": early})
                self.respond(item.stream_id, path, early, fields.get(b":method") == b"HEAD")

    def respond(self, stream, path, early, head):
        status, body = b"200", ("ok:%d" % self.identity).encode()
        if path == "/too-early" and early:
            status, body = b"425", b"too early"
        elif path == "/always-425":
            status, body = b"425", b"always"
        elif path == "/reject-next":
            STATE["reject_next"] = True
        elif path == "/stats":
            body = json.dumps({"connections": CONNECTIONS, "requests": REQUESTS}).encode()
        fields = [(b":status", status), (b"content-length", str(len(body)).encode()),
                  (b"x-peer", b"aioquic-1.2.0"), (b"x-early", b"1" if early else b"0"),
                  (b"x-connection", str(self.identity).encode())]
        self.http.send_headers(stream, fields)
        self.http.send_data(stream, b"" if head else body, end_stream=True)
        self.transmit()


async def main(args):
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"],
                               max_data=65536, max_stream_data=65536)
    config.load_cert_chain(args.cert, args.key)
    peer = await serve("127.0.0.1", 0, configuration=config, create_protocol=Peer,
                       session_ticket_handler=ticket_stored,
                       session_ticket_fetcher=ticket_fetched)
    print(peer._transport.get_extra_info("sockname")[1], flush=True)
    await asyncio.Future()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    asyncio.run(main(parser.parse_args()))

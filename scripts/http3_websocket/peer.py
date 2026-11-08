"""Independent RFC9220 framing: aioquic 1.2.0 and wsproto 1.2.0; no project codecs."""
import argparse
import asyncio
import importlib.metadata
import itertools

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, Setting
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from wsproto.connection import Connection, ConnectionType
from wsproto.events import TextMessage, BytesMessage, CloseConnection, Ping, Pong


class SettingsHeldPeer(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 0:
            raise SystemExit("CONNECT arrived before peer SETTINGS")


class NoConnect(H3Connection):
    def _get_local_settings(self):
        settings = super()._get_local_settings()
        settings.pop(Setting.ENABLE_CONNECT_PROTOCOL, None)
        return settings


class Peer(QuicConnectionProtocol):
    identities = itertools.count(1)
    disable_connect = False
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = (NoConnect if self.disable_connect else H3Connection)(self._quic)
        self.sessions = {}
        self.identity = next(self.identities)

    def send_data(self, stream_id, data, end_stream=False):
        self.http.send_data(stream_id, data, end_stream=end_stream)

    def quic_event_received(self, event):
        try:
            self.dispatch_event(event)
        except Exception as error:
            raise SystemExit(f"independent peer assertion failed: {error}") from error

    def dispatch_event(self, event):
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                fields = dict(item.headers)
                path = fields.get(b":path", b"/")
                if fields.get(b":protocol") != b"websocket":
                    self.http.send_headers(item.stream_id, [(b":status", b"200")])
                    self.send_data(item.stream_id, str(self.identity).encode() if path == b"/identity" else b"sibling", end_stream=True)
                    continue
                assert fields[b":method"] == b"CONNECT"
                assert fields[b":scheme"] == b"https"
                assert fields.get(b"sec-websocket-version") == b"13"
                assert not item.stream_ended
                assert not ({b"connection", b"upgrade", b"sec-websocket-key", b"sec-websocket-accept"} & fields.keys())
                if path == b"/refuse":
                    self.http.send_headers(item.stream_id, [(b":status", b"403")])
                    self.send_data(item.stream_id, b"", end_stream=True)
                    continue
                headers = [(b":status", b"200")]
                if b"sec-websocket-protocol" in fields:
                    headers.append((b"sec-websocket-protocol", b"wrong" if path == b"/protocol" else b"chat"))
                self.http.send_headers(item.stream_id, headers)
                websocket = Connection(ConnectionType.SERVER)
                self.sessions[item.stream_id] = websocket
                if path == b"/identity":
                    self.send_data(item.stream_id, websocket.send(TextMessage(data=str(self.identity))))
                elif path == b"/fragment":
                    self.send_data(item.stream_id, websocket.send(TextMessage(data="frag-", message_finished=False)))
                    self.send_data(item.stream_id, websocket.send(TextMessage(data="complete", message_finished=True)))
                elif path == b"/close-fin":
                    self.send_data(item.stream_id, websocket.send(CloseConnection(code=1000, reason="peer-close")), end_stream=True)
                elif path == b"/oversize":
                    self.send_data(item.stream_id, websocket.send(BytesMessage(data=b"x" * 2000)))
                elif path == b"/bad-frame":
                    self.send_data(item.stream_id, b"\x83\x00")
                elif path == b"/ping":
                    self.send_data(item.stream_id, websocket.send(Ping(payload=b"proof")))
            elif isinstance(item, DataReceived) and item.stream_id in self.sessions:
                websocket = self.sessions[item.stream_id]
                websocket.receive_data(item.data)
                for message in websocket.events():
                    if isinstance(message, (TextMessage, BytesMessage)):
                        self.send_data(item.stream_id, websocket.send(message))
                    elif isinstance(message, CloseConnection):
                        # /close-fin has already half-closed its sending direction.
                        if not self._quic._streams[item.stream_id].sender.is_finished:
                            self.send_data(item.stream_id, websocket.send(message.response()), end_stream=True)
                        self.sessions.pop(item.stream_id, None)
                    elif isinstance(message, Ping):
                        self.send_data(item.stream_id, websocket.send(message.response()))
                    elif isinstance(message, Pong):
                        self.send_data(item.stream_id, websocket.send(TextMessage(data="pong:" + message.payload.decode())))
        self.transmit()


async def main(args):
    for name, version in [("aioquic", "1.2.0"), ("wsproto", "1.2.0")]:
        assert importlib.metadata.version(name) == version
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"], max_stream_data=16_384)
    config.load_cert_chain(args.cert, args.key)
    Peer.disable_connect = args.disable_connect
    server = await serve("127.0.0.1", 0, configuration=config, create_protocol=SettingsHeldPeer if args.hold_settings else Peer)
    print(server._transport.get_extra_info("sockname")[1], flush=True)
    try:
        await asyncio.Future()
    finally:
        server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("--disable-connect", action="store_true")
    parser.add_argument("--hold-settings", action="store_true")
    asyncio.run(main(parser.parse_args()))

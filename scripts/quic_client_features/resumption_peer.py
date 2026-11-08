#!/usr/bin/env python3
"""Pinned unmodified aioquic 1.2.0 full/resumed network peer, early data disabled."""
import argparse
import asyncio
from importlib.metadata import version
import json
from pathlib import Path
from aioquic.asyncio import QuicConnectionProtocol, serve, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived

FIXTURE = Path(__file__).resolve().parents[2] / "apps/elixir_quic/test/fixtures/tls"
TICKETS = {}
LATEST = None


def emit(**values):
    print(json.dumps(values), flush=True)


def ticket_received(ticket):
    global LATEST
    LATEST = ticket
    TICKETS[ticket.ticket] = ticket
    emit(event="ticket", early=ticket.max_early_data_size is not None)


class Echo(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            emit(event="handshake", resumed=event.session_resumed, early=event.early_data_accepted)
        elif isinstance(event, StreamDataReceived):
            self._quic.send_stream_data(event.stream_id, event.data, event.end_stream)
        self.transmit()


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received = b""
        self.done = asyncio.get_running_loop().create_future()

    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            emit(event="handshake", resumed=event.session_resumed, early=event.early_data_accepted)
        elif isinstance(event, StreamDataReceived):
            self.received += event.data
            if event.end_stream:
                self.done.set_result(self.received)


async def main(args):
    assert version("aioquic") == "1.2.0"
    config = QuicConfiguration(is_client=args.role == "client", alpn_protocols=["ex-quic-r1"],
                               server_name="example.test" if args.role == "client" else None)
    config.load_verify_locations(str(FIXTURE / "root.pem"))
    if args.role == "server":
        config.load_cert_chain(str(FIXTURE / "leaf.pem"), str(FIXTURE / "leaf-key.pem"))
        server = await serve("127.0.0.1", 0, configuration=config, create_protocol=Echo,
                             session_ticket_handler=ticket_received,
                             session_ticket_fetcher=lambda identity: TICKETS.pop(identity, None))
        emit(event="listening", port=server._transport.get_extra_info("sockname")[1])
        try:
            await asyncio.sleep(35)
        finally:
            server.close()
    else:
        for index in range(2):
            config.session_ticket = LATEST
            async with connect("127.0.0.1", args.port, configuration=config, create_protocol=Client,
                               session_ticket_handler=ticket_received) as protocol:
                payload = f"resumption/{index}/".encode() + bytes(range(256))
                protocol._quic.send_stream_data(0, payload, end_stream=True)
                protocol.transmit()
                received = await asyncio.wait_for(protocol.done, 8)
                assert received == payload
                assert LATEST is not None, "server ticket missing"
                emit(event="stream", index=index, bytes=len(received), fin=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["server", "client"], required=True)
    parser.add_argument("--port", type=int)
    asyncio.run(main(parser.parse_args()))

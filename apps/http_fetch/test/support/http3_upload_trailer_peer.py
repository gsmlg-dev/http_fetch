"""Independent ordered upload/FIN oracle; pinned aioquic 1.2.0."""
import argparse
import asyncio
import base64
import itertools
import json
import signal
import sys

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamReset


def report(event, **fields):
    print(json.dumps(dict(event=event, **fields)), flush=True)


class Peer(QuicConnectionProtocol):
    identities = itertools.count(1)
    records = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.connection = next(self.identities)

    def quic_event_received(self, event):
        if isinstance(event, StreamReset):
            report("reset", id=f"{self.connection}:{event.stream_id}")
        for item in self.http.handle_event(event):
            identity = f"{self.connection}:{item.stream_id}"
            if isinstance(item, HeadersReceived):
                fields = [[name.decode(), value.decode()] for name, value in item.headers]
                if identity not in self.records:
                    self.records[identity] = dict(body=bytearray(), trailers=[], headers=fields,
                                                  events=["headers"], fin=0, peer=self,
                                                  stream=item.stream_id)
                    report("headers", id=identity, fields=fields)
                    if dict(item.headers).get(b":path") == b"/early":
                        self.respond(identity, 413)
                        continue
                else:
                    record = self.records[identity]
                    record["trailers"].extend(fields)
                    record["events"].append("trailers")
                    report("trailers", id=identity, fields=fields, ended=item.stream_ended)
            elif isinstance(item, DataReceived):
                self.records[identity]["body"].extend(item.data)
                if item.data:
                    self.records[identity]["events"].append("data")
                    report("data", id=identity, bytes=len(item.data))
            else:
                continue
            if item.stream_ended:
                record = self.records[identity]
                record["fin"] += 1
                record["events"].append("fin")
                report("end", **self.snapshot(identity))
                if dict(record["headers"]).get(":path") != "/hold":
                    self.respond(identity)

    @classmethod
    def snapshot(cls, identity):
        record = cls.records[identity]
        return dict(id=identity, body=base64.b64encode(record["body"]).decode(),
                    trailers=record["trailers"], headers=record["headers"],
                    events=record["events"], fin=record["fin"], requests=len(cls.records))

    def respond(self, identity, status=200):
        payload = json.dumps(self.snapshot(identity)).encode()
        stream = self.records[identity]["stream"]
        self.http.send_headers(stream, [(b":status", str(status).encode()),
                                       (b"content-length", str(len(payload)).encode())])
        self.http.send_data(stream, payload, end_stream=True)
        self.transmit()


async def main(args):
    config = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    config.load_cert_chain(args.cert, args.key)
    server = await serve("127.0.0.1", 0, configuration=config, create_protocol=Peer)
    report("ready", port=server._transport.get_extra_info("sockname")[1])
    closed = asyncio.Event()

    def command():
        line = sys.stdin.readline()
        if not line:
            closed.set()
            return
        value = json.loads(line)
        if value["op"] == "count":
            report("count", requests=len(Peer.records))
            return
        identity = value["id"]
        if value["op"] == "snapshot":
            report("snapshot", **Peer.snapshot(identity))
        elif value["op"] == "respond":
            Peer.records[identity]["peer"].respond(identity)

    loop = asyncio.get_running_loop()
    loop.add_reader(sys.stdin, command)
    try:
        await closed.wait()
    finally:
        loop.remove_reader(sys.stdin)
        server.close()


if __name__ == "__main__":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    asyncio.run(main(parser.parse_args()))

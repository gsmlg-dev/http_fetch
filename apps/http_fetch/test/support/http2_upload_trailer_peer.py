#!/usr/bin/env python3
"""Independent TLS hyper-h2 peer with explicit flow/response gates."""
import argparse
import base64
import json
import select
import socket
import ssl
import sys

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, SettingsAcknowledged, StreamEnded, StreamReset, TrailersReceived
from h2.settings import Settings, SettingCodes


def report(kind, **fields):
    print(json.dumps(dict(event=kind, **fields)), flush=True)


parser = argparse.ArgumentParser()
parser.add_argument("--cert", required=True)
parser.add_argument("--key", required=True)
parser.add_argument("--window", type=int, default=65535)
parser.add_argument("--header-limit", type=int, default=100000)
args = parser.parse_args()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args.cert, args.key)
context.set_alpn_protocols(["h2"])

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    report("ready", port=listener.getsockname()[1])
    raw, _ = listener.accept()
    with context.wrap_socket(raw, server_side=True) as sock:
        assert sock.selected_alpn_protocol() == "h2"
        connection = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        connection.local_settings = Settings(client=False, initial_values={
            SettingCodes.INITIAL_WINDOW_SIZE: args.window,
            SettingCodes.MAX_HEADER_LIST_SIZE: args.header_limit,
        })
        connection.decoder.max_header_list_size = 100000
        connection.initiate_connection()
        sock.sendall(connection.data_to_send())
        requests = {}
        wire = b""
        preface = True

        def snapshot(stream_id):
            record = requests[stream_id]
            return dict(id=stream_id, body=base64.b64encode(record["body"]).decode(),
                        trailers=record["trailers"], continuation=record["continuation"])

        def respond(stream_id, status=200):
            payload = json.dumps(snapshot(stream_id)).encode()
            if len(payload) > 10000:
                raise AssertionError("use controlled response for large trailer records")
            connection.send_headers(stream_id, [(":status", str(status)),
                                    ("content-length", str(len(payload)))])
            connection.send_data(stream_id, payload, end_stream=True)

        while True:
            readers = [sock] if sock.pending() else select.select([sock, sys.stdin], [], [], 10)[0]
            if not readers:
                raise TimeoutError("fixture gate timed out")
            for reader in readers:
                if reader is sys.stdin:
                    line = sys.stdin.readline()
                    if not line:
                        sys.exit(0)
                    command = json.loads(line)
                    stream_id = command["id"]
                    if command["op"] == "respond":
                        connection.send_headers(stream_id, [(":status", "200"), ("content-length", "0")], end_stream=True)
                    elif command["op"] == "reset":
                        connection.reset_stream(stream_id, error_code=8)
                    elif command["op"] == "grant":
                        connection.increment_flow_control_window(command["bytes"], stream_id)
                    elif command["op"] == "snapshot":
                        report("snapshot", **snapshot(stream_id))
                else:
                    data = sock.recv(65536)
                    if not data:
                        sys.exit(0)
                    wire += data
                    if preface and len(wire) >= 24:
                        assert wire[:24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                        wire = wire[24:]
                        preface = False
                    while not preface and len(wire) >= 9:
                        length = int.from_bytes(wire[:3], "big")
                        if len(wire) < 9 + length:
                            break
                        frame_type = wire[3]
                        stream_id = int.from_bytes(wire[5:9], "big") & 0x7fffffff
                        if frame_type == 9 and stream_id in requests:
                            requests[stream_id]["continuation"] += 1
                        wire = wire[9 + length:]
                    for event in connection.receive_data(data):
                        stream_id = getattr(event, "stream_id", None)
                        if isinstance(event, SettingsAcknowledged):
                            report("settings_ack")
                        elif isinstance(event, RequestReceived):
                            requests[stream_id] = dict(body=bytearray(), trailers=[], continuation=0,
                                                      path=dict(event.headers)[":path"])
                            report("headers", id=stream_id, fields=event.headers)
                        elif isinstance(event, DataReceived):
                            requests[stream_id]["body"].extend(event.data)
                            assert len(requests[stream_id]["body"]) <= 2 * 1024 * 1024
                            if args.window == 65535:
                                connection.acknowledge_received_data(event.flow_controlled_length, stream_id)
                            report("data", id=stream_id, bytes=len(requests[stream_id]["body"]))
                        elif isinstance(event, TrailersReceived):
                            requests[stream_id]["trailers"] = event.headers
                        elif isinstance(event, StreamEnded):
                            report("end", **snapshot(stream_id))
                            if requests[stream_id]["path"] == "/echo":
                                respond(stream_id)
                        elif isinstance(event, StreamReset):
                            report("reset", id=stream_id, code=event.error_code)
                output = connection.data_to_send()
                if output:
                    sock.sendall(output)

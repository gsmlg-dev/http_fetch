#!/usr/bin/env python3
"""Independent bounded HTTPS application oracle behind the OpenSSL TLS witness."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import select
import socket
import sys
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset
from h2.settings import SettingCodes, Settings
from wsproto.connection import Connection, ConnectionType
from wsproto.events import BytesMessage, CloseConnection, Ping, TextMessage

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))
from http2_websocket_peer import MaskOracle  # noqa: E402

BODY = b"identity-completion-ok"
SSE = b"id: identity-completion\ndata: identity-completion-event\n\n"
FRAME = "identity-completion-frame"
STOPPED = False


def emit(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)


def readable(sock, expiry):
    global STOPPED
    remaining = expiry - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("application_deadline")
    available, _, _ = select.select([sock, sys.stdin], [], [], remaining)
    if sys.stdin in available:
        command = sys.stdin.readline().strip()
        if command in ("", "stop"):
            STOPPED = True
            return "stop"
        return command
    return "socket"


def websocket_bytes(state, data):
    state["oracle"].receive(data)
    state["codec"].receive_data(data)
    result, closed = bytearray(), False
    for message in state["codec"].events():
        if isinstance(message, (TextMessage, BytesMessage)):
            assert message.message_finished, "unexpected_fragmented_client_message"
            result.extend(state["codec"].send(message))
            emit("frame", stream=state["stream"], payload_exact=True)
        elif isinstance(message, Ping):
            result.extend(state["codec"].send(message.response()))
        elif isinstance(message, CloseConnection):
            assert message.code == 1000, "unexpected_client_close"
            result.extend(state["codec"].send(message.response()))
            assert state["oracle"].frames["8"] == 1, "client_close_count"
            assert not state["oracle"].buffer, "client_frame_truncated"
            closed = True
            emit("client_close", stream=state["stream"], code=1000, masked=True)
    return bytes(result), closed


def ws_state(stream):
    return dict(codec=Connection(ConnectionType.SERVER), oracle=MaskOracle(), stream=stream)


def http1(sock, expected, application, expiry):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        if readable(sock, expiry) == "stop":
            return
        part = sock.recv(16384)
        if not part:
            return
        data.extend(part)
        assert len(data) <= 65536, "request_header_bound"
    head, rest = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    assert lines[0] == "GET /identity-completion HTTP/1.1", "request_target"
    headers = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        name = name.lower()
        assert name not in headers, "duplicate_request_header"
        headers[name] = value.strip()
    assert headers["host"] == expected["authority"], "external_origin_authority"
    assert not rest, "unexpected_request_body"
    emit("request", stream=1, application=application, request_exact=True,
         scheme="https", authority_exact=True)
    if application == "fetch":
        sock.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
                     str(len(BODY)).encode() + b"\r\n\r\n" + BODY)
        emit("response", stream=1, response_written=True)
        return
    if application == "sse":
        assert headers["accept"] == "text/event-stream", "sse_accept"
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n" + SSE)
        emit("response", stream=1, response_written=True)
        while readable(sock, expiry) != "stop":
            if not sock.recv(16384):
                return
        return
    assert headers["upgrade"].lower() == "websocket", "websocket_upgrade"
    assert headers["sec-websocket-version"] == "13", "websocket_version"
    key = headers["sec-websocket-key"]
    assert len(base64.b64decode(key, validate=True)) == 16, "websocket_nonce"
    accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
    sock.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    state = ws_state(1)
    sock.sendall(state["codec"].send(TextMessage(data=FRAME)))
    emit("response", stream=1, response_written=True)
    while readable(sock, expiry) != "stop":
        data = sock.recv(16384)
        if not data:
            return
        response, closed = websocket_bytes(state, data)
        if response:
            sock.sendall(response)
        if closed:
            return


def http2(sock, expected, application, expiry):
    conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
    conn.local_settings = Settings(client=False, initial_values={
        SettingCodes.ENABLE_CONNECT_PROTOCOL: 1,
        SettingCodes.MAX_CONCURRENT_STREAMS: 16,
    })
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    streams, held = {}, set()
    while True:
        action = readable(sock, expiry)
        if action == "stop":
            return
        if action == "tick":
            for sid in list(held):
                if application == "sse":
                    conn.send_data(sid, b"id: sibling\ndata: sibling-proof\n\n")
                elif application == "wss":
                    conn.send_data(sid, streams[sid]["codec"].send(TextMessage(data="identity-sibling-frame")))
                else:
                    conn.send_data(sid, b"ok", end_stream=True)
                    held.remove(sid)
                emit("tick", stream=sid, response_written=True)
            sock.sendall(conn.data_to_send())
            continue
        data = sock.recv(65536)
        if not data:
            return
        for event in conn.receive_data(data):
            sid = getattr(event, "stream_id", 0)
            if isinstance(event, RequestReceived):
                headers = dict(event.headers)
                assert len(headers) == len(event.headers), "duplicate_h2_header"
                assert headers[":scheme"] == "https", "external_https_scheme"
                assert headers[":authority"] == expected["authority"], "external_origin_authority"
                assert headers[":path"].startswith("/identity-completion"), "request_target"
                assert sid not in streams, "duplicate_stream"
                emit("request", stream=sid, application=application, request_exact=True,
                     scheme="https", authority_exact=True)
                if application == "wss":
                    assert headers[":method"] == "CONNECT", "extended_connect_method"
                    assert headers[":protocol"] == "websocket", "extended_connect_protocol"
                    assert headers["sec-websocket-version"] == "13", "websocket_version"
                    assert event.stream_ended is None, "premature_connect_end"
                    assert not set(headers) & {"connection", "upgrade", "sec-websocket-key"}, "h1_header_on_h2"
                    state = ws_state(sid)
                    streams[sid] = state
                    held.add(sid)
                    conn.send_headers(sid, [(":status", "200")])
                    conn.send_data(sid, state["codec"].send(TextMessage(data=FRAME)))
                else:
                    assert headers[":method"] == "GET", "get_method"
                    streams[sid] = {}
                    if application == "sse":
                        assert headers["accept"] == "text/event-stream", "sse_accept"
                        conn.send_headers(sid, [(":status", "200"), ("content-type", "text/event-stream")])
                        conn.send_data(sid, SSE)
                        held.add(sid)
                    elif headers[":path"].endswith(("/sibling", "/hold")):
                        conn.send_headers(sid, [(":status", "200")])
                        conn.send_data(sid, b"identity-sibling-")
                        held.add(sid)
                    else:
                        conn.send_headers(sid, [(":status", "200"), ("content-length", str(len(BODY)))])
                        conn.send_data(sid, BODY, end_stream=True)
                emit("response", stream=sid, response_written=True)
            elif isinstance(event, DataReceived):
                conn.acknowledge_received_data(event.flow_controlled_length, sid)
                if application == "wss" and event.data:
                    response, closed = websocket_bytes(streams[sid], event.data)
                    if response:
                        conn.send_data(sid, response, end_stream=closed)
                    if closed:
                        held.discard(sid)
            elif isinstance(event, StreamReset):
                held.discard(sid)
                emit("client_reset", stream=sid, code=event.error_code)
            elif isinstance(event, StreamEnded):
                emit("client_end", stream=sid)
        response = conn.data_to_send()
        if response:
            sock.sendall(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=["http1", "http2"], required=True)
    parser.add_argument("--application", choices=["fetch", "sse", "wss"], required=True)
    args = parser.parse_args()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    emit("ready", port=listener.getsockname()[1])
    expected = json.loads(sys.stdin.readline())
    expiry = time.monotonic() + 20
    try:
        if readable(listener, expiry) == "stop":
            return
        sock, _ = listener.accept()
        with sock:
            sock.settimeout(3)
            emit("application_connected", connection=1)
            operation = http1 if args.protocol == "http1" else http2
            operation(sock, expected, args.application, expiry)
    finally:
        listener.close()
        emit("application_closed")
        # This process-exit barrier is separate from transport EOF evidence.
        if not STOPPED:
            available, _, _ = select.select([sys.stdin], [], [], 5)
            if available:
                assert sys.stdin.readline().strip() in ("", "stop"), "shutdown_command"


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        emit("application_error", category=type(error).__name__)
        raise SystemExit(1) from None

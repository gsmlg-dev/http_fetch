"""Bounded independent OpenSSL peer for packaged ex_ssl consumer tests."""

import argparse
import base64
import hashlib
import json
import socket
import ssl
import struct
import sys


def event(kind, **fields):
    print(json.dumps({"kind": kind, **fields}), flush=True)


def exact(connection, length):
    result = bytearray()
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise EOFError("truncated")
        result.extend(part)
    return bytes(result)


def headers(connection):
    result = bytearray()
    while b"\r\n\r\n" not in result:
        if len(result) >= 16384:
            raise ValueError("headers_too_large")
        part = connection.recv(4096)
        if not part:
            raise EOFError("headers_truncated")
        result.extend(part)
    if len(result) > 16384:
        raise ValueError("headers_too_large")
    return bytes(result)


def frame(connection):
    head = exact(connection, 9)
    length = int.from_bytes(head[:3], "big")
    if length > 16384:
        raise ValueError("h2_frame_too_large")
    return head[3], head[4], int.from_bytes(head[5:], "big") & 0x7FFFFFFF, exact(connection, length)


def send_frame(connection, kind, flags, stream, payload):
    if len(payload) > 16384:
        raise ValueError("h2_frame_too_large")
    connection.sendall(len(payload).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack("!I", stream) + payload)


def http1(connection, large, path=b"/tls12"):
    request = headers(connection)
    if not request.startswith(b"GET " + path + b" HTTP/1.1\r\n"):
        raise ValueError("wrong_http1_request")
    body = b"B" * (262144 if large else 6)
    connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    event("exchange", bytes=len(body))


def http2(connection, large):
    if exact(connection, 24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
        raise ValueError("wrong_h2_preface")
    reads = 0

    def next_frame():
        nonlocal reads
        if reads >= 256:
            raise ValueError("too_many_h2_control_frames")
        reads += 1
        return frame(connection)

    kind, _, stream, settings = next_frame()
    if kind != 4 or stream != 0:
        raise ValueError("missing_h2_settings")
    if len(settings) % 6:
        raise ValueError("invalid_h2_settings")
    stream_window = 65535
    for offset in range(0, len(settings), 6):
        setting, value = struct.unpack("!HI", settings[offset:offset + 6])
        if setting == 4:
            if value > 0x7FFFFFFF:
                raise ValueError("invalid_h2_initial_window")
            stream_window = value
    connection_window = 65535
    saw_headers = False
    acknowledged = False
    window_updates = 0

    def control(kind, flags, stream, payload):
        nonlocal acknowledged, connection_window, stream_window, window_updates
        if kind == 4 and flags == 1 and stream == 0 and not payload:
            acknowledged = True
        elif kind == 8 and stream in (0, 1) and len(payload) == 4:
            increment = struct.unpack("!I", payload)[0] & 0x7FFFFFFF
            if increment == 0:
                raise ValueError("invalid_h2_window_update")
            if stream == 0:
                connection_window += increment
            else:
                stream_window += increment
            if connection_window > 0x7FFFFFFF or stream_window > 0x7FFFFFFF:
                raise ValueError("h2_window_overflow")
            window_updates += 1
        elif kind in (3, 7):
            raise ValueError("h2_stream_or_connection_reset")

    for _ in range(8):
        kind, flags, stream, payload = next_frame()
        control(kind, flags, stream, payload)
        if kind == 1 and stream == 1:
            saw_headers = True
            break
    if not saw_headers:
        raise ValueError("missing_h2_headers")
    body = b"B" * (262144 if large else 6)
    send_frame(connection, 4, 0, 0, b"")
    # HPACK indexed :status 200 (8); literal content-length with indexed name (28).
    digits = str(len(body)).encode()
    block = b"\x88\x0f\x0d" + bytes([len(digits)]) + digits
    send_frame(connection, 1, 4, 1, block)
    offset = 0
    while offset < len(body):
        available = min(16384, connection_window, stream_window, len(body) - offset)
        if available == 0:
            control(*next_frame())
            continue
        chunk = body[offset:offset + available]
        flags = 1 if offset + available == len(body) else 0
        send_frame(connection, 0, flags, 1, chunk)
        offset += available
        connection_window -= available
        stream_window -= available
    if not acknowledged:
        while not acknowledged:
            control(*next_frame())
    if not acknowledged:
        raise ValueError("missing_h2_settings_ack")
    event("exchange", bytes=len(body), window_updates=window_updates)


def websocket(connection):
    request = headers(connection)
    if not request.startswith(b"GET /socket HTTP/1.1\r\n"):
        raise ValueError("wrong_wss_request")
    fields = request.split(b"\r\n")
    keys = [line.split(b":", 1)[1].strip() for line in fields if line.lower().startswith(b"sec-websocket-key:")]
    if len(keys) != 1:
        raise ValueError("missing_wss_key")
    accept = base64.b64encode(hashlib.sha1(keys[0] + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
    connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    event("upgrade")
    head = exact(connection, 2)
    if head[0] != 0x81 or head[1] != 0x80 + 10:
        raise ValueError("wrong_wss_frame")
    mask = exact(connection, 4)
    payload = exact(connection, 10)
    decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    if decoded != b"tls12-echo":
        raise ValueError("wrong_wss_payload")
    echoed = b"echo:" + decoded
    connection.sendall(bytes([0x81, len(echoed)]) + echoed)
    head = exact(connection, 2)
    if head[0] != 0x88 or not (head[1] & 0x80):
        raise ValueError("missing_wss_close")
    size = head[1] & 0x7F
    if size > 125:
        raise ValueError("wss_close_too_large")
    mask = exact(connection, 4)
    payload = exact(connection, size)
    decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    connection.sendall(bytes([0x88, len(decoded)]) + decoded)
    event("exchange", bytes=10)


def sse(connection, index):
    request = headers(connection)
    if not request.startswith(b"GET /events HTTP/1.1\r\n"):
        raise ValueError("wrong_sse_request")
    last_id_ok = b"Last-Event-ID: 41\r\n" in request
    event("request", index=index, last_id_ok=last_id_ok)
    if index == 1:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nid: 41\ndata: first\n\n")
        event("first_ready")
        if sys.stdin.buffer.readline() != b"go\n":
            raise ValueError("missing_release")
    else:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: keep-alive\r\n\r\ndata: second\n\n")
        event("second_ready")
        sys.stdin.buffer.readline()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certfile", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--cafile", required=True)
    parser.add_argument("--mode", choices=["http1", "h2", "wss", "sse", "resumption"], required=True)
    parser.add_argument("--max-version", choices=["tls12", "tls13"], default="tls12")
    parser.add_argument("--large", action="store_true")
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3 if args.mode == "resumption" else ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2 if args.max_version == "tls12" and args.mode != "resumption" else ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION
    context.load_cert_chain(args.certfile, args.keyfile)
    context.load_verify_locations(cafile=args.cafile)
    context.verify_mode = ssl.CERT_NONE if args.mode == "resumption" else ssl.CERT_REQUIRED
    context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    context.set_ecdh_curve("prime256v1")
    context.set_alpn_protocols(["h2" if args.mode == "h2" else "http/1.1"])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(10)
    event("ready", port=listener.getsockname()[1], openssl=ssl.OPENSSL_VERSION)
    count = 2 if args.mode in ("sse", "resumption") else 1
    for index in range(1, count + 1):
        raw, _ = listener.accept()
        raw.settimeout(10)
        try:
            with context.wrap_socket(raw, server_side=True) as connection:
                der = connection.getpeercert(binary_form=True)
                event("handshake", index=index, version=connection.version(), cipher=connection.cipher()[0], alpn=connection.selected_alpn_protocol(), client_der_b64=base64.b64encode(der).decode() if der else None, session_reused=connection.session_reused)
                if args.mode == "http1":
                    http1(connection, args.large)
                elif args.mode == "resumption":
                    http1(connection, False, b"/resumption")
                elif args.mode == "h2":
                    http2(connection, args.large)
                elif args.mode == "wss":
                    websocket(connection)
                else:
                    sse(connection, index)
                if args.mode != "sse":
                    try:
                        connection.unwrap().close()
                    except (ssl.SSLError, OSError, EOFError):
                        pass
        except (ssl.SSLError, OSError, EOFError, ValueError) as error:
            event("failure", kind_name=type(error).__name__)
            raw.close()
    listener.close()


if __name__ == "__main__":
    main()

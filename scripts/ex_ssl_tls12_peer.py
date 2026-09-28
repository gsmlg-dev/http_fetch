"""Bounded independent OpenSSL peer for packaged ex_ssl consumer tests."""

import argparse
import base64
import hashlib
import json
import select
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


def client_hello_ticket_offered(data):
    if len(data) < 5:
        raise ValueError("truncated_handshake_record")
    record = data[:5]
    if record[0] != 22:
        raise ValueError("expected_handshake_record")
    record_length = int.from_bytes(record[3:5], "big")
    if len(data) != 5 + record_length:
        raise ValueError("truncated_handshake_record")
    payload = data[5:]
    if len(payload) < 4 or payload[0] != 1:
        raise ValueError("expected_client_hello")
    hello = payload[4:]
    offset = 2 + 32
    if len(hello) < offset + 1:
        raise ValueError("truncated_client_hello")
    session_id_length = hello[offset]
    offset += 1 + session_id_length
    if len(hello) < offset + 2:
        raise ValueError("truncated_cipher_suites")
    cipher_suites_length = int.from_bytes(hello[offset:offset + 2], "big")
    offset += 2 + cipher_suites_length
    if len(hello) < offset + 1:
        raise ValueError("truncated_compression_methods")
    compression_length = hello[offset]
    offset += 1 + compression_length
    if len(hello) < offset + 2:
        raise ValueError("truncated_extensions")
    extensions_end = offset + 2 + int.from_bytes(hello[offset:offset + 2], "big")
    offset += 2
    if extensions_end != len(hello):
        raise ValueError("invalid_client_hello_extensions")
    ticket_offered = False
    while offset < extensions_end:
        if offset + 4 > extensions_end:
            raise ValueError("truncated_extension")
        extension_type = int.from_bytes(hello[offset:offset + 2], "big")
        extension_length = int.from_bytes(hello[offset + 2:offset + 4], "big")
        offset += 4 + extension_length
        if offset > extensions_end:
            raise ValueError("truncated_extension_data")
        ticket_offered = ticket_offered or extension_type == 41
    return ticket_offered


def peek_client_hello_ticket_offered(raw):
    record = raw.recv(5, socket.MSG_PEEK | socket.MSG_WAITALL)
    if len(record) != 5:
        raise ValueError("truncated_handshake_record")
    record_length = int.from_bytes(record[3:5], "big")
    data = raw.recv(5 + record_length, socket.MSG_PEEK | socket.MSG_WAITALL)
    return client_hello_ticket_offered(data)


def read_client_hello_ticket_offered(raw):
    record = exact(raw, 5)
    return client_hello_ticket_offered(record + exact(raw, int.from_bytes(record[3:5], "big")))


def http1(connection, large, path=b"/tls12"):
    request = headers(connection)
    if not request.startswith(b"GET " + path + b" HTTP/1.1\r\n"):
        raise ValueError("wrong_http1_request")
    body = b"B" * (262144 if large else 6)
    connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    event("exchange", bytes=len(body))


def http2(connection, large, streaming=False):
    if exact(connection, 24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
        raise ValueError("wrong_h2_preface")
    reads = 0

    def next_frame():
        nonlocal reads
        if reads >= 1024:
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
    body = b"B" * (6 * 1024 * 1024 if large and streaming else 262144 if large else 6)
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


def websocket(connection, expected=b"tls12-echo"):
    request = headers(connection)
    if not request.startswith(b"GET /socket HTTP/1.1\r\n"):
        raise ValueError("wrong_wss_request")
    fields = request.split(b"\r\n")
    keys = [line.split(b":", 1)[1].strip() for line in fields if line.lower().startswith(b"sec-websocket-key:")]
    if len(keys) != 1:
        raise ValueError("missing_wss_key")
    accept = base64.b64encode(hashlib.sha1(keys[0] + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
    connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n\x81\x05hello")
    event("upgrade", greeting="hello")
    head = exact(connection, 2)
    if head[0] != 0x81 or head[1] != 0x80 + len(expected):
        raise ValueError("wrong_wss_frame")
    mask = exact(connection, 4)
    payload = exact(connection, len(expected))
    decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    if decoded != expected:
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
    event("exchange", bytes=len(expected), frames=1)


def sse(connection, index):
    request = headers(connection)
    if not request.startswith(b"GET /events HTTP/1.1\r\n"):
        raise ValueError("wrong_sse_request")
    last_id_ok = b"Last-Event-ID: 41\r\n" in request
    event("request", index=index, last_id_ok=last_id_ok)
    if index == 1:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nid: 41\ndata: first\n\n")
        event("first_ready")
        if not select.select([sys.stdin], [], [], 10)[0] or sys.stdin.buffer.readline() != b"go\n":
            raise ValueError("missing_release")
    else:
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: keep-alive\r\n\r\ndata: second\n\n")
        event("second_ready")
        if not select.select([sys.stdin], [], [], 10)[0]:
            raise ValueError("missing_stop")
        sys.stdin.buffer.readline()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certfile", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--cafile", required=True)
    parser.add_argument("--mode", choices=["http1", "h2", "wss", "sse", "resumption", "resumption-h2", "resumption-wss", "resumption-sse"], required=True)
    parser.add_argument("--max-version", choices=["tls12", "tls13"], default="tls12")
    parser.add_argument("--large", action="store_true")
    parser.add_argument("--reject-ticket", action="store_true")
    parser.add_argument("--hold-second-handshake", action="store_true")
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    resumption = args.mode.startswith("resumption")
    context.minimum_version = ssl.TLSVersion.TLSv1_3 if resumption else ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2 if args.max_version == "tls12" and not resumption else ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION
    context.load_cert_chain(args.certfile, args.keyfile)
    context.load_verify_locations(cafile=args.cafile)
    context.verify_mode = ssl.CERT_NONE if resumption else ssl.CERT_REQUIRED
    context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    context.set_ecdh_curve("prime256v1")
    context.set_alpn_protocols(["h2" if args.mode == "h2" or args.mode == "resumption-h2" else "http/1.1"])

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(10)
    event("ready", port=listener.getsockname()[1], openssl=ssl.OPENSSL_VERSION)
    count = 2 if args.mode in ("sse", "resumption", "resumption-h2", "resumption-wss", "resumption-sse") else 1
    for index in range(1, count + 1):
        raw, _ = listener.accept()
        raw.settimeout(10)
        try:
            if args.hold_second_handshake and index == 2:
                event("setup", index=index, ticket_offered=read_client_hello_ticket_offered(raw))
                while raw.recv(4096):
                    pass
                event("setup_closed", index=index)
                raw.close()
                continue
            # A fresh context has a new ticket key.  It deliberately rejects a
            # ticket while retaining the same certificate and TLS policy.
            active_context = context
            if args.reject_ticket and index == 2:
                active_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                active_context.minimum_version = context.minimum_version
                active_context.maximum_version = context.maximum_version
                active_context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION
                active_context.load_cert_chain(args.certfile, args.keyfile)
                active_context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
                active_context.set_ecdh_curve("prime256v1")
                active_context.set_alpn_protocols(["h2" if args.mode == "resumption-h2" else "http/1.1"])
            ticket_offered = peek_client_hello_ticket_offered(raw) if resumption and index == 2 else False
            with active_context.wrap_socket(raw, server_side=True) as connection:
                der = connection.getpeercert(binary_form=True)
                event("handshake", index=index, version=connection.version(), cipher=connection.cipher()[0], alpn=connection.selected_alpn_protocol(), client_der_b64=base64.b64encode(der).decode() if der else None, session_reused=connection.session_reused, ticket_offered=ticket_offered)
                if args.mode == "http1":
                    http1(connection, args.large)
                elif args.mode == "resumption":
                    http1(connection, False, b"/resumption")
                elif args.mode == "resumption-h2":
                    http2(connection, True, streaming=True)
                elif args.mode == "resumption-wss":
                    websocket(connection, b"resume-echo")
                elif args.mode == "resumption-sse":
                    sse(connection, index)
                elif args.mode == "h2":
                    http2(connection, args.large)
                elif args.mode == "wss":
                    websocket(connection)
                else:
                    sse(connection, index)
                if args.mode in ("h2", "resumption-h2"):
                    if not select.select([sys.stdin], [], [], 10)[0] or sys.stdin.buffer.readline() != b"go\n":
                        raise ValueError("missing_h2_release")
                    event("released")
                if args.mode not in ("sse", "resumption-sse"):
                    try:
                        connection.unwrap().close()
                    except (ssl.SSLError, OSError, EOFError):
                        pass
        except (ssl.SSLError, OSError, EOFError, ValueError) as error:
            event("failure", kind_name=type(error).__name__, detail=str(error))
            raw.close()
    listener.close()


if __name__ == "__main__":
    main()

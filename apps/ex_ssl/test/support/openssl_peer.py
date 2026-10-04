#!/usr/bin/env python3
"""Bounded independent OpenSSL test peer; emits metadata only as newline JSON."""

import argparse
import base64
import json
import select
import socket
import ssl
import sys
import time

MAX_BODY = 4 * 1024 * 1024


def announce(kind, **fields):
    sys.stdout.write(json.dumps({"kind": kind, **fields}, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def read_exact(connection, count):
    parts = []
    remaining = count
    while remaining:
        chunk = connection.recv(min(remaining, 64 * 1024))
        if not chunk:
            raise EOFError("incomplete bounded request")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def exchange(connection, mode, delay_ms):
    if mode == "echo":
        length = int.from_bytes(read_exact(connection, 4), "big")
        if length > MAX_BODY:
            raise ValueError("request too large")
        body = read_exact(connection, length)
        response = len(body).to_bytes(4, "big") + body
        if delay_ms:
            for index in range(0, len(response), 16 * 1024):
                connection.sendall(response[index : index + 16 * 1024])
                time.sleep(delay_ms / 1000)
        else:
            connection.sendall(response)
        announce("exchange", bytes=length)
    else:
        request = bytearray()
        while b"\r\n\r\n" not in request:
            if len(request) >= 64 * 1024:
                raise ValueError("HTTP headers too large")
            chunk = connection.recv(4096)
            if not chunk:
                raise EOFError("incomplete HTTP headers")
            request.extend(chunk)
        header, body = bytes(request).split(b"\r\n\r\n", 1)
        content_length = 0
        for line in header.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
        if content_length > MAX_BODY or len(body) > content_length:
            raise ValueError("HTTP body too large")
        if len(body) < content_length:
            read_exact(connection, content_length - len(body))
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong")
        announce("exchange", bytes=content_length)


def make_context(args, versions):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = versions[args.min_version]
    context.maximum_version = versions[args.max_version]
    context.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_RENEGOTIATION
    context.load_cert_chain(args.certfile, args.keyfile)
    context.set_ciphers(args.cipher)
    if args.alpn:
        context.set_alpn_protocols(args.alpn.split(","))
    if args.verify != "none":
        if not args.cafile:
            raise ValueError("client verification needs a CA file")
        context.load_verify_locations(cafile=args.cafile)
        context.verify_mode = ssl.CERT_REQUIRED if args.verify == "required" else ssl.CERT_OPTIONAL

    if args.group:
        context.set_ecdh_curve(args.group)
    return context


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--certfile", required=True)
    parser.add_argument("--keyfile", required=True)
    parser.add_argument("--cafile")
    parser.add_argument("--min-version", choices=["tls12", "tls13"], required=True)
    parser.add_argument("--max-version", choices=["tls12", "tls13"], required=True)
    parser.add_argument("--cipher", default="ECDHE-RSA-AES128-GCM-SHA256")
    parser.add_argument("--alpn", default="")
    parser.add_argument("--verify", choices=["none", "optional", "required"], default="none")
    parser.add_argument("--mode", choices=["echo", "http1"], default="echo")
    parser.add_argument("--max-connections", type=int, default=1)
    parser.add_argument("--delay-ms", type=int, default=0)
    parser.add_argument("--group")
    parser.add_argument("--restart-context", default="false", choices=["false", "true"])
    parser.add_argument("--abrupt-close", default="false", choices=["false", "true"])
    args = parser.parse_args()

    if args.max_connections not in range(1, 33) or args.delay_ms not in range(0, 1001):
        parser.error("invalid bounded fixture setting")
    versions = {"tls12": ssl.TLSVersion.TLSv1_2, "tls13": ssl.TLSVersion.TLSv1_3}
    if versions[args.min_version] > versions[args.max_version]:
        parser.error("invalid TLS version range")

    context = make_context(args, versions)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.5)
    announce("ready", port=listener.getsockname()[1], openssl=ssl.OPENSSL_VERSION)

    accepted = 0
    deadline = time.monotonic() + 45
    while accepted < args.max_connections and time.monotonic() < deadline:
        try:
            raw, _address = listener.accept()
        except socket.timeout:
            continue
        accepted += 1
        raw.settimeout(10)
        if args.restart_context == "true" and accepted > 1:
            context = make_context(args, versions)
        try:
            with context.wrap_socket(raw, server_side=True) as connection:
                der = connection.getpeercert(binary_form=True)
                announce(
                    "handshake",
                    version=connection.version(),
                    resumed=connection.session_reused,
                    cipher=connection.cipher()[0],
                    alpn=connection.selected_alpn_protocol(),
                    client_der_b64=base64.b64encode(der).decode("ascii") if der else None,
                )
                exchange(connection, args.mode, args.delay_ms)
                if args.abrupt_close == "true":
                    # The test first acknowledges the plaintext, then releases
                    # this barrier to test TCP truncation independently of timing.
                    announce("close_ready")
                    ready, _, _ = select.select([sys.stdin], [], [], 10)
                    if not ready or sys.stdin.readline().strip() != "close":
                        raise ValueError("missing close barrier")
                    # Close TCP after acknowledged application output without
                    # generating close_notify. This is deliberate truncation.
                    socket.socket(fileno=connection.detach()).close()
                    continue
                # Send close_notify so buffered application records remain usable
                # after the transport closes. The client closes after its reply.
                try:
                    connection.unwrap().close()
                except (ssl.SSLError, OSError, socket.timeout):
                    pass
        except (ssl.SSLError, OSError, EOFError, ValueError) as error:
            announce("failure", error=type(error).__name__)
            raw.close()
    listener.close()


if __name__ == "__main__":
    main()

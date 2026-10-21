#!/usr/bin/env python3
"""Bounded localhost TLS1.3 H1 peer, controlled using JSON lines on stdin/stdout."""
import argparse
import hashlib
import json
import platform
import socket
import ssl
import sys
import threading
import time

PAYLOAD = b"Z" * 1_048_576
MAX_REQUESTS = 2000


class Peer:
    def __init__(self, cert, key):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.num_tickets = 0
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.sockets = set()
        self.workers = []
        self.counters = {"accepted": 0, "closed": 0, "requests": 0,
                         "upload_bytes": 0, "download_bytes": 0}
        self.errors = []
        self.exchanges = {}
        self.handshakes = []

    def start(self):
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()

    def accept(self):
        while not self.stopping.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.counters["accepted"] += 1
                connection_id = self.counters["accepted"]
                if connection_id > MAX_REQUESTS:
                    raw.close()
                    self.errors.append("connection limit")
                    continue
                self.sockets.add(raw)
            worker = threading.Thread(target=self.serve, args=(raw, connection_id), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, raw, connection_id):
        conn = raw
        try:
            raw.settimeout(6)
            started = time.perf_counter_ns()
            conn = self.context.wrap_socket(raw, server_side=True)
            handshake_us = (time.perf_counter_ns() - started) / 1000
            with self.lock:
                self.sockets.discard(raw)
                self.sockets.add(conn)
            if conn.version() != "TLSv1.3" or conn.selected_alpn_protocol() != "http/1.1":
                raise ValueError("unexpected TLS version/ALPN")
            first = True
            stream = conn.makefile("rb")
            try:
                for _ in range(MAX_REQUESTS):
                    line = stream.readline(4097)
                    if not line:
                        break
                    if len(line) > 4096 or not line.endswith(b"\r\n"):
                        raise ValueError("invalid request line")
                    method, path, version = line.decode("ascii").strip().split(" ")
                    if version != "HTTP/1.1":
                        raise ValueError("not H1.1")
                    headers = {}
                    budget = 0
                    while True:
                        line = stream.readline(8193)
                        budget += len(line)
                        if budget > 32768 or not line.endswith(b"\r\n"):
                            raise ValueError("invalid headers")
                        if line == b"\r\n":
                            break
                        name, value = line.decode("ascii").split(":", 1)
                        name = name.lower()
                        if name in headers:
                            raise ValueError("duplicate header")
                        headers[name] = value.strip()
                    if "transfer-encoding" in headers:
                        raise ValueError("chunked uploads not in benchmark contract")
                    length = int(headers.get("content-length", "0"))
                    if length < 0 or length > len(PAYLOAD):
                        raise ValueError("invalid upload length")
                    body = stream.read(length)
                    if len(body) != length:
                        raise ValueError("truncated upload")
                    _, backend, workload, operation = path.split("/")
                    if backend not in ("ssl", "ex_ssl") or workload not in ("cold", "upload", "download", "reuse"):
                        raise ValueError("unknown workload")
                    if operation == "upload" and method == "POST" and body == PAYLOAD:
                        response = hashlib.sha256(body).hexdigest().encode("ascii")
                    elif operation == "download" and method == "GET" and not body:
                        response = PAYLOAD
                    elif operation in ("small", "close") and method == "GET" and not body:
                        response = b"ok"
                    else:
                        raise ValueError("incorrect method/body/operation")
                    close = operation == "close" or headers.get("connection", "").lower() == "close"
                    connection = "close" if close else "keep-alive"
                    head = (f"HTTP/1.1 200 OK\r\nContent-Length: {len(response)}\r\n"
                            f"Connection: {connection}\r\nX-Benchmark-Connection: {connection_id}\r\n"
                            "Content-Type: application/octet-stream\r\n\r\n").encode("ascii")
                    # Count before send so stats after a received response include it.
                    with self.lock:
                        if self.counters["requests"] >= MAX_REQUESTS:
                            raise ValueError("request limit")
                        self.counters["requests"] += 1
                        self.counters["upload_bytes"] += len(body)
                        self.counters["download_bytes"] += len(response)
                        self.exchanges[path] = self.exchanges.get(path, 0) + 1
                        if first:
                            self.handshakes.append({"backend": backend, "workload": workload,
                                                    "connection": connection_id,
                                                    "server_accept_to_handshake_us": handshake_us,
                                                    "tls": conn.version(), "alpn": conn.selected_alpn_protocol(),
                                                    "cipher": conn.cipher()[0], "resumed": conn.session_reused})
                            first = False
                    conn.sendall(head + response)
                    if close:
                        break
                else:
                    raise ValueError("per-connection request limit")
            finally:
                stream.close()
        except (OSError, ValueError, ssl.SSLError) as exc:
            if not self.stopping.is_set():
                with self.lock:
                    self.errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            conn.close()
            with self.lock:
                self.sockets.discard(raw)
                self.sockets.discard(conn)
                self.counters["closed"] += 1

    def stats(self):
        with self.lock:
            return {**self.counters, "active": len(self.sockets), "errors": list(self.errors),
                    "exchanges": dict(self.exchanges), "handshakes": list(self.handshakes)}

    def stop(self):
        self.stopping.set()
        self.listener.close()
        with self.lock:
            sockets = list(self.sockets)
        for conn in sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        self.acceptor.join(1)
        deadline = time.monotonic() + 2
        for worker in self.workers:
            worker.join(max(0, deadline - time.monotonic()))


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    peer = Peer(args.cert, args.key)
    peer.start()
    emit({"event": "ready", "port": peer.listener.getsockname()[1],
          "python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
          "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(), "max_requests": MAX_REQUESTS})
    try:
        for line in sys.stdin:
            if len(line) > 1024:
                raise ValueError("oversized control command")
            command = json.loads(line)
            if command == {"command": "stats"}:
                emit(peer.stats())
            elif command == {"command": "stop"}:
                peer.stop()
                emit({"event": "stopped", **peer.stats()})
                break
            else:
                raise ValueError("unknown control command")
    finally:
        peer.stop()


if __name__ == "__main__":
    main()

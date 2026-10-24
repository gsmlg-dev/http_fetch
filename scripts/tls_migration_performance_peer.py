#!/usr/bin/env python3
"""Bounded independent OpenSSL/hyper-h2 P4 peer; JSON-line control, loopback only.

Gate files acknowledge H1 no-read/H2 zero-window upload blocking. No client
private socket inspection is necessary. Importing this module has no effects.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import ssl
import sys
import threading
import time

PAYLOAD = b"Z" * 1_048_576
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()
MAX_REQUESTS = 2_000_000
MAX_CONNECTIONS = 512
MAX_HEADER_BYTES = 32_768


def parse_path(path):
    match = re.fullmatch(r"/perf/([mw]-[a-zA-Z0-9-]{1,80})/(cold|reuse|upload|download|cancel)", path)
    if not match:
        raise ValueError("invalid performance path")
    return match.groups()


def response_body(operation, body):
    if operation == "upload":
        if body != PAYLOAD:
            raise ValueError("incorrect 1MiB upload")
        return PAYLOAD_SHA.encode()
    if body:
        raise ValueError("unexpected request body")
    return PAYLOAD if operation == "download" else b"ok"


class Peer:
    def __init__(self, args):
        self.args = args
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        version = ssl.TLSVersion.TLSv1_2 if args.tls == "TLSv1.2" else ssl.TLSVersion.TLSv1_3
        self.context.minimum_version = self.context.maximum_version = version
        self.context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
        self.context.set_alpn_protocols([args.protocol])
        self.context.options |= ssl.OP_NO_TICKET
        self.context.load_cert_chain(args.cert, args.key)
        if version == ssl.TLSVersion.TLSv1_3:
            self.context.num_tickets = 0
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.sockets = set()
        self.workers = set()
        self.acceptor = None
        self.started = time.monotonic()
        self.state = Path(args.state_dir)
        self.state.mkdir(parents=True, exist_ok=True)
        self.identity = hashlib.sha256(Path(__file__).read_bytes() + Path(args.cert).read_bytes() + args.tls.encode() + args.protocol.encode()).hexdigest()
        self.reset()
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(256)
        self.listener.settimeout(0.2)

    def reset(self):
        with self.lock:
            if self.sockets or self.workers:
                raise ValueError("cannot reset active peer")
            self.requests = {}
            self.handshakes = []
            self.errors = []
            self.accepted = self.closed = 0
        for path in self.state.glob("*-gate.json"):
            path.unlink()
        for path in self.state.glob("*-release"):
            path.unlink()

    def error(self, reason):
        with self.lock:
            if len(self.errors) < 100:
                self.errors.append(reason)
            self.stopping.set()

    def start(self):
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()
        return dict(event="ready", port=self.listener.getsockname()[1], identity=self.identity,
                    tls=self.args.tls, alpn=self.args.protocol, openssl=ssl.OPENSSL_VERSION,
                    payload_sha256=PAYLOAD_SHA)

    def accept(self):
        while not self.stopping.is_set():
            if time.monotonic() - self.started > self.args.lifetime:
                self.error("bounded peer lifetime exceeded")
                break
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                if len(self.sockets) >= MAX_CONNECTIONS:
                    raw.close()
                    self.errors.append("live connection bound exceeded")
                    continue
                self.accepted += 1
                cid = self.accepted
                self.sockets.add(raw)
                worker = threading.Thread(target=self.serve, args=(raw, cid), daemon=True)
                self.workers.add(worker)
            worker.start()

    def begin(self, path, cid, method):
        identifier, operation = parse_path(path)
        if method != ("POST" if operation in ("upload", "cancel") else "GET"):
            raise ValueError("incorrect request method")
        with self.lock:
            if identifier in self.requests or len(self.requests) >= MAX_REQUESTS:
                raise ValueError("duplicate/replayed request or request bound")
            record = dict(id=identifier, connection=cid, operation=operation,
                          completed=False, cancelled=False, payload_ok=False,
                          upload_bytes=0, download_bytes=0)
            self.requests[identifier] = record
        return record

    def complete(self, record, body):
        response = response_body(record["operation"], body)
        with self.lock:
            record.update(completed=True, payload_ok=True,
                          upload_bytes=len(body), download_bytes=len(response) if record["operation"] == "download" else 0)
        return response

    def gate(self, record):
        path = self.state / (record["id"] + "-gate.json")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(dict(peer_gate=True, connection=record["connection"],
                                            operation="cancel", tls=self.args.tls,
                                            alpn=self.args.protocol, withheld_window=self.args.protocol == "h2")))
        temporary.replace(path)

    def cancelled(self, record):
        with self.lock:
            record.update(cancelled=True, completed=False, payload_ok=True)

    def serve(self, raw, cid):
        conn = raw
        pending_cancel = []
        try:
            raw.settimeout(15)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn = self.context.wrap_socket(raw, server_side=True)
            conn.settimeout(65)
            with self.lock:
                self.sockets.discard(raw)
                self.sockets.add(conn)
                self.handshakes.append(dict(connection=cid, tls=conn.version(),
                    alpn=conn.selected_alpn_protocol(), cipher=conn.cipher()[0], resumed=conn.session_reused))
            if conn.version() != self.args.tls or conn.selected_alpn_protocol() != self.args.protocol:
                raise ValueError("negotiated TLS/ALPN mismatch")
            if self.args.protocol == "h2":
                self.h2(conn, cid, pending_cancel)
            else:
                self.h1(conn, cid, pending_cancel)
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError):
            with self.lock:
                incomplete = any(r["connection"] == cid and not r["completed"] and not r["cancelled"] for r in self.requests.values())
            if incomplete and not pending_cancel:
                self.error("unexpected peer connection reset")
        except Exception as exc:
            if not self.stopping.is_set():
                self.error(type(exc).__name__ + ": " + str(exc))
        finally:
            for record in pending_cancel:
                self.cancelled(record)
            try:
                conn.close()
            finally:
                raw.close()
            with self.lock:
                self.sockets.discard(raw)
                self.sockets.discard(conn)
                self.closed += 1
                self.workers.discard(threading.current_thread())

    @staticmethod
    def read_header(conn):
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            part = conn.recv(1)
            if not part:
                if not head:
                    return None
                raise ValueError("truncated request header")
            head.extend(part)
            if len(head) > MAX_HEADER_BYTES:
                raise ValueError("header bound exceeded")
        return bytes(head)

    def h1(self, conn, cid, pending_cancel):
        for _ in range(MAX_REQUESTS):
            head = self.read_header(conn)
            if head is None:
                return
            lines = head.decode("ascii").split("\r\n")
            method, path, version = lines[0].split(" ")
            if version != "HTTP/1.1":
                raise ValueError("wrong HTTP version")
            headers = {}
            for line in lines[1:-2]:
                name, value = line.split(":", 1)
                name = name.lower()
                if name in headers:
                    raise ValueError("duplicate header")
                headers[name] = value.strip()
            record = self.begin(path, cid, method)
            if record["operation"] == "cancel":
                pending_cancel.append(record)
                self.gate(record)
                release = self.state / (record["id"] + "-release")
                deadline = time.monotonic() + 15
                # Deliberately NO reads (including TLS) until public client cancel.
                while not release.exists() and not self.stopping.wait(0.01):
                    if time.monotonic() >= deadline:
                        raise TimeoutError("cancellation release deadline")
                conn.settimeout(2)
                drained = 0
                while drained <= 512 * 1024**2:
                    part = conn.recv(65_536)
                    if not part:
                        self.cancelled(record)
                        return
                    drained += len(part)
                raise ValueError("cancel producer exceeded fixed bound")
            if "transfer-encoding" in headers:
                raise ValueError("ordinary measurement requires exact Content-Length")
            size = int(headers.get("content-length", "0"))
            if size < 0 or size > len(PAYLOAD):
                raise ValueError("upload bound exceeded")
            body = bytearray()
            while len(body) < size:
                part = conn.recv(min(65_536, size - len(body)))
                if not part:
                    raise ValueError("truncated upload")
                body.extend(part)
            response = self.complete(record, bytes(body))
            close = headers.get("connection", "").lower() == "close"
            connection = "close" if close else "keep-alive"
            encoded = (f"HTTP/1.1 200 OK\r\nContent-Length: {len(response)}\r\nConnection: {connection}\r\nX-Performance-Connection: {cid}\r\n\r\n").encode()
            conn.sendall(encoded + response)
            if close:
                return
        raise ValueError("connection request bound exceeded")

    def h2(self, conn, cid, pending_cancel):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset, ConnectionTerminated
        from h2.settings import Settings, SettingCodes
        h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        settings = {SettingCodes.MAX_CONCURRENT_STREAMS: 128}
        if self.args.workload == "cancel":
            settings[SettingCodes.INITIAL_WINDOW_SIZE] = 0
        h2.local_settings = Settings(client=False, initial_values=settings)
        h2.initiate_connection()
        conn.sendall(h2.data_to_send())
        streams, output = {}, {}
        while not self.stopping.is_set():
            data = conn.recv(65_536)
            if not data:
                return
            for event in h2.receive_data(data):
                if isinstance(event, RequestReceived):
                    if len(streams) >= 128 or sum(len(n) + len(v) for n, v in event.headers) > MAX_HEADER_BYTES:
                        raise ValueError("H2 active stream/header bound")
                    headers = dict(event.headers)
                    record = self.begin(headers[":path"], cid, headers[":method"])
                    streams[event.stream_id] = [record, bytearray()]
                    if record["operation"] == "cancel":
                        pending_cancel.append(record)
                        self.gate(record)
                elif isinstance(event, DataReceived):
                    record, body = streams[event.stream_id]
                    if record["operation"] == "cancel":
                        # Initial SETTINGS may race first DATA; no flow-control ACK.
                        if len(body) + len(event.data) > 65_535:
                            raise ValueError("client exceeded withheld upload window")
                    elif len(body) + len(event.data) > len(PAYLOAD):
                        raise ValueError("H2 upload bound")
                    body.extend(event.data)
                    if record["operation"] != "cancel":
                        h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamEnded):
                    record, body = streams.pop(event.stream_id)
                    if record["operation"] == "cancel":
                        raise ValueError("blocked cancel upload unexpectedly completed")
                    response = self.complete(record, bytes(body))
                    h2.send_headers(event.stream_id, [(":status", "200"), ("content-length", str(len(response))), ("x-performance-connection", str(cid))])
                    output[event.stream_id] = [response, 0]
                elif isinstance(event, StreamReset):
                    value = streams.pop(event.stream_id, None)
                    output.pop(event.stream_id, None)
                    if value and value[0]["operation"] == "cancel":
                        self.cancelled(value[0])
                    elif value:
                        raise ValueError("ordinary H2 request reset")
                elif isinstance(event, ConnectionTerminated):
                    return
            progress = True
            while progress:
                progress = False
                for sid, (body, offset) in list(output.items()):
                    size = min(len(body) - offset, h2.local_flow_control_window(sid), h2.max_outbound_frame_size)
                    if size > 0:
                        end = offset + size == len(body)
                        h2.send_data(sid, body[offset:offset + size], end_stream=end)
                        progress = True
                        if end:
                            del output[sid]
                        else:
                            output[sid][1] += size
                data = h2.data_to_send()
                if data:
                    conn.sendall(data)

    def stats(self):
        with self.lock:
            measured = [dict(r) for r in self.requests.values() if r["id"].startswith("m-")]
            warmup = [r for r in self.requests.values() if r["id"].startswith("w-")]
            ciphers = {h["cipher"] for h in self.handshakes}
            return dict(event="stats", identity=self.identity, tls=self.args.tls, alpn=self.args.protocol,
                        cipher=next(iter(ciphers)) if len(ciphers) == 1 else None,
                        resumed=any(h["resumed"] for h in self.handshakes), errors=list(self.errors),
                        handshakes=list(self.handshakes), requests=measured, warmup_requests=len(warmup),
                        accepted_connections=self.accepted, closed_connections=self.closed,
                        active_connections=len(self.sockets),
                        upload_bytes=sum(r["upload_bytes"] for r in measured),
                        download_bytes=sum(r["download_bytes"] for r in measured))

    def stop(self):
        self.stopping.set()
        self.listener.close()
        with self.lock:
            sockets = list(self.sockets)
            workers = list(self.workers)
        for conn in sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        for worker in workers:
            worker.join(timeout=2)
        if self.acceptor:
            self.acceptor.join(timeout=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--protocol", choices=("http/1.1", "h2"), required=True)
    parser.add_argument("--tls", choices=("TLSv1.2", "TLSv1.3"), required=True)
    parser.add_argument("--workload", choices=("cold", "reuse", "upload", "download", "cancel"), required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--lifetime", type=int, default=18_000)
    args = parser.parse_args()
    if not 1 <= args.lifetime <= 86_400:
        parser.error("lifetime must be 1..86400s")
    peer = Peer(args)
    try:
        print(json.dumps(peer.start()), flush=True)
        for line in sys.stdin:
            if len(line) > 1024:
                raise ValueError("control input bound")
            command = json.loads(line)["command"]
            if command == "stats":
                result = peer.stats()
            elif command == "reset":
                peer.reset()
                result = dict(event="reset")
            elif command == "stop":
                print(json.dumps(dict(event="stop")), flush=True)
                break
            else:
                raise ValueError("invalid control command")
            print(json.dumps(result), flush=True)
    finally:
        peer.stop()


if __name__ == "__main__":
    main()

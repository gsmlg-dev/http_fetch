"""Finite HTTP/1 upstream for the pinned Caddy HTTP/3 acceptance peer."""
import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import select
import socket
import sys


class Peer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    body_limit = 16 * 1024 * 1024

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = []
            total = 0
            while True:
                line = self.rfile.readline(130)
                if len(line) > 128 or not line.endswith(b"\r\n"):
                    raise ValueError("invalid upstream chunk size")
                size = int(line.split(b";", 1)[0], 16)
                if size < 0 or total + size > self.body_limit:
                    raise ValueError("upstream body limit")
                if size == 0:
                    for _ in range(128):
                        trailer = self.rfile.readline(8194)
                        if trailer == b"\r\n":
                            return b"".join(chunks)
                        if len(trailer) > 8192 or not trailer.endswith(b"\r\n"):
                            raise ValueError("invalid upstream trailer")
                    raise ValueError("upstream trailer limit")
                chunk = self.rfile.read(size)
                if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                    raise ValueError("truncated upstream chunk")
                chunks.append(chunk)
                total += size
        size = int(self.headers.get("Content-Length", "0"))
        if size < 0 or size > self.body_limit:
            raise ValueError("upstream body limit")
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError("truncated upstream body")
        return body

    def run_request(self):
        path = self.path.split("?", 1)[0]
        self.diagnostic("request", path=path,
                        content_length=self.headers.get("Content-Length"),
                        transfer_encoding=self.headers.get("Transfer-Encoding"))
        if path == "/early":
            self.reply(b"early", status=413, close=True)
            return
        body = self.read_body()
        self.diagnostic("body", path=path, decoded_bytes=len(body))
        if path == "/hold":
            while True:
                readable, _, _ = select.select([self.connection], [], [], 1)
                if readable and not self.connection.recv(1, socket.MSG_PEEK):
                    return
        elif path == "/empty":
            body = b""
        elif path == "/large":
            body = bytes(range(256)) * 32768
        elif path == "/digest":
            body = hashlib.sha256(body).hexdigest().encode()
        elif path == "/sse":
            body = b"id: 42\ndata: h3-event\n\n"
        elif path == "/trailers":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Trailer", "X-Checksum")
            self.end_headers()
            self.wfile.write(b"3\r\nabc\r\n0\r\nX-Checksum: " + hashlib.sha256(b"abc").hexdigest().encode() + b"\r\n\r\n")
            return
        else:
            body = body or b"caddy HTTP/3"
        if path == "/informational":
            self.wfile.write(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
        self.reply(body, content_type="text/event-stream" if path == "/sse" else None)

    def reply(self, body, status=200, close=False, content_type=None):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        if content_type:
            self.send_header("Content-Type", content_type)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = run_request
    do_HEAD = run_request
    do_POST = run_request
    do_PUT = run_request

    def log_message(self, *_args):
        pass

    def diagnostic(self, event, **fields):
        print(json.dumps({"event": event, **fields}), file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Peer)
    print(server.server_port, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

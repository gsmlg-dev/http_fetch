"""Independent HTTPS-over-TCP HTTP/1.1 origin that advertises an Alt-Svc value.

Uses only the Python standard library (`http.server` + `ssl`). Every response
carries `Alt-Svc: <value>` and `x-peer: python-ssl-h1`. Paths mirror the
aioquic peer so the same byte-integrity checks apply on either protocol:
`/large` returns bytes(range(256)) * 32768, POST `/digest` returns the request
body's SHA-256 hex digest, anything else returns `python-ssl-h1`.
Prints the bound TCP port on stdout once listening.
"""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    alt_svc = ""

    def log_message(self, *_args):
        pass

    def reply(self, body):
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.send_header("x-peer", "python-ssl-h1")
        self.send_header("alt-svc", self.alt_svc)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(bytes(range(256)) * 32768 if self.path == "/large" else b"python-ssl-h1")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        if self.path == "/digest":
            self.reply(hashlib.sha256(body).hexdigest().encode())
        else:
            self.reply(body)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def shutdown_request(self, request):
        # The stdlib default issues a raw TCP SHUT_WR without TLS close_notify;
        # the subsequent close can then reset the peer before it reads the
        # response. Send close_notify first.
        try:
            request.unwrap()
        except (OSError, ValueError):
            pass
        self.close_request(request)


def main(args):
    Handler.alt_svc = args.alt_svc
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(args.cert, args.key)
    server = Server(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("alt_svc")
    main(parser.parse_args())

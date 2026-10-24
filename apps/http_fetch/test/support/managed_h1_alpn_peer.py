"""Independent verified-TLS managed-H1 ALPN, reuse and no-replay fixture."""
import argparse
import json
import select
import socket
import ssl
import sys


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields)), flush=True)


def request(sock, pending):
    while b"\r\n\r\n" not in pending:
        data = sock.recv(65536)
        assert data, "request closed before headers"
        pending += data
    head, pending = pending.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    fields = [line.split(b":", 1) for line in lines[1:]]
    headers = {key.lower(): value.strip() for key, value in fields}
    size = int(headers.get(b"content-length", b"0"))
    while len(pending) < size:
        data = sock.recv(65536)
        assert data, "request closed before body"
        pending += data
    body, pending = pending[:size], pending[size:]
    emit("request", line=lines[0].decode("ascii"),
         host=headers[b"host"].decode("ascii"), body=body.hex(),
         content_length=headers.get(b"content-length", b"").decode("ascii"))
    return pending


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("--drop", action="store_true")
    parser.add_argument("--version", choices=["tls12", "tls13"])
    parser.add_argument("--requests", type=int, choices=[1, 2], default=2)
    parser.add_argument("--gate-response", type=int, choices=[1, 2])
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    if args.version:
        version = {"tls12": ssl.TLSVersion.TLSv1_2,
                   "tls13": ssl.TLSVersion.TLSv1_3}[args.version]
        context.minimum_version = version
        context.maximum_version = version
    context.set_alpn_protocols(["http/1.1"])
    context.set_servername_callback(lambda sock, name, _context: setattr(sock, "sni", name))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        emit("ready", port=listener.getsockname()[1])
        raw, _ = listener.accept()
        with context.wrap_socket(raw, server_side=True) as sock:
            sock.settimeout(5)
            details = {"version": sock.version()} if args.version else {}
            emit("tls", alpn=sock.selected_alpn_protocol(), sni=sock.sni, **details)
            pending = b""
            for index in range(args.requests):
                pending = request(sock, pending)
                if args.drop and index == 1:
                    break
                if args.gate_response == index + 1:
                    emit("response_waiting", request=index + 1)
                    assert select.select([sys.stdin], [], [], 5)[0], "response gate expired"
                    assert sys.stdin.readline() == "respond\n", "invalid response gate command"
                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\x00\xff\n\r")
            assert pending == b"", "unexpected pipelined or replayed bytes"
            if not args.drop:
                try:
                    assert sock.recv(1) == b"", "unexpected request after retirement"
                    closure = "eof"
                except ConnectionResetError:
                    # Managed retirement may abort the underlying TCP socket.
                    # This check runs only after both exact requests and replies.
                    closure = "reset"
                emit("closed", transport=closure)
        listener.settimeout(0.3)
        try:
            replay, _ = listener.accept()
        except TimeoutError:
            emit("complete", connections=1, requests=args.requests)
        else:
            replay.close()
            raise AssertionError("request replay or unexpected second connection")


if __name__ == "__main__":
    main()

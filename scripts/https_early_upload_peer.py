"""Independent TLS peer that stops all socket reads after HTTP request headers.

OTP's TLS receiver may read ahead even with application active:false, so it cannot
reliably force a native client send timeout. This subprocess has no background
receiver. Its only control command is `drain`; all input and runtime waits are bounded.
"""

import argparse
import json
import socket
import ssl
import sys
import time


def event(kind, **fields):
    print(json.dumps({"kind": kind, **fields}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(["http/1.1"])

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        listener.settimeout(10)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        event("listen", port=listener.getsockname()[1])
        raw, _ = listener.accept()
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        raw.settimeout(5)
        with context.wrap_socket(raw, server_side=True) as connection:
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                if len(head) >= 16384:
                    raise ValueError("request headers too large")
                part = connection.recv(1)
                if not part:
                    raise EOFError("request headers truncated")
                head.extend(part)
            if not head.startswith(b"POST /upload HTTP/1.1\r\n"):
                raise ValueError("unexpected request")
            event("ready")
            # No reads on the TLS/TCP socket occur until the test permits drain.
            command = sys.stdin.readline(64)
            if not command:
                return
            if command != "drain\n":
                raise ValueError("unexpected control command")
            total = 0
            deadline = time.monotonic() + 2
            while total <= 16 * 1024 * 1024:
                try:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    connection.settimeout(remaining)
                    data = connection.recv(65536)
                except TimeoutError:
                    event("drain_timeout", drained_bytes=total,
                          receive_buffer=connection.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
                    raise SystemExit(1)
                except (ConnectionResetError, ssl.SSLError):
                    event("closed", drained_bytes=total)
                    return
                if not data:
                    event("closed", drained_bytes=total)
                    return
                total += len(data)
            raise ValueError("unbounded pending upload")


if __name__ == "__main__":
    main()

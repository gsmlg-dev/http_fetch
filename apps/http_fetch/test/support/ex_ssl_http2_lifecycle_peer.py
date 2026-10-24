#!/usr/bin/env python3
"""Authenticated no-ALPN peer: hold until client cleanup, count every HTTP byte.

JSON-line stats/stop controls and a bounded lifetime match the H2 test harness.
A missing ALPN is the intended test condition; any application data is a failure.
"""
import argparse
import json
import socket
import select
import ssl
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--tls', choices=['TLSv1.2', 'TLSv1.3'], required=True)
    parser.add_argument('--protocol', choices=['http/1.1'], required=True)
    parser.add_argument('--workload')
    parser.add_argument('--state-dir')
    parser.add_argument('--lifetime', type=float, default=120)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    version = getattr(ssl.TLSVersion, args.tls.replace('.', '_'))
    context.minimum_version = context.maximum_version = version
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.set_alpn_protocols(['http/1.1'])
    context.options |= ssl.OP_NO_TICKET
    if args.tls == 'TLSv1.3':
        context.num_tickets = 0
    context.load_cert_chain(args.cert, args.key)
    stop = threading.Event()
    lock = threading.Lock()
    stats = dict(accepted_connections=0, closed_connections=0,
                 active_connections=0, handshakes=[], requests=[], errors=[], http_bytes=0)
    sockets, workers = set(), []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    listener.settimeout(.1)
    expires = time.monotonic() + args.lifetime

    def serve(raw, cid):
        conn = raw
        try:
            raw.settimeout(5)
            conn = context.wrap_socket(raw, server_side=True)
            with lock:
                sockets.discard(raw)
                sockets.add(conn)
                stats['handshakes'].append(dict(connection=cid, tls=conn.version(),
                    alpn=conn.selected_alpn_protocol(), cipher=conn.cipher()[0]))
            if conn.version() != args.tls or conn.selected_alpn_protocol() is not None:
                raise ValueError('expected exact TLS version with no ALPN')
            conn.settimeout(.1)
            while not stop.is_set():
                try:
                    data = conn.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                with lock:
                    stats['http_bytes'] += len(data)
                raise ValueError('application bytes received without h2')
        except (ConnectionResetError, ssl.SSLEOFError):
            pass
        except Exception as exc:
            if not stop.is_set():
                with lock:
                    stats['errors'].append(type(exc).__name__ + ': ' + str(exc))
        finally:
            conn.close()
            raw.close()
            with lock:
                sockets.discard(raw)
                sockets.discard(conn)
                stats['closed_connections'] += 1
                stats['active_connections'] -= 1

    def accept():
        while not stop.is_set() and time.monotonic() < expires:
            try:
                raw, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with lock:
                stats['accepted_connections'] += 1
                stats['active_connections'] += 1
                cid = stats['accepted_connections']
                sockets.add(raw)
            worker = threading.Thread(target=serve, args=(raw, cid))
            workers.append(worker)
            worker.start()
        stop.set()

    acceptor = threading.Thread(target=accept)
    acceptor.start()
    print(json.dumps(dict(event='ready', port=listener.getsockname()[1], tls=args.tls)), flush=True)
    try:
        while not stop.is_set():
            remaining = expires - time.monotonic()
            if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
                raise TimeoutError('bounded peer lifetime exceeded')
            line = sys.stdin.readline()
            if not line:
                break
            command = json.loads(line)['command']
            if command == 'stats':
                with lock:
                    print(json.dumps(dict(event='stats', **stats)), flush=True)
            elif command == 'stop':
                break
            else:
                raise ValueError('unknown command')
    finally:
        stop.set()
        listener.close()
        acceptor.join(1)
        with lock:
            remaining = list(sockets)
        for conn in remaining:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        for worker in workers:
            worker.join(6)
        if acceptor.is_alive() or any(worker.is_alive() for worker in workers):
            raise RuntimeError('peer workers failed to stop')
        print(json.dumps(dict(event='stop')), flush=True)


if __name__ == '__main__':
    main()

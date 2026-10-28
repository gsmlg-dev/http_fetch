#!/usr/bin/env python3
"""Independent bounded OpenSSL/hyper-h2 proxy lifecycle oracle, JSON-line controls."""
import argparse
import base64
import json
import select
import socket
import ssl
import sys
import threading
import time


def request_body(conn, headers, max_body=4 * 1024 * 1024):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            part = conn.recv(min(65536, size - len(data)))
            if not part:
                raise EOFError('incomplete request body')
            data.extend(part)
        return bytes(data)

    if 'transfer-encoding' not in headers:
        try:
            return exact(int(headers.get('content-length', 0)))
        except EOFError:
            # Preserve the original fixed-length peer's incomplete-upload exit.
            return None
    if headers['transfer-encoding'].lower() != 'chunked' or 'content-length' in headers:
        raise ValueError('unsupported or ambiguous transfer coding')

    framing = 0

    def line():
        nonlocal framing
        data = bytearray()
        while not data.endswith(b'\r\n'):
            data.extend(exact(1))
            framing += 1
            if len(data) > 8192 or framing > 32768:
                raise ValueError('chunk framing bound exceeded')
        return bytes(data[:-2])

    body = bytearray()
    while True:
        size = line()
        if not size or any(byte not in b'0123456789abcdefABCDEF' for byte in size):
            raise ValueError('invalid chunk size')
        size = int(size, 16)
        if len(body) + size > max_body:
            raise ValueError('chunked body bound exceeded')
        if size == 0:
            while True:
                trailer = line()
                if not trailer:
                    return bytes(body)
                if b':' not in trailer:
                    raise ValueError('invalid chunk trailer')
        body.extend(exact(size))
        if exact(2) != b'\r\n':
            raise ValueError('invalid chunk terminator')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--tls', choices=['TLSv1.2', 'TLSv1.3'], required=True)
    parser.add_argument('--protocol', choices=['http/1.1', 'h2'], required=True)
    parser.add_argument('--route', choices=['connect', 'forward', 'nested'], default='connect')
    parser.add_argument('--upstream-port', type=int)
    parser.add_argument('--mode', default='normal')
    parser.add_argument('--lifetime', type=int, default=120)
    args = parser.parse_args()
    if args.route == 'nested' and args.upstream_port not in range(1, 65536):
        parser.error('nested route requires a valid upstream port')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    version = getattr(ssl.TLSVersion, args.tls.replace('.', '_'))
    context.minimum_version = context.maximum_version = version
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    context.set_alpn_protocols([args.protocol])
    context.options |= ssl.OP_NO_TICKET
    if args.tls == 'TLSv1.3':
        context.num_tickets = 0
    context.load_cert_chain(args.cert, args.key)
    lock, stop = threading.Lock(), threading.Event()
    state = dict(accepted_connections=0, closed_connections=0, handshakes=[],
                 connects=[], requests=[], resets=[], errors=[])
    sockets, workers = set(), []
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(128)
    listener.settimeout(.1)
    expires = time.monotonic() + args.lifetime

    def head(conn):
        data = bytearray()
        while not data.endswith(b'\r\n\r\n'):
            try:
                part = conn.recv(1)
            except socket.timeout:
                if stop.is_set():
                    return None
                continue
            if not part:
                return None if not data else bytes(data)
            data.extend(part)
            if len(data) > 32768:
                raise ValueError('header bound exceeded')
        return bytes(data)

    def record(cid, sid, method, target, headers, body):
        item = dict(connection=cid, stream=sid, method=method, target=target,
                    headers=dict(headers), body=base64.b64encode(body).decode())
        with lock:
            state['requests'].append(item)
        return item

    def h1(conn, cid):
        for _ in range(100):
            data = head(conn)
            if data is None:
                return
            lines = data.decode('ascii').split('\r\n')
            method, target, _ = lines[0].split(' ')
            headers = [tuple(line.split(': ', 1)) for line in lines[1:-2]]
            body = request_body(conn, dict((k.lower(), v) for k, v in headers))
            if body is None:
                return
            record(cid, 0, method, target, headers, bytes(body))
            if '/hold' in target:
                while not stop.is_set():
                    try:
                        if not conn.recv(65536):
                            return
                    except socket.timeout:
                        continue
                return
            response = bytes(body) if body else b'ok'
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(response)).encode() +
                         b'\r\nX-Proxy-Connection: ' + str(cid).encode() + b'\r\n\r\n' + response)

    def h2(conn, cid):
        import h2.config
        import h2.connection
        import h2.events
        protocol = h2.connection.H2Connection(config=h2.config.H2Configuration(
            client_side=False, header_encoding='utf-8'))
        protocol.initiate_connection()
        conn.sendall(protocol.data_to_send())
        streams = {}
        while not stop.is_set():
            try:
                data = conn.recv(65536)
            except socket.timeout:
                continue
            if not data:
                return
            for event in protocol.receive_data(data):
                if isinstance(event, h2.events.RequestReceived):
                    streams[event.stream_id] = [dict(event.headers), bytearray()]
                elif isinstance(event, h2.events.DataReceived):
                    streams[event.stream_id][1].extend(event.data)
                    protocol.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamReset):
                    with lock:
                        state['resets'].append(dict(connection=cid, stream=event.stream_id,
                                                    error=event.error_code))
                elif isinstance(event, h2.events.StreamEnded):
                    headers, body = streams[event.stream_id]
                    record(cid, event.stream_id, headers[':method'], headers[':path'],
                           headers.items(), bytes(body))
                    if '/hold' not in headers[':path']:
                        response = bytes(body) if body else b'ok'
                        protocol.send_headers(event.stream_id, [(':status', '200'),
                            ('content-length', str(len(response))), ('x-proxy-connection', str(cid))])
                        protocol.send_data(event.stream_id, response, end_stream=True)
            pending = protocol.data_to_send()
            if pending:
                conn.sendall(pending)

    def nested(conn, cid):
        request = head(conn)
        if request is None or not request.startswith(
                f'CONNECT localhost:{args.upstream_port} HTTP/1.1\r\n'.encode()):
            raise ValueError('unexpected CONNECT target')
        with lock:
            state['connects'].append(dict(connection=cid, head=request.decode('ascii')))
        with socket.create_connection(('127.0.0.1', args.upstream_port), timeout=2) as upstream:
            upstream.settimeout(.2)
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            forwarded = 0
            while not stop.is_set() and time.monotonic() < expires:
                ready = [conn] if conn.pending() else select.select([conn, upstream], [], [], .1)[0]
                for source in ready:
                    try:
                        data = source.recv(65536)
                    except socket.timeout:
                        continue
                    if not data:
                        return
                    forwarded += len(data)
                    if forwarded > 4 * 1024 * 1024:
                        raise ValueError('nested tunnel byte bound exceeded')
                    (upstream if source is conn else conn).sendall(data)

    def serve(raw, cid):
        conn = raw
        tls_started = tls_completed = False
        try:
            raw.settimeout(10)
            if args.route == 'connect':
                request = head(raw)
                with lock:
                    state['connects'].append(dict(connection=cid, head=request.decode('ascii')))
                if args.mode == 'pre-upgrade':
                    while raw.recv(65536):
                        pass
                    return
                unsafe = dict(rejected=b'HTTP/1.1 407 Denied\r\n\r\n',
                    oversized=b'HTTP/1.1 200 OK\r\nX: '+b'x'*17000+b'\r\n\r\n',
                    buffered=b'HTTP/1.1 200 OK\r\n\r\nplaintext',
                    malformed=b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n')
                raw.sendall(unsafe.get(args.mode, b'HTTP/1.1 200 Connection Established\r\n\r\n'))
                if args.mode in unsafe:
                    while raw.recv(65536):
                        pass
                    return
            names = []
            context.set_servername_callback(lambda _ssl, name, _ctx: names.append(name))
            tls_started = True
            conn = context.wrap_socket(raw, server_side=True)
            tls_completed = True
            conn.settimeout(.2)
            with lock:
                sockets.discard(raw)
                sockets.add(conn)
                state['handshakes'].append(dict(connection=cid, tls=conn.version(),
                    alpn=conn.selected_alpn_protocol(), sni=names[-1] if names else None,
                    cipher=conn.cipher()[0]))
            if conn.version() != args.tls or conn.selected_alpn_protocol() != args.protocol:
                raise ValueError('exact TLS/ALPN prerequisite failed')
            if args.route == 'nested':
                nested(conn, cid)
            elif args.protocol == 'h2':
                h2(conn, cid)
            else:
                h1(conn, cid)
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError) as exc:
            if tls_started and not tls_completed:
                with lock:
                    state['errors'].append(dict(kind='tls', reason=type(exc).__name__))
        except ssl.SSLError as exc:
            with lock:
                state['errors'].append(dict(kind='tls', reason=str(exc)))
        except Exception as exc:
            if not stop.is_set():
                with lock:
                    state['errors'].append(dict(kind=type(exc).__name__, reason=str(exc)))
        finally:
            conn.close()
            raw.close()
            with lock:
                sockets.discard(raw)
                sockets.discard(conn)
                state['closed_connections'] += 1

    def accept():
        while not stop.is_set() and time.monotonic() < expires:
            try:
                raw, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with lock:
                state['accepted_connections'] += 1
                cid = state['accepted_connections']
                sockets.add(raw)
            worker = threading.Thread(target=serve, args=(raw, cid))
            workers.append(worker)
            worker.start()
        stop.set()

    acceptor = threading.Thread(target=accept)
    acceptor.start()
    print(json.dumps(dict(event='ready', port=listener.getsockname()[1], tls=args.tls,
                         alpn=args.protocol, openssl=ssl.OPENSSL_VERSION)), flush=True)
    try:
        while not stop.is_set():
            remaining = expires-time.monotonic()
            if remaining <= 0 or not select.select([sys.stdin], [], [], remaining)[0]:
                raise TimeoutError('bounded peer lifetime')
            line = sys.stdin.readline()
            if not line:
                break
            command = json.loads(line)['command']
            if command == 'stats':
                with lock:
                    print(json.dumps(dict(event='stats', active_connections=len(sockets), **state)), flush=True)
            elif command == 'stop':
                break
            else:
                raise ValueError('unknown control')
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
            worker.join(11)
        if acceptor.is_alive() or any(worker.is_alive() for worker in workers):
            raise RuntimeError('peer worker not stopped')
        print(json.dumps(dict(event='stop')), flush=True)


if __name__ == '__main__':
    main()

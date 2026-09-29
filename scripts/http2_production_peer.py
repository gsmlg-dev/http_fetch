#!/usr/bin/env python3
"""Independent hyper-h2 4.2.0 acceptance peer (loopback only)."""
import argparse
import hashlib
import json
import socket
import ssl
import threading

import h2
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset
from h2.settings import Settings, SettingCodes

parser = argparse.ArgumentParser()
parser.add_argument('--tls', action='store_true')
parser.add_argument('--cert')
parser.add_argument('--key')
parser.add_argument('--limit', type=int, default=100)
args = parser.parse_args()
context = None
if args.tls:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(['h2'])


def serve(sock):
    try:
        with sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if context:
                sock = context.wrap_socket(sock, server_side=True)
            sock.settimeout(120)
            connection = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
            connection.local_settings = Settings(client=False, initial_values={SettingCodes.MAX_CONCURRENT_STREAMS: args.limit})
            connection.initiate_connection()
            sock.sendall(connection.data_to_send())
            requests, pending, barrier = {}, {}, {}

            def respond(stream_id, length, payload, barrier_count=None):
                headers = [(':status', '200'), ('content-length', str(length)),
                           ('x-peer', 'hyper-h2-' + h2.__version__)]
                if barrier_count is not None:
                    headers.append(('x-gate-barrier', str(barrier_count)))
                connection.send_headers(stream_id, headers, end_stream=length == 0)
                if length:
                    pending[stream_id] = [length, payload, 0]

            while True:
                data = sock.recv(65536)
                if not data:
                    return
                for event in connection.receive_data(data):
                    if isinstance(event, RequestReceived):
                        requests[event.stream_id] = [dict(event.headers), hashlib.sha256(), 0]
                    elif isinstance(event, DataReceived):
                        record = requests[event.stream_id]
                        record[1].update(event.data)
                        record[2] += len(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        headers, digest, size = requests.pop(event.stream_id)
                        path = headers[':path']
                        if path.startswith('/concurrent/'):
                            _, _, number, length = path.split('/')
                            number, length = int(number), int(length)
                            if number not in range(100) or number in barrier or length != (6 * 1024 * 1024 if number == 0 else 1000 + number * 97):
                                raise ValueError('invalid or duplicate concurrency barrier request')
                            barrier[number] = (event.stream_id, length)
                            if len(barrier) == 100:
                                slow_stream, slow_length = barrier[0]
                                respond(slow_stream, slow_length, None, 100)
                                pending.pop(slow_stream)
                                for item in range(1, 100):
                                    stream_id, response_length = barrier[item]
                                    respond(stream_id, response_length, None, 100)
                                pending[slow_stream] = [slow_length, None, 0]
                        elif path.startswith('/bytes/'):
                            length, payload = int(path.split('/')[-1]), None
                        elif headers[':method'] == 'POST':
                            payload = f'{size}:{digest.hexdigest()}'.encode()
                            length = len(payload)
                        else:
                            payload = path.encode()
                            length = len(payload)
                        if not path.startswith('/concurrent/'):
                            respond(event.stream_id, length, payload)
                    elif isinstance(event, StreamReset):
                        requests.pop(event.stream_id, None)
                        pending.pop(event.stream_id, None)
                progress = True
                while progress:
                    progress = False
                    for stream_id, (remaining, payload, offset) in list(pending.items()):
                        n = min(remaining, connection.local_flow_control_window(stream_id), connection.max_outbound_frame_size)
                        if n > 0:
                            chunk = b'x' * n if payload is None else payload[offset:offset+n]
                            connection.send_data(stream_id, chunk, end_stream=n == remaining)
                            progress = True
                            if n == remaining:
                                del pending[stream_id]
                            else:
                                pending[stream_id] = [remaining-n, payload, offset+n]
                    output = connection.data_to_send()
                    if output:
                        sock.sendall(output)
    except (ConnectionResetError, BrokenPipeError, TimeoutError):
        pass
    except Exception as error:
        print(json.dumps({'peer_error': type(error).__name__, 'detail': str(error)}), flush=True)


with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(32)
    print(json.dumps({'port': listener.getsockname()[1], 'peer': 'hyper-h2', 'version': h2.__version__, 'tls': args.tls, 'limit': args.limit}), flush=True)
    while True:
        sock, _ = listener.accept()
        threading.Thread(target=serve, args=(sock,), daemon=True).start()

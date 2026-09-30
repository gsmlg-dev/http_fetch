#!/usr/bin/env python3
"""Loopback, independent hyper-h2 SSE peer; bounded generators and wire observations."""
import argparse
import itertools
import json
import socket
import ssl
import threading
from urllib.parse import parse_qs, urlsplit

import h2
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, DataReceived, RemoteSettingsChanged, RequestReceived, StreamReset
from h2.settings import SettingCodes, Settings
from hyperframe.frame import GoAwayFrame

parser = argparse.ArgumentParser()
parser.add_argument('--tls', action='store_true')
parser.add_argument('--cert')
parser.add_argument('--key')
parser.add_argument('--limit', type=int, default=16)
args = parser.parse_args()
context = None
if args.tls:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(['h2'])
ids = itertools.count(1)
output_lock = threading.Lock()


def log(**record):
    with output_lock:
        print(json.dumps(record), flush=True)


def event(n):
    return f'id: {n}\ndata: event-{n}-λ\n\n'.encode()


def batches(first, last):
    batch = bytearray()
    for n in range(first, last + 1):
        batch.extend(event(n))
        if len(batch) >= 8192:
            yield bytes(batch)
            batch.clear()
    if batch:
        yield bytes(batch)


def serve(raw, cid):
    sock = raw
    pending, held = {}, {}
    try:
        if context:
            sock = context.wrap_socket(raw, server_side=True)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(180)
        connection = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
        connection.local_settings = Settings(client=False, initial_values={SettingCodes.MAX_CONCURRENT_STREAMS: args.limit})
        connection.initiate_connection()
        sock.sendall(connection.data_to_send())
        log(kind='connection', connection=cid, protocol='h2' if context else 'h2c', alpn=sock.selected_alpn_protocol() if context else None)

        def respond(sid, chunks, *, keep=False, length=None, status=200, completed=None):
            headers = [(':status', str(status)), ('content-type', 'text/event-stream')]
            if length is not None:
                headers.append(('content-length', str(length)))
            connection.send_headers(sid, headers, end_stream=status == 204)
            if status != 204:
                pending[sid] = [iter(chunks), b'', 0, itertools.cycle([1, 7, 113, 4096, 8192]), keep, completed]

        while True:
            data = sock.recv(65536)
            if not data:
                log(kind='connection_closed', connection=cid)
                return
            for received in connection.receive_data(data):
                if isinstance(received, RemoteSettingsChanged):
                    log(kind='settings', connection=cid, settings={str(int(k)): v.new_value for k, v in received.changed_settings.items()})
                elif isinstance(received, DataReceived):
                    connection.acknowledge_received_data(received.flow_controlled_length, received.stream_id)
                elif isinstance(received, RequestReceived):
                    sid = received.stream_id
                    headers = dict(received.headers)
                    target = urlsplit(headers[':path'])
                    query = parse_qs(target.query)
                    path = target.path
                    cursor = headers.get('last-event-id', '')
                    if cursor and not cursor.isdecimal() and path != '/sse/semantics':
                        raise ValueError('unexpected controlled cursor')
                    log(kind='request', connection=cid, stream=sid, endpoint=path, method=headers[':method'], cursor=cursor)
                    count = int(query.get('count', ['10000'])[0])
                    first = int(cursor or '0') + 1 if path != '/sse/semantics' else 1
                    if path in ('/sse/numbered', '/sse/churn'):
                        last = min(count, first if path.endswith('churn') else (count // 2 if first == 1 else count))
                        respond(sid, itertools.chain([b'retry: 1\n\n'], batches(first, last)), keep=last == count, completed={'first': first, 'last': last, 'count': last - first + 1})
                    elif path == '/sse/semantics':
                        if cursor == 'done':
                            respond(sid, [], status=204)
                        else:
                            payload = '\ufeff: comment\r\nretry: 1\r\nid: 7\revent: custom\ndata: λ\r\ndata: second\n\nid:\ndata: reset\n\nid: done\ndata: final\n\ndata: incomplete'.encode()
                            respond(sid, [payload])
                    elif path == '/sse/large':
                        payload = b'id: 1\n' + (b'data: ' + b'x' * 64 + b'\n') * 2048 + b'\n'
                        respond(sid, [payload], length=len(payload), keep=True)
                    elif path == '/sse/overflow':
                        respond(sid, (b'data: ' + b'x' * 64 + b'\n' for _ in range(1024)), keep=True)
                    elif path == '/sse/pressure':
                        respond(sid, batches(1, count), keep=True)
                    elif path in ('/sse/hold', '/sse/reset', '/sse/goaway'):
                        held[sid] = path
                        respond(sid, [event(first)], keep=True)
                    elif path.startswith('/control/'):
                        affected = 0
                        for stream, endpoint in list(held.items()):
                            if path == '/control/held' and endpoint == '/sse/hold':
                                respond_state = pending.get(stream)
                                if respond_state:
                                    raise ValueError('control before initial event drain')
                                pending[stream] = [iter([event(2)]), b'', 0, itertools.cycle([8192]), True, None]
                                affected += 1
                            elif path == '/control/reset' and endpoint == '/sse/reset':
                                connection.reset_stream(stream, error_code=8)
                                pending.pop(stream, None)
                                held.pop(stream)
                                log(kind='reset', connection=cid, stream=stream, code=8)
                                affected += 1
                            elif path == '/control/goaway' and endpoint == '/sse/goaway':
                                # Keep accepted streams live: hyper-h2's close_connection
                                # closes its state machine, so serialize the standard
                                # hyperframe GOAWAY and preserve the accepted streams.
                                frame = GoAwayFrame(0)
                                frame.last_stream_id = max(sid, max(held))
                                frame.error_code = 0
                                sock.sendall(connection.data_to_send() + frame.serialize())
                                held.pop(stream)
                                pending[stream] = [iter([event(2)]), b'', 0, itertools.cycle([8192]), False, None]
                                log(kind='goaway', connection=cid, stream=stream, last_stream=frame.last_stream_id)
                                affected += 1
                        payload = str(affected).encode()
                        connection.send_headers(sid, [(':status', '200'), ('content-length', str(len(payload)))])
                        pending[sid] = [iter([payload]), b'', 0, itertools.cycle([8192]), False, None]
                    elif path.startswith('/fetch/'):
                        payload = path.encode()
                        connection.send_headers(sid, [(':status', '200'), ('content-length', str(len(payload)))])
                        pending[sid] = [iter([payload]), b'', 0, itertools.cycle([8192]), False, None]
                    else:
                        raise ValueError('unknown fixture endpoint')
                elif isinstance(received, StreamReset):
                    pending.pop(received.stream_id, None)
                    held.pop(received.stream_id, None)
                    log(kind='client_reset', connection=cid, stream=received.stream_id, code=int(received.error_code))
                elif isinstance(received, ConnectionTerminated):
                    return
            progress = True
            while progress:
                progress = False
                for sid, state in list(pending.items()):
                    chunks, chunk, offset, sizes, keep, completed = state
                    if offset == len(chunk):
                        try:
                            chunk = next(chunks)
                            offset = 0
                            # Retain the fetched chunk even when connection or
                            # stream credit is zero until a WINDOW_UPDATE arrives.
                            state[1], state[2] = chunk, offset
                        except StopIteration:
                            if not keep:
                                connection.end_stream(sid)
                            pending.pop(sid)
                            if completed:
                                log(kind='range_complete', connection=cid, stream=sid, **completed)
                            progress = True
                            continue
                    n = min(len(chunk) - offset, connection.local_flow_control_window(sid), connection.max_outbound_frame_size, next(sizes))
                    if n > 0:
                        connection.send_data(sid, chunk[offset:offset+n])
                        state[1], state[2] = chunk, offset + n
                        progress = True
                output = connection.data_to_send()
                if output:
                    sock.sendall(output)
    except (ConnectionResetError, BrokenPipeError) as error:
        log(kind='connection_closed', connection=cid, reason=type(error).__name__)
    except Exception as error:
        log(peer_error=type(error).__name__, detail=str(error), connection=cid)
    finally:
        sock.close()
        raw.close()


with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(32)
    log(kind='ready', port=listener.getsockname()[1], peer='hyper-h2', version=h2.__version__, tls=args.tls, limit=args.limit)
    while True:
        sock, _ = listener.accept()
        threading.Thread(target=serve, args=(sock, next(ids)), daemon=True).start()

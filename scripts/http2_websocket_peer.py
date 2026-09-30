#!/usr/bin/env python3
"""Independent RFC 8441 peer: hyper-h2 transport, wsproto messages, raw mask oracle."""
import argparse
from collections import Counter, deque
import itertools
import json
import socket
import ssl
import struct
import threading
from urllib.parse import parse_qs, urlsplit

import h2
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset
from h2.settings import SettingCodes, Settings
from hyperframe.frame import GoAwayFrame
import wsproto
from wsproto.connection import Connection, ConnectionType
from wsproto.events import BytesMessage, CloseConnection, Ping, Pong, TextMessage


class MaskOracle:
    """Bounded independent RFC 6455 client-frame validator, separate from wsproto."""
    def __init__(self):
        self.buffer = bytearray()
        self.frames = Counter()
        self.maximum_payload = 0
        self.close_code = None
        self.masks = set()

    def receive(self, data):
        self.buffer.extend(data)
        assert len(self.buffer) <= 16_777_230, 'raw client frame retention exceeded'
        while len(self.buffer) >= 2:
            first, second = self.buffer[:2]
            opcode, masked = first & 15, bool(second & 128)
            assert not first & 112 and opcode in (0, 1, 2, 8, 9, 10), 'invalid client opcode/RSV'
            assert masked, 'client frame was not masked'
            length, offset = second & 127, 2
            if length == 126:
                if len(self.buffer) < 4:
                    return
                length, offset = struct.unpack('!H', self.buffer[2:4])[0], 4
                assert length >= 126, 'nonminimal client frame length'
            elif length == 127:
                if len(self.buffer) < 10:
                    return
                length, offset = struct.unpack('!Q', self.buffer[2:10])[0], 10
                assert 65_535 < length <= 16_777_216, 'invalid/oversized client frame length'
            if opcode >= 8:
                assert first & 128 and length <= 125, 'fragmented/oversized control frame'
            if len(self.buffer) < offset + 4 + length:
                return
            mask = bytes(self.buffer[offset:offset + 4])
            payload = bytes(byte ^ mask[i % 4] for i, byte in enumerate(self.buffer[offset + 4:offset + 4 + length]))
            del self.buffer[:offset + 4 + length]
            self.frames[str(opcode)] += 1
            self.maximum_payload = max(self.maximum_payload, length)
            if len(self.masks) < 32:
                self.masks.add(mask)
            if opcode == 8:
                assert len(payload) != 1, 'one-byte client Close payload'
                self.close_code = struct.unpack('!H', payload[:2])[0] if payload else None
                assert self.close_code not in (1005, 1006, 1015), 'reserved Close transmitted'
                payload[2:].decode('utf-8')

    def summary(self):
        return dict(client_frames=dict(self.frames), masked_frames=sum(self.frames.values()),
                    maximum_client_payload=self.maximum_payload, client_close_code=self.close_code,
                    mask_samples=len(self.masks), retained_frame_bytes=len(self.buffer))


def raw_frame(opcode, payload, fin=True):
    first = opcode | (128 if fin else 0)
    size = len(payload)
    length = bytes([size]) if size < 126 else (b'\x7e' + struct.pack('!H', size) if size <= 65_535 else b'\x7f' + struct.pack('!Q', size))
    return bytes([first]) + length + payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--limit', type=int, default=16)
    parser.add_argument('--capability', type=int, choices=[0, 1], default=1)
    args = parser.parse_args()
    context = None
    if args.tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        context.set_alpn_protocols(['h2'])
    lock = threading.Lock()
    counter = itertools.count(1)

    def log(**record):
        with lock:
            print(json.dumps(record, ensure_ascii=False), flush=True)

    def serve(raw, cid):
        sock = raw
        streams, pending, held, withheld = {}, {}, {}, Counter()
        capability = args.capability
        try:
            if context:
                sock = context.wrap_socket(raw, server_side=True)
                assert sock.selected_alpn_protocol() == 'h2', 'TLS did not negotiate h2'
            sock.settimeout(180)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
            conn.local_settings = Settings(client=False, initial_values={
                SettingCodes.MAX_CONCURRENT_STREAMS: args.limit,
                SettingCodes.ENABLE_CONNECT_PROTOCOL: capability,
            })
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            log(kind='connection', connection=cid, protocol='h2' if context else 'h2c',
                alpn=sock.selected_alpn_protocol() if context else None, capability=capability)

            def enqueue(sid, data, end=False):
                state = pending.setdefault(sid, [deque(), 0, False, itertools.cycle([1, 7, 113, 4096, 8192])])
                if data:
                    state[0].append(data)
                state[2] |= end
                retained = sum(sum(len(chunk) for chunk in value[0]) - value[1] for value in pending.values())
                assert retained <= 67_108_864, 'peer pending output exceeded frozen 64 MiB bound'

            def respond(sid, body):
                conn.send_headers(sid, [(':status', '200'), ('content-length', str(len(body)))])
                enqueue(sid, body, end=True)

            def complete(sid):
                state = streams.get(sid)
                if state and state['local_end'] and state['remote_end'] and not state['completed']:
                    state['completed'] = True
                    assert state['oracle'].frames['8'] == 1, 'clean tunnel lacked exactly one masked client Close'
                    assert not state['oracle'].buffer, 'truncated client frame at clean END_STREAM'
                    log(kind='wire_complete', connection=cid, stream=sid,
                        endpoint=state['path'], messages=state['messages'], peer_messages=state['peer_messages'],
                        client_end_stream=True, peer_end_stream=True, **state['oracle'].summary())
                    streams.pop(sid)

            def control(path, control_sid):
                nonlocal capability
                affected = 0
                if path == '/control/enable':
                    conn.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
                    capability = 1
                    log(kind='capability_enabled', connection=cid)
                    return 1
                if path == '/control/held':
                    for sid in held:
                        held[sid] = 2
                        enqueue(sid, b'id: 2\ndata: sibling-2\n\n')
                    return len(held)
                for sid, state in list(streams.items()):
                    case = state['case']
                    if path == '/control/truncate' and case == 'truncated':
                        enqueue(sid, b'\x81\x05ab', end=True)
                        log(kind='truncated_eof', connection=cid, stream=sid)
                        affected += 1
                    elif path == f'/control/{case}' and case in ('malformed', 'oversized', 'parts'):
                        if case == 'malformed':
                            data = raw_frame(1, b'first') + b'\xc1\x01x'
                        elif case == 'oversized':
                            data = b'\x82\x7f' + struct.pack('!Q', 16_777_217)
                        else:
                            data = raw_frame(1, b'', False) + raw_frame(0, b'', False) * 64
                        enqueue(sid, data)
                        log(kind='fault_triggered', connection=cid, stream=sid, case=case)
                        affected += 1
                    elif path == '/control/reset' and case == 'reset':
                        conn.reset_stream(sid, error_code=8)
                        pending.pop(sid, None)
                        streams.pop(sid)
                        log(kind='server_reset', connection=cid, stream=sid, code=8)
                        affected += 1
                    elif path == '/control/goaway' and case == 'goaway':
                        frame = GoAwayFrame(0)
                        frame.last_stream_id = max([control_sid, *streams, *held])
                        frame.error_code = 0
                        sock.sendall(conn.data_to_send() + frame.serialize())
                        log(kind='server_goaway', connection=cid, stream=sid, last_stream=frame.last_stream_id)
                        affected += 1
                    elif path == '/control/resume' and case == 'blocked':
                        conn.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 65_535})
                        for stream, amount in list(withheld.items()):
                            if amount:
                                conn.acknowledge_received_data(amount, stream)
                        withheld.clear()
                        state['withhold'] = False
                        log(kind='credit_resumed', connection=cid, stream=sid)
                        affected += 1
                    elif path == '/control/shrink' and case == 'blocked':
                        assert withheld[sid] == 65_535, 'shrink barrier before both send windows exhausted'
                        conn.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 0})
                        log(kind='credit_shrunk', connection=cid, stream=sid, withheld_bytes=withheld[sid])
                        affected += 1
                return affected

            while True:
                incoming = sock.recv(65_536)
                if not incoming:
                    log(kind='connection_closed', connection=cid, active_ws=len(streams), active_sse=len(held))
                    return
                for event in conn.receive_data(incoming):
                    if isinstance(event, RequestReceived):
                        sid = event.stream_id
                        headers = dict(event.headers)
                        target = urlsplit(headers.get(':path', ''))
                        query = parse_qs(target.query)
                        path = target.path
                        if headers.get(':method') == 'CONNECT':
                            assert capability == 1, 'CONNECT before advertised peer permission'
                            assert event.stream_ended is None, 'initial CONNECT HEADERS had END_STREAM'
                            assert len(headers) == len(event.headers), 'duplicate CONNECT header'
                            assert headers.get(':protocol') == 'websocket'
                            assert headers.get(':scheme') == ('https' if context else 'http')
                            assert headers.get(':authority') == f'localhost:{sock.getsockname()[1]}'
                            assert path.startswith('/ws/') and headers.get('sec-websocket-version') == '13'
                            assert all(name == name.lower() for name, _ in event.headers)
                            assert not set(headers) & {'connection', 'upgrade', 'host', 'sec-websocket-key', 'sec-websocket-accept', 'content-length'}
                            assert [name for name, _ in event.headers[:5]] == [':method', ':protocol', ':scheme', ':authority', ':path']
                            case = query.get('case', ['echo'])[0]
                            count = int(query.get('count', ['1'])[0])
                            log(kind='connect', connection=cid, stream=sid, endpoint=path, case=case,
                                expected_count=count, initial_end_stream=False, wire_headers={name: value for name, value in event.headers if name.startswith(':') or name == 'sec-websocket-version'}, wire_oracle='PASS')
                            if case == 'reject':
                                conn.send_headers(sid, [(':status', '403'), ('content-length', '6')])
                                enqueue(sid, b'denied', end=True)
                                continue
                            response = [(':status', '200')]
                            if case == 'subprotocol':
                                response.append(('sec-websocket-protocol', 'unrequested'))
                            elif case == 'extensions':
                                response.append(('sec-websocket-extensions', 'permessage-deflate'))
                            conn.send_headers(sid, response)
                            state = dict(codec=Connection(ConnectionType.SERVER), oracle=MaskOracle(), path=path,
                                         case=case, count=count, messages=0, peer_messages=0, parts=[],
                                         message_bytes=0, local_end=False, remote_end=False, completed=False,
                                         withhold=case == 'blocked')
                            streams[sid] = state
                            if case == 'fragmented':
                                enqueue(sid, raw_frame(1, b'split-\xce', False) + state['codec'].send(Ping(payload=b'ping-proof')) + raw_frame(0, b'\xbb-end'))
                            elif case == 'pressure':
                                for number in range(1, count + 1):
                                    text = f'pressure-{number}:' + 'x' * 4096
                                    enqueue(sid, state['codec'].send(TextMessage(data=text)))
                                    state['peer_messages'] += 1
                        elif path == '/sse/hold':
                            conn.send_headers(sid, [(':status', '200'), ('content-type', 'text/event-stream')])
                            held[sid] = 1
                            enqueue(sid, b'id: 1\ndata: sibling-1\n\n')
                            log(kind='sse', connection=cid, stream=sid, endpoint=path)
                        elif path == '/peer/state':
                            respond(sid, json.dumps(dict(active_ws=len(streams), active_sse=len(held), withheld_bytes=sum(withheld.values()))).encode())
                        elif path.startswith('/control/'):
                            respond(sid, str(control(path, sid)).encode())
                            log(kind='control', connection=cid, stream=sid, endpoint=path)
                        elif path.startswith('/fetch/'):
                            respond(sid, path.encode())
                            log(kind='fetch', connection=cid, stream=sid, endpoint=path)
                        else:
                            raise AssertionError('unknown fixture endpoint')
                    elif isinstance(event, DataReceived):
                        sid = event.stream_id
                        state = streams.get(sid)
                        if state and state['withhold']:
                            withheld[sid] += event.flow_controlled_length
                        else:
                            conn.acknowledge_received_data(event.flow_controlled_length, sid)
                        if not state or not event.data:
                            continue
                        state['oracle'].receive(event.data)
                        state['codec'].receive_data(event.data)
                        for message in state['codec'].events():
                            if isinstance(message, (TextMessage, BytesMessage)):
                                part = message.data.encode() if isinstance(message.data, str) else message.data
                                state['parts'].append(part)
                                state['message_bytes'] += len(part)
                                assert state['message_bytes'] <= 16_777_216 and len(state['parts']) <= 16_384
                                if message.message_finished:
                                    payload = b''.join(state['parts'])
                                    state['parts'], state['message_bytes'] = [], 0
                                    state['messages'] += 1
                                    if payload.startswith(b'soak-tick:'):
                                        for held_sid in held:
                                            held[held_sid] += 1
                                            cursor = held[held_sid]
                                            enqueue(held_sid, f'id: {cursor}\ndata: sibling-{cursor}\n\n'.encode())
                                        log(kind='soak_tick', connection=cid, stream=sid,
                                            sse_streams=len(held), active_ws=len(streams),
                                            sequence=payload.decode())
                                    outbound = TextMessage(data=payload.decode()) if isinstance(message, TextMessage) else BytesMessage(data=payload)
                                    enqueue(sid, state['codec'].send(outbound))
                                    state['peer_messages'] += 1
                                    if state['messages'] % 500 == 0:
                                        log(kind='message_progress', connection=cid, stream=sid, messages=state['messages'])
                            elif isinstance(message, Ping):
                                enqueue(sid, state['codec'].send(message.response()))
                            elif isinstance(message, Pong):
                                log(kind='client_pong', connection=cid, stream=sid, payload=message.payload.decode())
                            elif isinstance(message, CloseConnection):
                                assert message.code != 1006, 'wsproto rejected a client frame'
                                # Finish an already-started frame, then retire unsent
                                # application frames before replying to client Close.
                                if sid in pending:
                                    queued = pending[sid]
                                    queued[0] = deque([queued[0][0]]) if queued[0] and queued[1] else deque()
                                enqueue(sid, state['codec'].send(message.response()), end=True)
                                log(kind='client_close', connection=cid, stream=sid, code=int(message.code))
                    elif isinstance(event, StreamEnded):
                        if event.stream_id in streams:
                            streams[event.stream_id]['remote_end'] = True
                            complete(event.stream_id)
                    elif isinstance(event, StreamReset):
                        state = streams.pop(event.stream_id, None)
                        held.pop(event.stream_id, None)
                        pending.pop(event.stream_id, None)
                        withheld.pop(event.stream_id, None)
                        log(kind='client_reset', connection=cid, stream=event.stream_id, code=int(event.error_code),
                            case=state['case'] if state else None, messages=state['messages'] if state else 0,
                            **(state['oracle'].summary() if state else {}))

                progress = True
                while progress:
                    progress = False
                    for sid, state in list(pending.items()):
                        chunks, offset, end, sizes = state
                        if not chunks:
                            if end:
                                conn.end_stream(sid)
                                if sid in streams:
                                    streams[sid]['local_end'] = True
                                    complete(sid)
                            pending.pop(sid)
                            progress = True
                            continue
                        chunk = chunks[0]
                        size = min(len(chunk) - offset, conn.local_flow_control_window(sid), conn.max_outbound_frame_size, next(sizes))
                        if size > 0:
                            conn.send_data(sid, chunk[offset:offset + size])
                            state[1] += size
                            if state[1] == len(chunk):
                                chunks.popleft()
                                state[1] = 0
                            progress = True
                    output = conn.data_to_send()
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
        log(kind='ready', port=listener.getsockname()[1], peer='hyper-h2/wsproto',
            h2_version=h2.__version__, wsproto_version=wsproto.__version__, tls=args.tls, capability=args.capability)
        while True:
            raw, _ = listener.accept()
            threading.Thread(target=serve, args=(raw, next(counter)), daemon=True).start()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Finite independent stream-client gates with drained, bounded wire evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('--peer', choices=['hyper-h2', 'node'], required=True)
parser.add_argument('--tls', action='store_true')
parser.add_argument('--backend', choices=['ssl', 'ex_ssl'], default='ssl')
parser.add_argument('--mode', choices=['sse', 'mixed', 'faults', 'churn'], default='sse')
parser.add_argument('--count', type=int, default=10000)
parser.add_argument('--limit', type=int, default=16)
parser.add_argument('--timeout', type=int, default=600)
parser.add_argument('--peer-check', action='store_true', help='Validate independent fixtures without claiming public-client acceptance')
args = parser.parse_args()
if args.count < (1001 if args.mode == 'churn' else 10000):
    parser.error('acceptance requires >=10000 events, or >=1001 churn opens for 1000 reconnects')
if not args.tls and args.backend != 'ssl':
    parser.error('ex_ssl matrix requires --tls')
import h2
import hpack
import hyperframe
assert (h2.__version__, hpack.__version__, hyperframe.__version__) == ('4.2.0', '4.1.0', '6.1.0')
if args.peer == 'node':
    versions = json.loads(subprocess.check_output(['node', '-p', 'JSON.stringify(process.versions)'], text=True))
    assert (versions['node'], versions['nghttp2']) == ('24.19.0', '1.69.0')
root = Path(__file__).resolve().parent.parent
fixtures = root / 'apps/http_fetch/test/support/fixtures'
env = os.environ.copy()
env.update(H2_PEER_LIMIT=str(args.limit), H2_PEER_TLS='1' if args.tls else '0', H2_PEER_CERT=str(fixtures / 'localhost.pem'), H2_PEER_KEY=str(fixtures / 'localhost.key'))
command = [sys.executable, str(root / 'scripts/http2_stream_peer.py'), '--limit', str(args.limit)] if args.peer == 'hyper-h2' else ['node', str(root / 'scripts/http2_stream_peer.mjs')]
if args.peer == 'hyper-h2' and args.tls:
    command += ['--tls', '--cert', env['H2_PEER_CERT'], '--key', env['H2_PEER_KEY']]
peer = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
observations, failures = [], []
ready = queue.Queue(maxsize=1)
finished = threading.Event()


def drain_peer():
    try:
        for line in peer.stdout:
            print(line, end='', flush=True)
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                failures.append('non-JSON peer output')
                continue
            if len(observations) >= 50000:
                if not failures:
                    failures.append('peer observation bound exceeded')
                continue
            observations.append(record)
            if 'peer_error' in record:
                failures.append(record)
            if record.get('kind') == 'ready':
                ready.put_nowait(record)
    finally:
        finished.set()


thread = threading.Thread(target=drain_peer, daemon=True)
thread.start()
result = None


def peer_check(port):
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, ResponseReceived, StreamEnded, StreamReset
    sock = socket.create_connection(('127.0.0.1', port), timeout=15)
    if args.tls:
        context = ssl.create_default_context(cafile=env['H2_PEER_CERT'])
        context.set_alpn_protocols(['h2'])
        sock = context.wrap_socket(sock, server_hostname='localhost')
        assert sock.selected_alpn_protocol() == 'h2'
    conn = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    def request(path, cursor='', stop_after=None, trigger=None):
        sid = conn.get_next_available_stream_id()
        headers = [(':method', 'GET'), (':scheme', 'https' if args.tls else 'http'), (':authority', f'localhost:{port}'), (':path', path)]
        if cursor:
            headers.append(('last-event-id', cursor))
        conn.send_headers(sid, headers, end_stream=True)
        sock.sendall(conn.data_to_send())
        payload, response = bytearray(), None
        done, triggered = False, False
        while not done:
            incoming = sock.recv(65536)
            if not incoming:
                raise RuntimeError('peer closed before completed fixture')
            for event in conn.receive_data(incoming):
                if isinstance(event, ResponseReceived) and event.stream_id == sid:
                    response = dict(event.headers)
                    if trigger and not triggered:
                        control = conn.get_next_available_stream_id()
                        conn.send_headers(control, [(':method', 'GET'), (':scheme', 'https' if args.tls else 'http'),
                            (':authority', f'localhost:{port}'), (':path', trigger)], end_stream=True)
                        triggered = True
                elif isinstance(event, DataReceived):
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if event.stream_id == sid:
                        payload.extend(event.data)
                        done |= stop_after is not None and len(payload) >= stop_after
                elif isinstance(event, StreamEnded) and event.stream_id == sid:
                    done = True
                elif isinstance(event, StreamReset) and event.stream_id == sid:
                    raise RuntimeError('unexpected fixture reset')
            sock.sendall(conn.data_to_send())
        if stop_after is not None:
            conn.reset_stream(sid, error_code=8)
            sock.sendall(conn.data_to_send())
        return response, bytes(payload)

    count = args.count
    split = count // 2
    _, first = request(f'/sse/numbered?count={count}')
    expected_first = b'retry: 1\n\n' + b''.join(f'id: {n}\ndata: event-{n}-λ\n\n'.encode() for n in range(1, split + 1))
    assert first == expected_first
    expected_second = b'retry: 1\n\n' + b''.join(f'id: {n}\ndata: event-{n}-λ\n\n'.encode() for n in range(split + 1, count + 1))
    _, second = request(f'/sse/numbered?count={count}', str(split), len(expected_second))
    assert second == expected_second
    expected_large = b'id: 1\n' + (b'data: ' + b'x' * 64 + b'\n') * 2048 + b'\n'
    headers, large = request('/sse/large', stop_after=len(expected_large))
    assert large == expected_large and int(headers['content-length']) == len(large)
    _, semantics = request('/sse/semantics', trigger='/control/semantics')
    assert semantics.startswith(b'\xef\xbb\xbf') and semantics.endswith(b'data: incomplete')
    headers, body = request('/sse/semantics', 'done')
    assert headers[':status'] == '204' and not body

    # Prove the reset fixture emits RST_STREAM(8) without preceding END_STREAM.
    reset_sid = conn.get_next_available_stream_id()
    conn.send_headers(reset_sid, [(':method', 'GET'), (':scheme', 'https' if args.tls else 'http'), (':authority', f'localhost:{port}'), (':path', '/sse/reset')], end_stream=True)
    sock.sendall(conn.data_to_send())
    initial = bytearray()
    while b'\n\n' not in initial:
        for event in conn.receive_data(sock.recv(65536)):
            if isinstance(event, DataReceived):
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                if event.stream_id == reset_sid:
                    initial.extend(event.data)
        sock.sendall(conn.data_to_send())
    assert bytes(initial) == 'id: 1\ndata: event-1-λ\n\n'.encode()
    control_sid = conn.get_next_available_stream_id()
    conn.send_headers(control_sid, [(':method', 'GET'), (':scheme', 'https' if args.tls else 'http'), (':authority', f'localhost:{port}'), (':path', '/control/reset')], end_stream=True)
    sock.sendall(conn.data_to_send())
    reset_seen, control_ended = False, False
    while not (reset_seen and control_ended):
        incoming = sock.recv(65536)
        assert incoming, 'connection ended before reset oracle completion'
        for event in conn.receive_data(incoming):
            if isinstance(event, StreamEnded):
                assert event.stream_id != reset_sid, 'reset fixture sent END_STREAM before reset'
                control_ended |= event.stream_id == control_sid
            elif isinstance(event, StreamReset) and event.stream_id == reset_sid:
                assert int(event.error_code) == 8
                reset_seen = True
            elif isinstance(event, DataReceived):
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        sock.sendall(conn.data_to_send())
    print(json.dumps({'kind': 'reset_wire_oracle', 'stream': reset_sid, 'code': 8, 'preceding_end_stream': False}), flush=True)
    sock.close()
    print(json.dumps({'result': 'PASS', 'mode': 'peer-check', 'count': count, 'large_bytes': len(large), 'public_client': False}), flush=True)


try:
    metadata = ready.get(timeout=15)
    files = ['http2_stream_peer.py', 'http2_stream_peer.mjs', 'http2_stream_clients_gate.py', 'http2_stream_clients_gate.exs', 'requirements-http2-stream-clients.txt']
    print(json.dumps({'kind': 'provenance', 'candidate_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), 'dirty_files': subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True).splitlines(), 'sources': {name: hashlib.sha256((root / 'scripts' / name).read_bytes()).hexdigest() for name in files}, 'peer': args.peer, 'tls': args.tls, 'backend': args.backend}), flush=True)
    if args.peer_check:
        peer_check(metadata['port'])
    else:
        env.update(HTTP_STREAM_GATE_URL=f"{'https' if args.tls else 'http'}://localhost:{metadata['port']}", HTTP_STREAM_GATE_BACKEND=args.backend, HTTP_STREAM_GATE_CA=str(fixtures / 'localhost-ca.pem'), HTTP_STREAM_GATE_MODE=args.mode, HTTP_STREAM_GATE_COUNT=str(args.count), MIX_ENV='test')
        result = subprocess.Popen(['mix', 'run', str(root / 'scripts/http2_stream_clients_gate.exs')], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        gate_lines = queue.Queue(maxsize=2048)

        def drain_gate():
            for line in result.stdout:
                gate_lines.put(line)
            gate_lines.put(None)

        gate_thread = threading.Thread(target=drain_gate, daemon=True)
        gate_thread.start()
        deadline, completed = time.monotonic() + args.timeout, False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('public gate workload deadline exceeded')
            line = gate_lines.get(timeout=remaining)
            if line is None:
                break
            print(line, end='', flush=True)
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            completed |= isinstance(record, dict) and record.get('result') == 'PASS' and record.get('mode') == args.mode and record.get('count') == args.count
        status = result.wait(timeout=5)
        if status != 0 or not completed:
            raise RuntimeError(f'public workload incomplete or failed: exit={status}, completed={completed}')
        requests = [item for item in observations if item.get('kind') == 'request']
        numbered = [item for item in requests if item.get('endpoint') == ('/sse/churn' if args.mode == 'churn' else '/sse/numbered')]
        if args.mode in ('sse', 'churn'):
            if len(numbered) != (args.count if args.mode == 'churn' else 2):
                raise RuntimeError('incorrect peer-observed reconnect count')
            expected = [str(n) if n else '' for n in range(args.count)] if args.mode == 'churn' else ['', str(args.count // 2)]
            if [item['cursor'] for item in numbered] != expected or len({item['connection'] for item in numbered}) != 1:
                raise RuntimeError('cursor or compatible reconnect connection mismatch')
        if args.mode == 'sse':
            semantics = [item for item in observations if item.get('kind') == 'semantics_triggered']
            if len(semantics) != 1:
                raise RuntimeError('missing controlled semantics EOF evidence')
            overflow = [item for item in observations if item.get('kind') == 'overflow_triggered']
            if len(overflow) != 1 or overflow[0]['lines'] != 1024 or overflow[0]['line_bytes'] != 71:
                raise RuntimeError('missing exact controlled overflow input evidence')
            pressure = [item for item in requests if item['endpoint'] == '/sse/pressure']
            sibling = [item for item in requests if item['endpoint'] in ('/fetch/paused', '/fetch/after-pause')]
            if len(pressure) != 1 or len(sibling) != 2 or len({item['connection'] for item in pressure + sibling}) != 1:
                raise RuntimeError('paused source reconnected or sibling Fetch changed connection')
        if args.mode == 'mixed':
            mixed = [item for item in requests if item['endpoint'] in ('/sse/hold', '/control/cancelled', '/control/held') or item['endpoint'].startswith('/fetch/')]
            if len({item['connection'] for item in mixed}) != 1:
                raise RuntimeError('Fetch/SSE did not share one independently observed connection')
            holds = [item for item in mixed if item['endpoint'] == '/sse/hold']
            barriers = [item for item in observations if item.get('kind') == 'cancellation_observed']
            cancellations = [item for item in mixed if item['endpoint'] == '/control/cancelled']
            controls = [item for item in mixed if item['endpoint'] == '/control/held']
            fetches = [item for item in mixed if item['endpoint'].startswith('/fetch/mixed-')]
            if len(holds) != 3 or len(barriers) != 1 or len(cancellations) != 1 or len(controls) != 1 or len(fetches) != 100:
                raise RuntimeError('mixed workload or cancellation barrier count mismatch')
            barrier = barriers[0]
            if barrier['control_stream'] != cancellations[0]['stream'] or barrier['connection'] != cancellations[0]['connection']:
                raise RuntimeError('cancellation response does not match the barrier request')
            resets = [item for item in observations if item.get('kind') == 'client_reset'
                      and item['connection'] == barrier['connection'] and item['stream'] == barrier['stream']]
            if barrier['code'] != 8 or barrier['stream'] not in [item['stream'] for item in holds] or len(resets) != 1 or resets[0]['code'] != 8:
                raise RuntimeError('missing exact held-stream CANCEL observation')
            if not observations.index(resets[0]) < observations.index(barrier) < observations.index(controls[0]):
                raise RuntimeError('sibling trigger preceded observed held-stream cancellation')
        connection_records = [item for item in observations if item.get('kind') == 'connection']
        if not connection_records or not any(item.get('kind') == 'settings' for item in observations):
            raise RuntimeError('missing protocol/settings evidence')
        if any(item['protocol'] != ('h2' if args.tls else 'h2c') or (args.tls and item['alpn'] != 'h2') for item in connection_records):
            raise RuntimeError('wire protocol or ALPN mismatch')
    if failures:
        raise RuntimeError(f'peer failures: {failures[:4]}')
    print(json.dumps({'result': 'PASS', 'mode': 'wire-audit', 'public_client': not args.peer_check, 'observations': len(observations)}), flush=True)
finally:
    if result and result.poll() is None:
        result.terminate()
        try:
            result.wait(timeout=5)
        except subprocess.TimeoutExpired:
            result.kill()
            result.wait(timeout=5)
    peer.terminate()
    try:
        peer.wait(timeout=5)
    except subprocess.TimeoutExpired:
        peer.kill()
        peer.wait(timeout=5)
    thread.join(timeout=5)

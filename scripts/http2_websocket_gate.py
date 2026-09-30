#!/usr/bin/env python3
"""Bounded RFC 8441 peer runner with public-workload and independent wire oracles."""
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time


class Evidence:
    def __init__(self):
        self.records = []
        self.errors = deque(maxlen=8)
        self.condition = threading.Condition()

    def drain(self, process, label):
        for line in process.stdout:
            print(line, end='', flush=True)
            with self.condition:
                if len(line) > 16_384:
                    self.errors.append('peer line exceeded bound')
                    self.condition.notify_all()
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    self.errors.append('non-JSON peer output')
                    self.condition.notify_all()
                    continue
                record['peer_instance'] = label
                if len(self.records) >= 40_000:
                    self.errors.append('peer record retention bound exceeded')
                else:
                    self.records.append(record)
                if 'peer_error' in record:
                    self.errors.append(record)
                self.condition.notify_all()

    def wait(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                if self.errors:
                    raise RuntimeError(f'independent peer failed: {list(self.errors)}')
                value = predicate(self.records)
                if value:
                    return value
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('peer evidence deadline exceeded')
                self.condition.wait(remaining)


def peer_check(port, tls, ca, count):
    """Exercise the fixture itself without claiming public-client acceptance."""
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, RemoteSettingsChanged, ResponseReceived, StreamEnded
    from h2.settings import SettingCodes
    from wsproto.connection import Connection, ConnectionType
    from wsproto.events import BytesMessage, CloseConnection, TextMessage

    raw = socket.create_connection(('127.0.0.1', port), timeout=30)
    sock = raw
    if tls:
        context = ssl.create_default_context(cafile=str(ca))
        context.set_alpn_protocols(['h2'])
        sock = context.wrap_socket(raw, server_hostname='localhost')
        assert sock.selected_alpn_protocol() == 'h2'
    conn = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    enabled = False
    while not enabled:
        for event in conn.receive_data(sock.recv(65_536)):
            if isinstance(event, RemoteSettingsChanged):
                enabled |= event.changed_settings.get(SettingCodes.ENABLE_CONNECT_PROTOCOL, None) is not None and event.changed_settings[SettingCodes.ENABLE_CONNECT_PROTOCOL].new_value == 1
        sock.sendall(conn.data_to_send())
    sid = conn.get_next_available_stream_id()
    conn.send_headers(sid, [(':method', 'CONNECT'), (':protocol', 'websocket'),
        (':scheme', 'https' if tls else 'http'), (':authority', f'localhost:{port}'),
        (':path', f'/ws/echo?count={count + 1}'), ('sec-websocket-version', '13')], end_stream=False)
    sock.sendall(conn.data_to_send())
    codec = Connection(ConnectionType.CLIENT)
    opened, remote_end = False, False
    messages = deque()
    parts = []

    def receive():
        nonlocal opened, remote_end, parts
        incoming = sock.recv(65_536)
        assert incoming, 'fixture closed before completion'
        for event in conn.receive_data(incoming):
            if isinstance(event, ResponseReceived):
                assert dict(event.headers)[':status'] == '200'
                opened = True
            elif isinstance(event, DataReceived):
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                if event.data:
                    codec.receive_data(event.data)
                    for message in codec.events():
                        if isinstance(message, (TextMessage, BytesMessage)):
                            parts.append(message.data)
                            if message.message_finished:
                                value = ''.join(parts) if isinstance(message, TextMessage) else b''.join(parts)
                                messages.append(value)
                                parts = []
                        elif isinstance(message, CloseConnection):
                            assert message.code == 1000
            elif isinstance(event, StreamEnded):
                remote_end = True
        output = conn.data_to_send()
        if output:
            sock.sendall(output)

    def send_frame(frame):
        offset = 0
        while offset < len(frame):
            size = min(len(frame) - offset, conn.local_flow_control_window(sid), conn.max_outbound_frame_size)
            if size == 0:
                receive()
            else:
                conn.send_data(sid, frame[offset:offset + size])
                offset += size
                sock.sendall(conn.data_to_send())

    while not opened:
        receive()
    for number in range(1, count + 1):
        value = f'message-{number}-λ' if number % 2 else f'binary-{number}'.encode()
        send_frame(codec.send(TextMessage(data=value) if isinstance(value, str) else BytesMessage(data=value)))
        while not messages:
            receive()
        assert messages.popleft() == value
    large = b'x' * 131_072
    send_frame(codec.send(BytesMessage(data=large)))
    while not messages:
        receive()
    assert messages.popleft() == large
    send_frame(codec.send(CloseConnection(code=1000, reason='fixture complete')))
    conn.end_stream(sid)
    sock.sendall(conn.data_to_send())
    while not remote_end:
        receive()
    sock.close()
    raw.close()


def main():
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('WebSocket acceptance interrupted; workload incomplete')

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['echo', 'faults', 'mixed', 'churn', 'soak'], default='echo')
    parser.add_argument('--peer', choices=['hyper-h2', 'node'], default='hyper-h2')
    parser.add_argument('--count', type=int, default=10000)
    parser.add_argument('--tls', action='store_true')
    parser.add_argument('--backend', choices=['ssl', 'ex_ssl'], default='ssl')
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--peer-check', action='store_true')
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--soak-check', action='store_true', help='short public runner check; never acceptance')
    args = parser.parse_args()
    if args.count < 1 or args.timeout < 1:
        parser.error('count and timeout must be positive')
    if not args.peer_check and args.mode in ('echo', 'churn') and args.count < (1000 if args.mode == 'churn' else 10000):
        parser.error('public acceptance requires echo >=10000 messages or churn >=1000 cycles')
    if not args.tls and args.backend != 'ssl':
        parser.error('ex_ssl requires actual TLS')
    if args.mode == 'soak' and args.seconds < (12 if args.soak_check else 1800):
        parser.error('soak requires >=1800 seconds; explicit --soak-check requires >=12')
    if args.peer == 'node' and args.mode != 'mixed':
        parser.error('Node RFC 8441 peer supports mixed mode only')
    import h2
    import hpack
    import hyperframe
    import wsproto
    assert (h2.__version__, hpack.__version__, hyperframe.__version__, wsproto.__version__) == ('4.2.0', '4.1.0', '6.1.0', '1.2.0')
    node_versions = None
    if args.peer == 'node':
        node_versions = json.loads(subprocess.check_output(['node', '-p', 'JSON.stringify(process.versions)'], text=True))
        assert (node_versions['node'], node_versions['nghttp2']) == ('24.19.0', '1.69.0')
    root = Path(__file__).resolve().parent.parent
    fixtures = root / 'apps/http_fetch/test/support/fixtures'
    evidence = Evidence()
    processes, threads = [], []
    result = None

    def launch(label, capability):
        peer_env = os.environ.copy()
        if args.peer == 'node':
            command = ['node', str(root / 'scripts/http2_websocket_peer.mjs')]
            peer_env.update(H2_PEER_TLS='1' if args.tls else '0',
                            H2_PEER_CERT=str(fixtures / 'localhost.pem'), H2_PEER_KEY=str(fixtures / 'localhost.key'))
        else:
            command = [sys.executable, str(root / 'scripts/http2_websocket_peer.py'), '--capability', str(capability)]
        if args.tls and args.peer == 'hyper-h2':
            command += ['--tls', '--cert', str(fixtures / 'localhost.pem'), '--key', str(fixtures / 'localhost.key')]
        process = subprocess.Popen(command, env=peer_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        processes.append(process)
        thread = threading.Thread(target=evidence.drain, args=(process, label), daemon=True)
        thread.start()
        threads.append(thread)
        return evidence.wait(lambda records: next((record for record in records if record.get('kind') == 'ready' and record['peer_instance'] == label), None), 15)

    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    try:
        main_peer = launch('main', 1)
        disabled = launch('disabled', 0) if args.mode == 'faults' and not args.peer_check else None
        peer_source = root / ('scripts/http2_websocket_peer.mjs' if args.peer == 'node' else 'scripts/http2_websocket_peer.py')
        versions = dict(h2=h2.__version__, hpack=hpack.__version__, hyperframe=hyperframe.__version__, wsproto=wsproto.__version__)
        if node_versions:
            versions.update(node=node_versions['node'], nghttp2=node_versions['nghttp2'])
        print(json.dumps(dict(kind='fixture_provenance', peer=args.peer, source_sha256={str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [peer_source, root / 'scripts/http2_websocket_gate.py', root / 'scripts/http2_websocket_gate.exs']}, versions=versions)), flush=True)
        if args.peer_check:
            peer_check(main_peer['port'], args.tls, fixtures / 'localhost-ca.pem', args.count)
            completed = dict(result='PASS', completed=True, mode='fixture-check', count=args.count, public_client=False)
        else:
            scheme = 'https' if args.tls else 'http'
            env = os.environ.copy()
            env.update(MIX_ENV='test', HTTP_WS_GATE_URL=f"{scheme}://localhost:{main_peer['port']}", HTTP_WS_GATE_BACKEND=args.backend,
                       HTTP_WS_GATE_CA=str(fixtures / 'localhost-ca.pem'), HTTP_WS_GATE_MODE=args.mode,
                       HTTP_WS_GATE_COUNT=str(args.count), HTTP_WS_GATE_SECONDS=str(args.seconds),
                       HTTP_WS_GATE_ACCEPTANCE='false' if args.soak_check else 'true')
            if disabled:
                env['HTTP_WS_GATE_DISABLED_URL'] = f"{scheme}://localhost:{disabled['port']}"
            result = subprocess.Popen(['mix', 'run', str(root / 'scripts/http2_websocket_gate.exs')], cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
            output = deque(maxlen=2048)
            condition = threading.Condition()
            finished = threading.Event()

            def drain_gate():
                for line in result.stdout:
                    with condition:
                        if len(output) == output.maxlen:
                            evidence.errors.append('public output queue bound exceeded')
                        output.append(line)
                        condition.notify_all()
                finished.set()
                with condition:
                    condition.notify_all()

            gate_thread = threading.Thread(target=drain_gate, daemon=True)
            gate_thread.start()
            deadline, completed = time.monotonic() + args.timeout, None
            while not finished.is_set() or output:
                with condition:
                    if not output:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError('public WebSocket workload deadline exceeded')
                        condition.wait(min(remaining, 1))
                        continue
                    line = output.popleft()
                if len(line) > 16_384:
                    raise RuntimeError('public output line bound exceeded')
                print(line, end='', flush=True)
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get('result') == 'PASS' and record.get('completed') is True and record.get('mode') == args.mode and record.get('count') == args.count:
                    completed = record
                if time.monotonic() > deadline:
                    raise TimeoutError('public WebSocket workload deadline exceeded')
            status = result.wait(timeout=5)
            gate_thread.join(timeout=5)
            if status != 0 or completed is None:
                raise RuntimeError(f'public acceptance incomplete: exit={status}, completed={completed is not None}')
            assert completed['acceptance'] == (not args.soak_check), 'developer check mislabeled as acceptance'

        minimum = args.count if args.mode == 'churn' and not args.peer_check else 1
        evidence.wait(lambda records: len([record for record in records if record.get('kind') == 'wire_complete' and record['peer_instance'] == 'main']) >= minimum, 15)
        records = evidence.records
        connections = [record for record in records if record.get('kind') == 'connection']
        assert connections and all(record['protocol'] == ('h2' if args.tls else 'h2c') and (not args.tls or record['alpn'] == 'h2') for record in connections)
        connects = [record for record in records if record.get('kind') == 'connect']
        assert connects and all(record['wire_oracle'] == 'PASS' and not record['initial_end_stream'] for record in connects)
        complete = [record for record in records if record.get('kind') == 'wire_complete' and record['peer_instance'] == 'main']
        if args.mode == 'churn' and not args.peer_check:
            assert len(connects) == args.count and len(complete) == args.count, 'peer did not count actual requested cycles'
            assert all(record['messages'] == 1 and record['client_close_code'] == 1000 for record in complete)
            assert len({record['connection'] for record in connects}) == 1, 'churn did not reuse one controlled connection'
        elif args.mode == 'echo' or args.peer_check:
            assert len(complete) == 1 and complete[0]['messages'] == args.count + 1
            assert complete[0]['maximum_client_payload'] > 65_535
            assert int(complete[0]['client_frames'].get('1', 0)) > 0 and int(complete[0]['client_frames'].get('2', 0)) > 0
        elif args.mode == 'mixed':
            assert len(connections) == 1, 'mixed workload opened an extra connection'
            if args.peer == 'node':
                assert any(record.get('kind') == 'settings_advertised' and
                           record.get('enable_connect_protocol') is True for record in records)
            mixed = [record for record in records if record.get('kind') in ('connect', 'sse', 'fetch', 'control')]
            assert len({record['connection'] for record in mixed}) == 1, 'Fetch/SSE/WS did not share one wire connection'
            assert len([record for record in mixed if record['kind'] == 'sse']) >= 2
            assert len(connects) >= 3 and any(record.get('case') == 'pressure' for record in connects)
            assert len(complete) == 3 and sorted(record['messages'] for record in complete) == [0, 1, 2]
            assert all(record['client_close_code'] == 1000 and record['retained_frame_bytes'] == 0 and
                       record['masked_frames'] == record['messages'] + 1 for record in complete)
        elif args.mode == 'faults':
            assert {record['case'] for record in records if record.get('kind') == 'fault_triggered'} == {'malformed', 'oversized', 'parts'}
            assert any(record.get('kind') == 'server_reset' for record in records)
            assert any(record.get('kind') == 'server_goaway' for record in records)
            assert any(record.get('kind') == 'client_pong' for record in records)
            assert any(record.get('kind') == 'credit_resumed' for record in records)
            disabled_connects = [record for record in connects if record['peer_instance'] == 'disabled']
            assert len(disabled_connects) == 1 and any(record.get('kind') == 'capability_enabled' and record['peer_instance'] == 'disabled' for record in records)
        elif args.mode == 'soak':
            assert completed['active_elapsed_ms'] >= args.seconds * 1000, 'short soak duration'
            assert completed['intervals'] == ['slow-consumer', 'cancellation', 'draining']
            cancelled = [record for record in records if record.get('kind') == 'client_reset' and record.get('case') == 'cancel']
            assert len(cancelled) == 1 and cancelled[0]['code'] == 8, 'missing controlled tunnel cancellation'
            assert len(complete) == len(connects) - 1, 'surviving soak tunnel did not complete cleanly'
            assert all((record['connection'], record['stream']) !=
                       (cancelled[0]['connection'], cancelled[0]['stream']) for record in complete)
            assert sum(record['messages'] for record in complete + cancelled) == completed['ws_messages']
            ticks = [record for record in records if record.get('kind') == 'soak_tick']
            sources = [record for record in records if record.get('kind') == 'sse']
            assert len(ticks) == completed['sse_ticks']
            assert all(record['sse_streams'] == 2 and record['active_ws'] >= 2 for record in ticks)
            assert len(sources) == 4 and completed['sse_messages'] == len(sources) + 2 * len(ticks)
            assert len([record for record in records if record.get('kind') == 'fetch']) == completed['fetch_requests']
            assert len([record for record in records if record.get('kind') == 'server_goaway']) == 1
            assert len(connections) == 2, 'soak lacked controlled replacement owner'
            assert len([record for record in connects if record.get('case') == 'pressure']) == 1
            assert all(record['client_close_code'] == 1000 for record in complete)
        if evidence.errors:
            raise RuntimeError(str(list(evidence.errors)))
        print(json.dumps(dict(result='PASS', completed=True, mode='wire-audit', public_client=not args.peer_check,
                              requested_mode=args.mode, peer=args.peer, count=args.count, observations=len(records),
                              clean_wire_sessions=len(complete), acceptance=not args.soak_check,
                              elapsed_soak_seconds=args.seconds if args.mode == 'soak' else None)), flush=True)
        if args.peer_check:
            print(json.dumps(completed), flush=True)
    finally:
        if result:
            stop(result)
        for process in processes:
            stop(process)
        for thread in threads:
            thread.join(timeout=5)


if __name__ == '__main__':
    main()

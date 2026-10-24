#!/usr/bin/env python3
"""Prove isolated candidate consumers use h2c and verified ExSSL H2 traffic."""
from collections import Counter
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading


MODES = ('h2c', 'ex_ssl')
CLIENTS = [['http_fetch'], ['http_event_source'], ['http_web_socket'],
           ['http_fetch', 'http_event_source', 'http_web_socket']]


def peer_command(root, mode):
    assert mode in MODES, 'unknown package traffic mode'
    command = [sys.executable, str(root / 'scripts/http2_websocket_peer.py')]
    if mode == 'ex_ssl':
        fixtures = root / 'apps/http_fetch/test/support/fixtures'
        command += ['--tls', '--cert', str(fixtures / 'localhost.pem'),
                    '--key', str(fixtures / 'localhost.key')]
    return command


def consumer_environment(environment, root, mode, port):
    assert mode in MODES, 'unknown package traffic mode'
    env = environment.copy()
    scheme = 'https' if mode == 'ex_ssl' else 'http'
    env.update(HTTP_RUNTIME_CONSUMER_URL=f'{scheme}://localhost:{port}',
               HTTP_RUNTIME_CONSUMER_MODE=mode)
    env.pop('HTTP_RUNTIME_CONSUMER_CA', None)
    if mode == 'ex_ssl':
        env['HTTP_RUNTIME_CONSUMER_CA'] = str(
            root / 'apps/http_fetch/test/support/fixtures/localhost-ca.pem')
    return env


def validate_mode(records, consumer_records, mode):
    assert mode in MODES, 'unknown package traffic mode'
    tls = mode == 'ex_ssl'
    ready = [record for record in records if record.get('kind') == 'ready']
    assert len(ready) == 1 and ready[0].get('tls') is tls, 'wrong peer transport mode'
    assert not any('peer_error' in record for record in records), 'package peer failed'
    connections = [record for record in records if record.get('kind') == 'connection']
    assert len(connections) == 4, 'expected one connection per isolated consumer'
    assert all(record.get('protocol') == ('h2' if tls else 'h2c') and
               record.get('alpn') == ('h2' if tls else None) for record in connections), \
        'wrong peer protocol/ALPN'
    identities = [record['connection'] for record in connections]
    assert len(set(identities)) == 4, 'duplicate peer connection identity'
    traffic = {}
    for record in records:
        if record.get('kind') in ('fetch', 'sse', 'connect'):
            traffic.setdefault(record['connection'], Counter())[record['kind']] += 1
    expected = [Counter(fetch=1), Counter(sse=1), Counter(connect=1),
                Counter(fetch=1, sse=1, connect=1)]
    assert len(traffic) == 4 and [traffic.get(cid) for cid in identities] == expected, \
        f'wrong standalone/mixed wire traffic: {traffic}'
    closed = [record for record in records if record.get('kind') == 'wire_complete']
    assert [(record['connection'], record['messages']) for record in closed] == [
        (identities[2], 1), (identities[3], 2)], 'wrong standalone/mixed WebSocket completion'
    assert all(record.get('client_end_stream') is True and
               record.get('peer_end_stream') is True and record.get('client_close_code') == 1000
               and record.get('client_frames', {}).get('8') == 1 for record in closed), \
        'incomplete WebSocket wire closure'
    traffic_results = [record for record in consumer_records
                       if record.get('gate') == 'isolated_http2_traffic']
    startup_results = [record for record in consumer_records
                       if record.get('gate') == 'isolated_runtime_startup']
    for results in (traffic_results, startup_results):
        assert [record.get('clients') for record in results] == CLIENTS and all(
            record.get('result') == 'PASS' for record in results), 'missing consumer completion'
    assert all(record.get('mode') == mode and record.get('verified_tls') is tls and
               record.get('backend') == ('ex_ssl' if tls else None) and
               record.get('scheme') == ('https' if tls else 'http') and
               record.get('protocol') == ('http2' if tls else 'h2c')
               for record in traffic_results), 'wrong consumer TLS/protocol evidence'
    return dict(mode=mode, protocol='h2' if tls else 'h2c', verified_tls=tls,
                consumers=4, connections=4, mixed_shared_connection=True, completed=True)


def aggregate_modes(results):
    assert len(results) == 2 and {result.get('mode') for result in results} == set(MODES), \
        'both distinct package traffic modes are required'
    for result in results:
        tls = result['mode'] == 'ex_ssl'
        assert result.get('verified_tls') is tls and result.get('protocol') == ('h2' if tls else 'h2c')
        assert result.get('consumers') == 4 and result.get('connections') == 4
        assert result.get('completed') is True and result.get('mixed_shared_connection') is True
    return dict(result='PASS', completed=True, gate='isolated_package_http2_traffic',
                packages=9, consumers=8, connections=8, mixed_shared_connection=True,
                verified_tls=True, modes=results)


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@contextmanager
def candidate_environment(root):
    env = os.environ.copy()
    if env.get('HTTP_FETCH_ARCHIVE_DIR'):
        yield env
        return
    # Freeze one archive set for both modes, rather than rebuilding between them.
    with tempfile.TemporaryDirectory(prefix='http-fetch-package-traffic-') as directory:
        version = env.get('HTTP_FETCH_RELEASE_VERSION') or re.search(
            r'@version "([^"]+)"', (root / 'mix.exs').read_text()).group(1)
        env.update(HTTP_FETCH_RELEASE_VERSION=version,
                   HTTP_FETCH_ARCHIVE_DIR=str(Path(directory) / 'archives'))
        process = subprocess.Popen(
            [sys.executable, str(root / 'scripts/release/stage.py'), 'build', version,
             str(Path(directory) / 'stage'), env['HTTP_FETCH_ARCHIVE_DIR']],
            cwd=root, env=env, start_new_session=True)
        try:
            assert process.wait(timeout=1800) == 0, 'candidate package build failed'
        finally:
            stop(process)
        yield env


def run_mode(root, mode, environment):
    records, consumer_records, failures = [], [], []
    ready = threading.Event()
    peer = subprocess.Popen(
        peer_command(root, mode),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)

    def drain(process, retained, strict=False):
        for line in process.stdout:
            print(line, end='', flush=True)
            try:
                if len(line) > 16384:
                    raise ValueError('package evidence line exceeded bound')
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    if strict:
                        raise ValueError('non-JSON package peer evidence') from None
                    continue
                if not isinstance(record, dict) or len(retained) >= 1000:
                    raise ValueError('invalid or excessive package evidence')
                retained.append(record)
                if 'peer_error' in record:
                    raise ValueError(f'package peer failed: {record}')
                if record.get('kind') == 'ready':
                    ready.set()
            except ValueError as error:
                if len(failures) < 8:
                    failures.append(str(error))

    reader = threading.Thread(target=drain, args=(peer, records, True), daemon=True)
    reader.start()
    consumer = consumer_reader = None
    try:
        assert ready.wait(15), 'package peer readiness deadline'
        port = next(record['port'] for record in records if record.get('kind') == 'ready')
        env = consumer_environment(environment, root, mode, port)
        consumer = subprocess.Popen(['bash', 'scripts/http_runtime_consumer_gate.sh'],
                                    cwd=root, env=env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, start_new_session=True)
        consumer_reader = threading.Thread(target=drain, args=(consumer, consumer_records), daemon=True)
        consumer_reader.start()
        status = consumer.wait(timeout=1800)
        assert status == 0, f'isolated package consumer failed: exit={status}'
        consumer_reader.join(timeout=5)
        assert not consumer_reader.is_alive(), 'consumer output did not terminate'
        stop(peer)
        reader.join(timeout=5)
        assert not reader.is_alive(), 'peer output did not terminate'
        assert not failures, f'package peer failed: {failures}'
        result = validate_mode(records, consumer_records, mode)
        print(json.dumps(dict(result='PASS', gate='isolated_package_http2_mode', **result)), flush=True)
        return result
    finally:
        stop(consumer)
        stop(peer)
        if consumer_reader:
            consumer_reader.join(timeout=5)
        reader.join(timeout=5)


def main():
    def interrupted(_signum, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt('package traffic interrupted')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    root = Path(__file__).resolve().parent.parent
    with candidate_environment(root) as environment:
        results = [run_mode(root, mode, environment) for mode in MODES]
        print(json.dumps(aggregate_modes(results)), flush=True)


if __name__ == '__main__':
    main()

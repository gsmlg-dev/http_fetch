#!/usr/bin/env python3
"""Build seven packages and prove four isolated consumers use real H2 traffic."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading


def main():
    def interrupted(_signum, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt('package traffic interrupted')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    root = Path(__file__).resolve().parent.parent
    records, failures = [], []
    ready = threading.Event()
    peer = subprocess.Popen(
        [sys.executable, str(root / 'scripts/http2_websocket_peer.py')],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)

    def drain():
        for line in peer.stdout:
            print(line, end='', flush=True)
            try:
                record = json.loads(line)
                if len(records) >= 1000 or len(line) > 16384:
                    raise ValueError('package peer evidence exceeded bound')
                records.append(record)
                if 'peer_error' in record:
                    failures.append(record)
                if record.get('kind') == 'ready':
                    ready.set()
            except (ValueError, json.JSONDecodeError) as error:
                failures.append(str(error))

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    consumer = None
    try:
        assert ready.wait(15), 'package peer readiness deadline'
        port = next(record['port'] for record in records if record.get('kind') == 'ready')
        env = os.environ.copy()
        env['HTTP_RUNTIME_CONSUMER_URL'] = f'http://localhost:{port}'
        consumer = subprocess.Popen(['bash', 'scripts/http_runtime_consumer_gate.sh'],
                                    cwd=root, env=env, start_new_session=True)
        status = consumer.wait(timeout=1800)
        assert status == 0, f'isolated package consumer failed: exit={status}'
        os.killpg(peer.pid, signal.SIGTERM)
        peer.wait(timeout=5)
        reader.join(timeout=5)
        assert not failures, f'package peer failed: {failures}'
        connections = [record for record in records if record.get('kind') == 'connection']
        assert len(connections) == 4, f'expected one connection per isolated consumer: {connections}'
        assert all(record['protocol'] == 'h2c' for record in connections)
        traffic = {}
        for record in records:
            if record.get('kind') in ('fetch', 'sse', 'connect'):
                traffic.setdefault(record['connection'], set()).add(record['kind'])
        expected = [{'fetch'}, {'sse'}, {'connect'}, {'fetch', 'sse', 'connect'}]
        assert list(traffic.values()) == expected, f'wrong standalone/mixed wire traffic: {traffic}'
        closed = [record for record in records if record.get('kind') == 'wire_complete']
        assert len(closed) == 2 and [record['messages'] for record in closed] == [1, 2]
        print(json.dumps(dict(result='PASS', completed=True, gate='isolated_package_http2_traffic',
                              packages=7, consumers=4, connections=4, mixed_shared_connection=True)), flush=True)
    finally:
        if consumer and consumer.poll() is None:
            os.killpg(consumer.pid, signal.SIGTERM)
            try:
                consumer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(consumer.pid, signal.SIGKILL)
                consumer.wait(timeout=5)
        if peer.poll() is None:
            os.killpg(peer.pid, signal.SIGTERM)
            try:
                peer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(peer.pid, signal.SIGKILL)
                peer.wait(timeout=5)
        reader.join(timeout=5)


if __name__ == '__main__':
    main()

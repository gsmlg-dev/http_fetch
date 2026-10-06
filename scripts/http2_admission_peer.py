#!/usr/bin/env python3
"""Control-channel barriers around real TCP accept, TLS negotiation and H2 replies."""
import argparse
import json
import socket
import ssl
import sys
import threading
import time

import h2
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import SettingsAcknowledged, StreamEnded
from h2.settings import SettingCodes, Settings

parser = argparse.ArgumentParser()
parser.add_argument('--cert', required=True)
parser.add_argument('--key', required=True)
parser.add_argument('--limit', type=int, default=1)
parser.add_argument('--protocol', choices=['h2', 'http/1.1', 'fail'], default='h2')
args = parser.parse_args()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args.cert, args.key)
context.set_alpn_protocols(['http/1.1' if args.protocol == 'http/1.1' else 'h2'])
handshake = threading.Event()
responses = threading.Event()
lock = threading.Lock()
counts = {'accepted': 0, 'handshakes': 0, 'requests': 0, 'settings_acks': 0,
          'inflight_handshakes': 0, 'peak_inflight_handshakes': 0,
          'negotiation_us_total': 0, 'negotiation_us_max': 0}


def report(event, **fields):
    with lock:
        print(json.dumps({'event': event, **counts, **fields}), flush=True)


def increment(name):
    with lock:
        counts[name] += 1
        print(json.dumps({'event': name, **counts}), flush=True)


def finish_handshake(start, success):
    with lock:
        counts['inflight_handshakes'] -= 1
        if success:
            elapsed = (time.monotonic_ns() - start) // 1000
            counts['handshakes'] += 1
            counts['negotiation_us_total'] += elapsed
            counts['negotiation_us_max'] = max(counts['negotiation_us_max'], elapsed)
        print(json.dumps({'event': 'handshake_settled', **counts}), flush=True)


def serve(raw, started):
    settled = False
    try:
        handshake.wait()
        if args.protocol == 'fail':
            raw.close()
            return
        with context.wrap_socket(raw, server_side=True) as sock:
            sock.settimeout(15)
            finish_handshake(started, True)
            settled = True
            if args.protocol == 'http/1.1':
                data = b''
                while b'\r\n\r\n' not in data:
                    data += sock.recv(65536)
                increment('requests')
                responses.wait()
                sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                # Wait for the consumer to close after parsing the complete reply.
                while sock.recv(65536):
                    pass
                return
            conn = H2Connection(config=H2Configuration(client_side=False))
            conn.local_settings = Settings(client=False, initial_values={SettingCodes.MAX_CONCURRENT_STREAMS: args.limit})
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            while True:
                data = sock.recv(65536)
                if not data:
                    return
                for event in conn.receive_data(data):
                    if isinstance(event, SettingsAcknowledged):
                        increment('settings_acks')
                    if isinstance(event, StreamEnded):
                        increment('requests')
                        responses.wait()
                        conn.send_headers(event.stream_id, [(':status', '200'), ('content-length', '2')])
                        conn.send_data(event.stream_id, b'ok', end_stream=True)
                output = conn.data_to_send()
                if output:
                    sock.sendall(output)
    except (OSError, ssl.SSLError, TimeoutError):
        raw.close()
    except Exception as error:
        report('error', detail=repr(error))
    finally:
        if not settled:
            finish_handshake(started, False)


listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen(128)
report('ready', port=listener.getsockname()[1], peer='hyper-h2', version=h2.__version__)


def accept():
    while True:
        sock, _ = listener.accept()
        started = time.monotonic_ns()
        with lock:
            counts['accepted'] += 1
            counts['inflight_handshakes'] += 1
            counts['peak_inflight_handshakes'] = max(counts['peak_inflight_handshakes'], counts['inflight_handshakes'])
            print(json.dumps({'event': 'accepted', **counts}), flush=True)
        threading.Thread(target=serve, args=(sock, started), daemon=True).start()


threading.Thread(target=accept, daemon=True).start()
for line in sys.stdin:
    command = line.strip()
    if command == 'handshake':
        handshake.set()
    elif command == 'respond':
        responses.set()
    elif command == 'snapshot':
        report('snapshot')
    elif command == 'stop':
        break
listener.close()

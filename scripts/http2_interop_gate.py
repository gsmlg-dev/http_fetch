#!/usr/bin/env python3
"""Run independent peer modes and retain sanitized JSON evidence."""
import argparse
import json
import os
import platform
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--peer', choices=['hyper-h2', 'node'], required=True)
parser.add_argument('--tls', action='store_true')
parser.add_argument('--backend', choices=['ssl', 'ex_ssl'], default='ssl')
parser.add_argument('--mode', choices=['smoke', 'reuse', 'transfer', 'concurrent', 'soak'], default='smoke')
parser.add_argument('--limit', type=int, default=100)
parser.add_argument('--count', type=int, default=10000)
parser.add_argument('--seconds', type=int, default=1800)
parser.add_argument('--package', action='store_true')
args = parser.parse_args()
if args.peer == 'hyper-h2':
    import h2
    import hpack
    import hyperframe
    assert (h2.__version__, hpack.__version__, hyperframe.__version__) == ('4.2.0', '4.1.0', '6.1.0')
else:
    versions = json.loads(subprocess.check_output(['node', '-p', 'JSON.stringify(process.versions)'], text=True))
    assert (versions['node'], versions['nghttp2']) == ('24.19.0', '1.69.0')
root = Path(__file__).resolve().parent.parent
fixtures = root / 'apps/http_fetch/test/support/fixtures'
env = os.environ.copy()
env.update(H2_PEER_LIMIT=str(args.limit), H2_PEER_TLS='1' if args.tls else '0',
           H2_PEER_CERT=str(fixtures / 'localhost.pem'), H2_PEER_KEY=str(fixtures / 'localhost.key'))
if args.peer == 'hyper-h2':
    command = [sys.executable, str(root / 'scripts/http2_production_peer.py'), '--limit', str(args.limit)]
    if args.tls:
        command += ['--tls', '--cert', env['H2_PEER_CERT'], '--key', env['H2_PEER_KEY']]
else:
    command = ['node', str(root / 'scripts/http2_production_peer.mjs')]
peer = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, text=True)
try:
    line = peer.stdout.readline()
    metadata = json.loads(line)
    metadata.update(candidate_sha=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                    candidate_tree=os.environ.get('HTTP_FETCH_CANDIDATE_TREE'),
                    working_tree_dirty=bool(subprocess.check_output(['git', 'diff', '--name-only'], cwd=root, text=True).strip()),
                    platform=platform.platform(), cpus=os.cpu_count(), seed=0)
    print(json.dumps(metadata), flush=True)
    env.update(HTTP_FETCH_GATE_URL=f"{'https' if args.tls else 'http'}://localhost:{metadata['port']}",
               HTTP_FETCH_GATE_BACKEND=args.backend, HTTP_FETCH_GATE_CA=str(fixtures / 'localhost-ca.pem'),
               HTTP_FETCH_GATE_MODE=args.mode, HTTP_FETCH_GATE_SECONDS=str(args.seconds), HTTP_FETCH_GATE_COUNT=str(args.count), MIX_ENV='test')
    command = [str(root / 'scripts/http2_package_gate.sh')] if args.package else ['mix', 'run', str(root / 'scripts/http2_production_gate.exs')]
    result = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
    completed = False
    for line in result.stdout:
        print(line, end='', flush=True)
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get('result') == 'PASS' and record.get('mode') == args.mode:
            completed = args.mode != 'soak' or record.get('elapsed_ms', 0) >= args.seconds * 1000
    status = result.wait()
    if status == 0 and not completed:
        raise RuntimeError('gate exited without a complete workload PASS record')
    sys.exit(status)
finally:
    peer.terminate()
    peer.wait(timeout=5)

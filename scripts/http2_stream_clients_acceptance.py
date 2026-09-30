#!/usr/bin/env python3
"""Run final-candidate Fetch42 and independent SSE/WS/package acceptance.

Requires a separate git archive export and the pinned peer Python environment.
Every gate keeps its original workload; two genuine 1800-second soaks are run.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--tree', required=True)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    source, repository, evidence = (path.resolve() for path in
                                    (args.source, args.repository, args.evidence))
    if source == repository or repository in source.parents:
        parser.error('source must be a separate immutable archive export')
    evidence.mkdir(parents=True, exist_ok=False)
    entries = subprocess.check_output(['git', '-C', str(repository), 'ls-tree', '-rz', args.tree], text=True)

    def snapshot():
        manifest = {}
        for entry in entries.split('\0'):
            if not entry:
                continue
            metadata, name = entry.split('\t', 1)
            mode, kind, expected = metadata.split()
            assert kind == 'blob', f'unsupported entry {name}'
            path = source / name
            content = os.readlink(path).encode() if mode == '120000' else path.read_bytes()
            actual = subprocess.check_output(['git', 'hash-object', '--stdin'], input=content).decode().strip()
            assert actual == expected, f'candidate drift {name}'
            manifest[name] = hashlib.sha256(content).hexdigest()
        extras = [str(path.relative_to(source)) for path in source.rglob('*')
                  if path.is_file() and path.suffix in ('.ex', '.exs', '.py', '.js', '.mjs', '.sh', '.yml', '.yaml', '.beam', '.so')
                  and path.relative_to(source).parts[0] not in {'doc', 'deps', '_build', '.git'}
                  and str(path.relative_to(source)) not in manifest]
        assert not extras, f'untracked executable candidate files: {extras}'
        return manifest

    before = snapshot()
    (evidence / 'source-manifest.json').write_text(json.dumps(before, indent=2) + '\n')
    env = os.environ.copy()
    env.update(MIX_ENV='test', MIX_BUILD_PATH=str(evidence / 'clients-build'),
               MIX_DEPS_PATH=str(repository / 'deps'), GIT_DIR=str(repository / '.git'),
               GIT_WORK_TREE=str(source), HTTP_FETCH_CANDIDATE_TREE=args.tree,
               HTTP2_PEER_PYTHON=sys.executable)
    env.setdefault('ERL_FLAGS', '+S 4:4')
    gates = {}
    for peer in ('hyper-h2', 'node'):
        for route, flags in (('h2c', []), ('ssl', ['--tls', '--backend', 'ssl']),
                             ('ex_ssl', ['--tls', '--backend', 'ex_ssl'])):
            for mode in ('sse', 'mixed', 'faults'):
                gates[f'sse-{peer}-{route}-{mode}'] = [sys.executable, 'scripts/http2_stream_clients_gate.py',
                                                     '--peer', peer, *flags, '--mode', mode]
        gates[f'sse-{peer}-churn'] = [sys.executable, 'scripts/http2_stream_clients_gate.py',
                                    '--peer', peer, '--mode', 'churn', '--count', '1001']
    for route, flags in (('h2c', []), ('ssl', ['--tls', '--backend', 'ssl']),
                         ('ex_ssl', ['--tls', '--backend', 'ex_ssl'])):
        for mode in ('echo', 'mixed', 'faults'):
            gates[f'ws-{route}-{mode}'] = [sys.executable, 'scripts/http2_websocket_gate.py',
                                         *flags, '--mode', mode]
        gates[f'ws-node-{route}-mixed'] = [sys.executable, 'scripts/http2_websocket_gate.py',
                                          '--peer', 'node', *flags, '--mode', 'mixed']
    gates['ws-churn'] = [sys.executable, 'scripts/http2_websocket_gate.py', '--mode', 'churn', '--count', '1000']
    gates['package-traffic'] = [sys.executable, 'scripts/http_runtime_package_traffic_gate.py']
    gates['docs'] = ['env', 'MIX_ENV=dev', f'MIX_BUILD_PATH={evidence / "docs-build"}',
                      'bash', 'scripts/http2_stream_clients_docs_gate.sh']
    gates['mixed-soak'] = [sys.executable, 'scripts/http2_websocket_gate.py', '--tls', '--backend', 'ex_ssl',
                           '--mode', 'soak', '--seconds', '1800', '--timeout', '2100']
    gates['fetch42'] = [sys.executable, 'scripts/http2_fetch42_gate.py', '--source', str(source),
                        '--repository', str(repository), '--tree', args.tree,
                        '--evidence', str(evidence / 'fetch42')]
    (evidence / 'commands.json').write_text(json.dumps(gates, indent=2) + '\n')
    active, active_lock, stopped = set(), threading.RLock(), threading.Event()

    def stop_group(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            except ProcessLookupError:
                pass

    def interrupted(_signum, _frame):
        stopped.set()
        with active_lock:
            running = list(active)
        for process in running:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        raise KeyboardInterrupt('acceptance interrupted; remaining gates NOT RUN')

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)

    def run(name, command, timeout):
        if stopped.is_set():
            return dict(gate=name, exit_status=130, not_run=True)
        start = time.monotonic()
        path = evidence / f'{name}.log'
        with path.open('w') as log:
            log.write(f'candidate_tree={args.tree}\ncommand={shlex.join(command)}\n')
            log.flush()
            process = subprocess.Popen(command, cwd=source, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            with active_lock:
                active.add(process)
            try:
                if stopped.is_set():
                    stop_group(process)
                status = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_group(process)
                status = 124
            finally:
                stop_group(process)
                with active_lock:
                    active.discard(process)
            elapsed = round((time.monotonic() - start) * 1000)
            log.write(f'\nexit_status={status}\nelapsed_ms={elapsed}\n')
        snapshot()
        result = dict(gate=name, exit_status=status, elapsed_ms=elapsed, candidate_tree=args.tree,
                      log_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        (evidence / f'{name}.result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        return result

    for name, command in [('prepare-deps', ['mix', 'deps.get', '--check-locked']),
                           ('prepare-compile', ['mix', 'compile', '--warnings-as-errors'])]:
        assert run(name, command, 600)['exit_status'] == 0, f'{name} failed'
    results = []
    # Fetch42 and docs use separate builds; prepared new-client gates share a read-only build.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(run, name, gates[name], 3600) for name in ('fetch42', 'mixed-soak')]
        for name, command in gates.items():
            if name not in ('fetch42', 'mixed-soak'):
                futures.append(pool.submit(run, name, command, 1800))
        results = [future.result() for future in futures]
    assert all(result['exit_status'] == 0 for result in results), 'FAIL: inspect gate results'
    assert snapshot() == before, 'source manifest changed'
    print(json.dumps(dict(result='PASS', completed=True, candidate_tree=args.tree,
                          fetch_gates=42, new_gates=len(gates) - 1,
                          requested_soak_seconds=1800)), flush=True)


if __name__ == '__main__':
    main()

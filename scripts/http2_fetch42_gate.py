#!/usr/bin/env python3
"""Reproduce the accepted 42 Fetch gates without historical /tmp dependencies.

Run with the pinned independent-peer Python environment. Source must be an
immutable exported candidate; pass its verified Git tree and separate evidence.
No workload size, original regression assertion, or backend is reduced.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import threading
import time


def commands(evidence):
    gates = {
        'final-deps': ['mix', 'deps.get', '--check-locked'],
        'final-compile': ['mix', 'compile', '--warnings-as-errors'],
        'final-format': ['mix', 'format', '--check-formatted'],
        'final-full-tests': ['mix', 'test', '--seed', '342781', '--max-cases', '8'],
        'final-credo': ['mix', 'credo', '--all'],
        'final-dialyzer': ['mix', 'dialyzer'],
        'final-hpack': ['mix', 'run', 'scripts/http2_hpack_gate.exs'],
        'final-external-consumer': ['env', '-u', 'MIX_BUILD_PATH', '-u', 'MIX_DEPS_PATH',
                                    '-u', 'GIT_DIR', '-u', 'GIT_WORK_TREE',
                                    'bash', 'scripts/external_consumer_smoke.sh'],
        'final-exssl-feature-consumer': ['env', '-u', 'GIT_DIR', '-u', 'GIT_WORK_TREE',
                                        'EX_SSL_DEP_MODE=published',
                                        f'EX_SSL_RESULTS_DIR={evidence / "published-exssl"}',
                                        'bash', 'scripts/ex_ssl_source_smoke.sh'],
        'final-tls-lifecycle-ci': ['mix', 'test',
                                 'apps/http_fetch/test/http/socket_client_http2_test.exs',
                                 '--seed', '36'],
        'final-runtime-regressions': ['env', 'ERL_FLAGS=+S 4:4', 'mix', 'test',
            'apps/http_core/test/http/http2_scheduler_test.exs',
            'apps/http_core/test/http/owner_monitor_test.exs',
            *[f'apps/http_fetch/test/http/{name}_test.exs' for name in (
                'http2_early_response_closure', 'http2_pool_progress',
                'http2_queue_socket_progress', 'http2_production_lifecycle',
                'http2_runtime_telemetry', 'http2_failed_open_cleanup')],
            '--seed', '342781', '--max-cases', '8'],
        'final-environment': [sys.executable, str(Path(__file__).resolve()), '--environment'],
    }
    for repeat in range(1, 4):
        gates[f'final-cold-fetch-repeat-{repeat}'] = [
            'env', 'ERL_FLAGS=+S 4:4', 'mix', 'test', 'apps/http_fetch/test',
            '--seed', '342781', '--max-cases', '8']
    interop = [sys.executable, 'scripts/http2_interop_gate.py']
    for peer in ('hyper-h2', 'node'):
        for transport, opts in (('h2c', []), ('tls-ssl', ['--tls', '--backend', 'ssl']),
                                ('tls-ex_ssl', ['--tls', '--backend', 'ex_ssl'])):
            for mode in ('smoke', 'transfer', 'concurrent'):
                gates[f'final-{mode}-{peer}-{transport}'] = [
                    *interop, '--peer', peer, *opts, '--mode', mode]
        for limit in (1, 2, 100):
            gates[f'final-reuse-{peer}-limit-{limit}'] = [
                *interop, '--peer', peer, '--mode', 'reuse', '--count', '10000',
                '--limit', str(limit)]
    for backend in ('ssl', 'ex_ssl'):
        gates[f'final-package-tls-{backend}'] = [
            'env', '-u', 'MIX_DEPS_PATH', *interop, '--peer', 'hyper-h2',
            '--tls', '--backend', backend, '--mode', 'smoke', '--package']
    gates['final-soak'] = [*interop, '--peer', 'node', '--tls', '--backend', 'ex_ssl',
                           '--mode', 'soak', '--seconds', '1800']
    assert len(gates) == 42
    return gates


def environment_report():
    import platform
    import h2
    import hpack
    import hyperframe
    print(json.dumps({'platform': platform.platform(), 'cpus': os.cpu_count(),
                      'python': sys.version, 'h2': h2.__version__,
                      'hpack': hpack.__version__, 'hyperframe': hyperframe.__version__}))
    for command in (['mix', '--version'], ['erl', '-noshell', '-eval',
        'io:format("otp_system=~s~n", [erlang:system_info(system_version)]), halt().'],
        ['node', '-p', 'JSON.stringify(process.versions)']):
        subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--tree')
    parser.add_argument('--repository', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--environment', action='store_true')
    args = parser.parse_args()
    if args.environment:
        environment_report()
        return
    if not all((args.source, args.evidence, args.tree)):
        parser.error('--source, --evidence, and --tree are required')
    source, evidence, repository = (p.resolve() for p in (
        args.source, args.evidence, args.repository))
    if source == repository or repository in source.parents:
        parser.error('--source must be a separate immutable Git archive export')

    def verify_source():
        entries = subprocess.check_output(
            ['git', '-C', str(repository), 'ls-tree', '-rz', args.tree], text=True)
        tracked = set()
        for entry in entries.split('\0'):
            if not entry:
                continue
            metadata, name = entry.split('\t', 1)
            tracked.add(name)
            mode, kind, expected = metadata.split()
            if kind != 'blob':
                raise RuntimeError(f'unsupported candidate entry: {name}')
            path = source / name
            if mode == '120000':
                content = os.readlink(path).encode()
            else:
                content = path.read_bytes()
            actual = subprocess.check_output(
                ['git', 'hash-object', '--stdin'], input=content).decode().strip()
            if actual != expected:
                raise RuntimeError(f'candidate source drift: {name}')
        extras = [str(path.relative_to(source)) for path in source.rglob('*')
                  if path.is_file() and path.suffix in ('.ex', '.exs', '.py', '.js', '.mjs', '.sh', '.yml', '.yaml', '.beam', '.so')
                  and path.relative_to(source).parts[0] not in {'doc', 'deps', '_build', '.git'}
                  and str(path.relative_to(source)) not in tracked]
        if extras:
            raise RuntimeError(f'untracked executable candidate files: {extras}')

    verify_source()
    evidence.mkdir(parents=True, exist_ok=False)
    gates = commands(evidence)
    env = os.environ.copy()
    env.update(HTTP_FETCH_CANDIDATE_TREE=args.tree, MIX_ENV='test',
               MIX_BUILD_PATH=str(evidence / 'build'),
               MIX_DEPS_PATH=str(repository / 'deps'),
               GIT_DIR=str(repository / '.git'), GIT_WORK_TREE=str(source),
               HTTP2_PEER_PYTHON=sys.executable)
    env.setdefault('ERL_FLAGS', '+S 4:4')
    lock, stopped = threading.Lock(), threading.Event()
    active, active_lock = set(), threading.RLock()

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
        raise KeyboardInterrupt('Fetch acceptance interrupted; remaining gates NOT RUN')

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    (evidence / 'commands.json').write_text(json.dumps(gates, indent=2) + '\n')

    def run(gate):
        if stopped.is_set():
            return None
        gate_env = env.copy()
        hex_home = evidence / 'hex-cache' / gate
        hex_home.mkdir(parents=True, exist_ok=False)
        gate_env['HEX_HOME'] = str(hex_home)
        started = time.monotonic()
        with (evidence / f'{gate}.log').open('w') as log:
            log.write(f'candidate_tree={args.tree}\ncommand={shlex.join(gates[gate])}\n')
            log.flush()
            process = subprocess.Popen(gates[gate], cwd=source, env=gate_env,
                                       stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            with active_lock:
                active.add(process)
            try:
                if stopped.is_set():
                    stop_group(process)
                status = process.wait(timeout=2400 if gate == 'final-soak' else 1800)
            except subprocess.TimeoutExpired:
                stop_group(process)
                status = 124
                log.write('\nFAIL: gate deadline exceeded\n')
            finally:
                stop_group(process)
                with active_lock:
                    active.discard(process)
            elapsed = int((time.monotonic() - started) * 1000)
            log.write(f'\nexit_status={status}\nelapsed_ms={elapsed}\n')
        verify_source()
        with lock:
            with (evidence / 'results.tsv').open('a') as ledger:
                ledger.write(f'{gate}\t{status}\t{elapsed}\t{args.tree}\n')
            print(f'{gate}: exit={status}, elapsed_ms={elapsed}', flush=True)
        if status:
            stopped.set()
        return status

    def batch(names, workers):
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            return all(status == 0 for status in list(executor.map(run, names)))

    preparation = ('final-deps', 'final-compile', 'final-format')
    tests = ('final-full-tests', *[f'final-cold-fetch-repeat-{i}' for i in range(1, 4)])
    packages = ('final-package-tls-ssl', 'final-package-tls-ex_ssl', 'final-tls-lifecycle-ci')
    if not all(run(gate) == 0 for gate in preparation) or not batch(tests, 4) or not batch(packages, 3):
        raise SystemExit('FAIL: prerequisite gate; remaining workloads NOT RUN')
    remaining = [gate for gate in gates if gate not in (*preparation, *tests, *packages)]
    # Start the genuine 30-minute workload alongside independent finite gates.
    remaining.remove('final-soak')
    if not batch(['final-soak', *remaining], 5):
        raise SystemExit('FAIL or NOT RUN: inspect ledger and logs')
    print(json.dumps({'result': 'PASS', 'gates': len(gates), 'candidate_tree': args.tree}), flush=True)


if __name__ == '__main__':
    main()

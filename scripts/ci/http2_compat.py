#!/usr/bin/env python3
"""Run shared H2 consumer regression gates and retain candidate evidence."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import time


def terminal_pass(records, kind):
    for record in records:
        if record.get('result') != 'PASS':
            continue
        if kind == 'package':
            modes = record.get('modes')
            if not isinstance(modes, list) or len(modes) != 2 or not all(
                    isinstance(mode, dict) for mode in modes):
                continue
            if not all(mode.get('mode') in ('h2c', 'ex_ssl') for mode in modes) or \
                    {mode.get('mode') for mode in modes} != {'h2c', 'ex_ssl'}:
                continue
            if not all(mode.get('verified_tls') is (mode['mode'] == 'ex_ssl') and
                       mode.get('protocol') == ('h2' if mode['mode'] == 'ex_ssl' else 'h2c') and
                       mode.get('consumers') == 4 and mode.get('connections') == 4 and
                       mode.get('completed') is True and mode.get('mixed_shared_connection') is True
                       for mode in modes):
                continue
            if all(record.get(key) == value for key, value in {
                    'gate': 'isolated_package_http2_traffic', 'completed': True,
                    'packages': 9, 'consumers': 8, 'connections': 8,
                    'mixed_shared_connection': True, 'verified_tls': True}.items()):
                return True
        elif (record.get('mode') == 'wire-audit' and record.get('public_client') is True
              and record.get('observations', 0) > 0
              and (kind == 'sse' or record.get('completed') is True)):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.evidence.mkdir(parents=True, exist_ok=False)
    candidate = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    env = {**os.environ, 'MIX_ENV': 'test'}
    env.pop('HTTP_FETCH_CI_APP', None)
    report = dict(candidate=candidate, status='RUNNING', gates=[], exclusions=[
        'This finite gate excludes long soaks; candidate production acceptance runs them separately.'])

    def save():
        (args.evidence / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(name, command, peer=None, backend=None, traffic_kind=None):
        path = args.evidence / f'{name}.log'
        record = dict(name=name, command=command, peer=peer, backend=backend,
                      candidate=candidate, status='RUNNING')
        report['gates'].append(record)
        save()
        start = time.monotonic()
        with path.open('w') as log:
            process = subprocess.Popen(command, cwd=root, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                status = process.wait(timeout=1800)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
        content = path.read_text()
        passes = []
        for line in content.splitlines():
            try:
                entry = json.loads(line)
                if isinstance(entry, dict) and entry.get('result') == 'PASS':
                    passes.append(entry)
            except json.JSONDecodeError:
                pass
        record.update(exit_status=status, elapsed_ms=round((time.monotonic() - start) * 1000),
                      log_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                      passes=passes, test_summaries=[line for line in content.splitlines()
                                                   if 'tests,' in line or 'excluded' in line])
        record['status'] = 'PASS' if status == 0 and (traffic_kind is None or terminal_pass(passes, traffic_kind)) else 'FAIL'
        save()
        if record['status'] != 'PASS':
            raise RuntimeError(f'{name} failed; see {path}')
        print(json.dumps(record), flush=True)

    try:
        run('prepare-deps', ['mix', 'deps.get', '--check-locked'])
        run('prepare-compile', ['mix', 'compile', '--warnings-as-errors'])
        run('selectors', [sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/ci', '-p', 'test_*.py', '-v'])
        run('root-format', ['mix', 'format', '--check-formatted', 'mix.exs', '.formatter.exs', 'config/config.exs'])
        run('consumer-tests', ['mix', 'test', 'apps/http_core/test', 'apps/http_runtime/test',
                               'apps/http_fetch/test', 'apps/http_event_source/test',
                               'apps/http_web_socket/test', '--include', 'integration', '--seed', '36'])
        for peer in ('hyper-h2', 'node'):
            for route, flags in (('h2c', []), ('ex_ssl', ['--tls', '--backend', 'ex_ssl'])):
                run(f'fetch-sse-{peer}-{route}', [sys.executable, 'scripts/http2_stream_clients_gate.py',
                    '--peer', peer, *flags, '--mode', 'mixed'], peer, route, 'sse')
                run(f'fetch-sse-ws-{peer}-{route}', [sys.executable, 'scripts/http2_websocket_gate.py',
                    '--peer', peer, *flags, '--mode', 'mixed'], peer, route, 'ws')
        version = re.search(r'@version "([^"]+)"', (root / 'mix.exs').read_text()).group(1)
        archives = args.evidence / 'archives'
        run('candidate-packages', [sys.executable, 'scripts/release/stage.py', 'build', version,
                                  str(args.evidence / 'stage'), str(archives)])
        report['packages'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in sorted(archives.glob('*.tar'))}
        if len(report['packages']) != 9:
            raise RuntimeError('expected nine candidate package artifacts')
        env.update(HTTP_FETCH_ARCHIVE_DIR=str(archives), HTTP_FETCH_RELEASE_VERSION=version)
        run('candidate-package-traffic', [sys.executable, 'scripts/http_runtime_package_traffic_gate.py'],
            'hyper-h2', 'h2c+ex_ssl', 'package')
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', error=str(error))
        raise
    finally:
        save()


if __name__ == '__main__':
    main()

"""Build an isolated candidate or published release and run the no-OTP-SSL gate.

This command starts real build tools and external peers. Unit tests mock those
collaborators. A passing mock run is never production removal evidence.

Usage: python3 no_otp_consumer_gate.py VERSION ARCHIVES STAGE --source-root ROOT
       --source-sha SHA --peer-plan PLAN.json --output NEW_DIRECTORY
       [--published]

Published mode requires all nine Hex archives to match the source-bound release
archives, then resolves packages with fresh Hex configuration and cache paths.

PLAN schema 1 contains pinned external peers and all REQUIRED scenarios. Peers
receive NO_OTP_NONCE in their environment. The structured JSON-line peer protocol
emits {kind:ready, port, identity} followed by independently observed scenario
records (kind:scenario, id, nonce, client, action, tls, alpn, requests, executed,
result, peer_identity, fallback, replay). Its stdin accepts {command:stats}.
Existing performance/h2_websocket/http3 raw peers can also be collected; missing
TLS/reset/replay evidence remains unconfirmed, never synthetic success.
"""

import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from urllib.parse import urlsplit

import archive_audit
import consumer_gate
from stage import PACKAGES, portable_manifest

HERE = Path(__file__).resolve().parent
CLIENTS = ('h1', 'h2', 'wss', 'sse', 'managed_h1', 'managed_h2', 'h3')
ACTIONS = ('success', 'invalid_identity', 'timeout', 'cancellation', 'shutdown')
REQUIRED = frozenset((client, action) for client in CLIENTS for action in ACTIONS)
MODULES = ('HTTP', 'SSL.Connection', 'Quic', 'QuicHttp3.Session',
           'HTTP.ManagedTransport', 'HTTP.WebSocket', 'HTTP.EventSource')
PROVENANCE = '''expected = System.fetch_env!("NO_OTP_VERSION")
project = System.fetch_env!("NO_OTP_PROJECT")
packages = ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)a
for app <- packages do
  dep = Enum.find(Mix.Dep.cached(), &(&1.app == app)) || raise("missing candidate #{app}")
  unless dep.scm == Hex.SCM and dep.opts[:hex] == Atom.to_string(app) and
           dep.status == {:ok, expected} and
           Path.expand(dep.opts[:dest]) == Path.join(project, "deps/#{app}"),
    do: raise("non-isolated or wrong-version candidate #{app}")
end
for dep <- Mix.Dep.cached() do
  unless dep.scm == Hex.SCM and not dep.opts[:override] and
           Path.expand(dep.opts[:dest]) == Path.join(project, "deps/#{dep.app}"),
    do: raise("transitive dependency escaped isolated Hex resolution")
end
loaded = for module <- [HTTP, SSL.Connection, Quic, QuicHttp3.Session, HTTP.ManagedTransport, HTTP.WebSocket, HTTP.EventSource] do
  Code.ensure_loaded!(module)
  path = :code.which(module) |> to_string() |> Path.expand()
  unless String.starts_with?(path, Path.join(project, "build") <> "/"),
    do: raise("module escaped candidate build: #{module}")
  {inspect(module), path}
end
IO.puts(JSON.encode!(%{gate: "no_otp_hex_provenance", version: expected, scm: "Hex.SCM", loaded_modules: Map.new(loaded)}))
'''


class GateError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise GateError(message)


def stable_version(version):
    require(isinstance(version, str) and re.fullmatch(
        r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)', version),
        'stable coordinated version required')


def validate_plan(plan):
    require(isinstance(plan, dict) and plan.get('schema') == 1, 'peer plan schema 1 required')
    peers = plan.get('peers')
    cases = plan.get('scenarios')
    require(isinstance(peers, dict) and peers, 'external peers required')
    require(isinstance(cases, list) and len(cases) == len(REQUIRED), 'complete scenario matrix required')
    for name, peer in peers.items():
        require(re.fullmatch(r'[a-zA-Z0-9_-]{1,60}', name), 'invalid peer name')
        require(isinstance(peer, dict) and peer.get('kind', 'structured') in
                ('structured', 'performance', 'h2_websocket', 'http3'), 'unknown peer observation adapter')
        require(isinstance(peer.get('argv'), list) and peer['argv'] and
                all(isinstance(arg, str) and arg and '\x00' not in arg for arg in peer['argv']),
                'peer argv required; no shell commands')
        require(isinstance(peer.get('script'), str) and peer['script'] in peer['argv'], 'pin actual peer script')
        require(re.fullmatch(r'[a-f0-9]{64}', peer.get('sha256', '')), 'peer script SHA256 required')
    seen = set()
    identifiers = set()
    for case in cases:
        pair = (case.get('client'), case.get('action'))
        require(pair in REQUIRED and pair not in seen, 'missing/duplicate/unknown mandatory scenario')
        seen.add(pair)
        require(isinstance(case.get('id'), str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,100}', case['id'])
                and case['id'] not in identifiers, 'unique bounded scenario id required')
        identifiers.add(case['id'])
        require(case.get('peer') in peers, 'scenario peer missing')
        require(case.get('tls') in ('TLSv1.2', 'TLSv1.3'), 'exact peer TLS version required')
        allowed = ('h3',) if case['client'] == 'h3' else (
            ('http/1.1',) if case['client'] in ('h1', 'managed_h1') else ('h2',))
        require(case.get('alpn') in allowed, 'wrong scenario protocol/ALPN')
        require(case['client'] != 'h3' or case['tls'] == 'TLSv1.3', 'QUIC requires TLS1.3')
        url = case.get('url', '')
        scheme = 'wss://' if case['client'] == 'wss' else 'https://'
        require(isinstance(url, str) and url.startswith(scheme) and url.count('{port}') == 1
                and not any(ord(char) <= 32 or ord(char) == 127 for char in url),
                'verified peer URL with one port placeholder required')
        parsed = urlsplit(url.replace('{port}', '1'))
        require(parsed.netloc == 'localhost:1' and not parsed.fragment and
                '{' not in parsed.path + parsed.query and '}' not in parsed.path + parsed.query,
                'owned localhost peer route without credentials/fragment required')
        needs_gate = (case['action'] == 'cancellation' and case['client'] in
                      ('h1', 'h2', 'managed_h1', 'managed_h2')) or (
                          case['client'] == 'h3' and case['action'] in
                          ('timeout', 'cancellation', 'shutdown'))
        if needs_gate:
            path = case.get('gate_file')
            require(isinstance(path, str) and path.startswith('{run}/') and
                    '..' not in Path(path).parts and path.count('{run}') == 1 and
                    '{' not in path[6:] and '}' not in path[6:],
                    'independent per-scenario gate file beneath fresh run directory required')
        require(isinstance(case.get('ca_file'), str) and case['ca_file'], 'explicit captured peer CA required')
        require(type(case.get('timeout_ms')) is int and 1 <= case['timeout_ms'] <= 30_000,
                'finite scenario timeout in 1..30000ms required')
        require(isinstance(case.get('expected'), str), 'exact expected payload required')
    require(seen == REQUIRED, 'mandatory scenario missing')
    return plan


def project_source(version):
    stable_version(version)
    dependencies = ', '.join('{:' + package + ', "== ' + version + '"}' for package in PACKAGES)
    return f'''defmodule NoOTP.ConsumerProject do
  use Mix.Project
  def project do
    [app: :no_otp_consumer, version: "0.0.0", deps: [{dependencies}],
     releases: [no_otp_consumer: [include_erts: true, strip_beams: false]]]
  end
  def application, do: [extra_applications: [:logger, :public_key]]
end
'''


def production_environment(directory, inherited):
    env = dict(inherited)
    for key in tuple(env):
        if key.startswith(('RELEASE_', 'ERL_')):
            env.pop(key)
    for key in ('ERL_LIBS', 'ERL_FLAGS', 'ERL_AFLAGS', 'ERL_ZFLAGS', 'ELIXIR_ERL_OPTIONS',
                'MIX_BUILD_PATH', 'MIX_DEPS_PATH', 'MIX_ENV', 'MIX_TARGET', 'MIX_EXS',
                'HEX_HOME', 'HEX_MIRROR', 'HEX_TRUSTED_MIRROR', 'HEX_UNSAFE_REGISTRY',
                'HEX_UNSAFE_HTTPS', 'HTTP_FETCH_CI_APP', 'RELEASE_ROOT', 'RELEASE_COOKIE',
                'RELEASE_DISTRIBUTION', 'RELEASE_NODE'):
        env.pop(key, None)
    env.update(MIX_ENV='prod', MIX_BUILD_PATH=str(directory / 'build'),
               MIX_DEPS_PATH=str(directory / 'deps'), HEX_HOME=str(directory / 'hex'),
               PYTHONDONTWRITEBYTECODE='1')
    return env


def within(path, root):
    return Path(path).is_absolute() and Path(os.path.normpath(path)).is_relative_to(
        Path(os.path.normpath(root)))


def validate_runtime(state, release):
    require(isinstance(state, dict), 'runtime isolation evidence missing')
    for key in ('ssl_available', 'ssl_loaded', 'ssl_application_loaded', 'ssl_started'):
        require(state.get(key) is False, f'{key}: OTP ssl unavailable/not-loaded/not-started must be proved')
    paths = state.get('code_paths')
    require(isinstance(paths, list) and paths, 'actual release code paths required')
    modules = state.get('loaded_modules')
    require(isinstance(modules, dict) and set(MODULES).issubset(modules), 'all representative loaded module paths required')
    all_loaded = state.get('all_loaded_paths')
    require(isinstance(all_loaded, dict) and all_loaded, 'complete loaded production module inventory required')
    state['canonical_paths'] = {}
    state['canonical_errors'] = {}
    try:
        canonical_release = release.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        state['canonical_errors'][str(release)] = str(error)
        raise GateError('canonical release path unconfirmed') from error
    state['canonical_release'] = str(canonical_release)
    require(str(canonical_release) == str(release), 'canonical release root escaped owned directory')
    for path in paths + list(modules.values()) + list(all_loaded.values()):
        require(isinstance(path, str) and within(path, release), 'host/umbrella module path escaped release')
        try:
            canonical = str(Path(path).resolve(strict=True))
        except (OSError, RuntimeError) as error:
            state['canonical_errors'][path] = str(error)
            raise GateError('canonical module path unconfirmed') from error
        state['canonical_paths'][path] = canonical
        require(within(canonical, canonical_release), 'canonical module path escaped owned release')
        require(not any(part in ('test', 'support', '_build', 'deps') or
                        part.startswith('ssl-') for part in Path(path).parts + Path(canonical).parts),
                'OTP ssl or test support on production code path')


def validate_artifacts(report, version):
    require(isinstance(report, dict), 'artifact audit missing')
    for field in ('checked_app_files', 'checked_rel_files', 'checked_boot_files', 'checked_beams'):
        require(type(report.get(field)) is int and report[field] > 0, f'{field}: no artifacts inspected')
    for field in ('ssl_app_dependencies', 'ssl_bundle_paths', 'ssl_boot_entries',
                  'direct_otp_ssl_imports', 'unresolved_dispatch', 'missing_abstract_code',
                  'duplicate_package_apps'):
        require(report.get(field) == [], f'{field}: forbidden or unconfirmed production evidence')
    require(report.get('package_versions') == {package: version for package in PACKAGES},
            'all nine release package versions must match candidate archives')


def validate_scenario(case, consumer, peer, nonce):
    count = 0 if case['action'] == 'invalid_identity' else 1
    for origin, record in (('consumer', consumer), ('peer', peer)):
        require(isinstance(record, dict), f'{origin}: missing scenario')
        for key in ('id', 'client', 'action'):
            require(record.get(key) == case[key], f'{origin}: wrong {key}')
        require(record.get('nonce') == nonce, f'{origin}: stale scenario generation')
        require(record.get('result') == 'PASS' and type(record.get('executed')) is int
                and record['executed'] == 1, f'{origin}: skipped/zero/failed scenario')
        require(isinstance(record.get('peer_identity'), str) and record['peer_identity'],
                f'{origin}: independent peer identity missing')
    require(consumer['peer_identity'] == peer['peer_identity'], 'consumer/peer identity mismatch')
    require(consumer.get('requested_tls') == case['tls'] and consumer.get('required_alpn') == case['alpn'],
            'consumer requested policy mismatch')
    require(consumer.get('fallback_isolated') is True and consumer.get('requests_submitted') == 1,
            'consumer actual isolation/submission evidence missing')
    require(peer.get('tls') == case['tls'] and peer.get('alpn') == case['alpn'],
            'peer actual TLS/ALPN mismatch')
    require(peer.get('fallback') is False and peer.get('replay') is False,
            'independent peer fallback/replay evidence missing or failed')
    require(type(peer.get('requests')) is int and peer['requests'] == count,
            'wrong independent traffic count')
    require(consumer.get('cleanup') == 'confirmed', 'provider cleanup pending/unconfirmed/unsupported')
    allowed = {'request_completion', 'client_completion', 'managed_receipt', 'quic_session_endpoint'}
    require(consumer.get('cleanup_kind') in allowed, 'logical close/PID DOWN is not provider cleanup proof')
    expected_kind = ('quic_session_endpoint' if case['client'] == 'h3' else
                     'managed_receipt' if case['client'].startswith('managed_') else
                     'client_completion' if case['client'] in ('wss', 'sse') else 'request_completion')
    require(consumer['cleanup_kind'] == expected_kind, 'cleanup barrier belongs to a different client/resource scope')


class Runner:
    """Every command owns one new session; only that group is stopped/reaped."""

    def __init__(self, directory, max_seconds=1800):
        self.directory = directory
        self.deadline = time.monotonic() + max_seconds
        self.commands = []

    def remaining(self, limit=300):
        left = min(limit, self.deadline - time.monotonic())
        require(left > 0, 'whole gate deadline exceeded')
        return left

    @staticmethod
    def stop(process):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                return process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        return process.communicate(timeout=5)

    def command(self, args, *, cwd=None, env=None, limit=300):
        started = time.monotonic()
        entry = dict(argv=list(map(str, args)), cwd=str(cwd), exit=None)
        self.commands.append(entry)
        process = subprocess.Popen(entry['argv'], cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, start_new_session=True)
        try:
            output, _ = process.communicate(timeout=self.remaining(limit))
        except BaseException:
            output, _ = self.stop(process)
            entry.update(exit=process.returncode, timeout_or_interrupt=True)
            raise GateError('owned command interrupted or exceeded deadline') from None
        finally:
            entry['elapsed_seconds'] = time.monotonic() - started
            self.directory.joinpath(f'command-{len(self.commands):03d}.log').write_text(
                locals().get('output', 'output unavailable'))
            self.directory.joinpath('commands.json').write_text(json.dumps(self.commands, indent=2))
        entry['exit'] = process.returncode
        self.directory.joinpath('commands.json').write_text(json.dumps(self.commands, indent=2))
        require(process.returncode == 0, f'owned command failed: exit={process.returncode}')
        return output


def build_release(project, release, env, runner):
    runner.command(['unbuffer', 'mix', 'deps.get'], cwd=project, env=env)
    runner.command(['unbuffer', 'mix', 'compile', '--warnings-as-errors'], cwd=project, env=env)
    runner.command(['unbuffer', 'mix', 'run', '--no-start', '-e', PROVENANCE], cwd=project, env=env)
    runner.command(['unbuffer', 'mix', 'release', 'no_otp_consumer', '--path', str(release)],
                   cwd=project, env=env)


def release_command(release):
    return [str(release / 'bin/no_otp_consumer'), 'eval', 'NoOTP.Consumer.run()']


def verify_source(stage, source, archives, version):
    """Reuse archive audit, then bind portable staged bytes to actual source bytes."""
    pinned = {}
    for package in PACKAGES:
        archive_audit.audit_package(package, version, stage, archives)
        archive = archives / f'{package}-{version}.tar'
        with tarfile.open(archive) as outer:
            content = outer.extractfile('contents.tar.gz').read()
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as inner:
            members = inner.getmembers()
            require(all(member.isfile() or member.isdir() for member in members),
                    'archive links/devices have no safe source provenance')
            names = sorted(member.name for member in members if member.isfile())
        for name in names:
            relative = Path(name)
            require(not relative.is_absolute() and '..' not in relative.parts, 'archive path escaped stage')
            path = stage / package / relative
            original = source / 'apps' / package / relative
            require(original.is_file(), f'staged file lacks source provenance: {package}/{relative}')
            wanted = portable_manifest(original.read_text()).encode() if relative == Path('mix.exs') else original.read_bytes()
            require(path.read_bytes() == wanted, f'staged source differs: {package}/{relative}')
            pinned[f'{package}/{relative}'] = hashlib.sha256(wanted).hexdigest()
    return pinned


class Peer:
    def __init__(self, name, config, directory, env, runner):
        self.name, self.config, self.directory, self.runner = name, config, directory, runner
        script = Path(config['script']).resolve()
        require(hashlib.sha256(script.read_bytes()).hexdigest() == config['sha256'], 'external peer script pin changed')
        self.records, self.lines, self.messages = [], [], queue.Queue()
        argv = [arg.replace('{run}', str(directory)) for arg in config['argv']]
        self.process = subprocess.Popen(argv, cwd=directory, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, start_new_session=True, bufsize=1)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        try:
            ready = self.messages.get(timeout=runner.remaining(15))
            if config.get('kind') == 'http3' and isinstance(ready, int):
                ready = dict(port=ready, identity=config['sha256'])
            require(isinstance(ready, dict) and (ready.get('kind') == 'ready' or ready.get('event') == 'ready'
                    or config.get('kind') == 'http3'), 'peer readiness missing')
            require(type(ready.get('port')) is int and 0 < ready['port'] < 65536, 'peer port invalid')
            self.ready = ready
        except BaseException:
            self.close()
            raise

    def _read(self):
        for line in self.process.stdout:
            if len(line) > 1_048_576 or len(self.lines) >= 10_000:
                self.messages.put(dict(peer_error='peer output bound exceeded'))
                break
            self.lines.append(line)
            try:
                record = json.loads(line)
                self.records.append(record)
                self.messages.put(record)
            except json.JSONDecodeError:
                self.messages.put(dict(peer_error='non-JSON peer output'))

    def observe(self):
        if self.config.get('kind', 'structured') in ('structured', 'performance'):
            require(self.process.poll() is None, 'external peer exited before evidence collection')
            self.process.stdin.write('{"command":"stats"}\n')
            self.process.stdin.flush()
            until = time.monotonic() + self.runner.remaining(15)
            while time.monotonic() < until:
                try:
                    record = self.messages.get(timeout=max(0.001, until - time.monotonic()))
                except queue.Empty:
                    break
                if isinstance(record, dict) and record.get('event', record.get('kind')) == 'stats':
                    require(record.get('errors') == [] and record.get('active_connections') == 0,
                            'peer error or live connections remain after release traffic')
                    require(not any(isinstance(item, dict) and ('peer_error' in item or item.get('kind') == 'error')
                                    for item in self.records), 'external peer reported failure')
                    return
            raise GateError('external peer stats deadline/evidence missing')

    def scenario(self, case, nonce):
        # Structured records are independently emitted, not supplied by consumer.
        selected = [record for record in self.records if isinstance(record, dict)
                    and record.get('kind') == 'scenario' and record.get('id') == case['id']]
        require(len(selected) == 1, f'{case["id"]}: missing exact peer scenario evidence; raw peer adapter is diagnostic only')
        return selected[0]

    def close(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        else:
            self.process.wait(timeout=5)
        self.thread.join(timeout=5)
        self.directory.joinpath(f'peer-{self.name}.log').write_text(''.join(self.lines))
        self.directory.joinpath(f'peer-{self.name}.json').write_text(json.dumps(self.records, indent=2))
        require(not self.thread.is_alive(), 'owned peer output reader did not stop')


@contextmanager
def bounded_registry_commands(runner, source=None):
    original = consumer_gate.command
    original_root = consumer_gate.ROOT
    consumer_gate.command = runner.command
    if source is not None:
        consumer_gate.ROOT = source
    try:
        yield
    finally:
        consumer_gate.command = original
        consumer_gate.ROOT = original_root


def run(version, archives, stage, source, source_sha, plan, output, max_seconds=1800, *, published=False):
    stable_version(version)
    validate_plan(plan)
    require(re.fullmatch(r'[a-f0-9]{40}', source_sha), 'full source SHA required')
    output, source = output.resolve(), source.resolve()
    require(not output.exists() and not within(output, source), 'new isolated output outside source tree required')
    output.mkdir(parents=True)
    runner = Runner(output, max_seconds)
    nonce = uuid.uuid4().hex
    project, release = output / 'project', output / 'release'
    env = production_environment(project, os.environ)
    if published:
        env.pop('HEX_OFFLINE', None)
        env.update(HEX_CONFIG_HOME=str(project / 'hex'), HEX_CACHE_HOME=str(project / 'hex-cache'))
    peers = []
    report = dict(gate='no_otp_production_release', status='FAIL', nonce=nonce,
                  source_sha=source_sha, version=version, output=str(output),
                  dependency_source='published' if published else 'candidate')
    try:
        head = runner.command(['git', 'rev-parse', 'HEAD'], cwd=source, env=env).strip()
        require(head == source_sha, 'candidate source HEAD mismatch')
        runner.command(['unbuffer', 'elixir', str(source / 'scripts/release/versions.exs'),
                        'validate', version], cwd=source, env=env)
        runner.command(['unbuffer', 'elixir', str(source / 'scripts/release/archives.exs'),
                        version, str(archives)], cwd=source, env=env)
        report['staged_source_sha256'] = verify_source(stage, source, archives, version)
        report['archives'] = {package: hashlib.sha256(
            (archives / f'{package}-{version}.tar').read_bytes()).hexdigest() for package in PACKAGES}
        if published:
            statuses = runner.command([sys.executable, str(source / 'scripts/release/hex_packages.py'),
                                       'preflight', version, str(archives)], cwd=source, env=env)
            require(statuses.strip().splitlines() == [f'{package}: matching' for package in PACKAGES],
                    'all nine published archives must match before release construction')
            report['published_archives'] = {package: 'matching' for package in PACKAGES}
        project.joinpath('lib').mkdir(parents=True)
        project.joinpath('mix.exs').write_text(project_source(version))
        for stem in ('no_otp_consumer', 'no_otp_release_audit'):
            shutil.copyfile(HERE / f'{stem}.exs', project / 'lib' / f'{stem}.ex')
        env.update(NO_OTP_VERSION=version, NO_OTP_PROJECT=str(project), NO_OTP_NONCE=nonce,
                   NO_OTP_RELEASE=str(release), NO_OTP_REPORT=str(output / 'release-report.json'))
        # Public CA input only: peer private keys are never read/copied by the gate.
        config = dict(schema=1, nonce=nonce, version=version, scenarios=[])
        with bounded_registry_commands(runner, source):
            registry = nullcontext(None)
            if not published:
                public = consumer_gate.setup_registry(archives, version, output / 'registry', env)
                registry = consumer_gate.local_registry(public)
            with registry as url:
                if url is not None:
                    runner.command(['unbuffer', 'mix', 'hex.repo', 'set', 'hexpm', '--url', url,
                                    '--public-key', str(public / 'public_key')], env=env)
                build_release(project, release, env, runner)
        for name, peer_config in plan['peers'].items():
            peers.append(Peer(name, peer_config, output, env, runner))
        by_name = {peer.name: peer for peer in peers}
        for case in plan['scenarios']:
            actual = dict(case)
            peer = by_name[case['peer']]
            actual['url'] = case['url'].replace('{port}', str(peer.ready['port']))
            actual['peer_identity'] = peer.ready.get('identity', peer.config['sha256'])
            actual['nonce'] = nonce
            ca = output / f'ca-{case["peer"]}.pem'
            ca.write_bytes(Path(case['ca_file']).read_bytes())
            actual['ca_file'] = str(ca)
            if 'gate_file' in case:
                actual['gate_file'] = case['gate_file'].replace('{run}', str(output))
            config['scenarios'].append(actual)
        config_path = output / 'traffic.json'
        config_path.write_text(json.dumps(config, indent=2))
        env['NO_OTP_CONFIG'] = str(config_path)
        runner.command(release_command(release), cwd=output, env=env, limit=runner.remaining(1200))
        actual = json.loads(Path(env['NO_OTP_REPORT']).read_text())
        report['release'] = actual
        validate_artifacts(actual.get('artifacts'), version)
        validate_runtime(actual.get('before'), release)
        validate_runtime(actual.get('after'), release)
        require(actual.get('runtime', {}).get('elixir') and actual['runtime'].get('otp'), 'runtime versions missing')
        require(len(actual.get('scenarios', [])) == len(REQUIRED), 'release scenario count missing')
        for peer in peers:
            peer.observe()
        for case in config['scenarios']:
            selected = [record for record in actual['scenarios'] if record.get('id') == case['id']]
            require(len(selected) == 1, 'release scenario duplicate/missing')
            validate_scenario(case, selected[0], by_name[case['peer']].scenario(case, nonce), nonce)
        report['status'] = 'PASS'
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        failures = []
        for peer in reversed(peers):
            try:
                peer.close()
            except BaseException as error:
                failures.append(str(error))
        report['teardown_errors'] = failures
        if failures:
            report['status'] = 'FAIL'
        output.joinpath('gate-report.json').write_text(json.dumps(report, indent=2))
        if failures:
            raise GateError('owned peer teardown failed; diagnostics retained')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('archives', type=Path)
    parser.add_argument('stage', type=Path)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--peer-plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-seconds', type=int, default=1800)
    parser.add_argument('--published', action='store_true')
    args = parser.parse_args()
    require(1 <= args.max_seconds <= 7200, 'bounded gate duration required')
    result = run(args.version, args.archives.resolve(), args.stage.resolve(), args.source_root,
                 args.source_sha, json.loads(args.peer_plan.read_text()), args.output, args.max_seconds,
                 published=args.published)
    print(json.dumps(dict(gate=result['gate'], status=result['status'], output=result['output'])))


if __name__ == '__main__':
    main()

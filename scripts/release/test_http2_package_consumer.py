"""Candidate package HTTP/2 endpoint routing and provenance regressions."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import consumer_gate
from stage import PACKAGES, ROOT

spec = importlib.util.spec_from_file_location(
    'package_traffic', ROOT / 'scripts/http_runtime_package_traffic_gate.py')
package_traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_traffic)


class HTTPRuntimeTrafficEvidenceTests(unittest.TestCase):
    def evidence(self, mode):
        tls = mode == 'ex_ssl'
        records = [dict(kind='ready', port=8443, tls=tls)]
        clients = [['http_fetch'], ['http_event_source'], ['http_web_socket'],
                   ['http_fetch', 'http_event_source', 'http_web_socket']]
        consumer = []
        for cid, (selected, kinds) in enumerate(zip(clients, (
                ['fetch'], ['sse'], ['connect'], ['sse', 'connect', 'fetch'])), 1):
            records.append(dict(kind='connection', connection=cid,
                                protocol='h2' if tls else 'h2c', alpn='h2' if tls else None))
            for kind in kinds:
                records.append(dict(kind=kind, connection=cid))
            if 'connect' in kinds:
                records.append(dict(kind='wire_complete', connection=cid,
                                    messages=2 if len(selected) == 3 else 1,
                                    client_end_stream=True, peer_end_stream=True,
                                    client_close_code=1000, client_frames={'8': 1}))
            consumer.extend([
                dict(result='PASS', gate='isolated_http2_traffic', clients=selected,
                     mode=mode, protocol='http2' if tls else 'h2c',
                     backend='ex_ssl' if tls else None, verified_tls=tls,
                     scheme='https' if tls else 'http'),
                dict(result='PASS', gate='isolated_runtime_startup', clients=selected),
            ])
        return records, consumer

    def test_both_modes_require_actual_peer_and_all_four_consumer_evidence(self):
        for mode in ('h2c', 'ex_ssl'):
            records, consumer = self.evidence(mode)
            result = package_traffic.validate_mode(records, consumer, mode)
            self.assertEqual(result['mode'], mode)
            self.assertEqual(result['connections'], 4)
            self.assertEqual(result['consumers'], 4)
            self.assertEqual(result['verified_tls'], mode == 'ex_ssl')

    def test_missing_traffic_unverified_tls_wrong_alpn_and_replay_fail(self):
        for mode in ('h2c', 'ex_ssl'):
            original, original_consumer = self.evidence(mode)
            mutations = [([], original_consumer), (original, [])]
            mutations.append(([r for r in original if r.get('kind') != 'fetch'], original_consumer))
            mutations.append((original + [dict(kind='fetch', connection=1)], original_consumer))
            mutations.append((original, original_consumer[:-1]))
            mutations.append((original, [r for r in original_consumer
                                         if r.get('gate') != 'isolated_http2_traffic']))
            if mode == 'ex_ssl':
                mutations.append(([{**r, 'protocol': 'h2c'} if r.get('kind') == 'connection' else r
                                   for r in original], original_consumer))
                mutations.append(([{**r, 'alpn': None} if r.get('kind') == 'connection' else r
                                   for r in original], original_consumer))
                mutations.append((original, [{**r, 'verified_tls': False}
                                             if r.get('gate') == 'isolated_http2_traffic' else r
                                             for r in original_consumer]))
            mutations.append(([{**r, 'peer_end_stream': False}
                               if r.get('kind') == 'wire_complete' else r
                               for r in original], original_consumer))
            for index, (records, consumer) in enumerate(mutations):
                with self.subTest(mode=mode, mutation=index):
                    with self.assertRaises((AssertionError, ValueError)):
                        package_traffic.validate_mode(records, consumer, mode)

    def test_aggregate_rejects_h2c_only_duplicate_modes_and_incomplete_tls(self):
        results = [package_traffic.validate_mode(*self.evidence(mode), mode)
                   for mode in ('h2c', 'ex_ssl')]
        summary = package_traffic.aggregate_modes(results)
        self.assertEqual((summary['consumers'], summary['connections']), (8, 8))
        self.assertTrue(summary['verified_tls'])
        for incomplete in (results[:1], results[1:], [results[0], results[0]],
                           [results[0], {**results[1], 'verified_tls': False}]):
            with self.assertRaises((AssertionError, ValueError)):
                package_traffic.aggregate_modes(incomplete)

    def test_modes_select_tls_peer_and_verified_https_consumer_without_fallback(self):
        environment = {'HTTP_FETCH_ARCHIVE_DIR': '/exact/archives',
                       'HTTP_FETCH_RELEASE_VERSION': '1.2.3'}
        for mode, scheme in (('h2c', 'http'), ('ex_ssl', 'https')):
            command = package_traffic.peer_command(ROOT, mode)
            self.assertEqual('--tls' in command, mode == 'ex_ssl')
            selected = package_traffic.consumer_environment(environment, ROOT, mode, 8443)
            self.assertEqual(selected['HTTP_RUNTIME_CONSUMER_URL'], f'{scheme}://localhost:8443')
            self.assertEqual(selected['HTTP_RUNTIME_CONSUMER_MODE'], mode)
            for key, value in environment.items():
                self.assertEqual(selected[key], value)
            if mode == 'ex_ssl':
                self.assertEqual(selected['HTTP_RUNTIME_CONSUMER_CA'],
                                 str(ROOT / 'apps/http_fetch/test/support/fixtures/localhost-ca.pem'))
                self.assertIn(str(ROOT / 'apps/http_fetch/test/support/fixtures/localhost.pem'), command)
        driver = (ROOT / 'scripts/http_runtime_consumer_gate.exs').read_text()
        for required in ('tls_backend: :ex_ssl', 'verify: :verify_peer',
                         'server_name_indication: ~c"localhost"',
                         '"https://", "wss://"', ':public_key.pkix_verify_hostname_match_fun(:https)'):
            self.assertIn(required, driver)
        self.assertNotIn(':verify_none', driver)

    def test_runtime_projects_keep_exact_hex_graph_and_transport_environment(self):
        environment = {'HTTP_RUNTIME_CONSUMER_URL': 'https://localhost:8443',
                       'HTTP_RUNTIME_CONSUMER_MODE': 'ex_ssl',
                       'HTTP_RUNTIME_CONSUMER_CA': '/fixture/ca.pem'}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(consumer_gate, 'command') as command:
                consumer_gate.runtime_projects(Path(directory), '1.2.3', environment)
            launches = [call for call in command.call_args_list
                        if call.args[0] == ['mix', 'run', 'gate.exs', 'verify']]
            self.assertEqual(len(launches), 4)
            for call in launches:
                for key, value in environment.items():
                    self.assertEqual(call.kwargs['env'][key], value)
                source = (call.kwargs['cwd'] / 'mix.exs').read_text()
                for forbidden in ('path:', 'override:', 'in_umbrella:'):
                    self.assertNotIn(forbidden, source)
                self.assertIn('"== 1.2.3"', source)


class HTTP2PackageConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environment = {
            'HTTP_FETCH_GATE_URL': 'https://localhost:8443',
            'HTTP_FETCH_GATE_BACKEND': 'ex_ssl',
            'HTTP_FETCH_GATE_CA': '/operator/verified-ca.pem',
            'HTTP_FETCH_GATE_MODE': 'smoke',
        }

    def test_package_shell_routes_to_supplied_endpoint_consumer(self):
        shell = (ROOT / 'scripts/http2_package_gate.sh').read_text()
        self.assertIn('scripts/release/consumer_gate.py', shell)
        self.assertIn('--mode h2', shell)
        self.assertNotIn('http_runtime_package_traffic_gate.py', shell)
        self.assertLess(shell.index('scripts/release/archives.exs'), shell.index('--mode h2'))

    def test_isolated_consumer_preserves_tls_endpoint_backend_and_driver(self):
        with patch.object(consumer_gate, 'command') as command:
            consumer_gate.http2_project(self.directory, '1.2.3', self.environment)
        project = self.directory / 'h2'
        manifest = (project / 'mix.exs').read_text()
        for package in PACKAGES:
            self.assertIn(f'{{:{package}, "== 1.2.3"}}', manifest)
        for forbidden in ('path:', 'override:', 'in_umbrella:'):
            self.assertNotIn(forbidden, manifest)
        for script in ('http2_production_gate.exs', 'http2_metrics.exs'):
            self.assertEqual((project / script).read_bytes(), (ROOT / 'scripts' / script).read_bytes())
        launcher = command.call_args_list[-1]
        self.assertEqual(launcher.args[0], ['mix', 'run', 'gate.exs'])
        self.assertEqual(launcher.kwargs['cwd'], project)
        environment = launcher.kwargs['env']
        for key, value in self.environment.items():
            self.assertEqual(environment[key], value)
        self.assertEqual(environment['MIX_BUILD_PATH'], str(project / 'build'))
        self.assertEqual(environment['MIX_DEPS_PATH'], str(project / 'deps'))
        self.assertEqual((project / 'gate.exs').read_text(),
                         'Code.require_file("provenance.exs", __DIR__)\n'
                         'Code.require_file("http2_production_gate.exs", __DIR__)\n')

    def test_workload_failure_propagates_without_h2c_fallback(self):
        def command(args, **_kwargs):
            if args == ['mix', 'run', 'gate.exs']:
                raise subprocess.CalledProcessError(1, args)
        with patch.object(consumer_gate, 'command', side_effect=command):
            with self.assertRaises(subprocess.CalledProcessError):
                consumer_gate.http2_project(self.directory, '1.2.3', self.environment)

    def test_missing_candidate_archive_blocks_workload(self):
        with patch.object(consumer_gate, 'http2_project') as traffic:
            with self.assertRaisesRegex(RuntimeError, 'missing candidate archive'):
                consumer_gate.run('1.2.3', self.directory, mode='h2')
        traffic.assert_not_called()

    def test_provenance_rejects_path_dependency_before_network_traffic(self):
        with patch.object(consumer_gate, 'command'):
            consumer_gate.http2_project(self.directory, '1.2.3', self.environment)
        project = self.directory / 'h2'
        dependency = project / 'deps/ex_ssl'
        dependency.mkdir(parents=True)
        (dependency / 'mix.exs').write_text('''defmodule FakeSSL.MixProject do
  use Mix.Project
  def project, do: [app: :ex_ssl, version: "1.2.3"]
end
''')
        (project / 'mix.exs').write_text('''defmodule RejectedConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :rejected_consumer, version: "0.0.0", deps: [{:ex_ssl, path: "deps/ex_ssl"}]]
end
''')
        result = subprocess.run(['mix', 'run', 'provenance.exs'], cwd=project,
                                env={**os.environ, 'MIX_ENV': 'prod',
                                     'MIX_BUILD_PATH': str(project / 'build'),
                                     'MIX_DEPS_PATH': str(project / 'deps')},
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid Hex resolution for ex_ssl', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

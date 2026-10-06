"""Candidate package HTTP/2 endpoint routing and provenance regressions."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import consumer_gate
from stage import PACKAGES, ROOT


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

"""Check current-provider gate composition without executing its collaborators."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def option(command, name, default=None):
    return command[command.index(name) + 1] if name in command else default


def routes(commands, script):
    return [(option(command, '--peer', 'hyper-h2'),
             option(command, '--backend', 'ex_ssl') if '--tls' in command else 'h2c',
             option(command, '--mode', 'smoke'))
            for command in commands
            if script in command and '--package' not in command]


class PreparedCommands(Exception):
    pass


class CurrentH2MatrixTests(unittest.TestCase):
    def test_current_ci_preserves_both_peers_and_each_supported_consumer_route(self):
        gate = load('current_h2_ci', 'scripts/ci/http2_compat.py')
        commands = []

        def launch(command, **_options):
            commands.append(command)
            return types.SimpleNamespace(pid=123456789, wait=lambda **_kw: 0, poll=lambda: 0)

        def read(path, **_options):
            return '@version "0.21.19"' if path.name == 'mix.exs' else '{"result":"PASS"}\n'

        with patch.object(sys, 'argv', ['http2_compat.py', '--evidence', '/evidence']), \
             patch.object(Path, 'mkdir'), patch.object(Path, 'open'), \
             patch.object(Path, 'write_text'), patch.object(Path, 'read_bytes', return_value=b'archive'), \
             patch.object(Path, 'read_text', autospec=True, side_effect=read), \
             patch.object(Path, 'glob', return_value=[Path('/archives') / f'package{i}.tar' for i in range(9)]), \
             patch.object(gate.subprocess, 'check_output', return_value='candidate-sha\n'), \
             patch.object(gate.subprocess, 'Popen', side_effect=launch), \
             patch.object(gate, 'terminal_pass', return_value=True), \
             patch('sys.stdout', new_callable=io.StringIO):
            gate.main()
        for script in ('scripts/http2_stream_clients_gate.py', 'scripts/http2_websocket_gate.py'):
            self.assertCountEqual(routes(commands, script),
                                  [(peer, route, 'mixed') for peer in ('hyper-h2', 'node')
                                   for route in ('h2c', 'ex_ssl')])
        self.assertEqual(sum('scripts/http_runtime_package_traffic_gate.py' in command
                             for command in commands), 1)
        consumers = next(command for command in commands if command[:2] == ['mix', 'test'])
        self.assertIn('--include', consumers)
        self.assertEqual(option(consumers, '--include'), 'integration')

    def test_fetch_gate_preserves_supported_modes_reuse_and_candidate_tls(self):
        gate = load('current_fetch_gate', 'scripts/http2_fetch42_gate.py')
        commands = gate.commands(Path('/evidence'))
        expected = [(peer, route, mode) for peer in ('hyper-h2', 'node')
                    for route in ('h2c', 'ex_ssl') for mode in ('smoke', 'transfer', 'concurrent')]
        traffic = routes(commands.values(), 'scripts/http2_interop_gate.py')
        self.assertCountEqual([route for route in traffic if route[2] in ('smoke', 'transfer', 'concurrent')], expected)
        reuse = [command for command in commands.values() if option(command, '--mode') == 'reuse']
        self.assertCountEqual([(option(command, '--peer'), option(command, '--limit'), option(command, '--count'))
                               for command in reuse],
                              [(peer, str(limit), '10000') for peer in ('hyper-h2', 'node') for limit in (1, 2, 100)])
        packages = [command for command in commands.values() if '--package' in command]
        self.assertEqual(len(packages), 1)
        self.assertIn('--tls', packages[0])
        self.assertEqual(option(packages[0], '--backend'), 'ex_ssl')
        for name in ('final-tls-lifecycle-ci', 'final-runtime-regressions'):
            self.assertEqual(option(commands[name], '--include'), 'integration')

    def test_stream_acceptance_preserves_supported_modes_and_churn_workloads(self):
        gate = load('current_stream_gate', 'scripts/http2_stream_clients_acceptance.py')
        captured = {}

        def write(path, content, **_options):
            if path.name == 'commands.json':
                captured.update(json.loads(content))
                raise PreparedCommands()
            return len(content)

        def output(command, **_options):
            return '' if 'ls-tree' in command else '/repository/.git\n'

        with patch.object(sys, 'argv', ['stream_acceptance.py', '--source', '/candidate',
                                       '--repository', '/repository', '--tree', 'tree', '--evidence', '/evidence']), \
             patch.object(Path, 'mkdir'), patch.object(Path, 'rglob', return_value=[]), \
             patch.object(Path, 'write_text', autospec=True, side_effect=write), \
             patch.object(gate.subprocess, 'check_output', side_effect=output), \
             patch.object(gate.subprocess, 'Popen', side_effect=AssertionError('workload started')):
            with self.assertRaises(PreparedCommands):
                gate.main()
        commands = list(captured.values())
        sse = routes(commands, 'scripts/http2_stream_clients_gate.py')
        self.assertCountEqual(sse, [(peer, route, mode) for peer in ('hyper-h2', 'node')
                                   for route in ('h2c', 'ex_ssl') for mode in ('sse', 'mixed', 'faults')]
                              + [(peer, 'h2c', 'churn') for peer in ('hyper-h2', 'node')])
        ws = routes(commands, 'scripts/http2_websocket_gate.py')
        self.assertCountEqual(ws, [('hyper-h2', route, mode) for route in ('h2c', 'ex_ssl')
                                  for mode in ('echo', 'mixed', 'faults')]
                             + [('node', route, 'mixed') for route in ('h2c', 'ex_ssl')]
                             + [('hyper-h2', 'h2c', 'churn'), ('hyper-h2', 'ex_ssl', 'soak')])
        churn = [command for command in commands if option(command, '--mode') == 'churn']
        self.assertCountEqual([option(command, '--count') for command in churn], ['1001', '1001', '1000'])
        self.assertIn('package-traffic', captured)
        self.assertIn('docs', captured)
        self.assertIn('fetch42', captured)


if __name__ == '__main__':
    unittest.main()

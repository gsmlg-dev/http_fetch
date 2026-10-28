"""Exercise gate CLI/default routing through mocked peer and companion startup.

No subprocess, socket, or public workload runs. Stop at the real Mix invocation
so these controls prove startup configuration, never traffic acceptance.
"""
import io
import json
import os
from pathlib import Path
import runpy
import sys
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
GATES = (
    ("http2_stream_clients_gate", "HTTP_STREAM_GATE"),
    ("http2_websocket_gate", "HTTP_WS_GATE"),
)


class BeforePublicWorkload(Exception):
    pass


class GateStartupTests(unittest.TestCase):
    def startup(self, name, prefix, flags):
        launches = []
        versions = {"h2": "4.2.0", "hpack": "4.1.0", "hyperframe": "6.1.0", "wsproto": "1.2.0"}
        modules = {}
        for module, version in versions.items():
            modules[module] = types.ModuleType(module)
            modules[module].__version__ = version

        def launch(command, **options):
            launches.append((command, options))
            if command[0] == "mix":
                raise BeforePublicWorkload()
            return types.SimpleNamespace(
                stdout=iter([json.dumps(dict(kind="ready", port=23456)) + "\n"]),
                pid=123456789, poll=lambda: 0, terminate=lambda: None,
                wait=lambda **_options: 0)

        def output(command, **_options):
            if command[0] == "node":
                return json.dumps(dict(node="24.19.0", nghttp2="1.69.0"))
            return "candidate-sha\n" if "rev-parse" in command else ""

        argv = [name + ".py", "--peer", "hyper-h2", "--mode", "mixed", *flags]
        with patch.object(sys, "argv", argv), patch.dict(sys.modules, modules), \
             patch.dict(os.environ, {prefix + "_BACKEND": "ssl", prefix + "_CA": "/stale/ca"}, clear=True), \
             patch("subprocess.Popen", side_effect=launch), \
             patch("subprocess.check_output", side_effect=output), \
             patch("signal.signal"), patch("socket.create_connection") as connect, \
             patch("sys.stdout", new_callable=io.StringIO) as stdout, \
             patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(BeforePublicWorkload):
                runpy.run_path(str(ROOT / "scripts" / (name + ".py")), run_name="__main__")
            connect.assert_not_called()
        self.assertEqual(len(launches), 2)
        return launches, [json.loads(line) for line in stdout.getvalue().splitlines()]

    def test_default_plaintext_ci_invocation_reaches_companion_without_tls_claim(self):
        for name, prefix in GATES:
            with self.subTest(gate=name):
                launches, records = self.startup(name, prefix, [])
                peer, companion = launches
                self.assertNotIn("--tls", peer[0])
                self.assertEqual(companion[1]["env"][prefix + "_URL"], "http://localhost:23456")
                self.assertFalse(prefix + "_BACKEND" in companion[1]["env"], prefix + "_BACKEND")
                self.assertFalse(prefix + "_CA" in companion[1]["env"], prefix + "_CA")
                for record in records:
                    self.assertNotEqual(record.get("result"), "PASS")
                    if "backend" in record:
                        self.assertIsNone(record["backend"])

    def test_tls_defaults_to_ex_ssl_and_preserves_explicit_selection(self):
        for name, prefix in GATES:
            for selection, expected in (([], "ex_ssl"), (["--backend", "ex_ssl"], "ex_ssl")):
                with self.subTest(gate=name, backend=expected, flags=selection):
                    launches, _records = self.startup(name, prefix, ["--tls", *selection])
                    self.assertIn("--tls", launches[0][0])
                    env = launches[1][1]["env"]
                    self.assertEqual(env[prefix + "_URL"], "https://localhost:23456")
                    self.assertEqual(env[prefix + "_BACKEND"], expected)
                    self.assertTrue(env[prefix + "_CA"].endswith("localhost-ca.pem"))

    def test_plaintext_never_selects_a_provider_even_with_tls_only_backend_argument(self):
        for name, prefix in GATES:
            for backend in ("ex_ssl",):
                with self.subTest(gate=name, backend=backend):
                    launches, _records = self.startup(name, prefix, ["--backend", backend])
                    self.assertFalse(prefix + "_BACKEND" in launches[1][1]["env"], prefix + "_BACKEND")
                    self.assertFalse(prefix + "_CA" in launches[1][1]["env"], prefix + "_CA")

    def test_node_peer_routes_preserve_plaintext_and_verified_tls(self):
        routes = (([], False, None), (["--tls"], True, "ex_ssl"),
                  (["--tls", "--backend", "ex_ssl"], True, "ex_ssl"))
        for name, prefix in GATES:
            for flags, tls, backend in routes:
                with self.subTest(gate=name, tls=tls, backend=backend):
                    launches, _records = self.startup(name, prefix, ["--peer", "node", *flags])
                    self.assertEqual(launches[0][0][0], "node")
                    self.assertEqual(launches[0][1]["env"]["H2_PEER_TLS"], "1" if tls else "0")
                    self.assertEqual(launches[1][1]["env"].get(prefix + "_BACKEND"), backend)

    def test_removed_tls_backend_rejects_before_starting_collaborators(self):
        modules = {}
        for name, version in {"h2": "4.2.0", "hpack": "4.1.0", "hyperframe": "6.1.0",
                              "wsproto": "1.2.0"}.items():
            modules[name] = types.ModuleType(name)
            modules[name].__version__ = version
        for name in ("http2_stream_clients_gate", "http2_websocket_gate", "http2_interop_gate"):
            with self.subTest(gate=name), \
                 patch.object(sys, "argv", [name + ".py", "--peer", "hyper-h2", "--tls",
                                            "--backend", "ssl"]), \
                 patch.dict(sys.modules, modules), patch("signal.signal"), \
                 patch("subprocess.Popen", side_effect=AssertionError("removed provider started peer")) as launch, \
                 patch("subprocess.check_output", side_effect=AssertionError("removed provider ran command")) as output, \
                 patch("socket.create_connection") as connect, \
                 patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as raised:
                    runpy.run_path(str(ROOT / "scripts" / (name + ".py")), run_name="__main__")
                self.assertEqual(raised.exception.code, 2)
                launch.assert_not_called()
                output.assert_not_called()
                connect.assert_not_called()

    def test_acceptance_count_and_duration_thresholds_still_reject_before_peers(self):
        cases = [
            ("http2_stream_clients_gate", ["--backend", "unrecognized"]),
            ("http2_websocket_gate", ["--backend", "unrecognized"]),
            ("http2_stream_clients_gate", ["--mode", "sse", "--count", "9999"]),
            ("http2_stream_clients_gate", ["--mode", "churn", "--count", "1000"]),
            ("http2_websocket_gate", ["--mode", "echo", "--count", "9999"]),
            ("http2_websocket_gate", ["--mode", "churn", "--count", "999"]),
            ("http2_websocket_gate", ["--mode", "soak", "--seconds", "1799"]),
        ]
        for name, flags in cases:
            with self.subTest(gate=name, flags=flags), \
                 patch.object(sys, "argv", [name + ".py", "--peer", "hyper-h2", *flags]), \
                 patch("subprocess.Popen") as launch, patch("signal.signal"), \
                 patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as raised:
                    runpy.run_path(str(ROOT / "scripts" / (name + ".py")), run_name="__main__")
                self.assertEqual(raised.exception.code, 2)
                launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()

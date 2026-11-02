"""Blocked static audits must retain failure while collecting traffic evidence."""
from contextlib import ExitStack, nullcontext
from pathlib import Path
import copy
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import no_otp_consumer_gate as gate
from test_no_otp_consumer_gate import evidence, plan


class BlockedTrafficTests(unittest.TestCase):
    def test_cli_explicitly_enables_diagnostics_and_keeps_gate_failure(self):
        argv = ["gate", "1.2.3", "/archives", "/stage", "--source-root", "/source",
                "--source-sha", "a" * 40, "--peer-plan", "/plan.json",
                "--output", "/fresh", "--collect-blocked-traffic"]
        with patch.object(sys, "argv", argv), \
             patch.object(Path, "read_text", return_value=json.dumps(plan())), \
             patch.object(gate, "run", side_effect=gate.GateError("static blocker retained")) as run, \
             self.assertRaisesRegex(gate.GateError, "static blocker retained"):
            gate.main()
        self.assertEqual(run.call_args.kwargs,
                         dict(published=False, collect_blocked_traffic=True))

    def test_native_diagnostic_isolation_keeps_every_other_gate(self):
        result = subprocess.run(
            ["elixir", str(Path(__file__).with_suffix(".exs"))],
            env={**os.environ, "NO_OTP_VERSION": "1.2.3"},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertRegex(result.stdout, r"(?:12 tests, 0 failures|Result: 12 passed)")

    def run_fixture(self, *, diagnostic, mutation=None, command_failure=True):
        artifacts = dict(
            checked_app_files=10, checked_rel_files=1, checked_boot_files=1,
            checked_beams=10, ssl_app_dependencies=[], ssl_bundle_paths=[],
            ssl_boot_entries=[], direct_otp_ssl_imports=[],
            unresolved_dispatch=[dict(beam="/fresh/release/lib/client/ebin/client.beam",
                                      line=4, kind="unresolved_fun_invocation")],
            missing_abstract_code=[], duplicate_package_apps=[],
            package_versions={package: "1.2.3" for package in gate.PACKAGES})
        runtime = dict(
            ssl_available=False, ssl_loaded=False, ssl_application_loaded=False,
            ssl_started=False, code_paths=["/fresh/release/lib/kernel-1/ebin"],
            loaded_modules={module: "/fresh/release/lib/client/ebin/client.beam"
                            for module in gate.MODULES},
            all_loaded_paths={"HTTP": "/fresh/release/lib/client/ebin/client.beam"})
        actual = dict(nonce="run-nonce", artifacts=artifacts,
                      before=copy.deepcopy(runtime), after=copy.deepcopy(runtime),
                      runtime=dict(elixir="1.18.6", otp="28"),
                      scenarios=[evidence(case) for case in plan()["scenarios"]])
        if mutation:
            mutation(actual)
        original = copy.deepcopy(actual)
        writes = {}
        runner = MagicMock()
        runner.remaining.return_value = 10
        runner.command.side_effect = ["a" * 40, "versions ok", "archives ok", "repo ok",
                                      gate.GateError("owned command failed: exit=1")
                                      if command_failure else "release ok"]
        peer = MagicMock(name="actual-peer")
        peer.name = "peer"
        peer.ready = dict(port=12345, identity="pinned-peer")
        peer.scenario.side_effect = lambda case, nonce: evidence(case)
        with ExitStack() as stack:
            for name, value in (
                    ("Runner", MagicMock(return_value=runner)),
                    ("Peer", MagicMock(return_value=peer)),
                    ("build_release", MagicMock()),
                    ("verify_source", MagicMock(return_value={"file": "source-pin"}))):
                stack.enter_context(patch.object(gate, name, value))
            stack.enter_context(patch.object(gate.consumer_gate, "setup_registry",
                                            return_value=Path("/fresh/registry/public")))
            stack.enter_context(patch.object(gate.consumer_gate, "local_registry",
                                            return_value=nullcontext("http://127.0.0.1:1")))
            stack.enter_context(patch.object(gate.shutil, "copyfile"))
            stack.enter_context(patch.object(gate.uuid, "uuid4",
                                            return_value=MagicMock(hex="run-nonce")))
            stack.enter_context(patch.object(Path, "resolve", lambda path, strict=False: path))
            stack.enter_context(patch.object(Path, "exists", return_value=False))
            stack.enter_context(patch.object(Path, "mkdir"))
            stack.enter_context(patch.object(Path, "read_bytes", return_value=b"input"))
            stack.enter_context(patch.object(Path, "write_bytes"))
            stack.enter_context(patch.object(Path, "write_text",
                                            lambda path, value: writes.update({str(path): value})))
            stack.enter_context(patch.object(Path, "read_text", return_value=json.dumps(actual)))
            with self.assertRaises(gate.GateError) as error:
                gate.run("1.2.3", Path("/archives"), Path("/stage"), Path("/source"),
                         "a" * 40, plan(), Path("/fresh"),
                         collect_blocked_traffic=diagnostic)
        self.assertEqual(actual, original)
        peer.close.assert_called_once()
        return writes, peer, str(error.exception)

    def test_static_failure_retains_all_findings_after_35_validated_scenarios(self):
        writes, peer, error = self.run_fixture(diagnostic=True)
        report = json.loads(writes["/fresh/gate-report.json"])
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["static_status"], "FAIL")
        self.assertEqual(report["traffic_status"], "PASS")
        self.assertEqual(len(report["release"]["scenarios"]), 35)
        self.assertEqual(len(report["release"]["artifacts"]["unresolved_dispatch"]), 1)
        self.assertEqual(peer.scenario.call_count, 35)
        peer.observe.assert_called_once()
        self.assertIn("unresolved_dispatch", error)
        self.assertTrue(json.loads(writes["/fresh/traffic.json"])["collect_blocked_traffic"])

    def test_default_still_stops_on_failed_release_command(self):
        writes, peer, error = self.run_fixture(diagnostic=False)
        self.assertIn("owned command failed", error)
        peer.observe.assert_not_called()
        self.assertEqual(json.loads(writes["/fresh/gate-report.json"])["status"], "FAIL")

    def test_bad_cleanup_does_not_become_a_passing_traffic_diagnostic(self):
        writes, _peer, _error = self.run_fixture(
            diagnostic=True,
            mutation=lambda report: report["scenarios"][0].update(cleanup="pending"))
        report = json.loads(writes["/fresh/gate-report.json"])
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["traffic_status"], "FAIL")

    def test_runtime_ssl_leak_is_still_rejected(self):
        writes, peer, _error = self.run_fixture(
            diagnostic=True, mutation=lambda report: report["after"].update(ssl_available=True))
        report = json.loads(writes["/fresh/gate-report.json"])
        self.assertEqual(report["traffic_status"], "FAIL")
        peer.scenario.assert_not_called()

    def test_every_other_artifact_failure_still_blocks_diagnostics(self):
        for field in ("ssl_app_dependencies", "ssl_bundle_paths", "ssl_boot_entries",
                      "direct_otp_ssl_imports", "missing_abstract_code", "duplicate_package_apps"):
            with self.subTest(field=field):
                writes, peer, error = self.run_fixture(
                    diagnostic=True,
                    mutation=lambda report: report["artifacts"].update({field: ["finding"]}))
                report = json.loads(writes["/fresh/gate-report.json"])
                self.assertEqual(report["status"], "FAIL")
                self.assertEqual(report["static_status"], "FAIL")
                self.assertEqual(report["traffic_status"], "FAIL")
                self.assertIn(field, error)
                peer.observe.assert_not_called()

    def test_wrong_nonce_cannot_supply_diagnostic_evidence(self):
        writes, peer, error = self.run_fixture(
            diagnostic=True, mutation=lambda report: report.update(nonce="old-run"))
        self.assertEqual(json.loads(writes["/fresh/gate-report.json"])["traffic_status"], "FAIL")
        self.assertIn("nonce", error)
        peer.scenario.assert_not_called()

    def test_even_zero_release_exit_cannot_hide_static_blockers(self):
        writes, _peer, _error = self.run_fixture(diagnostic=True, command_failure=False)
        report = json.loads(writes["/fresh/gate-report.json"])
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["static_status"], "FAIL")

    def test_published_verification_does_not_accept_diagnostic_mode(self):
        with self.assertRaisesRegex(gate.GateError, "published"):
            gate.run("1.2.3", Path("/archives"), Path("/stage"), Path("/source"),
                     "a" * 40, plan(), Path("/fresh"), published=True,
                     collect_blocked_traffic=True)


if __name__ == "__main__":
    unittest.main()

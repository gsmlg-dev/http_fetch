"""Published no-OTP releases retain source, traffic and cleanup gates."""

from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

import no_otp_consumer_gate as gate
from test_no_otp_consumer_gate import plan


class PublishedNoOTPTests(unittest.TestCase):
    def run_to_release(self, preflight):
        stack = ExitStack()
        self.addCleanup(stack.close)
        runner_type = stack.enter_context(patch.object(gate, "Runner"))
        runner = runner_type.return_value
        runner.command.side_effect = ["a" * 40, "versions ok", "archives ok", preflight, "release ran"]
        runner.remaining.return_value = 10
        build = stack.enter_context(patch.object(gate, "build_release"))
        verify = stack.enter_context(patch.object(gate, "verify_source", return_value={"file": "source-pin"}))
        registry = stack.enter_context(patch.object(gate.consumer_gate, "setup_registry"))
        local = stack.enter_context(patch.object(gate.consumer_gate, "local_registry"))
        peer_type = stack.enter_context(patch.object(gate, "Peer"))
        peer_type.return_value.name = "peer"
        peer_type.return_value.ready = dict(port=12345, identity="actual-peer-ready")
        peer_type.return_value.config = {"sha256": "a" * 64}
        stack.enter_context(patch.object(gate.shutil, "copyfile"))
        stack.enter_context(patch.object(Path, "resolve", lambda path: path))
        stack.enter_context(patch.object(Path, "exists", return_value=False))
        stack.enter_context(patch.object(Path, "mkdir"))
        stack.enter_context(patch.object(Path, "read_bytes", return_value=b"input"))
        stack.enter_context(patch.object(Path, "write_bytes"))
        stack.enter_context(patch.object(Path, "read_text", return_value='{"artifacts": {}}'))
        writes = {}
        stack.enter_context(patch.object(Path, "write_text", lambda path, value: writes.update({str(path): value})))
        error = None
        try:
            gate.run("1.2.3", Path("/archives"), Path("/stage"), Path("/source"), "a" * 40,
                     plan(), Path("/fresh"), published=True)
        except gate.GateError as caught:
            error = caught
        self.assertIsNotNone(error, "mocked release has no passing artifact/runtime evidence")
        report = json.loads(writes["/fresh/gate-report.json"])
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["dependency_source"], "published")
        registry.assert_not_called()
        local.assert_not_called()
        verify.assert_called_once()
        return runner, build, peer_type, report

    def test_matching_published_archives_build_without_candidate_registry(self):
        preflight = "".join(f"{package}: matching\n" for package in gate.PACKAGES)
        runner, build, peers, report = self.run_to_release(preflight)
        build.assert_called_once()
        commands = [item.args[0] for item in runner.command.call_args_list]
        self.assertEqual(commands[3], [sys.executable, "/source/scripts/release/hex_packages.py",
                                      "preflight", "1.2.3", "/archives"])
        self.assertEqual(commands[-1], ["/fresh/release/bin/no_otp_consumer", "eval", "NoOTP.Consumer.run()"])
        self.assertEqual(report["published_archives"], {package: "matching" for package in gate.PACKAGES})
        peers.assert_called_once()
        peers.return_value.close.assert_called_once()
        self.assertEqual(report["teardown_errors"], [])

    def test_partial_missing_duplicate_or_wrong_preflight_stops_before_build(self):
        matching = [f"{package}: matching" for package in gate.PACKAGES]
        for output in ("\n".join(matching[:-1]), "\n".join(matching[:-1] + [matching[-1].replace("matching", "missing")]),
                       "\n".join(matching + [matching[-1]]), "\n".join(reversed(matching))):
            with self.subTest(output=output):
                runner, build, peers, report = self.run_to_release(output)
                build.assert_not_called()
                peers.assert_not_called()
                self.assertEqual(runner.command.call_count, 4)
                self.assertIn("all nine published archives", report["error"])

    def test_failed_or_timed_out_preflight_never_falls_back(self):
        for code in (1, 124):
            with self.subTest(code=code):
                runner, build, peers, report = self.run_to_release(
                    gate.GateError(f"owned command failed: exit={code}"))
                build.assert_not_called()
                peers.assert_not_called()
                self.assertEqual(runner.command.call_count, 4)
                self.assertIn(f"exit={code}", report["error"])

    def test_published_build_has_cold_hex_state_and_retains_prod_isolation(self):
        inherited = {"HEX_HOME": "/candidate/hex", "HEX_CONFIG_HOME": "/candidate/config",
                     "HEX_CACHE_HOME": "/candidate/cache", "HEX_OFFLINE": "true",
                     "HEX_MIRROR": "http://candidate", "HEX_TRUSTED_MIRROR": "http://candidate",
                     "ERL_LIBS": "/host/lib", "MIX_BUILD_PATH": "/old/build"}
        with patch.dict(os.environ, inherited):
            _, build, _, _ = self.run_to_release("".join(f"{package}: matching\n" for package in gate.PACKAGES))
        env = build.call_args.args[2]
        self.assertEqual(env["HEX_HOME"], "/fresh/project/hex")
        self.assertEqual(env["HEX_CONFIG_HOME"], "/fresh/project/hex")
        self.assertEqual(env["HEX_CACHE_HOME"], "/fresh/project/hex-cache")
        self.assertEqual(env["MIX_ENV"], "prod")
        self.assertEqual(env["MIX_BUILD_PATH"], "/fresh/project/build")
        self.assertEqual(env["MIX_DEPS_PATH"], "/fresh/project/deps")
        for key in ("HEX_OFFLINE", "HEX_MIRROR", "HEX_TRUSTED_MIRROR", "ERL_LIBS"):
            self.assertNotIn(key, env)

    def test_cli_published_switch_reaches_the_same_production_gate(self):
        argv = ["no_otp_consumer_gate.py", "1.2.3", "/archives", "/stage", "--source-root", "/source",
                "--source-sha", "a" * 40, "--peer-plan", "/plan.json", "--output", "/fresh"]
        for flags, published in (([], False), (["--published"], True)):
            with self.subTest(published=published), patch.object(sys, "argv", argv + flags), \
                    patch.object(Path, "read_text", return_value=json.dumps(plan())), \
                    patch.object(gate, "run", return_value={"gate": "no_otp_production_release",
                                                          "status": "PASS", "output": "/fresh"}) as run, \
                    redirect_stdout(io.StringIO()):
                gate.main()
                self.assertEqual(run.call_args.kwargs, {"published": published})


class NoOTPReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/release.yml").read_text()

    def step(self, name):
        matches = re.findall(r"^      - name: " + re.escape(name) +
                             r"\n(.*?)(?=^      - |\Z)", self.workflow, re.M | re.S)
        self.assertEqual(len(matches), 1, "exactly one required release step: " + name)
        return matches[0]

    def test_candidate_release_must_pass_before_tag_or_package_publication(self):
        name = "Require isolated candidate release without OTP SSL"
        step = self.step(name)
        self.assertLess(self.workflow.index(name),
                        self.workflow.index("name: Commit version and create immutable tag"))
        self.assertLess(self.workflow.index(name),
                        self.workflow.index("name: Publish and verify packages in dependency order"))
        self.assertIn("scripts/release/no_otp_consumer_gate.py", step)
        self.assertNotIn("--published", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotRegex(step, r"(?m)^        if:")
        self.assertNotIn("|| true", step)
        self.assertIn("set -euo pipefail", step)

    def test_published_release_cannot_reuse_candidate_evidence(self):
        name = "Require isolated published release without OTP SSL"
        step = self.step(name)
        self.assertGreater(self.workflow.index(name),
                           self.workflow.index("name: Publish and verify packages in dependency order"))
        self.assertLess(self.workflow.index(name),
                        self.workflow.index("name: Attach and verify all immutable GitHub release archives"))
        self.assertIn("scripts/release/no_otp_consumer_gate.py", step)
        self.assertIn("--published", step)
        self.assertIn("/published-", step)
        self.assertNotIn("/candidate-", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotRegex(step, r"(?m)^        if:")
        self.assertNotIn("|| true", step)
        self.assertIn("set -euo pipefail", step)

    def test_both_modes_cover_tls12_and_tls13_from_the_checked_out_source(self):
        for mode in ("candidate", "published"):
            with self.subTest(mode=mode):
                step = self.step(f"Require isolated {mode} release without OTP SSL")
                self.assertIn("for tls in TLSv1.2 TLSv1.3; do", step)
                self.assertIn('--source-root "$GITHUB_WORKSPACE"', step)
                self.assertIn('--source-sha "$(git rev-parse HEAD)"', step)
                self.assertIn('--peer-plan "$RUNNER_TEMP/no-otp-plan-$tls.json"', step)
                self.assertIn(f'--output "$RUNNER_TEMP/no-otp-release/{mode}-$tls"', step)

    def test_peer_plans_bind_pinned_environment_and_existing_verified_fixtures(self):
        step = self.step("Prepare independent no-OTP SSL peers")
        self.assertIn('uv venv "$RUNNER_TEMP/no-otp-peer-python" --python 3.12', step)
        self.assertIn("--requirement scripts/requirements-http2-stream-clients.txt", step)
        self.assertIn("aioquic==1.2.0", step)
        self.assertIn('"$RUNNER_TEMP/no-otp-peer-python/bin/python" scripts/release/no_otp_peer.py plan', step)
        self.assertIn("for tls in TLSv1.2 TLSv1.3; do", step)
        self.assertIn('--tls "$tls"', step)
        self.assertIn('--cert "$GITHUB_WORKSPACE/apps/http_fetch/test/support/fixtures/localhost.pem"', step)
        self.assertIn('--key "$GITHUB_WORKSPACE/apps/http_fetch/test/support/fixtures/localhost.key"', step)
        self.assertIn('--ca "$GITHUB_WORKSPACE/apps/http_fetch/test/support/fixtures/localhost-ca.pem"', step)

    def test_failed_release_retains_diagnostics_without_archiving_release_or_keys(self):
        step = self.step("Preserve no-OTP release diagnostics")
        self.assertIn("if: always()", step)
        for name in ("gate-report.json", "release-report.json", "commands.json",
                     "command-*.log", "peer-*.log", "peer-*.json"):
            self.assertIn("no-otp-release/**/" + name, step)
        self.assertNotIn("no-otp-peer-python", step)
        self.assertNotRegex(step, r"(?m)no-otp-release/\*\*\s*$")
        self.assertNotIn(".key", step)
        self.assertNotIn(".erlang.cookie", step)


class NoOTPCIWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()
        matches = re.findall(r"^  no-otp-release:\n(.*?)(?=^  [a-zA-Z0-9_-]+:|\Z)",
                             workflow, re.M | re.S)
        if len(matches) != 1:
            raise AssertionError("exactly one automatic no-OTP candidate job is required")
        cls.job = matches[0]

    def step(self, name):
        matches = re.findall(r"^      - name: " + re.escape(name) +
                             r"\n(.*?)(?=^      - |\Z)", self.job, re.M | re.S)
        self.assertEqual(len(matches), 1, "exactly one required CI step: " + name)
        return matches[0]

    def test_affected_candidates_require_an_independent_fail_closed_job(self):
        self.assertIn("needs: changes", self.job)
        self.assertIn("if: needs.changes.outputs.candidate_tls == 'true'", self.job)
        self.assertNotIn("needs: checks", self.job)
        self.assertNotIn("continue-on-error", self.job)
        self.assertNotIn("|| true", self.job)
        for forbidden in ("git push", "git tag", "hex_packages.py publish", "HEX_API_KEY"):
            self.assertNotIn(forbidden, self.job)

    def test_each_tls_version_uses_fresh_source_bound_production_archives(self):
        build = self.step("Build and validate all candidate archives")
        self.assertIn("scripts/release/stage.py build", build)
        self.assertIn("scripts/release/archives.exs", build)
        self.assertNotIn("--package", build)
        run = self.step("Require isolated candidate release without OTP SSL")
        self.assertIn("for tls in TLSv1.2 TLSv1.3; do", run)
        self.assertIn("scripts/release/no_otp_consumer_gate.py", run)
        self.assertIn('--source-root "$GITHUB_WORKSPACE"', run)
        self.assertIn('--source-sha "$(git rev-parse HEAD)"', run)
        self.assertIn('--peer-plan "$RUNNER_TEMP/no-otp-plan-$tls.json"', run)
        self.assertIn('--output "$RUNNER_TEMP/no-otp-release/candidate-$tls"', run)
        self.assertNotIn("--published", run)
        self.assertNotRegex(run, r"(?m)^        if:")
        self.assertIn("set -euo pipefail", run)
        self.assertLess(self.job.index("name: Build and validate all candidate archives"),
                        self.job.index("name: Require isolated candidate release without OTP SSL"))

    def test_pinned_peers_and_required_tools_precede_the_release_gate(self):
        prepare = self.step("Prepare independent no-OTP SSL peers")
        self.assertIn("expect", prepare)
        self.assertIn("command -v unbuffer", prepare)
        self.assertIn("--requirement scripts/requirements-http2-stream-clients.txt", prepare)
        self.assertIn("aioquic==1.2.0", prepare)
        self.assertIn("for tls in TLSv1.2 TLSv1.3; do", prepare)
        self.assertIn('--tls "$tls"', prepare)
        for flag, fixture in (("--cert", "localhost.pem"), ("--key", "localhost.key"),
                              ("--ca", "localhost-ca.pem")):
            self.assertIn(f'{flag} "$GITHUB_WORKSPACE/apps/http_fetch/test/support/fixtures/{fixture}"',
                          prepare)
        self.assertLess(self.job.index("name: Prepare independent no-OTP SSL peers"),
                        self.job.index("name: Require isolated candidate release without OTP SSL"))

    def test_failures_retain_reports_without_release_keys_or_cookies(self):
        step = self.step("Preserve no-OTP release diagnostics")
        self.assertIn("if: always()", step)
        self.assertIn("if-no-files-found: error", step)
        for name in ("gate-report.json", "release-report.json", "commands.json",
                     "command-*.log", "peer-*.log", "peer-*.json"):
            self.assertIn("no-otp-release/**/" + name, step)
        self.assertNotRegex(step, r"(?m)no-otp-release/\*\*\s*$")
        self.assertNotIn(".key", step)
        self.assertNotIn(".erlang.cookie", step)


if __name__ == "__main__":
    unittest.main()

"""Release HTTP/3 isolation, gate propagation and publication ordering."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import consumer_gate
from stage import PACKAGES, ROOT
sys.path.insert(0, str(ROOT / "scripts/http3"))
import post_release_canary


class HTTP3ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_consumer_resolves_nine_exact_hex_packages_and_uses_own_project(self):
        self.assertTrue(hasattr(consumer_gate, "http3_project"), "missing isolated HTTP3 consumer")
        with patch.object(consumer_gate, "command") as command:
            consumer_gate.http3_project(self.directory, "1.2.3", {"MIX_ENV": "prod"})
        project = self.directory / "http3"
        manifest = (project / "mix.exs").read_text()
        for package in PACKAGES:
            self.assertIn(f'{{:{package}, "== 1.2.3"}}', manifest)
        for forbidden in ("path:", "override:", "in_umbrella:"):
            self.assertNotIn(forbidden, manifest)
        self.assertEqual((project / "public_gate.exs").read_bytes(),
                         (ROOT / "scripts/http3/public_gate.exs").read_bytes())
        launcher = command.call_args_list[-1]
        args = launcher.args[0]
        self.assertIn(str(ROOT / "scripts/http3/public_gate.py"), args)
        self.assertEqual(args[args.index("--project-dir") + 1], str(project))
        self.assertEqual(args[args.index("--gate-script") + 1], str(project / "gate.exs"))
        environment = launcher.kwargs["env"]
        self.assertEqual(environment["MIX_ENV"], "test")
        self.assertEqual(environment["MIX_BUILD_PATH"], str(project / "build"))
        self.assertEqual(environment["MIX_DEPS_PATH"], str(project / "deps"))
        self.assertEqual(environment["HTTP3_CONSUMER_VERSION"], "1.2.3")
        self.assertIn('Code.require_file("provenance.exs", __DIR__)',
                      (project / "gate.exs").read_text())

    def test_peer_or_public_gate_failure_propagates(self):
        self.assertTrue(hasattr(consumer_gate, "http3_project"), "missing isolated HTTP3 consumer")
        def command(args, **_kwargs):
            if "uv" == args[0]:
                raise subprocess.CalledProcessError(1, args)
        with patch.object(consumer_gate, "command", side_effect=command):
            with self.assertRaises(subprocess.CalledProcessError):
                consumer_gate.http3_project(self.directory, "1.2.3", {})

    def test_published_mode_never_builds_local_registry(self):
        self.assertTrue(hasattr(consumer_gate, "http3_project"), "missing isolated HTTP3 consumer")
        with patch.object(consumer_gate, "setup_registry") as registry, patch.object(
                consumer_gate, "http3_project") as project:
            consumer_gate.run("1.2.3", None, mode="http3", published=True)
        registry.assert_not_called()
        project.assert_called_once()
        self.assertEqual(project.call_args.args[2]["MIX_ENV"], "prod")
        self.assertEqual(project.call_args.args[2]["HTTP3_CONSUMER_SOURCE"], "published")

    def test_release_requires_source_and_artifact_h3_before_publication(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        source = 'name: Require independent public HTTP3 before publication'
        candidate = 'name: Require isolated candidate HTTP3 traffic'
        published = 'name: Verify published isolated HTTP3 traffic'
        self.assertIn(source, workflow, "source public H3 gate is not required")
        self.assertIn(candidate, workflow, "candidate artifact H3 gate is not required")
        publication = workflow.index('name: Publish and verify packages in dependency order')
        self.assertLess(workflow.index(source), publication)
        self.assertLess(workflow.index(candidate), publication)
        self.assertGreater(workflow.index(published), publication)
        self.assertIn("'caddy_*_test.py'", workflow)
        self.assertIn('if: always()', workflow[workflow.index('name: Preserve HTTP3 release peer diagnostics'):])

    def test_candidate_missing_archive_stops_before_consumer_traffic(self):
        with patch.object(consumer_gate, "http3_project") as traffic:
            with self.assertRaisesRegex(RuntimeError, "missing candidate archive"):
                consumer_gate.run("1.2.3", self.directory, mode="http3")
        traffic.assert_not_called()

    def test_published_checksum_mismatch_stops_before_consumer_traffic(self):
        with patch("hex_packages.release_status", side_effect=RuntimeError("checksum mismatch")), patch.object(
                consumer_gate, "http3_project") as traffic:
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                consumer_gate.run("1.2.3", self.directory, mode="http3", published=True)
        traffic.assert_not_called()

    def test_real_mix_consumer_rejects_path_package_before_public_gate(self):
        project = self.directory / "rejected"
        dependency = project / "deps/ex_ssl"
        dependency.mkdir(parents=True)
        (dependency / "mix.exs").write_text('''defmodule FakeSSL.MixProject do
  use Mix.Project
  def project, do: [app: :ex_ssl, version: "1.2.3"]
end
''')
        (project / "mix.exs").write_text('''defmodule RejectedConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :rejected_consumer, version: "0.0.0", deps: [{:ex_ssl, path: "deps/ex_ssl"}]]
end
''')
        shutil.copyfile(ROOT / "scripts/release/http3_consumer.exs", project / "provenance.exs")
        environment = {**os.environ, "MIX_ENV": "test", "MIX_BUILD_PATH": str(project / "build"),
                       "MIX_DEPS_PATH": str(project / "deps"), "HTTP3_CONSUMER_VERSION": "1.2.3",
                       "HTTP3_CONSUMER_PROJECT": str(project), "HTTP3_CONSUMER_SOURCE": "candidate"}
        result = subprocess.run(["mix", "run", "provenance.exs"], cwd=project, env=environment,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid Hex resolution for ex_ssl", result.stdout + result.stderr)

    def test_canary_preserves_provenance_and_requires_full_duration_from_tag(self):
        sha = "a" * 40
        with patch.object(consumer_gate, "command") as command:
            consumer_gate.http3_project(self.directory, "1.2.3", {}, canary_sha=sha)
        project = self.directory / "http3"
        self.assertEqual((project / "canary.exs").read_bytes(),
                         (ROOT / "scripts/http3/canary.exs").read_bytes())
        self.assertFalse((project / "public_gate.exs").exists())
        self.assertEqual((project / "gate.exs").read_text(),
                         'Code.require_file("provenance.exs", __DIR__)\n'
                         'Code.require_file("canary.exs", __DIR__)\n')
        launcher = command.call_args_list[-1]
        self.assertEqual(launcher.kwargs["env"]["HTTP3_CANARY_SECONDS"], "86400")
        self.assertEqual(launcher.kwargs["env"]["HTTP3_CANARY_SHA"], sha)
        arguments = launcher.args[0]
        self.assertEqual(arguments[arguments.index("--timeout") + 1], "87000")

    def test_canary_rejects_candidate_mode_missing_archives_and_wrong_tag(self):
        for published, archives in [(False, self.directory), (True, None)]:
            with self.assertRaisesRegex(ValueError, "requires published"):
                consumer_gate.run("1.2.3", archives, mode="http3-canary", published=published)
        sha = "a" * 40
        with patch.object(consumer_gate.subprocess, "check_output", side_effect=[sha, "b" * 40]):
            with self.assertRaisesRegex(ValueError, "exact release tag"):
                consumer_gate.verify_canary_source("1.2.3", sha)
        with patch.object(consumer_gate.subprocess, "check_output", side_effect=[sha, sha, "changed.py"]):
            with self.assertRaisesRegex(ValueError, "tracked changes"):
                consumer_gate.verify_canary_source("1.2.3", sha)

    def test_published_canary_keeps_checksum_preflight_before_traffic(self):
        with patch.object(consumer_gate, "verify_canary_source"), patch(
                "hex_packages.release_status", side_effect=RuntimeError("checksum mismatch")), patch.object(
                consumer_gate, "http3_project") as traffic:
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                consumer_gate.run("1.2.3", self.directory, mode="http3-canary",
                                  published=True, source_sha="a" * 40)
        traffic.assert_not_called()

    def test_published_canary_checks_all_nine_archives_without_local_registry(self):
        sha = "a" * 40
        with patch.object(consumer_gate, "verify_canary_source"), patch(
                "hex_packages.release_status", return_value="matching") as checksums, patch.object(
                consumer_gate, "setup_registry") as registry, patch.object(
                consumer_gate, "http3_project") as traffic:
            consumer_gate.run("1.2.3", self.directory, mode="http3-canary",
                              published=True, source_sha=sha)
        self.assertEqual(checksums.call_count, 9)
        registry.assert_not_called()
        self.assertEqual(traffic.call_args.kwargs["canary_sha"], sha)
        self.assertEqual(traffic.call_args.args[2]["HTTP3_CONSUMER_SOURCE"], "published")

    def test_canary_cannot_pass_on_short_interrupted_or_unproven_result(self):
        sha = "a" * 40
        provenance = "HTTP3 consumer provenance: published, nine Hex packages == 1.2.3: PASS\n"
        result = f"HTTP3 canary result: PASS seconds=86400 requests=1 peak_memory=1 errors=0 commit={sha}\n"
        classify = post_release_canary.classify
        self.assertEqual(classify(0, provenance + result, 86400, "1.2.3", sha), "PASS")
        for code, output, elapsed in [(0, provenance + result, 100), (-15, provenance + result, 86400),
                                      (1, provenance + result, 86400), (0, result, 86400),
                                      (0, provenance + result.replace(sha, "b" * 40), 86400),
                                      (0, provenance + result.replace("seconds=86400", "seconds=100"), 86400)]:
            self.assertNotEqual(classify(code, output, elapsed, "1.2.3", sha), "PASS")

    def test_failed_canary_creates_separate_bug_and_comments_tracking_issue(self):
        args = SimpleNamespace(output_dir=self.directory, repo="gsmlg-dev/http_fetch",
                               issue=42, version="1.2.3", source_sha="a" * 40)
        status = dict(result="FAIL", elapsed_seconds=100, returncode=1,
                      error="checksum mismatch", failure_evidence="Existing Hex package differs from release archive",
                      last_canary_measurement="No workload measurement recorded")
        with patch.object(post_release_canary.subprocess, "check_output", return_value="https://github.com/gsmlg-dev/http_fetch/issues/43\n") as create, patch.object(
                post_release_canary.subprocess, "run") as comment:
            post_release_canary.report(args, status)
        self.assertIn("Bug", create.call_args.args[0])
        self.assertIn("42", comment.call_args.args[0])
        self.assertTrue(status["followup_issue"].endswith("/43"))
        report = (self.directory / "report.md").read_text()
        self.assertIn("Separate follow-up task", report)
        self.assertIn("Required: all nine", report)
        self.assertNotIn("Verified: all nine", report)
        self.assertIn("checksum mismatch", report)
        self.assertIn("Existing Hex package differs", report)
        self.assertIn("No workload measurement recorded", report)
        status["result"] = "PASS"
        status["provenance_verified"] = True
        status["last_canary_measurement"] = "HTTP3 canary result: PASS seconds=86400 requests=1024"
        with patch.object(post_release_canary.subprocess, "run"):
            post_release_canary.report(args, status)
        report = (self.directory / "report.md").read_text()
        self.assertIn("Verified: all nine", report)
        self.assertIn("seconds=86400 requests=1024", report)
        self.assertIn("Runner wall time including setup", report)

    def test_interrupted_worker_records_final_status_and_stops_its_child(self):
        args = SimpleNamespace(output_dir=self.directory, repo="gsmlg-dev/http_fetch",
                               issue=42, version="1.2.3", source_sha="a" * 40)
        with patch.object(post_release_canary, "verify_canary_source"), patch.object(
                post_release_canary.subprocess, "run"), patch.object(
                post_release_canary.subprocess, "Popen") as popen, patch.object(
                post_release_canary.os, "killpg") as stop, patch.object(
                post_release_canary, "report"):
            child = popen.return_value
            child.pid = 12345
            child.poll.return_value = None
            child.wait.side_effect = [KeyboardInterrupt(), 0]
            self.assertEqual(post_release_canary.worker(args), 1)
        status = json.loads((self.directory / "status.json").read_text())
        self.assertEqual(status["result"], "INTERRUPTED")
        stop.assert_called_once_with(12345, post_release_canary.signal.SIGINT)


if __name__ == "__main__":
    unittest.main()

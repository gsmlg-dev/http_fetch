"""Release HTTP/3 isolation, gate propagation and publication ordering."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import consumer_gate
from stage import PACKAGES, ROOT


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


if __name__ == "__main__":
    unittest.main()

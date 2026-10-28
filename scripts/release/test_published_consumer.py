"""Published TLS consumers must resolve cold Hex packages before traffic."""

from contextlib import ExitStack
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch

import consumer_gate


class PublishedConsumerTests(unittest.TestCase):
    def test_published_modes_verify_every_archive_without_candidate_registry(self):
        for mode in ("all", "runtime", "external", "h2", "feature"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                archives = Path(directory)
                checksums = stack.enter_context(patch("hex_packages.release_status", return_value="matching"))
                registry = stack.enter_context(patch.object(consumer_gate, "setup_registry"))
                server = stack.enter_context(patch.object(consumer_gate, "local_registry"))
                projects = {name: stack.enter_context(patch.object(consumer_gate, name)) for name in (
                    "verify_project", "runtime_projects", "external_project", "http2_project",
                    "feature_project", "migration_project", "http3_project")}
                consumer_gate.run("1.2.3", archives, mode=mode, published=True)
                self.assertEqual(checksums.call_args_list, [
                    call(package, "1.2.3", archives / f"{package}-1.2.3.tar")
                    for package in consumer_gate.PACKAGES])
                registry.assert_not_called()
                server.assert_not_called()
                expected = {"all": {"verify_project": 9}, "runtime": {"runtime_projects": 1},
                            "external": {"external_project": 1}, "h2": {"http2_project": 1},
                            "feature": {"feature_project": 1, "migration_project": 1}}[mode]
                for name, project in projects.items():
                    self.assertEqual(project.call_count, expected.get(name, 0))

    def test_new_published_modes_require_release_archives_before_work(self):
        with patch.object(consumer_gate.tempfile, "mkdtemp") as directory:
            for mode in ("all", "runtime", "external", "h2", "feature"):
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "release archives"):
                    consumer_gate.run("1.2.3", mode=mode, published=True)
            directory.assert_not_called()

    def test_last_package_mismatch_prevents_all_published_traffic(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("hex_packages.release_status", side_effect=["matching"] * 8 + ["missing"]), \
                patch.object(consumer_gate, "feature_project") as features, \
                patch.object(consumer_gate, "migration_project") as migration, \
                patch.object(consumer_gate, "setup_registry") as registry:
            with self.assertRaisesRegex(RuntimeError, "published package is missing"):
                consumer_gate.run("1.2.3", directory, mode="feature", published=True)
            features.assert_not_called()
            migration.assert_not_called()
            registry.assert_not_called()

    def test_published_resolution_cannot_reuse_inherited_candidate_cache(self):
        inherited = {"HEX_HOME": "/candidate/hex", "HEX_CONFIG_HOME": "/candidate/config",
                     "HEX_CACHE_HOME": "/candidate/cache", "HEX_MIRROR": "http://candidate",
                     "HEX_TRUSTED_MIRROR": "http://candidate", "HEX_OFFLINE": "true",
                     "HEX_UNSAFE_REGISTRY": "1", "HEX_UNSAFE_HTTPS": "1",
                     "MIX_BUILD_PATH": "/candidate/build", "MIX_DEPS_PATH": "/candidate/deps"}
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, inherited), \
                patch("hex_packages.release_status", return_value="matching"), \
                patch.object(consumer_gate, "external_project") as project:
            consumer_gate.run("1.2.3", directory, mode="external", published=True)
            root, _, env = project.call_args.args
            self.assertEqual(env["HTTP_FETCH_CONSUMER_SOURCE"], "published")
            self.assertEqual(env["HEX_HOME"], str(root / "hex"))
            self.assertEqual(env["HEX_CONFIG_HOME"], str(root / "hex"))
            self.assertEqual(env["HEX_CACHE_HOME"], str(root / "hex-cache"))
            for key in ("HEX_MIRROR", "HEX_TRUSTED_MIRROR", "HEX_OFFLINE", "HEX_UNSAFE_REGISTRY",
                        "HEX_UNSAFE_HTTPS", "MIX_BUILD_PATH", "MIX_DEPS_PATH"):
                self.assertNotIn(key, env)

    def test_current_feature_consumers_override_inherited_historical_default(self):
        for source in ("candidate", "published"):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory, \
                    patch.object(consumer_gate, "command", side_effect=RuntimeError("stop before Mix")) as command:
                with self.assertRaisesRegex(RuntimeError, "stop before Mix"):
                    consumer_gate.feature_project(Path(directory), "1.2.3", {
                        "HTTP_FETCH_CONSUMER_SOURCE": source,
                        "EX_SSL_EXPECTED_DEFAULT_BACKEND": "ssl",
                    })
                self.assertEqual(command.call_args.kwargs["env"]["EX_SSL_EXPECTED_DEFAULT_BACKEND"],
                                 "ex_ssl")
                self.assertEqual(command.call_args.kwargs["env"]["HTTP_FETCH_CONSUMER_SOURCE"],
                                 source)

    def test_published_feature_failure_propagates_before_migration(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("hex_packages.release_status", return_value="matching"), \
                patch.object(consumer_gate, "feature_project", side_effect=subprocess.CalledProcessError(2, "mix")), \
                patch.object(consumer_gate, "migration_project") as migration:
            with self.assertRaises(subprocess.CalledProcessError):
                consumer_gate.run("1.2.3", directory, mode="feature", published=True)
            migration.assert_not_called()

    def test_published_migration_provenance_names_the_actual_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "provenance.log"
            with patch.dict(os.environ, {"EX_SSL_PROVENANCE_LOG": str(report)}), \
                    patch.object(consumer_gate.subprocess, "check_output", return_value="a" * 40), \
                    patch.object(consumer_gate, "command", side_effect=RuntimeError("stop before Mix")):
                with self.assertRaisesRegex(RuntimeError, "stop before Mix"):
                    consumer_gate.migration_project(Path(directory), "1.2.3", {
                        "HTTP_FETCH_CONSUMER_SOURCE": "published"})
            provenance = (Path(directory) / "migration/provenance.exs").read_text()
            self.assertIn('IO.puts("runtime=migration-hex-published/', provenance)
            self.assertNotIn("migration-hex-candidate", provenance)
            self.assertIn("migration_fixture_source=umbrella-current/" + "a" * 40, report.read_text())

    def test_release_runs_published_tls_consumers_after_publication(self):
        workflow = (consumer_gate.ROOT / ".github/workflows/release.yml").read_text()
        start = workflow.index("name: Verify published isolated TLS migration consumers")
        self.assertGreater(start, workflow.index("name: Publish and verify packages in dependency order"))
        end = workflow.index("name: Attach and verify all immutable GitHub release archives")
        self.assertLess(start, end)
        step = workflow[start:end]
        self.assertIn("for mode in all external feature; do", step)
        self.assertIn('--mode "$mode" --published', step)


if __name__ == "__main__":
    unittest.main()

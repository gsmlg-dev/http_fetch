"""The candidate migration gate must exercise packages without source overrides."""

from pathlib import Path
from contextlib import redirect_stdout
import io
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import consumer_gate


class MigrationConsumerTests(unittest.TestCase):
    def test_staging_retains_test_paths_and_never_copies_production_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "consumer"
            groups = consumer_gate.stage_migration_tests(project)

            self.assertTrue(groups)
            for files in groups.values():
                self.assertTrue(files)
                for name in files:
                    self.assertEqual((project / name).read_bytes(),
                                     (consumer_gate.ROOT / name).read_bytes())
            self.assertTrue((project / "apps/ex_ssl/test/support/local_tls_peer.ex").is_file())
            self.assertTrue((project / "scripts/tls_migration_performance_peer.py").is_file())
            self.assertEqual(list(project.glob("apps/*/lib")), [])
            self.assertEqual(list(project.glob("apps/*/mix.exs")), [])

    def test_missing_mandatory_suite_fails_before_launching_mix(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(consumer_gate, "ROOT", Path(directory) / "missing"):
                with patch.object(consumer_gate, "command") as command:
                    with self.assertRaisesRegex(RuntimeError, "missing migration"):
                        consumer_gate.migration_project(Path(directory), "1.2.3", {})
                    command.assert_not_called()

    def test_missing_ticket_scenarios_fail_before_staging(self):
        required = (
            "apps/ex_ssl/test/ssl/manual_ticket_test.exs",
            "apps/ex_ssl/test/ssl/manual_ticket_integration_test.exs",
            "apps/ex_ssl/test/ssl/resumption_context_test.exs",
            "apps/ex_ssl/test/ssl/protocol/resumption_verifier_test.exs",
            "apps/ex_ssl/test/ssl/tls12_session_options_test.exs",
            "apps/ex_ssl/test/ssl/tls12_session_cache_test.exs",
            "apps/ex_ssl/test/ssl/tls12_session_context_test.exs",
            "apps/ex_ssl/test/ssl/tls12_session_integration_test.exs",
            "apps/ex_ssl/test/ssl/protocol/tls12_session_test.exs",
        )
        for name in required:
            with self.subTest(name=name):
                missing = consumer_gate.ROOT / name
                with patch.object(Path, "exists", new=lambda path: path != missing), \
                        patch.object(Path, "mkdir"), \
                        patch.object(consumer_gate.shutil, "copytree") as copytree, \
                        patch.object(consumer_gate.shutil, "copyfile") as copyfile:
                    with self.assertRaisesRegex(RuntimeError, "missing migration.*" + name):
                        consumer_gate.stage_migration_tests(Path("unused"))
                    copytree.assert_not_called()
                    copyfile.assert_not_called()

    def test_project_resolves_all_nine_packages_and_compiles_only_test_support(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(consumer_gate, "command", side_effect=RuntimeError("stop before Mix")):
                with self.assertRaisesRegex(RuntimeError, "stop before Mix"):
                    consumer_gate.migration_project(Path(directory), "1.2.3", {})
            project = Path(directory) / "migration"
            source = (project / "mix.exs").read_text()
            for package in consumer_gate.PACKAGES:
                self.assertIn(f'{{:{package}, "== 1.2.3"}}', source)
            for forbidden in ("path:", "override:", "in_umbrella:", '"lib"'):
                self.assertNotIn(forbidden, source)
            self.assertIn('"apps/ex_ssl/test/support"', source)

    def test_a_zero_test_file_cannot_hide_behind_another_passing_file(self):
        files = consumer_gate.MIGRATION_GROUPS["policy"][:2]
        outputs = iter(("1 test, 0 failures\n", "0 tests, 0 failures\n"))

        def finish_test(_args, **kwargs):
            kwargs["stdout"].write(next(outputs))
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(consumer_gate, "MIGRATION_GROUPS", {"policy": files}), \
                patch.object(consumer_gate, "command"), \
                patch.object(consumer_gate.subprocess, "run", side_effect=finish_test):
            with self.assertRaisesRegex(RuntimeError, "candidate migration file failed:.*ocsp"):
                consumer_gate.migration_project(Path(directory), "1.2.3", {})

    def test_same_named_client_suites_keep_separate_result_logs(self):
        files = consumer_gate.MIGRATION_GROUPS["streams"]
        outputs = ("2 tests, 0 failures\n", "3 tests, 0 failures\n")
        remaining = iter(outputs)

        def finish_test(_args, **kwargs):
            kwargs["stdout"].write(next(remaining))
            return SimpleNamespace(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory) / "groups"
            with patch.object(consumer_gate, "MIGRATION_GROUPS", {"streams": files}), \
                    patch.object(consumer_gate, "command"), \
                    patch.object(consumer_gate.subprocess, "run", side_effect=finish_test), \
                    patch.dict(consumer_gate.os.environ, {"EX_SSL_GROUP_LOG_DIR": str(logs)}):
                consumer_gate.migration_project(Path(directory), "1.2.3", {})
            actual = list(logs.glob("*.log"))
            self.assertEqual(len(actual), 2)
            self.assertEqual({log.read_text() for log in actual}, set(outputs))

    def test_failed_file_reports_first_assertion_and_final_summary(self):
        files = consumer_gate.MIGRATION_GROUPS["policy"][:1]
        first_failure = "  1) test independent policy\n     left:  :unexpected_policy\n"
        final_summary = "Result: 1164/1252 passed\nFailed: 88 tests\n"
        output = "peer progress\n" * 1000 + first_failure + "later progress\n" * 1000 + final_summary

        def finish_test(_args, **kwargs):
            kwargs["stdout"].write(output)
            return SimpleNamespace(returncode=2)

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(consumer_gate, "MIGRATION_GROUPS", {"policy": files}), \
                patch.object(consumer_gate, "command"), \
                patch.object(consumer_gate.subprocess, "run", side_effect=finish_test):
            reported = io.StringIO()
            with redirect_stdout(reported):
                with self.assertRaisesRegex(RuntimeError, "candidate migration file failed:"):
                    consumer_gate.migration_project(Path(directory), "1.2.3", {})
            self.assertIn(first_failure, reported.getvalue())
            self.assertIn(final_summary, reported.getvalue())


if __name__ == "__main__":
    unittest.main()

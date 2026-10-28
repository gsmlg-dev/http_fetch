"""Regressions for the historical Hex consumer source boundary."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_COMMIT = "e844ce03067fedac82c079f21c47810e671be0bb"


class HistoricalSourceTests(unittest.TestCase):
    def test_staged_historical_fetch_has_regular_package_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "stage"
            result = subprocess.run(
                ["python3", str(ROOT / "scripts/ci/stage_ex_ssl_history.py"),
                 str(ROOT), HISTORICAL_COMMIT, str(target)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((target / "mix.lock").read_bytes(),
                             subprocess.check_output(["git", "show", f"{HISTORICAL_COMMIT}:mix.lock"], cwd=ROOT))
            fetch = target / "apps/http_fetch"
            for name in ("LICENSE", "README.md", "CHANGELOG.md"):
                self.assertTrue((fetch / name).is_file())
                self.assertFalse((fetch / name).is_symlink())
            core = (target / "apps/http_core/mix.exs").read_text()
            self.assertIn('{:ex_ssl, "~> 0.7.2"}', core)
            self.assertNotIn('in_umbrella: true, hex: :ex_ssl', core)

    def test_rejects_wrong_revision_before_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "stage"
            result = subprocess.run(
                ["python3", str(ROOT / "scripts/ci/stage_ex_ssl_history.py"),
                 str(ROOT), "0" * 40, str(target)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(target.exists())

    def test_scheduled_workflow_runs_both_historical_and_candidate_gates(self):
        workflow = (ROOT / ".github/workflows/ex_ssl_compat.yml").read_text()
        self.assertIn(HISTORICAL_COMMIT, workflow)
        self.assertIn("scripts/ex_ssl_published_feature_gate.sh", workflow)
        self.assertIn("scripts/release/stage.py build", workflow)
        self.assertIn("scripts/ex_ssl_source_smoke.sh", workflow)
        self.assertIn("EX_SSL_DEP_MODE: candidate", workflow)
        self.assertIn("scripts/release/consumer_gate.py", workflow)
        self.assertIn("steps.published_feature.outcome != 'skipped'", workflow)
        self.assertIn("steps.candidate_feature.outcome != 'skipped'", workflow)
        self.assertEqual(workflow.count("if-no-files-found: error"), 2)

    def test_historical_runner_pins_default_independently_of_inherited_environment(self):
        source = (ROOT / "scripts/ex_ssl_source_smoke.sh").read_text()
        start = source.index("EX_SSL_EXPECTED_DEFAULT_BACKEND=ex_ssl")
        end = source.index("export EX_SSL_EXPECTED_DEFAULT_BACKEND", start)
        setup = source[start:end] + 'printf "%s" "$EX_SSL_EXPECTED_DEFAULT_BACKEND"'
        for mode, expected in (("source", "ex_ssl"), ("candidate", "ex_ssl"), ("published", "ssl")):
            with self.subTest(mode=mode):
                env = {**os.environ, "EX_SSL_DEP_MODE": mode,
                       "EX_SSL_EXPECTED_DEFAULT_BACKEND": "invalid-inherited-value"}
                result = subprocess.run(["bash", "-eu", "-c", setup], env=env,
                                        capture_output=True, text=True, check=True)
                self.assertEqual(result.stdout, expected)
        self.assertIn(HISTORICAL_COMMIT, source)
        fixture = (ROOT / "scripts/ex_ssl_fixture_manifest.env").read_text()
        self.assertIn("EX_SSL_FIXTURE_VERSION=0.7.2", fixture)

    def test_exunit_120_result_format_requires_all_tests_to_pass(self):
        from sys import path
        path.insert(0, str(ROOT / "scripts/release"))
        from consumer_gate import feature_group_passed

        self.assertTrue(feature_group_passed("Finished in 0.6 seconds\nResult: 12 passed\n"))
        self.assertTrue(feature_group_passed("Finished in 0.6 seconds\n12 tests, 0 failures\n"))
        self.assertFalse(feature_group_passed("Result: 11 passed, 1 failed\n"))
        self.assertFalse(feature_group_passed("Result: 11 passed, 1 skipped\n"))
        self.assertFalse(feature_group_passed("Result: 0 passed\n"))
        self.assertFalse(feature_group_passed("12 tests, 0 failures, 1 excluded\n"))
        self.assertFalse(feature_group_passed("0 tests, 0 failures\n"))


if __name__ == "__main__":
    unittest.main()

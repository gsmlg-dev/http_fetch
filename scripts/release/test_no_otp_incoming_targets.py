"""Focused incoming-target controls and isolated wrapper resource tests."""
from pathlib import Path
import os
import re
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, call, patch

HERE = Path(__file__).resolve().parent
EXPECTED_TESTS = 19


def run_compiled_controls():
    argv = ["elixir", str(HERE / "test_no_otp_incoming_targets.exs")]
    with tempfile.TemporaryDirectory(prefix="no-otp-incoming-") as directory:
        environment = os.environ.copy()
        environment["TMPDIR"] = directory
        child = subprocess.Popen(argv, cwd=HERE.parent.parent, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True, env=environment)
        try:
            output, _ = child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                output, _ = child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                output, _ = child.communicate(timeout=5)
            raise AssertionError("compiled incoming-target controls timed out:\n" + output)
        if child.returncode != 0:
            raise AssertionError("compiled incoming-target controls failed:\n" + output)
        output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
        summaries = re.findall(r"\b(\d+) tests, (\d+) failures\b", output)
        if summaries != [(str(EXPECTED_TESTS), "0")]:
            raise AssertionError("unexpected compiled control summary:\n" + output)
        if re.search(r"\b[1-9]\d* (?:excluded|skipped)\b", output):
            raise AssertionError("compiled controls were excluded or skipped:\n" + output)
        return output


class CompiledIncomingTargetTests(unittest.TestCase):
    def test_all_focused_compiled_controls(self):
        run_compiled_controls()


class IncomingTargetWrapperResourceTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory(prefix="incoming-wrapper-resource-")
        self.addCleanup(self.sandbox.cleanup)
        self.parent = Path(self.sandbox.name)
        self.keep = self.parent / "pre-existing.txt"
        self.keep.write_bytes(b"preserve unrelated state")
        self.environment = dict(os.environ, TMPDIR=str(self.parent), CUSTOM_INCOMING="preserved")
        env_patch = patch.dict(os.environ, self.environment, clear=True)
        env_patch.start()
        self.addCleanup(env_patch.stop)
        temp_patch = patch.object(tempfile, "tempdir", str(self.parent))
        temp_patch.start()
        self.addCleanup(temp_patch.stop)
        self.roots = []

    def invoke(self, output="19 tests, 0 failures\n", returncode=0, outcomes=None, spawn_error=None):
        child = Mock(pid=712346, returncode=returncode)
        captured = {}
        responses = iter(outcomes) if outcomes is not None else None

        def spawn(argv, **kwargs):
            directory = Path(kwargs["env"]["TMPDIR"])
            self.roots.append(directory)
            captured.update(argv=argv, kwargs=kwargs, directory=directory)
            self.assertTrue(directory.is_dir())
            self.assertNotEqual(directory, self.parent)
            self.assertEqual(directory.parent, self.parent)
            (directory / "owned.beam").write_bytes(b"fixture bytes")
            if spawn_error is not None:
                raise spawn_error
            return child

        def communicate(*, timeout):
            self.assertTrue(captured["directory"].is_dir(), "root removed before child reap")
            if responses is not None:
                response = next(responses)
                if isinstance(response, Exception):
                    raise response
                return response
            return output, None

        child.communicate.side_effect = communicate
        error = None
        with patch(__name__ + ".subprocess.Popen", side_effect=spawn), \
                patch(__name__ + ".os.killpg") as killpg:
            try:
                run_compiled_controls()
            except (AssertionError, OSError) as failure:
                error = failure
        self.assertFalse(captured["directory"].exists())
        self.assertEqual(self.keep.read_bytes(), b"preserve unrelated state")
        self.assertEqual(set(self.parent.iterdir()), {self.keep})
        self.assertEqual(dict(os.environ), self.environment)
        self.assertEqual(captured["kwargs"]["env"], dict(self.environment, TMPDIR=str(captured["directory"])))
        self.assertEqual(captured["argv"], ["elixir", str(HERE / "test_no_otp_incoming_targets.exs")])
        self.assertEqual(captured["kwargs"]["cwd"], HERE.parent.parent)
        self.assertTrue(captured["kwargs"]["start_new_session"])
        self.assertTrue(captured["kwargs"]["text"])
        self.assertEqual(captured["kwargs"]["stdout"], subprocess.PIPE)
        self.assertEqual(captured["kwargs"]["stderr"], subprocess.STDOUT)
        return child, killpg, error

    def test_success_isolated_roots_and_ansi_summary(self):
        for output in ["19 tests, 0 failures\n", "\x1b[32m19 tests, 0 failures\x1b[0m\n"]:
            child, signals, error = self.invoke(output=output)
            self.assertIsNone(error)
            self.assertEqual(child.communicate.call_args_list, [call(timeout=60)])
            signals.assert_not_called()
        self.assertNotEqual(self.roots[0], self.roots[1])

    def test_nonzero_exit_is_not_a_pass(self):
        _, signals, error = self.invoke(returncode=1)
        self.assertIsInstance(error, AssertionError)
        signals.assert_not_called()

    def test_partial_duplicate_and_wrong_summaries_are_rejected(self):
        for output in ["18 tests, 0 failures\n", "19 tests, 1 failures\n", "119 tests, 0 failures\n",
                       "19 tests, 0 failures\n19 tests, 0 failures\n", ""]:
            _, _, error = self.invoke(output=output)
            self.assertIsInstance(error, AssertionError)

    def test_excluded_or_skipped_controls_are_rejected(self):
        for suffix in ["1 excluded", "1 skipped"]:
            _, _, error = self.invoke(output="19 tests, 0 failures, " + suffix)
            self.assertIsInstance(error, AssertionError)

    def test_term_timeout_reaps_before_removing_root(self):
        child, signals, error = self.invoke(returncode=-15, outcomes=[
            subprocess.TimeoutExpired("elixir", 60), ("terminated", None)])
        self.assertIsInstance(error, AssertionError)
        self.assertIn("timed out", str(error))
        self.assertEqual(child.communicate.call_args_list, [call(timeout=60), call(timeout=5)])
        self.assertEqual(signals.call_args_list, [call(child.pid, signal.SIGTERM)])

    def test_kill_timeout_reaps_before_removing_root(self):
        child, signals, error = self.invoke(returncode=-9, outcomes=[
            subprocess.TimeoutExpired("elixir", 60), subprocess.TimeoutExpired("elixir", 5),
            ("killed", None)])
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(child.communicate.call_args_list,
                         [call(timeout=60), call(timeout=5), call(timeout=5)])
        self.assertEqual(signals.call_args_list,
                         [call(child.pid, signal.SIGTERM), call(child.pid, signal.SIGKILL)])

    def test_spawn_failure_only_cleans_owned_root(self):
        _, signals, error = self.invoke(spawn_error=OSError("fixture spawn failure"))
        self.assertIsInstance(error, OSError)
        signals.assert_not_called()

    def test_zero_skip_and_exclusion_counts_do_not_hide_selected_controls(self):
        _, _, error = self.invoke(output="19 tests, 0 failures, 0 excluded, 0 skipped\n")
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()

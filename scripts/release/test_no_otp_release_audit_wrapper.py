"""Resource tests for the compiled audit wrapper; no Elixir process is started."""
from pathlib import Path
import os
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, call, patch

import test_no_otp_release_audit as wrapper


# Both retained suite generations use these resource tests. Their exact count
# remains independently enforced by the real compiled wrapper, not this mock.
SUCCESS_OUTPUT = "310 tests, 0 failures\n328 tests, 0 failures\n"


class CompiledAuditWrapperIsolationTests(unittest.TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory(prefix="audit-wrapper-resource-test-")
        self.addCleanup(self.sandbox.cleanup)
        self.parent = Path(self.sandbox.name)
        self.stale = self.parent / "no-otp-lexical-7" / "lib" / "audit_fixture-1" / "ebin"
        self.stale.mkdir(parents=True)
        self.stale_file = self.stale / "old.beam"
        self.stale_file.write_bytes(b"pre-existing fixture bytes")
        self.sibling = self.parent / "sibling"
        self.sibling.mkdir()
        self.sibling_file = self.sibling / "keep.txt"
        self.sibling_file.write_bytes(b"unrelated sibling bytes")
        self.original_files = {self.stale_file: self.stale_file.read_bytes(),
                               self.sibling_file: self.sibling_file.read_bytes()}
        self.environment = {
            "TMPDIR": str(self.parent), "TMP": str(self.sibling), "TEMP": str(self.sibling),
            "PATH": "/fixture/tools", "ERL_FLAGS": "+S 4:4",
            "NO_OTP_AUDIT_SOURCE_ROOT": "/fixture/source", "CUSTOM_OPTION": "preserved",
        }
        environment_patch = patch.dict(os.environ, self.environment, clear=True)
        environment_patch.start()
        self.addCleanup(environment_patch.stop)
        # Keep every actual filesystem operation inside this test's sandbox,
        # independently of tempfile's process-wide cached default directory.
        tempdir_patch = patch.object(tempfile, "tempdir", str(self.parent))
        tempdir_patch.start()
        self.addCleanup(tempdir_patch.stop)
        self.roots = []
        self.children = []

    def invoke(self, returncode=0, outcomes=None, output=SUCCESS_OUTPUT, spawn_error=None):
        child = Mock(pid=712345, returncode=returncode)
        self.children.append(child)
        captured = {}
        responses = iter(outcomes) if outcomes is not None else None

        def spawn(argv, **kwargs):
            # This models the same VM-local fixture number across invocations.
            # Observe stale data, but never write into an unowned parent path.
            child_environment = kwargs.get("env", dict(os.environ))
            root = Path(child_environment.get("TMPDIR", tempfile.gettempdir()))
            self.roots.append(root)
            captured.update(argv=argv, kwargs=kwargs, environment=child_environment,
                            root=root, existed_at_spawn=root.is_dir())
            stale = root / "no-otp-lexical-7" / "lib" / "audit_fixture-1" / "ebin" / "old.beam"
            captured['inherited_stale_fixture'] = stale.exists()
            if root != self.parent:
                fixture = root / "no-otp-lexical-7" / "nested"
                fixture.mkdir(parents=True)
                (fixture / "owned.beam").write_bytes(b"this child only")
                (root / "sibling-link").symlink_to(self.sibling, target_is_directory=True)
            if spawn_error is not None:
                raise spawn_error
            return child

        def communicate(*, timeout):
            self.assertTrue(captured["root"].is_dir(), "temporary root removed before child reap")
            if responses is not None:
                response = next(responses)
                if isinstance(response, Exception):
                    raise response
                return response
            if captured['inherited_stale_fixture']:
                return "310 tests, 1 failures\n328 tests, 1 failures\n", None
            return output, None

        child.communicate.side_effect = communicate
        case = wrapper.CompiledLexicalAuditTests('test_real_lexical_and_adversarial_beam_controls')
        with patch.object(wrapper.subprocess, "Popen", side_effect=spawn) as popen, \
                patch.object(wrapper.os, "killpg") as killpg:
            result = unittest.TestResult()
            case.run(result)
        captured.update(result=result, popen=popen, killpg=killpg, child=child)
        return captured

    def assert_owned_and_cleaned(self, observed):
        root = observed['root']
        self.assertTrue(observed['existed_at_spawn'])
        self.assertNotEqual(root, self.parent)
        self.assertEqual(root.parent, self.parent)
        self.assertFalse(root.exists())
        self.assertFalse(observed['inherited_stale_fixture'])
        self.assertEqual(dict(os.environ), self.environment)
        self.assertEqual(observed['environment'], dict(self.environment, TMPDIR=str(root)))
        self.assertIsNot(observed['environment'], os.environ)
        for file, content in self.original_files.items():
            self.assertEqual(file.read_bytes(), content)
        self.assertEqual(set(self.parent.iterdir()), {self.parent / "no-otp-lexical-7", self.sibling})
        self.assertEqual(observed['argv'], ["elixir", str(wrapper.HERE / "test_no_otp_release_audit.exs")])
        self.assertEqual(observed['kwargs']['cwd'], wrapper.HERE.parent.parent)
        self.assertTrue(observed['kwargs']['text'])
        self.assertTrue(observed['kwargs']['start_new_session'])
        self.assertEqual(observed['kwargs']['stdout'], subprocess.PIPE)
        self.assertEqual(observed['kwargs']['stderr'], subprocess.STDOUT)

    def test_successive_children_never_reuse_stale_vm_fixture_paths(self):
        for configured_tmpdir in [True, False]:
            if not configured_tmpdir:
                del os.environ["TMPDIR"]
                del self.environment["TMPDIR"]
            observed = self.invoke()
            self.assertTrue(observed['result'].wasSuccessful(), observed['result'].failures)
            self.assert_owned_and_cleaned(observed)
            self.assertEqual(observed['child'].communicate.call_args_list, [call(timeout=60)])
            observed['killpg'].assert_not_called()
        self.assertNotEqual(self.roots[0], self.roots[1])

    def test_nonzero_child_exit_cleans_only_its_owned_root(self):
        observed = self.invoke(returncode=1, output="compiled child failed")
        self.assertEqual(len(observed['result'].failures), 1)
        self.assertEqual(observed['result'].errors, [])
        self.assert_owned_and_cleaned(observed)
        self.assertEqual(observed['child'].communicate.call_args_list, [call(timeout=60)])
        observed['killpg'].assert_not_called()

    def test_timeout_term_reaps_before_owned_root_cleanup(self):
        observed = self.invoke(returncode=-15, outcomes=[subprocess.TimeoutExpired('elixir', 60),
                                                       ("terminated", None)])
        self.assertEqual(len(observed['result'].failures), 1)
        self.assertIn("compiled audit controls timed out", observed['result'].failures[0][1])
        self.assertEqual(observed['result'].errors, [])
        self.assert_owned_and_cleaned(observed)
        self.assertEqual(observed['child'].communicate.call_args_list,
                         [call(timeout=60), call(timeout=5)])
        self.assertEqual(observed['killpg'].call_args_list, [call(712345, signal.SIGTERM)])

    def test_timeout_kill_keeps_original_both_grace_waits(self):
        observed = self.invoke(returncode=-9, outcomes=[subprocess.TimeoutExpired('elixir', 60),
                                                      subprocess.TimeoutExpired('elixir', 5),
                                                      ("killed", None)])
        self.assertEqual(len(observed['result'].failures), 1)
        self.assertIn("compiled audit controls timed out", observed['result'].failures[0][1])
        self.assertEqual(observed['result'].errors, [])
        self.assert_owned_and_cleaned(observed)
        self.assertEqual(observed['child'].communicate.call_args_list,
                         [call(timeout=60), call(timeout=5), call(timeout=5)])
        self.assertEqual(observed['killpg'].call_args_list,
                         [call(712345, signal.SIGTERM), call(712345, signal.SIGKILL)])

    def test_spawn_error_still_cleans_fresh_root_without_signaling(self):
        observed = self.invoke(spawn_error=OSError("fixture spawn unavailable"))
        self.assertEqual(len(observed['result'].errors), 1)
        self.assertEqual(observed['result'].failures, [])
        self.assert_owned_and_cleaned(observed)
        observed['child'].communicate.assert_not_called()
        observed['killpg'].assert_not_called()

    def test_summary_and_exclusion_assertions_still_fail_and_clean(self):
        for output in ["1 tests, 0 failures", SUCCESS_OUTPUT + "1 excluded",
                       SUCCESS_OUTPUT + "1 skipped"]:
            with self.subTest(output=output):
                observed = self.invoke(output=output)
                self.assertEqual(len(observed['result'].failures), 1)
                self.assertEqual(observed['result'].errors, [])
                self.assert_owned_and_cleaned(observed)
                observed['killpg'].assert_not_called()


if __name__ == "__main__":
    unittest.main()

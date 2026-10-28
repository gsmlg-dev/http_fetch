"""Run real compiled-BEAM lexical controls without building a consumer release."""
from pathlib import Path
import os
import re
import signal
import subprocess
import unittest


HERE = Path(__file__).resolve().parent


class CompiledLexicalAuditTests(unittest.TestCase):
    def test_real_lexical_and_adversarial_beam_controls(self):
        argv = ["elixir", str(HERE / "test_no_otp_release_audit.exs")]
        child = subprocess.Popen(argv, cwd=HERE.parent.parent, text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            output, _ = child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            # Signal only the group created above, and always reap its leader.
            os.killpg(child.pid, signal.SIGTERM)
            try:
                output, _ = child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                output, _ = child.communicate(timeout=5)
            self.fail("compiled audit controls timed out:\n" + output)
        self.assertEqual(child.returncode, 0, output)
        output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
        self.assertRegex(output, r"\b87 tests, 0 failures\b")
        self.assertNotRegex(output, r"\b[1-9]\d* (?:excluded|skipped)\b")


if __name__ == "__main__":
    unittest.main()

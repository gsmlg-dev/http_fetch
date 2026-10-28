"""Run single-VM public close-correlation controls from the real consumer source."""
from pathlib import Path
import os
import re
import signal
import subprocess
import unittest

HERE = Path(__file__).resolve().parent


class CompiledConsumerTests(unittest.TestCase):
    def test_public_h3_close_reason_controls(self):
        env = dict(os.environ)
        env.pop("NO_OTP_CONSUMER_SOURCE", None)
        child = subprocess.Popen(
            ["elixir", str(HERE / "test_no_otp_consumer.exs")],
            cwd=HERE.parent.parent, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            output, _ = child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                output, _ = child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                output, _ = child.communicate(timeout=5)
            self.fail("compiled consumer controls timed out:\n" + output)
        self.assertEqual(child.returncode, 0, output)
        output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
        self.assertRegex(output, r"\b6 tests, 0 failures\b")
        self.assertNotRegex(output, r"\b[1-9]\d* (?:excluded|skipped)\b")


if __name__ == "__main__":
    unittest.main()

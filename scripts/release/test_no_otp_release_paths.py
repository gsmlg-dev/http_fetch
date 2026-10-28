"""Exercise actual filesystem path evidence in a separate Elixir VM."""
from pathlib import Path
import os
import re
import signal
import subprocess
import tempfile
import unittest


class ReleasePathTests(unittest.TestCase):
    def test_standard_and_adversarial_release_paths(self):
        script = Path(__file__).with_suffix(".exs")
        env = dict(os.environ, TMPDIR=str(Path(tempfile.gettempdir()).resolve(strict=True)))
        child = subprocess.Popen(["elixir", str(script)], text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True, env=env)
        try:
            output, _ = child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                output, _ = child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                output, _ = child.communicate(timeout=5)
            self.fail("release path controls timed out:\n" + output)
        self.assertEqual(child.returncode, 0, output)
        output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
        self.assertRegex(output, r"\b5 tests, 0 failures\b")
        self.assertNotRegex(output, r"\b[1-9]\d* (?:excluded|skipped)\b")


if __name__ == "__main__":
    unittest.main()

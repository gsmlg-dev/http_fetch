"""Candidate family variants resolve Hex identities with optional Plug isolated."""

import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import consumer_gate
import family_consumer


class FamilyConsumersTest(unittest.TestCase):
    def test_four_isolated_consumers_use_exact_hex_deps_and_execute_behavior_gates(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(family_consumer, "command") as run:
            root = Path(temporary)
            family_consumer.family_projects(root, "1.0.0-rc.9", {"MIX_ENV": "prod"})
            self.assertEqual(run.call_count, 12)
            for variant, package in (("pool", "http_pool"), ("fetch", "http_fetch"),
                                     ("test-no-plug", "http_test"), ("test-plug", "http_test")):
                project = root / "family" / variant
                manifest = (project / "mix.exs").read_text()
                self.assertIn('{:' + package + ', "== 1.0.0-rc.9"}', manifest)
                for forbidden in ("path:", "override:", "in_umbrella:"):
                    self.assertNotIn(forbidden, manifest)
                self.assertEqual("{:plug," in manifest, variant == "test-plug")
                self.assertTrue((project / "gate.exs").read_text())
                calls = [call for call in run.call_args_list if call.kwargs["cwd"] == project]
                self.assertEqual([call.args[0] for call in calls], [
                    ["mix", "deps.get"], ["mix", "compile", "--warnings-as-errors"],
                    ["mix", "run", "gate.exs"]])
                self.assertTrue(all(call.kwargs["env"]["MIX_BUILD_PATH"] == str(project / "build")
                                    for call in calls))

    def test_candidate_ci_runs_family_gate_without_manual_only_condition(self):
        ci = (consumer_gate.ROOT / ".github/workflows/ci.yml").read_text()
        step = ci.split("      - name: Verify standalone pools and test adapters", 1)[1].split("      - name:", 1)[0]
        self.assertIn("--mode family", step)
        self.assertNotIn("full_gate", step)
        self.assertNotIn("continue-on-error", step)


if __name__ == "__main__":
    unittest.main()

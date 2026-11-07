"""Regress isolated runtime ownership and package-count evidence after extraction."""
import importlib.util
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimePoolOwnershipTests(unittest.TestCase):
    def test_candidate_supervision_keeps_registry_and_exactly_one_default_pool_pair(self):
        result = subprocess.run(
            ['elixir', 'scripts/ci/test_runtime_pool_ownership.exs'], cwd=ROOT,
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_traffic_summary_counts_the_actual_production_package_inventory(self):
        traffic = load('runtime_ownership_traffic', 'scripts/http_runtime_package_traffic_gate.py')
        release = load('runtime_ownership_release', 'scripts/release/stage.py')
        results = [dict(mode=mode, protocol='h2' if mode == 'ex_ssl' else 'h2c',
                        verified_tls=mode == 'ex_ssl', consumers=4, connections=4,
                        completed=True, mixed_shared_connection=True)
                   for mode in ('h2c', 'ex_ssl')]
        self.assertEqual(traffic.aggregate_modes(results)['packages'], len(release.PACKAGES))


if __name__ == '__main__':
    unittest.main()

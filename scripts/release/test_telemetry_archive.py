"""Candidate registry must use the locked Telemetry version and checksum."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import consumer_gate


class TelemetryArchiveTests(unittest.TestCase):
    def test_cached_archive_uses_lock_version_and_preserves_bytes(self):
        for version in ("1.3.0", "1.4.2"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                data = b"locked telemetry archive"
                self.prepare(root, version, hashlib.sha256(data).hexdigest(), data)
                output = root / "registry"
                output.mkdir()
                with patch.object(consumer_gate, "ROOT", root), patch.object(Path, "home", return_value=root):
                    consumer_gate.telemetry_archive(output)
                self.assertEqual((output / f"telemetry-{version}.tar").read_bytes(), data)

    def test_corrupt_cached_archive_is_rejected_before_registry_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root, "1.4.2", "0" * 64, b"corrupt archive")
            output = root / "registry"
            output.mkdir()
            with patch.object(consumer_gate, "ROOT", root), patch.object(Path, "home", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "differs from locked outer checksum"):
                    consumer_gate.telemetry_archive(output)
            self.assertEqual(list(output.iterdir()), [])

    @staticmethod
    def prepare(root, version, checksum, data):
        (root / "mix.lock").write_text(
            f'"telemetry": {{:hex, :telemetry, "{version}", "abcd", [:rebar3], [], "hexpm", "{checksum}"}}'
        )
        cache = root / ".hex/packages/hexpm"
        cache.mkdir(parents=True)
        (cache / f"telemetry-{version}.tar").write_bytes(data)


if __name__ == "__main__":
    unittest.main()

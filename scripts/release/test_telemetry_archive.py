"""Candidate registry must use the locked Telemetry version and checksum."""
import hashlib
import os
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
                with patch.object(consumer_gate, "ROOT", root), patch.object(Path, "home", return_value=root), \
                        patch.dict(os.environ, {"HEX_CACHE_HOME": str(root / ".hex")}):
                    consumer_gate.telemetry_archive(output)
                self.assertEqual((output / f"telemetry-{version}.tar").read_bytes(), data)

    def test_corrupt_cached_archive_is_rejected_before_registry_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare(root, "1.4.2", "0" * 64, b"corrupt archive")
            output = root / "registry"
            output.mkdir()
            with patch.object(consumer_gate, "ROOT", root), patch.object(Path, "home", return_value=root), \
                    patch.dict(os.environ, {"HEX_CACHE_HOME": str(root / ".hex")}):
                with self.assertRaisesRegex(RuntimeError, "differs from locked outer checksum"):
                    consumer_gate.telemetry_archive(output)
            self.assertEqual(list(output.iterdir()), [])

    def test_configured_hex_cache_is_used_without_network_fallback(self):
        for variable in ("HEX_CACHE_HOME", "HEX_HOME"):
            with self.subTest(variable=variable), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                data = b"configured locked archive"
                self.prepare(root, "1.4.2", hashlib.sha256(data).hexdigest(), data)
                cache = root / "configured-cache"
                (root / ".hex").rename(cache)
                output = root / "registry"
                output.mkdir()
                environment = {key: value for key, value in os.environ.items()
                               if key not in ("HEX_CACHE_HOME", "HEX_HOME")}
                environment[variable] = str(cache)
                with patch.object(consumer_gate, "ROOT", root), \
                        patch.dict(os.environ, environment, clear=True), \
                        patch.object(consumer_gate, "urlopen", side_effect=AssertionError("unexpected network")):
                    consumer_gate.telemetry_archive(output)
                self.assertEqual((output / "telemetry-1.4.2.tar").read_bytes(), data)

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

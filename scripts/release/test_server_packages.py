"""Independent versions and native archive boundaries cannot leak into core releases."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import docs
import server_packages
import stage

ROOT = stage.ROOT


class ServerPackagesTest(unittest.TestCase):
    def fixture(self, root):
        for package in ("abyss", "abyss_raw", "hell", "http_fetch"):
            source = ROOT / stage.package_path(package) / "mix.exs"
            target = root / stage.package_path(package) / "mix.exs"
            target.parent.mkdir(parents=True)
            shutil.copyfile(source, target)

    def test_prepare_abyss_changes_both_packages_and_preserves_other_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            untouched = {package: (root / stage.package_path(package) / "mix.exs").read_bytes()
                         for package in ("hell", "http_fetch")}
            with patch.object(server_packages, "ROOT", root):
                server_packages.prepare("abyss", "0.10.1")
                self.assertEqual(server_packages.inventory("abyss"), {"abyss": "0.10.1", "abyss_raw": "0.10.1"})
            for package, source in untouched.items():
                self.assertEqual((root / stage.package_path(package) / "mix.exs").read_bytes(), source)

    def test_invalid_version_and_ambiguous_field_reject_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            raw = root / "packages/abyss_raw/mix.exs"
            original = (root / "apps/abyss/mix.exs").read_bytes()
            with patch.object(server_packages, "ROOT", root):
                for version in ("01.0.0", "1.0", "1.0.0;echo injected", None):
                    with self.assertRaises(ValueError):
                        server_packages.prepare("abyss", version)
                raw.write_text(raw.read_text() + '\n@version "duplicate"\n')
                with self.assertRaises(ValueError):
                    server_packages.prepare("abyss", "0.10.1")
            self.assertEqual((root / "apps/abyss/mix.exs").read_bytes(), original)

    def test_divergent_abyss_group_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            raw = root / "packages/abyss_raw/mix.exs"
            raw.write_text(raw.read_text().replace(f'@version "{stage.source_version(raw.parent)}"', '@version "9.8.7"'))
            with patch.object(server_packages, "ROOT", root), self.assertRaises(ValueError):
                server_packages.inventory("all")

    def test_publication_cannot_select_all_groups_or_write_before_identity(self):
        with patch.object(server_packages.subprocess, "run") as command, \
                patch.object(server_packages, "release_status") as registry:
            with self.assertRaisesRegex(ValueError, "exactly one"):
                server_packages.publish("all", Path("/stage"), Path("/archives"), {"hell": "0.1.3"})
            command.assert_not_called()
            registry.assert_not_called()

    def test_core_inventory_remains_nine_and_native_package_is_outside_umbrella(self):
        self.assertEqual(len(stage.PACKAGES), 9)
        self.assertFalse(set(stage.PACKAGES) & {"abyss", "hell", "abyss_raw"})
        self.assertEqual(stage.package_path("abyss_raw"), Path("packages/abyss_raw"))
        self.assertEqual(len(stage.ALL_PACKAGES), 12)

    def test_wrong_requested_archive_version_stops_before_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            staged = stage.stage_sources(directory / "stage", ("abyss",))
            with patch.object(stage.subprocess, "run") as command:
                with self.assertRaisesRegex(ValueError, "differs from requested"):
                    stage.build(staged, "1.0.0", directory / "archives", ("abyss",))
                command.assert_not_called()

    def test_server_docs_links_resolve_each_package_directory_and_group_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            versions = server_packages.inventory("all")
            staged = stage.stage_sources(directory / "stage", tuple(versions))
            for package, version in versions.items():
                group = "abyss" if package.startswith("abyss") else "hell"
                target = directory / "docs" / package
                docs.prepare_docs_source(staged / package, target, version,
                                         source_ref=f"{group}-v{version}",
                                         source_path=str(stage.package_path(package)))
                text = (target / "mix.exs").read_text()
                pattern = f'http_fetch/blob/{group}-v{version}/{stage.package_path(package)}/%{{path}}#L%{{line}}'
                self.assertIn(pattern, text)
                self.assertIn(f'source_ref: "{group}-v{version}"', text)
                self.assertNotIn('source_ref: "main"', text)
                self.assertEqual(text.count("source_url_pattern:"), 1)
                result = subprocess.run(["elixir", "-e", 'Code.string_to_quoted!(File.read!("mix.exs"))'],
                                        cwd=target, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

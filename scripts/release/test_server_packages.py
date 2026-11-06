"""Unified versions preserve portable and asynchronous native release boundaries."""
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
        shutil.copyfile(ROOT / "mix.exs", root / "mix.exs")
        for package in ("abyss", "abyss_raw", "hell", "http_fetch"):
            source = ROOT / stage.package_path(package) / "mix.exs"
            target = root / stage.package_path(package) / "mix.exs"
            target.parent.mkdir(parents=True)
            shutil.copyfile(source, target)

    def test_independent_server_prepare_is_rejected_without_source_changes(self):
        # The workflow prepares the release version before running this suite.
        # Exercise both sides of that transition and a stable release fixture.
        for version in ("1.0.0-rc.3", "1.0.0-rc.4", "1.0.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.fixture(root)
                for path in root.rglob("mix.exs"):
                    original = stage.source_version(path.parent)
                    path.write_text(path.read_text().replace(original, version))
                before = {path: path.read_bytes() for path in root.rglob("mix.exs")}
                different_version = f"{int(version.split('.')[0]) + 1}.0.0"
                with patch.object(server_packages, "ROOT", root):
                    with self.assertRaisesRegex(ValueError, "versions.exs prepare"):
                        server_packages.prepare("abyss", different_version)
                    server_packages.prepare("all", version, validate=True)
                    with self.assertRaisesRegex(ValueError, "unified root version"):
                        server_packages.prepare("native", different_version, validate=True)
                self.assertEqual({path: path.read_bytes() for path in before}, before)

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
            with self.assertRaisesRegex(ValueError, "unified release"):
                server_packages.publish("all", Path("/stage"), Path("/archives"), {"hell": "0.1.3"})
            command.assert_not_called()
            registry.assert_not_called()

    def test_core_inventory_remains_nine_and_native_package_is_outside_umbrella(self):
        self.assertEqual(len(stage.PACKAGES), 9)
        self.assertFalse(set(stage.PACKAGES) & {"abyss", "hell", "abyss_raw"})
        self.assertEqual(stage.package_path("abyss_raw"), Path("packages/abyss_raw"))
        self.assertEqual(len(stage.ALL_PACKAGES), 12)
        self.assertEqual(stage.RELEASE_PACKAGES, (*stage.PACKAGES, "abyss", "hell"))
        self.assertEqual(stage.NATIVE_PACKAGES, ("abyss_raw",))

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
                target = directory / "docs" / package
                docs.prepare_docs_source(staged / package, target, version,
                                         source_ref=f"v{version}",
                                         source_path=str(stage.package_path(package)))
                text = (target / "mix.exs").read_text()
                pattern = f'http_fetch/blob/v{version}/{stage.package_path(package)}/%{{path}}#L%{{line}}'
                self.assertIn(pattern, text)
                self.assertIn(f'source_ref: "v{version}"', text)
                self.assertNotIn('source_ref: "main"', text)
                self.assertEqual(text.count("source_url_pattern:"), 1)
                result = subprocess.run(["elixir", "-e", 'Code.string_to_quoted!(File.read!("mix.exs"))'],
                                        cwd=target, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

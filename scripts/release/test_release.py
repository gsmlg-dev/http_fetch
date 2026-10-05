import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import archive_audit
import docs
import github_assets
import hex_packages
import stage


def source_version(root):
    return re.search(r'@version "([^"]+)"', (root / "mix.exs").read_text()).group(1)


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in ("mix.exs", "mix.lock", *(f"apps/{app}/mix.exs" for app in stage.PACKAGES)):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.fixture_version = "9.8.7"
        result = self.command("prepare", self.fixture_version)
        self.assertEqual(result.returncode, 0, result.stderr)

    def command(self, mode, version):
        return subprocess.run(["elixir", str(SCRIPT_DIR / "versions.exs"), mode, version],
                              cwd=self.root, capture_output=True, text=True)

    def test_prepare_and_validate_all_nine(self):
        result = self.command("prepare", "1.0.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        for app in stage.PACKAGES:
            text = (self.root / "apps" / app / "mix.exs").read_text()
            self.assertIn('1.0.0', text)
            self.assertNotIn(self.fixture_version, text)
        self.assertEqual(self.command("validate", "1.0.0").returncode, 0)
        self.assertNotEqual(self.command("validate", "1.0.1").returncode, 0)

    def test_missing_graph_edge_and_incompatible_lock_reject_before_writes(self):
        core = self.root / "apps/http_core/mix.exs"
        source, removed = re.subn(r'^\s*\{:elixir_quic, "[^"]+", in_umbrella: true, hex: :elixir_quic\},\n', '', core.read_text(), flags=re.MULTILINE)
        self.assertEqual(removed, 1)
        core.write_text(source)
        before = (self.root / "mix.exs").read_bytes()
        result = self.command("prepare", "1.0.0")
        self.assertIn("internal dependency graph mismatch", result.stderr)
        self.assertEqual((self.root / "mix.exs").read_bytes(), before)
        shutil.copyfile(ROOT / "apps/http_core/mix.exs", core)
        (self.root / "mix.lock").write_text(
            '%{"external": {:hex, :external, "1.0.0", "hash", [:mix], '
            '[{:http_core, "~> 0.16.0", [optional: true]}], "hexpm", "hash"}}\n')
        result = self.command("prepare", "1.0.0")
        self.assertIn("http_fetch/issues/16", result.stderr)
        self.assertEqual((self.root / "mix.exs").read_bytes(), before)

    def test_invalid_version_rejects_before_writes(self):
        before = (self.root / "mix.exs").read_bytes()
        self.assertNotEqual(self.command("prepare", "1..0").returncode, 0)
        self.assertEqual((self.root / "mix.exs").read_bytes(), before)


class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.version = source_version(ROOT)
        cls.stage = stage.stage_sources(cls.root / "stage")
        cls.archives = stage.build(cls.stage, cls.version, cls.root / "archives")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_portable_manifests_and_all_archive_metadata(self):
        for package in stage.PACKAGES:
            text = (self.stage / package / "mix.exs").read_text()
            self.assertNotIn("in_umbrella:", text)
            self.assertNotIn("build_path: \"../../", text)
            self.assertNotIn("lockfile: \"../../", text)
        result = subprocess.run(["elixir", str(SCRIPT_DIR / "archives.exs"), self.version, str(self.archives)],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for package in stage.PACKAGES:
            archive_audit.audit_package(package, self.version, self.stage, self.archives)

    def test_documentation_staging_adds_ex_doc_only_when_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            for package in stage.PACKAGES:
                target = Path(directory) / package
                docs.prepare_docs_source(self.stage / package, target, self.version)
                text = (target / "mix.exs").read_text()
                self.assertEqual(text.count("{:ex_doc,"), 1, package)
                pattern = f'https://github.com/gsmlg-dev/http_fetch/blob/v{self.version}/apps/{package}/%{{path}}#L%{{line}}'
                self.assertEqual(text.count(f'source_url_pattern: "{pattern}"'), 1, package)

    def test_rebuild_match_and_mismatch_rejection(self):
        stage.verify_rebuild(self.stage, self.version, self.archives)
        manifest = self.stage / "http_core/mix.exs"
        original = manifest.read_text()
        try:
            manifest.write_text(original + "\n# divergent staged source\n")
            with self.assertRaisesRegex(RuntimeError, "rebuild differs"):
                stage.verify_rebuild(self.stage, self.version, self.archives)
        finally:
            manifest.write_text(original)

    def test_omitted_or_corrupted_runtime_file_rejected(self):
        source = self.stage / "http_core/lib/http/headers.ex"
        original = source.read_bytes()
        try:
            source.write_bytes(b"corrupted")
            with self.assertRaisesRegex(RuntimeError, "differs from stage"):
                archive_audit.audit_package("http_core", self.version, self.stage, self.archives)
        finally:
            source.write_bytes(original)
        # Remove one file from the inner tar while retaining a syntactically valid outer tar.
        archive = self.archives / f"http_core-{self.version}.tar"
        outer_bytes = archive.read_bytes()
        try:
            with tarfile.open(fileobj=io.BytesIO(outer_bytes)) as outer:
                content = outer.extractfile("contents.tar.gz").read()
                outer_members = [(m, outer.extractfile(m).read()) for m in outer if m.isfile()]
            inner_output = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as inner, tarfile.open(fileobj=inner_output, mode="w:gz") as out:
                for member in inner:
                    if member.name != "lib/http/headers.ex":
                        out.addfile(member, inner.extractfile(member) if member.isfile() else None)
            rebuilt = io.BytesIO()
            with tarfile.open(fileobj=rebuilt, mode="w") as out:
                for member, data in outer_members:
                    if member.name == "contents.tar.gz":
                        data = inner_output.getvalue()
                    member.size = len(data)
                    out.addfile(member, io.BytesIO(data))
            archive.write_bytes(rebuilt.getvalue())
            with self.assertRaisesRegex(RuntimeError, "omitted runtime source"):
                archive_audit.audit_package("http_core", self.version, self.stage, self.archives)
        finally:
            archive.write_bytes(outer_bytes)


class RemotePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.archives = Path(self.temp.name)
        for package in stage.PACKAGES:
            (self.archives / f"{package}-1.0.0.tar").write_bytes(package.encode())

    def test_hex_mismatch_blocks_all_publication(self):
        with patch.object(hex_packages, "release_status", side_effect=RuntimeError("checksum mismatch")), patch.object(
            hex_packages.subprocess, "run") as publish:
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                hex_packages.run("publish", "1.0.0", self.archives, self.archives)
        publish.assert_not_called()

    def test_hex_retry_order_and_rebuild_guard(self):
        calls = []
        def status(package, *_args):
            calls.append(package)
            return "matching" if package == "ex_ssl" else "missing" if len(calls) <= len(stage.PACKAGES) else "matching"
        with patch.object(hex_packages, "release_status", side_effect=status), patch.object(
            hex_packages, "verify_rebuild") as rebuild, patch.object(hex_packages.subprocess, "run") as publish, patch.dict(
            "os.environ", {"HEX_API_KEY": "test"}):
            hex_packages.run("publish", "1.0.0", self.archives, self.archives)
        self.assertEqual(rebuild.call_count, len(stage.PACKAGES))
        commands = publish.call_args_list
        self.assertEqual([call.args[0] for call in commands],
                         [["mix", "deps.get", "--only", "prod"],
                          ["mix", "hex.publish", "package", "--yes"]] * (len(stage.PACKAGES) - 1))
        self.assertEqual([str(call.kwargs["cwd"]) for call in commands],
                         [str(self.archives / package) for package in stage.PACKAGES[1:] for _ in range(2)])
        self.assertTrue(all(call.kwargs["env"]["MIX_ENV"] == "prod" for call in commands))
        self.assertEqual(calls[:len(stage.PACKAGES)], list(stage.PACKAGES))

    def test_dependency_failure_blocks_package_publication(self):
        with patch.object(hex_packages, "release_status", return_value="missing"), patch.object(
            hex_packages, "verify_rebuild"), patch.object(hex_packages.subprocess, "run",
            side_effect=subprocess.CalledProcessError(1, "mix deps.get")) as commands, patch.dict(
            "os.environ", {"HEX_API_KEY": "test"}):
            with self.assertRaises(subprocess.CalledProcessError):
                hex_packages.run("publish", "1.0.0", self.archives, self.archives)
        self.assertEqual(commands.call_count, 1)
        self.assertEqual(commands.call_args.args[0], ["mix", "deps.get", "--only", "prod"])

    def test_dependency_preparation_cannot_mutate_published_archive(self):
        events = []
        def rebuild(*_args, **kwargs):
            events.append("verify")
            if kwargs.get("packages"):
                raise RuntimeError("staged package rebuild differs")
        with patch.object(hex_packages, "release_status", return_value="missing"), patch.object(
            hex_packages, "verify_rebuild", side_effect=rebuild), patch.object(
            hex_packages.subprocess, "run", side_effect=lambda *_args, **_kwargs: events.append("deps")), patch.dict(
            "os.environ", {"HEX_API_KEY": "test"}):
            with self.assertRaisesRegex(RuntimeError, "rebuild differs"):
                hex_packages.run("publish", "1.0.0", self.archives, self.archives)
        self.assertEqual(events, ["verify", "deps", "verify"])

    def test_github_post_write_requires_all_matching_assets(self):
        with patch.object(github_assets, "existing_release", side_effect=[None, {"assets": []}]), patch.object(
            github_assets.subprocess, "run") as commands, patch.dict("os.environ", {"GITHUB_REPOSITORY": "example/repo"}):
            with self.assertRaisesRegex(RuntimeError, "asset missing after completion"):
                github_assets.run("complete", "1.0.0", self.archives)
        self.assertEqual(commands.call_count, 1)

    def test_invalid_semver_rejected(self):
        with self.assertRaises(ValueError):
            hex_packages.run("preflight", "1..0", self.archives)
        with self.assertRaises(ValueError):
            github_assets.run("preflight", "1..0", self.archives)


if __name__ == "__main__":
    unittest.main()

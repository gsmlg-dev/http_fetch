"""RC publication keeps coordinated identities and all existing release gates."""

from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch

import consumer_gate
import docs
import github_assets
import hex_packages
import no_otp_consumer_gate
import stage


ROOT = Path(__file__).resolve().parents[2]
VERSION = "1.0.0-rc.1"


class ReleaseCandidateTests(unittest.TestCase):
    def test_prepare_and_validate_keep_all_nine_exact_rc_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ["mix.exs", "mix.lock", *(f"apps/{app}/mix.exs" for app in stage.PACKAGES)]
            for name in paths:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            lock = (root / "mix.lock").read_bytes()
            for mode in ("prepare", "validate"):
                result = subprocess.run(
                    ["elixir", str(ROOT / "scripts/release/versions.exs"), mode, VERSION],
                    cwd=root, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
            for name in paths:
                if name == "mix.lock":
                    continue
                source = (root / name).read_text()
                self.assertRegex(source, rf'(?:@version|version:) "{re.escape(VERSION)}"')
                requirements = re.findall(
                    r'\{:[a-z0-9_]+, "([^"]+)", in_umbrella: true, hex:', source)
                self.assertTrue(all(value == "== " + VERSION for value in requirements))
            self.assertEqual((root / "mix.lock").read_bytes(), lock)

    def test_stage_cli_accepts_rc_before_building_exact_archive_names(self):
        with patch.object(sys, "argv", ["stage.py", "build", VERSION, "/stage", "/archives"]), \
                patch.object(stage, "stage_sources", return_value=Path("/stage")), \
                patch.object(stage, "build") as build:
            stage.main()
        build.assert_called_once_with(Path("/stage"), VERSION, Path("/archives"), stage.PACKAGES)

    def test_no_otp_rc_keeps_exact_hex_dependencies_and_required_plan(self):
        source = no_otp_consumer_gate.project_source(VERSION)
        for package in stage.PACKAGES:
            self.assertIn('{:' + package + ', "== ' + VERSION + '"}', source)
        self.assertNotIn(":ssl", source)
        with patch.object(no_otp_consumer_gate, "Runner") as runner:
            with self.assertRaisesRegex(no_otp_consumer_gate.GateError, "peer plan schema 1 required"):
                no_otp_consumer_gate.run(VERSION, Path("/archives"), Path("/stage"),
                                         Path("/source"), "a" * 40, {}, Path("/fresh"))
        runner.assert_not_called()

    def test_rc_hex_preflight_checks_every_matching_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            archives = Path(directory)
            for package in stage.PACKAGES:
                (archives / f"{package}-{VERSION}.tar").write_bytes(package.encode())
            with patch.object(hex_packages, "release_status", return_value="matching") as status, \
                    patch.object(hex_packages.subprocess, "run") as publication, \
                    redirect_stdout(io.StringIO()):
                hex_packages.run("preflight", VERSION, archives)
            self.assertEqual(status.call_args_list, [
                call(package, VERSION, archives / f"{package}-{VERSION}.tar")
                for package in stage.PACKAGES])
            publication.assert_not_called()

    def test_rc_published_consumer_retains_checksum_and_cold_registry_boundary(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            archives = Path(directory).resolve()
            status = stack.enter_context(patch("hex_packages.release_status", return_value="matching"))
            registry = stack.enter_context(patch.object(consumer_gate, "setup_registry"))
            server = stack.enter_context(patch.object(consumer_gate, "local_registry"))
            project = stack.enter_context(patch.object(consumer_gate, "external_project"))
            consumer_gate.run(VERSION, archives, mode="external", published=True)
            self.assertEqual(status.call_args_list, [
                call(package, VERSION, archives / f"{package}-{VERSION}.tar")
                for package in stage.PACKAGES])
            self.assertEqual(project.call_args.args[1], VERSION)
            self.assertEqual(project.call_args.args[2]["HTTP_FETCH_CONSUMER_SOURCE"], "published")
            registry.assert_not_called()
            server.assert_not_called()

    def test_docs_keep_rc_source_tag_without_publishing_by_default(self):
        with patch.object(docs, "prepare_docs_source") as prepare, \
                patch.object(docs.subprocess, "run") as commands, redirect_stdout(io.StringIO()):
            docs.run(VERSION, Path("/stage"))
        self.assertEqual(prepare.call_count, len(stage.PACKAGES))
        self.assertTrue(all(item.args[2] == VERSION for item in prepare.call_args_list))
        self.assertEqual([item.args[0] for item in commands.call_args_list],
                         [["mix", "deps.get"], ["mix", "docs"]] * len(stage.PACKAGES))

    def test_workflow_accepts_rc_and_rejects_noncanonical_or_injected_versions(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        [validation] = re.findall(r'^\s*(\[\[ "\$RELEASE_VERSION" =~ .* \]\])$', workflow, re.M)
        for version in ("0.0.0", "1.0.0", VERSION, "1.0.0-rc.12"):
            with self.subTest(version=version):
                result = subprocess.run(["bash", "-c", validation],
                                        env={**os.environ, "RELEASE_VERSION": version}, timeout=5)
                self.assertEqual(result.returncode, 0)
        for version in ("1.0.0-rc", "1.0.0-rc.01", "01.0.0-rc.1", "1.0.0-beta.1",
                        "1.0.0-rc.1+build", "1.0.0-rc.1;false", "1.0.0-rc.1\n"):
            with self.subTest(version=version):
                result = subprocess.run(["bash", "-c", validation],
                                        env={**os.environ, "RELEASE_VERSION": version}, timeout=5)
                self.assertNotEqual(result.returncode, 0)

    def test_post_release_canary_accepts_rc_without_starting_background_work(self):
        path = ROOT / "scripts/http3/post_release_canary.py"
        spec = importlib.util.spec_from_file_location("rc_canary_fixture", path)
        canary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(canary)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(sys, "argv", [str(path), VERSION, "a" * 40,
                                           str(Path(directory) / "canary"), "--issue", "1"]), \
                patch.object(canary, "verify_canary_source") as verify, \
                patch.object(canary, "worker", return_value=0) as worker:
            self.assertEqual(canary.main(), 0)
        verify.assert_called_once_with(VERSION, "a" * 40)
        worker.assert_called_once()


class ReleaseCandidateGitHubTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.archives = Path(directory.name)
        for package in stage.PACKAGES:
            (self.archives / f"{package}-{VERSION}.tar").write_bytes(package.encode())
        self.release = {"prerelease": True, "assets": [
            {"name": f"{package}-{VERSION}.tar"} for package in stage.PACKAGES]}
        environment = patch.dict(os.environ, {"GITHUB_REPOSITORY": "example/repo"})
        environment.start()
        self.addCleanup(environment.stop)

    def download(self, argv, **_kwargs):
        if argv[:3] == ["gh", "release", "download"]:
            name = argv[argv.index("--pattern") + 1]
            target = Path(argv[argv.index("--dir") + 1]) / name
            target.write_bytes((self.archives / name).read_bytes())

    def test_create_rc_is_prerelease_without_replacing_latest(self):
        with patch.object(github_assets, "existing_release", side_effect=[None, self.release]), \
                patch.object(github_assets.subprocess, "run", side_effect=self.download) as commands:
            github_assets.run("complete", VERSION, self.archives)
        create = commands.call_args_list[0].args[0]
        self.assertEqual(create[:4], ["gh", "release", "create", "v" + VERSION])
        self.assertIn("--prerelease", create)
        self.assertIn("--latest=false", create)
        self.assertEqual(commands.call_count, 1 + len(stage.PACKAGES))

    def test_existing_stable_marked_rc_blocks_before_any_remote_write(self):
        wrong = {**self.release, "prerelease": False}
        with patch.object(github_assets, "existing_release", return_value=wrong), \
                patch.object(github_assets.subprocess, "run") as commands:
            for mode in ("preflight", "complete"):
                with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, "prerelease"):
                    github_assets.run(mode, VERSION, self.archives)
        commands.assert_not_called()

    def test_created_rc_must_read_back_as_prerelease(self):
        wrong = {**self.release, "prerelease": False}
        with patch.object(github_assets, "existing_release", side_effect=[None, wrong]), \
                patch.object(github_assets.subprocess, "run") as commands:
            with self.assertRaisesRegex(RuntimeError, "prerelease"):
                github_assets.run("complete", VERSION, self.archives)
        self.assertEqual(commands.call_count, 1)


if __name__ == "__main__":
    unittest.main()

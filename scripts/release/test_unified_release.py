"""Unified versions and optional native publication retain independent jobs."""

from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import github_assets
import hex_packages
import native_consumer_gate
import server_consumer_gate
import server_packages
import stage


VERSION = "1.0.0-rc.4"


class UnifiedReleaseTests(unittest.TestCase):
    def test_portable_and_no_otp_proof_boundaries_are_distinct(self):
        self.assertEqual(len(stage.PACKAGES), 10)
        self.assertEqual(stage.RELEASE_PACKAGES, (*stage.PACKAGES, "http_test", "abyss", "hell"))
        self.assertEqual(stage.ALL_PACKAGES, (*stage.RELEASE_PACKAGES, "abyss_raw"))
        self.assertEqual(stage.GROUPS["native"], ("abyss_raw",))
        self.assertEqual(hex_packages.PACKAGES, stage.RELEASE_PACKAGES)
        for group in (stage.PACKAGES, stage.NATIVE_PACKAGES):
            with self.assertRaisesRegex(ValueError, "portable packages publish as one group"):
                hex_packages.run("publish", VERSION, Path("/absent"), packages=group)

    def test_native_github_assets_require_completed_portable_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            archives = Path(temporary)
            (archives / f"abyss_raw-{VERSION}.tar").write_bytes(b"native candidate")
            with patch.object(github_assets, "existing_release", return_value=None), \
                    patch.object(github_assets.subprocess, "run") as remote, \
                    patch.dict(os.environ, {"GITHUB_REPOSITORY": "example/repo"}):
                for mode in ("preflight", "complete"):
                    with self.assertRaisesRegex(RuntimeError, "portable GitHub release must exist"):
                        github_assets.run(mode, VERSION, archives, packages=stage.NATIVE_PACKAGES)
                remote.assert_not_called()

    def test_native_publication_cannot_write_before_matching_abyss(self):
        with tempfile.TemporaryDirectory() as temporary:
            archives = Path(temporary)
            (archives / f"abyss-{VERSION}.tar").write_bytes(b"abyss candidate")
            with patch.object(server_packages, "publication_identity"), \
                    patch.object(server_packages, "source_version", return_value=VERSION), \
                    patch.object(server_packages, "release_status", return_value="missing") as status, \
                    patch.object(server_packages, "verify_rebuild") as rebuild, \
                    patch.object(server_packages.subprocess, "run") as remote:
                with self.assertRaisesRegex(ValueError, "verified published Abyss required"):
                    server_packages.publish("native", Path("/stage"), archives, {"abyss_raw": VERSION})
                status.assert_called_once_with("abyss", VERSION, archives / f"abyss-{VERSION}.tar")
                rebuild.assert_not_called()
                remote.assert_not_called()

    def test_native_retry_uses_shared_tag_and_checks_every_rebuild(self):
        with tempfile.TemporaryDirectory() as temporary:
            archives = Path(temporary)
            (archives / f"abyss-{VERSION}.tar").write_bytes(b"abyss candidate")
            with patch.object(server_packages, "publication_identity") as identity, \
                    patch.object(server_packages, "source_version", return_value=VERSION), \
                    patch.object(server_packages, "release_status", side_effect=["matching", "missing", "matching"]) as status, \
                    patch.object(server_packages, "stage_sources", return_value=Path("/tagged")), \
                    patch.object(server_packages, "verify_rebuild") as rebuild, \
                    patch.object(server_packages.subprocess, "run") as remote:
                server_packages.publish("native", Path("/stage"), archives, {"abyss_raw": VERSION})
                identity.assert_called_once_with("native", {"abyss_raw": VERSION})
                self.assertEqual([call.args[0] for call in status.call_args_list], ["abyss", "abyss_raw", "abyss_raw"])
                self.assertEqual(rebuild.call_count, 3)
                self.assertEqual([call.args[0] for call in remote.call_args_list], [
                    ["mix", "deps.get", "--only", "prod"], ["mix", "hex.publish", "package", "--yes"]])
                self.assertTrue(all(call.kwargs["env"]["MIX_ENV"] == "prod"
                                    for call in remote.call_args_list))
                self.assertEqual(rebuild.call_args.kwargs["env"]["MIX_ENV"], "prod")

    def test_native_identity_uses_exact_unified_tag_and_clean_checkout(self):
        with patch.object(server_packages.subprocess, "check_output", side_effect=["a" * 40, "a" * 40, ""]) as git, \
                patch.dict(os.environ, {"HEX_API_KEY": "test"}):
            server_packages.publication_identity("native", {"abyss_raw": VERSION})
            self.assertEqual(git.call_args_list[1].args[0],
                             ["git", "rev-parse", f"refs/tags/v{VERSION}^{{commit}}"])
        with patch.object(server_packages.subprocess, "check_output", side_effect=["a" * 40, "b" * 40]), \
                self.assertRaisesRegex(ValueError, "immutable v"):
            server_packages.publication_identity("native", {"abyss_raw": VERSION})

    def test_published_server_consumers_use_matching_archives_without_local_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            archives = Path(temporary)
            for package in ("abyss", "hell"):
                (archives / f"{package}-{VERSION}.tar").write_bytes(package.encode())
            versions = {"abyss": VERSION, "hell": VERSION, "elixir_quic": VERSION, "ex_ssl": VERSION}
            for package in ("elixir_quic", "ex_ssl"):
                (archives / f"{package}-{VERSION}.tar").write_bytes(package.encode())
            with patch.object(server_consumer_gate, "source_versions", return_value=versions), \
                    patch.object(server_consumer_gate, "prepare_mix_toolchain"), \
                    patch.object(server_consumer_gate, "release_status", return_value="matching") as status, \
                    patch.object(server_consumer_gate, "setup_registry") as registry, \
                    patch.object(server_consumer_gate, "local_registry") as local, \
                    patch.object(server_consumer_gate, "verify_project") as project, \
                    redirect_stdout(io.StringIO()):
                server_consumer_gate.run(archives, published=True)
                self.assertEqual([call.args[0] for call in status.call_args_list],
                                 ["abyss", "hell", "elixir_quic", "ex_ssl"])
                self.assertEqual([call.args[1] for call in project.call_args_list], ["abyss", "hell", "quic"])
                environment = project.call_args.args[3]
                self.assertNotIn("HEX_MIRROR", environment)
                self.assertIn("hex-cache", environment["HEX_CACHE_HOME"])
                registry.assert_not_called()
                local.assert_not_called()

    def test_native_published_consumer_fails_before_build_on_missing_archive(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(native_consumer_gate, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "matching abyss"):
                native_consumer_gate.run(VERSION, Path(temporary))
            command.assert_not_called()

    def test_native_published_consumer_uses_cold_hex_and_exact_shared_versions(self):
        commands = []

        def command(arguments, *, cwd, env):
            commands.append(arguments)
            self.assertEqual(env["MIX_ENV"], "prod")
            self.assertEqual(env["ABYSS_EXPECTED_VERSION"], VERSION)
            self.assertEqual(env["ABYSS_RAW_EXPECTED_VERSION"], VERSION)
            self.assertNotIn("MIX_BUILD_PATH", env)
            self.assertNotIn("HEX_MIRROR", env)
            self.assertNotIn("CARGO_TARGET_DIR", env)
            self.assertIn("hex-cache", env["HEX_CACHE_HOME"])
            manifest = (cwd / "mix.exs").read_text()
            self.assertIn(f'{{:abyss, "== {VERSION}"}}', manifest)
            self.assertIn(f'{{:abyss_raw, "== {VERSION}"}}', manifest)
            self.assertNotIn("path:", manifest)
            self.assertNotIn("in_umbrella:", manifest)
            provenance = (cwd / "provenance.exs").read_text()
            self.assertIn("Hex.SCM", provenance)
            self.assertIn('Path.join(__DIR__, "_build")', provenance)

        with tempfile.TemporaryDirectory() as temporary:
            archives = Path(temporary)
            for package in ("abyss", "abyss_raw"):
                (archives / f"{package}-{VERSION}.tar").write_bytes(package.encode())
            with patch.object(native_consumer_gate, "release_status", return_value="matching") as status, \
                    patch.object(native_consumer_gate, "prepare_mix_toolchain"), \
                    patch.object(native_consumer_gate, "command", side_effect=command), \
                    patch.dict(os.environ, {"HEX_MIRROR": "invalid", "MIX_BUILD_PATH": "/shared",
                                           "CARGO_TARGET_DIR": "/shared"}), \
                    redirect_stdout(io.StringIO()):
                native_consumer_gate.run(VERSION, archives)
                self.assertEqual([call.args[0] for call in status.call_args_list], ["abyss", "abyss_raw"])
        self.assertEqual(commands[:3], [["mix", "deps.get"], ["mix", "compile", "--warnings-as-errors"],
                                        ["mix", "run", "provenance.exs"]])
        self.assertEqual(commands[3], ["mix", "run", str(stage.ROOT / "apps/abyss/scripts/release/native_smoke.exs")])

    def test_native_published_consumer_rejects_noncanonical_versions(self):
        with patch.object(native_consumer_gate, "release_status") as status:
            for version in ("1.0.0-rc.04", "1.0.0;echo injected", "1.0.0-beta.1"):
                with self.subTest(version=version), self.assertRaisesRegex(ValueError, "canonical"):
                    native_consumer_gate.run(version, Path("/absent"))
            status.assert_not_called()

    def test_workflow_never_waits_for_native_in_portable_release(self):
        workflow = (stage.ROOT / ".github/workflows/release.yml").read_text()
        portable, native = workflow.split("\n  native-release:\n", 1)
        self.assertIn("needs: release", native)
        self.assertNotIn("\nconcurrency:\n", workflow)
        self.assertIn("group: release-portable-http-fetch-packages", portable)
        self.assertIn("group: release-abyss-raw-${{ inputs.version }}", native)
        self.assertNotIn("needs: native-release", portable)
        self.assertNotIn("rust-toolchain", portable)
        self.assertIn("packages/abyss_raw/mix.exs", portable)
        self.assertIn("Publish and verify packages in dependency order", portable)
        artifact_step = portable.split("Preserve verified portable archives", 1)[1].split("\n      - name:", 1)[0]
        self.assertIn("overwrite: true", artifact_step)
        self.assertIn("needs.release.outputs.source_sha", native)
        self.assertIn("refs/tags/v$RELEASE_VERSION^{commit}", native)
        for requirement in ("publish native", "--group native", "GITHUB_STEP_SUMMARY"):
            self.assertIn(requirement, native)
        self.assertNotIn("continue-on-error", native)

    def test_publication_workflows_do_not_run_validation_suites(self):
        for filename in ("release.yml", "release-complete.yml"):
            workflow = (stage.ROOT / ".github/workflows" / filename).read_text()
            with self.subTest(workflow=filename):
                for forbidden in ("mix test", "mix format", "mix credo", "mix dialyzer",
                                  "--warnings-as-errors", "MIX_ENV=test", "unittest",
                                  "consumer_gate.py", "p5_consumers.py", "cargo clippy",
                                  "test_arp.sh", "scripts/interop/", "scripts/migration/gate",
                                  "scripts/http3/", "ex_ssl_source_smoke", "docker",
                                  "setup-go", "setup-uv", "defer_static_analysis"):
                    self.assertNotIn(forbidden, workflow)

    def test_dependencies_and_compilation_are_required_before_packaging(self):
        workflow = (stage.ROOT / ".github/workflows/release.yml").read_text()
        portable, native = workflow.split("\n  native-release:\n", 1)
        for job, build in ((portable, "Build thirteen portable archives"),
                           (native, "Build and audit the native archive")):
            steps = re.split(r"(?m)^      - ", job)[1:]
            deps = next(step for step in steps if "run: mix deps.get\n" in step)
            compile_step = next(step for step in steps if "run: mix compile\n" in step)
            for step in (deps, compile_step):
                self.assertNotIn("if:", step)
                self.assertNotIn("continue-on-error", step)
            self.assertLess(job.index(deps), job.index(compile_step))
            self.assertLess(job.index(compile_step), job.index(build))


if __name__ == "__main__":
    unittest.main()

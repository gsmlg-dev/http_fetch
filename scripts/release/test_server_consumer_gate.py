"""Server candidate gates must preserve independent versions and Hex isolation."""

import hashlib
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

import server_consumer_gate as gate


class ServerConsumerGateTests(unittest.TestCase):
    def test_independent_source_versions_are_not_coordinated_client_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for package, manifest in {
                "abyss": '@version "0.10.7"',
                "hell": 'version: "0.1.8"',
            }.items():
                target = root / "apps" / package
                target.mkdir(parents=True)
                (target / "mix.exs").write_text(manifest)
            with patch.object(gate, "ROOT", root):
                self.assertEqual(gate.source_versions(), {"abyss": "0.10.7", "hell": "0.1.8"})

    def test_metrics_cache_must_match_locked_outer_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cache = directory / "cache/packages/hexpm"
            cache.mkdir(parents=True)
            name = "telemetry_metrics-1.2.0.tar"
            (cache / name).write_bytes(b"modified archive")
            output = directory / "tarballs"
            output.mkdir()
            with patch.dict(os.environ, {"HEX_CACHE_HOME": str(directory / "cache")}), \
                    patch.object(gate, "locked_package", return_value=("1.2.0", "0" * 64)), \
                    patch.object(gate, "urlopen", side_effect=AssertionError("unexpected fetch")):
                with self.assertRaisesRegex(RuntimeError, "locked outer checksum"):
                    gate.metrics_archive(output)
            self.assertEqual(list(output.iterdir()), [])

    def test_verified_metrics_cache_is_copied_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cache = directory / "cache/packages/hexpm"
            cache.mkdir(parents=True)
            data = b"verified archive"
            name = "telemetry_metrics-1.2.0.tar"
            (cache / name).write_bytes(data)
            output = directory / "tarballs"
            output.mkdir()
            with patch.dict(os.environ, {"HEX_CACHE_HOME": str(directory / "cache")}), \
                    patch.object(gate, "locked_package", return_value=("1.2.0", hashlib.sha256(data).hexdigest())), \
                    patch.object(gate, "urlopen", side_effect=AssertionError("unexpected fetch")):
                gate.metrics_archive(output)
            self.assertEqual((output / name).read_bytes(), data)

    def test_consumer_environment_discards_inherited_workspace_and_registry(self):
        inherited = {"MIX_BUILD_PATH": "/umbrella/build", "MIX_DEPS_PATH": "/umbrella/deps",
                     "MIX_HOME": "/umbrella/mix", "ERL_LIBS": "/umbrella/lib",
                     "ERL_FLAGS": "-pa /umbrella/ebin", "ERL_AFLAGS": "-pa /umbrella/ebin",
                     "ERL_ZFLAGS": "-pa /umbrella/ebin",
                     "HEX_UNSAFE_REGISTRY": "1", "HEX_MIRROR": "https://wrong.example",
                     "HEX_CACHE_HOME": "/shared/cache", "HTTP_FETCH_CI_APP": "ex_ssl"}
        with patch.dict(os.environ, inherited):
            env = gate.isolated_environment(Path("/isolated"))
        for key in inherited:
            if key == "HEX_CACHE_HOME":
                self.assertEqual(env[key], "/isolated/hex-cache")
            else:
                self.assertNotIn(key, env)
        self.assertEqual(env["HEX_HOME"], "/isolated/hex")
        self.assertEqual(env["HEX_CONFIG_HOME"], "/isolated/hex-config")
        self.assertEqual(env["MIX_ENV"], "prod")

    def test_mix_toolchain_copies_hex_without_unrelated_archives_or_plts(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source-mix"
            hex_archive = source / "archives/hex-2.4.0"
            hex_archive.mkdir(parents=True)
            (hex_archive / "hex.beam").write_bytes(b"hex toolchain")
            unrelated = source / "archives/other-1.0.0"
            unrelated.mkdir()
            (source / "old.plt").write_bytes(b"not build tooling")
            destination = directory / "isolated"
            env = {}
            with patch.dict(os.environ, {"MIX_HOME": str(source), "MIX_ARCHIVES": str(source / "archives")}):
                gate.prepare_mix_toolchain(destination, env)
            self.assertEqual((destination / "mix/archives/hex-2.4.0/hex.beam").read_bytes(), b"hex toolchain")
            self.assertFalse((destination / "mix/archives/other-1.0.0").exists())
            self.assertFalse((destination / "mix/old.plt").exists())
            self.assertEqual(env["MIX_HOME"], str(destination / "mix"))

    def test_isolated_toolchain_preserves_legacy_and_versioned_rebar_executables(self):
        for relative in ("rebar3", "elixir/1-18-otp-28/rebar3"):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source = directory / "source-mix"
                (source / "archives/hex-2.4.0").mkdir(parents=True)
                executable = source / relative
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_bytes(b"rebar build tooling")
                executable.chmod(0o755)
                destination = directory / "isolated"
                env = {}
                with patch.dict(os.environ, {"MIX_HOME": str(source),
                                             "MIX_ARCHIVES": str(source / "archives")}):
                    gate.prepare_mix_toolchain(destination, env)
                copied = destination / "mix" / relative
                self.assertEqual(copied.read_bytes(), executable.read_bytes())
                self.assertTrue(os.access(copied, os.X_OK))

    def test_hell_only_registry_does_not_require_abyss_or_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archives = directory / "archives"
            archives.mkdir()
            candidate = archives / "hell-0.1.3.tar"
            candidate.write_bytes(b"candidate")
            with patch.object(gate, "telemetry_archive") as telemetry, \
                    patch.object(gate, "metrics_archive", side_effect=AssertionError("unrelated metrics")), \
                    patch.object(gate, "command") as command:
                public = gate.setup_registry(archives, ("hell",), {"hell": "0.1.3"}, directory, {})
            self.assertEqual((public / "tarballs" / candidate.name).read_bytes(), b"candidate")
            telemetry.assert_called_once_with(public / "tarballs")
            self.assertIn("--name=hexpm", command.call_args_list[-1].args[0])

    def test_hell_consumer_closure_includes_its_ex_ssl_transport(self):
        versions = {"hell": "1.0.0-rc.6", "ex_ssl": "1.0.0-rc.6"}
        with patch.object(gate, "locked_package", return_value=("1.2.3", "0" * 64)):
            source = gate.provenance("hell", versions)
        self.assertIn('hell: "1.0.0-rc.6", telemetry: "1.2.3", ex_ssl: "1.0.0-rc.6"', source)
        self.assertIn("[Hell, Hell.Transports.SSL, SSL]", source)
        self.assertIn("[Abyss, HTTP, Quic, Rustler, AbyssDhcpSocket.Native]", source)
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(gate, "source_versions", return_value=versions) as source_versions, \
                patch.object(gate, "prepare_mix_toolchain"), \
                patch.object(gate, "setup_registry", return_value=Path(temporary)) as registry, \
                patch.object(gate, "local_registry"), \
                patch.object(gate, "command"), \
                patch.object(gate, "verify_project"), \
                patch.object(gate.tempfile, "mkdtemp", return_value=temporary):
            gate.run(temporary, "hell", keep=True)
        source_versions.assert_called_once_with(("hell", "ex_ssl"))
        self.assertEqual(registry.call_args.args[1], ("hell", "ex_ssl"))

    def test_registry_fails_closed_for_missing_requested_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(gate, "command") as command:
                with self.assertRaisesRegex(RuntimeError, "missing candidate archive"):
                    gate.setup_registry(directory, ("abyss",), {"abyss": "0.10.0"}, directory, {})
            command.assert_not_called()

    def test_consumer_manifests_use_exact_hex_versions_without_path_override(self):
        for package, version in gate.source_versions().items():
            source = gate.manifest(package, version)
            self.assertIn(f'{{:{package}, "== {version}"}}', source)
            for forbidden in ("path:", "override:", "in_umbrella:"):
                self.assertNotIn(forbidden, source)

    def test_quic_manifest_explicitly_selects_current_engines_with_independent_abyss(self):
        versions = {"abyss": "0.10.0", "elixir_quic": "1.0.0-rc.3", "ex_ssl": "1.0.0-rc.3"}
        source = gate.manifest("quic", versions["abyss"], versions)
        for package, version in versions.items():
            self.assertIn(f'{{:{package}, "== {version}"}}', source)
        self.assertIn("AbyssEchoExample.Application", source)
        for forbidden in ("path:", "override:", "in_umbrella:", "abyss_raw", "Rustler"):
            self.assertNotIn(forbidden, source)

    def test_exact_quic_consumer_runs_both_migration_modes_after_hex_provenance(self):
        versions = {name: "1.0.0-rc.6" for name in ("abyss", "elixir_quic", "ex_ssl")}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source"
            example = source / "apps/abyss/examples/quic_echo/lib"
            example.mkdir(parents=True)
            (example / "application.ex").write_text("# consumer application harness")
            with patch.object(gate, "ROOT", source), \
                    patch.object(gate, "locked_package", return_value=("1.2.3", "0" * 64)), \
                    patch.object(gate, "command") as command:
                gate.verify_project(directory, "quic", versions, {"MIX_ENV": "prod"})
            commands = [call.args[0] for call in command.call_args_list]
            project = directory / "quic"
            provenance = commands.index(["mix", "run", "provenance.exs"])
            migrations = [(index, call) for index, call in enumerate(command.call_args_list)
                          if len(call.args[0]) > 1 and call.args[0][1] == str(source / "scripts/migration/gate.py")]
            self.assertEqual(len(migrations), 2)
            for (index, call), mode in zip(migrations, ("standalone", "abyss")):
                self.assertGreater(index, provenance)
                self.assertEqual(call.args[0], [sys.executable, str(source / "scripts/migration/gate.py"),
                                               "--project", str(project), "--mode", mode, "--timeout", "30"])
                self.assertEqual(call.kwargs["cwd"], project)
            manifest = (project / "mix.exs").read_text()
            for name, version in versions.items():
                self.assertIn(f'{{:{name}, "== {version}"}}', manifest)
            for forbidden in ("path:", "in_umbrella:", "override:"):
                self.assertNotIn(forbidden, manifest)


if __name__ == "__main__":
    unittest.main()

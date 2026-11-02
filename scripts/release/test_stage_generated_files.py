"""Local integration artifacts must not become candidate package inputs."""

import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import stage


class StageGeneratedFilesTests(unittest.TestCase):
    def test_stage_ignores_application_test_tmp_without_dropping_source_or_fixtures(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            root = directory / "repository"
            source = root / "apps/ex_ssl"
            (source / "tmp").mkdir(parents=True)
            os.mkfifo(source / "tmp/policy.fifo")
            (source / "lib/tmp").mkdir(parents=True)
            (source / "lib/tmp/source.ex").write_text("defmodule Kept, do: nil\n")
            (source / "test/support").mkdir(parents=True)
            (source / "test/support/fixture.pem").write_text("test input\n")
            (source / "mix.exs").write_text('def project, do: [app: :ex_ssl]\n')

            with patch.object(stage, "ROOT", root), patch.object(stage, "PACKAGES", ("ex_ssl",)):
                staged = stage.stage_sources(directory / "stage") / "ex_ssl"

            self.assertFalse((staged / "tmp").exists())
            self.assertEqual((staged / "lib/tmp/source.ex").read_bytes(),
                             (source / "lib/tmp/source.ex").read_bytes())
            self.assertEqual((staged / "test/support/fixture.pem").read_bytes(),
                             (source / "test/support/fixture.pem").read_bytes())
            self.assertTrue((source / "tmp/policy.fifo").exists())

    def test_abyss_staging_ignores_test_fifo_and_keeps_nested_tmp_source(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location(
            "abyss_concurrent", root / "scripts/interop/abyss_concurrent.py")
        abyss = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(abyss)

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            repository = directory / "repository"
            stage_script = repository / "scripts/release/stage.py"
            stage_script.parent.mkdir(parents=True)
            shutil.copyfile(stage.__file__, stage_script)
            for package in ("ex_ssl", "elixir_quic"):
                source = repository / "apps" / package
                (source / "tmp").mkdir(parents=True)
                os.mkfifo(source / "tmp/policy.fifo")
                (source / "lib/tmp").mkdir(parents=True)
                (source / "lib/tmp/source.ex").write_text("defmodule Kept, do: nil\n")
                (source / "test/support").mkdir(parents=True)
                (source / "test/support/fixture.pem").write_text("test input\n")
                (source / "mix.exs").write_text(f'def project, do: [app: :{package}]\n')

            upstream = directory / "upstream"
            (upstream / "examples/quic_echo/lib").mkdir(parents=True)
            (upstream / "examples/quic_echo/lib/echo.ex").write_text("fixture\n")
            (upstream / "examples/quic_echo/mix.exs").write_text(
                'def deps, do: [{:elixir_quic, "== 0.17.0"}]\n')
            digest = hashlib.sha256()
            for path in sorted(path for path in upstream.rglob("*") if path.is_file()):
                digest.update(path.relative_to(upstream).as_posix().encode() + b"\0"
                              + hashlib.sha256(path.read_bytes()).digest())
            archive = directory / "abyss.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                output.add(upstream, arcname=".")

            def inspect_staging(_args, consumer, _env, _timeout):
                for package in ("ex_ssl", "elixir_quic"):
                    source = repository / "apps" / package
                    staged = consumer.parent / package
                    self.assertFalse((staged / "tmp").exists())
                    for name in ("lib/tmp/source.ex", "test/support/fixture.pem"):
                        self.assertEqual((staged / name).read_bytes(), (source / name).read_bytes())
                    self.assertTrue((source / "tmp/policy.fifo").is_fifo())

            with patch.object(abyss, "ROOT", repository), \
                    patch.object(abyss, "ABYSS_CONTENT_HASH", digest.hexdigest()), \
                    patch.object(abyss.sys, "dont_write_bytecode", True), \
                    patch.object(abyss, "command", side_effect=inspect_staging) as command, \
                    patch.object(abyss.urllib.request, "urlretrieve") as download:
                abyss.run(archive)
            download.assert_not_called()
            self.assertEqual([call.args[0][:2] for call in command.call_args_list],
                             [["mix", "deps.get"], ["mix", "compile"], ["mix", "run"]])


if __name__ == "__main__":
    unittest.main()

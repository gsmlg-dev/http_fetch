"""Local integration artifacts must not become candidate package inputs."""

import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()

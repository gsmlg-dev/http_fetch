import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from changed_apps import ALL, needs_full_gate, needs_historical_tls, select_apps

SCRIPT = Path(__file__).with_name("changed_apps.py")


def run_cli(cwd, *args):
    with tempfile.TemporaryDirectory() as output_dir:
        output_file = Path(output_dir) / "output"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args], cwd=cwd,
            env={**os.environ, "GITHUB_OUTPUT": str(output_file)},
            capture_output=True, text=True,
        )
        return result, output_file.read_text() if output_file.exists() else ""


class SelectionTest(unittest.TestCase):
    def test_nondoc_changes_select_reverse_dependency_closure(self):
        self.assertEqual(select_apps(["apps/http_event_source/lib/event.ex"], "ci.yml"), ["http_event_source"])
        self.assertEqual(select_apps(["apps/http_runtime/lib/pool.ex"], "test.yml"),
                         ["http_runtime", "http_fetch", "http_web_socket", "http_event_source"])
        self.assertEqual(select_apps(["apps/elixir_quic/lib/quic.ex"], "ci.yml"),
                         [app for app in ALL if app != "ex_ssl"])
        self.assertEqual(select_apps(["apps/ex_ssl/lib/ssl.ex"], "ci.yml"), ALL)
        self.assertEqual(select_apps(["apps/elixir_quic_http3/lib/http3.ex"], "ci.yml"), ["elixir_quic_http3"])

    def test_docs_select_only_owner_and_shared_selects_all(self):
        self.assertEqual(select_apps(["apps/http_core/README.md"], "ci.yml"), ["http_core"])
        self.assertEqual(select_apps(["README.md", "docs/overview.md"], "ci.yml"), [])
        for path in ("mix.exs", "mix.lock", "config/config.exs", ".credo.exs",
                     "scripts/ci/changed_apps.py", "scripts/release/versions.exs",
                     ".github/workflows/changes.yml"):
            with self.subTest(path=path):
                self.assertEqual(select_apps([path], "test.yml"), ALL)
        self.assertEqual(select_apps([".github/workflows/ci.yml"], "test.yml"), [])

    def test_full_consumer_and_historical_tls_gate_selection(self):
        for path in ("apps/ex_ssl/lib/ssl.ex", "apps/http_core/lib/http/tls_backend.ex",
                     "apps/http_event_source/mix.exs", "mix.lock", "scripts/release/stage.py"):
            with self.subTest(path=path):
                self.assertTrue(needs_full_gate([path], "ci.yml"))
        for path in ("apps/ex_ssl/test/ssl_test.exs", "apps/http_event_source/lib/event.ex",
                     "apps/ex_ssl/README.md", "README.md"):
            with self.subTest(path=path):
                self.assertFalse(needs_full_gate([path], "ci.yml"))
        self.assertTrue(needs_historical_tls(["apps/ex_ssl/lib/ssl.ex"]))
        self.assertTrue(needs_historical_tls(["config/config.exs"]))
        self.assertFalse(needs_historical_tls(["apps/http_event_source/mix.exs"]))
        self.assertFalse(needs_historical_tls(["docs/ex-ssl-consumer-contract.md"]))

    def test_deleted_and_renamed_paths(self):
        self.assertEqual(select_apps(["apps/http_event_source/deleted.ex"], "ci.yml"), ["http_event_source"])
        self.assertEqual(select_apps(["apps/elixir_quic/old.ex", "apps/http_fetch/new.ex"], "ci.yml"),
                         [app for app in ALL if app != "ex_ssl"])

    def test_missing_base_and_manual_module(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = run_cli(directory, "--workflow", "e2e.yml", "--event", "push", "--base", "0" * 40)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("apps=" + json.dumps(ALL, separators=(",", ":")), output)
            for app in (*ALL, "all"):
                result, output = run_cli(directory, "--workflow", "e2e.yml", "--event", "workflow_dispatch",
                                         "--manual-module", app)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("apps=" + json.dumps(ALL if app == "all" else [app], separators=(",", ":")), output)
            result, _ = run_cli(directory, "--workflow", "e2e.yml", "--event", "workflow_dispatch",
                                "--manual-module", "invalid")
            self.assertNotEqual(result.returncode, 0)

    def test_git_range_rename_deletion_docs_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

            def write(path, content):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)

            git("init", "-q")
            git("config", "user.name", "Workflow Test")
            git("config", "user.email", "workflow@example.invalid")
            write("apps/http_event_source/old.ex", "old")
            write("README.md", "initial")
            git("add", ".")
            git("commit", "-qm", "baseline")
            base = git("rev-parse", "HEAD")
            write("README.md", "docs only")
            git("add", ".")
            git("commit", "-qm", "docs")
            result, output = run_cli(directory, "--workflow", "test.yml", "--event", "push",
                                     "--base", base, "--head", git("rev-parse", "HEAD"))
            self.assertEqual((result.returncode, output), (0, "apps=[]\nhas_changes=false\nfull_gate=false\nhistorical_tls=false\n"))
            (root / "apps/http_core").mkdir()
            git("mv", "apps/http_event_source/old.ex", "apps/http_core/new.ex")
            git("commit", "-qm", "rename")
            result, output = run_cli(directory, "--workflow", "ci.yml", "--event", "push",
                                     "--base", base, "--head", git("rev-parse", "HEAD"))
            expected = [app for app in ALL if app not in ("ex_ssl", "elixir_quic")]
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output, "apps=" + json.dumps(expected, separators=(",", ":")) + "\nhas_changes=true\nfull_gate=false\nhistorical_tls=false\n")


if __name__ == "__main__":
    unittest.main()

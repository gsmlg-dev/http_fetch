import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from changed_apps import ALL, select_apps

SCRIPT = Path(__file__).with_name("changed_apps.py").resolve()
WORKFLOWS = ("ci.yml", "test.yml", "e2e.yml")


def run_cli(cwd, *args):
    with tempfile.TemporaryDirectory() as output_dir:
        output_file = Path(output_dir) / "output"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args], cwd=cwd,
            env={**os.environ, "GITHUB_OUTPUT": str(output_file)},
            capture_output=True, text=True,
        )
        return result, output_file.read_text() if output_file.exists() else ""


def expected_output(apps, manual=False):
    return ("apps=" + json.dumps(apps, separators=(",", ":"))
            + f"\nhas_changes={'true' if apps else 'false'}"
            + f"\nfull_gate={'true' if manual else 'false'}"
            + f"\nhistorical_tls={'true' if manual else 'false'}\n")


class SelectionTest(unittest.TestCase):
    def test_every_app_path_selects_only_its_owner(self):
        for workflow in WORKFLOWS:
            for app in ALL:
                for suffix in ("lib/module.ex", "test/module_test.exs", "e2e/check.exs",
                               "docs/guide.md", "README.md", "mix.exs", "priv/data.bin"):
                    with self.subTest(workflow=workflow, app=app, suffix=suffix):
                        self.assertEqual(select_apps([f"apps/{app}/{suffix}"], workflow), [app])

    def test_root_shared_scripts_and_unknown_apps_select_nothing(self):
        paths = ["mix.exs", "mix.lock", "config/config.exs", ".credo.exs", ".formatter.exs",
                 ".dialyzer_ignore.exs", "scripts/ci/changed_apps.py", "scripts/release/stage.py",
                 "scripts/interop/run.exs", "scripts/ex_ssl_source_smoke.sh", "README.md",
                 "docs/overview.md", "apps/unknown/lib/foo.ex", "apps/http_core_other/test.exs",
                 "other/apps/http_core/lib/foo.ex", ".github/workflows/changes.yml"]
        paths += [f".github/workflows/{workflow}" for workflow in WORKFLOWS]
        for workflow in WORKFLOWS:
            self.assertEqual(select_apps(paths, workflow), [])
            self.assertEqual(select_apps(paths + ["apps/http_runtime/mix.exs"], workflow),
                             ["http_runtime"])

    def test_multiple_owners_are_unique_and_in_inventory_order(self):
        paths = ["apps/http_fetch/new.ex", "apps/elixir_quic/old.ex",
                 "apps/http_fetch/mix.exs", "apps/ex_ssl/test/deleted_test.exs"]
        for workflow in WORKFLOWS:
            self.assertEqual(select_apps(paths, workflow), ["ex_ssl", "elixir_quic", "http_fetch"])

    def test_manual_always_selects_all_for_every_workflow_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            for workflow in WORKFLOWS:
                result, output = run_cli(directory, "--workflow", workflow,
                                         "--event", "workflow_dispatch")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output, expected_output(ALL, manual=True))

    def test_missing_or_invalid_ranges_fail_without_enabling_full_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            for base in ("", "0" * 40, "not-a-revision"):
                result, output = run_cli(directory, "--workflow", "ci.yml", "--event", "push",
                                         "--base", base)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")
                self.assertIn("Cannot determine changed paths", result.stderr)

    def test_git_ranges_rename_delete_root_only_and_zero_sha(self):
        # Git writes are confined to this disposable fixture, never the project checkout.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

            def write(path, content):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)

            def check(base, head, apps):
                for workflow in WORKFLOWS:
                    result, output = run_cli(directory, "--workflow", workflow, "--event", "push",
                                             "--base", base, "--head", head)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output, expected_output(apps))

            git("init", "-q")
            git("config", "user.name", "Workflow Test")
            git("config", "user.email", "workflow@example.invalid")
            write("apps/http_event_source/old.ex", "old")
            write("README.md", "initial")
            git("add", ".")
            git("commit", "-qm", "baseline")
            base = git("rev-parse", "HEAD")
            check("0" * 40, base, ["http_event_source"])
            write("README.md", "docs only")
            git("add", ".")
            git("commit", "-qm", "docs")
            check(base, "HEAD", [])
            (root / "apps/http_core").mkdir()
            git("mv", "apps/http_event_source/old.ex", "apps/http_core/new.ex")
            git("commit", "-qm", "rename")
            check(base, "HEAD", ["http_core", "http_event_source"])
            base = git("rev-parse", "HEAD")
            git("rm", "apps/http_core/new.ex")
            git("commit", "-qm", "delete")
            check(base, "HEAD", ["http_core"])
            check(base, "0" * 40, ["http_core"])
            check("0" * 40, "HEAD", [])
            result, output = run_cli(directory, "--workflow", "ci.yml", "--event", "push",
                                     "--base", "", "--head", "HEAD")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output, "")


class WorkflowContractTest(unittest.TestCase):
    def test_all_entry_workflows_dispatch_all_and_automatically_filter_app_paths(self):
        root = SCRIPT.parents[2]
        for workflow in WORKFLOWS:
            text = (root / ".github/workflows" / workflow).read_text()
            with self.subTest(workflow=workflow):
                self.assertRegex(text, r"(?m)^  workflow_dispatch: \{\}$")
                for event in ("push", "pull_request"):
                    block = re.search(rf"(?m)^  {event}:\n((?:    .*\n)+)", text).group(1)
                    self.assertIn("paths: ['apps/**']", block)
                self.assertIn("app: ${{ fromJSON(needs.changes.outputs.apps) }}", text)
                self.assertNotIn("manual_module", text)
                self.assertNotIn("inputs.version", text)
        changes = (root / ".github/workflows/changes.yml").read_text()
        self.assertNotIn("manual_module", changes)
        self.assertIn("HEAD_SHA: ${{ github.event.after || github.sha }}", changes)
        self.assertIn('--head "$HEAD_SHA"', changes)

    def test_scoped_checks_and_manual_full_gates_are_preserved(self):
        root = SCRIPT.parents[2]
        ci = (root / ".github/workflows/ci.yml").read_text()
        checks, full = ci.split("  candidate-consumer:")
        self.assertNotIn("mix format --check-formatted mix.exs", checks)
        self.assertIn("mix format --check-formatted mix.exs .formatter.exs config/config.exs", full)
        self.assertIn("if: needs.changes.outputs.full_gate == 'true'", full)
        self.assertIn("if: needs.changes.outputs.historical_tls == 'true'", full)
        self.assertIn('python3 scripts/release/consumer_gate.py "$RELEASE_VERSION"', full)
        self.assertIn("bash scripts/ex_ssl_source_smoke.sh", full)
        self.assertIn("bash scripts/ex_ssl_published_feature_gate.sh", full)
        e2e = (root / ".github/workflows/e2e.yml").read_text()
        for gate in ("apps/ex_ssl/e2e/quic_tls/run.exs", "docker build --tag ex-ssl-e2e:local",
                     "mix test", "scripts/interop/test_peer.py", "scripts/phase1/interop.exs",
                     "scripts/datagram/interop.exs", "apps/elixir_quic_http3/e2e/transport_smoke.exs",
                     'mix test "apps/${HTTP_FETCH_CI_APP}/e2e"'):
            self.assertIn(gate, e2e)
        test = (root / ".github/workflows/test.yml").read_text()
        self.assertIn("mix test apps/${{ matrix.app }}/test", test)
        self.assertIn("test-${{ matrix.app }}-", test)
        self.assertNotIn("restore-keys:", test)


if __name__ == "__main__":
    unittest.main()

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from changed_apps import ALL, H2_CONSUMERS, affected_h2_consumers, dependency_graph, select_apps

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
            + f"\nh2_compat={'true' if manual or any(app in H2_CONSUMERS for app in apps) else 'false'}"
            + f"\nhistorical_tls={'true' if manual else 'false'}\n")


class SelectionTest(unittest.TestCase):
    def test_actual_graph_selects_shared_h2_consumers(self):
        graph = dependency_graph()
        self.assertEqual(graph["http_fetch"], {"http_core", "http_runtime"})
        for owner in ("http_core", "http_runtime", "ex_ssl", "elixir_quic",
                      "elixir_quic_http3"):
            paths = [f"apps/{owner}/lib/module.ex"]
            for workflow in WORKFLOWS:
                expected = [app for app in ALL if app == owner or app in H2_CONSUMERS]
                self.assertEqual(select_apps(paths, workflow), expected)
                self.assertEqual(affected_h2_consumers(paths), list(H2_CONSUMERS))

    def test_shared_manifests_harnesses_and_workflows_select_h2_consumers(self):
        for path in ("mix.exs", "mix.lock", "config/config.exs", ".credo.exs",
                     ".formatter.exs", ".dialyzer_ignore.exs", "scripts/ci/changed_apps.py",
                     "scripts/release/stage.py", "scripts/http2_stream_peer.py",
                     "scripts/http_runtime_package_traffic_gate.py",
                     "scripts/requirements-http2-stream-clients.txt",
                     "scripts/ex_ssl_source_smoke.sh", ".github/workflows/changes.yml"):
            for workflow in WORKFLOWS:
                self.assertEqual(select_apps([path], workflow), list(H2_CONSUMERS))
        for workflow in WORKFLOWS:
            self.assertEqual(select_apps([f".github/workflows/{workflow}"], workflow),
                             list(H2_CONSUMERS))

    def test_irrelevant_docs_and_unrelated_apps_remain_cheap(self):
        for path in ("README.md", "docs/overview.md", "scripts/unrelated.py",
                     "apps/unknown/lib/foo.ex", "other/apps/http_core/lib/foo.ex"):
            self.assertEqual(select_apps([path], "ci.yml"), [])
            self.assertEqual(affected_h2_consumers([path]), [])
        self.assertEqual(select_apps(["apps/http_core/README.md"], "ci.yml"), ["http_core"])
        self.assertEqual(affected_h2_consumers(["apps/http_core/README.md"]), [])
        self.assertEqual(select_apps(["apps/http_web_transport/lib/foo.ex"], "ci.yml"),
                         ["http_web_transport"])
        self.assertEqual(affected_h2_consumers(["apps/http_web_transport/lib/foo.ex"]), [])

    def test_graph_changes_affect_selection_without_hardcoded_ancestry(self):
        graph = {app: set() for app in ALL}
        graph["http_fetch"] = {"http_core"}
        self.assertEqual(affected_h2_consumers(["apps/http_core/lib/foo.ex"], graph),
                         ["http_fetch"])

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
            check(base, "HEAD", ["http_core", *H2_CONSUMERS])
            base = git("rev-parse", "HEAD")
            git("rm", "apps/http_core/new.ex")
            git("commit", "-qm", "delete")
            check(base, "HEAD", ["http_core", *H2_CONSUMERS])
            check(base, "0" * 40, ["http_core", *H2_CONSUMERS])
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
                    self.assertIn("'apps/**'", block)
                    self.assertIn("'mix.lock'", block)
                    self.assertIn("'scripts/http2_*'", block)
                    self.assertIn("'.github/workflows/**'", block)
                self.assertIn("app: ${{ fromJSON(needs.changes.outputs.apps) }}", text)
                self.assertNotIn("manual_module", text)
                self.assertNotIn("inputs.version", text)
        changes = (root / ".github/workflows/changes.yml").read_text()
        self.assertNotIn("manual_module", changes)
        self.assertIn("HEAD_SHA: ${{ github.event.after || github.sha }}", changes)
        self.assertIn('--head "$HEAD_SHA"', changes)

    def test_h2_gate_is_required_and_retains_evidence(self):
        root = SCRIPT.parents[2]
        ci = (root / ".github/workflows/ci.yml").read_text()
        self.assertIn("if: needs.changes.outputs.h2_compat == 'true'", ci)
        self.assertIn("python3 scripts/ci/http2_compat.py", ci)
        self.assertIn("h2-compat-${{ github.sha }}", ci)
        self.assertIn("if-no-files-found: error", ci)

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
        self.assertIn("python3 -m pip install --requirement scripts/requirements-http2-stream-clients.txt", test)
        self.assertNotIn("restore-keys:", test)
        release = (root / ".github/workflows/release.yml").read_text()
        self.assertLess(release.index("--requirement scripts/requirements-http2-stream-clients.txt"),
                        release.index("mix test --seed"))


if __name__ == "__main__":
    unittest.main()

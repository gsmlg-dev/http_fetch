import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import changed_apps
from changed_apps import ALL, H2_CONSUMERS, affected_h2_consumers, dependency_graph, select_apps

SCRIPT = Path(__file__).with_name("changed_apps.py").resolve()
WORKFLOWS = ("ci.yml", "test.yml", "integration.yml", "e2e.yml")


def run_cli(cwd, *args):
    with tempfile.TemporaryDirectory() as output_dir:
        output_file = Path(output_dir) / "output"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args], cwd=cwd,
            env={**os.environ, "GITHUB_OUTPUT": str(output_file)},
            capture_output=True, text=True,
        )
        return result, output_file.read_text() if output_file.exists() else ""


def expected_output(apps, manual=False, candidate=False):
    return ("apps=" + json.dumps(apps, separators=(",", ":"))
            + f"\nhas_changes={'true' if apps else 'false'}"
            + f"\nfull_gate={'true' if manual else 'false'}"
            + f"\nh2_compat={'true' if manual or any(app in H2_CONSUMERS for app in apps) else 'false'}"
            + f"\ncandidate_tls={'true' if manual or candidate else 'false'}"
            + f"\nhistorical_tls={'true' if manual else 'false'}\n")


class SelectionTest(unittest.TestCase):
    def test_actual_graph_selects_shared_h2_consumers(self):
        graph = dependency_graph()
        self.assertEqual(graph["http_fetch"], {"http_core", "http_runtime"})
        affected = {
            "ex_ssl": ["ex_ssl", "elixir_quic", "elixir_quic_http3", *H2_CONSUMERS],
            "elixir_quic": ["elixir_quic", "elixir_quic_http3", *H2_CONSUMERS],
            "http_core": ["http_core", "elixir_quic_http3", *H2_CONSUMERS],
            "http_runtime": ["http_runtime", *H2_CONSUMERS],
            "elixir_quic_http3": ["elixir_quic_http3", *H2_CONSUMERS],
        }
        for owner, expected in affected.items():
            paths = [f"apps/{owner}/lib/module.ex"]
            for workflow in WORKFLOWS:
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
                self.assertEqual(select_apps([path], workflow),
                                 ["elixir_quic", "elixir_quic_http3", *H2_CONSUMERS])
        for workflow in WORKFLOWS:
            self.assertEqual(select_apps([f".github/workflows/{workflow}"], workflow),
                             ["elixir_quic", "elixir_quic_http3", *H2_CONSUMERS])

    def test_candidate_tls_covers_app_code_tests_manifests_and_direct_harnesses(self):
        for app in ALL:
            for suffix in ("lib/module.ex", "test/module_test.exs", "mix.exs",
                           "e2e/traffic.exs", "priv/fixture.pem"):
                with self.subTest(app=app, suffix=suffix):
                    self.assertTrue(changed_apps.candidate_tls_required([f"apps/{app}/{suffix}"]))
        for path in ("mix.exs", "mix.lock", "config/test.exs", ".formatter.exs",
                     ".credo.exs", ".dialyzer_ignore.exs", "scripts/ci/changed_apps.py",
                     ".github/workflows/test.yml", "scripts/ex_ssl_options_test.exs",
                     "scripts/ex_ssl_tls12_peer.py", "scripts/external_consumer_smoke.exs",
                     "scripts/external_consumer_smoke.sh", "scripts/http3/public_gate.py",
                     "scripts/release/consumer_gate.py", "scripts/http2_stream_peer.py",
                     "scripts/http_runtime_package_traffic_gate.py"):
            with self.subTest(path=path):
                self.assertTrue(changed_apps.candidate_tls_required([path]))

    def test_candidate_tls_keeps_docs_and_unrelated_paths_cheap(self):
        for path in ("README.md", "docs/migration.md", "scripts/unrelated.py",
                     "apps/unknown/lib/module.ex", "scripts/release/README.md",
                     "apps/ex_ssl/docs/ARCHITECTURE.md", "apps/http_core/README.md"):
            with self.subTest(path=path):
                self.assertFalse(changed_apps.candidate_tls_required([path]))

    def test_quic_selection_uses_current_dependency_graph(self):
        graph = {app: set() for app in ALL}
        graph["elixir_quic_http3"] = {"http_runtime"}
        self.assertEqual(changed_apps.affected_quic_consumers(
            ["apps/http_runtime/lib/module.ex"], graph), ["elixir_quic_http3"])
        self.assertEqual(changed_apps.affected_quic_consumers(
            ["apps/ex_ssl/lib/module.ex"], graph), [])

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
            for base, head in (("", "HEAD"), ("0" * 40, "HEAD"),
                               ("not-a-revision", "HEAD"), ("HEAD", ""),
                               ("0" * 40, "0" * 40)):
                result, output = run_cli(directory, "--workflow", "ci.yml", "--event", "push",
                                         "--base", base, "--head", head)
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

            def check(base, head, apps, candidate=False):
                for workflow in WORKFLOWS:
                    for event in ("push", "pull_request"):
                        result, output = run_cli(directory, "--workflow", workflow, "--event", event,
                                                 "--base", base, "--head", head)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(output, expected_output(apps, candidate=candidate))

            git("init", "-q")
            git("config", "user.name", "Workflow Test")
            git("config", "user.email", "workflow@example.invalid")
            write("apps/http_event_source/old.ex", "old")
            write("README.md", "initial")
            git("add", ".")
            git("commit", "-qm", "baseline")
            base = git("rev-parse", "HEAD")
            check("0" * 40, base, ["http_event_source"], candidate=True)
            write("README.md", "docs only")
            git("add", ".")
            git("commit", "-qm", "docs")
            check(base, "HEAD", [])
            (root / "apps/http_core").mkdir()
            git("mv", "apps/http_event_source/old.ex", "apps/http_core/new.ex")
            git("commit", "-qm", "rename")
            check(base, "HEAD", ["http_core", "elixir_quic_http3", *H2_CONSUMERS], candidate=True)
            base = git("rev-parse", "HEAD")
            git("rm", "apps/http_core/new.ex")
            git("commit", "-qm", "delete")
            check(base, "HEAD", ["http_core", "elixir_quic_http3", *H2_CONSUMERS], candidate=True)
            check(base, "0" * 40, ["http_core", "elixir_quic_http3", *H2_CONSUMERS], candidate=True)
            check("0" * 40, "HEAD", [])
            base = git("rev-parse", "HEAD")
            write("apps/ex_ssl/README.md", "app docs only")
            git("add", ".")
            git("commit", "-qm", "app docs")
            check(base, "HEAD", ["ex_ssl"])
            for path, expected in (
                ("apps/ex_ssl/test/policy_test.exs",
                 ["ex_ssl", "elixir_quic", "elixir_quic_http3", *H2_CONSUMERS]),
                ("apps/http_fetch/mix.exs", ["http_fetch"]),
                ("scripts/ex_ssl_options_test.exs",
                 ["elixir_quic", "elixir_quic_http3", *H2_CONSUMERS]),
                ("scripts/external_consumer_smoke.exs",
                 ["elixir_quic", "elixir_quic_http3", *H2_CONSUMERS]),
                ("scripts/http3/public_gate.py",
                 ["elixir_quic", "elixir_quic_http3", *H2_CONSUMERS]),
            ):
                base = git("rev-parse", "HEAD")
                write(path, "candidate harness or app source")
                git("add", ".")
                git("commit", "-qm", "relevant change")
                check(base, "HEAD", expected, candidate=True)
            result, output = run_cli(directory, "--workflow", "ci.yml", "--event", "push",
                                     "--base", "", "--head", "HEAD")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output, "")


class WorkflowContractTest(unittest.TestCase):
    def test_static_analysis_deferral_is_explicit_manual_and_keeps_other_gates_required(self):
        root = SCRIPT.parents[2]
        strict = "if: ${{ !(github.event_name == 'workflow_dispatch' && inputs.defer_static_analysis) }}"
        deferred = "if: github.event_name == 'workflow_dispatch' && inputs.defer_static_analysis"
        for filename, lint_names, required_names in (
            ("ci.yml", ("Check selected app with Credo", "Check selected app with Dialyzer"),
             ("Check selected app formatting", "Compile selected closure",
              "Build selected portable Hex package", "Check git diff")),
            ("release.yml", ("Check source with Credo", "Check source with Dialyzer"),
             ("Validate all source and automation", "Build and run Go HTTP E2E server",
              "Build, inspect, and independently consume all nine archives",
              "Preflight Hex and GitHub immutability before any remote write")),
        ):
            with self.subTest(workflow=filename):
                text = (root / ".github/workflows" / filename).read_text()
                dispatch = text.split("  workflow_dispatch:", 1)[1].split("\n\n", 1)[0]
                self.assertRegex(dispatch, r"(?m)^      defer_static_analysis:\n"
                                 r"        description: [^\n]+\n"
                                 r"        required: false\n"
                                 r"        default: false\n"
                                 r"        type: boolean$")
                steps = text.split("      - name: ")[1:]
                by_name = {step.split("\n", 1)[0]: step for step in steps}
                for name in lint_names:
                    self.assertIn(strict, by_name[name])
                    self.assertNotIn("continue-on-error", by_name[name])
                summary = by_name["Record deferred static analysis"]
                self.assertIn(deferred, summary)
                self.assertIn("Credo: DEFERRED", summary)
                self.assertIn("Dialyzer: DEFERRED", summary)
                self.assertIn('"$GITHUB_STEP_SUMMARY"', summary)
                for name in required_names:
                    self.assertNotIn("defer_static_analysis", by_name[name])
                    self.assertNotIn("continue-on-error", by_name[name])

    def test_candidate_tls_is_automatic_required_and_retains_feature_evidence(self):
        root = SCRIPT.parents[2]
        ci = (root / ".github/workflows/ci.yml").read_text()
        candidate = ci.split("  candidate-consumer:")[1].split("  published-ex-ssl-feature-gate:")[0]
        self.assertIn("if: needs.changes.outputs.candidate_tls == 'true'", candidate)
        self.assertNotIn("continue-on-error", candidate)
        self.assertIn("if-no-files-found: error", candidate)
        self.assertNotIn("if-no-files-found: warn", candidate)
        self.assertIn("- name: Check root formatting and automation regressions\n"
                      "        if: needs.changes.outputs.full_gate == 'true'", candidate)
        for event in ("push", "pull_request"):
            block = re.search(rf"(?m)^  {event}:\n((?:    .*\n)+)", ci).group(1)
            self.assertIn("'scripts/external_consumer_smoke.*'", block)
            self.assertIn("'scripts/http3/**'", block)
        changes = (root / ".github/workflows/changes.yml").read_text()
        self.assertIn("value: ${{ jobs.detect.outputs.candidate_tls }}", changes)
        self.assertIn("candidate_tls: ${{ steps.paths.outputs.candidate_tls }}", changes)

    def test_all_entry_workflows_dispatch_all_and_automatically_filter_app_paths(self):
        root = SCRIPT.parents[2]
        for workflow in WORKFLOWS:
            text = (root / ".github/workflows" / workflow).read_text()
            with self.subTest(workflow=workflow):
                if workflow == "ci.yml":
                    self.assertRegex(text, r"(?m)^  workflow_dispatch:$")
                else:
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
        compatibility = (root / "scripts/ci/http2_compat.py").read_text()
        self.assertIn("'--include', 'integration', '--seed', '36'", compatibility)

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
        self.assertNotIn("pip install", test)
        self.assertNotIn("setup-uv", test)
        self.assertNotIn("--include integration", test)
        integration = (root / ".github/workflows/integration.yml").read_text()
        self.assertIn("python3 -m pip install --requirement scripts/requirements-http2-stream-clients.txt", integration)
        self.assertIn("--only integration", integration)
        self.assertNotIn("continue-on-error", integration)
        self.assertNotIn("restore-keys:", test)
        self.assertIn('HTTP_QUIC_PHASE1_REAL: "1"', integration)
        self.assertIn('mix test "apps/${HTTP_FETCH_CI_APP}/e2e" --include e2e', e2e)
        for app in ALL:
            helper = (root / "apps" / app / "test/test_helper.exs").read_text()
            self.assertIn("exclude: [:integration, :e2e]", helper, app)
        release = (root / ".github/workflows/release.yml").read_text()
        self.assertIn("mix test --seed 28092026 --include integration", release)
        self.assertLess(release.index("--requirement scripts/requirements-http2-stream-clients.txt"),
                        release.index("mix test --seed"))


if __name__ == "__main__":
    unittest.main()

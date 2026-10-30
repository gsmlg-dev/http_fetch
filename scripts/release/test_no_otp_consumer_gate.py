"""Mocked gate tests and disposable-Git administrative privacy regressions."""
from contextlib import nullcontext
from pathlib import Path
import io
import json
import os
import shlex
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import no_otp_consumer_gate as gate


def plan():
    peers = {"peer": {"argv": ["python3", "/peers/peer.py"],
                       "script": "/peers/peer.py", "sha256": "a" * 64}}
    cases = []
    for client, action in sorted(gate.REQUIRED):
        protocol = "h3" if client == "h3" else ("http/1.1" if client in ("h1", "managed_h1") else "h2")
        scheme = "wss" if client == "wss" else "https"
        cases.append(dict(id=client + "." + action, client=client, action=action,
                          peer="peer", url=scheme + "://localhost:{port}/" + client + "/" + action,
                          ca_file="/inputs/ca.pem", tls="TLSv1.3", alpn=protocol,
                          expected="ok", timeout_ms=1000,
                          gate_file="{run}/" + client + "." + action + ".gate.json"))
    return dict(schema=1, peers=peers, scenarios=cases)


def evidence(case):
    kind = ("quic_session_endpoint" if case["client"] == "h3" else
            "managed_receipt" if case["client"].startswith("managed_") else
            "client_completion" if case["client"] in ("wss", "sse") else "request_completion")
    return dict(id=case["id"], nonce="run-nonce", result="PASS", executed=1,
                client=case["client"], action=case["action"], tls=case["tls"],
                alpn=case["alpn"], cleanup="confirmed", cleanup_kind=kind,
                requested_tls=case["tls"], required_alpn=case["alpn"],
                fallback_isolated=True, requests_submitted=1,
                requests=0 if case["action"] == "invalid_identity" else 1,
                peer_identity="pinned-peer", fallback=False, replay=False)


class PlanTests(unittest.TestCase):
    def test_complete_matrix_is_required(self):
        self.assertEqual(len(gate.validate_plan(plan())["scenarios"]), 35)
        for missing in gate.REQUIRED:
            bad = plan()
            bad["scenarios"] = [case for case in bad["scenarios"]
                                if (case["client"], case["action"]) != missing]
            with self.subTest(missing=missing), self.assertRaises(gate.GateError):
                gate.validate_plan(bad)

    def test_duplicate_zero_or_unpinned_peer_is_rejected(self):
        for mutate in (lambda p: p["scenarios"].append(p["scenarios"][0]),
                       lambda p: p["peers"]["peer"].pop("sha256"),
                       lambda p: p["scenarios"][0].update(timeout_ms=0),
                       lambda p: p["scenarios"][0].update(url="http://localhost:{port}/"),
                       lambda p: p["scenarios"][0].update(tls="auto")):
            bad = plan()
            mutate(bad)
            with self.assertRaises(gate.GateError):
                gate.validate_plan(bad)

    def test_fresh_project_and_prod_environment(self):
        source = gate.project_source("1.2.3")
        self.assertIn("include_erts: true", source)
        self.assertIn("strip_beams: false", source)
        for forbidden in (":ssl", "path:", "override:", "in_umbrella:"):
            self.assertNotIn(forbidden, source)
        for package in gate.PACKAGES:
            self.assertIn('{:' + package + ', "== 1.2.3"}', source)
        env = gate.production_environment(Path("/fresh"), {
            "PATH": "/bin", "ERL_LIBS": "/umbrella/_build/test", "ERL_FLAGS": "-pa /host",
            "ELIXIR_ERL_OPTIONS": "-pa /test", "MIX_ENV": "test", "MIX_BUILD_PATH": "/old",
            "HEX_UNSAFE_REGISTRY": "1", "HTTP_FETCH_CI_APP": "http_fetch"})
        self.assertEqual(env["MIX_ENV"], "prod")
        self.assertEqual(env["MIX_BUILD_PATH"], "/fresh/build")
        self.assertEqual(env["MIX_DEPS_PATH"], "/fresh/deps")
        self.assertEqual(env["HEX_HOME"], "/fresh/hex")
        for key in ("ERL_LIBS", "ERL_FLAGS", "ELIXIR_ERL_OPTIONS", "HEX_UNSAFE_REGISTRY", "HTTP_FETCH_CI_APP"):
            self.assertNotIn(key, env)

    def test_peer_route_and_independent_gate_are_bound_to_fresh_run(self):
        for url in ("https://example.com:{port}/", "https://user@localhost:{port}/",
                    "https://localhost:443/path/{port}", "https://localhost:{port}/#fragment",
                    "https://localhost:{port}/{port}", "https://localhost:{port}/\n"):
            bad = plan()
            bad["scenarios"][0]["url"] = url
            with self.subTest(url=url), self.assertRaises(gate.GateError):
                gate.validate_plan(bad)
        for path in (None, "/old/gate.json", "{run}/../gate.json", "{run}/{case}.json"):
            bad = plan()
            case = next(c for c in bad["scenarios"] if c["client"] == "h1" and c["action"] == "cancellation")
            case["gate_file"] = path
            with self.subTest(path=path), self.assertRaises(gate.GateError):
                gate.validate_plan(bad)


class EvidenceTests(unittest.TestCase):
    def test_zero_skipped_pending_wrong_protocol_and_replay_are_rejected(self):
        case = plan()["scenarios"][0]
        good = evidence(case)
        gate.validate_scenario(case, good, good, "run-nonce")
        for change in ({"executed": 0}, {"result": "SKIP"}, {"cleanup": "pending"},
                       {"cleanup": "unconfirmed"}, {"requested_tls": "TLSv1.2"}, {"required_alpn": "h2"},
                       {"fallback_isolated": False}, {"requests_submitted": 0},
                       {"nonce": "old-run"}, {"peer_identity": ""}):
            bad = {**good, **change}
            with self.subTest(change=change), self.assertRaises(gate.GateError):
                gate.validate_scenario(case, bad, good, "run-nonce")

    def test_raw_peer_and_consumer_must_both_match(self):
        case = plan()["scenarios"][0]
        good = evidence(case)
        for change in ({"requests": 0}, {"alpn": "fallback"}, {"nonce": "other"},
                       {"tls": "TLSv1.2"}, {"fallback": True}, {"replay": True},
                       {"result": "FAIL"}, {"executed": 0}):
            with self.assertRaises(gate.GateError):
                gate.validate_scenario(case, good, {**good, **change}, "run-nonce")

    def test_unknown_provider_cleanup_cannot_be_relabelled_from_pid_down(self):
        case = next(c for c in plan()["scenarios"] if c["client"] == "wss")
        good = evidence(case)
        with self.assertRaises(gate.GateError):
            gate.validate_scenario(case, {**good, "cleanup_kind": "public_pid_down"}, good, "run-nonce")

    @patch.object(Path, "resolve", lambda path, strict=False: path)
    def test_artifact_and_runtime_audits_fail_closed(self):
        base = dict(checked_app_files=10, checked_rel_files=1, checked_boot_files=1,
                    checked_beams=10, ssl_app_dependencies=[], ssl_bundle_paths=[],
                    ssl_boot_entries=[], direct_otp_ssl_imports=[], unresolved_dispatch=[],
                    missing_abstract_code=[], duplicate_package_apps=[],
                    package_versions={p: "1.2.3" for p in gate.PACKAGES})
        gate.validate_artifacts(base, "1.2.3")
        for field in ("ssl_app_dependencies", "ssl_bundle_paths", "ssl_boot_entries",
                      "direct_otp_ssl_imports", "unresolved_dispatch", "missing_abstract_code",
                      "duplicate_package_apps"):
            with self.subTest(field=field), self.assertRaises(gate.GateError):
                gate.validate_artifacts({**base, field: ["finding"]}, "1.2.3")
        for field in ("checked_app_files", "checked_rel_files", "checked_boot_files", "checked_beams"):
            with self.assertRaises(gate.GateError):
                gate.validate_artifacts({**base, field: 0}, "1.2.3")
        for versions in ({}, {**base["package_versions"], "ex_ssl": "1.2.2"}):
            with self.assertRaises(gate.GateError):
                gate.validate_artifacts({**base, "package_versions": versions}, "1.2.3")
        state = dict(ssl_available=False, ssl_loaded=False, ssl_application_loaded=False,
                     ssl_started=False, code_paths=["/release/lib/kernel-1/ebin"],
                     loaded_modules={module: "/release/lib/http_fetch-1.2.3/ebin/Elixir." + module + ".beam"
                                     for module in gate.MODULES},
                     all_loaded_paths={"Enum": "/release/lib/elixir-1/ebin/Elixir.Enum.beam"})
        gate.validate_runtime(state, Path("/release"))
        for field in ("ssl_available", "ssl_loaded", "ssl_application_loaded", "ssl_started"):
            with self.assertRaises(gate.GateError):
                gate.validate_runtime({**state, field: True}, Path("/release"))
        for path in ("/host/lib/stdlib/ebin", "/release/lib/ssl-1/ebin", "/release/test/support",
                     "/release/../host/ebin"):
            with self.assertRaises(gate.GateError):
                gate.validate_runtime({**state, "code_paths": [path]}, Path("/release"))
        for change in ({"loaded_modules": {}}, {"all_loaded_paths": {}},
                       {"all_loaded_paths": {"Enum": "/host/Elixir.Enum.beam"}}):
            with self.subTest(change=change), self.assertRaises(gate.GateError):
                gate.validate_runtime({**state, **change}, Path("/release"))

    def test_release_looking_symlink_cannot_hide_host_module(self):
        escaped = "/release/lib/http_fetch-1.2.3/ebin/Elixir.HTTP.beam"
        def state():
            return dict(ssl_available=False, ssl_loaded=False, ssl_application_loaded=False,
                        ssl_started=False, code_paths=["/release/lib/kernel-1/ebin"],
                        loaded_modules={module: escaped for module in gate.MODULES},
                        all_loaded_paths={"HTTP": escaped})
        with patch.object(Path, "resolve", lambda path, strict=False: path):
            gate.validate_runtime(state(), Path("/release"))
        observed = state()
        def canonical(path, strict=False):
            return Path("/host/umbrella/_build/prod/Elixir.HTTP.beam") if str(path) == escaped else path
        with patch.object(Path, "resolve", canonical), self.assertRaisesRegex(gate.GateError, "canonical.*escaped"):
            gate.validate_runtime(observed, Path("/release"))
        self.assertEqual(observed["canonical_paths"][escaped], "/host/umbrella/_build/prod/Elixir.HTTP.beam")

    def test_missing_canonical_evidence_is_unconfirmed(self):
        state = dict(ssl_available=False, ssl_loaded=False, ssl_application_loaded=False,
                     ssl_started=False, code_paths=["/release/lib/kernel-1/ebin"],
                     loaded_modules={module: "/release/lib/client/ebin/Elixir.HTTP.beam" for module in gate.MODULES},
                     all_loaded_paths={"HTTP": "/release/lib/client/ebin/Elixir.HTTP.beam"})
        with patch.object(Path, "resolve", side_effect=OSError("unavailable")), \
             self.assertRaisesRegex(gate.GateError, "canonical.*unconfirmed"):
            gate.validate_runtime(state, Path("/release"))

    def test_cleanup_cannot_be_borrowed_from_another_scope(self):
        case = next(c for c in plan()["scenarios"] if c["client"] == "h1")
        good = evidence(case)
        with self.assertRaises(gate.GateError):
            gate.validate_scenario(case, {**good, "cleanup_kind": "quic_session_endpoint"}, good, "run-nonce")

    def test_missing_wrong_version_or_partial_audit_never_passes(self):
        for value in (None, {}, {"checked_app_files": 1}):
            with self.assertRaises(gate.GateError):
                gate.validate_artifacts(value, "1.2.3")
        for value in (None, {}, {"ssl_available": False}):
            with self.assertRaises(gate.GateError):
                gate.validate_runtime(value, Path("/release"))



class ClientCompletionScopeTests(unittest.TestCase):
    def test_all_35_cases_accept_their_exact_public_scope(self):
        for case in plan()["scenarios"]:
            with self.subTest(case=case["id"]):
                good = evidence(case)
                gate.validate_scenario(case, good, good, "run-nonce")

    def test_every_client_rejects_missing_unknown_or_swapped_scope(self):
        kinds = (None, "", "public_pid_down", "unsupported", "request_completion",
                 "client_completion", "managed_receipt", "quic_session_endpoint")
        for case in plan()["scenarios"]:
            good = evidence(case)
            for kind in kinds:
                if kind == good["cleanup_kind"]:
                    continue
                with self.subTest(case=case["id"], kind=kind), self.assertRaises(gate.GateError):
                    bad = {**good, "cleanup_kind": kind}
                    if kind is None:
                        bad.pop("cleanup_kind")
                    gate.validate_scenario(case, bad, good, "run-nonce")

    def test_client_receipt_nonconfirmed_results_never_pass(self):
        for case in plan()["scenarios"]:
            if case["client"] not in ("wss", "sse"):
                continue
            good = evidence(case)
            for state in (None, "pending", "unconfirmed", "cleanup_pending",
                          "cleanup_unconfirmed", "unsupported", "unsupported_completion"):
                with self.subTest(case=case["id"], state=state), self.assertRaises(gate.GateError):
                    gate.validate_scenario(case, {**good, "cleanup": state}, good, "run-nonce")

class OrchestrationTests(unittest.TestCase):
    def test_registry_reuses_existing_helper_and_restores_scope_on_failure(self):
        original, original_root = gate.consumer_gate.command, gate.consumer_gate.ROOT
        runner = MagicMock()
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with gate.bounded_registry_commands(runner, Path("/candidate-source")):
                self.assertEqual(gate.consumer_gate.command, runner.command)
                self.assertEqual(gate.consumer_gate.ROOT, Path("/candidate-source"))
                raise RuntimeError("stop")
        self.assertEqual(gate.consumer_gate.command, original)
        self.assertEqual(gate.consumer_gate.ROOT, original_root)

    def test_existing_output_or_source_mismatch_fails_before_build(self):
        with patch.object(Path, "resolve", lambda p: p), patch.object(Path, "exists", return_value=True):
            with self.assertRaises(gate.GateError):
                gate.run("1.2.3", Path("/archives"), Path("/stage"), Path("/source"), "a" * 40,
                         plan(), Path("/fresh"))

    @patch.object(gate, "Peer")
    @patch.object(gate, "build_release")
    @patch.object(gate, "verify_source", return_value={"file": "source-pin"})
    @patch.object(gate.consumer_gate, "local_registry", return_value=nullcontext("http://127.0.0.1:1"))
    @patch.object(gate.consumer_gate, "setup_registry", return_value=Path("/fresh/registry/public"))
    @patch.object(gate.shutil, "copyfile")
    @patch.object(gate, "Runner")
    def test_full_orchestration_invokes_actual_release_and_retains_failure(self, runner_type, copyfile,
                                                                        registry, local, verify, build, peer_type):
        runner = runner_type.return_value
        runner.command.side_effect = ["a" * 40, "versions ok", "archives ok", "repo ok", "release failed"]
        runner.remaining.return_value = 10
        peer_type.return_value.name = "peer"
        peer_type.return_value.ready = dict(port=12345, identity="actual-peer-ready")
        peer_type.return_value.config = {"sha256": "a" * 64}
        writes = {}
        def write(path, value):
            writes[str(path)] = value
        def read(path):
            if str(path).endswith("release-report.json"):
                return '{"artifacts": {}}'
            return "not used"
        with patch.object(Path, "resolve", lambda p: p), patch.object(Path, "exists", return_value=False), \
             patch.object(Path, "mkdir"), patch.object(Path, "read_bytes", return_value=b"input"), \
             patch.object(Path, "write_bytes"), patch.object(Path, "write_text", write), \
             patch.object(Path, "read_text", read), self.assertRaises(gate.GateError):
            gate.run("1.2.3", Path("/archives"), Path("/stage"), Path("/source"), "a" * 40,
                     plan(), Path("/fresh"))
        build.assert_called_once()
        registry.assert_called_once()
        self.assertEqual([call.args[0] for call in runner.command.call_args_list
                          if call.args[0][0] == "git"], [["git", "rev-parse", "HEAD"]])
        self.assertEqual(runner.command.call_args_list[-1].args[0],
                         ["/fresh/release/bin/no_otp_consumer", "eval", "NoOTP.Consumer.run()"])
        self.assertEqual(build.call_args.args[2]["MIX_ENV"], "prod")
        self.assertEqual(build.call_args.args[2]["MIX_BUILD_PATH"], "/fresh/project/build")
        self.assertEqual(build.call_args.args[2]["MIX_DEPS_PATH"], "/fresh/project/deps")
        self.assertIn('"status": "FAIL"', writes["/fresh/gate-report.json"])
        peer_type.return_value.close.assert_called_once()

    def test_peer_identity_and_raw_adapter_do_not_fabricate_scenario(self):
        peer = object.__new__(gate.Peer)
        peer.records = [{"event": "stats", "requests": [], "active_connections": 0}]
        with self.assertRaisesRegex(gate.GateError, "raw peer adapter is diagnostic only"):
            peer.scenario(plan()["scenarios"][0], "run-nonce")

    def test_peer_errors_or_live_connections_fail_independently(self):
        for stats in ({"kind": "stats", "errors": ["TLS failed"], "active_connections": 0},
                      {"kind": "stats", "errors": [], "active_connections": 1}):
            peer = object.__new__(gate.Peer)
            peer.config = {}
            peer.records = [stats]
            peer.process = MagicMock()
            peer.process.poll.return_value = None
            peer.runner = MagicMock()
            peer.runner.remaining.return_value = 1
            peer.messages = gate.queue.Queue()
            peer.messages.put(stats)
            with self.subTest(stats=stats), self.assertRaisesRegex(gate.GateError, "peer error or live connections"):
                peer.observe()

    def test_source_stage_mismatch_is_rejected_after_archive_audit(self):
        outer, inner, member = MagicMock(), MagicMock(), MagicMock()
        outer.extractfile.return_value.read.return_value = b"mock archive content"
        member.name = "lib/public.ex"
        member.isfile.return_value = True
        inner.getmembers.return_value = [member]
        outer_context, inner_context = MagicMock(), MagicMock()
        outer_context.__enter__.return_value = outer
        inner_context.__enter__.return_value = inner
        def read(path):
            return b"staged" if str(path).startswith("/stage/") else b"source"
        with patch.object(gate.archive_audit, "audit_package") as audit, \
             patch.object(gate.tarfile, "open", side_effect=[outer_context, inner_context]), \
             patch.object(Path, "is_file", return_value=True), patch.object(Path, "read_bytes", read), \
             self.assertRaisesRegex(gate.GateError, "staged source differs"):
            gate.verify_source(Path("/stage"), Path("/source"), Path("/archives"), "1.2.3")
        audit.assert_called_once()

    def test_actual_build_and_release_executable_contract(self):
        runner = MagicMock()
        gate.build_release(Path("/fresh/project"), Path("/fresh/release"), {}, runner)
        commands = [call.args[0] for call in runner.command.call_args_list]
        self.assertEqual(commands[0], ["unbuffer", "mix", "deps.get"])
        self.assertIn(["unbuffer", "mix", "compile", "--warnings-as-errors"], commands)
        self.assertIn(["unbuffer", "mix", "release", "no_otp_consumer", "--path", "/fresh/release"], commands)
        self.assertTrue(any("Mix.Dep.cached" in " ".join(cmd) and "Hex.SCM" in " ".join(cmd) for cmd in commands))
        self.assertEqual(gate.release_command(Path("/fresh/release")),
                         ["/fresh/release/bin/no_otp_consumer", "eval", "NoOTP.Consumer.run()"])
        self.assertFalse(any("test" in cmd or "--no-deps-check" in cmd for cmd in commands))

    @patch.object(gate.subprocess, "Popen")
    @patch.object(gate.os, "killpg")
    def test_timeout_reaps_only_owned_process_group(self, killpg, popen):
        process = popen.return_value
        process.pid = 12345
        process.returncode = -15
        process.communicate.side_effect = [gate.subprocess.TimeoutExpired(["cmd"], 1), ("partial", "")]
        process.poll.return_value = None
        runner = gate.Runner(Path("/logs"), max_seconds=1)
        with patch.object(Path, "write_text"), self.assertRaises(gate.GateError):
            runner.command(["cmd"], cwd=Path("/fresh"), env={})
        popen.assert_called_once()
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        killpg.assert_called_once_with(12345, gate.signal.SIGTERM)
        process.communicate.assert_called()

    def test_source_pin_and_hex_provenance_rejection(self):
        with self.assertRaises(gate.GateError):
            gate.project_source("1.2.3; unsafe")
        self.assertIn("dep.opts[:dest]", gate.PROVENANCE)
        self.assertIn("Hex.SCM", gate.PROVENANCE)
        self.assertIn("dep.status == {:ok, expected}", gate.PROVENANCE)
        self.assertIn(":code.which", gate.PROVENANCE)



class AdministrativePrivacyTests(unittest.TestCase):
    """Exercise real administrative Git only; stop before any build or release."""

    def private_fixture(self, directory):
        source = directory / "source"
        source.mkdir()
        marker = directory / "private-access.json"
        filter_script = directory / "fixture_clean_filter.py"
        filter_script.write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "identity = dict(pid=os.getpid(), pgid=os.getpgrp())\n"
            "try:\n"
            " raw = Path('/proc/self/stat').read_text()\n"
            " identity['start_ticks'] = int(raw[raw.rfind(')') + 2:].split()[19])\n"
            "except FileNotFoundError: pass\n"
            "Path(sys.argv[1]).write_text(json.dumps(identity))\n"
            "trace = os.environ.get('G1_FILTER_PROCESS_LEDGER')\n"
            "if trace:\n"
            " with open(trace, 'a') as output: output.write(json.dumps(identity) + '\\n')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n")
        env = {**{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
               "GIT_AUTHOR_NAME": "Privacy fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
               "GIT_COMMITTER_NAME": "Privacy fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        logs = directory / "setup-commands"
        logs.mkdir()
        runner = gate.Runner(logs, max_seconds=30)
        def git(*args):
            return runner.command(["git", *args], cwd=source, env=env, limit=10).strip()
        git("init", "--quiet")
        git("config", "filter.privacy.clean",
            shlex.join([sys.executable, "-I", "-B", str(filter_script), str(marker)]))
        git("config", "filter.privacy.required", "true")
        (source / ".gitattributes").write_text("private-sentinel.txt filter=privacy\n")
        (source / "public.txt").write_text("original public bytes\n")
        (source / "private-sentinel.txt").write_text("original fixture-only bytes\n")
        git("add", "--", ".gitattributes", "public.txt", "private-sentinel.txt")
        git("commit", "--quiet", "-m", "synthetic privacy fixture")
        head = git("rev-parse", "HEAD")
        (source / "public.txt").write_text("changed public bytes\n")
        sentinel = "SYNTHETIC_PRIVATE_SENTINEL_FOR_GIT_CAPTURE_REGRESSION"
        (source / "private-sentinel.txt").write_text(sentinel + "\n")
        marker.unlink(missing_ok=True)  # Setup access must not count as capture access.
        return source, head, marker, sentinel, env

    def administrative_capture(self, directory, source, source_sha, env, expected_error):
        original_runner = gate.Runner
        runners = []
        class AdministrativePrefixRunner(original_runner):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                runners.append(self)

            def command(self, args, **kwargs):
                if args[0] != "git":
                    raise gate.GateError("fixture stops before build")
                return super().command(args, **kwargs)

        output = directory / "capture"
        with patch.object(gate, "Runner", AdministrativePrefixRunner), \
             patch.dict(os.environ, env, clear=True), self.assertRaisesRegex(gate.GateError, expected_error):
            gate.run("1.2.3", directory / "archives", directory / "stage", source,
                     source_sha, plan(), output, max_seconds=30)
        return output, [entry["argv"] for runner in runners for entry in runner.commands]

    def test_administrative_capture_never_accesses_or_exports_private_fixture(self):
        with tempfile.TemporaryDirectory(prefix="g1-privacy-") as temporary:
            directory = Path(temporary)
            source, head, marker, sentinel, env = self.private_fixture(directory)
            output, commands = self.administrative_capture(
                directory, source, head, env, "fixture stops before build")
            exported = [path.read_text() for path in output.iterdir() if path.is_file()]
            observation = dict(git_argv=commands, private_filter_accessed=marker.exists(),
                               synthetic_sentinel_exported=any(sentinel in text for text in exported),
                               public_fixture_modified=(source / "public.txt").read_text() == "changed public bytes\n")
            if marker.exists():
                observation["filter_identity"] = json.loads(marker.read_text())
            evidence = os.environ.get("G1_PRIVACY_EVIDENCE")
            if evidence:
                Path(evidence).write_text(json.dumps(observation, indent=2) + "\n")
            self.assertFalse(observation["private_filter_accessed"],
                             "administrative Git capture accessed the synthetic private clean filter")
            self.assertFalse(observation["synthetic_sentinel_exported"])
            self.assertEqual(commands, [["git", "rev-parse", "HEAD"]])
            self.assertTrue(observation["public_fixture_modified"])
            self.assertNotIn("source_diff", json.loads((output / "gate-report.json").read_text()))

    def test_real_head_mismatch_rejects_before_private_capture_or_build(self):
        with tempfile.TemporaryDirectory(prefix="g1-head-") as temporary:
            directory = Path(temporary)
            source, _head, marker, _sentinel, env = self.private_fixture(directory)
            _output, commands = self.administrative_capture(
                directory, source, "0" * 40, env, "candidate source HEAD mismatch")
            self.assertEqual(commands, [["git", "rev-parse", "HEAD"]])
            self.assertFalse(marker.exists())


class SourceArchiveIdentityTests(unittest.TestCase):
    """Use real tiny archives and bytes, without package/build tools."""

    @staticmethod
    def write_archive(archives, package, files):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode="w:gz") as inner:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                inner.addfile(member, io.BytesIO(data))
        with tarfile.open(archives / f"{package}-1.2.3.tar", "w") as outer:
            member = tarfile.TarInfo("contents.tar.gz")
            member.size = len(content.getvalue())
            outer.addfile(member, io.BytesIO(content.getvalue()))

    def test_real_source_stage_and_archive_tampering_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="g1-archives-") as temporary:
            directory = Path(temporary)
            source, stage, archives = (directory / name for name in ("source", "stage", "archives"))
            archives.mkdir()
            manifest = b'defmodule Fixture.MixProject do\n  def project, do: [version: "1.2.3"]\nend\n'
            files = {"mix.exs": manifest, "lib/public.ex": b"defmodule PublicFixture do\nend\n"}
            for package in gate.PACKAGES:
                for name, data in files.items():
                    for root in (source / "apps" / package, stage / package):
                        path = root / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data)
                self.write_archive(archives, package, files)
            pinned = gate.verify_source(stage, source, archives, "1.2.3")
            self.assertEqual(len(pinned), len(gate.PACKAGES) * len(files))
            package = gate.PACKAGES[0]
            for label, path, error, message in (
                    ("source", source / "apps" / package / "lib/public.ex", gate.GateError, "staged source differs"),
                    ("stage", stage / package / "lib/public.ex", RuntimeError, "archive source differs from stage")):
                with self.subTest(tamper=label):
                    path.write_bytes(b"tampered public source\n")
                    try:
                        with self.assertRaisesRegex(error, message):
                            gate.verify_source(stage, source, archives, "1.2.3")
                    finally:
                        path.write_bytes(files["lib/public.ex"])
            self.write_archive(archives, package, {**files, "lib/public.ex": b"tampered archive\n"})
            with self.assertRaisesRegex(RuntimeError, "archive source differs from stage"):
                gate.verify_source(stage, source, archives, "1.2.3")
            self.write_archive(archives, package, files)
            self.assertEqual(gate.verify_source(stage, source, archives, "1.2.3"), pinned)



class CallablePreflightTests(unittest.TestCase):
    @staticmethod
    def report():
        beam = '/release/lib/fixture-1/ebin/fixture.beam'
        inspection = dict(beam=beam, module=':fixture', sha256='a' * 64,
                          missing_abstract_code=False, unresolved_dispatch=[])
        snapshot = {key: inspection[key] for key in ('beam', 'module', 'sha256')}
        snapshot.update(selected=True, debug=True, exports=[dict(function='entry', arity=1)])
        return dict(checked_app_files=1, checked_rel_files=1, checked_boot_files=1,
                    checked_beams=1, ssl_app_dependencies=[], ssl_bundle_paths=[],
                    ssl_boot_entries=[], direct_otp_ssl_imports=[], unresolved_dispatch=[],
                    missing_abstract_code=[], duplicate_package_apps=[],
                    package_versions={p: '1.2.3' for p in gate.PACKAGES},
                    beam_inspections=[inspection],
                    callable_provenance_preflight=dict(
                        schema=1, stage='incoming_only', requests_valid=True, scan_complete=True,
                        scanned_nodes=20, scanned_sites=1, snapshots=[snapshot],
                        external_callable_records=[], roots=[dict(
                            root=dict(module=':fixture', function='entry', arity=1), exported=True,
                            status='no_syntactic_incoming_edges', incoming=[])]))

    @staticmethod
    def edge(report):
        return dict(beam=report['beam_inspections'][0]['beam'], module=':fixture',
                    owner=dict(function='caller', arity=1), path=[2, 4, 0, 4, 0],
                    ordinal=0, line=3, kind='direct_arguments_require_proof')

    def test_diagnostics_do_not_replace_zero_unresolved_requirement(self):
        report = self.report()
        gate.validate_artifacts(report, '1.2.3')
        report['unresolved_dispatch'] = [dict(kind='unresolved_fun_invocation')]
        with self.assertRaises(gate.GateError):
            gate.validate_artifacts(report, '1.2.3')

    def test_external_classification_cannot_be_forged_at_any_level(self):
        for level in ('top', 'preflight', 'beam'):
            report = self.report()
            target = (report if level == 'top' else report['beam_inspections'][0]
                      if level == 'beam' else report['callable_provenance_preflight'])
            target['external_callable_records'] = [dict(status='proven')]
            with self.subTest(level=level), self.assertRaises(gate.GateError):
                gate.validate_artifacts(report, '1.2.3')

    def test_snapshot_coverage_hash_and_debug_are_bound_to_inspection(self):
        mutations = [lambda p: p['snapshots'].clear(),
                     lambda p: p['snapshots'].append(p['snapshots'][0]),
                     lambda p: p['snapshots'][0].update(sha256='b' * 64),
                     lambda p: p['snapshots'][0].update(module=':other'),
                     lambda p: p['snapshots'][0].update(debug=False)]
        for mutate in mutations:
            report = self.report()
            mutate(report['callable_provenance_preflight'])
            with self.assertRaises(gate.GateError):
                gate.validate_artifacts(report, '1.2.3')

    def test_unknown_selected_path_never_reports_closed_input_universe(self):
        report = self.report()
        preflight = report['callable_provenance_preflight']
        preflight['snapshots'][0]['selected'] = False
        with self.assertRaises(gate.GateError):
            gate.validate_artifacts(report, '1.2.3')
        preflight['roots'][0]['status'] = 'unconfirmed'
        gate.validate_artifacts(report, '1.2.3')

    def test_duplicate_and_rebound_original_node_identities_are_rejected(self):
        for mutate in ('duplicate', 'rebound', 'bad_path', 'unbound_beam'):
            report = self.report()
            preflight = report['callable_provenance_preflight']
            edge = self.edge(report)
            preflight['roots'][0].update(status='unconfirmed', incoming=[edge])
            if mutate == 'duplicate':
                preflight['scanned_sites'] = 2
                preflight['roots'][0]['incoming'].append(dict(edge))
            elif mutate == 'rebound':
                preflight['scanned_sites'] = 2
                preflight['roots'][0]['incoming'].append({**edge, 'path': [9]})
            elif mutate == 'bad_path':
                edge['path'] = [True]
            else:
                edge['beam'] = '/foreign/fixture.beam'
            with self.subTest(mutation=mutate), self.assertRaises(gate.GateError):
                gate.validate_artifacts(report, '1.2.3')

    def test_incoming_edges_remain_unconfirmed_even_when_root_exported(self):
        report = self.report()
        root = report['callable_provenance_preflight']['roots'][0]
        root['incoming'] = [self.edge(report)]
        with self.assertRaises(gate.GateError):
            gate.validate_artifacts(report, '1.2.3')
        root['status'] = 'unconfirmed'
        gate.validate_artifacts(report, '1.2.3')

    def test_invalid_or_exhausted_proof_flags_cannot_claim_success(self):
        for change in (dict(schema=True), dict(stage='external_proven'),
                       dict(scan_complete='true'), dict(scanned_nodes=2_000_001),
                       dict(scanned_sites=100_000), dict(requests_valid=False)):
            report = self.report()
            report['callable_provenance_preflight'].update(change)
            with self.subTest(change=change), self.assertRaises(gate.GateError):
                gate.validate_artifacts(report, '1.2.3')

    def test_absent_export_and_duplicate_root_cannot_become_contracts(self):
        for mutate in ('absent', 'duplicate'):
            report = self.report()
            preflight = report['callable_provenance_preflight']
            if mutate == 'absent':
                preflight['roots'][0]['root']['function'] = 'missing'
            else:
                preflight['roots'].append(preflight['roots'][0])
            with self.subTest(mutation=mutate), self.assertRaises(gate.GateError):
                gate.validate_artifacts(report, '1.2.3')


class PrivateShapeTests(unittest.TestCase):
    @staticmethod
    def report():
        report = CallablePreflightTests.report()
        preflight = report['callable_provenance_preflight']
        preflight['scanned_sites'] = 3
        preflight['scanned_nodes'] = 80
        beam = report['beam_inspections'][0]['beam']
        target = dict(function='deliver', arity=2, parameter_index=1)
        shapes = [dict(kind='tuple', tag='informational', arity=3),
                  dict(kind='tuple', tag='trailers', arity=2)]
        def site(ordinal, owner):
            return dict(beam=beam, module=':fixture', owner=dict(function=owner, arity=2),
                        ordinal=ordinal, line=10 + ordinal, path=[ordinal + 2, 4, 0, 4, 0])
        record = dict(module=':fixture', beam=beam, sha256='a' * 64, status='checked',
                      inventory=dict(complete=True, nodes=70, calls=3),
                      slots=[{**target, 'shapes': shapes}],
                      callers=[dict(target=target.copy(), origin=dict(kind='seed', shape=shape.copy()),
                                    site=site(n, 'dispatch')) for n, shape in enumerate(shapes)],
                      observations=[dict(source=target.copy(),
                                         callee=dict(function='notify', arity=2, argument_index=1),
                                         expected_path=None, site=site(2, 'deliver'), shapes=shapes)])
        preflight['private_shape_derivations'] = dict(schema=1, requests_valid=True, modules=[record])
        return report

    @staticmethod
    def record(report):
        return report['callable_provenance_preflight']['private_shape_derivations']['modules'][0]

    def test_complete_private_shape_theorem_is_separate_from_zero_unresolved(self):
        report = self.report()
        gate.validate_artifacts(report, '1.2.3')
        report['unresolved_dispatch'] = [dict(kind='unresolved_fun_invocation')]
        with self.assertRaises(gate.GateError):
            gate.validate_artifacts(report, '1.2.3')

    def test_stale_artifact_and_incomplete_selection_reject_checked_shapes(self):
        for mutation in ('hash', 'path', 'selected', 'debug', 'scan'):
            report = self.report()
            record = self.record(report)
            preflight = report['callable_provenance_preflight']
            preflight['roots'][0]['status'] = 'unconfirmed'
            if mutation == 'hash':
                record['sha256'] = 'b' * 64
            elif mutation == 'path':
                record['beam'] = '/foreign/fixture.beam'
            elif mutation == 'selected':
                preflight['snapshots'][0]['selected'] = False
            elif mutation == 'debug':
                preflight['snapshots'][0]['debug'] = False
                report['beam_inspections'][0]['missing_abstract_code'] = True
            else:
                preflight['scan_complete'] = False
            with self.subTest(mutation=mutation), self.assertRaises(gate.GateError):
                gate.validate_callable_preflight(report)

    def test_exported_duplicate_or_missing_slots_cannot_claim_private_proof(self):
        for mutation in ('export', 'duplicate', 'absent', 'wrong_index'):
            report = self.report()
            record = self.record(report)
            if mutation == 'export':
                report['callable_provenance_preflight']['snapshots'][0]['exports'].append(
                    dict(function='deliver', arity=2))
            elif mutation == 'duplicate':
                record['slots'].append(record['slots'][0].copy())
            elif mutation == 'absent':
                record['slots'] = []
            else:
                record['slots'][0]['parameter_index'] = 2
            with self.subTest(mutation=mutation), self.assertRaises(gate.GateError):
                gate.validate_callable_preflight(report)

    def test_unknown_or_wrong_seed_and_omitted_callers_reject_theorem(self):
        for mutation in ('unknown', 'tag', 'arity', 'no_callers', 'duplicate', 'internal_seed'):
            report = self.report()
            record = self.record(report)
            if mutation == 'unknown':
                record['callers'][0]['origin']['kind'] = 'external'
            elif mutation in ('tag', 'arity'):
                record['callers'][0]['origin']['shape'][mutation] = 'wrong' if mutation == 'tag' else 2
            elif mutation == 'no_callers':
                record['callers'] = []
            elif mutation == 'duplicate':
                record['callers'].append(record['callers'][0])
            else:
                record['callers'][0]['site']['owner']['function'] = 'deliver'
            with self.subTest(mutation=mutation), self.assertRaises(gate.GateError):
                gate.validate_callable_preflight(report)

    def test_forwarded_domains_need_a_checked_source_and_external_seed(self):
        report = self.report()
        record = self.record(report)
        source = dict(function='wrap', arity=2, parameter_index=1)
        record['slots'].append({**source, 'shapes': record['slots'][0]['shapes']})
        record['callers'][0]['target'] = source.copy()
        record['callers'][1]['origin'] = dict(kind='parameter', source=source.copy())
        record['callers'][1]['site']['owner']['function'] = 'wrap'
        gate.validate_callable_preflight(report)
        record['callers'][0]['origin'] = dict(kind='parameter', source=record['callers'][1]['target'])
        record['callers'][0]['site']['owner']['function'] = 'deliver'
        with self.assertRaises(gate.GateError):
            gate.validate_callable_preflight(report)

    def test_original_path_ordinal_owner_and_observation_must_agree(self):
        for mutation in ('path', 'ordinal', 'owner', 'shape', 'argument', 'duplicate'):
            report = self.report()
            record = self.record(report)
            observation = record['observations'][0]
            if mutation == 'path':
                observation['expected_path'] = [99]
            elif mutation == 'ordinal':
                observation['site']['ordinal'] = record['callers'][0]['site']['ordinal']
            elif mutation == 'owner':
                observation['site']['owner']['function'] = 'dispatch'
            elif mutation == 'shape':
                observation['shapes'] = [dict(kind='atom', value='done')]
            elif mutation == 'argument':
                observation['callee']['argument_index'] = 2
            else:
                record['observations'].append(observation)
            with self.subTest(mutation=mutation), self.assertRaises(gate.GateError):
                gate.validate_callable_preflight(report)

    def test_inventory_bounds_schema_and_status_are_strict(self):
        for mutation in ('nodes', 'calls', 'complete', 'schema', 'valid', 'status'):
            report = self.report()
            record = self.record(report)
            proof = report['callable_provenance_preflight']['private_shape_derivations']
            if mutation == 'nodes':
                record['inventory']['nodes'] = 100_001
            elif mutation == 'calls':
                record['inventory']['calls'] = 4_097
            elif mutation == 'complete':
                record['inventory']['complete'] = False
            elif mutation == 'schema':
                proof['schema'] = True
            elif mutation == 'valid':
                proof['requests_valid'] = False
            else:
                record['status'] = 'external'
            with self.subTest(mutation=mutation), self.assertRaises(gate.GateError):
                gate.validate_callable_preflight(report)

    def test_unconfirmed_records_carry_no_success_evidence(self):
        report = self.report()
        record = self.record(report)
        record.update(status='unconfirmed', inventory=None, slots=[], callers=[], observations=[])
        gate.validate_callable_preflight(report)
        record['slots'] = [dict(function='deliver', arity=2, parameter_index=1)]
        with self.assertRaises(gate.GateError):
            gate.validate_callable_preflight(report)

    def test_duplicate_modules_and_external_records_are_still_rejected(self):
        report = self.report()
        proof = report['callable_provenance_preflight']['private_shape_derivations']
        proof['modules'].append(proof['modules'][0])
        with self.assertRaises(gate.GateError):
            gate.validate_callable_preflight(report)
        report = self.report()
        report['callable_provenance_preflight']['external_callable_records'] = [dict(status='checked')]
        with self.assertRaises(gate.GateError):
            gate.validate_callable_preflight(report)

    def test_unbound_null_artifact_cannot_impersonate_a_present_module(self):
        report = self.report()
        record = self.record(report)
        record.update(status='unconfirmed', beam=None, sha256=None, inventory=None,
                      slots=[], callers=[], observations=[])
        with self.assertRaises(gate.GateError):
            gate.validate_callable_preflight(report)
        record['module'] = ':missing'
        gate.validate_callable_preflight(report)


class PrivateFieldTests(unittest.TestCase):
    @staticmethod
    def report():
        report = CallablePreflightTests.report()
        inspection = report['beam_inspections'][0]
        inspection['parameter_invariant_derivation'] = dict(status='not_requested', checked_slots=[])
        slot = dict(function='loop', arity=1, parameter_index=0, field='transport')
        origin = dict(kind='field_identity', source=slot)
        literal = dict(kind='literal', owner=dict(function='run', arity=0), path=[2, 4, 0, 4, 0, 3, 0])
        seed_fact = dict(kind='atoms', targets=['lists'], origins=[literal])
        identity_fact = dict(kind='atoms', targets=['lists'], origins=[origin])
        seed_site = dict(owner=dict(function='run', arity=0), path=[2, 4, 0, 4, 0], line=1)
        back_site = dict(owner=dict(function='loop', arity=1), path=[3, 4, 0, 4, 0], line=2)
        record = dict(module=inspection['module'], beam=inspection['beam'], sha256=inspection['sha256'],
                      selected=True, status='checked',
                      inventory=dict(complete=True, nodes=20, calls=2, evaluated_nodes=40),
                      slots=[dict(slot, targets=['lists'])],
                      callers=[dict(target=slot, origin=dict(kind='seed', targets=['lists']),
                                    fact=seed_fact, site=seed_site),
                               dict(target=slot, origin=origin, fact=identity_fact, site=back_site)],
                      constructions=[dict(site=seed_site, value=dict(kind='partial_map', fields=[
                          dict(field='transport', value=seed_fact)]))],
                      conditional_returns=[dict(function='loop', arity=1, value=dict(kind='unknown'))])
        report['private_field_derivations'] = dict(schema=1, stage='diagnostic_only',
                                                 requests_valid=True, modules=[record])
        return json.loads(json.dumps(report))

    @staticmethod
    def record(report):
        return report['private_field_derivations']['modules'][0]

    def test_checked_field_graph_is_diagnostic_only(self):
        report = self.report()
        gate.validate_artifacts(report, '1.2.3')
        report['unresolved_dispatch'] = [dict(kind='unresolved_module_dispatch')]
        with self.assertRaises(gate.GateError):
            gate.validate_artifacts(report, '1.2.3')

    def test_unknown_origin_requires_unconfirmed_graph(self):
        report = self.report()
        record = self.record(report)
        record['callers'][0].update(origin=dict(kind='unknown'), fact=dict(kind='unknown'))
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)
        record['status'] = 'unconfirmed'
        gate.validate_private_fields(report)

    def test_recursive_allowed_literal_is_not_an_identity(self):
        report = self.report()
        record = self.record(report)
        seed = record['callers'][0]
        record['callers'][1].update(origin=seed['origin'], fact=seed['fact'])
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)

    def test_identity_cycle_without_seed_cannot_claim_checked(self):
        report = self.report()
        record = self.record(report)
        record['callers'] = record['callers'][1:]
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)
        record['status'] = 'unconfirmed'
        gate.validate_private_fields(report)

    def test_field_evidence_cannot_borrow_requested_but_unchecked_scalar(self):
        report = self.report()
        record = self.record(report)
        source = dict(function='init', arity=1, parameter_index=0)
        record['callers'][0]['fact']['origins'] = [dict(kind='checked_parameter', source=source)]
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)
        report['beam_inspections'][0]['parameter_invariant_derivation'] = dict(
            status='checked', checked_slots=[dict(source, targets=['lists'])])
        gate.validate_private_fields(report)

    def test_stale_artifact_missing_selection_and_nonflat_values_are_rejected(self):
        mutations = [lambda r: r.update(sha256='b' * 64),
                     lambda r: r.update(selected=False),
                     lambda r: r['constructions'][0]['value']['fields'][0].update(
                         value=dict(kind='tuple', elements=[])),
                     lambda r: r['callers'][0]['fact'].update(targets=['ssl'])]
        for mutate in mutations:
            report = self.report()
            mutate(self.record(report))
            with self.subTest(mutation=mutate), self.assertRaises(gate.GateError):
                gate.validate_private_fields(report)

    def test_duplicate_slots_call_sites_and_modules_are_rejected(self):
        mutations = [lambda p: p['modules'].append(p['modules'][0]),
                     lambda p: p['modules'][0]['slots'].append(p['modules'][0]['slots'][0]),
                     lambda p: p['modules'][0]['callers'].append(p['modules'][0]['callers'][0])]
        for mutate in mutations:
            report = self.report()
            mutate(report['private_field_derivations'])
            with self.assertRaises(gate.GateError):
                gate.validate_private_fields(report)

    def test_rejected_requests_and_ineligible_modules_carry_no_certificate(self):
        report = self.report()
        proof = report['private_field_derivations']
        proof['requests_valid'] = False
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)
        proof['modules'] = []
        gate.validate_private_fields(report)
        report = self.report()
        record = self.record(report)
        record.update(status='unconfirmed', selected=False, inventory=None,
                      slots=[], callers=[], constructions=[], conditional_returns=[])
        gate.validate_private_fields(report)
        record['status'] = 'checked'
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)

    def test_exhausted_field_inventory_never_claims_complete(self):
        report = self.report()
        record = self.record(report)
        record['inventory']['evaluated_nodes'] = 200_001
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)
        record.update(status='unconfirmed')
        record['inventory']['complete'] = False
        gate.validate_private_fields(report)

    def test_unknown_value_cannot_hide_an_asserted_finite_fact(self):
        report = self.report()
        self.record(report)['conditional_returns'][0]['value']['targets'] = ['lists']
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)

    def test_extra_field_namespace_cannot_classify_external_code(self):
        for where in ('proof', 'module'):
            report = self.report()
            target = report['private_field_derivations'] if where == 'proof' else self.record(report)
            target['external_callable_records'] = [dict(status='checked')]
            with self.assertRaises(gate.GateError):
                gate.validate_private_fields(report)

    def test_origin_identity_cannot_change_field_or_allowed_domain(self):
        report = self.report()
        record = self.record(report)
        record['callers'][1]['origin']['source']['field'] = 'protocol_module'
        with self.assertRaises(gate.GateError):
            gate.validate_private_fields(report)


if __name__ == "__main__":
    unittest.main()

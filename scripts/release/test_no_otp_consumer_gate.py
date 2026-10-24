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


if __name__ == "__main__":
    unittest.main()

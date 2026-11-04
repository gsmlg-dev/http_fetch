"""Pure P4 gate tests. No peer, socket, subprocess or BEAM execution."""
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
import io
import tarfile
from types import SimpleNamespace
import copy
import json
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
import unittest

import tls_migration_performance as gate


SHA = "a" * 64
BEAM_MODULES = ("HTTP", "HTTP.Promise", "HTTP.Response", "HTTP.RequestCompletion",
                "HTTP.ManagedTransport", "SSL", "SSL.Lifecycle")


def resources(connections=1):
    return dict(processes=4 * connections, tcp_sockets=connections,
                generations=connections, observers=connections,
                data_resources=3 * connections)


def vm():
    return dict(process_count=100, port_count=10, process_memory_bytes=10_000_000,
                binary_memory_bytes=1_000_000, total_memory_bytes=30_000_000,
                rss_bytes=50_000_000)


def arm(cell, phase):
    count = 1000
    operation = cell["workload"]
    body = None if operation == "cancel" else gate.PAYLOAD_SHA if operation == "download" else gate.UPLOAD_REPLY_SHA if operation == "upload" else gate.SMALL_SHA
    samples = [dict(id=str(i), elapsed_us=1000, payload_sha256=body,
                    request_completion="confirmed", cancellation_us=1000 if operation == "cancel" else None, connection=i + cell["concurrency"] + 1 if operation in ("cold", "cancel") else i % cell["concurrency"] + 1,
                    cleanup=dict(status="confirmed", elapsed_us=1000,
                                 retired_data_resources=0, observer_exited=True),
                    public_snapshot=dict(provider_resources=resources()),
                    public_snapshot_point="blocked-before-cancel" if operation == "cancel" else "response-complete-before-retirement",
                    blocked=dict(peer_gate=True, completion_pending=True,
                                 source="peer-read-or-flow-control-gate") if operation == "cancel" else None)
               for i in range(count)]
    requests = [dict(id=str(i), connection=s["connection"], operation=operation,
                     payload_ok=True, completed=operation != "cancel", cancelled=operation == "cancel")
                for i, s in enumerate(samples)]
    connections = cell["concurrency"]
    return dict(phase=phase, backend="ex_ssl" if phase == "candidate" else "ssl",
                source_sha256=SHA, build_sha256=SHA,
                selected_transport=dict(module="Elixir.HTTP.Transport.ExSSL" if phase == "candidate" else "Elixir.HTTP.Transport.SSL", beam_sha256=SHA),
                fixtures={p: SHA for p in gate.FIXTURE_PATHS},
                otp_ssl=dict(before=dict(loaded=False, started=False), after=dict(loaded=False, started=False)),
                runtime=dict(otp="29", elixir="1.19", host="fixture",
                    erts="17.0", architecture="fixture-architecture", schedulers=4,
                    beam_sha256={"Elixir." + name: SHA for name in BEAM_MODULES}),
                effective=dict(verify="verify_peer", tls=cell["tls"], alpn=cell["protocol"],
                               cipher_policy="ecdhe-rsa-aes128gcm-tls12/aes128gcm-sha256-tls13", payload_bytes=1048576,
                               concurrency=connections, pool_connections=connections,
                               warmup=1, warm_state="fresh-scope-per-arm", forced_global_gc=False),
                warmup=[dict(id="warmup", payload_ok=True, request_completion="confirmed")],
                samples=samples, wall_us=1000 * count, failures=[],
                peer=dict(identity=SHA, errors=[], tls=cell["tls"], alpn=cell["protocol"],
                          cipher="TLS_AES_128_GCM_SHA256" if cell["tls"] == "TLSv1.3" else "ECDHE-RSA-AES128-GCM-SHA256", resumed=False, requests=requests,
                          handshakes=[dict(connection=i + 1, tls=cell["tls"], alpn=cell["protocol"], cipher="TLS_AES_128_GCM_SHA256" if cell["tls"] == "TLSv1.3" else "ECDHE-RSA-AES128-GCM-SHA256", resumed=False) for i in range(count + connections if operation in ("cold", "cancel") else connections)],
                          warmup_requests=1, accepted_connections=count + connections if operation in ("cold", "cancel") else connections,
                          closed_connections=count + connections if operation in ("cold", "cancel") else connections,
                          active_connections=0, upload_bytes=count * 1048576 if operation == "upload" else 0,
                          download_bytes=count * 1048576 if operation == "download" else 0),
                baseline=vm(), live_resources=resources(connections),
                retirement=dict(status="confirmed", elapsed_us=1000,
                                retired_data_resources=0, observer_exited=True),
                observation_ms=2000, after_retirement=vm(), provider_after_retirement=resources(0))


def cell(workload="reuse"):
    result = dict(kind="measurement", trial=1, protocol="http/1.1", tls="TLSv1.3", concurrency=1, workload=workload)
    result["arms"] = [arm(result, phase) for phase in gate.PHASES]
    return result


def soak_cell():
    value = cell()
    value["kind"] = "soak"
    for a in value["arms"]:
        a["peer"]["handshakes"] = [dict(a["peer"]["handshakes"][0], connection=i + 1) for i in range(3)]
        a["peer"].update(accepted_connections=3, closed_connections=3)
        observation = dict(vm=vm(), provider=resources(), live_connections=1)
        a.update(wall_us=1_800_000_000, duration_us=1_800_000_000, completed_cycles=1000,
                 resource_samples=[dict(observation, elapsed_us=i * 1_800_000) for i in range(1000)],
                 retirement_cycles=[dict(baseline=vm(), after_retirement=vm(), observation_ms=2000,
                                         retirement=copy.deepcopy(a["retirement"])) for _ in range(3)])
    return value


def source_fixture(name, root, directory):
    files = {"mix.lock": SHA, "mix.exs": SHA, "scripts/tls_migration_performance.exs": SHA,
             **{p: SHA for p in gate.FIXTURE_PATHS}}
    source = dict(files=files, sha256=gate.digest(files), head="a" * 40)
    source["fixtures"] = {p: files[p] for p in gate.FIXTURE_PATHS}
    execution = dict(root=str(root), build_path=str(directory / (name + "-build")),
                     deps_path=str(directory / (name + "-deps")), mix_env="prod",
                     runner_sha256=SHA, wrapper_sha256=gate.sha(gate.RUNNER_WRAPPER.encode()))
    transport = "Elixir.HTTP.Transport.ExSSL" if name == "candidate" else "Elixir.HTTP.Transport.SSL"
    build = dict(execution=execution, beam_sha256={n: SHA for n in gate.BEAM_MODULES | {transport}},
                 commands=[["mix", "deps.get", "--check-locked"], ["mix", "compile", "--warnings-as-errors"]],
                 exits=[0, 0], lock_before=SHA, lock_after=SHA)
    build["sha256"] = gate.digest(build)
    source["build"] = build
    return source


def smoke_arm(spec, phase, source):
    value = arm(spec, phase)
    value["samples"] = value["samples"][:10]
    value["peer"]["requests"] = value["peer"]["requests"][:10]
    value["warmup"] = [dict(id=f"w-{i}", payload_ok=True, request_completion="confirmed") for i in range(9 if spec["kind"] == "soak" else 3)]
    value["effective"]["warmup"] = len(value["warmup"])
    value["peer"]["warmup_requests"] = len(value["warmup"])
    connections = 3 if spec["kind"] == "soak" else 11 if spec["workload"] in ("cold", "cancel") else 1
    value["peer"]["handshakes"] = [dict(value["peer"]["handshakes"][0], connection=i + 1) for i in range(connections)]
    value["peer"].update(accepted_connections=connections, closed_connections=connections,
                         upload_bytes=10 * len(gate.PAYLOAD) if spec["workload"] == "upload" else 0,
                         download_bytes=10 * len(gate.PAYLOAD) if spec["workload"] == "download" else 0)
    value["runtime"]["beam_sha256"] = {n: source["build"]["beam_sha256"][n] for n in gate.BEAM_MODULES}
    value["selected_transport"]["beam_sha256"] = source["build"]["beam_sha256"][value["selected_transport"]["module"]]
    value.update(wall_us=10000, source_sha256=source["sha256"], build_sha256=source["build"]["sha256"],
                 execution=source["build"]["execution"], fixtures=source["fixtures"])
    if spec["kind"] == "soak":
        value.update(wall_us=5_000_000, duration_us=5_000_000, completed_cycles=10,
                     resource_samples=[dict(elapsed_us=500000 * (i + 1), vm=vm(), provider=resources(), live_connections=1) for i in range(10)],
                     retirement_cycles=[dict(baseline=vm(), after_retirement=vm(), observation_ms=2000,
                                             retirement=copy.deepcopy(value["retirement"])) for _ in range(3)])
    return value


@contextmanager
def mocked_run(directory, phase_only=False, failed=False, reference=False):
    run = SimpleNamespace(output=directory / "run", closed=0, launched=[], builds=[])
    candidate = source_fixture("candidate", gate.ROOT, run.output)
    run.args = SimpleNamespace(output=run.output, candidate_sha256=candidate["sha256"], smoke=True,
                               python="unused", otp_reference_sha=gate.DEFAULT_OTP_REFERENCE if reference else None)
    reference_root = run.output / "otp-reference-source"
    ref = source_fixture("reference", reference_root, run.output)
    ref["head"] = gate.DEFAULT_OTP_REFERENCE
    ref["build"]["beam_sha256"] = {n: "b" * 64 for n in ref["build"]["beam_sha256"]}

    def export(*_args):
        # A genuine in-memory tar authenticates the synthetic source manifest.
        blobs = {path: b"reference" if path == "mix.exs" else b"fixture" for path in ref["files"]}
        ref["files"] = {p: gate.sha(b) for p, b in blobs.items()}
        # Candidate and reference fixtures must be identical.
        for p in gate.FIXTURE_PATHS:
            candidate["files"][p] = ref["files"][p]
        # This fixture is prepared before execute below, so candidate digest stays pinned.
        ref["sha256"] = gate.digest(ref["files"])
        ref.update(requested_commit=ref["head"])
        archive_path = run.output / "otp-reference.tar"
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT, pax_headers={"comment": ref["head"]}) as archive:
            for path, blob in blobs.items():
                member = tarfile.TarInfo(path)
                member.size = len(blob)
                archive.addfile(member, io.BytesIO(blob))
        ref["archive"] = dict(path=archive_path.name, sha256=gate.sha(archive_path.read_bytes()))
        return reference_root, ref

    if reference:
        # Use the same valid blob hashes for fixtures and immutable manifests.
        candidate["files"] = {p: gate.sha(b"fixture") for p in candidate["files"]}
        candidate["sha256"] = gate.digest(candidate["files"])
        run.args.candidate_sha256 = candidate["sha256"]

    def build(name, root, source, output):
        run.builds.append((name, root))
        source["fixtures"] = {p: source["files"][p] for p in gate.FIXTURE_PATHS}
        source["build"]["execution"]["runner_sha256"] = source["files"]["scripts/tls_migration_performance.exs"]
        source["build"].update(lock_before=source["files"]["mix.lock"], lock_after=source["files"]["mix.lock"])
        source["build"]["sha256"] = gate.digest({k: v for k, v in source["build"].items() if k != "sha256"})
        if name == "candidate":
            candidate.update(source)
        return dict(MIX_ENV="prod", MIX_BUILD_PATH=source["build"]["execution"]["build_path"],
                    MIX_DEPS_PATH=source["build"]["execution"]["deps_path"])

    class FakePeer:
        def __init__(self, spec, *_args):
            self.spec = spec
            self.ready = dict(event="ready", port=1234, identity=SHA)
        def command(self, command):
            if command == "stats" and hasattr(run, "current"):
                return run.current["peer"]
            return dict(event=command)
        def close(self):
            run.closed += 1

    def launch(command, root, env, log, timeout):
        config = json.loads(Path(env["TLS_PERF_CONFIG"]).read_text())
        run.launched.append((command, root, env, config))
        if failed:
            Path(config["output"]).write_text(json.dumps(dict(failures=["runner failure"])))
            log.write_text("retained runner failure")
            return 7
        source = candidate if config["phase"] == "candidate" else ref
        run.current = smoke_arm(config["cell"], config["phase"], source)
        value = dict(phase=config["phase"]) if phase_only else run.current
        Path(config["output"]).write_text(json.dumps(value))
        return 0

    def fingerprint(root=gate.ROOT):
        return copy.deepcopy(candidate if root == gate.ROOT else ref)

    with ExitStack() as stack:
        stack.enter_context(patch.object(gate, "fingerprint", side_effect=fingerprint))
        stack.enter_context(patch.object(gate, "build_source", side_effect=build))
        stack.enter_context(patch.object(gate, "export_reference", side_effect=export))
        stack.enter_context(patch.object(gate, "PeerProcess", FakePeer))
        stack.enter_context(patch.object(gate.subprocess, "check_output", return_value="a" * 40))
        stack.enter_context(patch.object(gate, "run_owned", side_effect=launch))
        yield run


class PerformanceGateTest(unittest.TestCase):
    def test_valid_measurement_recomputes_raw_statistics(self):
        result = gate.validate_cell(cell(), SHA)
        self.assertEqual(result["candidate"]["latency_us"]["p99"], 1000)

    def test_absent_and_malformed_reports_fail_closed(self):
        for value in (None, {}, [], {"schema": gate.SCHEMA, "cells": []}):
            with self.subTest(value=value), self.assertRaises(gate.GateError):
                gate.validate_report(value, SHA)

    def test_missing_matrix_cell_is_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "matrix"):
            gate.validate_report(dict(schema=gate.SCHEMA, mode="promotion", source_sha256=SHA,
                                      source={"files": {"mix.exs": SHA}}, cells=[cell()]), SHA)

    def test_wrong_payload_and_missing_peer_exchange_fail(self):
        for mutate in (lambda x: x["arms"][1]["samples"][0].update(payload_sha256="b" * 64),
                       lambda x: x["arms"][1]["peer"]["requests"].pop()):
            value = cell("upload")
            mutate(value)
            with self.assertRaises(gate.GateError):
                gate.validate_cell(value, SHA)

    def test_pending_unsupported_and_missing_resource_proof_fail(self):
        for mutate in (lambda a: a["samples"][0].update(request_completion="unsupported"),
                       lambda a: a["retirement"].update(status="pending"),
                       lambda a: a.update(live_resources=None),
                       lambda a: a["retirement"].update(observer_exited=False)):
            value = cell()
            mutate(value["arms"][1])
            with self.assertRaises(gate.GateError):
                gate.validate_cell(value, SHA)

    def test_drift_over_twenty_percent_invalidates_trial(self):
        value = cell()
        for sample in value["arms"][2]["samples"]:
            sample["elapsed_us"] = 1201
        value["arms"][2]["wall_us"] = 1_201_000
        with self.assertRaisesRegex(gate.GateError, "environment.*drift"):
            gate.validate_cell(value, SHA)

    def test_latency_cleanup_and_goodput_budgets_are_enforced(self):
        for operation, mutate in (
            ("cold", lambda a: a["samples"][0]["cleanup"].update(elapsed_us=1_000_001)),
            ("reuse", lambda a: [s.update(elapsed_us=20_000) for s in a["samples"]]),
            ("upload", lambda a: a.update(wall_us=2_000_000)),
        ):
            value = cell(operation)
            mutate(value["arms"][1])
            with self.assertRaises(gate.GateError):
                gate.validate_cell(value, SHA)

    def test_wrong_protocol_source_gc_or_duplicate_id_fail(self):
        for mutate in (lambda a: a["peer"].update(tls="TLSv1.2"),
                       lambda a: a.update(source_sha256="b" * 64),
                       lambda a: a["effective"].update(forced_global_gc=True),
                       lambda a: a["samples"][0].update(id="1")):
            value = cell()
            mutate(value["arms"][1])
            with self.assertRaises(gate.GateError):
                gate.validate_cell(value, SHA)

    def test_short_sample_and_unproven_blocked_cancel_fail(self):
        for mutate in (lambda a: a.update(samples=a["samples"][:999]),
                       lambda a: a["samples"][0].update(blocked=None)):
            value = cell("cancel")
            mutate(value["arms"][1])
            with self.assertRaises(gate.GateError):
                gate.validate_cell(value, SHA)

    def test_matrix_has_all_workloads_trials_and_soak_connections(self):
        matrix = gate.matrix()
        self.assertEqual(len(matrix), 188)
        self.assertEqual(sum(c["kind"] == "measurement" for c in matrix), 180)
        self.assertEqual({c["concurrency"] for c in matrix if c["kind"] == "soak"}, {1, 100})


    def test_soak_duration_memory_plateau_and_fixed_connections(self):
        value = soak_cell()
        gate.validate_cell(value, SHA)
        for mutate in (lambda a: a.update(duration_us=1_799_999_999),
                       lambda a: a.update(completed_cycles=999),
                       lambda a: a["resource_samples"][0].update(live_connections=0),
                       lambda a: a.update(retirement_cycles=[]),
                       lambda a: a["retirement_cycles"][0]["after_retirement"].update(binary_memory_bytes=20_000_000)):
            broken = copy.deepcopy(value)
            mutate(broken["arms"][1])
            with self.assertRaises(gate.GateError):
                gate.validate_cell(broken, SHA)

    def test_wall_time_covers_longest_and_concurrent_sum_of_samples(self):
        for concurrency, wall, longest in ((1, 1, 1000), (1, 999999, 1000),
                                            (8, 124999, 1000), (8, 2000, 3000)):
            with self.subTest(concurrency=concurrency, wall=wall):
                value = cell("upload")
                value["concurrency"] = concurrency
                value["arms"] = [arm(value, phase) for phase in gate.PHASES]
                value["arms"][1]["wall_us"] = wall
                value["arms"][1]["samples"][0]["elapsed_us"] = longest
                with self.assertRaisesRegex(gate.GateError, "wall.*raw"):
                    gate.validate_cell(value, SHA)

    def test_soak_duration_is_same_wall_interval(self):
        value = soak_cell()
        value["arms"][1]["duration_us"] += 1
        with self.assertRaisesRegex(gate.GateError, "duration.*wall"):
            gate.validate_cell(value, SHA)

    def test_handshake_ids_are_positive_unique_and_bind_every_exchange(self):
        for workload in gate.WORKLOADS:
            for identifier in (None, 0, -1, True, "1", 999999):
                with self.subTest(workload=workload, identifier=identifier):
                    value = cell(workload)
                    value["arms"][1]["peer"]["handshakes"][0]["connection"] = identifier
                    with self.assertRaisesRegex(gate.GateError, "authenticated.*connection|handshake.*connection"):
                        gate.validate_cell(value, SHA)
        value = soak_cell()
        value["arms"][1]["peer"]["handshakes"][0]["connection"] = 999999
        with self.assertRaises(gate.GateError):
            gate.validate_cell(value, SHA)
        value = cell()
        value["arms"][1]["peer"]["handshakes"] *= 2
        value["arms"][1]["peer"].update(accepted_connections=2, closed_connections=2)
        with self.assertRaisesRegex(gate.GateError, "handshake.*connection"):
            gate.validate_cell(value, SHA)

    def test_repeated_soak_cleanup_enters_p99_without_duplicate_final_wait(self):
        value = soak_cell()
        result = gate.validate_cell(value, SHA)
        self.assertEqual(result["candidate"]["cleanup_us"]["n"], 3)
        for cycle in value["arms"][1]["retirement_cycles"][1:]:
            cycle["retirement"]["elapsed_us"] = 900000
        with self.assertRaisesRegex(gate.GateError, "cleanup p99"):
            gate.validate_cell(value, SHA)

    def test_runtime_requires_complete_typed_module_identity(self):
        mutations = [lambda r, name=name: r.pop(name) for name in
                     ("erts", "architecture", "schedulers", "beam_sha256")]
        mutations += [lambda r: r.update(erts=[]), lambda r: r.update(architecture=" "),
                      lambda r: r.update(schedulers=True), lambda r: r.update(schedulers=0),
                      lambda r: r["beam_sha256"].pop("Elixir.SSL.Lifecycle"),
                      lambda r: r["beam_sha256"].update({"Elixir.HTTP": "not-a-hash"})]
        for mutate in mutations:
            value = cell()
            for a in value["arms"]:
                mutate(a["runtime"])
            with self.subTest(runtime=value["arms"][1]["runtime"]), self.assertRaisesRegex(gate.GateError, "runtime|BEAM"):
                gate.validate_cell(value, SHA)

    def test_later_cold_cancel_provider_peak_and_missing_live_snapshot_fail(self):
        for workload in ("cold", "cancel"):
            for provider in (None, resources(0), dict(resources(), processes=7)):
                value = cell(workload)
                value["arms"][1]["samples"][-1]["public_snapshot"]["provider_resources"] = provider
                with self.subTest(workload=workload, provider=provider), self.assertRaises(gate.GateError):
                    gate.validate_cell(value, SHA)

    def test_cold_cancel_live_peaks_are_recomputed_from_every_sample(self):
        for workload in ("cold", "cancel"):
            value = cell(workload)
            for a in value["arms"]:
                a["samples"][-1]["public_snapshot"]["provider_resources"]["processes"] = 5
                a["live_resources"]["processes"] = 5
            result = gate.validate_cell(value, SHA)
            self.assertEqual(result["candidate"]["per_connection_resource_peaks"]["processes"], 5)

    def test_one_late_connection_cannot_hide_excess_inside_aggregate_allowance(self):
        for workload in ("cold", "cancel"):
            value = cell(workload)
            value["concurrency"] = 8
            value["arms"] = [arm(value, phase) for phase in gate.PHASES]
            candidate = value["arms"][1]
            candidate["samples"][-1]["public_snapshot"]["provider_resources"]["processes"] = 7
            candidate["live_resources"]["processes"] = 35
            with self.assertRaisesRegex(gate.GateError, "per-connection.*peak"):
                gate.validate_cell(value, SHA)

    def test_cancel_requires_snapshot_from_blocked_gate_before_cancel(self):
        value = cell("cancel")
        value["arms"][1]["samples"][-1]["public_snapshot_point"] = "after-cancel"
        with self.assertRaisesRegex(gate.GateError, "live snapshot"):
            gate.validate_cell(value, SHA)

    def test_provider_process_socket_and_resource_accumulation_fail(self):
        for mutate in (lambda a: a["live_resources"].update(processes=7),
                       lambda a: a["live_resources"].update(tcp_sockets=2),
                       lambda a: a["provider_after_retirement"].update(observers=1),
                       lambda a: a["after_retirement"].update(process_count=103)):
            value = cell()
            mutate(value["arms"][1])
            with self.assertRaises(gate.GateError):
                gate.validate_cell(value, SHA)

    def test_peer_parser_checks_payloads_without_starting_tls(self):
        import tls_migration_performance_peer as peer
        self.assertEqual(peer.parse_path("/perf/m-123/upload"), ("m-123", "upload"))
        self.assertEqual(peer.response_body("upload", gate.PAYLOAD), gate.PAYLOAD_SHA.encode())
        for path in ("/perf/../upload", "/perf/m-1/unbounded", "/perf/m-1/cold/extra"):
            with self.assertRaises(ValueError):
                peer.parse_path(path)
        with self.assertRaises(ValueError):
            peer.response_body("upload", b"wrong")

    def test_mocked_smoke_orchestration_preserves_raw_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with mocked_run(Path(directory), phase_only=True) as run:
                with self.assertRaises(gate.GateError):
                    gate.execute(run.args)
                report = json.loads((run.output / "report.json").read_text())
                self.assertEqual(report["mode"], "smoke")
                self.assertEqual([a["phase"] for a in report["cells"][0]["arms"]], ["candidate"])
                self.assertEqual(run.closed, 1)
                self.assertFalse((run.output / "validated.json").exists())
                self.assertEqual(len(report["failures"]), 1)

    def test_raw_artifact_loading_requires_exact_bytes_and_safe_paths(self):
        value = cell()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            refs = []
            for a in value["arms"]:
                path = base / (a["phase"] + ".json")
                path.write_text(json.dumps(a))
                refs.append(dict(phase=a["phase"], path=path.name, sha256=gate.sha(path.read_bytes())))
            indexed = dict(value, arms=refs)
            gate.validate_cell(gate.resolve_cell(indexed, base), SHA)
            (base / "candidate.json").write_text("{}")
            with self.assertRaisesRegex(gate.GateError, "hash"):
                gate.resolve_cell(indexed, base)
            refs[0]["path"] = "../missing.json"
            with self.assertRaisesRegex(gate.GateError, "unsafe"):
                gate.resolve_cell(indexed, base)

    def test_runner_failure_preserves_diagnostics_and_stops_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            with mocked_run(Path(directory), failed=True) as run:
                with self.assertRaisesRegex(gate.GateError, "runner failed"):
                    gate.execute(run.args)
                report = json.loads((run.output / "report.json").read_text())
                self.assertEqual(run.closed, 1)
                self.assertEqual(len(report["failures"]), 1)
                diagnostics = {a["path"]: a["sha256"] for a in report["diagnostics"]}
                for name in ("cell-000/candidate.json", "cell-000/candidate.log"):
                    self.assertEqual(diagnostics[name], gate.sha((run.output / name).read_bytes()))
                self.assertTrue((run.output / "cell-000" / "peer-final.json").exists())
                self.assertFalse((run.output / "validated.json").exists())

    def test_complete_candidate_smoke_routes_only_current_production(self):
        with tempfile.TemporaryDirectory() as directory, mocked_run(Path(directory)) as run:
            self.assertEqual(gate.execute(run.args), 2)
            self.assertEqual(len(run.launched), 24)
            self.assertEqual(run.closed, 24)
            self.assertEqual(run.builds, [("candidate", gate.ROOT)])
            for command, root, env, config in run.launched:
                self.assertEqual(root, gate.ROOT)
                self.assertEqual(config["phase"], "candidate")
                self.assertEqual(config["backend"], "ex_ssl")
                self.assertEqual(env["MIX_ENV"], "prod")
                self.assertTrue(env["MIX_BUILD_PATH"].startswith(str(run.output)))
                self.assertTrue(env["MIX_DEPS_PATH"].startswith(str(run.output)))
                self.assertEqual(command, ["mix", "run", "--no-compile", "-e", gate.RUNNER_WRAPPER])
                self.assertEqual((config["samples"], config["warmup"], config["soak_ms"]), (10, 3, 5000))
            self.assertTrue((run.output / "functional-validation.json").exists())
            self.assertFalse((run.output / "validated.json").exists())

    def test_reference_smoke_uses_archived_runner_in_isolated_brackets(self):
        with tempfile.TemporaryDirectory() as directory, mocked_run(Path(directory), reference=True) as run:
            self.assertEqual(gate.execute(run.args), 2)
            self.assertEqual(len(run.launched), 72)
            self.assertEqual(run.closed, 24)
            self.assertEqual(run.builds, [("candidate", gate.ROOT), ("reference", run.output / "otp-reference-source")])
            for index, (_, root, env, config) in enumerate(run.launched):
                phase = gate.PHASES[index % 3]
                name = "candidate" if phase == "candidate" else "reference"
                self.assertEqual(config["phase"], phase)
                self.assertEqual(config["backend"], gate.BACKEND_BY_PHASE[phase])
                self.assertEqual(root, gate.ROOT if name == "candidate" else run.output / "otp-reference-source")
                self.assertEqual(env["MIX_BUILD_PATH"], str(run.output / (name + "-build")))
                self.assertEqual(env["MIX_DEPS_PATH"], str(run.output / (name + "-deps")))
            report = json.loads((run.output / "report.json").read_text())
            self.assertNotEqual(report["sources"]["candidate"]["sha256"], report["sources"]["reference"]["sha256"])
            self.assertFalse((run.output / "validated.json").exists())

    def test_smoke_report_rejects_missing_cells_phases_and_corrupt_artifacts(self):
        with tempfile.TemporaryDirectory() as directory, mocked_run(Path(directory)) as run:
            gate.execute(run.args)
            report = json.loads((run.output / "report.json").read_text())
            for selected in (0, 6, 12, 18, 23):
                broken = copy.deepcopy(report)
                broken["cells"].pop(selected)
                with self.assertRaisesRegex(gate.GateError, "matrix"):
                    gate.validate_smoke_report(broken, run.args.candidate_sha256, run.output)
            for mutate in (lambda r: r["cells"][0]["arms"].clear(),
                           lambda r: r["cells"][0]["arms"].append(r["cells"][0]["arms"][0]),
                           lambda r: r["cells"][0]["arms"][0].update(path="../outside.json"),
                           lambda r: r["cells"][0]["arms"][0].update(sha256="f" * 64),
                           lambda r: r["sources"]["candidate"]["files"].update({"mix.lock": "f" * 64}),
                           lambda r: r.update(schema="http-fetch-tls-p4-v1")):
                broken = copy.deepcopy(report)
                mutate(broken)
                with self.assertRaises(gate.GateError):
                    gate.validate_smoke_report(broken, run.args.candidate_sha256, run.output)

    def test_smoke_functional_negatives_fail_closed_without_promotion_budgets(self):
        mutations = [
            ("reuse", lambda a: a.update(source_sha256="f" * 64)),
            ("reuse", lambda a: a.update(build_sha256="f" * 64)),
            ("reuse", lambda a: a["execution"].update(root="/wrong")),
            ("reuse", lambda a: a["runtime"].update(beam_sha256={n: "f" * 64 for n in gate.BEAM_MODULES})),
            ("reuse", lambda a: a["fixtures"].update({gate.FIXTURE_PATHS[-1]: "f" * 64})),
            ("reuse", lambda a: a["selected_transport"].update(module="Elixir.HTTP.Transport.SSL")),
            ("reuse", lambda a: a.update(phase="otp-before")),
            ("reuse", lambda a: a.update(otp_ssl={})),
            ("reuse", lambda a: a["otp_ssl"]["after"].update(loaded=True, started=True)),
            ("reuse", lambda a: a["peer"].update(cipher="wrong-cipher")),
            ("upload", lambda a: a["samples"][0].update(payload_sha256="f" * 64)),
            ("reuse", lambda a: a["peer"].update(errors=["peer failure"])),
            ("reuse", lambda a: a.update(failures=["runner failure"])),
            ("reuse", lambda a: a["peer"]["requests"].pop()),
            ("reuse", lambda a: a["samples"][0].update(request_completion="pending")),
            ("cancel", lambda a: a["samples"][0].update(blocked=None)),
            ("cancel", lambda a: a["samples"][0]["cleanup"].update(elapsed_us=1_000_001)),
            ("reuse", lambda a: a["retirement"].update(status="unconfirmed")),
            ("soak", lambda a: a.update(duration_us=4_999_999, wall_us=4_999_999)),
            ("soak", lambda a: a.update(completed_cycles=0)),
            ("soak", lambda a: a.update(resource_samples=[])),
            ("soak", lambda a: a["resource_samples"][0].pop("elapsed_us")),
        ]
        with tempfile.TemporaryDirectory() as directory, mocked_run(Path(directory)) as run:
            gate.execute(run.args)
            report = json.loads((run.output / "report.json").read_text())
            for workload, mutate in mutations:
                spec = next(c for c in report["cells"] if (c["kind"] == "soak" if workload == "soak" else c["kind"] == "measurement" and c["workload"] == workload))
                artifact = spec["arms"][0]
                path = run.output / artifact["path"]
                original = path.read_bytes()
                value = json.loads(original)
                mutate(value)
                path.write_text(json.dumps(value))
                original_sha = artifact["sha256"]
                artifact["sha256"] = gate.sha(path.read_bytes())
                with self.subTest(workload=workload, mutation=mutate), self.assertRaises(gate.GateError):
                    gate.validate_smoke_report(report, run.args.candidate_sha256, run.output)
                path.write_bytes(original)
                artifact["sha256"] = original_sha
            # Functional smoke allows slow samples and >500ms cleanup, up to
            # the unchanged 1000ms functional deadline; it proves no load budget.
            source = report["sources"]["candidate"]
            spec = gate.smoke_matrix()[0]
            value = smoke_arm(spec, "candidate", source)
            for sample in value["samples"]:
                sample["elapsed_us"] = 200000
                sample["cleanup"]["elapsed_us"] = 900000
            value["wall_us"] = 2_000_000
            gate.validate_arm(value, spec, source["sha256"], smoke=True, source=source)

    def test_reference_provenance_and_bracket_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, mocked_run(Path(directory), reference=True) as run:
            gate.execute(run.args)
            report = json.loads((run.output / "report.json").read_text())
            for mutate in (lambda r: r["sources"]["reference"].update(requested_commit="f" * 40),
                           lambda r: r["sources"]["reference"]["archive"].update(sha256="f" * 64),
                           lambda r: r["cells"][0]["arms"].reverse()):
                broken = copy.deepcopy(report)
                mutate(broken)
                with self.assertRaises(gate.GateError):
                    gate.validate_smoke_report(broken, run.args.candidate_sha256, run.output)
            for phase, mutate in (("otp-before", lambda a: a.update(source_sha256=report["sources"]["candidate"]["sha256"])),
                                  ("candidate", lambda a: a["execution"].update(root=str(run.output / "otp-reference-source"))),
                                  ("otp-after", lambda a: a["runtime"].update(erts="changed")),
                                  ("otp-after", lambda a: a["peer"].update(identity="f" * 64)),
                                  ("otp-after", lambda a: a["effective"].update(cipher_policy="changed"))):
                artifact = next(a for a in report["cells"][0]["arms"] if a["phase"] == phase)
                path = run.output / artifact["path"]
                original = path.read_bytes()
                value = json.loads(original)
                mutate(value)
                path.write_text(json.dumps(value))
                original_sha = artifact["sha256"]
                artifact["sha256"] = gate.sha(path.read_bytes())
                with self.assertRaises(gate.GateError):
                    gate.validate_smoke_report(report, run.args.candidate_sha256, run.output)
                path.write_bytes(original)
                artifact["sha256"] = original_sha

    def test_build_uses_locked_prod_owned_paths_and_sequential_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "source"
            output = base / "output"
            root.mkdir()
            output.mkdir()
            (root / "mix.lock").write_text("locked")
            source = source_fixture("candidate", root, output)
            source["files"]["mix.lock"] = gate.sha(b"locked")
            source["sha256"] = gate.digest(source["files"])
            beam_dir = output / "candidate-build/lib/fixture/ebin"
            beam_dir.mkdir(parents=True)
            for module in source["build"]["beam_sha256"]:
                (beam_dir / (module + ".beam")).write_bytes(b"compiled fixture")
            with patch.object(gate, "fingerprint", return_value=source), \
                 patch.object(gate, "run_owned", return_value=0) as command:
                env = gate.build_source("candidate", root, source, output)
            self.assertEqual(command.call_count, 2)
            self.assertEqual([c.args[0] for c in command.call_args_list],
                             [["mix", "deps.get", "--check-locked"], ["mix", "compile", "--warnings-as-errors"]])
            self.assertTrue(all(c.args[1] == root for c in command.call_args_list))
            self.assertEqual(env["MIX_ENV"], "prod")
            self.assertEqual(env["MIX_BUILD_PATH"], str(output / "candidate-build"))
            self.assertEqual(env["MIX_DEPS_PATH"], str(output / "candidate-deps"))
            self.assertEqual(source["build"]["lock_before"], source["build"]["lock_after"])
            self.assertEqual(source["build"]["exits"], [0, 0])
            self.assertEqual(source["build"]["sha256"], gate.digest({k: v for k, v in source["build"].items() if k != "sha256"}))
            def mutate_lock(*_args):
                (root / "mix.lock").write_text("changed")
                return 0
            with patch.object(gate, "run_owned", side_effect=mutate_lock), self.assertRaisesRegex(gate.GateError, "changed lockfile"):
                gate.build_source("candidate", root, source, output)

    def test_runner_timeout_and_failed_leader_clean_owned_process_group(self):
        class FakeProcess:
            pid = 12345
            def __init__(self, *_args, **_kwargs):
                self.calls = 0
            def wait(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired("fixture", 1)
                return 7
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate.subprocess, "Popen", FakeProcess), patch.object(gate.os, "killpg") as kill:
                with self.assertRaises(subprocess.TimeoutExpired):
                    gate.run_owned(["mix"], gate.ROOT, {}, Path(directory) / "runner.log", 1)
                self.assertEqual(kill.call_args_list[0].args, (12345, gate.signal.SIGTERM))
                self.assertEqual(kill.call_args_list[-1].args, (12345, gate.signal.SIGKILL))
            # The launcher has already exited, but its owned group is still signalled.
            process = SimpleNamespace(pid=12345, wait=lambda **_kwargs: 7)
            with patch.object(gate.os, "killpg") as kill:
                gate.stop_owned(process)
                self.assertEqual(kill.call_count, 2)

    def test_unknown_backend_execute_rejects_before_peer_build_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(output=Path(directory) / "run", candidate_sha256=SHA,
                                   smoke=True, backend="ssl")
            with patch.object(gate, "PeerProcess") as peer, patch.object(gate, "build_source") as build:
                with self.assertRaisesRegex(gate.GateError, "ex_ssl"):
                    gate.execute(args)
                peer.assert_not_called()
                build.assert_not_called()
                self.assertFalse(args.output.exists())
        runner = (gate.ROOT / "scripts/tls_migration_performance.exs").read_text()
        self.assertLess(runner.index('if config["backend"] != "ex_ssl"'), runner.index("scopes = open_scopes"))
        self.assertNotIn('else: :ssl', runner)

    def test_cli_smoke_validation_exit_is_incomplete_and_malformed_is_fail(self):
        with tempfile.TemporaryDirectory() as directory, mocked_run(Path(directory)) as run:
            with redirect_stdout(io.StringIO()):
                gate.execute(run.args)
            argv = ["performance", "validate", str(run.output / "report.json"), "--candidate-sha256", run.args.candidate_sha256]
            with patch.object(gate.sys, "argv", argv), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(gate.main(), 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "INCOMPLETE")
            report = json.loads((run.output / "report.json").read_text())
            artifact = report["cells"][0]["arms"][0]
            path = run.output / artifact["path"]
            path.write_text(json.dumps(dict(phase="candidate")))
            artifact["sha256"] = gate.sha(path.read_bytes())
            (run.output / "report.json").write_text(json.dumps(report))
            with patch.object(gate.sys, "argv", argv), redirect_stderr(io.StringIO()) as output:
                self.assertEqual(gate.main(), 1)
                self.assertEqual(json.loads(output.getvalue())["status"], "FAIL")
            self.assertFalse((run.output / "validated.json").exists())

    def test_cli_malformed_report_and_nested_evidence_emit_structured_fail(self):
        with tempfile.TemporaryDirectory() as directory, mocked_run(Path(directory)) as run:
            with redirect_stdout(io.StringIO()):
                gate.execute(run.args)
            report_path = run.output / "report.json"
            original_report = json.loads(report_path.read_text())
            argv = ["performance", "validate", str(report_path), "--candidate-sha256", run.args.candidate_sha256]
            cases = [("null-report", None), ("list-report", []), ("integer-artifact-path", "path"),
                     ("null-soak-observation", "observation"), ("null-retirement-cycle", "retirement"),
                     ("null-arms", "arms"), ("null-build-beams", "beams"), ("list-cell-protocol", "protocol"),
                     ("list-peer-identity", "peer_identity"), ("list-peer-cipher", "peer_cipher"),
                     ("list-peer-request-id", "peer_request_id")]
            for label, mutation in cases:
                report = copy.deepcopy(original_report)
                arm_path = None
                original_arm = None
                if mutation in ("observation", "retirement", "peer_identity", "peer_cipher", "peer_request_id"):
                    spec = next(c for c in report["cells"] if c["kind"] == ("soak" if mutation in ("observation", "retirement") else "measurement"))
                    artifact = spec["arms"][0]
                    arm_path = run.output / artifact["path"]
                    original_arm = arm_path.read_bytes()
                    value = json.loads(original_arm)
                    if mutation in ("observation", "retirement"):
                        value["resource_samples" if mutation == "observation" else "retirement_cycles"][0] = None
                    elif mutation == "peer_request_id":
                        value["peer"]["requests"][0]["id"] = []
                    else:
                        value["peer"]["identity" if mutation == "peer_identity" else "cipher"] = []
                    arm_path.write_text(json.dumps(value))
                    artifact["sha256"] = gate.sha(arm_path.read_bytes())
                elif mutation == "path":
                    report["cells"][0]["arms"][0]["path"] = 17
                elif mutation == "arms":
                    report["cells"][0]["arms"] = None
                elif mutation == "beams":
                    build = report["sources"]["candidate"]["build"]
                    build["beam_sha256"] = None
                    build["sha256"] = gate.digest({k: v for k, v in build.items() if k != "sha256"})
                elif mutation == "protocol":
                    report["cells"][0]["protocol"] = []
                else:
                    report = mutation
                report_path.write_text(json.dumps(report))
                try:
                    with self.subTest(case=label), patch.object(gate.sys, "argv", argv), \
                         redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                        self.assertEqual(gate.main(), 1)
                        self.assertEqual(stdout.getvalue(), "")
                        failure = json.loads(stderr.getvalue())
                        self.assertEqual(failure["status"], "FAIL")
                        self.assertNotIn("Traceback", stderr.getvalue())
                finally:
                    if arm_path is not None:
                        arm_path.write_bytes(original_arm)

    def test_cli_normalizes_remaining_schema_type_errors_to_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report_path.write_text(json.dumps(dict(schema=gate.SCHEMA, mode="smoke")))
            argv = ["performance", "validate", str(report_path), "--candidate-sha256", SHA]
            for error in (TypeError, AttributeError, KeyError, IndexError, OverflowError):
                with self.subTest(error=error.__name__), patch.object(gate.sys, "argv", argv), \
                     patch.object(gate, "validate_smoke_report", side_effect=error("malformed fixture field")), \
                     redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(gate.main(), 1)
                    self.assertEqual(json.loads(stderr.getvalue())["status"], "FAIL")
                    self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_source_cell_and_raw_reports_fail_closed(self):
        for value in (None, {}, {"schema": gate.SCHEMA, "mode": "smoke", "cells": [None]},
                      {"schema": "http-fetch-tls-p4-v1", "mode": "smoke", "cells": []}):
            with self.assertRaises(gate.GateError):
                gate.validate_smoke_report(value, SHA)

    def test_v2_smoke_matrix_is_complete(self):
        self.assertEqual(gate.SCHEMA, "http-fetch-tls-p4-v2")
        cells = gate.smoke_matrix()
        self.assertEqual(len(cells), 24)
        self.assertEqual(sum(c["kind"] == "measurement" for c in cells), 20)
        self.assertEqual({c["protocol"] for c in cells}, {"http/1.1", "h2"})
        self.assertEqual({c["tls"] for c in cells}, {"TLSv1.2", "TLSv1.3"})

    def test_non_smoke_requires_reference_before_build_or_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            args = type("Args", (), dict(output=Path(directory) / "run",
                        candidate_sha256=SHA, smoke=False, python="unused"))()
            with patch.object(gate.subprocess, "run") as build, patch.object(gate, "PeerProcess") as peer:
                with self.assertRaisesRegex(gate.GateError, "otp-reference-sha"):
                    gate.execute(args)
                build.assert_not_called()
                peer.assert_not_called()

    def test_unknown_backend_is_rejected_before_launch(self):
        for value in (None, "ssl", "otp", "", "bogus"):
            with self.assertRaises(gate.GateError):
                gate.candidate_backend(value)

    def test_smoke_is_never_promotion(self):
        with self.assertRaisesRegex(gate.GateError, "promotion"):
            gate.validate_report(dict(schema=gate.SCHEMA, mode="smoke", cells=[]), SHA)


if __name__ == "__main__":
    unittest.main()

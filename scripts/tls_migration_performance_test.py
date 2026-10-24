"""Pure P4 gate tests. No peer, socket, subprocess or BEAM execution."""
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
                    request_completion="confirmed", cancellation_us=1000 if operation == "cancel" else None, connection=i + 1 if operation in ("cold", "cancel") else i % cell["concurrency"] + 1,
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
                source_sha256=SHA, runtime=dict(otp="29", elixir="1.19", host="fixture",
                    erts="17.0", architecture="fixture-architecture", schedulers=4,
                    beam_sha256={"Elixir." + name: SHA for name in BEAM_MODULES}),
                effective=dict(verify="verify_peer", tls=cell["tls"], alpn=cell["protocol"],
                               cipher_policy="ecdhe-aes128gcm", payload_bytes=1048576,
                               concurrency=connections, pool_connections=connections,
                               warmup=1, warm_state="fresh-scope-per-arm", forced_global_gc=False),
                warmup=[dict(id="warmup", payload_ok=True, request_completion="confirmed")],
                samples=samples, wall_us=1000 * count, failures=[],
                peer=dict(identity=SHA, errors=[], tls=cell["tls"], alpn=cell["protocol"],
                          cipher="AES128-GCM", resumed=False, requests=requests,
                          handshakes=[dict(connection=i + 1, tls=cell["tls"], alpn=cell["protocol"], cipher="AES128-GCM", resumed=False) for i in range(count if operation in ("cold", "cancel") else connections)],
                          warmup_requests=1, accepted_connections=count if operation in ("cold", "cancel") else connections,
                          closed_connections=count if operation in ("cold", "cancel") else connections,
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
        observation = dict(vm=vm(), provider=resources(), live_connections=1)
        a.update(wall_us=1_800_000_000, duration_us=1_800_000_000, completed_cycles=1000,
                 resource_samples=[dict(observation, elapsed_us=i * 1_800_000) for i in range(1000)],
                 retirement_cycles=[dict(baseline=vm(), after_retirement=vm(), observation_ms=2000,
                                         retirement=copy.deepcopy(a["retirement"])) for _ in range(3)])
    return value


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
        class FakePeer:
            closed = 0
            def __init__(self, *_args):
                self.ready = dict(event="ready", port=1234, identity=SHA)
            def command(self, command):
                return dict(event=command)
            def close(self):
                FakePeer.closed += 1

        class FakeRunner:
            pid = 12345
            def __init__(self, _command, **kwargs):
                self.config = json.loads(Path(kwargs["env"]["TLS_PERF_CONFIG"]).read_text())
            def wait(self, **_kwargs):
                Path(self.config["output"]).write_text(json.dumps(dict(phase=self.config["phase"])))
                return 0

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            args = type("Args", (), dict(output=output, candidate_sha256=SHA, smoke=True, python="unused"))()
            with patch.object(gate, "fingerprint", return_value=dict(sha256=SHA, files={"fixture": SHA})), \
                 patch.object(gate, "PeerProcess", FakePeer), \
                 patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                 patch.object(gate.subprocess, "check_output", return_value="head"), \
                 patch.object(gate.subprocess, "Popen", FakeRunner):
                self.assertEqual(gate.execute(args), 2)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(report["mode"], "smoke")
            self.assertEqual([a["phase"] for a in report["cells"][0]["arms"]], list(gate.PHASES))
            self.assertEqual(FakePeer.closed, 1)
            self.assertFalse((output / "validated.json").exists())
            with self.assertRaises(gate.GateError):
                gate.validate_report(report, SHA)

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
        class FakePeer:
            closed = 0
            def __init__(self, *_args):
                self.ready = dict(event="ready", port=1234, identity=SHA)
            def command(self, command):
                return dict(event=command)
            def close(self):
                FakePeer.closed += 1

        class FailedRunner:
            pid = 12345
            def __init__(self, *_args, **_kwargs):
                pass
            def wait(self, **_kwargs):
                return 7

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            args = type("Args", (), dict(output=output, candidate_sha256=SHA, smoke=True, python="unused"))()
            with patch.object(gate, "fingerprint", return_value=dict(sha256=SHA, files={"fixture": SHA})), \
                 patch.object(gate, "PeerProcess", FakePeer), \
                 patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                 patch.object(gate.subprocess, "check_output", return_value="head"), \
                 patch.object(gate.subprocess, "Popen", FailedRunner):
                with self.assertRaisesRegex(gate.GateError, "runner failed"):
                    gate.execute(args)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual(FakePeer.closed, 1)
            self.assertEqual(len(report["failures"]), 1)
            self.assertTrue((output / "cell-000" / "peer-final.json").exists())
            self.assertFalse((output / "validated.json").exists())

    def test_smoke_is_never_promotion(self):
        with self.assertRaisesRegex(gate.GateError, "promotion"):
            gate.validate_report(dict(schema=gate.SCHEMA, mode="smoke", cells=[]), SHA)


if __name__ == "__main__":
    unittest.main()

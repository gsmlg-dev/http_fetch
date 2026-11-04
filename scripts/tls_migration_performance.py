#!/usr/bin/env python3
"""P4 source-candidate load gate. `run` launches real peers/BEAM; `validate` is pure.

Run only after public P2/P3 acceptance, with exclusive runtime ownership:
  python3 scripts/tls_migration_performance.py fingerprint
  python3 scripts/tls_migration_performance.py run --smoke --candidate-sha256 SHA --output /tmp/p4-smoke
  python3 scripts/tls_migration_performance.py run --otp-reference-sha COMMIT --candidate-sha256 SHA --output /tmp/p4-run
  python3 scripts/tls_migration_performance.py validate /tmp/p4-run/report.json --candidate-sha256 SHA

Promotion is fail closed. Smoke creates diagnostics and exits incomplete (2).
No historical P0 report can be consumed as this schema. Raw arm files and runner
logs are retained, including failed/unstable trials. No outlier/trial deletion.
"""
import argparse
from collections import Counter
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import tarfile
import threading
import time

SCHEMA = "http-fetch-tls-p4-v2"
DEFAULT_OTP_REFERENCE = "1ef7a51721138d533ea30b3237da1fd96e8a8712"
BACKEND_BY_PHASE = {"otp-before": "ssl", "candidate": "ex_ssl", "otp-after": "ssl"}
PHASES = ("otp-before", "candidate", "otp-after")
WORKLOADS = ("cold", "reuse", "upload", "download", "cancel")
PAYLOAD = b"Z" * 1_048_576
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()
UPLOAD_REPLY_SHA = hashlib.sha256(PAYLOAD_SHA.encode()).hexdigest()
SMALL_SHA = hashlib.sha256(b"ok").hexdigest()
BEAM_MODULES = {"Elixir." + name for name in ("HTTP", "HTTP.Promise", "HTTP.Response",
                "HTTP.RequestCompletion", "HTTP.ManagedTransport", "SSL", "SSL.Lifecycle")}
ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATHS = tuple("apps/http_fetch/test/support/fixtures/" + name
                      for name in ("localhost.pem", "localhost.key", "localhost-ca.pem"))


class GateError(ValueError):
    """Missing/invalid evidence or a measured promotion budget violation."""


def require(condition, reason):
    if not condition:
        raise GateError(reason)


def number(value, name, minimum=0):
    require(type(value) in (int, float) and math.isfinite(value) and value >= minimum,
            f"invalid numeric evidence: {name}")
    return value


def sha(value):
    return hashlib.sha256(value).hexdigest()


def summary(values):
    require(bool(values), "zero raw samples")
    values = sorted(number(v, "sample", 0) for v in values)
    return {"n": len(values), **{f"p{p}": values[math.ceil(len(values) * p / 100) - 1]
                               for p in (50, 95, 99)}, "min": values[0], "max": values[-1]}


def matrix():
    cells = []
    for trial, protocol, tls in itertools.product(range(1, 4), ("http/1.1", "h2"), ("TLSv1.2", "TLSv1.3")):
        for concurrency, workload in itertools.product((1, 8, 32), WORKLOADS):
            cells.append(dict(kind="measurement", trial=trial, protocol=protocol,
                              tls=tls, concurrency=concurrency, workload=workload))
        for concurrency in (() if trial != 1 else (1, 100)):
            cells.append(dict(kind="soak", trial=trial, protocol=protocol, tls=tls,
                              concurrency=concurrency, workload="reuse"))
    return cells


def smoke_matrix():
    cells = []
    for protocol, tls in itertools.product(("http/1.1", "h2"), ("TLSv1.2", "TLSv1.3")):
        for workload in WORKLOADS:
            cells.append(dict(kind="measurement", trial=1, protocol=protocol,
                              tls=tls, concurrency=1, workload=workload))
        cells.append(dict(kind="soak", trial=1, protocol=protocol, tls=tls,
                          concurrency=1, workload="reuse"))
    return cells


def candidate_backend(value):
    require(value == "ex_ssl", "current-source backend must be ex_ssl")
    return value


def digest(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def hash_value(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def key(cell):
    fields = ("kind", "trial", "protocol", "tls", "concurrency", "workload")
    require(isinstance(cell, dict) and all(type(cell.get(k)) is (int if k in ("trial", "concurrency") else str)
            for k in fields), "malformed matrix cell identity")
    return tuple(cell[k] for k in fields)


def resource_counts(value, connections, label):
    require(isinstance(value, dict), f"missing public provider enumeration: {label}")
    for name in ("processes", "tcp_sockets", "generations", "observers", "data_resources"):
        require(type(value.get(name)) is int and value[name] >= 0, f"missing public provider count {label}.{name}")
    require(value["tcp_sockets"] == connections, f"wrong underlying TCP socket count: {label}")
    require(value["generations"] == connections, f"generation accumulation: {label}")
    return value


def cleanup(value):
    require(isinstance(value, dict) and value.get("status") == "confirmed", "ordinary cleanup is pending/unsupported/unconfirmed")
    elapsed = number(value.get("elapsed_us"), "cleanup elapsed")
    require(elapsed <= 1_000_000, "ordinary cleanup exceeds 1000ms")
    require(value.get("retired_data_resources") == 0 and value.get("observer_exited") is True,
            "missing enrolled-resource/observer retirement proof")
    return elapsed


def memory(value):
    require(isinstance(value, dict), "missing VM/RSS observation")
    for field in ("process_count", "port_count", "process_memory_bytes", "binary_memory_bytes", "total_memory_bytes", "rss_bytes"):
        number(value.get(field), field)
    return value


def validate_arm(arm, cell, expected_source, smoke=False, source=None):
    require(isinstance(arm, dict), "malformed arm")
    phase = arm.get("phase")
    require(phase in PHASES and arm.get("backend") == ("ex_ssl" if phase == "candidate" else "ssl"), "wrong backend/order identity")
    require(arm.get("source_sha256") == expected_source, "wrong candidate/source identity")
    runtime = arm.get("runtime")
    require(isinstance(runtime, dict) and all(isinstance(runtime.get(x), str) and runtime[x].strip()
            for x in ("otp", "elixir", "host", "erts", "architecture")), "missing/malformed runtime identity")
    require(type(runtime.get("schedulers")) is int and runtime["schedulers"] > 0, "invalid runtime schedulers")
    beams = runtime.get("beam_sha256")
    require(isinstance(beams, dict) and set(beams) == BEAM_MODULES and
            all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in beams.values()), "missing/malformed runtime BEAM identity")
    require(hash_value(arm.get("build_sha256")), "missing build identity")
    selected = arm.get("selected_transport", {})
    require(isinstance(selected, dict), "malformed selected transport identity")
    transport = "Elixir.HTTP.Transport.ExSSL" if phase == "candidate" else "Elixir.HTTP.Transport.SSL"
    require(selected.get("module") == transport and hash_value(selected.get("beam_sha256")), "wrong selected transport identity")
    require(isinstance(arm.get("fixtures"), dict) and set(arm["fixtures"]) == set(FIXTURE_PATHS) and
            all(hash_value(v) for v in arm["fixtures"].values()), "missing fixture hashes")
    if phase == "candidate":
        states = arm.get("otp_ssl", {})
        require(isinstance(states, dict) and set(states) == {"before", "after"} and all(isinstance(v, dict) and
                set(v) == {"loaded", "started"} and all(type(b) is bool for b in v.values())
                for v in states.values()), "missing candidate OTP loaded/started observations")
        require(states["before"] == states["after"], "candidate workload changed OTP loaded/started state")
    if source is not None:
        build = source["build"]
        require(arm["build_sha256"] == build["sha256"] and arm.get("execution") == build["execution"], "wrong source/build execution identity")
        require(beams == {name: build["beam_sha256"][name] for name in BEAM_MODULES}, "runtime BEAM differs from own build")
        require(selected["beam_sha256"] == build["beam_sha256"][transport], "selected transport BEAM differs from own build")
        require(arm["fixtures"] == source["fixtures"], "runner fixture identity changed")
    effective = arm.get("effective", {})
    require(effective.get("verify") == "verify_peer" and effective.get("tls") == cell["tls"] and effective.get("alpn") == cell["protocol"], "wrong effective verification/TLS/ALPN")
    require(effective.get("payload_bytes") == len(PAYLOAD) and effective.get("concurrency") == cell["concurrency"] and effective.get("pool_connections") == cell["concurrency"], "unmatched payload/pool/concurrency")
    require(effective.get("forced_global_gc") is False and
            effective.get("cipher_policy") == "ecdhe-rsa-aes128gcm-tls12/aes128gcm-sha256-tls13" and
            effective.get("warm_state") == "fresh-scope-per-arm", "missing/wrong policy or forced global GC")
    warmup = arm.get("warmup")
    require(isinstance(warmup, list) and warmup and all(isinstance(w, dict) for w in warmup) and effective.get("warmup") == len(warmup), "missing warmup")
    require(all(isinstance(w.get("id"), str) and w["id"] for w in warmup) and len({w["id"] for w in warmup}) == len(warmup), "missing/duplicate warmup exchange ID")
    require(all(w.get("payload_ok") is True and w.get("request_completion") == "confirmed" for w in warmup), "failed warmup")
    require(arm.get("failures") == [], "failed exchanges/runner failures")
    peer = arm.get("peer", {})
    require(isinstance(peer, dict), "malformed independent peer evidence")
    require(peer.get("errors") == [] and re.fullmatch(r"[0-9a-f]{64}", str(peer.get("identity", ""))), "missing/failed independent peer")
    require(peer.get("tls") == cell["tls"] and peer.get("alpn") == cell["protocol"] and peer.get("cipher") == ("TLS_AES_128_GCM_SHA256" if cell["tls"] == "TLSv1.3" else "ECDHE-RSA-AES128-GCM-SHA256") and peer.get("resumed") is False, "wrong authenticated peer TLS/ALPN/cipher")
    samples = arm.get("samples")
    minimum = 1 if smoke else 1000
    require(isinstance(samples, list) and all(isinstance(s, dict) for s in samples) and len(samples) >= minimum, f"fewer than {minimum} measured raw samples")
    if smoke:
        require(cell["kind"] != "measurement" or len(samples) == 10, "smoke measurement must contain exactly ten samples")
        require(len(warmup) == (9 if cell["kind"] == "soak" else 3), "wrong smoke warmup count")
    ids = [s.get("id") for s in samples]
    require(all(isinstance(i, str) and i for i in ids) and len(ids) == len(set(ids)), "missing/duplicate sample ID")
    records = peer.get("requests")
    require(isinstance(records, list) and all(isinstance(r, dict) for r in records), "missing raw peer exchanges")
    require(all(isinstance(r.get("id"), str) and r["id"] for r in records), "malformed peer request ID")
    require(Counter(r["id"] for r in records) == Counter(ids), "missing/duplicate/replayed peer exchange")
    require(peer.get("warmup_requests") == len(warmup), "wrong peer warmup count")
    handshakes = peer.get("handshakes")
    require(isinstance(handshakes, list) and handshakes and all(isinstance(h, dict) for h in handshakes) and len(handshakes) == peer.get("accepted_connections"), "missing raw authenticated handshakes")
    require(all(h.get("tls") == cell["tls"] and h.get("alpn") == cell["protocol"] and h.get("cipher") == peer["cipher"] and h.get("resumed") is False for h in handshakes), "unauthenticated/mismatched handshake")
    connection_ids = [h.get("connection") for h in handshakes]
    require(all(type(i) is int and i > 0 for i in connection_ids) and len(set(connection_ids)) == len(connection_ids), "invalid/duplicate handshake connection ID")
    require(set(connection_ids) == set(range(1, len(connection_ids) + 1)), "nonsequential handshake connection identity")
    expected_connections = cell["concurrency"] * (3 if cell["kind"] == "soak" else 1)
    if cell["kind"] == "measurement" and cell["workload"] in ("cold", "cancel"):
        expected_connections += len(samples)
    require(len(connection_ids) == expected_connections, "wrong exact peer connection count")
    authenticated_connections = set(connection_ids)
    require(peer.get("accepted_connections") == peer.get("closed_connections") and peer.get("active_connections") == 0, "peer connection retirement incomplete")
    record_map = {r["id"]: r for r in records}
    timings, cleanups, sample_resources = [], [], []
    expected_payload = PAYLOAD_SHA if cell["workload"] == "download" else UPLOAD_REPLY_SHA if cell["workload"] == "upload" else SMALL_SHA
    for sample in samples:
        timings.append(number(sample.get("elapsed_us"), "elapsed_us", 0.001))
        require(sample.get("request_completion") == "confirmed", "unsupported/pending request completion")
        record = record_map[sample["id"]]
        require(type(sample.get("connection")) is int and sample["connection"] in authenticated_connections and
                type(record.get("connection")) is int and record["connection"] in authenticated_connections,
                "measured exchange lacks authenticated handshake connection")
        require(record.get("connection") == sample.get("connection") and record.get("operation") == cell["workload"] and record.get("payload_ok") is True, "wrong peer request/payload/connection")
        if cell["workload"] == "cancel":
            blocked = sample.get("blocked")
            require(isinstance(blocked, dict) and blocked.get("peer_gate") is True and blocked.get("completion_pending") is True and blocked.get("source") == "peer-read-or-flow-control-gate", "unproven blocked-output cancellation")
            cancellation_us = number(sample.get("cancellation_us"), "cancellation_us")
            require(isinstance(sample.get("cleanup"), dict) and sample["cleanup"].get("elapsed_us", -1) >= cancellation_us, "cleanup omitted public cancellation wait")
            require(record.get("cancelled") is True and record.get("completed") is False and sample.get("payload_sha256") is None, "cancellation exchanged a successful response")
        else:
            require(sample.get("payload_sha256") == expected_payload and record.get("completed") is True and record.get("cancelled") is False, "incorrect response payload")
        if cell["workload"] in ("cold", "cancel"):
            cleanups.append(cleanup(sample.get("cleanup")))
            point = "blocked-before-cancel" if cell["workload"] == "cancel" else "response-complete-before-retirement"
            require(sample.get("public_snapshot_point") == point, "missing truthful live snapshot point")
            snapshot = sample.get("public_snapshot")
            require(isinstance(snapshot, dict), "missing public live snapshot")
            sample_resources.append(resource_counts(snapshot.get("provider_resources"), 1, "sample live"))
    for operation in ("upload", "download"):
        expected_bytes = len(samples) * len(PAYLOAD) if cell["workload"] == operation else 0
        require(peer.get(operation + "_bytes") == expected_bytes, "wrong independent payload byte count")
    connections = cell["concurrency"]
    if cell["kind"] == "measurement" and cell["workload"] in ("cold", "cancel"):
        require(len({s["connection"] for s in samples}) == len(samples), "cold/cancel connection was reused")
    elif cell["kind"] == "measurement":
        require(len({s["connection"] for s in samples}) == connections, "wrong reused connection count")
    live = resource_counts(arm.get("live_resources"), connections, "live")
    per_connection_peaks = None
    if sample_resources:
        per_connection_peaks = {f: max(r[f] for r in sample_resources) for f in live}
        batch_peaks = {f: max(sum(r[f] for r in sample_resources[i:i + connections])
                             for i in range(0, len(sample_resources), connections)) for f in live}
        require(live == batch_peaks, "reported live resources omit measured batch peaks")
    cleanups.append(cleanup(arm.get("retirement")))
    require(arm.get("observation_ms") == 2000, "retirement observation must be fixed 2s")
    baseline, after = memory(arm.get("baseline")), memory(arm.get("after_retirement"))
    retired = resource_counts(arm.get("provider_after_retirement"), 0, "retired")
    require(all(v == 0 for v in retired.values()), "provider resources survived retirement")
    require(smoke or after["binary_memory_bytes"] <= baseline["binary_memory_bytes"] + 8 * 1024**2 and after["process_count"] <= baseline["process_count"] + 2 and after["port_count"] <= baseline["port_count"], "retirement memory/process/port drift")
    wall = number(arm.get("wall_us"), "wall_us", 0.001)
    require(wall >= max(timings) and wall * connections >= math.fsum(timings), "wall time contradicts raw sample durations/concurrency")
    result = dict(latency_us=summary(timings), live_resources=live, per_connection_resource_peaks=per_connection_peaks,
                  goodput_mib_s=len(samples) / (wall / 1_000_000) if cell["workload"] in ("upload", "download") else None)
    if cell["kind"] == "soak":
        require(number(arm.get("duration_us"), "soak duration") >= (5_000_000 if smoke else 1_800_000_000) and type(arm.get("completed_cycles")) is int and arm["completed_cycles"] >= (1 if smoke else 1000), "short/incomplete soak (30-minute promotion minimum)")
        require(arm["duration_us"] == wall, "soak duration differs from measured wall interval")
        require(len(samples) == arm["completed_cycles"] * connections, "incomplete per-connection soak cycles")
        observations = arm.get("resource_samples")
        require(isinstance(observations, list) and all(isinstance(o, dict) for o in observations) and len(observations) >= (1 if smoke else 1000), "missing raw soak observations")
        timestamps = [number(o.get("elapsed_us"), "soak observation timestamp") for o in observations]
        require(timestamps == sorted(set(timestamps)) and timestamps[-1] <= wall, "invalid soak observation timestamps")
        for observation in observations:
            resource_counts(observation.get("provider"), connections, "soak")
            memory(observation.get("vm"))
            require(observation.get("live_connections") == connections, "soak lost fixed live connections")
        require(smoke or max(o["elapsed_us"] for o in observations) - min(o["elapsed_us"] for o in observations) >= 1_798_000_000, "soak observations do not span 30 minutes")
        require(len({s["connection"] for s in samples}) == connections, "soak reconnect/generation accumulation")
        retirement_cycles = arm.get("retirement_cycles")
        require(isinstance(retirement_cycles, list) and all(isinstance(c, dict) for c in retirement_cycles) and len(retirement_cycles) >= 2, "missing repeated retirement plateau cycles")
        require(all(retirement_cycles[0].get(f) == arm.get(f) for f in
                    ("retirement", "baseline", "after_retirement", "observation_ms")), "first retirement cycle does not match final soak retirement")
        cycle_baselines, cycle_retired = [], []
        for index, cycle in enumerate(retirement_cycles):
            elapsed = cleanup(cycle.get("retirement"))
            if index != 0:  # Final soak retirement is already counted above.
                cleanups.append(elapsed)
            require(cycle.get("observation_ms") == 2000, "plateau observation must be fixed 2s")
            cycle_baselines.append(memory(cycle.get("baseline")))
            cycle_retired.append(memory(cycle.get("after_retirement")))
        require(smoke or max(v["binary_memory_bytes"] for v in cycle_retired) <= min(v["binary_memory_bytes"] for v in cycle_baselines) + 8 * 1024**2 and max(v["process_count"] for v in cycle_retired) <= min(v["process_count"] for v in cycle_baselines) + 2, "repeated retirement cycles do not plateau")
        result["memory_p95"] = {f: summary([o["vm"][f] for o in observations])["p95"] for f in ("process_memory_bytes", "binary_memory_bytes")}
        result["resource_peaks"] = {f: max(o["provider"][f] for o in observations) for f in live}
        require(all(result["resource_peaks"][f] == live[f] for f in live), "soak provider resource accumulation")
    result["cleanup_us"] = summary(cleanups)
    require(smoke or result["cleanup_us"]["p99"] <= 500_000, "ordinary cleanup p99 exceeds 500ms")
    return result


def validate_cell(cell, expected_source, sources=None, smoke=False, phases=PHASES):
    require(isinstance(cell, dict) and key(cell) in {key(c) for c in matrix()}, "unknown matrix cell")
    arms = cell.get("arms", [])
    require(isinstance(arms, list) and all(isinstance(a, dict) and isinstance(a.get("runtime"), dict) and isinstance(a.get("effective"), dict) and isinstance(a.get("peer"), dict) for a in arms), "malformed arm/runtime/effective evidence")
    require([a.get("phase") for a in arms] == list(phases), "missing OTP-before/candidate/OTP-after bracket")
    require(all(platform(a.get("runtime")) == platform(arms[0].get("runtime")) and a.get("effective") == arms[0].get("effective") for a in arms), "unmatched host/runtime/effective policy/warm state")
    require(all(hash_value(a["peer"].get("identity")) and isinstance(a["peer"].get("cipher"), str) for a in arms), "malformed peer identity/cipher")
    require(len({a["peer"]["identity"] for a in arms}) == 1, "peer identity changed inside bracket")
    require(len({a["peer"]["cipher"] for a in arms}) == 1, "negotiated cipher changed inside bracket")
    require(all(a.get("fixtures") == arms[0].get("fixtures") for a in arms), "fixture identity changed inside bracket")
    results = []
    for arm in arms:
        source = sources["candidate" if arm["phase"] == "candidate" else "reference"] if sources else None
        results.append(validate_arm(arm, cell, source["sha256"] if source else expected_source, smoke, source))
    if smoke:
        return dict(cell={k: v for k, v in cell.items() if k != "arms"}, functional="PASS")
    before, candidate, after = results
    for percentile in ("p50", "p95", "p99"):
        b, a = before["latency_us"][percentile], after["latency_us"][percentile]
        require(abs(a / b - 1) <= 0.20, f"environment latency drift >20%: {percentile}")
        scale, additive = {"p50": (2, 2000), "p95": (2.5, 5000), "p99": (3, 10000)}[percentile]
        require(candidate["latency_us"][percentile] <= scale * min(a, b) + additive, f"latency {percentile} budget exceeded")
    if cell["workload"] in ("upload", "download"):
        b, a = before["goodput_mib_s"], after["goodput_mib_s"]
        require(abs(a / b - 1) <= 0.20, "environment goodput drift >20%")
        require(candidate["goodput_mib_s"] >= 0.70 * max(a, b), "application goodput below 70% OTP")
    require(candidate["live_resources"]["processes"] <= min(before["live_resources"]["processes"], after["live_resources"]["processes"]) + 2 * cell["concurrency"], "provider process budget exceeded")
    if cell["workload"] in ("cold", "cancel"):
        require(candidate["per_connection_resource_peaks"]["processes"] <=
                min(before["per_connection_resource_peaks"]["processes"], after["per_connection_resource_peaks"]["processes"]) + 2,
                "per-connection provider process peak budget exceeded")
    if cell["kind"] == "soak":
        for f, multiplier, additive in (("process_memory_bytes", 1.5, 8 * 1024**2), ("binary_memory_bytes", 2, 2 * 1024**2)):
            require(abs(after["memory_p95"][f] / max(before["memory_p95"][f], 1) - 1) <= 0.20, f"environment soak memory drift >20%: {f}")
            require(candidate["memory_p95"][f] <= multiplier * min(before["memory_p95"][f], after["memory_p95"][f]) + additive, f"soak memory budget exceeded: {f}")
    return dict(cell={k: v for k, v in cell.items() if k != "arms"}, candidate=candidate, otp_before=before, otp_after=after)


def platform(runtime):
    return {k: v for k, v in (runtime or {}).items() if k != "beam_sha256"}


def resolve_cell(cell, base_dir):
    """Load one bracket at a time; full raw soak reports can exceed a GiB."""
    arms = []
    require(isinstance(cell, dict) and isinstance(cell.get("arms"), list), "malformed raw arm artifact list")
    for artifact in cell["arms"]:
        require(isinstance(artifact, dict), "malformed raw arm artifact")
        if "path" not in artifact:
            arms.append(artifact)
            continue
        raw = artifact_bytes(artifact, base_dir)
        arm = json.loads(raw)
        require(isinstance(arm, dict), "malformed raw arm artifact")
        require(arm.get("phase") == artifact.get("phase"), "raw artifact phase mismatch")
        arms.append(arm)
    return dict(cell, arms=arms)


def validate_sources(report, expected_source, base_dir):
    require(report.get("source_sha256") == expected_source, "wrong candidate identity")
    sources = report.get("sources", {})
    require(isinstance(sources, dict) and all(isinstance(s, dict) for s in sources.values()), "malformed source identities")
    phases = PHASES if "reference" in sources else ("candidate",)
    require(set(sources) == ({"candidate", "reference"} if len(phases) == 3 else {"candidate"}), "missing source identities")
    for name, source in sources.items():
        files = source.get("files")
        require(isinstance(files, dict) and files and all(hash_value(v) for v in files.values()), "missing source file hashes")
        require(digest(files) == source.get("sha256"), "source manifest digest mismatch")
        require(name != "candidate" or source["sha256"] == expected_source, "wrong candidate source manifest")
        require(re.fullmatch(r"[0-9a-f]{40}", str(source.get("head", ""))), "missing immutable source commit")
        require(source.get("fixtures") == {p: files.get(p) for p in FIXTURE_PATHS} and
                all(hash_value(v) for v in source["fixtures"].values()), "missing source fixture hashes")
        build = source.get("build", {})
        require(isinstance(build, dict), "malformed build receipt")
        require(build.get("sha256") == digest({k: v for k, v in build.items() if k != "sha256"}), "build receipt digest mismatch")
        execution = build.get("execution", {})
        require(isinstance(execution, dict), "malformed build execution")
        require(execution.get("mix_env") == "prod" and all(isinstance(execution.get(k), str) and execution[k]
                for k in ("root", "build_path", "deps_path")), "missing isolated production build identity")
        require(execution.get("runner_sha256") == files.get("scripts/tls_migration_performance.exs") and
                execution.get("wrapper_sha256") == sha(RUNNER_WRAPPER.encode()), "wrong runner/wrapper identity")
        require(build.get("commands") == [["mix", "deps.get", "--check-locked"], ["mix", "compile", "--warnings-as-errors"]]
                and build.get("exits") == [0, 0], "missing strict locked build receipt")
        require(build.get("lock_before") == files.get("mix.lock") == build.get("lock_after"), "build changed lockfile")
        modules = BEAM_MODULES | {"Elixir.HTTP.Transport.ExSSL" if name == "candidate" else "Elixir.HTTP.Transport.SSL"}
        require(isinstance(build.get("beam_sha256"), dict) and set(build["beam_sha256"]) == modules and all(hash_value(v) for v in build["beam_sha256"].values()), "missing build BEAM manifest")
        if name == "reference":
            require(source.get("requested_commit") == source["head"], "reference commit changed")
            raw = artifact_bytes(source.get("archive", {}), base_dir)
            try:
                import io
                with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                    require(archive.pax_headers.get("comment") == source["head"], "reference archive commit mismatch")
                    require(all(sha(archive.extractfile(path).read()) == expected for path, expected in files.items()), "reference archive/source manifest mismatch")
            except (KeyError, tarfile.TarError, AttributeError) as exc:
                raise GateError("invalid reference archive manifest") from exc
    if "reference" in sources:
        candidate, reference = sources["candidate"], sources["reference"]
        require(candidate["fixtures"] == reference["fixtures"], "reference certificate/CA fixture mismatch")
        for field in ("root", "build_path", "deps_path"):
            require(candidate["build"]["execution"][field] != reference["build"]["execution"][field], "reference/current build isolation violated")
    return sources, phases


def artifact_bytes(artifact, base_dir):
    require(base_dir is not None and isinstance(artifact, dict) and isinstance(artifact.get("path"), str), "raw artifact base directory/path required")
    directory = Path(base_dir).resolve()
    path = (directory / artifact["path"]).resolve()
    require(path.is_relative_to(directory) and path.is_file(), "missing/unsafe raw artifact")
    raw = path.read_bytes()
    require(sha(raw) == artifact.get("sha256"), "raw artifact hash mismatch")
    return raw


def validate_evidence(report, expected_source, base_dir, smoke):
    require(isinstance(report, dict) and report.get("schema") == SCHEMA, "missing/malformed P4 v2 report; v1/P0 evidence is unsupported")
    require(report.get("mode") == ("smoke" if smoke else "promotion"), "diagnostic mode cannot pass promotion")
    cells = report.get("cells", [])
    required = smoke_matrix() if smoke else matrix()
    require(isinstance(cells, list) and all(isinstance(c, dict) for c in cells) and Counter(key(c) for c in cells) == Counter(key(c) for c in required), "missing/duplicate mandatory matrix cells")
    sources, phases = validate_sources(report, expected_source, base_dir)
    require(smoke or phases == PHASES, "promotion requires OTP reference bracket")
    require(report.get("failures") == [], "failed/unstable trial retained in report")
    results = []
    for cell in cells:
        require(isinstance(cell.get("arms"), list) and all(isinstance(a, dict) and set(a) == {"phase", "path", "sha256"} for a in cell["arms"]), "missing raw arm artifact paths/hashes")
        results.append(validate_cell(resolve_cell(cell, base_dir), expected_source, sources, smoke, phases))
    return dict(status="FUNCTIONAL_PASS" if smoke else "PASS", schema=SCHEMA,
                source_sha256=expected_source, cells=len(results), arms=len(results) * len(phases), comparisons=results)


def validate_smoke_report(report, expected_source, base_dir=None):
    return validate_evidence(report, expected_source, base_dir, True)


def validate_report(report, expected_source, base_dir=None):
    return validate_evidence(report, expected_source, base_dir, False)


def fingerprint(root=ROOT):
    paths = set(root.glob("apps/*/lib/**/*.ex")) | set(root.glob("apps/*/mix.exs")) | set(root.glob("config/*")) | set(root.glob("scripts/tls_migration_performance*"))
    paths |= {root / "mix.exs", root / "mix.lock"}
    paths |= {root / p for p in FIXTURE_PATHS}
    files = {str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted(paths) if p.is_file()}
    return dict(files=files, sha256=sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()))


class PeerProcess:
    def __init__(self, cell, directory, python):
        fixtures = ROOT / "apps/http_fetch/test/support/fixtures"
        self.stderr = (directory / "peer.stderr").open("w")
        self.process = subprocess.Popen([python, str(ROOT / "scripts/tls_migration_performance_peer.py"),
            "--cert", str(fixtures / "localhost.pem"), "--key", str(fixtures / "localhost.key"),
            "--protocol", cell["protocol"], "--tls", cell["tls"], "--workload", cell["workload"], "--state-dir", str(directory),
            "--lifetime", "18000"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, start_new_session=True)
        self.lines = queue.Queue(maxsize=32)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.ready = self.read()
            require(self.ready.get("event") == "ready", "peer did not become ready")
        except BaseException:
            self.close()
            raise

    def _read(self):
        for line in self.process.stdout:
            try:
                self.lines.put(json.loads(line), timeout=2)
            except (ValueError, queue.Full):
                try:
                    self.lines.put_nowait({"event": "invalid-peer-output"})
                except queue.Full:
                    pass
                return
        try:
            self.lines.put_nowait({"event": "peer-exit", "exit": self.process.poll()})
        except queue.Full:
            pass

    def read(self):
        try:
            return self.lines.get(timeout=20)
        except queue.Empty as exc:
            raise GateError("peer control timeout") from exc

    def command(self, command):
        self.process.stdin.write(json.dumps({"command": command}) + "\n")
        self.process.stdin.flush()
        result = self.read()
        require(result.get("event") == command, "unexpected peer control result")
        return result

    def close(self):
        try:
            if self.process.poll() is None:
                self.command("stop")
                self.process.wait(timeout=10)
        finally:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=10)
            self.process.stdin.close()
            self.process.stdout.close()
            self.reader.join(timeout=2)
            self.stderr.close()


# The unchanged historical runner supplies workload/completion measurements. This
# wrapper adds observations from that same VM, before and after its own runner.
RUNNER_WRAPPER = r"""
config = System.fetch_env!("TLS_PERF_CONFIG") |> File.read!() |> JSON.decode!()
backend = case config["backend"] do
  "ex_ssl" -> :ex_ssl
  "ssl" -> :ssl
  _ -> raise "unknown performance backend"
end
{:ok, ^backend} = HTTP.TLSBackend.resolve(backend)
transport = HTTP.TLSBackend.transport(backend)
Code.ensure_loaded!(transport)
{^transport, beam, _} = :code.get_object_code(transport)
sha = fn bytes -> :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower) end
state = fn ->
  %{"loaded" => Enum.any?(Application.loaded_applications(), &(elem(&1, 0) == :ssl)),
    "started" => Enum.any?(Application.started_applications(), &(elem(&1, 0) == :ssl))}
end
before = state.()
runner = Path.expand("scripts/tls_migration_performance.exs")
Code.require_file(runner)
report = config["output"] |> File.read!() |> JSON.decode!()
fixtures = Map.new(config["fixtures"], fn {path, _} -> {path, sha.(File.read!(path))} end)
execution = %{
  "root" => File.cwd!(), "mix_env" => Atom.to_string(Mix.env()),
  "build_path" => Path.expand(Mix.Project.build_path()),
  "deps_path" => Path.expand(Mix.Project.deps_path()),
  "runner_sha256" => sha.(File.read!(runner)),
  "wrapper_sha256" => config["wrapper_sha256"]
}
report = Map.merge(report, %{
  "build_sha256" => config["build_sha256"], "execution" => execution,
  "selected_transport" => %{"module" => Atom.to_string(transport), "beam_sha256" => sha.(beam)},
  "fixtures" => fixtures, "otp_ssl" => %{"before" => before, "after" => state.()}
})
File.write!(config["output"], JSON.encode!(report))
"""


def stop_owned(process):
    # A failed launcher may already have exited while its children remain in
    # the task-owned process group. Signal that group even after leader exit.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def run_owned(command, root, env, log_path, timeout):
    with log_path.open("w") as log:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        finally:
            stop_owned(process)


def export_reference(commit, directory):
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit), "otp-reference-sha must be a full immutable commit SHA")
    resolved = subprocess.check_output(["git", "rev-parse", "--verify", commit + "^{commit}"], cwd=ROOT, text=True).strip()
    require(resolved == commit, "reference commit did not resolve exactly")
    archive_path = directory / "otp-reference.tar"
    with archive_path.open("wb") as archive:
        subprocess.run(["git", "archive", "--format=tar", commit], cwd=ROOT, stdout=archive, check=True, timeout=120)
    root = directory / "otp-reference-source"
    root.mkdir()
    with tarfile.open(archive_path) as archive:
        require(archive.pax_headers.get("comment") == commit, "reference archive commit mismatch")
        archive.extractall(root, filter="data")
    selector = (root / "apps/http_core/lib/http/tls_backend.ex").read_text()
    runner = (root / "scripts/tls_migration_performance.exs").read_text()
    require("def transport(:ssl), do: HTTP.Transport.SSL" in selector and
            '[:ssl, "ssl"]' in selector and (root / "apps/http_core/lib/http/transport/ssl.ex").is_file(),
            "historical reference lacks legacy selector/OTP adapter")
    require(all(api in runner for api in ("HTTP.ManagedTransport.open", "HTTP.ManagedTransport.await_retired",
            "HTTP.RequestCompletion.await", "HTTP.RequestCompletion.abort_and_await", "defp soak", "defp cancellation")),
            "historical reference lacks required public workload capabilities")
    source = fingerprint(root)
    source.update(head=commit, requested_commit=commit,
                  archive=dict(path=archive_path.name, sha256=sha(archive_path.read_bytes())))
    return root, source


def build_source(name, root, source, directory):
    build_path = directory / (name + "-build")
    deps_path = directory / (name + "-deps")
    env = dict(os.environ, MIX_ENV="prod", MIX_BUILD_PATH=str(build_path), MIX_DEPS_PATH=str(deps_path))
    # MIX_HOME/HEX_HOME remain the caller's; each source owns dependency checkout
    # and build output paths, and neither source's mix.lock may be rewritten.
    lock_before = sha((root / "mix.lock").read_bytes())
    commands = [["mix", "deps.get", "--check-locked"], ["mix", "compile", "--warnings-as-errors"]]
    exits = []
    for index, command in enumerate(commands):
        code = run_owned(command, root, env, directory / f"{name}-{index}.log", 1800)
        exits.append(code)
        require(code == 0, f"{name} build failed: {command}; see retained build log")
        require(sha((root / "mix.lock").read_bytes()) == lock_before, f"{name} build changed lockfile")
        require(fingerprint(root)["sha256"] == source["sha256"], f"{name} source changed during build")
    modules = BEAM_MODULES | {"Elixir.HTTP.Transport.ExSSL" if name == "candidate" else "Elixir.HTTP.Transport.SSL"}
    beams = {}
    for module in sorted(modules):
        paths = list(build_path.glob(f"lib/*/ebin/{module}.beam"))
        require(len(paths) == 1, f"missing/ambiguous built BEAM {name} {module}")
        beams[module] = sha(paths[0].read_bytes())
    execution = dict(root=str(root), build_path=str(build_path), deps_path=str(deps_path), mix_env="prod",
                     runner_sha256=source["files"]["scripts/tls_migration_performance.exs"],
                     wrapper_sha256=sha(RUNNER_WRAPPER.encode()))
    build = dict(execution=execution, beam_sha256=beams, commands=commands, exits=exits,
                 lock_before=lock_before, lock_after=sha((root / "mix.lock").read_bytes()))
    build["sha256"] = digest(build)
    source.update(build=build, fixtures={p: source["files"][p] for p in FIXTURE_PATHS})
    return env


def execute(args):
    reference_commit = getattr(args, "otp_reference_sha", None)
    require(args.smoke or reference_commit, "full run requires --otp-reference-sha " + DEFAULT_OTP_REFERENCE)
    candidate_backend(getattr(args, "backend", "ex_ssl"))
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    report_path = directory / "report.json"
    report = dict(schema=SCHEMA, mode="smoke" if args.smoke else "promotion",
                  source_sha256=args.candidate_sha256, sources={}, cells=[], failures=[])
    (directory / "runner-wrapper.exs").write_text(RUNNER_WRAPPER)
    try:
        source = fingerprint()
        require(source["sha256"] == args.candidate_sha256, "candidate changed before build")
        source["head"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        roots = {"candidate": ROOT}
        report["sources"]["candidate"] = source
        if reference_commit:
            roots["reference"], report["sources"]["reference"] = export_reference(reference_commit, directory)
            require({p: source["files"].get(p) for p in FIXTURE_PATHS} ==
                    {p: report["sources"]["reference"]["files"].get(p) for p in FIXTURE_PATHS},
                    "reference certificate/CA fixture mismatch")
        environments = {name: build_source(name, root, report["sources"][name], directory)
                        for name, root in roots.items()}
        phases = PHASES if reference_commit else ("candidate",)
        selected = smoke_matrix() if args.smoke else matrix()
        for index, spec in enumerate(selected):
            cell = dict(spec, arms=[])
            report["cells"].append(cell)
            cell_dir = directory / f"cell-{index:03d}"
            cell_dir.mkdir()
            peer = None
            try:
                peer = PeerProcess(spec, cell_dir, args.python)
                for phase in phases:
                    name = "candidate" if phase == "candidate" else "reference"
                    arm_source = report["sources"][name]
                    peer.command("reset")
                    config = dict(cell=spec, phase=phase, backend=BACKEND_BY_PHASE[phase],
                                  source_sha256=arm_source["sha256"], peer=peer.ready, state_dir=str(cell_dir),
                                  samples=10 if args.smoke else 1000, warmup=3,
                                  soak_ms=5000 if args.smoke else 1_800_000,
                                  build_sha256=arm_source["build"]["sha256"], fixtures=arm_source["fixtures"],
                                  wrapper_sha256=sha(RUNNER_WRAPPER.encode()),
                                  output=str(cell_dir / f"{phase}.json"))
                    config_path = cell_dir / f"{phase}-config.json"
                    config_path.write_text(json.dumps(config))
                    runner_env = dict(environments[name], TLS_PERF_CONFIG=str(config_path))
                    code = run_owned(["mix", "run", "--no-compile", "-e", RUNNER_WRAPPER], roots[name],
                                     runner_env, cell_dir / f"{phase}.log",
                                     (config["soak_ms"] / 1000 + 900) if spec["kind"] == "soak" else 1800)
                    require(code == 0 and Path(config["output"]).is_file(), f"runner failed: cell {index} {phase}")
                    arm = json.loads(Path(config["output"]).read_text())
                    arm["peer"] = peer.command("stats")
                    Path(config["output"]).write_text(json.dumps(arm))
                    cell["arms"].append(dict(phase=phase, path=str(Path(config["output"]).relative_to(directory)),
                                             sha256=sha(Path(config["output"]).read_bytes())))
                    for source_name, root in roots.items():
                        require(fingerprint(root)["sha256"] == report["sources"][source_name]["sha256"], "source changed during trial")
                    report_path.write_text(json.dumps(report))
                validate_cell(resolve_cell(cell, directory), source["sha256"], report["sources"], args.smoke, phases)
            finally:
                if peer is not None:
                    try:
                        (cell_dir / "peer-final.json").write_text(json.dumps(peer.command("stats")))
                    finally:
                        peer.close()
        result = (validate_smoke_report if args.smoke else validate_report)(report, args.candidate_sha256, directory)
        if args.smoke:
            (directory / "functional-validation.json").write_text(json.dumps(result))
            print(json.dumps(dict(status="INCOMPLETE", functional="PASS", cells=result["cells"], arms=result["arms"],
                                  reason="smoke cannot pass promotion", report=str(report_path))))
            return 2
        (directory / "validated.json").write_text(json.dumps(result))
        print(json.dumps({k: v for k, v in result.items() if k != "comparisons"}))
        return 0
    except BaseException as exc:
        report["failures"].append(dict(type=type(exc).__name__, detail=str(exc)))
        raise
    finally:
        # Failure evidence is retained even if a runner dies before producing a
        # valid arm. Include every existing raw/config/peer/log artifact, without
        # treating a failed output as a validated phase.
        paths = set(directory.glob("*.log")) | set(directory.glob("cell-*/*"))
        paths.add(directory / "runner-wrapper.exs")
        report["diagnostics"] = [dict(path=str(p.relative_to(directory)), sha256=sha(p.read_bytes()))
                                 for p in sorted(paths) if p.is_file()]
        report_path.write_text(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("fingerprint")
    validate = commands.add_parser("validate")
    validate.add_argument("report", type=Path)
    validate.add_argument("--candidate-sha256", required=True)
    run = commands.add_parser("run")
    run.add_argument("--candidate-sha256", required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--python", default=sys.executable)
    run.add_argument("--smoke", action="store_true")
    run.add_argument("--otp-reference-sha", help="immutable pre-removal commit; documented pin: " + DEFAULT_OTP_REFERENCE)
    args = parser.parse_args()
    try:
        if args.command == "fingerprint":
            print(json.dumps(fingerprint(), indent=2))
            return 0
        if args.command == "validate":
            report = json.loads(args.report.read_text())
            require(isinstance(report, dict), "missing/malformed P4 v2 report object")
            validator = validate_smoke_report if report.get("mode") == "smoke" else validate_report
            try:
                result = validator(report, args.candidate_sha256, args.report.parent)
            except (TypeError, AttributeError, KeyError, IndexError, OverflowError) as exc:
                # Unexpected JSON field types must fail as evidence errors, never
                # escape the CLI as a traceback or become diagnostic success.
                raise GateError(f"malformed report evidence ({type(exc).__name__}): {exc}") from exc
            if report.get("mode") == "smoke":
                print(json.dumps(dict(status="INCOMPLETE", functional="PASS", cells=result["cells"], arms=result["arms"])))
                return 2
            print(json.dumps(result))
            return 0
        return execute(args)
    except (GateError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps(dict(status="FAIL", error=str(exc))), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

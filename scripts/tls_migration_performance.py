#!/usr/bin/env python3
"""P4 source-candidate load gate. `run` launches real peers/BEAM; `validate` is pure.

Run only after public P2/P3 acceptance, with exclusive runtime ownership:
  python3 scripts/tls_migration_performance.py fingerprint
  python3 scripts/tls_migration_performance.py run --candidate-sha256 SHA --output /tmp/p4-run
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
import threading
import time

SCHEMA = "http-fetch-tls-p4-v1"
PHASES = ("otp-before", "candidate", "otp-after")
WORKLOADS = ("cold", "reuse", "upload", "download", "cancel")
PAYLOAD = b"Z" * 1_048_576
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()
UPLOAD_REPLY_SHA = hashlib.sha256(PAYLOAD_SHA.encode()).hexdigest()
SMALL_SHA = hashlib.sha256(b"ok").hexdigest()
BEAM_MODULES = {"Elixir." + name for name in ("HTTP", "HTTP.Promise", "HTTP.Response",
                "HTTP.RequestCompletion", "HTTP.ManagedTransport", "SSL", "SSL.Lifecycle")}
ROOT = Path(__file__).resolve().parents[1]


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


def key(cell):
    return tuple(cell.get(k) for k in ("kind", "trial", "protocol", "tls", "concurrency", "workload"))


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


def validate_arm(arm, cell, expected_source):
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
    effective = arm.get("effective", {})
    require(effective.get("verify") == "verify_peer" and effective.get("tls") == cell["tls"] and effective.get("alpn") == cell["protocol"], "wrong effective verification/TLS/ALPN")
    require(effective.get("payload_bytes") == len(PAYLOAD) and effective.get("concurrency") == cell["concurrency"] and effective.get("pool_connections") == cell["concurrency"], "unmatched payload/pool/concurrency")
    require(effective.get("forced_global_gc") is False and effective.get("cipher_policy") and effective.get("warm_state"), "missing policy or forced global GC")
    warmup = arm.get("warmup")
    require(isinstance(warmup, list) and warmup and effective.get("warmup") == len(warmup), "missing warmup")
    require(all(w.get("payload_ok") is True and w.get("request_completion") == "confirmed" for w in warmup), "failed warmup")
    require(arm.get("failures") == [], "failed exchanges/runner failures")
    peer = arm.get("peer", {})
    require(peer.get("errors") == [] and re.fullmatch(r"[0-9a-f]{64}", str(peer.get("identity", ""))), "missing/failed independent peer")
    require(peer.get("tls") == cell["tls"] and peer.get("alpn") == cell["protocol"] and peer.get("cipher") and peer.get("resumed") is False, "wrong authenticated peer TLS/ALPN/cipher")
    samples = arm.get("samples")
    require(isinstance(samples, list) and len(samples) >= 1000, "fewer than 1000 measured raw samples")
    ids = [s.get("id") for s in samples]
    require(all(isinstance(i, str) and i for i in ids) and len(ids) == len(set(ids)), "missing/duplicate sample ID")
    records = peer.get("requests")
    require(isinstance(records, list), "missing raw peer exchanges")
    require(Counter(r.get("id") for r in records) == Counter(ids), "missing/duplicate/replayed peer exchange")
    require(peer.get("warmup_requests") == len(warmup), "wrong peer warmup count")
    handshakes = peer.get("handshakes")
    require(isinstance(handshakes, list) and handshakes and len(handshakes) == peer.get("accepted_connections"), "missing raw authenticated handshakes")
    require(all(h.get("tls") == cell["tls"] and h.get("alpn") == cell["protocol"] and h.get("cipher") == peer["cipher"] and h.get("resumed") is False for h in handshakes), "unauthenticated/mismatched handshake")
    connection_ids = [h.get("connection") for h in handshakes]
    require(all(type(i) is int and i > 0 for i in connection_ids) and len(set(connection_ids)) == len(connection_ids), "invalid/duplicate handshake connection ID")
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
    if cell["workload"] in ("upload", "download"):
        require(peer.get(cell["workload"] + "_bytes") == len(samples) * len(PAYLOAD), "wrong independent payload byte count")
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
    require(after["binary_memory_bytes"] <= baseline["binary_memory_bytes"] + 8 * 1024**2 and after["process_count"] <= baseline["process_count"] + 2 and after["port_count"] <= baseline["port_count"], "retirement memory/process/port drift")
    wall = number(arm.get("wall_us"), "wall_us", 0.001)
    require(wall >= max(timings) and wall * connections >= math.fsum(timings), "wall time contradicts raw sample durations/concurrency")
    result = dict(latency_us=summary(timings), live_resources=live, per_connection_resource_peaks=per_connection_peaks,
                  goodput_mib_s=len(samples) / (wall / 1_000_000) if cell["workload"] in ("upload", "download") else None)
    if cell["kind"] == "soak":
        require(number(arm.get("duration_us"), "soak duration") >= 1_800_000_000 and type(arm.get("completed_cycles")) is int and arm["completed_cycles"] >= 1000, "short/incomplete 30-minute soak")
        require(arm["duration_us"] == wall, "soak duration differs from measured wall interval")
        require(len(samples) == arm["completed_cycles"] * connections, "incomplete per-connection soak cycles")
        observations = arm.get("resource_samples")
        require(isinstance(observations, list) and len(observations) >= 1000, "missing raw soak observations")
        for observation in observations:
            resource_counts(observation.get("provider"), connections, "soak")
            memory(observation.get("vm"))
            require(observation.get("live_connections") == connections, "soak lost fixed live connections")
        require(max(o["elapsed_us"] for o in observations) - min(o["elapsed_us"] for o in observations) >= 1_798_000_000, "soak observations do not span 30 minutes")
        require(len({s["connection"] for s in samples}) == connections, "soak reconnect/generation accumulation")
        retirement_cycles = arm.get("retirement_cycles")
        require(isinstance(retirement_cycles, list) and len(retirement_cycles) >= 2, "missing repeated retirement plateau cycles")
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
        require(max(v["binary_memory_bytes"] for v in cycle_retired) <= min(v["binary_memory_bytes"] for v in cycle_baselines) + 8 * 1024**2 and max(v["process_count"] for v in cycle_retired) <= min(v["process_count"] for v in cycle_baselines) + 2, "repeated retirement cycles do not plateau")
        result["memory_p95"] = {f: summary([o["vm"][f] for o in observations])["p95"] for f in ("process_memory_bytes", "binary_memory_bytes")}
        result["resource_peaks"] = {f: max(o["provider"][f] for o in observations) for f in live}
        require(all(result["resource_peaks"][f] == live[f] for f in live), "soak provider resource accumulation")
    result["cleanup_us"] = summary(cleanups)
    require(result["cleanup_us"]["p99"] <= 500_000, "ordinary cleanup p99 exceeds 500ms")
    return result


def validate_cell(cell, expected_source):
    require(isinstance(cell, dict) and key(cell) in {key(c) for c in matrix()}, "unknown matrix cell")
    arms = cell.get("arms", [])
    require([a.get("phase") for a in arms] == list(PHASES), "missing OTP-before/candidate/OTP-after bracket")
    require(all(a.get("runtime") == arms[0].get("runtime") and a.get("effective") == arms[0].get("effective") for a in arms), "unmatched host/runtime/effective policy/warm state")
    require(len({a.get("peer", {}).get("identity") for a in arms}) == 1, "peer identity changed inside bracket")
    require(len({a.get("peer", {}).get("cipher") for a in arms}) == 1, "negotiated cipher changed inside bracket")
    results = [validate_arm(a, cell, expected_source) for a in arms]
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


def resolve_cell(cell, base_dir):
    """Load one bracket at a time; full raw soak reports can exceed a GiB."""
    arms = []
    for artifact in cell.get("arms", []):
        if "path" not in artifact:
            arms.append(artifact)
            continue
        require(base_dir is not None, "raw artifact base directory required")
        directory = Path(base_dir).resolve()
        path = (directory / artifact["path"]).resolve()
        require(path.is_relative_to(directory) and path.is_file(), "missing/unsafe raw arm artifact")
        raw = path.read_bytes()
        require(sha(raw) == artifact.get("sha256"), "raw arm artifact hash mismatch")
        arm = json.loads(raw)
        require(arm.get("phase") == artifact.get("phase"), "raw artifact phase mismatch")
        arms.append(arm)
    return dict(cell, arms=arms)


def validate_report(report, expected_source, base_dir=None):
    require(isinstance(report, dict) and report.get("schema") == SCHEMA, "missing/malformed P4 report")
    require(report.get("mode") == "promotion", "diagnostic mode cannot pass promotion")
    cells = report.get("cells", [])
    require(isinstance(cells, list) and Counter(key(c) for c in cells) == Counter(key(c) for c in matrix()), "missing/duplicate mandatory matrix cells")
    require(report.get("source_sha256") == expected_source, "wrong candidate identity")
    source = report.get("source", {})
    files = source.get("files")
    require(isinstance(files, dict) and files and all(re.fullmatch(r"[0-9a-f]{64}", str(v)) for v in files.values()), "missing source file hashes")
    require(sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()) == expected_source, "source manifest digest mismatch")
    require(source.get("head") and source.get("build_command") and source.get("build_exit") == 0, "missing compiled source identity")
    require(report.get("failures") == [], "failed/unstable trial retained in report")
    results = [validate_cell(resolve_cell(c, base_dir), expected_source) for c in cells]
    return dict(status="PASS", schema=SCHEMA, source_sha256=expected_source, cells=len(results), comparisons=results)


def fingerprint(root=ROOT):
    paths = set(root.glob("apps/*/lib/**/*.ex")) | set(root.glob("apps/*/mix.exs")) | set(root.glob("config/*")) | set(root.glob("scripts/tls_migration_performance*"))
    paths |= {root / "mix.exs", root / "mix.lock"}
    paths |= set((root / "apps/http_fetch/test/support/fixtures").glob("localhost*.pem"))
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


def execute(args):
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = fingerprint()
    require(source["sha256"] == args.candidate_sha256, "candidate changed before build")
    env = os.environ.copy()
    env["MIX_ENV"] = "test"
    command = ["mix", "compile", "--warnings-as-errors"]
    with (directory / "compile.log").open("w") as log:
        compiled = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=1800, check=False)
    require(compiled.returncode == 0 and fingerprint()["sha256"] == source["sha256"], "build failed or source changed")
    source.update(head=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  build_command=command, build_exit=compiled.returncode)
    report = dict(schema=SCHEMA, mode="smoke" if args.smoke else "promotion", source_sha256=source["sha256"], source=source, cells=[], failures=[])
    selected = matrix() if not args.smoke else [matrix()[0]]
    report_path = directory / "report.json"
    try:
        for index, spec in enumerate(selected):
            cell = dict(spec, arms=[])
            report["cells"].append(cell)
            cell_dir = directory / f"cell-{index:03d}"
            cell_dir.mkdir()
            peer = None
            try:
                peer = PeerProcess(spec, cell_dir, args.python)
                for phase in PHASES:
                    peer.command("reset")
                    config = dict(cell=spec, phase=phase, backend="ex_ssl" if phase == "candidate" else "ssl",
                                  source_sha256=source["sha256"], peer=peer.ready, state_dir=str(cell_dir),
                                  samples=10 if args.smoke else 1000, warmup=3,
                                  soak_ms=5000 if args.smoke else 1_800_000,
                                  output=str(cell_dir / f"{phase}.json"))
                    config_path = cell_dir / "config.json"
                    config_path.write_text(json.dumps(config))
                    runner_env = dict(env, TLS_PERF_CONFIG=str(config_path))
                    with (cell_dir / f"{phase}.log").open("w") as log:
                        process = subprocess.Popen(["mix", "run", "--no-compile", "scripts/tls_migration_performance.exs"], cwd=ROOT,
                                                   env=runner_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                        try:
                            code = process.wait(timeout=(config["soak_ms"] / 1000 + 900) if spec["kind"] == "soak" else 1800)
                        except BaseException:
                            os.killpg(process.pid, signal.SIGTERM)
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                os.killpg(process.pid, signal.SIGKILL)
                                process.wait(timeout=10)
                            raise
                    require(code == 0 and Path(config["output"]).exists(), f"runner failed: cell {index} {phase}")
                    arm = json.loads(Path(config["output"]).read_text())
                    arm["peer"] = peer.command("stats")
                    Path(config["output"]).write_text(json.dumps(arm))
                    cell["arms"].append(arm)
                    require(fingerprint()["sha256"] == source["sha256"], "source changed during trial")
                    report_path.write_text(json.dumps(report))
                if not args.smoke:
                    validate_cell(cell, source["sha256"])
                # Keep raw evidence in immutable hashed arm files, loading only
                # one comparison bracket at a time during final validation.
                cell["arms"] = [dict(phase=phase, path=str((cell_dir / f"{phase}.json").relative_to(directory)), sha256=sha((cell_dir / f"{phase}.json").read_bytes())) for phase in PHASES]
            finally:
                if peer is not None:
                    try:
                        (cell_dir / "peer-final.json").write_text(json.dumps(peer.command("stats")))
                    finally:
                        peer.close()
    except BaseException as exc:
        report["failures"].append(dict(type=type(exc).__name__, detail=str(exc)))
        raise
    finally:
        report_path.write_text(json.dumps(report))
    if args.smoke:
        print(json.dumps(dict(status="INCOMPLETE", reason="smoke cannot pass promotion", report=str(report_path))))
        return 2
    result = validate_report(report, args.candidate_sha256, directory)
    (directory / "validated.json").write_text(json.dumps(result))
    print(json.dumps({k: v for k, v in result.items() if k != "comparisons"}))
    return 0


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
    args = parser.parse_args()
    try:
        if args.command == "fingerprint":
            print(json.dumps(fingerprint(), indent=2))
            return 0
        if args.command == "validate":
            result = validate_report(json.loads(args.report.read_text()), args.candidate_sha256, args.report.parent)
            print(json.dumps(result))
            return 0
        return execute(args)
    except (GateError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps(dict(status="FAIL", error=str(exc))), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

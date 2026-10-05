"""Detached published-package canary; never part of release acceptance."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
from consumer_gate import verify_canary_source


def write_status(directory, status):
    temporary = directory / "status.tmp"
    temporary.write_text(json.dumps(status, indent=2) + "\n")
    temporary.replace(directory / "status.json")


def classify(returncode, output, elapsed, version, source_sha):
    if returncode < 0:
        return "INTERRUPTED"
    provenance = f"HTTP3 consumer provenance: published, nine Hex packages == {version}: PASS"
    result = re.search(r"HTTP3 canary result: PASS seconds=(\d+) requests=(\d+) "
                       r"[^\n]*errors=0 commit=([a-f0-9]{40})(?:\s|$)", output)
    if (returncode == 0 and elapsed >= 86400 and provenance in output and result
            and int(result[1]) >= 86400 and int(result[2]) > 0 and result[3] == source_sha):
        return "PASS"
    return "FAIL"


def report(args, status):
    directory = args.output_dir
    body = directory / "report.md"
    verification = "Verified" if status.get("provenance_verified") else "Required"
    details = ""
    for key in ("error", "report_error", "last_canary_measurement", "failure_evidence"):
        if status.get(key):
            details += f"\n{key}:\n\n```text\n{status[key]}\n```\n"
    body.write_text(
        f"Post-release independent HTTP/3 canary: **{status['result']}**\n\n"
        f"Release: `v{args.version}`; tagged SHA: `{args.source_sha}`.\n"
        f"{verification}: all nine exact published Hex versions, with GitHub archive checksum checks.\n"
        f"Required workload duration: 86400 seconds.\n"
        f"Runner wall time including setup: {status['elapsed_seconds']:.3f} seconds.\n"
        f"Exit code: `{status['returncode']}`.\n\n"
        f"Durable evidence directory: `{directory}` (`consumer.log`, `status.json`, `peer-logs/`).\n"
        "The consumer log contains loaded application provenance and the measured workload result.\n"
        "This asynchronous result does not change the completed release gates.\n" + details)
    if status["result"] == "FAIL":
        followup = subprocess.check_output(
            ["gh", "issue", "create", "--repo", args.repo, "--type", "Bug",
             "--title", f"[canary] HTTP/3 {args.version} post-release test failed",
             "--body-file", str(body)], text=True, timeout=60).strip()
        status["followup_issue"] = followup
        with body.open("a") as output:
            output.write(f"\nSeparate follow-up task: {followup}\n")
    subprocess.run(["gh", "issue", "comment", str(args.issue), "--repo", args.repo,
                    "--body-file", str(body)], check=True, timeout=60)


def worker(args):
    directory = args.output_dir
    started = time.monotonic()
    status = {"result": "RUNNING", "pid": os.getpid(), "version": args.version,
              "source_sha": args.source_sha, "tracking_issue": args.issue,
              "started_at": datetime.now(timezone.utc).isoformat()}
    write_status(directory, status)
    child = None
    returncode = 1
    try:
        verify_canary_source(args.version, args.source_sha)
        archives = directory / "archives"
        archives.mkdir()
        subprocess.run(["gh", "release", "download", f"v{args.version}", "--repo", args.repo,
                        "--pattern", "*.tar", "--dir", str(archives)], check=True, timeout=180)
        environment = {**os.environ, "PYTHONUNBUFFERED": "1",
                       "HTTP3_GATE_LOG_DIR": str(directory / "peer-logs")}
        with (directory / "consumer.log").open("w") as output:
            child = subprocess.Popen(
                [sys.executable, str(ROOT / "scripts/release/consumer_gate.py"), args.version,
                 str(archives), "--mode", "http3-canary", "--published", "--keep",
                 "--source-sha", args.source_sha], cwd=ROOT, env=environment,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            returncode = child.wait(timeout=88200)
    except (KeyboardInterrupt, InterruptedError, subprocess.TimeoutExpired) as error:
        if isinstance(error, subprocess.TimeoutExpired):
            status["error"] = "outer canary deadline exceeded"
        else:
            returncode = -signal.SIGINT
        if child is not None and child.poll() is None:
            # SIGINT lets the Python peer launcher run its owned cleanup paths.
            os.killpg(child.pid, signal.SIGINT)
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                status["forced_shutdown"] = True
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    except Exception as error:
        status["error"] = str(error)
    elapsed = time.monotonic() - started
    log = directory / "consumer.log"
    output = log.read_text(errors="replace") if log.is_file() else ""
    provenance = f"HTTP3 consumer provenance: published, nine Hex packages == {args.version}: PASS"
    measurements = [line for line in output.splitlines() if line.startswith(
        ("HTTP3 canary elapsed_ms=", "HTTP3 canary result:"))]
    status.update(result=classify(returncode, output, elapsed, args.version, args.source_sha),
                  returncode=returncode, elapsed_seconds=elapsed,
                  provenance_verified=provenance in output,
                  last_canary_measurement=measurements[-1] if measurements else "No workload measurement recorded",
                  finished_at=datetime.now(timezone.utc).isoformat())
    if status["result"] == "FAIL":
        status.setdefault("error", f"published consumer exited {returncode}; required full-duration PASS was not proven")
        status["failure_evidence"] = "\n".join(output.splitlines()[-12:])[-3000:] or "No consumer output recorded"
    write_status(directory, status)
    try:
        report(args, status)
    except Exception as error:
        status["report_error"] = str(error)
    write_status(directory, status)
    return 0 if status["result"] == "PASS" and "report_error" not in status else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("source_sha")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--issue", type=int, required=True)
    parser.add_argument("--repo", default="gsmlg-dev/http_fetch")
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", args.version) or args.issue < 1:
        parser.error("stable release version and positive tracking issue required")
    args.output_dir = args.output_dir.resolve()
    def interrupted(*_args):
        raise InterruptedError()
    signal.signal(signal.SIGTERM, interrupted)
    if args.worker:
        return worker(args)
    verify_canary_source(args.version, args.source_sha)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    if not args.detach:
        return worker(args)
    write_status(args.output_dir, {"result": "LAUNCHING", "version": args.version,
                                  "source_sha": args.source_sha, "tracking_issue": args.issue})
    with (args.output_dir / "worker.log").open("w") as output:
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), args.version, args.source_sha,
             str(args.output_dir), "--issue", str(args.issue), "--repo", args.repo, "--worker"],
            cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
    launch = {"pid": child.pid, "output_dir": str(args.output_dir)}
    (args.output_dir / "launch.json").write_text(json.dumps(launch) + "\n")
    print(json.dumps(launch))
    return 0


if __name__ == "__main__":
    sys.exit(main())

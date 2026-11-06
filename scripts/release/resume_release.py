"""Finish docs/native publication only after a fully verified portable release.

The source release must have failed solely at documentation publication. This
helper never publishes portable packages or changes an existing source tag.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from archive_audit import audit_package
from github_assets import verify_assets
from hex_packages import release_status
from stage import RELEASE_PACKAGES, ROOT, source_version, stage_sources


PORTABLE_JOB = "Validate and release eleven portable packages"
DOCS_STEP = "Publish package documentation separately"
REQUIRED_STEPS = (
    "Validate immutable tag and branch",
    "Prepare or validate versions and exact internal graph",
    "Check release changelog section",
    "Install locked dependencies",
    "Compile all applications in default environment",
    "Prepare independent admission peer before source tests",
    "Validate all source and automation",
    "Check source with Credo",
    "Check source with Dialyzer",
    "Build and run Go HTTP E2E server",
    "Run all local imported transport gates",
    "Verify QUIC reliable streams under impairment",
    "Build pinned Caddy TLS fingerprint fixture",
    "Verify Caddy JA3 and JA4 observations",
    "Run pinned aioquic comparison",
    "Build documentation",
    "Verify HTTP/3 companion with pinned independent aioquic",
    "Require independent public HTTP3 before publication",
    "Build, inspect, and independently consume all eleven portable archives",
    "Require isolated candidate HTTP3 traffic",
    "Verify real HTTP/2 package traffic and TLS feature groups",
    "Prepare independent no-OTP SSL peers",
    "Require isolated candidate release without OTP SSL",
    "Preflight Hex and GitHub immutability before any remote write",
    "Check Hex publication credentials",
    "Record immutable release source",
    "Publish and verify packages in dependency order",
    "Verify published isolated HTTP3 traffic",
    "Verify published isolated TLS migration consumers",
    "Verify published server consumers",
    "Require isolated published release without OTP SSL",
    "Attach and verify all immutable GitHub release archives",
    "Preserve verified portable archives for asynchronous native publication",
)


def validate_provenance(run, jobs, repository, source_sha):
    if (run.get("repository", {}).get("full_name") != repository
            or run.get("event") != "workflow_dispatch"
            or run.get("path") != ".github/workflows/release.yml"
            or run.get("status") != "completed"
            or run.get("conclusion") != "failure"
            or run.get("head_sha") != source_sha):
        raise ValueError("source run must be the failed release workflow at the exact immutable tag")
    portable = [job for job in jobs if job.get("name") == PORTABLE_JOB]
    if len(portable) != 1 or portable[0].get("conclusion") != "failure":
        raise ValueError("exactly one failed portable release job required")
    steps = portable[0]["steps"]
    names = [step["name"] for step in steps]
    if len(set(names)) != len(names):
        raise ValueError("ambiguous duplicate release steps")
    states = {step["name"]: step["conclusion"] for step in steps}
    if states.get(DOCS_STEP) != "failure":
        raise ValueError("only documentation publication may have failed")
    for name in REQUIRED_STEPS:
        if states.get(name) != "success" or names.index(name) >= names.index(DOCS_STEP):
            raise ValueError(f"required release gate not successful before docs: {name}")
    if states.get("Record deferred static analysis") != "skipped":
        raise ValueError("deferred static analysis is not eligible for completion")
    for step in steps:
        if step["name"] != DOCS_STEP and step["conclusion"] not in ("success", "skipped"):
            raise ValueError(f"unrelated release failure: {step['name']}")
    for job in jobs:
        if job is not portable[0] and job.get("conclusion") not in ("success", "skipped"):
            raise ValueError(f"unrelated failed release job: {job.get('name')}")


def api(path, *, paginate=False):
    command = ["gh", "api", path]
    if paginate:
        command.extend(["--paginate", "--slurp"])
    return json.loads(subprocess.check_output(command, text=True))


def provenance(version, run_id, receipt):
    repository = os.environ["GITHUB_REPOSITORY"]
    source_sha = subprocess.check_output(
        ["git", "rev-parse", f"refs/tags/v{version}^{{commit}}"], cwd=ROOT, text=True).strip()
    run = api(f"repos/{repository}/actions/runs/{run_id}")
    pages = api(f"repos/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs?per_page=100",
                paginate=True)
    jobs = [job for page in pages for job in page["jobs"]]
    validate_provenance(run, jobs, repository, source_sha)
    receipt.write_text(json.dumps({"run": run, "jobs": jobs, "version": version,
                                   "source_sha": source_sha}, indent=2) + "\n")
    print(f"Verified source run {run_id} at {source_sha}")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"source_sha={source_sha}\n")


def artifacts(version, archives, stage_dir, source_sha):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    tagged = subprocess.check_output(
        ["git", "rev-parse", f"refs/tags/v{version}^{{commit}}"], cwd=ROOT, text=True).strip()
    if head != source_sha or tagged != source_sha or source_version(ROOT) != version:
        raise ValueError("artifact verification requires checkout of the exact verified source tag")
    stage_sources(stage_dir, RELEASE_PACKAGES)
    for package in RELEASE_PACKAGES:
        audit_package(package, version, stage_dir, archives)
    subprocess.run(["elixir", str(ROOT / "scripts/release/archives.exs"), version, str(archives)], check=True)
    for package in RELEASE_PACKAGES:
        if release_status(package, version, archives / f"{package}-{version}.tar") != "matching":
            raise ValueError(f"verified published portable archive required: {package}")
    verify_assets(os.environ["GITHUB_REPOSITORY"], f"v{version}",
                  [archives / f"{package}-{version}.tar" for package in RELEASE_PACKAGES])
    print("Verified all eleven published Hex/GitHub archives against the immutable tag")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    origin = commands.add_parser("provenance")
    origin.add_argument("version")
    origin.add_argument("run_id", type=int)
    origin.add_argument("receipt", type=Path)
    distribution = commands.add_parser("artifacts")
    distribution.add_argument("version")
    distribution.add_argument("archives", type=Path)
    distribution.add_argument("stage_dir", type=Path)
    distribution.add_argument("source_sha")
    args = parser.parse_args()
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.(?:0|[1-9]\d*))?", args.version):
        parser.error("canonical stable or RC version required")
    if args.mode == "provenance":
        provenance(args.version, args.run_id, args.receipt)
    else:
        artifacts(args.version, args.archives, args.stage_dir, args.source_sha)


if __name__ == "__main__":
    main()

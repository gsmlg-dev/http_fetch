#!/usr/bin/env python3
"""Select directly changed umbrella apps, or all apps for manual verification."""

import argparse
import json
import os
import subprocess
from pathlib import Path


APPS = (
    "ex_ssl", "elixir_quic", "http_core", "http_runtime", "elixir_quic_http3",
    "http_fetch", "http_web_socket", "http_event_source", "http_web_transport",
)
ALL = list(APPS)


def select_apps(paths, workflow):
    # Every path under an app belongs to that app, including docs and manifests.
    # Shared files and dependency relationships never expand automatic matrices.
    owners = {parts[1] for path in paths
              if len(parts := path.split("/")) >= 3 and parts[0] == "apps"}
    return [app for app in APPS if app in owners]


def changed_paths(base, head):
    if not base or not head:
        raise ValueError("Cannot determine changed paths: base and head revisions are required")
    base_zero = set(base) == {"0"}
    head_zero = set(head) == {"0"}
    if base_zero and head_zero:
        raise ValueError("Cannot determine changed paths: both revisions are zero SHAs")
    if base_zero or head_zero:
        # New/deleted branches compare the existing tree against an empty tree.
        # List actual tracked paths; do not silently select the package inventory.
        command = ["git", "ls-tree", "-r", "--name-only", "-z", head if base_zero else base]
    else:
        # Disable rename detection to retain both source and destination owners.
        command = ["git", "diff", "--name-only", "--no-renames", "-z", base, head]
    result = subprocess.run(command, capture_output=True, check=False)
    if result.returncode:
        detail = os.fsdecode(result.stderr).strip()
        raise ValueError(f"Cannot determine changed paths: {detail}")
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", required=True, choices=("ci.yml", "test.yml", "e2e.yml"))
    parser.add_argument("--event", required=True, choices=("push", "pull_request", "workflow_dispatch"))
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args()

    manual = args.event == "workflow_dispatch"
    if manual:
        apps = ALL
    else:
        try:
            apps = select_apps(changed_paths(args.base, args.head), args.workflow)
        except ValueError as error:
            parser.error(str(error))

    output = (f"apps={json.dumps(apps, separators=(',', ':'))}\n"
              f"has_changes={'true' if apps else 'false'}\n"
              f"full_gate={'true' if manual else 'false'}\n"
              f"historical_tls={'true' if manual else 'false'}\n")
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()

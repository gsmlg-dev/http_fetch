#!/usr/bin/env python3
"""Select app owners and affected H2 consumers from umbrella dependencies."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path


APPS = (
    "ex_ssl", "elixir_quic", "http_core", "http_runtime", "elixir_quic_http3",
    "http_fetch", "http_web_socket", "http_event_source", "http_web_transport",
)
ALL = list(APPS)


H2_CONSUMERS = ("http_fetch", "http_web_socket", "http_event_source")
ROOT = Path(__file__).resolve().parents[2]
SHARED_FILES = {"mix.exs", "mix.lock", ".formatter.exs", ".credo.exs",
                ".dialyzer_ignore.exs"}


def dependency_graph(root=ROOT):
    # Read the real in_umbrella declarations, including imported TLS/QUIC apps.
    graph = {}
    for app in APPS:
        source = (root / "apps" / app / "mix.exs").read_text()
        graph[app] = set(re.findall(
            r"\{:(\w+),[^{}]*\bin_umbrella:\s*true", source))
    return graph


def dependency_closure(app, graph):
    closure, pending = set(), [app]
    while pending:
        dependency = pending.pop()
        if dependency not in closure:
            closure.add(dependency)
            pending.extend(graph.get(dependency, ()))
    return closure


def shared_h2_path(path):
    return (path in SHARED_FILES or path.startswith(("config/", "scripts/ci/",
            ".github/workflows/", "scripts/http2_", "scripts/http_runtime_",
            "scripts/requirements-http2", "scripts/release/", "scripts/ex_ssl_")))


def affected_h2_consumers(paths, graph=None):
    graph = dependency_graph() if graph is None else graph
    if any(shared_h2_path(path) for path in paths):
        return list(H2_CONSUMERS)
    owners = {parts[1] for path in paths
              if len(parts := path.split("/")) >= 3 and parts[0] == "apps"
              and not (parts[2] == "docs" or path.endswith(".md"))}
    return [app for app in H2_CONSUMERS
            if owners & dependency_closure(app, graph)]


def select_apps(paths, workflow):
    owners = {parts[1] for path in paths
              if len(parts := path.split("/")) >= 3 and parts[0] == "apps"}
    selected = owners | set(affected_h2_consumers(paths))
    return [app for app in APPS if app in selected]


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
        h2_compat = True
    else:
        try:
            paths = changed_paths(args.base, args.head)
            apps = select_apps(paths, args.workflow)
            h2_compat = bool(affected_h2_consumers(paths))
        except ValueError as error:
            parser.error(str(error))

    output = (f"apps={json.dumps(apps, separators=(',', ':'))}\n"
              f"has_changes={'true' if apps else 'false'}\n"
              f"full_gate={'true' if manual else 'false'}\n"
              f"h2_compat={'true' if h2_compat else 'false'}\n"
              f"historical_tls={'true' if manual else 'false'}\n")
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Select affected umbrella apps for a GitHub Actions workflow."""

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
DEPENDENCIES = {
    "ex_ssl": (),
    "elixir_quic": ("ex_ssl",),
    "http_core": ("ex_ssl", "elixir_quic"),
    "http_runtime": ("http_core", "elixir_quic_http3"),
    "elixir_quic_http3": ("http_core", "elixir_quic"),
    "http_fetch": ("http_core", "http_runtime"),
    "http_web_socket": ("http_core", "http_runtime"),
    "http_event_source": ("http_core", "http_runtime"),
    "http_web_transport": ("http_core",),
}
QUIC_SCRIPTS = ("scripts/interop/", "scripts/phase1/", "scripts/datagram/", "scripts/http3/")
SHARED = ("mix.exs", "mix.lock", ".formatter.exs", ".credo.exs", ".dialyzer_ignore.exs")
PACKAGE_SCRIPTS = ("scripts/release/", "scripts/external_consumer_smoke", "scripts/http_runtime_", "scripts/http2_package_gate", "scripts/ex_ssl_")


def dependents(app):
    selected = {app}
    while True:
        expanded = selected | {
            child for child, parents in DEPENDENCIES.items() if selected.intersection(parents)
        }
        if expanded == selected:
            return selected
        selected = expanded


def needs_full_gate(paths, workflow):
    own_workflow = f".github/workflows/{workflow}"
    return any(
        path in SHARED or path in (own_workflow, ".github/workflows/changes.yml")
        or any(path == f"apps/{app}/mix.exs" for app in APPS)
        or path.startswith(("apps/ex_ssl/lib/", "apps/http_core/lib/"))
        or path.startswith(("config/", "scripts/ci/", *PACKAGE_SCRIPTS))
        for path in paths
    )


def needs_historical_tls(paths):
    return any(
        path in SHARED or path == "apps/ex_ssl/mix.exs"
        or path.startswith(("apps/ex_ssl/lib/", "config/", "scripts/ex_ssl_"))
        for path in paths
    )


def select_apps(paths, workflow):
    selected = set()
    own_workflow = f".github/workflows/{workflow}"

    for path in paths:
        if (
            path in SHARED
            or path == own_workflow
            or path == ".github/workflows/changes.yml"
            or path.startswith(("config/", "scripts/ci/"))
        ):
            return ALL
        for app in APPS:
            if path.startswith(f"apps/{app}/"):
                if path.endswith((".md", ".txt")) or any(
                    segment in path for segment in ("/docs/", "/test/", "/e2e/")
                ):
                    selected.add(app)
                else:
                    selected.update(dependents(app))
        if path.startswith(QUIC_SCRIPTS):
            selected.update(dependents("elixir_quic"))
        if path.startswith(PACKAGE_SCRIPTS):
            return ALL

    return [app for app in APPS if app in selected]


def changed_paths(base, head):
    if not base or set(base) == {"0"}:
        return None
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", base, head],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return None
    # --no-renames reports both the deleted source and added destination.
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", required=True, choices=("ci.yml", "test.yml", "e2e.yml"))
    parser.add_argument("--event", required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--manual-module", default="")
    args = parser.parse_args()

    if args.event == "workflow_dispatch":
        if args.manual_module not in (*APPS, "all"):
            parser.error("manual E2E module must be all or an umbrella app")
        apps = ALL if args.manual_module == "all" else [args.manual_module]
    else:
        paths = changed_paths(args.base, args.head)
        apps = ALL if paths is None else select_apps(paths, args.workflow)

    if args.event == "workflow_dispatch":
        full_gate = args.manual_module == "all"
        historical_tls = args.manual_module in ("all", "ex_ssl")
    else:
        full_gate = paths is None or needs_full_gate(paths, args.workflow)
        historical_tls = paths is None or needs_historical_tls(paths)
    output = (f"apps={json.dumps(apps, separators=(',', ':'))}\n"
              f"has_changes={'true' if apps else 'false'}\n"
              f"full_gate={'true' if full_gate else 'false'}\n"
              f"historical_tls={'true' if historical_tls else 'false'}\n")
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")


if __name__ == "__main__":
    main()

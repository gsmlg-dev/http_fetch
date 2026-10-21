#!/usr/bin/env python3
"""Bounded source inventory for the TLS migration; not a runtime-removal proof.

Run from any directory. Output JSON contains source identities and review candidates.
String literals, comments and compatibility message names can match: classify them
in docs/tls-migration-design.md before treating them as executable dependencies.
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "otp_call_or_type": r":ssl\s*\.",
    "dynamic_dispatch": r"\bapply\s*\(|:erlang\.apply|TLSBackend\.transport|tls_transport\(",
    "private_socket": r":sslsocket|:cancellable_ssl",
    "backend_selection": r"tls_backend|def transport\(:ssl\)",
    "application_dependency": r"extra_applications|included_applications|optional_applications",
}


def inventory():
    results = []
    for app in sorted((ROOT / "apps").iterdir()):
        if not app.is_dir():
            continue
        paths = [app / "mix.exs", *sorted((app / "lib").rglob("*.ex"))]
        for path in paths:
            if not path.is_file():
                continue
            data = path.read_bytes()
            matches = []
            for line_number, line in enumerate(data.decode("utf-8").splitlines(), 1):
                categories = [name for name, pattern in PATTERNS.items() if re.search(pattern, line)]
                if categories:
                    matches.append({"line": line_number, "categories": categories, "text": line.strip()})
            if matches:
                results.append({"path": str(path.relative_to(ROOT)),
                                "sha256": hashlib.sha256(data).hexdigest(), "matches": matches})
    return results


def main():
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).splitlines()
    print(json.dumps({"schema_version": 1, "head": head, "working_tree": status,
                      "scope": "apps/*/lib/**/*.ex and apps/*/mix.exs; excludes test, e2e, docs, scripts",
                      "limitation": "review candidates only; no BEAM, dynamic-target or release-closure proof",
                      "files": inventory()}, indent=2))


if __name__ == "__main__":
    main()

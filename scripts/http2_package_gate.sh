#!/usr/bin/env bash
# Candidate package H2 gate using Hex resolution and a real independent peer.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=${HTTP_FETCH_RELEASE_VERSION:-$(sed -n 's/.*@version "\([^"]*\)".*/\1/p' "$repo_root/mix.exs")}
if [[ -n "${HTTP_FETCH_ARCHIVE_DIR:-}" ]]; then
  archive_dir=$HTTP_FETCH_ARCHIVE_DIR
else
  work_dir=$(mktemp -d "${TMPDIR:-/tmp}/http-fetch-h2-candidate.XXXXXXXX")
  trap 'rm -rf "$work_dir"' EXIT
  archive_dir=$work_dir/archives
  python3 "$repo_root/scripts/release/stage.py" build "$version" "$work_dir/stage" "$archive_dir"
fi
elixir "$repo_root/scripts/release/archives.exs" "$version" "$archive_dir"
python3 "$repo_root/scripts/release/consumer_gate.py" "$version" "$archive_dir" --mode h2

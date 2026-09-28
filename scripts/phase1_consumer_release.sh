#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d)
release_started=0
release_pid=
cleanup() {
  if [[ "$release_started" == 1 ]]; then "$work_dir/release/bin/phase1_consumer" stop || true; fi
  if [[ -n "$release_pid" ]]; then kill "$release_pid" 2>/dev/null || true; wait "$release_pid" 2>/dev/null || true; fi
  rm -rf "$work_dir"
}
trap cleanup EXIT
mkdir -p "$work_dir/consumer" "$work_dir/http_core"
# A standalone source artifact: Git dependencies are intentionally not a Hex
# publication. Do not reuse the umbrella build, lockfile or adjacent repositories.
cp "$repo_root/apps/http_core/mix.exs" "$work_dir/http_core/"
cp -R "$repo_root/apps/http_core/lib" "$work_dir/http_core/"
cp "$repo_root/scripts/phase1_release_check.exs" "$work_dir/consumer/check.exs"
cat > "$work_dir/consumer/mix.exs" <<'MIX'
defmodule Phase1Consumer.MixProject do
  use Mix.Project
  def project, do: [app: :phase1_consumer, version: "0.1.0", deps: [{:http_core, path: "../http_core"}]]
  def application, do: [extra_applications: [:logger]]
end
MIX
cd "$work_dir/consumer"
export MIX_ENV=prod
export MIX_BUILD_PATH="$work_dir/build"
mix deps.get
mix deps.tree --only runtime
mix compile --warnings-as-errors
mix run -e '
lock = Mix.Dep.Lock.read()
{:git, _, "f1327e0bb7fb2093b8dc2b07e72b26233a739963", _} = lock[:ex_ssl]
{:git, _, "5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb", _} = lock[:ex_quic]
[:ex_ssl] = for dep <- Mix.Dep.cached(), dep.app == :ex_ssl, do: dep.app
Code.eval_file("check.exs")
'
mix release --path "$work_dir/release"
export RELEASE_NODE="http_fetch_phase1_$$"
"$work_dir/release/bin/phase1_consumer" start > "$work_dir/release.log" 2>&1 &
release_pid=$!
release_started=1
# A finite readiness barrier for the freshly spawned release, not a test retry.
ready=0
for attempt in {1..50}; do
  if "$work_dir/release/bin/phase1_consumer" rpc ':ok' >/dev/null 2>&1; then ready=1; break; fi
  if ! kill -0 "$release_pid" 2>/dev/null; then cat "$work_dir/release.log"; exit 1; fi
  sleep 0.1
done
if [[ "$ready" != 1 ]]; then cat "$work_dir/release.log"; exit 1; fi
"$work_dir/release/bin/phase1_consumer" rpc "Code.eval_file(\"$work_dir/consumer/check.exs\")"
"$work_dir/release/bin/phase1_consumer" stop
release_started=0
wait "$release_pid"
release_pid=
printf '%s\n' 'PHASE1_CONSUMER_RELEASE_PASS'

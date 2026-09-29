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
# Resolve published packages in an isolated consumer. Do not reuse the umbrella
# build, lockfile or adjacent repositories.
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
{:hex, :ex_ssl, "0.7.2", "cba8ff536d7571537e75d112d2712ba49b5b406bc475acc1dda253b513229ab3", _, _, "hexpm", "f0f9532a6ac8b2dcb701b491394705df8f10c31f63fc7e5aad157eebb909aecb"} = lock[:ex_ssl]
{:hex, :elixir_quic, "0.2.2", "8dd7017d98d76c2bf0b875859d015d6694cc8206bc246dc423c7b77b5333425b", _, _, "hexpm", "2c73402421edf4156db843bbf11fe26aa5cd78eb1ae7acac863ed41fa47e8c74"} = lock[:elixir_quic]
for app <- [:ex_ssl, :elixir_quic] do
  [dep] = for dependency <- Mix.Dep.cached(), dependency.app == app, do: dependency
  true = dep.scm == Hex.SCM
end
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

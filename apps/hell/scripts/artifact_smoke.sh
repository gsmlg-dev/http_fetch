#!/usr/bin/env bash
set -euo pipefail

artifact=${1:?Usage: bash scripts/artifact_smoke.sh PACKAGE.tar VERSION}
version=${2:?Expected package version required}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
app_root=$(cd "$(dirname "$0")/.." && pwd)
repo_root=$(cd "$app_root/../.." && pwd)
artifact=$(cd "$(dirname "$artifact")" && pwd)/$(basename "$artifact")
[[ -f "$artifact" ]]
[[ -d "$repo_root/deps/telemetry" ]] || { echo 'Run mix deps.get with the existing mix.lock first' >&2; exit 1; }
consumer_dir=$(mktemp -d "${TMPDIR:-/tmp}/hell-consumer.XXXXXX")
trap 'rm -rf "$consumer_dir"' EXIT

# Hex verifies the package's internal checksum before safe in-memory extraction.
mix run --no-compile --no-deps-check --no-start "$app_root/scripts/check_package.exs" \
  "$artifact" "$consumer_dir/package" "$version"
export HELL_PACKAGE_DIR="$consumer_dir/package"
cp -R "$repo_root/deps/telemetry" "$consumer_dir/telemetry"
export HELL_TELEMETRY_DIR="$consumer_dir/telemetry"
cp -R "$app_root/test" "$consumer_dir/test"
export HELL_TEST_DIR="$consumer_dir/test"
export HELL_FIXTURE_DIR="$consumer_dir/test/support"
export HELL_EXPECTED_VERSION="$version"
cat > "$consumer_dir/mix.exs" <<'MIX'
defmodule HellArtifactConsumer.MixProject do
  use Mix.Project

  def project do
    [
      app: :hell_artifact_consumer,
      version: "0.0.0",
      deps: [
        {:hell, path: System.fetch_env!("HELL_PACKAGE_DIR")},
        {:telemetry, path: System.fetch_env!("HELL_TELEMETRY_DIR"), override: true}
      ]
    ]
  end

  def application, do: [extra_applications: [:hell]]
end
MIX
unset MIX_BUILD_PATH MIX_DEPS_PATH ERL_LIBS
cd "$consumer_dir"
MIX_ENV=prod mix deps.get --offline
MIX_ENV=prod mix run "$app_root/scripts/artifact_smoke.exs"

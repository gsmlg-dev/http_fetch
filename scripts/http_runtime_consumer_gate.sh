#!/usr/bin/env bash
# Package dependency/startup proof, plus H2 traffic when a peer URL is supplied.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d /tmp/http-runtime-consumer.XXXXXXXX)
trap 'rm -rf "$work_dir"' EXIT
unset MIX_BUILD_PATH MIX_DEPS_PATH MIX_ENV GIT_DIR GIT_WORK_TREE

export HTTP_RUNTIME_PACKAGE_DIR="$work_dir/packages"
export HTTP_RUNTIME_REPO_ROOT="$repo_root"
mkdir -p "$HTTP_RUNTIME_PACKAGE_DIR"
apps=(http_core http_runtime elixir_quic_http3 http_fetch http_web_socket http_event_source http_web_transport)
for app in "${apps[@]}"; do
  (
    cd "$repo_root/apps/$app"
    MIX_ENV=prod MIX_BUILD_PATH="$work_dir/package-build" \
      mix hex.build --unpack -o "$HTTP_RUNTIME_PACKAGE_DIR/$app"
  )
done

# Audit original Hex metadata before rewriting only temporary shared dependency paths.
elixir "$repo_root/scripts/http_runtime_consumer_gate.exs" prepare

for selected in http_fetch http_event_source http_web_socket http_fetch,http_event_source,http_web_socket; do
  consumer_dir="$work_dir/consumer-${selected//,/-}"
  mkdir -p "$consumer_dir"
  cat > "$consumer_dir/mix.exs" <<'ELIXIR'
defmodule RuntimeConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :runtime_consumer, version: "0.1.0", deps: deps()]
  def application, do: [extra_applications: [:logger]]
  defp deps do
    packages = System.fetch_env!("HTTP_RUNTIME_PACKAGE_DIR")
    for client <- String.split(System.fetch_env!("HTTP_RUNTIME_CONSUMER_CLIENTS"), ","),
      do: {String.to_atom(client), path: Path.join(packages, client)}
  end
end
ELIXIR
  cp "$repo_root/mix.lock" "$consumer_dir/mix.lock"
  cp "$repo_root/scripts/http_runtime_consumer_gate.exs" "$consumer_dir/gate.exs"
  (
    cd "$consumer_dir"
    export HTTP_RUNTIME_CONSUMER_CLIENTS="$selected"
    export MIX_ENV=prod MIX_BUILD_PATH="$consumer_dir/build" MIX_DEPS_PATH="$consumer_dir/deps"
    mix deps.get --check-locked
    mix deps.tree --only runtime
    mix compile --warnings-as-errors
    mix run gate.exs verify
  )
done
printf '{"result":"PASS","gate":"http_runtime_consumers","consumers":4,"packages":7}\n'

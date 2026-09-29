#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d /tmp/http2-package-gate.XXXXXX)
package_dir="$work_dir/packages"
consumer_dir="$work_dir/consumer"
mkdir -p "$package_dir" "$consumer_dir"
apps=(http_core elixir_quic_http3 http_fetch http_web_socket http_event_source http_web_transport)
for app in "${apps[@]}"; do
  (
    cd "$repo_root/apps/$app"
    MIX_ENV=prod MIX_BUILD_PATH="$work_dir/package-build" mix hex.build --unpack -o "$package_dir/$app"
  )
done
cat > "$consumer_dir/mix.exs" <<'ELIXIR'
defmodule HTTP2PackageConsumer.MixProject do
  use Mix.Project
  def project, do: [app: :http2_package_consumer, version: "0.1.0", deps: deps()]
  def application, do: [extra_applications: [:logger]]
  defp deps do
    root = System.fetch_env!("HTTP_FETCH_PACKAGE_DIR")
    for app <- [:http_core, :elixir_quic_http3, :http_fetch, :http_web_socket, :http_event_source, :http_web_transport],
      do: {app, path: Path.join(root, Atom.to_string(app)), override: true}
  end
end
ELIXIR
cp "$repo_root/scripts/http2_production_gate.exs" "$consumer_dir/gate.exs"
(
  cd "$consumer_dir"
  export HTTP_FETCH_PACKAGE_DIR="$package_dir"
  export MIX_BUILD_PATH="$work_dir/consumer-build"
  MIX_ENV=prod mix deps.get
  MIX_ENV=prod mix compile --warnings-as-errors
  MIX_ENV=prod mix run gate.exs
)
printf 'package_consumer=%s\n' "$consumer_dir"

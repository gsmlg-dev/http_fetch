#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

package_dir="$work_dir/packages"
consumer_dir="$work_dir/consumer"
mkdir -p "$package_dir"

apps=(http_core http_fetch http_web_socket http_event_source http_web_transport)

for app in "${apps[@]}"; do
  (
    cd "$repo_root/apps/$app"
    MIX_ENV=prod mix hex.build --unpack -o "$package_dir/$app"
  )
done

mix new "$consumer_dir" --sup >/dev/null

cat >"$consumer_dir/mix.exs" <<'EOF'
defmodule ExternalConsumer.MixProject do
  use Mix.Project

  def project do
    [app: :external_consumer, version: "0.1.0", deps: deps()]
  end

  def application do
    [extra_applications: [:logger, :public_key, :ssl]]
  end

  defp deps do
    package_dir = System.fetch_env!("HTTP_FETCH_PACKAGE_DIR")

    [
      {:http_core, path: Path.join(package_dir, "http_core")},
      {:http_fetch, path: Path.join(package_dir, "http_fetch")},
      {:http_web_socket, path: Path.join(package_dir, "http_web_socket")},
      {:http_event_source, path: Path.join(package_dir, "http_event_source")},
      {:http_web_transport, path: Path.join(package_dir, "http_web_transport")}
    ]
  end
end
EOF

cp "$repo_root/scripts/external_consumer_smoke.exs" "$consumer_dir/smoke.exs"

(
  cd "$consumer_dir"
  export HTTP_FETCH_PACKAGE_DIR="$package_dir"
  export HTTP_FETCH_CERTFILE="$repo_root/apps/http_fetch/test/support/fixtures/localhost.pem"
  export HTTP_FETCH_CACERTFILE="$repo_root/apps/http_fetch/test/support/fixtures/localhost-ca.pem"
  export HTTP_FETCH_KEYFILE="$repo_root/apps/http_fetch/test/support/fixtures/localhost.key"
  MIX_ENV=prod mix deps.get
  MIX_ENV=prod mix deps.tree --only runtime
  MIX_ENV=prod mix compile --warnings-as-errors
  MIX_ENV=prod mix run smoke.exs
)

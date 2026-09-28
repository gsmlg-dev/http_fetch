#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/http-fetch-phase1-abyss.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/http_core" "$work/consumer" "$work/fixtures"
cp "$root/apps/http_core/mix.exs" "$work/http_core/mix.exs"
cp -R "$root/apps/http_core/lib" "$work/http_core/lib"
cp -R "$root/apps/http_fetch/test/support/fixtures/." "$work/fixtures"
cp "$root/scripts/phase1_quic_abyss.exs" "$work/consumer/phase1_quic_abyss.exs"

cat > "$work/consumer/mix.exs" <<'EOF'
defmodule Phase1AbyssConsumer.MixProject do
  use Mix.Project

  def project do
    [app: :phase1_abyss_consumer, version: "0.0.0", elixir: "~> 1.18", deps: deps()]
  end

  def application, do: [extra_applications: [:logger, :public_key]]

  defp deps do
    [
      {:http_core, path: "../http_core"},
      {:abyss, git: "https://github.com/gsmlg-dev/abyss.git", ref: "50e121fce66daeb9cb25a2f5dc93050ca37efc5d"}
    ]
  end
end
EOF

export MIX_ENV=prod
export MIX_BUILD_PATH="$work/build"
export HTTP_QUIC_FIXTURES="$work/fixtures"
cd "$work/consumer"
mix deps.get
mix compile --warnings-as-errors
mix run phase1_quic_abyss.exs

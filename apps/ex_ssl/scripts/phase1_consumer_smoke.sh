#!/usr/bin/env bash
# Build an unpublished package and exercise normal application dependency startup.
set -euo pipefail

candidate=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$candidate/_build/phase1"
work=$(mktemp -d "$candidate/_build/phase1/consumer.XXXXXX")
trap 'rm -rf "$work"' EXIT
unset MIX_BUILD_PATH MIX_DEPS_PATH
export MIX_ENV=prod

cd "$candidate"
MIX_BUILD_PATH="$work/package-build" mix hex.build --unpack -o "$work/package"
mkdir -p "$work/consumer"
cat > "$work/consumer/mix.exs" <<'ELIXIR'
defmodule Phase1Consumer.MixProject do
  use Mix.Project
  def project do
    [app: :phase1_consumer, version: "0.0.0",
     deps: [{:ex_ssl, path: System.fetch_env!("EX_SSL_PACKAGE_DIR")}]]
  end
  def application, do: []
end
ELIXIR

cd "$work/consumer"
export EX_SSL_PACKAGE_DIR="$work/package"
export EX_SSL_FIXTURE_DIR="$candidate/test/fixtures/server_flight"
mix deps.get
mix compile --warnings-as-errors

# A fresh VM excludes Mix/Hex tooling, which may itself start OTP :ssl.
elixir -pa _build/prod/lib/ex_ssl/ebin -pa _build/prod/lib/phase1_consumer/ebin -e '
  {:ok, started} = Application.ensure_all_started(:phase1_consumer)
  true = Enum.all?([:crypto, :public_key, :ex_ssl, :phase1_consumer], &(&1 in started))
  deps = Application.spec(:ex_ssl, :applications)
  true = :crypto in deps and :public_key in deps
  false = :ssl in deps
  false = Enum.any?(Application.started_applications(), fn {app, _, _} -> app == :ssl end)
  true = Code.ensure_loaded?(SSL.QUIC)
  true = Enum.all?([new: 2, feed: 3, info: 1, abort: 2, capabilities: 0],
    fn {name, arity} -> function_exported?(SSL.QUIC, name, arity) end)
  fixture = System.fetch_env!("EX_SSL_FIXTURE_DIR")
  [{:Certificate, root, :not_encrypted}] =
    File.read!(Path.join(fixture, "root.pem")) |> :public_key.pem_decode()
  {:ok, state, [{:emit, :initial, <<1, _::binary>>}]} = SSL.QUIC.new(:client,
    cacerts: [root], reference_identity: {:dns_id, "example.test"},
    alpn: [<<0, 255, 1>>], transport_parameters: <<>>)
  %{phase: :aborted} = state |> SSL.QUIC.abort(:consumer_shutdown) |> SSL.QUIC.info()
  false = Enum.any?(Application.started_applications(), fn {app, _, _} -> app == :ssl end)
  IO.puts("PASS packaged consumer startup: crypto/public_key/ex_ssl; SSL.QUIC public API; no OTP ssl")
  :ok = Application.stop(:phase1_consumer)
  :ok = Application.stop(:ex_ssl)
'

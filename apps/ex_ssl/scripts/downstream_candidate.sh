#!/usr/bin/env bash
# Source-candidate evidence only. Never edits a companion checkout or publishes.
set -euo pipefail

candidate=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly consumer_sha=6a6c93e5c852e2e2bbffcc2186bef9bf34a79cac
work=$(mktemp -d "${TMPDIR:-/tmp}/exssl-candidate.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/tmp"
export TMPDIR="$work/tmp"
# Inherited global paths would alias the package and consumer projects.
unset MIX_BUILD_PATH MIX_DEPS_PATH MIX_ENV

printf 'Candidate ex_ssl HEAD: %s\n' "$(git -C "$candidate" rev-parse HEAD)"
printf 'Candidate working-tree changes (included in this check):\n'
git -C "$candidate" status --short
printf 'Pinned http_fetch SHA: %s\n' "$consumer_sha"
git init -q "$work/http_fetch"
git -C "$work/http_fetch" fetch --quiet --depth 1 https://github.com/gsmlg-dev/http_fetch.git "$consumer_sha"
git -C "$work/http_fetch" checkout --quiet --detach FETCH_HEAD
test "$(git -C "$work/http_fetch" rev-parse HEAD)" = "$consumer_sha"
test -f "$work/http_fetch/scripts/ex_ssl_source_smoke.sh"

printf '\nStandalone package/startup boundary (unpublished candidate)\n'
(
  cd "$candidate"
  MIX_ENV=prod MIX_BUILD_PATH="$work/package-build" mix hex.build --unpack -o "$work/package"
)
mkdir -p "$work/standalone"
cat > "$work/standalone/mix.exs" <<'ELIXIR'
defmodule StandaloneCandidate.MixProject do
  use Mix.Project
  def project do
    [app: :standalone_candidate, version: "0.0.0",
     deps: [{:ex_ssl, path: System.fetch_env!("EX_SSL_PACKAGE_DIR")}]]
  end
  def application, do: []
end
ELIXIR
(
  cd "$work/standalone"
  export EX_SSL_PACKAGE_DIR="$work/package" MIX_ENV=prod
  mix deps.get
  mix compile --warnings-as-errors
  # A fresh VM excludes Mix/Hex tooling, which can itself start OTP :ssl.
  elixir -pa _build/prod/lib/ex_ssl/ebin -e '
    {:ok, _} = Application.ensure_all_started(:ex_ssl)
    true = Code.ensure_loaded?(SSL)
    false = :ssl in Application.spec(:ex_ssl, :applications)
    false = Enum.any?(Application.started_applications(), fn {app, _, _} -> app == :ssl end)
    true = is_pid(Process.whereis(SSL.ConnectionSupervisor))
    true = is_pid(Process.whereis(SSL.TicketCache))
    IO.puts("Standalone loaded ex_ssl: #{:code.which(SSL)} version=#{Application.spec(:ex_ssl, :vsn)}")
    :ok = Application.stop(:ex_ssl)
  '
)

# Pass an additional test through the existing script interface. The pinned
# consumer sources stay untouched; its own temporary project owns all overrides.
cat > "$work/candidate_boundary_test.exs" <<'ELIXIR'
defmodule SourceCandidateBoundaryTest do
  use ExUnit.Case, async: false
  test "the packaged HTTP consumer actually loads this source candidate" do
    expected = System.fetch_env!("EX_SSL_SOURCE_DIR") |> Path.expand()
    assert Path.expand(Mix.Project.deps_paths()[:ex_ssl]) == expected
    assert {:source, source} = List.keyfind(SSL.module_info(:compile), :source, 0)
    assert Path.expand(to_string(source)) == Path.join(expected, "lib/ssl.ex")
    assert :code.which(SSL) != :non_existing
    IO.puts("Source candidate loaded ex_ssl: #{:code.which(SSL)} version=#{Application.spec(:ex_ssl, :vsn)} source=#{source}")
  end
end
ELIXIR
printf '\nPinned downstream source-candidate integration (not published Hex validation), seed 36\n'
(
  cd "$work/http_fetch"
  EX_SSL_DEP_MODE=source EX_SSL_SOURCE_DIR="$candidate" \
    bash scripts/ex_ssl_source_smoke.sh test "$work/candidate_boundary_test.exs"
)

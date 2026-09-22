#!/usr/bin/env bash
# Cross-repository candidate validation. Release smoke remains external_consumer_smoke.sh.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${EX_SSL_SOURCE_DIR:?Set EX_SSL_SOURCE_DIR to the candidate ex_ssl checkout}"
export EX_SSL_SOURCE_DIR=$(cd "$EX_SSL_SOURCE_DIR" && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
export HTTP_FETCH_PACKAGE_DIR="$work_dir/packages"
mkdir -p "$HTTP_FETCH_PACKAGE_DIR" "$work_dir/consumer/test"
for app in http_core http_fetch http_web_socket http_event_source http_web_transport; do
  (cd "$repo_root/apps/$app" && MIX_ENV=prod mix hex.build --unpack -o "$HTTP_FETCH_PACKAGE_DIR/$app")
done
cat > "$work_dir/consumer/mix.exs" <<'MIX'
defmodule CandidateConsumer.MixProject do
  use Mix.Project
  def project do
    packages = System.fetch_env!("HTTP_FETCH_PACKAGE_DIR")
    [app: :candidate_consumer, version: "0.0.0", deps: [
      {:http_core, path: Path.join(packages, "http_core")},
      {:http_fetch, path: Path.join(packages, "http_fetch")},
      {:http_web_socket, path: Path.join(packages, "http_web_socket")},
      {:http_event_source, path: Path.join(packages, "http_event_source")},
      {:http_web_transport, path: Path.join(packages, "http_web_transport")},
      {:ex_ssl, path: System.fetch_env!("EX_SSL_SOURCE_DIR"), override: true}
    ]]
  end
  def application, do: [extra_applications: [:logger, :ssl, :public_key]]
end
MIX
cp "$repo_root/mix.lock" "$work_dir/consumer/mix.lock"
for test_file in "$repo_root"/scripts/ex_ssl_*_test.exs; do
  cp "$test_file" "$work_dir/consumer/test/$(basename "$test_file")"
done
printf 'ExUnit.start()\n' > "$work_dir/consumer/test/test_helper.exs"
(cd "$work_dir/consumer" && mix deps.get && mix compile --warnings-as-errors && mix test "$@" --seed 36)

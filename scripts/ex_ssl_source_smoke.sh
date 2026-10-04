#!/usr/bin/env bash
# Feature-consumer validation. Source candidates and released Hex dependencies are separate modes.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=ex_ssl_fixture_manifest.env
source "$repo_root/scripts/ex_ssl_fixture_manifest.env"
export EX_SSL_FIXTURE_REPOSITORY EX_SSL_FIXTURE_VERSION EX_SSL_FIXTURE_COMMIT
export EX_SSL_HEX_INNER_CHECKSUM EX_SSL_HEX_OUTER_CHECKSUM
: "${EX_SSL_DEP_MODE:=source}"
: "${EX_SSL_TEST_SEED:=36}"
: "${EX_SSL_RESULTS_DIR:=$repo_root/.ex_ssl-results}"
: "${EX_SSL_GATE_TIMEOUT_SECONDS:=1800}"
export EX_SSL_DEP_MODE EX_SSL_TEST_SEED EX_SSL_RESULTS_DIR

if [[ "${EX_SSL_GATE_IN_TIMEOUT:-}" != 1 ]]; then
  exec env EX_SSL_GATE_IN_TIMEOUT=1 timeout --preserve-status "$EX_SSL_GATE_TIMEOUT_SECONDS" "$0" "$@"
fi

if [[ "$EX_SSL_DEP_MODE" != source && "$EX_SSL_DEP_MODE" != published && "$EX_SSL_DEP_MODE" != candidate ]]; then
  echo "EX_SSL_DEP_MODE must be source, published, or candidate" >&2
  exit 2
fi
if (( $# != 0 )); then
  echo "feature gate does not accept Mix test arguments; use EX_SSL_TEST_SEED for deterministic runs" >&2
  exit 2
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/http-fetch-ex-ssl.XXXXXXXX")
mkdir -p "$work_dir/tmp"
export TMPDIR="$work_dir/tmp"
unset MIX_BUILD_PATH MIX_DEPS_PATH MIX_ENV
consumer_dir="$work_dir/consumer"
fixture_dir=""
required_fixtures=(test/support/signature_fixtures.ex test/support/client_auth_fixtures.ex)
required_groups=(
  ex_ssl_algorithms_test.exs ex_ssl_mtls_redirects_test.exs ex_ssl_mtls_streams_test.exs
  ex_ssl_mtls_test.exs ex_ssl_options_test.exs ex_ssl_resumption_test.exs ex_ssl_resumption_policy_test.exs
  ex_ssl_resumption_lifecycle_test.exs ex_ssl_tls12_test.exs
)
test_log="$work_dir/test.log"
provenance_log="$work_dir/provenance.log"
group_log_dir="$work_dir/groups"
export EX_SSL_TEST_LOG="$test_log" EX_SSL_PROVENANCE_LOG="$provenance_log"
export EX_SSL_GROUP_LOG_DIR="$group_log_dir"

cleanup() {
  local status=$?
  export EX_SSL_GATE_STATUS="$status"
  if ! "$repo_root/scripts/ex_ssl_feature_report.sh"; then
    [[ "$status" == 0 ]] && status=1
  fi
  rm -rf "$work_dir"
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for prerequisite in git mix python3 openssl timeout; do
  command -v "$prerequisite" >/dev/null || { echo "required prerequisite missing: $prerequisite" >&2; exit 2; }
done

validate_fixture_checkout() {
  local directory=$1 actual_commit fixture
  [[ -d "$directory" ]] || { echo "fixture checkout does not exist: $directory" >&2; exit 2; }
  actual_commit=$(git -C "$directory" rev-parse HEAD 2>/dev/null) || {
    echo "fixture directory is not a Git checkout: $directory" >&2; exit 2;
  }
  [[ "$actual_commit" == "$EX_SSL_FIXTURE_COMMIT" ]] || {
    echo "fixture checkout must be pinned to $EX_SSL_FIXTURE_COMMIT, found $actual_commit" >&2; exit 2;
  }
  for fixture in "${required_fixtures[@]}"; do
    [[ -f "$directory/$fixture" ]] || { echo "fixture checkout is missing $fixture" >&2; exit 2; }
    [[ "$(git -C "$directory" rev-parse "$EX_SSL_FIXTURE_COMMIT:$fixture")" == \
      "$(git hash-object "$directory/$fixture")" ]] || {
      echo "fixture file differs from $EX_SSL_FIXTURE_COMMIT: $fixture" >&2
      exit 2
    }
  done
}

if [[ "$EX_SSL_DEP_MODE" == source ]]; then
  : "${EX_SSL_SOURCE_DIR:?Set EX_SSL_SOURCE_DIR to the candidate ex_ssl checkout for source mode}"
  export EX_SSL_SOURCE_DIR=$(cd "$EX_SSL_SOURCE_DIR" && pwd)
fi

if [[ -n "${EX_SSL_FIXTURE_DIR:-}" ]]; then
  [[ -d "$EX_SSL_FIXTURE_DIR" ]] || {
    echo "fixture checkout does not exist: $EX_SSL_FIXTURE_DIR" >&2
    exit 2
  }
  fixture_dir=$(cd "$EX_SSL_FIXTURE_DIR" && pwd)
  validate_fixture_checkout "$fixture_dir"
else
  fixture_dir="$work_dir/fixtures"
  git clone --no-checkout "$EX_SSL_FIXTURE_REPOSITORY" "$fixture_dir" >/dev/null 2>&1
  git -C "$fixture_dir" fetch --depth 1 origin "$EX_SSL_FIXTURE_COMMIT" >/dev/null 2>&1
  git -C "$fixture_dir" checkout --detach --quiet "$EX_SSL_FIXTURE_COMMIT"
  validate_fixture_checkout "$fixture_dir"
fi

export EX_SSL_DEP_MODE EX_SSL_FIXTURE_DIR="$fixture_dir"
if [[ "$EX_SSL_DEP_MODE" == candidate ]]; then
  : "${EX_SSL_CANDIDATE_ARCHIVE_DIR:?Set EX_SSL_CANDIDATE_ARCHIVE_DIR to the nine candidate Hex archives}"
  version=${HTTP_FETCH_RELEASE_VERSION:-$(sed -n 's/.*@version "\([^"]*\)".*/\1/p' "$repo_root/mix.exs")}
  python3 "$repo_root/scripts/release/consumer_gate.py" "$version" "$EX_SSL_CANDIDATE_ARCHIVE_DIR" --mode feature
  exit 0
fi
export HTTP_FETCH_PACKAGE_DIR="$work_dir/packages"
mkdir -p "$HTTP_FETCH_PACKAGE_DIR" "$consumer_dir/test" "$EX_SSL_RESULTS_DIR" "$group_log_dir"

for group in "${required_groups[@]}"; do
  [[ -f "$repo_root/scripts/$group" ]] || { echo "required feature group missing: $group" >&2; exit 2; }
done

for app in http_core http_runtime http_fetch http_web_socket http_event_source http_web_transport; do
  (
    cd "$repo_root/apps/$app"
    MIX_ENV=prod MIX_BUILD_PATH="$work_dir/package-build/$app" \
      MIX_DEPS_PATH="$work_dir/package-deps" \
      mix hex.build --unpack -o "$HTTP_FETCH_PACKAGE_DIR/$app"
  )
done

cp "$repo_root/scripts/ex_ssl_feature_consumer_mix.exs" "$consumer_dir/mix.exs"
cp "$repo_root/mix.lock" "$consumer_dir/mix.lock"
shopt -s nullglob
discovered_groups=()
for group in "$repo_root"/scripts/ex_ssl_*_test.exs; do
  discovered_groups+=("$(basename "$group")")
  cp "$group" "$consumer_dir/test/$(basename "$group")"
done
cp "$repo_root/scripts/ex_ssl_tls12_peer.py" "$consumer_dir/test/ex_ssl_tls12_peer.py"
cp "$repo_root/scripts/ex_ssl_published_provenance.exs" "$consumer_dir/provenance.exs"
printf 'ExUnit.start()\n' >"$consumer_dir/test/test_helper.exs"

(
  cd "$consumer_dir"
  MIX_ENV=test mix deps.get --check-locked
  MIX_ENV=test mix deps.tree --only runtime
  MIX_ENV=test mix compile --warnings-as-errors
  if [[ "$EX_SSL_DEP_MODE" == published ]]; then
    MIX_ENV=test mix run provenance.exs | tee "$provenance_log"
  else
    MIX_ENV=test mix run -e \
      'IO.puts("runtime=source-candidate/" <> to_string(Application.spec(:ex_ssl, :vsn))); IO.puts("loaded_ssl_connection=" <> to_string(:code.which(SSL.Connection)))' \
      | tee "$provenance_log"
    printf 'source_commit=%s\n' "$(git -C "$EX_SSL_SOURCE_DIR" rev-parse HEAD)" >>"$provenance_log"
    if [[ -n "$(git -C "$EX_SSL_SOURCE_DIR" status --porcelain)" ]]; then
      printf 'source_dirty=true\n' >>"$provenance_log"
    else
      printf 'source_dirty=false\n' >>"$provenance_log"
    fi
  fi
)

for group in "${discovered_groups[@]}"; do
  group_log="$group_log_dir/$group.log"
  (
    cd "$consumer_dir"
    env MIX_ENV=test mix test "test/$group" --seed "$EX_SSL_TEST_SEED" | tee "$group_log"
  )
  grep -Eq '[1-9][0-9]* tests?, 0 failures' "$group_log" || {
    echo "feature group did not execute successfully: $group" >&2; exit 1;
  }
  if grep -Eq '[1-9][0-9]* (excluded|skipped)' "$group_log"; then
    echo "feature group has unexpected excluded or skipped tests: $group" >&2; exit 1
  fi
done

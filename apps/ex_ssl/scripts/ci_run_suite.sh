#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  printf 'usage: %s mix-test-arguments...\n' "$0" >&2
  exit 64
fi

report_dir="${CI_REPORT_DIR:-${TMPDIR:-/tmp}/ex_ssl-ci-reports}"
mkdir -p "$report_dir"
report="$report_dir/mix-test.log"
summary="$report_dir/mix-test-summary.txt"
result_file="$report_dir/exunit-result.txt"
timeout_seconds="${CI_SUITE_TIMEOUT_SECONDS:-1200}"
suite_pid=""

cleanup_suite_process_group() {
  if [ -n "$suite_pid" ]; then
    kill -TERM -- "-$suite_pid" 2>/dev/null || true

    for _attempt in 1 2 3; do
      kill -0 "$suite_pid" 2>/dev/null || break
      sleep 1
    done

    kill -KILL -- "-$suite_pid" 2>/dev/null || true
  fi
}

abort_interrupted() {
  cleanup_suite_process_group
  suite_pid=""
  exit 130
}

abort_terminated() {
  cleanup_suite_process_group
  suite_pid=""
  exit 143
}

trap cleanup_suite_process_group EXIT
trap abort_interrupted INT
trap abort_terminated TERM
rm -f "$result_file"

set +e
CI_EXUNIT_RESULT_FILE="$result_file" \
  setsid timeout --foreground --kill-after=30s "$timeout_seconds" \
  bash -c 'mix test "$@"' -- "$@" >"$report" 2>&1 &
suite_pid=$!
wait "$suite_pid"
status=$?
set -e
if [ "${CI:-false}" != true ]; then
  cat "$report"
fi
cleanup_suite_process_group
suite_pid=""

{
  printf 'mix test exit status: %s\n' "$status"
  if [ -f "$result_file" ]; then
    cat "$result_file"
  else
    printf 'ExUnit result file: missing\n'
  fi
  sed -n 's/^[.]*\(TLS 1\.2 interop peer=.*\)$/\1/p' "$report"
} >"$summary"

if [ "$status" -eq 0 ] && ! grep -qxE 'executed=[1-9][0-9]*' "$result_file"; then
  printf 'mandatory suite completed without executing a test or property\n' >&2
  status=1
fi
printf 'mandatory suite exit status: %s\n' "$status" >>"$summary"
cat "$summary"
exit "$status"

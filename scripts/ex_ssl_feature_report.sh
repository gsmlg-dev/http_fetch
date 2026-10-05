#!/usr/bin/env bash
set -euo pipefail

: "${EX_SSL_RESULTS_DIR:?EX_SSL_RESULTS_DIR is required}"
: "${EX_SSL_DEP_MODE:?EX_SSL_DEP_MODE is required}"
: "${EX_SSL_FIXTURE_VERSION:?EX_SSL_FIXTURE_VERSION is required}"
: "${EX_SSL_FIXTURE_COMMIT:?EX_SSL_FIXTURE_COMMIT is required}"
: "${EX_SSL_TEST_LOG:?EX_SSL_TEST_LOG is required}"
: "${EX_SSL_PROVENANCE_LOG:?EX_SSL_PROVENANCE_LOG is required}"

mkdir -p "$EX_SSL_RESULTS_DIR"
report="$EX_SSL_RESULTS_DIR/ex_ssl_feature_gate-${EX_SSL_DEP_MODE}.txt"
{
  printf 'mode=%s\n' "$EX_SSL_DEP_MODE"
  printf 'fixture_version=%s\n' "$EX_SSL_FIXTURE_VERSION"
  printf 'fixture_commit=%s\n' "$EX_SSL_FIXTURE_COMMIT"
  printf 'seed=%s\n' "${EX_SSL_TEST_SEED:-36}"
  printf 'exit_status=%s\n' "${EX_SSL_GATE_STATUS:-unknown}"
  if [[ -f "$EX_SSL_PROVENANCE_LOG" ]]; then
    grep -E '^(runtime|resolved_scm|resolved_destination|resolved_build|resolved_from|hex_inner_checksum|hex_outer_checksum|loaded_ssl_connection|package_source_commit|source_commit|source_dirty)=' \
      "$EX_SSL_PROVENANCE_LOG" | sed -E 's#/(tmp|var/folders)/[^ ]+#<temporary-path>#g'
  else
    printf 'provenance=not-produced\n'
  fi
  if [[ -d "${EX_SSL_GROUP_LOG_DIR:-}" ]]; then
    for group_log in "$EX_SSL_GROUP_LOG_DIR"/*.log; do
      [[ -f "$group_log" ]] || continue
      printf 'group=%s\n' "$(basename "$group_log" .log)"
      grep -E 'Finished in|Result:|[0-9]+ tests?, [0-9]+ failures?|[0-9]+ (excluded|skipped)' "$group_log" || true
    done
  else
    printf 'tests=not-produced\n'
  fi
} >"$report"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  { printf '### %s ex_ssl feature gate\n\n```text\n' "$EX_SSL_DEP_MODE"; cat "$report"; printf '```\n'; } >>"$GITHUB_STEP_SUMMARY"
fi

# Historical worktree ledger

Preserved from commit 62b05c0 during the release merge. Superseded by
../EX_SSL_HTTP_FETCH_PROGRESS.md; its incomplete statuses are historical.

# ex_ssl/http_fetch implementation progress

This ledger records work against the implementation plan. `verified` means the
listed checks were executed at the recorded revision; skipped or unavailable
checks are recorded as gaps, not passes.

| Task | Repository revision | Status | Tests executed | Remaining gaps |
| --- | --- | --- | --- | --- |
| P0.1 consumer requirement inventory | `http_fetch` `690258a` | verified | `MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test apps/http_web_socket/test apps/http_event_source/test apps/http_web_transport/test` — 422 tests + 20 doctests, 0 failures | Full production-call inventory and remote CI remain evidence work. |
| P0.2 cross-record HTTP/2 closure | `http_fetch` `690258a` | verified | `apps/http_fetch/test/http/socket_client_http2_test.exs` seeds 1–5 — 31 tests/run, 0 failures; `apps/http_core/test/http/http2_test.exs` seeds 101, 202, 303, 404, 505 — 25 tests/run, 0 failures | No implementation change required; PR #14 remains unmerged. |
| P0.3 consumer boundary | `http_fetch` `690258a` | verified | TLS transport tests — 32 tests, 0 failures; scoped consumer suite above — 0 failures | E2E, external-consumer smoke, and static-analysis evidence remain for Phase 6. |
| P1 TLS 1.3 algorithm expansion | `ex_ssl` `99c09ec` | not_started | Existing baseline only | P-384 ECDSA, Ed25519, RSA-PSS-PSS, and P-384 ECDHE are not all implemented. |
| P2 initial-handshake mTLS | `ex_ssl` `99c09ec` | not_started | Existing optional CertificateRequest rejection/empty-response tests only | Client identity loading, client Certificate/CertificateVerify, and HTTP mTLS coverage are missing. |
| P3 options/socket compatibility | both | not_started | Existing backend-selection and unsupported-option tests only | Capability registry, safe TCP allowlist, and bounded certificate-policy matrix remain. |
| P4 TLS 1.2 client subset | — | not_started | None | Requires an architecture decision and an independent TLS 1.2 protocol path. |
| P5 TLS 1.3 resumption/diagnostics | — | not_started | None | Ticket processing, cache isolation, and evidence are missing. |
| P6 release evidence/readiness | — | not_started | None | Depends on delivered phases; no merge, publish, or default switch authorized. |

Baseline notes:

- The plan's ex_ssl `0f16c2c` and http_fetch `a1312cc` values were inspection
  baselines, not reset targets.
- The checked-out http_fetch PR head is `690258a`, which includes the later
  completed-early-response upload fix.
- OTP `:ssl` remains the default backend; `:ex_ssl` remains explicit only.

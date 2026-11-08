# QUIC TLS resumption provider implementation plan

> **For agentic workers:** Execute inline under `scoped-prd-execution`. User prohibits extra agents, branches, worktrees and commits for this lane.

**Goal:** Implement record-free authenticated PSK-DHE and separately gated early-data TLS actions without storage or IO in the provider.

**Architecture:** Extend the caller-owned `SSL.QUIC` state with one pending continuation and redacted QUIC session/request structs. Reuse shared client binder/HRR, PKIX, Finished and key schedule; extend server flight generation for a committed PSK. The QUIC runtime owns cache policy, atomic consume, leases, time and early capacity.

**Tech Stack:** Elixir/OTP crypto/public_key, ExUnit, existing aioquic reference harness.

## Execution boundary

Only `apps/ex_ssl/**`, new `scripts/quic_tls_features/**`, this plan and the two assigned `docs/quic/tls-*` documents. Existing files owned by other lanes are read-only. Preserve TCP policy, versions, locks, shared build and deps. Build VM: `ERL_FLAGS='+S 2:2' MIX_ENV=test HTTP_FETCH_CI_APP=ex_ssl MIX_BUILD_PATH=/tmp/http-fetch-quic-tls-B-20261108/test` from umbrella root.

## Steps and observable gates

- [x] Read approved R1/R2 design, parallel ownership, nested ExSSL architecture and current TLS code.
- [x] Publish concrete `new/2`, `continue/3`, session and ordered action contract in `docs/quic/tls-continuation-contract.md` before engine integration.
- [x] Add `SSL.QUIC.Session` (bounded/redacted material) and `SSL.QUIC.Request` (one continuation), with public types. Test malformed replies, feed while waiting, stale/duplicate/mismatched IDs, abort and redaction.
- [x] Extend exact-byte resumption primitives with first-identity binder verification, including multiple legal identities and HRR synthetic-message-hash prefix. Keep existing TCP construction unchanged. Verify independently computed HKDF/HMAC vectors and mutated binders.
- [x] Extend server handshake selection/flight to accept only a committed compatible PSK, consume CH1 before HRR, verify CH2 without a second lookup/commit, and omit certificate/CV only for resumed authentication. Validate fresh key shares and paired secrets.
- [x] Opt-in client session revalidation checks current PKIX/name/trust/signature/ALPN/context/expiry before offering. Test changed identity/trust/context and expired session full-handshake fallback; invalid authentication remains fatal.
- [x] After verified client Finished, derive one new ticket, request store, and emit NST only on acknowledgment. Store miss/failure skips optional ticket. Client decodes NST into private receipt actions. Test no store before Finished, replacement ticket after resumed handshake and malformed tickets.
- [x] Separately add client early-secret action, server commit-gated early-secret/accept/reject actions and EE signaling. HRR, decline and capacity shortage reject early data; readiness waits for Finished. Test early maximum `0xffffffff`, exact cipher/ALPN continuity and invalid Finished. No EndOfEarlyData in QUIC.
- [x] Run focused provider tests, existing QUIC/TCP unit regressions and existing independent record-free aioquic gate using the lane build. Inspect owned diff and explicit formatting only. Record exact counts and any unavailable transport acceptance in `docs/quic/tls-resumption-validation.md`.

## Commands

Preparation uses installed shared dependency sources only: `mix compile --warnings-as-errors` with the environment above (no deps.get). Focused red/green: `mix test apps/ex_ssl/test/ssl/quic_resumption_test.exs apps/ex_ssl/test/ssl/protocol/quic_binder_test.exs`. Regression: `mix test apps/ex_ssl/test`. Integration scope is existing affected TLS/QUIC scenarios, with finite timeouts and task-owned peers. Format explicit changed `.ex`/`.exs` paths using `mix format <paths>` and then `--check-formatted <paths>`.

Capabilities remain false until independent complete runtime acceptance. Pure provider tests and even record-free peer exchanges do not establish QUIC packet-level 0-RTT or resumption support.

## Executed result

Provider implementation is complete within this lane. Final unit gate executed
703 tests and 20 properties with zero failures (2912 integration/E2E cases
excluded); the focused real TCP/QUIC-config integration gate passed 29 tests.
Independent record-free aioquic passed 13 existing certificate scenarios and 12
full+resumed pairs covering both roles/all three suites/early off and on.
Full QUIC packet-level R1/R2 runtime acceptance remains NOT RUN pending Task A;
capability flags stay false. See the owned validation ledger for exact commands,
negative cases and limits. No commit or shared build/dependency mutation occurred.

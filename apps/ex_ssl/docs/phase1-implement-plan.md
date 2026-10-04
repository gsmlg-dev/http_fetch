# Phase 1: QUIC TLS contract hardening

Date: 2026-09-28. Scope: this repository only; preserve the existing
`SSL.QUIC.new/2`, `feed/3`, `info/1`, `abort/2`, `capabilities/0` API and ordered
actions. The authoritative contract remains [QUIC_TLS_INTERFACE.md](QUIC_TLS_INTERFACE.md).
This plan adds no QUIC transport, HTTP/3, application routing, resumption, 0-RTT,
server mTLS, compatibility shim or publishing step.

## Source and worktree

Initial checkout: `main` at `bcb946d40327c68f238df5fd66d945d90f251af4`, which did
not contain `SSL.QUIC`. The sole initial dirty entry was the user-owned,
untracked `01-ex_ssl-plan.md`. Its SHA-256 was
`ce92e3b6caa09fb22a96b8f733a42461f690a304eda10bf05025e8c286296d68`.

`git ls-remote origin refs/heads/main` identified the requested review baseline
`02eb981f59d4e182d4473e264a9f8b093ec6bf3d`. Fetch showed a clean 0-ahead/9-behind
relationship and no conflicting plan-file path; `git merge --ff-only origin/main`
updated the checkout. The plan-file checksum remained unchanged. Work proceeds
against that actual implementation, not reconstructed older code.

## Ordered work and checks

1. **S-01, public contract:** inspect existing QUIC tests; add public-API real
   certificate-handshake checks for exact action order, authentication milestones,
   terminal states and redacted diagnostics. Preserve correct production behavior.
   Verify the existing QUIC suite and additional contract tests.
2. **S-02, configuration and post-handshake:** exercise trust, DNS/IP reference
   identity independent of SNI, credentials, opaque ALPN, profile freshness and
   strict options/limits. Test fragmented/coalesced legal tickets and forbidden
   post-handshake messages. Reproduce any defect before a minimal scoped fix.
   Extend the authoritative interface matrix without duplicating its contract.
3. **S-03, consumer and handoff:** run formatter, strict dev/test compilation,
   scoped unit/contract tests, the pinned independent aioquic harness, and a fresh
   VM/standalone consumer startup check. Run scoped TCP interoperability if shared
   TLS code changes, and existing independent TLS checks as verification. Record
   commands, runtime, results and limitations in
   [phase1-acceptance.md](phase1-acceptance.md).

S-01 and S-02 test investigations can run independently; final verification and
documentation follow their completed edits. No neighboring repository is edited.
No commit, push, merge of a development branch, tag or publication is implied by
the delivery: distinguish the reviewed base SHA from uncommitted working-tree
changes in the acceptance report.

## Acceptance gate

G-S requires stable public calls, both roles and ordered actions, actual
directional-secret agreement, identity/transport-parameter authentication
boundaries, negative CA/identity/ALPN/configuration/resource cases, terminal
behavior, legal ticket tolerance, no authentication downgrade and an identified
consumable source. Use PASS / FAIL / BLOCKED / NOT RUN for evidence; do not count
unexecuted runtime-matrix or network tests as passes.

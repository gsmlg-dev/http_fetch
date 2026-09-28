# Phase 1 implementation plan

Baseline: `3bf5ec6518f17800f95b54bb8c5dbda55386d44a`, inspected 2026-09-28.
Worktree: `.trees/codex/quic-phase1`, branch `codex/quic-phase1`.
The original untracked `04-http_fetch-plan.md` and earlier consumer-validation
worktree are preserved. This work is limited to this repository.

1. **F-01:** Audit dependencies and production paths; pin ex_quic G-T
   `5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb` and its exact ex_ssl G-S
   `f1327e0bb7fb2093b8dc2b07e72b26233a739963`. Both are obtainable Git
   revisions with upstream acceptance records. Remove the old shared TLS Hex
   constraint without an override. Verify root compilation, generated application
   dependencies and existing HTTP/TLS regressions.
2. **F-02:** Add a thin internal adapter preserving the frozen public QUIC
   handles, bounded pull interface, operation references and unknown outcomes.
   The TCP socket behaviour and WebTransport application-session behaviour are
   unsuitable for raw multiplexed streams. No adapter-owned process, retry loop,
   byte queue or protocol session is necessary. Strict scripted-driver tests
   verify exact forwarding, bounds and message association; real UDP tests remain
   separate. Callers serialize operations; arbitrary concurrent callers are not
   a bounded work queue.
3. **F-03:** Normalize client TLS configuration before endpoint construction.
   Explicit trust, reference identity independent of SNI, opaque ALPN, credentials
   and supported algorithm/profile options follow the pinned SSL.QUIC contract.
   Reject unknown/unsafe settings. File loading happens before TLS feed.
4. **F-04:** Exercise the adapter against standalone ex_quic, pinned aioquic and
   the available pinned Abyss public service with a custom raw-stream handler.
   Build a standalone consumer and a fresh release from copied http_core source
   with network-resolved immutable dependencies. Verify ordinary startup and
   runtime/code boundaries. Record commands, failures and final gate decisions.

Production `HTTP.HTTP3`, existing `HTTP.H3` codecs and WebTransport remain on
`:quic_h3`/`:quic`. OTP TLS remains the default. No new HTTP/3 selector, QPACK,
HTTP/3 client session, DoQ, server HTTP protocol or production Abyss dependency
is introduced. No push, merge, tag or publication is authorized.

Acceptance and limitations are recorded in `phase1-acceptance.md`; upstream
contract mappings are in `ex-quic-consumer-contract.md`. PASS always requires
executed evidence. G-F is independent of G-A; any missing joint result affects
its G-P1 item separately.

## Upstream ACK correction follow-up

The initial G-T pin was ex_quic v0.2.0 (`27779b72da0c784787142012fee3e229fe5397df`).
After the real joint test exposed issue #2, the implementation was revalidated
against v0.2.1 at the pin above. Its public contracts and ex_ssl source are
unchanged. The same joint workload now passes; no local engine workaround was
added. Current commands/results are in the acceptance report.

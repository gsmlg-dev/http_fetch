# Complete the ExSSL migration

Execution checklist derived from the accepted 2026-10-21 HTTP Fetch migration plan.
Baseline: `main@6b69bde3f43f2270317c38fbe68d5ac9635d3b36`, nine packages at `0.21.14`.
Status: P0 baseline/interfaces recorded with explicit failing gates; P1/P2 implementation
is active. No production default or dependency removal has been made.

See [design and compatibility table](tls-migration-design.md) and
[execution evidence](tls-migration-validation.md). A checkbox means executed and
reviewed acceptance, not merely a test file or implementation exists.

## P0 — Baseline and contract

- [x] Record HEAD, versions, initial clean worktree and runtime.
- [x] Read root and nested repository instructions.
- [x] Inventory production calls, selectors, private socket assumptions and manifests.
- [x] Record effective TLS/managed defaults and compatibility differences with owners.
- [x] Complete baseline source tests including required integration/independent peers;
      classify exclusions/skips/failures (full root run, all 663 TLS checks, real QUIC;
      known failures remain implementation/host gates, not accepted behavior).
- [x] Build current nine candidate archives and validate identity/internal requirements.
- [x] Run isolated candidate external consumer smoke.
- [x] Run the current candidate TLS feature gate with all required fixtures/peers
      (baseline nine groups, 68 tests; not an integrated migration candidate).
- [x] Complete trace of public entry points, proxy/Unix routes and cancellation/handoff
      (route matrix distinguishes actual TLS peers and newly identified blockers).
- [x] Finalize public lifecycle enrollment, closure, receipt and transfer interface
      (v1 design target; no public API implementation claimed).
- [x] Resolve public policy decisions or keep each explicitly release-blocking.
- [x] Measure OTP and explicit ExSSL HTTP workloads: handshake/request p95/p99,
      upload/download throughput, process/port counts, 60-second reuse memory and
      cleanup observations; unsupported public evidence remains explicit.
      Full load/30-minute soak and stable tail acceptance remain P4/P5 gates.
- [x] Record numeric regression budgets before default promotion
      (v1 targets in design; full load/soak validator remains required).

Exit: every blocker has an owner and acceptance test; current implementation,
executed evidence and required work are distinguishable. OTP remains default.

## P1 — TLS policy and compatibility (after P0)

- [x] Default HTTP ExSSL policy offers TLS1.3 + supported TLS1.2 in one handshake;
      explicit TLS1.3-only still works and has an independent negative peer test
      (22 contextual policy scenarios; broad P1 option/peer compatibility stays open).
- [ ] Validate bounded TLS1.2 ECDHE/AES-GCM, EMS, secure renegotiation and needed
      version-specific signature support. Never enable TLS1.3 PKCS1 CertificateVerify.
- [x] Resolve internal managed buffer and explicit buffer/tos/tclass/priority values
      without silently dropping options or changing protocol safety bounds
      (driver support tested; enabling managed ExSSL remains a P3 gate).
- [x] Implement explicit TCP verify_none with verify_peer default, mandatory signature /
      Finished / AEAD checks, protocol credential constraints and mode-partitioned tickets
      (OTP/OpenSSL references; proxy/managed/package/runtime matrix remains open).
- [ ] Resolve advanced verification callbacks, revocation and client identity compatibility.
- [ ] Preserve trust precedence, system roots, DNS/IP origin identity, SNI separation,
      pinned dialing, CONNECT upgrade and mTLS redirect isolation.
- [ ] Preserve explicit ordered wire profiles; reject real conflicts before I/O.
- [ ] Document/test mixed default vs profile and auto-ticket interaction; tickets stay
      disabled by default and unsupported combinations return explicit errors.

Exit: required option/default table resolved with independent positive/negative
coverage; no supported endpoint class silently lost.

## P2 — Provider lifecycle and duplex correctness (after P0; parallel with P1)

- [x] Implement/test internal fixed-role resource ledger, allocation fences, creator loss
      and late enrollment (pure foundation only; public/runtime proof remains open).
- [x] Implement/test internal authority epochs, recipient/nonce/owner acknowledgment,
      lost-reply replay and controller monitor generations (runtime remains open).

- [x] Implement/test private fixed atomic receipt and observer-aware finite reader
      (storage/wait foundation only; real monitor/enrollment integration remains open).
- [x] Read existing ex_ssl architecture/design/PRD/implementation docs before changes.
- [ ] Public attempt handle exists before allocation, survives failed setup and transfer.
- [ ] Provider enrolls/observes every connection, writer, TCP and setup worker without
      a cancellation gap; completion requires closed enrollment and observed DOWN.
- [ ] Separate handshake outcome, logical closure, cleanup pending and unconfirmed.
- [ ] Durable bounded terminal receipt and finite waits use original absolute deadline.
- [ ] Explicit acknowledged cancellation ownership transfer prevents stale abort.
- [ ] Reproduce occupied-writer control :busy; implement bounded pending output while
      preserving record sequence, key epoch, protected bytes and write deadline.
- [ ] Cover abort/setup/handoff races, wrong trust/identity/options, killed writers,
      KeyUpdate/upload, early response, close_notify/truncation, owner death,
      abandonment, stale acknowledgments, repeated close/await and evidence loss.
- [x] Shared QUIC TLS-core regressions pass (round5 source: QUIC249, H3 companion113,
      and three real opt-ins; independent H3/package gates remain P4).

Exit: HTTP obtains truthful cleanup evidence with no private TLS field inspection;
resources return to baseline after deterministic failures/cancellation.

## P3 — Completion and managed H1/H2 (after P1 + P2)

- [ ] ExSSL connect/upgrade enroll attempts and return public phase/lifecycle evidence.
- [ ] Generic HTTP lifecycle accepts evidence; temporary OTP extraction stays isolated.
- [ ] Enable ExSSL completion only once setup and established cleanup are covered.
- [ ] Enable managed ExSSL policy with frozen effective trust/identity/socket settings.
- [ ] Preserve private generation pools, capacity, origin/route and H2 policy isolation.
- [ ] Preserve structured errors; request_started=false needs positive phase evidence.
- [ ] H1 handoff/abort and H2 stream cancellation preserve healthy shared connections.
- [ ] Scope/generation retirement waits for provider termination and cannot redial.
- [ ] Existing supported proxy routes, unread bodies, abandoned uploads and owner death
      settle truthfully within existing deadlines.

## P4 — Source, consumer, package and CI acceptance (after P3)

- [ ] Agreed matrix covers TLS1.2/1.3, identity/mTLS/resumption, H1/H2 Fetch, SSE,
      WSS/extended CONNECT, managed runtime, current proxies and explicit QUIC/H3.
- [ ] Execute deterministic independent OTP/OpenSSL/Python/Node/H2/aioquic peers;
      missing prerequisites, zero tests and skipped mandatory scenarios fail the gate.
- [ ] Candidate Hex consumers use all current archives with equal exact versions.
- [ ] Mixed-package traffic includes real ExSSL TLS in addition to h2c.
- [ ] Relevant changes automatically select candidate TLS consumers and QUIC/H3 CI.
- [ ] Execute supported runtime matrix (baseline 1.18/OTP28; configured 1.19/OTP28
      and 1.20/OTP29) and retain historical standalone labels separately.
- [ ] Compare workload results against budgets set from P0.

Exit: integrated explicit ExSSL passes all agreed gates. P5 remains blocked until then.

## P5 — Promote default (release boundary B)

- [ ] Update selector, all implicit client/managed paths, examples and smoke assertions.
- [ ] Preserve explicit ExSSL; keep temporary explicit OTP with named removal boundary C.
- [ ] Redirect/reconnect/proxy/pool contexts retain resolved backend and policy.
- [ ] No fallback, verification relaxation, weaker retry or uncertain body replay.
- [ ] Default matrix, fresh consumers and representative downstream workloads pass.

Release boundary A is P0–P4 compatibility completion with OTP still default. Select
actual versions with repository tooling; no guessed reserved versions.

## P6 — Remove production OTP SSL (after P5)

- [ ] Delete OTP transport implementation, backend branches, private socket types/layouts.
- [ ] Remove five unconditional ssl extra_applications and audit transitive/generated apps.
- [ ] Legacy tls_backend=:ssl returns an explicit configuration error.
- [ ] Test peers start OTP SSL only in isolated test/external environments.
- [ ] Build an actual fresh candidate production consumer release with no umbrella
      overrides/test support; ssl absent from app closure, rel/boot and bundled dirs.
- [ ] Execute release with OTP SSL unavailable on code path, checking loaded/started
      apps before and after traffic; do not modify host Erlang installation.
- [ ] Scan BEAM imports plus dynamic dispatch; source inventory alone is insufficient.
- [ ] External peers exercise H1/H2 HTTPS, WSS, SSE, managed cleanup and supported H3,
      including identity failure, deadline, abort and long-lived shutdown.
- [ ] Record source SHA, archive hashes, runtimes/module paths and peer observations.

## P7 — Coordinated release and published verification (after P6)

- [ ] Full umbrella regression, formatting, Credo, Dialyzer and required CI pass.
- [ ] Use existing source/archive identity, immutable tags and release recovery tooling.
- [ ] Publish in dependency order: ex_ssl → elixir_quic → http_core →
      elixir_quic_http3 → http_runtime → Fetch/SSE/WebSocket/WebTransport.
- [ ] All nine versions and exact internal requirements remain coordinated.
- [ ] Cold published consumers repeat default ExSSL H1/H2/WSS/SSE, existing published
      H3 and production-release-without-OTP-SSL checks.
- [ ] Record exact partial publication state if any step fails; no completion claim.
- [ ] Current docs distinguish implemented, executed, released and unsupported behavior.

Final done: all applicable gates above pass, production OTP TLS is absent, and cold
published consumers independently confirm the complete release behavior.

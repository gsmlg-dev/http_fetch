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
- [x] Remove the observed H3 fixture cleanup check/close race against natural
      external peer exit: known-port-only idempotent cleanup, unchanged assertions
      and timeouts (round12 actual on_exit RED; root whole file10/10 GREEN).
- [x] Make pin fixtures portable without vacuous identity checks: distinct certificate
      SAN vs real dial, same-port IPv4/IPv6 pool/refusal/retry controls, independently
      proven saturation, complete mutation and no-fallback/replay accept queues
      (round8:85 focused checks; overall full-source gate remains separately reported).
- [x] Qualify requested KeyUpdate progress across native output-job transitions:
      queued or authenticated epoch change while the logical write remains blocked,
      exact16MiB/no replay and an independent peer accepting new-epoch client traffic
      (round8:48 ordering/lifecycle/abandon/backpressure checks; no engine change).
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
      (OTP/OpenSSL references; explicit sole-TLS proxy routes also covered in round7;
      managed/package/runtime matrix remains open).
- [x] Prepare provider-owned immutable upgrade configuration before CONNECT proxy dial;
      consume the same loaded trust/client credentials/profile/reference/SNI/options,
      with fresh connection keys/randomness and live session-ticket binders
      (133 focused checks including59 lifecycle; adoption/cleanup integration remains open).
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
      (storage/wait foundation only; actual TLS enrollment integration remains open).
- [x] Implement/test private temporary observer, bounded supervisor bootstrap,
      authenticated fixed-role admission, independent DOWN and nonextendable retirement
      (round7 baseline59/current71 lifecycle checks; actual native births/adoption/transfer/public facade remain open).
- [x] Read existing ex_ssl architecture/design/PRD/implementation docs before changes.
- [x] Retain explicit upload-abandonment abort intent after the retained native job
      finishes: matched ordinary FIN vs abandoned RESET, authenticated response reads,
      exact local DOWN/Port absence before bounded independent-peer drain
      (round9 deterministic old-source RED ->2/2 GREEN; no actor/layout changes).
- [x] Measure finite ordinary-reuse upload pressure instead of assuming 1MiB blocks:
      4MiB/90ms sustained wait/original350ms peer pause and1s budget, exact body,
      same worker/source unfinished, proper same-peer80ms negative control;
      18 focused +81 whole-file passes, corrected case also passed full round10.
      Cancellation remote-close remains open; length-mismatch fixture is corrected below.
      Round12 captured one actual ExSSL failure with successful abandonment, live
      zero-linger readback and successful Port.close before exact local retirement;
      peer still timed out2s. Kernel/terminal-delivery cause remains unproven.
- [x] Authenticate private pre-native constructor rejection without allocating a
      resource: exact permit/caller/parent generation, fixed role-use tombstone,
      no fabricated DOWN or loss clearing, closed-fence accounting and helper completion
      (round10 RED31/33 -> GREEN43/43; twelve added cases; not native-error cleanup).
- [x] Privately enroll inert Connection/writer births after init returns, with exact
      original Observer monitors and nonce-fenced writer readiness/release; reject
      unsupported private contexts before process construction and all legacy attach.
      One original control/setup minimum covers even blocked enrollment calls;
      first missing-entry RED ->15 GREEN, shorter-setup RED15/17 -> final17 GREEN.
      This proves private process births, not TCP adoption or public lifecycle.
- [x] Replace fixed-length mismatch fixture timing with actual peer header/prefix
      receipts: controlled old3/3 accept:eINVAL while listener owned/open, corrected
      27 focused +62 whole-file passes; exact errors/abc/abc/empty bytes unchanged.
- [x] Implement the private cooperative TCP ownership protocol core: retain consumed
      creator generations; writer/Connection challenge; allocator prepare and original
      Connection commit after actual native ownership transfer, one-use attempt-bound
      grant. Round13 six REAL passive-TCP cases; round14 ten REAL TCP cases
      plus one unknown-permit process fixture and two pure identity cases pass.
      Added precommit cancel, queued Writer/TCP DOWN, genuine wrong native owner
      with same-grant recovery, and sticky unknown-permit cancellation coverage.
      Round15 adds completed-allocator rejection, valid role-edge reservation
      after rejected Setup-to-Writer allocation, and pure retained-creator view
      coverage: 13 Observer cases +2 pure handoff cases +ledger-view regression.
      First finite readiness deadline bounds PENDING phases only; successful commit
      cancels/ref-fences that timer, never imposes a connection lifetime cap.
      Lost ACK stays acceptance-unknown. No actual TLS actor attach/readiness/public
      lifecycle/adoption claim; task20 hard-edge race coverage remains OPEN.
- [x] Centralize private literal-IPv4 TCP allocation for already enrolled allocators:
      reserve before native entry, keep one caller-clipped absolute deadline, return
      the exact Port only after original Observer enrollment; close known late Ports.
      Native errors keep unresolved permits and unconfirmed retirement.
      That transport constructor alone does not prove allocator birth;
      TLS integration and all-path failure identity remain open.
- [x] Implement/test private unlinked allocator birth: inert init, original
      parent/recipient/Observer monitors and clipped deadline, self-enrollment
      before NativeTCP, nonce-bound allocation notification after Port enrollment.
      Four actual-constructor cases pass; all lifecycle95/95. Setup orchestration,
      handoff and public readiness remain open. Round23 provider regression recorded
      one Observer-bootstrap admission failure before native allocation; cause still unknown.
- [x] Integrate explicit post-birth readiness through actual Writer and Connection:
      authenticate the original recipient, nonce and socket reference; consume one
      setup-clipped pending budget and acknowledge the Observer challenge. Birth-only
      lifetime behavior stays unchanged. Five actual-actor cases, lifecycle+birth117/117
      and Round24 restored three-provider+Fetch-H2 scope1527/1527 pass.
      TLS attachment and public readiness remain open.
- [x] Transfer actual allocator-owned passive TCP to the prepared Connection:
      bounded prepare, reference-fenced earlier deadline, asynchronous original
      endpoint offer and canonical TCP/Allocator commit before adoption.
      Helper completion follows actual commit ACK; termination closes only a
      still-self-owned Port. Six actual-constructor cases plus one canonical
      parameter case pass; lifecycle+birth124/124 and configured static gates pass.
      Actual-actor ACK-loss is source-reviewed, not directly forced by these cases.
      TLS attachment, setup outcome and public readiness remain open.
- [x] Compose private actual Setup/Connection/Writer/Allocator births and native
      handoff under one absolute pending budget. Bound unlinked inert construction
      avoids an unbounded supervisor wait; ROOT remains application owner.
      Definitive handoff ACK plus normal Allocator DOWN precede one native candidate;
      Setup stays pending with original timer armed. Six actual-Setup cases and
      lifecycle+birth130/130/static gates pass; no TLS outcome/public acceptance.
- [x] Opt in to private passive TLS through the actual Setup/Connection/Writer.
      Authenticate admission before unchanged NativeE, then preserve original classic
      handshakeD including infinity; real Finished Writer ACK precedes TLS completion.
      ACK connected publication plus helper completion under one finite settlement P
      before private ROOT readiness/normal Setup retirement. Round27 eight independent
      OTP/OpenSSL cases, lifecycle+birth138/138, provider1548/1548 and static gates pass.
      Public I/O/owner acceptance remain closed; precise failure publication is open.
- [x] Record recognized private pre-success TLS/peer alerts once under fixed P and
      shorter RPC cutoff R; authenticate committed typed ownership and close admission
      before unchanged alert/close. Preserve original expiry, Root lease and category.
      Round28 three actual OTP scenarios/five cooperative cases, provider1556/1556
      and static gates pass. Earlier focused timing failures remain recorded; public
      failure ACKs, all-error identity and physical FD cleanup remain open.
- [x] Attribute recognized private native refusal/reachability once, clipped to the
      original NativeE and a 250ms RPC. Require original live allocator/pending TCP
      generation; retain unknown allocation and original Root cancellation lease.
      Round29 two actual refusal/seven cooperative cases, focused155/155 and static
      gates pass; fresh-build provider1565/1565. Two earlier warm-build startup
      failures remain recorded and unexplained. This is live attribution only;
      unknown native identity still prevents durable cleanup receipt sealing.
- [x] Verify the public OTP29 retained-socket identity route with four throwaway
      plain-loopback experiments: refusal, close, owner death, controller transfer.
      Original socket monitor survives transfer; separate inet peer observes data
      and EOF. Primitive feasibility only; no TLS/lifecycle/physical-FD acceptance.
- [ ] Add private pre-connect opaque-socket enrollment with exact original monitor,
      unchanged unresolved permits and loss semantics; then adapt the full native
      transport lifetime and authenticated known-socket connect-failure settlement.
- [ ] Before public lifecycle acceptance, complete native constructor identity proof
      and acknowledged failure publication for real allocator/setup orchestration
      under original deadlines. Private success and TLS/connect attribution above
      do not complete this all-error identity/publication gate.
      Native connect error/helper DOWN is not native cleanup proof; unresolved identity
      coverage remains unconfirmed. Public upgrade/transfer stay gated separately.
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

# Complete the ExSSL migration

Execution checklist derived from the accepted 2026-10-21 HTTP Fetch migration plan.
Baseline: `main@6b69bde3f43f2270317c38fbe68d5ac9635d3b36`, nine packages at `0.21.14`.
Status (2026-10-28): P0–P4 acceptance is complete at `3c561646b7f1bc9042c5cadbc37ed7c6b48fae15`,
including resumption, nested HTTPS proxies, public lifecycle, completion and
managed H1/H2. P5 default promotion is accepted at
`0f4b3dd0f37caadc71b6db7bdc9fff74e9170825` after source, candidate and configured
runtime gates pass. Explicit OTP remains transitional until P6. P6/P7 remain open;
the default promotion has not been published.

See [design and compatibility table](tls-migration-design.md) and
[execution evidence](tls-migration-validation.md). A checkbox means executed and
reviewed acceptance, not merely a test file or implementation exists.

## Current accepted evidence and remaining gates

At `3c561646b7f1bc9042c5cadbc37ed7c6b48fae15`, manual all-nine
[unit](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620226704),
[integration](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620230336)
and [E2E](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620233581)
workflows pass on Elixir 1.18 / OTP 28. Unit and integration selections partition
the 6,762 discovered source cases into 2,063 and 4,699 executed cases, respectively;
excluded cases are not counted as executed. E2E passes 52 ExUnit cases plus the
independent Caddy, QUIC and HTTP/3 checks. Apps without their own suite are
identified in the [execution ledger](tls-migration-validation.md#p4-integrated-acceptance--2026-10-28).

The same source's [manual CI](https://github.com/gsmlg-dev/http_fetch/actions/runs/40621971812)
and [compatibility CI](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620237216)
pass 62 candidate groups with 2,944 checks on each of Elixir 1.18 / OTP 28,
1.19 / OTP 28 and 1.20 / OTP 29. The 53 migration files execute 2,876 checks,
including manual TLS1.3 tickets, TLS1.2 EMS reuse and nested HTTPS proxy cleanup.
All nine `0.21.18` packages resolve through isolated Hex.SCM builds. Each report
has the exact current fixture manifest, with no zero-test file, skip or exclusion.
Earlier selections, including `a38261c` and `f405e7b`, remain historical evidence.

All 19 shared H2 gates pass, including isolated h2c and verified ExSSL package
traffic. Their 19 log hashes and nine archive hashes match the retained report.
Three real-QUIC opt-ins are skipped in the H2-only source runner and execute in
the separate all-nine integration workflow; the H2 source run is not described
as skip-free. Manual CI explicitly records Credo/Dialyzer as deferred. The current
[automatic CI](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620203449)
passes every functional job; its overall failure is the deferred Credo result.
The separate [public H3 gate](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620203412)
also passes. These results close P4's non-deferred gates; they do not establish P5
default behavior or production OTP removal.

P5's later [acceptance boundary](tls-migration-validation.md#p5-default-promotion-acceptance--2026-10-28)
adds the complete default matrix, current all-nine integration and three candidate
runtime selections, each passing 71 groups and 3,061 checks. Source/archive identity
is verified; P6 production removal and P7 publication remain required.

User decisions override the historical checklist where noted: performance work,
including comparative latency/throughput and load/soak budgets, is TODO outside
this goal. Credo and Dialyzer issues are deferred and must be reported separately
from functional gate results. No performance or deferred-quality pass is claimed.
Cancellation deadlines, resource cleanup, security and functional release gates
remain required. Historical evidence and failed invocations remain in the ledger.

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
      Full load/30-minute soak and stable tail acceptance are now deferred TODOs
      outside this goal, following the user's performance-scope decision.
- [x] Record numeric regression budgets before default promotion
      (historical v1 targets in design; performance acceptance is deferred).

- [x] Separate unit, integration and end-to-end suites. Default mix test runs only
      single-VM unit tests with external collaborators mocked; real external I/O
      belongs to integration tests, and complete user flows to end-to-end tests.
      Align test.yml with the unit-only default and keep explicit integration/E2E
      gates mandatory. Current all-nine unit/integration/E2E CI passes at `3c561646`:
      2,063 units, 4,699 integration cases and 52 ExUnit E2E cases, plus independent
      Caddy/QUIC/H3 steps. WebTransport has no integration-tagged source cases;
      Core and Runtime have no standalone ExUnit E2E suite. Their actual selections
      are explicit rather than counted as executed scenarios. R34–R38 history and
      earlier failures remain in the execution ledger; source-tier acceptance does
      not establish the complete P4 compatibility or production-release matrix.

Exit: every blocker has an owner and acceptance test; current implementation,
executed evidence and required work are distinguishable. OTP remains default.

## P1 — TLS policy and compatibility (after P0)

- [x] Default HTTP ExSSL policy offers TLS1.3 + supported TLS1.2 in one handshake;
      explicit TLS1.3-only still works and has an independent negative peer test
      (22 contextual policy scenarios; broad P1 option/peer compatibility stays open).
- [x] Validate the source subset for TLS1.2 ECDHE/AES-GCM, EMS, secure renegotiation
      and version-specific RSA-PKCS1 SHA256/384/512 server/client signatures.
      R42 passes922 ExSSL checks including six forced OpenSSL cases and14 shared
      QUIC checks. TLS1.3/QUIC PKCS1 handshake exclusion remains enforced;
      integrated candidate/HTTP/platform acceptance is still required by P4.
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
- [x] Preserve ordinary TCP verify_fun, including setup/cancellation and callback-state
      privacy; retain existing managed callback exclusions. The ordinary callback
      slice passes22 policy/security, seven live and369 regression checks; both
      prepared attachments verify full ordered events/state reset. Current-source
      focused85/P2-391 and scoped quality pass. Four TLS13 integration cases prove
      cancellation/expiry of an actually blocked callback on dial/prepared routes,
      exact original-resource DOWN, durable receipts and callback-state privacy.
- [x] Fully implement CRL/OCSP and partial_chain before OTP removal, with OTP reference
      and independent positive/negative acceptance (current source plus all three
      candidate runtimes; finite policy limits remain documented in the design).
- [x] Fully implement encrypted private keys and multiple client identities before
      OTP removal, preserving ordinary mTLS and HTTP behavior. The user accepted the
      longer migration on 2026-10-23; next-major removal is not an alternative.
      Current source/candidate identity, Fetch and stream-client scenarios pass;
      managed exclusions and admission limits remain the documented contract.
- [x] Preserve trust precedence, system roots, DNS/IP origin identity, SNI separation,
      pinned dialing, CONNECT upgrade and mTLS redirect isolation.
- [x] Preserve explicit ordered wire profiles; reject real conflicts before I/O.
- [x] Document/test mixed default vs profile and auto-ticket interaction; tickets stay
      disabled by default and unsupported combinations return explicit errors.
- [x] Implement TLS1.3 manual ticket delivery and `use_ticket` with bounded opaque
      maps, independent OTP/OpenSSL full/resumed mTLS checks, origin/trust/identity/
      profile isolation and unchanged automatic-ticket policy. Current source and
      all three candidate runtime selections pass.
- [x] Resolve TLS1.2 `reuse_sessions` before default promotion. OTP accepts this
      control. ExSSL now implements opt-in EMS abbreviated handshakes and bounded
      saved IDs and VM-local opaque capabilities (true/false/save), with 55 focused
      native checks passing, including renegotiated ALPN on resumed connections.
      Raw reuse remains disabled by default. OTP29 public tuple references pass;
      native automatic/ID cache misses remain diagnostic. Integrated source and
      all three candidate runtime selections pass; TLS1.3 tickets remain separate.

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
- [x] Add dial-only TCP opaque socket monitor identities to the pure ledger.
      Three actual monitor cases cover exact DOWN correlation, scope rejection and
      late known stop with sticky loss. Round30 provider1568/1568(initial fixture),
      refined fixture3/3 and configured static gates pass. Runtime enrollment below
      remains pending; pure accounting is not a constructor/FD/socket support claim.
- [x] Establish independent OTP29 closed-owner reference evidence: explicit close
      while owner remains alive and actual owner death both erase public owner facts;
      original and late monitor DOWN cannot reconstruct origin. Two new cases plus
      accepted ledger three pass5/5; no runtime/API change. Preserve closed-first
      unknown permits; pre-authenticated known identities need separate late handling.
- [x] Accept private pre-connect opaque-socket enrollment through source gates.
      R32 implements dedicated enroll_socket: original allocator/current owner,
      actual monitor, canonical integer outer deadline and fresh post-monitor use
      checks; unsupported Port handoff/connected publication explicitly reject.
      Closed-FIRST stays unknown even after collector DOWN; known late identities
      retain stop accounting/loss. Five new cases + accepted five pass10/10;
      R32 source gates exposed an original startup/bind regression (1574/1575 twice).
      R33 observes runtime code loading inside admission and loads known control code
      before successful supervisor startup. Normal lifecycle148/four-scope1575,
      WAE/format/configuredCredo/Dial and independent source review pass. Task40/41
      are accepted for this private scope; native Socket transport lifetime is below.
- [x] Add the private raw Socket Allocator constructor and authenticated recognized
      connect-failure settlement (R37). Exact pre-connect enrollment, captured NativeE,
      original typed monitor/creator generation and canonical receiver are enforced.
      Four real Allocator cases plus13 authentication/unit cases pass17/17; unknown
      open/enrollment errors remain unknown. Handoff/TLS/publication are still gated.
- [x] Accept explicit private Socket Setup and authenticated inert ownership handoff (R38).
      Same roles, original typed monitors, nonces and absolute deadlines; public SDK
      owner transfer and Allocator DOWN precede native-owned. Canonical raw handoff
      frames reject injected/malformed budgets. Four real Setup cases require peer
      closure and original roles31/observed_down31; inert terminal controller exit
      avoids competing explicit close/forced-retirement calls. No raw TLS readiness.
      Focused lifecycle169/169, prepared serial integration1605/1605 and default
      units1679/1679 pass. Earlier concurrent timing failure remains unexplained;
      acceptance is limited to this private inert handoff, not TLS/public lifecycle.
- [x] Adapt the native Socket transport lifetime, Setup orchestration and TLS I/O;
      public lifecycle/duplex coverage and the current complete ExSSL source gate pass.
- [x] Validate native constructor identity and acknowledged failure publication for
      real allocator/setup orchestration under original deadlines, including public
      failed setup and cancellation. Unknown native identity remains unconfirmed.
      Native connect error/helper DOWN is not native cleanup proof; unresolved identity
      coverage remains unconfirmed. Public upgrade/transfer stay gated separately.
- [x] Public attempt handle exists before allocation, survives failed setup and transfer.
- [x] Provider enrolls/observes every connection, writer, TCP and setup worker without
      a cancellation gap; completion requires closed enrollment and observed DOWN.
- [x] Separate handshake outcome, logical closure, cleanup pending and unconfirmed.
- [x] Durable bounded terminal receipt and finite waits use original absolute deadline.
- [x] Explicit acknowledged cancellation ownership transfer prevents stale abort.
- [x] Reproduce occupied-writer control :busy; implement one bounded protected-control
      slot preserving sequence, epoch, ciphertext and original deadline, including
      abandonment and reciprocal close. R43 focused/nearby and reviewed HTTP consumer
      checks pass; public lifecycle and integrated stage gates remain below.
- [x] Validate public killed-blocked-writer cleanup, connect after pre-cancel and
      deterministic trust/identity/options/setup/established-cancel resource recovery.
      Seven integration checks and the391-case provider/duplex/QUIC selection pass;
      default units exclude these seven cases and scoped quality gates pass.
      The complete current ExSSL default gate passes580 checks, with577 integration/
      E2E cases excluded and zero skipped; source-matched391 evidence remains valid.
      The complete current ExSSL integration gate now also passes1157 checks with
      zero failures, skips or exclusions. P1 compatibility remains open.
- [x] Cover abort/setup/handoff races, wrong trust/identity/options, killed writers,
      KeyUpdate/upload, early response, close_notify/truncation, owner death,
      abandonment, stale acknowledgments, repeated close/await and evidence loss.
      Current all-nine source and three-runtime candidate gates include the public
      lifecycle/cleanup suites, 35 native Socket TLS cases and native policy
      open/read/close cancellation, deadline, actor-loss and ACK-loss boundaries.
- [x] Shared QUIC TLS-core regressions pass (round5 source: QUIC249, H3 companion113,
      and three real opt-ins; independent H3/package gates remain P4).

Exit: HTTP obtains truthful cleanup evidence with no private TLS field inspection;
resources return to baseline after deterministic failures/cancellation.
Current source and selected candidate/runtime acceptance meet this provider exit.
Remaining HTTP route/option compatibility, final CI and production release gates
are tracked below; no performance or whole-migration completion is implied.

## P3 — Completion and managed H1/H2 (after P1 + P2)

The current local candidate selection passes direct/pinned and CONNECT H1/H2
completion, managed scopes, identity cleanup, and stream-client completion on
the tested TLS1.2/TLS1.3 routes. Request completion releases request ownership
while healthy pools retain TLS authority; queued handoffs retain the original
deadline. Full-stage acceptance still depends on the current integrated gates.
H3 completion retains its existing `unsupported_completion` boundary.

- [x] ExSSL connect/upgrade enroll attempts and return public phase/lifecycle evidence.
- [x] Generic HTTP lifecycle accepts evidence; temporary OTP extraction stays isolated.
- [x] Enable ExSSL completion only once setup and established cleanup are covered.
- [x] Enable managed ExSSL policy with frozen effective trust/identity/socket settings.
- [x] Preserve private generation pools, capacity, origin/route and H2 policy isolation.
- [x] Preserve structured errors; request_started=false needs positive phase evidence.
- [x] H1 handoff/abort and H2 stream cancellation preserve healthy shared connections.
- [x] Scope/generation retirement waits for provider termination and cannot redial.
- [x] Existing supported proxy routes, unread bodies, abandoned uploads and owner death
      settle truthfully within existing deadlines.
      Direct/pinned H1/H2, HTTP CONNECT and HTTPS-proxy forwarding to HTTP origins
      pass current source/candidate gates, including abandonment and owner death.
      HTTPS origins through HTTPS proxies now pass 23 local source cases, including
      H1/H2 pooled ownership, all four TLS1.2/TLS1.3 combinations, byte-preserving
      upload, credentials, independent verification and cancellation at each phase.
      Both provider obligations precede TCP allocation and require independent
      cleanup receipts. Current source, all three candidate runtimes and final
      functional CI pass at `3c561646`.

## P4 — Source, consumer, package and CI acceptance (after P3)

- [x] Agreed matrix covers TLS1.2/1.3, identity/mTLS/resumption, H1/H2 Fetch, SSE,
      WSS/extended CONNECT, managed runtime, current proxies and explicit QUIC/H3.
- [x] Execute deterministic independent OTP/OpenSSL/Python/Node/H2/aioquic peers;
      missing prerequisites, zero tests and skipped mandatory scenarios fail the gate.
- [x] Candidate Hex consumers use all current archives with equal exact versions
      (`3c561646`, CI40621971812 and compatibility40620237216; all53 migration files).
- [x] Extend mixed-package traffic harness to require verified ExSSL TLS plus h2c
      (R41 bounded automation checks pass).
- [x] Execute both traffic modes against the integrated current candidate archives
      (`3c561646`: h2c plus verified ExSSL H2, all19 gates and retained hash audit).
- [x] Implement automatic candidate TLS and affected QUIC/H3 selection for relevant
      changes; R40 local automation suite passes 20 checks. Remote execution remains
      a separate gate below.
- [x] Execute relevant automatic CI and manual all-nine regression on integrated source.
      Manual CI/unit/integration/E2E pass at `3c561646`; Credo/Dialyzer are explicitly
      deferred. Automatic CI passes all functional jobs and fails only deferred Credo.
- [x] Execute supported runtime matrix (baseline 1.18/OTP28; configured 1.19/OTP28
      and 1.20/OTP29) and retain historical standalone labels separately
      (`3c561646`: all62 candidate groups pass2944 checks on each runtime;
      baseline additionally passes all-nine unit/integration/E2E workflows).
- [ ] TODO outside this goal: compare workload results against historical P0 budgets.

Exit accepted at `3c561646`: integrated explicit ExSSL passes all non-deferred agreed
gates. P5 may proceed; deferred performance and quality checks are not passes.

## P5 — Promote default (release boundary B)

- [x] Update selector, all implicit client/managed paths, examples and smoke assertions.
- [x] Preserve explicit ExSSL; keep temporary explicit OTP with named removal boundary C.
- [x] Redirect/reconnect/proxy/pool contexts retain resolved backend and policy.
- [x] No fallback, verification relaxation, weaker retry or uncertain body replay.
- [x] Default matrix, fresh consumers and representative downstream workloads pass.
      Accepted at `0f4b3dd`: source unit, full integration and E2E gates pass;
      the three configured candidate runtimes each pass 71 groups/3,061 checks.
      All 19 shared H2 gates and nine archives pass identity review. The final
      QUIC test synchronization preserves exact cleanup counts and original waits.
      Earlier local timing failures remain recorded; no performance pass is claimed.

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

- [ ] Full umbrella regression, formatting and required functional CI pass.
      Report user-deferred Credo/Dialyzer separately; retain their actual failures.
- [ ] Commit the completed migration and push the reviewed source to GitHub before
      releasing the next coordinated major version through existing version tooling;
      all source, candidate, CI and release gates must pass first.
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

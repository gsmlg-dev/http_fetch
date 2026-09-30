# HTTP/2 production validation

## Current closure follow-up — 2026-09-30

**Final-candidate mandatory local acceptance: PASS.** All 42 freshly executed
gates completed on the frozen follow-up tree, including the genuine 30-minute
mixed soak. The source/archive and command ledger audit passed at
`2026-09-30T18:31:30+08:00`. No F1/F2 runtime blocker remains within the tested
contract. Remote CI reruns and artifact uploads are **NOT RUN**, not authorized.
The preceding closure changes were
already present when this task started. They were preserved and their archived
42-gate ledger, checksum manifest and source provenance were independently
checked. That earlier acceptance is not acceptance of this changed candidate.

- Baseline HEAD remains `ec53f21584b435d37768890b13c71a18a4584554`.
- Frozen source tree: `3523e1e1049046e6c9f3592f6986c98465a60062`,
  frozen at `2026-09-30T17:59:25+08:00`. The checkout is intentionally dirty;
  no commit or branch was created. A separate temporary index preserves the
  user's index, prompt deletion and unrelated untracked review documents.
- F1 coverage now proves an actual 16-KiB owner-held upload chunk is blocked
  after a SETTINGS window shrink, before final response headers arrive. Raw
  socket PING barriers, a producer-read barrier and owner receive tracing
  establish ordering without sleeps. Late body chunk/EOF/error/ACK events and
  new upload credit cannot resume abandoned DATA; a live same-socket sibling
  and valid response trailers complete, with and without a peer NO_ERROR reset.
  Coordinator DOWN proves cleanup. A separate wire oracle rejects duplicate
  upload EOF/reset after an already-completed binary upload.
- F2's previous promotion guard also stranded an existing waiter when only
  one of two owners drained/died and the surviving owner was saturated. Both
  new deterministic cases failed before the repair (`13 tests, 2 failures`).
  Promotion now permits a replacement within the existing connection budgets
  while still waiting for initial zero-capacity owners rather than creating
  duplicate cold connectors. Original deadlines, monitors and never-sent-only
  promotion remain intact. Pending reservations are FIFO within each key;
  global redispatch revisits every key, without promising cross-origin FIFO.
- Expanded regressions pass: `67 tests, 0 failures`, seed `342781`, four BEAM
  schedulers, max_cases 8. Preflight strict compilation, format, the full suite
  and Credo pass. These preflight runs do not replace frozen-candidate gates.
- The first follow-up tree `cc5ba68d54c643c4b696193969c41f549a775b78`
  passed the full suite but failed one concurrent cold repeat: the failed-open
  fixture inspected the warm owner's stream map immediately after response
  delivery, before the coordinator's serialized release. The fixture now waits
  for the actual owner `:released` telemetry event without removing or weakening
  its cleanup assertions. Its scoped rerun passes (35 tests). That attempt's
  incomplete soak was deliberately stopped after 209,449 ms; its exit is 1
  because the workload completion oracle rejects interrupted work. It is FAIL,
  not a 30-minute soak pass, and remains separately archived.
- The next attempt `05167114f0c1cd5166b088e99b475dc4023303e3`
  passed full tests, all three cold repeats, strict compilation, formatting,
  Credo, Dialyzer and the published feature consumer. Its OTP-TLS package gate
  failed the resumed early-response fixture before the second request reached
  the peer (`{:error, :owner_closed}`). The ticket-warming fetch was allowed to
  reuse its closing pooled owner. A deterministic peer-close barrier and an
  assertion that the warming origin is absent from the pool reproduced both
  resumed-case failures. Only this warming fixture now uses
  `http2_reuse: false`, matching the existing ticket-resumption fixture policy;
  the peer still asserts actual TLS session resumption. Production pooling and
  the subsequent fetch remain unchanged. The corrected follow-up suite passes
  67 tests. The obsolete soak was stopped after 452,884 ms and rejected with
  exit 1, not counted as final acceptance.
- The unchanged 42 mandatory commands were rerun against this tree with
  a fresh build path, including both peers, all transports/backends, the full
  transfer/concurrency/reuse workloads, package consumers and the full soak.
  Exact command/status logs are in `/tmp/http-fetch-closure-extended.XUFS84`;
  the accessible archive is `docs/http2-closure-evidence/3523e1e10490.tar.gz`,
  with an adjacent `.sha256` checksum file and an internal `MANIFEST.sha256`.

No commit, push, merge, release, package publication, deployment, remote workflow
dispatch or artifact upload is authorized or performed by this follow-up.

### Current provenance and implementation mapping

The isolated source directory is
`/tmp/http-fetch-closure-candidate-3523e1e1049046e6c9f3592f6986c98465a60062`;
the fresh test build is `/tmp/http-fetch-closure-final-3523e1e10490-build`.
`mix.lock` SHA-256 remains
`12e29c2b5b801498a06aa6771f455f75e70f78f3b2e3d7d2f69f5e846b5d80d5`.
Runtime: Elixir/Mix 1.18.5, OTP package 28.5.0.5 / ERTS 16.4.0.5,
Linux 6.18.48, eight CPUs. Independent peers: Node 24.19.0 / nghttp2 1.69.0,
hyper-h2 4.2.0 / hpack 4.1.0 / hyperframe 6.1.0. Peer versions are asserted
by the gate, not inferred from a successful connection.

| Finding | Runtime contract and current executed proof | Review group |
| --- | --- | --- |
| F1 | `connection_owner.ex` serializes final-header upload abandonment, clears pending DATA/scheduler work, ignores late producer events and closes an unfinished request half only after valid response completion. A CANCEL reset does not manufacture a false Content-Length EOF. Optional peer NO_ERROR closure preserves the complete response. `body_bridge.ex` makes shutdown terminal. `http2_early_response_closure_test.exs` exercises complete 200/413 binary/stream uploads at zero window and peer limit one; an actual blocked 16-KiB owner-held chunk, restored credit, late events, sibling traffic and response trailers; optional reset; and already-completed upload exact-once closure. `http2_scheduler_test.exs` retains sibling work on repeated removal. | `f1.patch` |
| F2 | `pool.ex` atomically promotes queued never-sent waiters to exclusive connector claims, redispatching across keys when capacity changes; `socket_client.ex` consumes the promotion on the production request path. `promote_connector/3` also permits replacement beside a saturated surviving owner, within per-key/global limits. `http2_pool_progress_test.exs` covers DOWN/draining, cross-origin idle expiry, capacity changes, cancellation/deadline, connector death/failure, stale registration and saturated siblings. `http2_queue_socket_progress_test.exs` observes public-fetch GOAWAY/closed-owner replacement without another request. No sent POST or consumed producer is automatically replayed. | `f2.patch` |
| Acceptance fixtures | `http2_failed_open_cleanup_test.exs` waits for actual serialized release before checking owner maps. `socket_client_http2_test.exs` waits for ticket-warming peer closure and prevents that fixture-only warm request from retaining a closing pooled origin; TLS resumption remains independently asserted. Existing production deadline and telemetry assertions remain intact. | `fixture-barriers.patch` |

Per-key queued reservation order is FIFO; cross-origin redispatch does not claim
global FIFO. Historical pre-fix failures are separately labeled in
`historical-baseline-red/`. The additional saturated-sibling failures are in
`f2-partial-owner-red.log`; corrected current runtime suites are freshly run in
`final-runtime-regressions.log` and the full/package gates.

### Current acceptance ledger

Every row below refers to the current tree, not the historical archive.
`results.tsv` has exactly 42 unique required gate records, all exit zero. Each
`final-*.log` records tree, exact command, start time, duration and actual output.
The interop completion oracle additionally requires an explicit workload PASS,
including the full requested soak duration; an interrupted process exit cannot
qualify. Rejected attempts remain archived and are not counted.

| Gate family | Current outcome and scope | Status |
| --- | --- | --- |
| Locked dependencies, strict compile, format, Credo, Dialyzer | Five gates: `mix deps.get --check-locked`, `mix compile --warnings-as-errors`, `mix format --check-formatted`, `mix credo --all`, `mix dialyzer`. Four intentional Dialyzer ignores, zero unnecessary ignores. | PASS |
| Full umbrella suite | 687 tests, 20 doctests, zero failures; three existing gated QUIC skips. Seed 342781, max_cases 8. | PASS |
| Concurrent cold/load repeats | Three separate fetch VMs, four BEAM schedulers each: 309 tests / 20 doctests / zero failures per run, seed 342781, max_cases 8. | PASS |
| Runtime regressions and TLS lifecycle | Selected core/fetch regressions: 42 tests, zero failures, seed 342781 / max_cases 8 / four schedulers. Separate socket-client TLS lifecycle: 43 tests, zero failures, seed 36. | PASS |
| Clean package consumers | Both OTP-TLS and ex_ssl gates execute from unpacked packages: 82 tests each, zero failures, seed 342781 / max_cases 8. Six-package external consumer passes. Published ex_ssl 0.7.2 feature consumer passes 68 tests across nine groups, seed 36, with checksum/loaded-module provenance. | PASS |
| Independent smoke / transfer / concurrency | 18 gates: both peers × h2c / TLS-ssl / TLS-ex_ssl × three modes. Every transfer verifies a 10-MiB binary POST, three 10-MiB streamed POSTs with 1/16/64-KiB source chunks and a 10-MiB download. Every concurrency gate confirms 100 overlapping requests and 99 fast completions while a 6-MiB consumer stays paused, on one connection. | PASS |
| Sequential reuse | Six h2c gates: both peers × MAX_CONCURRENT_STREAMS 1/2/100; 10,000 requests each. All explicitly complete with one connection and zero remaining reservations. | PASS |
| HPACK / profiles / protocol faults | Independent HPACK gate passes. Full core/fetch suites retain cold/warm wire-profile, SETTINGS/flow-control, reset/GOAWAY, deadline, caller-death, blocked-writer, framing/HPACK fault and HTTP/1 / HTTP/3 compatibility coverage. | PASS |
| Full mixed soak | Node TLS with ex_ssl: 3,811 batches / 60,976 requests, seed 0; explicit PASS after 1,800,128 ms. One connection / one pool key / zero remaining reservations. Wrapper duration is separately recorded as 1,801,962 ms. | PASS |
| Environment / source audit | Runtime/peer version gate passes. Derived audit checks all 42 records, 308 source archive blobs and 306 matching workspace blobs; HEAD remains the baseline. | PASS |

Soak resource assertions execute after every batch. Across 39 logged quiescent
samples, maxima are 74,111,960 bytes BEAM memory, 153 processes, one pool key,
426,976 bytes owner heap and 375,559 bytes owner-referenced binaries. All logged
active/protocol stream counts and owner mailboxes are zero. The unchanged
budgets are 8 MiB owner heap, 2 MiB referenced binaries, at most 16 mailbox
messages, four owners and one pool key; global soak tolerance is first-batch
BEAM memory +128 MiB and process count +64. Quiescent upload/receive buffers
and reservations must settle to zero. Logged maxima are sampled observations,
not reconstructed per-request peaks. `acceptance-audit.json` is explicitly a
derived summary of raw logs.

### Current commands and artifact verification

The complete 42-command ledger, runner, source snapshot and report snapshot are
inside `docs/http2-closure-evidence/3523e1e10490.tar.gz`. Extract it and run
`sha256sum -c MANIFEST.sha256`; verify the outer archive using the adjacent
`3523e1e10490.tar.gz.sha256` from its directory. `README.md` explains original
temporary paths and reproduction. Representative exact invocations are:

```sh
MIX_ENV=test mix deps.get --check-locked
MIX_ENV=test mix compile --warnings-as-errors
MIX_ENV=test mix test --seed 342781 --max-cases 8
MIX_ENV=test ERL_FLAGS='+S 4:4' mix test apps/http_fetch/test --seed 342781 --max-cases 8
MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs --seed 36
mix format --check-formatted
MIX_ENV=test mix credo --all
MIX_ENV=test mix dialyzer
/tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py --peer hyper-h2 --tls --backend ex_ssl --mode transfer
/tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py --peer node --mode reuse --count 10000 --limit 100
/tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py --peer node --tls --backend ex_ssl --mode soak --seconds 1800
```

`f1.patch`, `f2.patch` and `fixture-barriers.patch` are independently reviewable
groups against the baseline, including changes already present at task start.
The source freeze precedes this final report and the archive: those later files
are reporting-only. The final parity audit excludes only this report and the
user's pre-existing deleted `CODEX_HTTP2_PROMPT.md`; executable, test, fixture
and configuration bytes match the tested tree. Scope remains the tested HTTP/2
contract, not an unrestricted protocol-conformance or remote-CI claim.

## Earlier closure candidate — 2026-09-30 (historical)

**Mandatory local production acceptance: PASS.** All 42 recorded final gates
completed successfully on the immutable tree below, including the full soak.
No reviewed runtime blocker remains within the tested HTTP/2 contract.
Remote CI reruns and artifact uploads are **NOT RUN**: neither was authorized.
No commit, merge, push, release, publication, deployment, or remote workflow
dispatch was performed in this closure task.

### Immutable provenance

- Baseline HEAD: `ec53f21584b435d37768890b13c71a18a4584554` (0.15.0).
- Tested Git tree: `e762dc80ddaf50ef546940798aabf2ef78934e66`.
- Reviewed main: `e24c4a139703afd14c11a3bc03cd73f71eb84074`;
  preceding review: `a2c508a48812556d43c85ba89654df3200e1551c`.
- This is an uncommitted candidate tree, not a newly created commit. A temporary
  Git index selected only closure files; the user's prompt deletion and untracked
  completion review were not included as candidate changes and remain untouched. The source archive was
  extracted into `/tmp/http-fetch-closure-candidate-e762dc80ddaf` and compiled
  with a fresh `/tmp/http-fetch-closure-final-e762dc80ddaf-build` directory.
- Lockfile SHA-256:
  `12e29c2b5b801498a06aa6771f455f75e70f78f3b2e3d7d2f69f5e846b5d80d5`.
  Root builds use the locked dependency checkout; packaged consumers resolve
  and compile their dependencies in new, out-of-umbrella temporary projects.
- Environment: Linux 6.18.48, eight CPUs, Elixir 1.18.5, OTP 28.5.0.5.
  Peers: hyper-h2 4.2.0, hpack 4.1.0, hyperframe 6.1.0; Node 24.19.0 with
  nghttp2 1.69.0. The harness verifies those exact versions.
- Every final gate records its exact command, tree, start time, elapsed time,
  and exit status. This report and the local evidence archive are subsequent
  reporting-only additions, not executable changes to the tested candidate.

### Reviewable implementation groups and finding mapping

| Group / finding | Reconciled code and policy | Executed evidence | Status |
| --- | --- | --- | --- |
| Runtime A / F1 | `connection_owner.ex` marks final-header uploads stopped, clears pending bytes and scheduler membership, and ignores late body events. `body_bridge.ex` stops reads and clears retained chunks, ACK state and credit. Release sends CANCEL only after response completion if the request half remains unfinished; a completed response followed by peer NO_ERROR remains valid. | `http2_early_response_closure_test.exs`: raw socket SETTINGS window 0 / concurrency 1 before POST; binary and external bodies, 200/413, same-socket reuse after observed CANCEL; incomplete response plus upload credit and a PING processing barrier; completed NO_ERROR reset; late ACK/credit after early response or cancellation. `f1-red.log` records the original failures; final full tests, focused regressions and both clean package consumers pass. | PASS |
| Runtime B / F2 | `pool.ex` atomically promotes one eligible queued caller to connector, retains its original deadline/monitor, validates connector ownership on registration, and redispatches across keys when global capacity changes. `socket_client.ex` carries the original remaining deadline into promotion. A dead newly registered owner fails its own unsent reservation instead of blocking eligible callers behind it. No sent request or consumed producer is replayed. | Eleven `http2_pool_progress_test.exs` cases cover DOWN/draining, key A idle expiry freeing capacity for B, zero-to-positive SETTINGS capacity, promoted death/cancel/deadline, stale registration, connector failure and the last global slot. `http2_queue_socket_progress_test.exs` uses raw frames and the public API to replace a GOAWAY/closed owner without a rescue call. `f2-red.log` and `f2-registered-red.log` precede the corresponding repairs. | PASS |
| Runtime / scheduler defect found during acceptance | `HTTP.HTTP2.Scheduler.remove/2` now preserves sibling IDs when removing an already absent ID. Early-response stop and release legitimately remove the same stream twice; the old empty-list base case discarded every other queued upload. | The first attempted soak stalled with positive connection/stream credit, an empty owner mailbox and sibling uploads missing from the scheduler. `scheduler-red.log` reproduces the missing-ID removal failure; `http2_scheduler_test.exs` and final mixed traffic verify the repair. The failed soak is retained, not blamed on or suppressed in the Node peer. | PASS |
| Gate C / F3 | The post-review `c67aa4c` repair already injects the unchanged coordinator deadline event only after a streamed response is returned. This task preserves it and adds a separately gated pre-header expiry regression. Production deadlines are not restarted or extended. | The original full fetch job at reviewed `e24c4a1`, seed 342781 / max_cases 8 / four schedulers, reproduces the exact `{:error, :request_timeout}` / `.status` KeyError twice under concurrent load. A controlled raw-peer barrier also demonstrates correct pre-header expiry. The final full fetch job passes three fresh-VM repeats under concurrent load, with the returned-stream error assertion retained. | PASS |
| Gate C / independent OwnerMonitor diagnosis | `OwnerMonitor.start/2` is unchanged. The old 100-ms assertion bounds scheduling of a spawned fixture's readiness marker, not just the monitor operation. Test readiness and DOWN observations now have explicit 5-second headroom; shutdown reasons, guardian cleanup and owner survival assertions are unchanged. | `timing-diagnosis.log` holds fixture startup at a message barrier: the old 100-ms observation expires, then readiness and the real owner-death shutdown contract pass after release. Final core tests and focused regressions pass. The exact earlier natural OwnerMonitor flake is not claimed reproduced; the controlled scheduling-budget diagnosis is separate from HTTP/2 expiry. | PASS (narrow timing hardening) |
| Gate C / concurrent fixture isolation | The raw scripted peer owns and retains its listening socket for the lifetime of its pooled connection. Telemetry assertions identify the emitting owner/bridge instead of treating another asynchronous request's event as a duplicate. The failed-open fixture restores both owner and pool capacity after its deliberate private-state mutation. | Concurrent candidate repeats exposed telemetry cross-talk and an `:owner_closed` response before the intended owner-death assertion. `peer-port-red.log` independently proves the previous fixture allowed a second listener on the still-live pooled origin. Admission tracing additionally exposed stale fixture capacity. Final full and repeated fetch suites pass without exclusions, production retries or relaxed outcome assertions. | PASS |
| Gate D / F4 and repository quality | Already fixed at HEAD: both legacy unpackers and generated consumer declarations include all six packages; fetch/WebTransport require `elixir_quic_http3 ~> 0.15.0`; narrowly scoped HTTP/3 formatting/Credo corrections and fresh-connection TLS resumption fixtures are retained. This task does not duplicate those fixes or change TLS backends. The newer package gate additionally runs the lifecycle/closure tests from unpacked packages and honors the lockfile. | `final-external-consumer.log`, `final-exssl-feature-consumer.log`, `final-tls-lifecycle-ci.log`, both `final-package-tls-*.log`, root format/strict compile/Credo/Dialyzer logs. | PASS (local equivalents) |
| Verification E / F5 | All acceptance uses the frozen tree above, with the original workload targets retained. A zero process exit without a complete workload PASS record is not accepted; soak completion additionally requires the requested duration. | All 42 final gates completed with exit status zero. The soak contains an explicit completed workload and PASS record after 1,800,145 ms; see acceptance ledger below and the derived audit. | PASS (local acceptance) |

The raw F1 socket oracle does not reuse the production frame or HPACK codec.
F2 combines deterministic pool-state barriers with an independent raw socket
GOAWAY/reconnection oracle. HTTP/1 remains the overall default; TLS choices,
profiles, pure core/runtime separation and the supervised owner remain intact.
No HTTP/3 feature work, opaque engine replacement or protocol/backend fallback
is included.

### Final-candidate acceptance ledger

| Mandatory target | Exact evidence and workload | Status |
| --- | --- | --- |
| Locked dependencies, fresh strict compilation | `final-deps.log`: `mix deps.get --check-locked`; `final-compile.log`: `mix compile --warnings-as-errors`, fresh test build. | PASS |
| Root formatting, Credo, Dialyzer | `final-format.log`, `final-credo.log` (`--all`), `final-dialyzer.log`. Four pre-existing intentional Dialyzer skips remain, with no unnecessary skips or new directory suppression. | PASS |
| Full umbrella tests | `final-full-tests.log`: seed 342781, max_cases 8; 684 tests and 20 doctests, zero failures, three existing gated QUIC skips. No HTTP/2 tests are excluded. | PASS |
| Lifecycle cold/load repeats | Three `final-cold-fetch-repeat-*.log` runs, each a fresh VM with four schedulers, seed 342781 / max_cases 8: 306 tests and 20 doctests, zero failures each. The complete HTTP/2 TLS lifecycle file also passes seed 36. | PASS |
| Both legacy consumers | Six unpacked applications, clean dependency resolution, compilation, startup and existing smoke assertions. Published ex_ssl gate preserves all nine feature groups: 68 tests, zero failures; runtime ex_ssl 0.7.2 and fixture commit/checksums verified. | PASS |
| New HTTP/2 package consumers | `final-package-tls-ssl.log` and `final-package-tls-ex_ssl.log`: clean six-package consumers, strict prod/test compilation, real independent peer requests and 79 HTTP/2 tests each, seed 342781 / max_cases 8. | PASS |
| Independent full matrix | 18 `final-{smoke,transfer,concurrent}-{hyper-h2,node}-{h2c,tls-ssl,tls-ex_ssl}.log` entries, all successful. Each transfer includes a 10-MiB binary upload, 10-MiB streamed uploads with 1/16/64-KiB source chunks and a verified 10-MiB download. Every concurrent variant retains the 100-request overlap barrier, a paused 6-MiB reader and resource assertions. | PASS |
| Sequential reuse | 10,000 requests at each peer stream limit 1/2/100, for both pinned peers; six `final-reuse-*-limit-*.log` entries, all successful, with one reused connection and zero remaining reservations each. | PASS |
| Small/zero/shrunk windows, SETTINGS-only resume and EOF | Core production/settings and fetch production-flow/runtime/body-bridge tests in the full suite, including zero-credit EOF and negative stream credit after SETTINGS shrink. | PASS |
| Frame/HPACK faults, reset/GOAWAY, caller death and blocked writes | Core protocol-boundary/HPACK production tests; fetch boundary/lifecycle/pool/failed-open tests and real blocked-writer tests in `socket_client_http2_test.exs`; independent `final-hpack.log`. | PASS |
| Cold/warm WireProfile fidelity | `http2_profile_wire_test.exs` checks every named profile on stream IDs 1 and 3, exact SETTINGS, header order and priority signaling; profile-key isolation and ordinary routing remain covered in the full suite. | PASS |
| F1/F2 and cleanup regressions | `final-runtime-regressions.log`, the full suite and packaged closure tests; raw-wire response-preservation/terminal-transition assertions plus deterministic connector/monitor/timer cleanup. | PASS |
| Complete 30-minute mixed-traffic soak | `final-soak.log`: pinned Node/nghttp2, TLS ex_ssl, seed 0, 3,846 batches / 61,536 mixed requests; completed workload PASS after 1,800,145 ms, process exit 0 after 1,801,170 ms. One reused connection, zero final reservations. | PASS |
| Remote CI rerun / artifact upload | No remote workflow was triggered and no remote artifact was uploaded. Local results do not rewrite the historical failed jobs. | NOT RUN (not authorized) |

The soak's documented acceptance budgets are unchanged: every quiescent batch
requires zero reservations, runtime/protocol streams, pending upload bytes and
unconsumed receive bytes; at most one key/four owners; owner mailbox <=16,
heap <=8 MiB and referenced binary bytes <=2 MiB. Global tolerances are the
initial sample plus 128 MiB BEAM memory and 64 processes. Producer ACK/credit
and retained-chunk bounds also remain covered by bridge and early-response
regressions. These are tested budgets, not universal throughput guarantees.

The actual soak log contains 39 resource samples (every 100th batch and the
final snapshot). Their observed maxima are 74,249,064 bytes BEAM memory,
153 processes, one pool key, owner heap 285,320 bytes and referenced binaries
342,893 bytes. All logged quiescent runtime/protocol stream counts and owner
mailboxes are zero. Resource assertions run every batch; these logged maxima
are sampled observations, not reconstructed per-request measurements.
`acceptance-audit.json` is explicitly a derived summary of these raw records.

### Historical CI and rejected candidates

- Retrieved logs confirm run `36644446649`, job `109664034826`, failed the old
  200-ms lifecycle fixture (284 tests / 20 doctests, seed 342781, max_cases 8).
  CI used Elixir 1.18.5 / OTP 28.5.0.7 on Ubuntu with four schedulers; local
  reproduction uses OTP 28.5.0.5 on Linux/Nix, not a claimed identical CI image.
- Run `36644446650`, jobs `109664034677` and `109664034639`, failed preparing
  `elixir_quic_http3`; the latter skipped its TLS lifecycle step. These were
  dependency-fixture preparation failures, not demonstrated TLS defects.
  Their corrected local equivalents pass on this candidate; the historical
  remote jobs were not rerun or relabeled.
- Attempt tree `b88541f98de1a9c492bacc46162e615928b3c5dd` failed its first soak
  batch after about 61 seconds, revealing non-idempotent scheduler removal.
  Its otherwise passing matrix and quality checks are not final acceptance.
- Attempt tree `368960c1fa20952779de4a58d6c5e3aaac82ebae` passed the full suite
  once but failed concurrent fetch repeats. Its soak and reuse were explicitly
  stopped for fixture repairs. The stopped soak's BEAM shutdown returned zero
  without a completed workload record; it is **not** a passing soak. The
  completion oracle now rejects that situation. All mandatory final targets
  were restarted on `e762dc80ddaf50ef546940798aabf2ef78934e66`.
- The older `2b462399a7611807eebd63331677044b0ba286c6` matrix and stopped soak
  remain historical evidence only. No raw logs were reconstructed from prose.

Actual source, command/seed/version/exit/timing logs, rejected-attempt evidence,
sanitized feature reports and resource samples are retained in
`docs/http2-closure-evidence/e762dc80ddaf.tar.gz`, with its SHA-256 in the
adjacent `.sha256` file. The archive includes a per-file checksum manifest,
the acceptance audit and both rejected attempts; no raw logs were synthesized
from summaries. All 306 unchanged candidate blobs outside this reporting
document and the user-owned prompt deletion matched the workspace at that audit,
before the current follow-up's pool and regression changes.
Remote artifact publication awaits explicit authorization.

## Historical audit trail (before this closure)

The remainder records earlier candidates and their then-current blockers, not
the status of the closure tree above.

**Historical production contract: NOT MET.** The historical acceptance stop below remains
part of the audit trail. During the subsequently authorized 0.15.0 release
preparation, full tests passed (661 tests, 20 doctests, zero failures, three gated
QUIC skips), along with format, Credo, Dialyzer and a six-package external
consumer. Release preparation fixed the HTTP/3 style findings and package
metadata/consumer omissions. The returned-stream deadline regression now
injects the timer event after response delivery; the real deadline under
backpressured ex_ssl drain remains covered. The final 30-minute soak and
complete final independent HTTP/2 matrix are still NOT RUN.

### Historical acceptance stop
The final full-suite attempt found two failures in the unchanged, out-of-scope
`HTTP.OwnerMonitorTest` (100 ms `:watching` assertions). No fix or retry of those
tests was attempted. The upload-admission cleanup fix is committed;
its focused tests and Dialyzer passed. The previous soak was stopped as obsolete
intermediate evidence; a full soak on the final source has **NOT RUN**.
Required root format/Credo checks also fail in unchanged HTTP/3 files.
The user subsequently authorized committing, merging to main and pushing.
This integration authorization does not establish production readiness; no
package release or deployment is included.

## Candidate and environment

- Current source candidate: `93b36e0bc3f990ac361a53c9091a52367428a702`.
- Earlier independent acceptance candidate: `2b462399a7611807eebd63331677044b0ba286c6`.
  Its results below are intermediate evidence, not acceptance of the current tree.
- Review baseline: `a2c508a48812556d43c85ba89654df3200e1551c`.
- Implementation baseline: `d095739c3310601c27252afe76255674906d6c78`.
- Implementation branch: `codex/http2-production`; integration target: `main`.
- Elixir 1.18.5; Erlang OTP 28 / ERTS 16.4.0.5.
- Linux 6.18.48 x86_64, glibc 2.42; Intel Core i5-9300H, 4 cores / 8 logical CPUs.
- Independent peers: Python hyper-h2 4.2.0, hpack 4.1.0, hyperframe 6.1.0;
  Node 24.19.0 with nghttp2 1.69.0.
- Seeded credit model: `{9113, 7541, 2026}`; independent workloads: seed 0.
- Acceptance runs share this host with other validation processes. Durations
  below are observed acceptance runtimes, not isolated throughput benchmarks.

Commands use `MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build`
unless noted. Default `_build` had stale http_core 0.11.0 metadata. A clean build
path resolved dependency preparation without changing source or the lockfile.

The plan/review files predated this work as user-owned untracked files and are
preserved. Protocol/runtime changes were committed in dependency groups: pure
core (`4f11419`), owner/flow/pool/fetch integration (`f00ad4f`), activation and
observability (`32fe273`), independent gates (`e0af3aa`), deterministic reset
barrier (`1b6449f`), and complete-response TCP close handling (`2b46239`).
P2–P5 runtime changes are grouped because the shared owner, consumption ACKs,
pool reservations, and public route migration depend on each other.

## Public configurations and contracts

Ordinary explicit `http_version: :http2` and h2c prior knowledge use the same
supervised ConnectionOwner as explicit wire profiles. HTTPS `:auto` uses it when
h2 is negotiated; existing strict-profile negotiation checks remain. The overall
default remains HTTP/1. TLS backends remain OTP `:ssl` and explicit `:ex_ssl`,
without backend fallback. No h2c Upgrade, proxy, CONNECT, push, HTTP/3 expansion,
or ex_ssl modification was added.

Pool identities retain origin, TLS, profile and caller scope separation. Opaque
TLS options, including structs, conservatively disable reuse. Owners are temporary
children of a dedicated supervisor, independent of the initiating request.
Automatic request replay is not implemented: ambiguous POSTs and consumed
producers are never silently retried.

Wire-profile revision 2 explicitly advertises ENABLE_PUSH=0. All three IDs
(`native_v1`, `synthetic_test_v1`, `synthetic_test_v2`) have cold/warm public-wire
coverage. Synthetic profiles do not claim browser fingerprint equivalence.
See `HTTP2_FINGERPRINTS.md` for the migration details.

## Finding-to-regression evidence

Paths below are relative to the repository. Test basenames live under
`apps/http_core/test/http/` or `apps/http_fetch/test/http/` as indicated.

| Finding / phase | Implementation | Executed regression and acceptance evidence |
|---|---|---|
| H2-01 / P1,P4 | core `http2/connection.ex`, owner stream release | core `http2_production_core_test.exs`, `http2_credit_invariant_test.exs`; public reuse gate at peer limits 1/2/100. Runtime and protocol maps are both measured. |
| H2-02 / P1,P3 | core prefix scheduler; owner fair drains; `body_bridge.ex` | `http2_production_flow_test.exs`, `http2_body_bridge_test.exs`, `http2_runtime_test.exs`; exact independent 10 MiB binary/streamed uploads with 1/16/64 KiB source chunks. |
| H2-03 / P1,P2 | separate peer send allowance and local receive accounting | core production tests, owner boundary tests, and seeded credit-conservation test with 10,000 interleaved receive/ACK operations. |
| H2-04 / P3 | consumption ACKs, finite owner admission, monitored delivery worker | `http2_slow_consumer_test.exs`; independent 100-request barrier with one paused 6 MiB stream and 99 completing siblings. |
| H2-05 / P1,P2 | `boundary.ex`, SETTINGS/owner dispatch, no-push policy | `http2_protocol_boundary_test.exs`, `http2_production_boundary_test.exs`; PING, reset, GOAWAY, continuation lock, padding/priority, frame limits, server ENABLE_PUSH=1 rejection. |
| H2-06 / P1,P5 | `stream_state.ex`, socket response phases, `stream.ex` | core response semantics, fetch production semantics/lifecycle, and stream tests: informational/final/trailer phases, CL/body rules, redirects, returned-stream errors. |
| H2-07 / P2,P5 | staged batch validation, terminal flags, bounded close drain, original deadlines | production lifecycle/boundary tests; 43 socket HTTP2 tests; actual blocked-writer and activation tests. TCP and OTP TLS peer-close tests also each passed 51 consecutive runs. |
| H2-08 / P4 | connection supervisor; caller/connector/subscriber monitors; bounded pool | production pool, route, pool-key and pool telemetry tests. Covers deadlines, cancellation, abandoned claims, owner death, capacity and opaque TLS structs. |
| H2-09 / P1 | connection-wide HPACK, ACK-sensitive decoder limits, bounded decode | core HPACK/settings production tests; independent hpack 4.1.0 shrink/grow/shared-state gate; fatal ambiguous header-write regression. |
| H2-10 / P5 | profile validation, order once, common public runtime | `http2_profile_wire_test.exs` checks every named profile on stream IDs 1 and 3: exact SETTINGS, raw header-name order, priority frames/header; route and profile-key tests. |

Actual early red evidence was retained, including owner boundary 5/5 failures
(`/tmp/http2-owner-red.log`), pure boundary 5/5 failures
(`/tmp/http2-boundary-red.log`), and public upload 1/2 failures
(`/tmp/http2-flow-red.log`). Later regressions reproduced activation failure,
opaque TLS struct pooling crashes, and peer-close races before their fixes.
No test was removed to conceal those failures. The returned-stream reset fixture
now explicitly waits for response delivery before sending reset, avoiding a race
that could legally reject the promise before any response had been returned.

Large ex_ssl fixture preparation uses explicit TCP_NODELAY to avoid hundreds of
serialized delayed-ACK round trips; request deadlines were not expanded.

## Latest verification and mandatory stop

- `mix test`: **FAIL**, 661 tests and 20 doctests, two failures, three gated QUIC
  skips. `/tmp/http2-final-tests.log`. Failures are
  `apps/http_core/test/http/owner_monitor_test.exs:4` and `:37`, both waiting
  for `{:watching, guardian}` within the existing 100 ms assertion timeout.
  Both test and implementation are unchanged from the implementation baseline.
- Focused failed-open cleanup plus real blocked-writer tests: **PASS**, 3 tests,
  zero failures, `/tmp/http2-final-cleanup.log`. Warm and cold admission failure
  release internal producers and preserve a reusable pooled owner; a required
  send timeout reaps the request tasks.
- `mix dialyzer`: **PASS**, four intentional ignores, no unnecessary ignores;
  `/tmp/http2-final-dialyzer.log`.
- `mix credo --all`: **FAIL**, only the same two excluded HTTP/3 findings;
  `/tmp/http2-final-credo.log` (before removal of an unreachable error branch).
- The full suite preceded the final removal of that unreachable branch. Focused
  tests and Dialyzer ran after it. Final independent
  matrix/reuse/package/30-minute soak acceptance is not claimed.

AGENTS requires stopping on out-of-scope test failures. Those tests were not
modified, and subsequent implementation/acceptance was stopped.

## Integration verification

Before committing the cleanup fix, its two focused test files were rerun:
3 tests, zero failures. Formatting passed for all four changed source/test files.
The required pre-push `mix credo` was rerun and failed only in the same unchanged
HTTP/3 files (`control.ex:230` and `transport/quic.ex:27`), recorded in
`/tmp/http2-prepush-credo.log`. The user-owned plan and review remain untracked
and are not included in these commits.

## Earlier candidate repository checks

| Command | Candidate outcome |
|---|---|
| `mix deps.get --check-locked` with isolated build | PASS |
| `mix compile --warnings-as-errors` | PASS |
| `mix test` | PASS: 658 tests, 20 doctests, 0 failures; 3 explicitly gated QUIC skips. `/tmp/http2-candidate-tests.log` |
| Changed HTTP2 source/test/script `mix format --check-formatted` | PASS |
| Root `mix format --check-formatted` | FAIL: unchanged `apps/elixir_quic_http3/lib/quic_http3/qpack.ex:700`; `/tmp/http2-candidate-format.log` |
| Root `mix credo --all` | FAIL: unchanged HTTP/3 `control.ex:230` single-clause with; `transport/quic.ex:27` redundant with clause. `/tmp/http2-candidate-credo.log` |
| `mix dialyzer` | PASS; four existing intentional ignores retained; `/tmp/http2-candidate-dialyzer.log` |
| `MIX_ENV=dev MIX_BUILD_PATH=/tmp/http-fetch-h2-production-docs mix docs` | PASS with existing documentation warnings; `/tmp/http2-candidate-docs.log` |
| `git diff --check` | PASS |

The three HTTP/3 files above are byte-for-byte unchanged from the implementation
baseline. The objective excludes HTTP/3 expansion and AGENTS requires surgical
scope. They were not edited to manufacture a green repository-wide gate.

## Earlier candidate independent acceptance workloads

The runner prints candidate SHA, tracked-tree dirtiness, peer versions, platform,
seed, actual resource samples and final outcome. The matrix uses a fresh peer and
VM per case. No production codec is used by either independent server.

| Gate | Candidate status |
|---|---|
| Smoke: two peers × h2c / TLS OTP ssl / TLS ex_ssl | PASS |
| 10 MiB binary and 1/16/64 KiB-chunked streaming uploads, plus 10 MiB download, all six peer/transport cases | PASS at `2b46239`; final tree NOT RUN |
| 100 simultaneous requests, differing sizes; one paused 6 MiB response while 99 finish | PASS at `2b46239` on hyper-h2 h2c and Node/nghttp2 TLS ex_ssl; final tree NOT RUN |
| 10,000 sequential requests at peer limits 1/2/100 | PASS at `2b46239`, all three limits; final tree NOT RUN |
| Independent HPACK decoder | PASS; `/tmp/http2-candidate-hpack.log` |
| Fresh consumers of six built packages, TLS OTP ssl and ex_ssl | PASS at `2b46239`, both consumers; final tree NOT RUN |
| 30-minute mixed TLS ex_ssl traffic against Node/nghttp2 | STOPPED intermediate run at `2b46239`; final full soak NOT RUN |

Matrix summary: `/tmp/http2-candidate-matrix-summary.log`. Per-case logs use
`/tmp/http2-candidate-<mode>-<peer>-<h2c|tls>-<backend>[-package].log`.
Reuse logs: `/tmp/http2-candidate-reuse{1,2,100}.log`.

The concurrent peers withhold all responses until 100 distinct requests have
arrived on one connection. The gate verifies their barrier header and body bytes,
holds a streamed response unread, waits for all 99 siblings, measures the paused
owner, then consumes the final stream. This proves overlap and sibling progress;
launching 100 tasks alone is not treated as proof.

The package gate uses `mix hex.build --unpack` for six applications, then creates
a separate consumer with unpacked package paths. It compiles with warnings as
errors and exercises public fetch without an explicit ex_ssl dependency.
It does not publish packages.

Reproduction examples (from repository root):

```sh
MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build \
  /tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py \
  --peer hyper-h2 --mode reuse --limit 1 --count 10000

MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build \
  /tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py \
  --peer node --tls --backend ex_ssl --mode concurrent

MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build \
  /tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py \
  --peer node --tls --backend ex_ssl --mode soak --seconds 1800
```

Use `--mode transfer` for large transfers and `--package` for the external
consumer. Create the Python environment with pinned `h2==4.2.0`, `hpack==4.1.0`,
and `hyperframe==6.1.0`. Peers bind loopback and use existing test certificates.

## Bounds, observations and limits

- Receive admission has a 1 MiB connection budget and at most 128 unconsumed
  deliveries per stream. Stream credit returns only after consumption; connection
  credit may return on admission within the budget so siblings can progress.
- Producer source chunks are capped at 64 KiB and scheduled in at most 16 KiB
  quanta. A caller-supplied binary remains an original request allocation, not a
  claimed receive-buffer bound. HTTP/2 bridge status and telemetry report its
  bounded chunks and lifetime outcomes.
- Writes use a finite one-second send timeout. A real peer with small TCP buffers
  grants 64 MiB credit and stops reading; the request returns a transport timeout
  within five seconds, with owner death and pool removal asserted.
- Writer batch peak measures serialized batches, **not** queued mailbox bytes.
- Connection telemetry exposes active/protocol streams, receive/upload bytes,
  finite close categories, numeric peer error codes and flow-control stalls.
  Pool telemetry exposes aggregate reservations, waiters, connecting/draining
  counts and queue wait. It excludes raw keys, headers, bodies and TLS identities.
- A real paused consumer retained 65,535 wire bytes while its sibling and PING
  progressed. Its gate bounds each observed mailbox to 8 messages, process memory
  to 2 MB and binary references to 1 MiB. Independent 100-request gates also
  observed 65,535 buffered bytes and owner mailbox 0 while the last consumer paused.
- The soak uses 16 concurrent mixed requests per batch. Every quiescent batch
  checks zero pool reservations, runtime/protocol streams, pending upload and
  unconsumed receive bytes; at most one pool key/four owners; owner mailbox <=16,
  heap <=8 MiB and binary references <=2 MiB. Global tolerances are baseline
  +128 MiB BEAM memory and +64 processes. These are explicit acceptance budgets,
  not universal memory or throughput guarantees.

## Remaining blockers

1. Two unchanged, out-of-scope OwnerMonitor tests failed in the full suite.
   Work stopped per the explicit scope policy; the cause has not been established.
2. Upload-cleanup source and tests are committed. Final source acceptance,
   independent matrix/reuse/package gates and the complete soak remain NOT RUN.
3. Repository-wide format and Credo remain FAIL in the unchanged, excluded HTTP/3
   files. HTTP/2 tests passing does not make those required gates green.

The user authorized main-branch integration and remote push after reviewing the
blocked state. No package release or deployment is included. Production readiness
is not claimed while these blocking gates are incomplete or failing.

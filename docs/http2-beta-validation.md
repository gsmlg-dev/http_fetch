# HTTP/2 beta hardening validation

Evidence date: 2026-10-06 (Asia/Shanghai). This report distinguishes reviewed
source, mutable-source preflight, frozen-candidate acceptance, and GitHub Actions.
The supported workload and rollout/rollback policy are in
[HTTP/2 beta support and operations](http2-beta-support.md).

**Scoped beta readiness: PASS.** Frozen candidate `ad111de` completed all 78
acceptance gates, including both genuine 1,800-second soaks. Its automatic CI,
manual full CI/Test/E2E and remote artifact audit also passed at that exact SHA.
The three earlier failed/interrupted attempts remain rejected evidence. This
decision covers the recorded runtime, native profiles, peer/routes and bounded
workloads below; it does not establish unlimited concurrency, gRPC, arbitrary
fingerprints, additional runtimes or a multi-hour production canary.

## Candidate and baseline

| Identity | Value |
| --- | --- |
| Reviewed baseline | `d11a6608c9f61c5176c6c43cf7b8918f91f88f0f` (`v0.16.7`) |
| Selected implementation commit | `ad111de8d6556107d5338877472eeeab56338485` |
| Selected Git tree | `1b52775fe812bcea3719638b5dcf3a930af19e3b` |
| Selected immutable source export | `/tmp/http2-beta-candidate-ad111de` |
| Selected acceptance evidence | `/tmp/http2-beta-acceptance-ad111de` (PASS) |
| Rejected first attempt | `15df56acc86ee1e48ab89a0eaee6c9e3d339912e`; tree `2835575e7eb56864570fe45ff5820765e2c2485a` |
| Rejected second attempt | `8560016447213864d869aaf1be460b99cb93b390`; tree `d38d23cf5aa436e1e6a72c4316caab685527ff40` |
| Rejected third attempt | `eb0e8a964fc54cf05192dae8c41c9ac966a4fad7`; tree `b42cbb45154510e521724729d24465b5517d8f02` |
| Rejected exports/evidence | `/tmp/http2-beta-candidate-<short-SHA>` and `/tmp/http2-beta-acceptance-<short-SHA>` for the three identities above |
| First/isolated compatibility attempts | `/tmp/http2-beta-ci-compat-15df56a`, `/tmp/http2-beta-ci-compat-isolated` |

The implementation was divided into runtime/metadata (`66da054`), consumer CI
(`4c97140`), package/metrics harnesses (`5c8cae3`), and support documentation
(`15df56a`). Acceptance runs from a separate Git archive export. Both existing
acceptance runners verify every tracked source blob against the frozen tree
before and after workloads and reject extra executable source. Package gates
rebuild from that source and resolve isolated signed-Hex consumers. A later
validation-report commit does not replace the tested implementation identity.
The scheduling (`8560016`), fixture (`eb0e8a9`) and historical-path (`ad111de`)
commits completed acceptance preparation. All runtime and package-source blobs
are identical to `15df56a`; its complete 19-gate compatibility rerun remains
evidence for that preceding candidate,
separate from the selected candidate's completed production acceptance.

The original plan audited source and historical CI without executing local
Elixir tests. Historical v0.16.0/v0.15.1 acceptance and the v0.16.7 release remain
historical evidence; none is relabeled as a fresh run of this candidate.

## Findings, changes, and red/green evidence

### A: automatic HTTPS admission — confirmed

On the reviewed baseline, `cold auto HTTPS bounds actual TCP accepts for ssl`
and the corresponding `ex_ssl` test observed **six accepted TCP connections**
for six simultaneous callers under a one-connection limit. The assertion
expected one. The baseline run selected two tests: two failures, 18 excluded;
excluded cases were not executed.

`apps/http_fetch/lib/http/socket_client.ex` now acquires the existing pool's
connect claim before reusable automatic HTTPS dialing. H1 negotiation completes
and releases its claim, allowing queued callers to negotiate; it does not fail
all queued callers merely because ALPN selected H1. Subscriber monitoring reaches
both interruptible dialing and pool waits, including registration waits.
`apps/http_runtime/lib/http/http2/pool.ex` provides successful non-H2 settlement
and a caller-bound, one-time first-stream reservation entitlement for an already
admitted connector. This entitlement does not allow arbitrary callers or repeated
reservations to bypass the pending limit.

`apps/http_runtime/lib/http/http2/connection_owner.ex` permits at most one initial
reservation for an automatic owner before peer SETTINGS, then obeys the actual
peer capacity. Allowing the first request preserves peers that wait for request
HEADERS before sending SETTINGS. Explicit H2/h2c behavior is retained.

The final preflight admission run passed **24 real TLS regressions and two pool
regressions**. Tests in `http2_auto_admission_test.exs` include cold/saturated
bursts, pre-TLS overload, failed handshake, H1 fallback, abort/deadline/caller
death while queued and dialing, and caller death while awaiting initial stream
capacity, for both backends. `http2_admission_pool_test.exs` covers one initial
reservation, zero/changing SETTINGS, and the one-time admitted reservation when
the external queue is full. Existing `http2_pool_key_test.exs` covers distinct
trust, client key/certificate contents, backend, scope, ALPN and profile identities.

The independent hyper-h2 control channel observes actual accepts, successful
handshakes, in-flight/peak negotiations and requests. The final cold-burst
preflight observed, for each backend, one accepted connection, one handshake,
peak in-flight negotiations one, six completed requests, and no remaining
in-flight handshake. Pool waiters, connectors, callers, reservations,
promotions and deadline maps returned to the asserted baseline. Negotiation
latencies in this preflight were 47,395 microseconds (`ssl`) and 6,880 microseconds
(`ex_ssl`); these are observations of that run, not performance guarantees.

### B: H2 metadata retention — confirmed

The exact reviewed-baseline regression
`retains multiple ordered 103 blocks and duplicate fields separately from final headers`
failed because `response.informational` was empty. That run selected one final
regression: one failure, 22 excluded. The completed metadata suite passed
**23 tests** after the change.

`socket_client.ex` now preserves ordered informational blocks, stores buffered
trailers separately, and uses the existing `HTTP.Stream` trailer/completion
messages for streamed responses. Informational responses do not abandon uploads.
Count/byte retention limits supplement the unchanged HPACK/protocol validation.
`apps/http_fetch/lib/http/response.ex` and the support document explain H1/H2/H3
availability, immutable streamed responses, completion timing and limits.

`http2_response_metadata_test.exs` covers multiple 103 blocks, duplicate fields,
buffered/streamed/empty bodies, split HEADERS/CONTINUATION, invalid pseudo-header
and Content-Length trailers, nonterminal trailers, count/byte boundaries,
binary and public-stream uploads, simultaneous stream isolation, HPACK dynamic
state across reuse, and validated DATA/trailers at EOF. Exact ordering tests
include `stream trailers wait for final DATA delivery acknowledgement and precede end`
and both `abort`/`reset during unacknowledged final delivery cannot publish queued trailers as success`.

Independent Python and Node production peers now implement `/metadata/buffer`
and `/metadata/stream`. The existing production smoke driver asserts two ordered
103 blocks, exact body integrity, separate buffered trailers, and acknowledged
stream trailers followed by end. Frozen acceptance runs those assertions over
h2c and verified TLS with both backends, including isolated package TLS consumers.

### C: shared/downstream automatic gates — confirmed

The baseline selector regression failed with
`baseline fails to select H2 consumers for shared core changes`.
The final preflight CI-helper suite passed **16 tests**. `scripts/ci/changed_apps.py`
reads actual `in_umbrella` dependency declarations and selects changed owners plus
affected Fetch/EventSource/WebSocket consumers. CI/Test/E2E now trigger on relevant
root manifests/lockfile, configuration, H2 harnesses, CI/release tooling and
workflow paths. Irrelevant root documentation stays cheap.

The new CI compatibility job invokes `scripts/ci/http2_compat.py`, preparing the
root dependency closure and running consumer suites, both independent peers over
h2c/TLS, and signed candidate-package mixed traffic. Records retain candidate SHA,
commands, backend/peer, test summaries/exclusions, archive checksums and log hashes.
Terminal-evidence tests reject generic PASS records, peer-only source checks,
empty observations, and package metadata PASS without completed four-consumer
traffic. Test and release jobs install pinned admission-peer dependencies before
running Fetch/source tests. Real GitHub Actions execution and artifact auditing
are recorded separately below.

Acceptance also exposed an existing package harness mismatch: `--tls --package`
ran the separate four-consumer h2c gate and then exited with
`gate exited without a complete workload PASS record`. This was a routing error,
not evidence of a TLS client failure. `scripts/http2_package_gate.sh` now audits
archives and invokes the signed isolated consumer's `h2` mode in
`scripts/release/consumer_gate.py`. Five focused regressions pass, including an
actual Mix rejection of a path dependency before network traffic. The separate
four-consumer h2c gate remains separate.

## Preflight results

These checks ran against mutable implementation source before the final freeze.
They establish regressions and preparation; they do not substitute for frozen
production acceptance.

| Check | Observed result |
| --- | --- |
| Reviewed-baseline scoped tests | PASS: 76 tests, zero failures |
| New metadata regressions | PASS: 23 tests |
| New TLS admission and pool regressions | PASS: 26 tests |
| Existing SocketClient H2 compatibility after final admission recovery | PASS: 69 tests |
| Core/runtime/Fetch/EventSource/WebSocket consumer suites | PASS: 890 tests, 20 doctests, zero failures; three optional core QUIC skips |
| CI/selector/terminal-evidence helpers | PASS: 16 tests |
| Release/package helper regressions | PASS: 32 tests |
| Compile with warnings as errors, scoped/full formatting, Credo, actionlint | PASS |
| Independent source metadata smoke, Python and Node h2c | PASS |
| Independent package metadata smoke, hyper-h2 TLS `ssl` and `ex_ssl` | PASS |

Package preflight resolved all nine packages at `0.16.7` through `Hex.SCM`, checked
application versions/dependency destinations, and proved HTTP, connection-owner,
pool and SSL modules loaded from the consumer's isolated build. Both TLS runs
ended with one healthy idle connection and zero reservations. Reported smoke
workload times were 412 ms (`ssl`) and 474 ms (`ex_ssl`), excluding package setup.
The three optional QUIC skips are not H2 gates and are not counted as passed tests.

## Superseded first frozen attempt

The first full acceptance attempt used commit `15df56a` and tree
`2835575e7eb56864570fe45ff5820765e2c2485a`. It is **not accepted**. Fetch cold
repeat 1 failed a 100 ms fixture-initialization assertion while multiple test
VMs and source workloads were active. The full root suite and cold repeats 2/3
passed, but those successes do not make the aggregate attempt pass. The runner
was terminated after the failed prerequisite; the aggregate exited 130. Its
partial mixed soak terminal record measured **143,460 ms**, exit -2, and is
**INTERRUPTED, not a genuine completed 1,800-second soak**. The Fetch aggregate
record measured 107,368 ms and exited 1.

The first new CI compatibility attempt also **FAILED**: an H2 deadline/TLS
monitor observed `:noproc` where its fixture expected `:normal`, and an H1
WebSocket worker observed `:shutdown` where its fixture expected `:normal`.
An unchanged targeted H2 rerun passed. The H1 WebSocket case was excluded by
that targeted invocation, so that invocation does not validate it. The complete isolated compatibility rerun then passed all 19 gates at the
same candidate, including all five consumer suites (890 tests, 20 doctests, zero
failures, three optional core QUIC skips), both peers over all three routes, and
nine signed candidate packages with four-consumer traffic. Every recorded log
hash matches its retained log. This does not retroactively accept the failed
concurrent attempt or establish completed soaks. Failed logs and terminal records
are preserved.

The committed scheduling-only adjustment serializes complete/cold Fetch test
VMs and waits for the actual prerequisite result file before starting
mixed/source load gates. All 78 original workloads, assertions and deadlines
are retained, and the two real soaks remain parallel. No existing fixture
assertion or timeout was changed to hide these failures. The replacement was
frozen at `8560016`/`d38d23c`; its full acceptance failed before starting load
or soak workloads.

## Superseded second frozen prerequisite failure

At `8560016447213864d869aaf1be460b99cb93b390`/tree
`d38d23cf5aa436e1e6a72c4316caab685527ff40`, compile, formatting, full root tests,
and cold Fetch repeat 1 passed. Cold repeat 2 failed
`factory owner with no surviving waiter expires instead of occupying capacity`
(`HTTP.HTTP2ProductionPoolTest`, `http2_production_pool_test.exs:212`).
`Pool.stats(pool)` still reported one idle `orphan` connection where the assertion
expected an empty map. That run reported 367 tests, 20 doctests and one failure,
exit 2. The Fetch aggregate exited 1 after 136,582 ms and explicitly marked
remaining workloads NOT RUN. Neither original soak began. This is a failed
prerequisite, not a passed acceptance run. The fixture observes the owner's
DOWN message at the test process; the pool processes its own DOWN message
independently. That observation does not synchronize removal from the pool.
The fixture repair committed at `eb0e8a9` waits boundedly for the actual empty
pool state before the unchanged assertion, retaining the 20 ms idle timeout and
the same total 1,000 ms budget for owner-DOWN observation and pool cleanup. Standalone 200- and 2,000-iteration probes did not reproduce the timing
failure, including a skewed probe; they are not a deterministic red regression.
The frozen failed log remains the observed failure evidence. The repaired scoped
pool suite passed 11 tests. Three complete cold Fetch
repeats at the newly frozen `eb0e8a9` each passed 367 tests and 20 doctests with
zero failures, in 24.9, 24.9 and 24.2 seconds. Their logs are
`/tmp/http2-beta-fixture-cold-repeat-{1,2,3}.log`. The complete frozen acceptance
then began with master log `/tmp/http2-beta-acceptance-eb0e8a9.log`; terminal
load/soak evidence remained pending at that superseded attempt; current remote
results are recorded separately below.

## Superseded third frozen harness failure

Candidate `eb0e8a9` passed all ten source prerequisites, including its full root
suite and three cold repeats, then failed `final-exssl-feature-consumer` in
2,927 ms. That gate invoked the retained pinned historical staging script from
a nongit immutable source export; `git archive` returned exit 128 with
`fatal: not a git repository`. The historical consumer tests did not run in
that gate. The path correction committed at `ad111de` explicitly gives the script the
actual repository for history lookup while preserving the immutable candidate
script and historical commit `e844ce03067fedac82c079f21c47810e671be0bb`.

The parent interrupted the remaining work after the failed gate. Fetch aggregate
exit was -2 after 317,641 ms. The Fetch soak was interrupted with exit -15 after
97,997 ms; the mixed soak was interrupted with exit -2 after 99,063 ms. Neither
is a completed 1,800-second soak. Independent package TLS, HPACK, lifecycle,
Credo, Dialyzer, external consumer and numerous SSE/WS gate records passed before
shutdown, but the aggregate is not accepted. A new candidate and complete
load/soak run were required after that failed attempt. Four historical staging
unit regressions, Bash syntax and diff checks passed for the two-line harness
correction; the independent published feature preflight then passed nine groups, 68 tests,
zero failures (exit 0). Its terminal provenance records `Hex.SCM`, `ex_ssl 0.7.2`,
inner checksum `cba8ff536d7571537e75d112d2712ba49b5b406bc475acc1dda253b513229ab3`,
outer checksum `f0f9532a6ac8b2dcb701b491394705df8f10c31f63fc7e5aad157eebb909aecb`,
and source commit `e844ce03067fedac82c079f21c47810e671be0bb`.
That gate deliberately tests the pinned historical source against published
dependencies, separately from current candidate-runtime tests. The same gate
then passed at frozen `ad111de` with nine groups, 68 tests, zero failures, exit 0
and measured runner duration 130,991 ms; the archive-path failure is resolved.

## Frozen acceptance matrix

The retained commands preserve existing workloads, assertions and deadlines.
The local environment is Elixir 1.18.5/OTP 28, hyper-h2 4.2.0 with HPACK
4.1.0/hyperframe 6.1.0, and Node 24.19.0/nghttp2 1.69.0.

| Candidate check | Peers/routes | Status |
| --- | --- | --- |
| Existing 42 Fetch gates | Python and Node; h2c, verified H2 `ssl`/`ex_ssl`; packages and source | PASS: 42 unique gates, all exit 0 |
| SSE numbered/mixed/faults and churn | Python and Node; h2c and both TLS backends; 1,001-event churn | PASS: all 20 gates; tree and log hashes verified |
| WebSocket echo/mixed/faults and churn | Python plus Node mixed cases; h2c and both TLS backends; 1,000-session churn | PASS: all 13 gates; tree and log hashes verified |
| Four isolated package consumers, including shared Fetch/SSE/WS | Signed candidate artifacts; independent hyper-h2; h2c | PASS: completed four-consumer traffic |
| Fetch 1,800-second soak | Node, verified H2 `ex_ssl` | PASS: actual workload 1,800,309 ms |
| Mixed Fetch/SSE/WS 1,800-second soak | Independent hyper-h2, verified H2 `ex_ssl` | PASS: active workload 1,800,089 ms |
| New CI compatibility harness on frozen candidate | Both peers, h2c/TLS, candidate packages | PASS: 19-gate artifact audit at `ad111de`; earlier failed/isolated runs retained separately |
| Real GitHub Actions CI/Test/E2E | Exact pushed `ad111de` implementation candidate | Automatic CI and manual full CI/Test/E2E PASS |

The selected `ad111de` root suite completed with exit 0 in 50,714 ms. Its reported
summary totals are **1,864 tests, 20 doctests, 20 properties, zero failures,
177 excluded and three skipped**; excluded/skipped cases are not passed cases.
The 177 `:integration` exclusions come from `apps/ex_ssl/test/test_helper.exs`'s
existing `ExUnit.start(exclude: [:integration])`. The three core QUIC integration
tests require `HTTP_QUIC_PHASE1_REAL=1`, which was not set in this root test run.
Independent H2 traffic, admission tests and metadata tests are separate gates;
this ordinary source test summary does not establish long-soak completion.

The existing 42 gates include 10 MiB transfer integrity, streamed uploads and
early final responses, 10,000-request reuse at peer limits 1/2/100, barrier-controlled
concurrency/paused consumers, lifecycle/cancellation/deadline/reset regressions,
full source tests, formatting, Credo, Dialyzer, and independently resolved
consumers. New admission/metadata tests run in the same frozen test suites.

The aggregate terminal record reports PASS/completed, 42 Fetch gates and 36
additional gates. All 42 unique Fetch ledger rows exited 0 at the frozen tree.
All 39 top-level gate result records exited 0 and match their retained log hashes.
Both original soaks have terminal PASS records and actual active workload duration
at least **1,800,000 ms**, independently of setup/cleanup/outer-runner time.
Historical and interrupted soaks are excluded from this result.

## GitHub Actions evidence

The selected implementation candidate `ad111de8d6556107d5338877472eeeab56338485`
is pushed. These run identities, head SHAs and recorded results were verified
through GitHub. Artifact/log auditing of compatibility evidence is recorded
separately from workflow conclusions; nonterminal runs are not passed runs.

| Selected candidate workflow | Run | Observed status |
| --- | --- | --- |
| Automatic CI | [37415397249](https://github.com/gsmlg-dev/http_fetch/actions/runs/37415397249) | PASS |
| Manual full Test | [37415403676](https://github.com/gsmlg-dev/http_fetch/actions/runs/37415403676) | PASS |
| Manual full E2E | [37415403796](https://github.com/gsmlg-dev/http_fetch/actions/runs/37415403796) | PASS |
| Manual full CI | [37415694802](https://github.com/gsmlg-dev/http_fetch/actions/runs/37415694802) | PASS |

The final full CI artifact audit passed all **19 compatibility gates** and
verified all **nine candidate package hashes**. Its five consumer suites reported
890 tests, 20 doctests, zero failures and three optional core QUIC skips. Both
independent peers exercised h2c, verified OTP TLS and verified `ex_ssl` TLS;
the package gate completed four isolated consumers, four connections and one
shared Fetch/SSE/WebSocket connection. Its artifact exclusion record states
that this finite compatibility job excludes long soaks and that package mixed
traffic uses h2c while the independent source consumers exercise both TLS
backends. Separate candidate and published historical `ex_ssl` reports each
passed nine groups/68 tests. These are completed traffic/test records, not
metadata-only or generic PASS markers.

Retained final remote artifacts:

| Artifact | ID | GitHub SHA-256 digest |
| --- | --- | --- |
| H2 compatibility | `11390629953` | `edecfc3340c1dd5d351ae27c8d2de053fffa0590d06d139b6d2110612a0edf63` |
| Candidate `ex_ssl` features | `11391650093` | `54997973ca0e58a9431fdb9ef9ac09fffac40dc8b1134e7e7881a02efe41f8d2` |
| Published historical `ex_ssl` features | `11390254655` | `8f75f49a56277ec68acbbc2e3a383798b226124a6c4c02083e28916ab57c3587` |

The audit and artifact metadata are retained in
`/tmp/http2-beta-remote/37415694802-artifact-audit.json` and
`37415694802-artifacts.json`, included in the final repository evidence archive
below.

The preceding `eb0e8a964fc54cf05192dae8c41c9ac966a4fad7` passed automatic CI
[37414623716](https://github.com/gsmlg-dev/http_fetch/actions/runs/37414623716),
manual full Test [37414644747](https://github.com/gsmlg-dev/http_fetch/actions/runs/37414644747),
manual full E2E [37414644664](https://github.com/gsmlg-dev/http_fetch/actions/runs/37414644664)
(all nine app jobs), and manual full CI
[37414951481](https://github.com/gsmlg-dev/http_fetch/actions/runs/37414951481).
Those are predecessor results, separately retained. The automatically triggered
predecessor H3 workflow `37414623352` also succeeded but is outside this H2 task.
A later report-only commit can have its own workflow revision; it does not
replace the frozen implementation identity.

## Completed soak observations and retained evidence

These are observations of the selected candidate, not performance guarantees.
Both soak log hashes match the retained `soak-observations.json` summaries.

| Observation | Fetch / Node / `ex_ssl` | Mixed / hyper-h2 / `ex_ssl` |
| --- | --- | --- |
| Active workload duration | 1,800,309 ms | 1,800,089 ms; total client 1,801,016 ms; outer runner 1,804,515 ms |
| Resource samples | 43 | 1,659 |
| Maximum sampled owner/process heap | 426,664 bytes | 197,864 bytes |
| Maximum sampled referenced binaries | 430,519 bytes | 677,589 bytes |
| Maximum sampled mailbox | 0 | 28; owner-monitor mailbox 0 |
| Maximum owners | 1 | 2 during controlled draining/promotion |
| Process/session/monitor observations | Process count 159, one pool key | Workers/sessions/monitor workers each peaked at 5; monitor heap 2,816 bytes, binaries 0 |
| Terminal idle state | One healthy owner, one pool key, zero active/protocol streams, reservations 0, mailbox 0 | One healthy owner; workers/sessions/monitor workers all 0, mailbox 0 |
| Completed workload counters | 67,792 H2 request-stop observations | 1,652 soak Fetch requests, 3,303 WS messages, 3,306 SSE messages, 1,651 ticks |

The mixed soak completed all three prescribed intervals: slow consumer,
cancellation and draining. Its independent wire audit passed 3,338 observations
and five clean wire sessions. Expected injected failures were checked by their
original assertions; no unexpected workload failure was accepted. Active samples
and terminal quiescence are separate: healthy idle pooled owners remain present.

The bounded terminal telemetry reports Fetch mean request duration **207.664 ms**
(67,792 observations), mean granted reservation wait **136.991 microseconds**
(67,792 observations), and mean resumed flow-control stall **38.463 ms**
(230,544 observations). For mixed traffic, observed H2 request-stop mean duration
was **42.244 ms** (1,655 observations, including setup), granted reservation wait
**6.916 microseconds** (1,665 observations), and the one promotion wait was
**12.087 ms**. The populated request-duration bucket ceilings were 1,000 ms for
Fetch and 100 ms for mixed traffic; these are histogram bounds, not exact maxima
or latency guarantees. Fault/drain categories and all bucket counts/totals are
retained for independent inspection. Stall intervals can overlap across streams.

The final archive is
[ad111de8d655.tar.gz](http2-beta-evidence/ad111de8d655.tar.gz), with
[checksum](http2-beta-evidence/ad111de8d655.tar.gz.sha256):
`3cffee6406fed80716c238b36513b287beef7208c50833423ad0b59440bb8c40`.
It contains 465 retained evidence files plus `evidence-manifest.json`, including
frozen commands/source manifests/ledgers, soak observations, the three rejected
attempts, baseline red/green and preflight evidence, and raw remote logs,
compatibility reports and artifact audits. Builds, caches, staging trees and
package payloads are excluded; nine package checksums remain in the remote
reports and signed payloads are available from the linked GitHub artifact.
The archive checksum matches the checked-in checksum file. All 465 manifest
payload sizes/hashes and the frozen candidate/tree identities were verified.

## Workload budgets and readiness limits

The admissible-workload error budget is zero unexpected failures and exact
body/event integrity. Expected injected cancellation/reset/deadline failures must
match their assertions; they are separate from unexpected failures. Existing
limits are preserved: Fetch quiescent owner heap at most 8 MiB, referenced binaries
at most 2 MiB, mailbox at most 16, no active/protocol streams or upload/receive
buffers, and at most four owners/one pool key in its gate. SSE/WS suites retain
their own owner/session/worker/mailbox budgets and sibling-progress assertions.
Healthy pooled idle owners need not be zero.

The added aggregate collector retains bounded counters/buckets for request and
queue latency, pool/stream counts, reset/GOAWAY/close categories and flow-control
stall duration; it does not retain request IDs or bodies. Admission peers retain
actual TCP/handshake counters. The completed observations above report sampled
maxima and final counters; raw records retain the individual samples and events.

**Scoped beta readiness is PASS** for the tested Elixir 1.18.5/OTP 28, native
profiles, routes/backends and admissible workloads. Frozen acceptance, required
automatic/manual workflows and artifact auditing passed at the selected
candidate. Multi-hour/24-hour representative canaries, other runtime
versions, arbitrary concurrency/QPS guarantees, gRPC, complete RFC conformance,
package publication and deployment are **NOT RUN or NOT CLAIMED**. Start the
beta cohort with explicit H2, native profiles, verified TLS and finite
application concurrency/deadlines as the support document specifies. Both
`:ssl` and `:ex_ssl`, automatic-negotiation admission and H2 metadata have
recorded acceptance here. Untested backend/runtime combinations and custom
fingerprints require separate acceptance before expansion. The support
document's staged rollout/rollback runbook remains the operator contract; no
package publication or deployment was performed by this task.

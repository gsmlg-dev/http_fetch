# TLS migration execution ledger

## P7 release-candidate preparation — 2026-10-29

Release tooling at `9840e8e2966885a3af5d4c1f33d7eb7245e4d4f7` accepts canonical
`major.minor.patch-rc.N` versions alongside stable versions. The next coordinated
release targets the user-selected `1.0.0-rc.0`, subject to a fresh availability
check. GitHub RCs use the prerelease flag and `--latest=false`; formal `1.0.0`
follows later validation and a release decision.

A fresh isolated preparation builds all nine `1.0.0-rc.0` archives, verifies their
exact internal requirements and staged source bytes, and reproduces identical archive
hashes. Nine fresh candidate Hex consumers each resolve the exact RC through
Hex.SCM, compile with warnings-as-errors and start with the matching application
version on local Elixir 1.18.5 / OTP 29 (ERTS 17.0.2). No path or umbrella
overrides are used. These are candidate checks, not a fresh supported-runtime
matrix, published-consumer results or the final OTP-free release traffic gate.

The RC-specific automation suite passes all 11 tests with `1.0.0-rc.0`, including
exact dependencies, publication preflight, GitHub prerelease flags and version
validation. The earlier full release automation suite passed 195 tests, CI
automation passed 38 tests, and the unchanged version helper passed strict
compilation and formatting. At that prior source baseline, five unchanged
published-consumer tests failed macOS `/tmp` versus `/private/tmp` assertions;
the full suite passed with an isolated canonical temporary directory, without
changing those tests or their assertions.
Source, build-cache and lockfile guards remain intact. Receipts and archive hashes
for the new `rc.0` checks are retained at
`/private/tmp/http-fetch-root-resume-20261029T0820Z`; earlier `rc.1` preparation
and full automation results remain at
`/private/tmp/http-fetch-root-resume-20261029T0530Z` as historical evidence.

No RC has been published. P6 release acceptance and P7 publication remain open;
Credo/Dialyzer and performance retain their existing deferrals.

## P6 source-removal checkpoint — 2026-10-29

Production removal is committed at `55d719467f691d857df18323e162afcae338ecd3`.
It deletes the retired OTP transport and nested adapter, removes production OTP
selectors and the five unconditional application dependencies, and explicitly
rejects `tls_backend: :ssl`. The current production sources, app manifests,
configuration and lockfile remain identical through `60c1c4a`.

All-nine [units](https://github.com/gsmlg-dev/http_fetch/actions/runs/40809490861)
and the configured [E2E workflow](https://github.com/gsmlg-dev/http_fetch/actions/runs/40809490824)
pass at `55d7194`; apps without standalone E2E suites retain the P4 scope below.
All-nine [integration](https://github.com/gsmlg-dev/http_fetch/actions/runs/40814044245)
passes at `a29248a`, including the corrected H3 attach-timeout precondition. These
are configured Linux results. The earlier macOS blocked-writer observation race
remains open; no unrestricted macOS integration pass is claimed.

The isolated production [release audit](https://github.com/gsmlg-dev/http_fetch/actions/runs/40817866344)
at `71162cb` scans 348 BEAM files. It finds zero direct OTP SSL imports,
application dependencies, boot entries or bundled SSL paths. OTP SSL is
unavailable, unloaded and unstarted before and after the scan. Its 192 unresolved
dynamic calls still reject the release gate, so no traffic scenario executes.

The latest auditor extension proves complete single-hop local wrappers around
selected remote returns and checks nine private SocketClient transport parameter
slots. All 310 compiled controls pass within the unchanged 60-second limit,
alongside 108 tooling checks, strict compilation and formatting. Independent
whole-source compilation verifies the executable equivalence of all three
composed mutation fixtures; compilation jobs finish before any audit begins.

A separate immutable 350-BEAM comparison removes exactly six SocketClient
findings, reducing its configured unresolved count from 181 to 175. The default
count remains 184. Every other ordinary field, occurrence multiplicity and
incoming provenance record remains exact; all source, cache and release guards
pass. The actual artifact gate still rejects the remaining findings. This frozen
comparison does not establish a fresh candidate release or traffic result.
Receipts are retained under
`/private/tmp/http-fetch-root-resume-20261029T0820Z/audit30-acceptance`.

P6 release/traffic acceptance and P7 coordinated publication remain open.
Credo/Dialyzer remain user-deferred; performance is TODO outside this goal.

## P5 default promotion acceptance — 2026-10-28

The shared resolver, Fetch, EventSource, WebSocket and managed H1/H2 now default
to ExSSL. Explicit OTP remains transitional until P6. H2 pool keys use the shared
resolver, reject invalid effective configuration and retain the backend frozen
when a request is constructed. Existing H3 selector/completion boundaries remain.
Direct HTTP/H2c and invalid-scheme requests retain their cleanup tracking when
the TLS selector is ExSSL; an invalid scheme still fails before dialing and joins
an attached upload source. Internal no-request completion admission stays bounded.

P5's non-deferred gates are accepted at
`0f4b3dd0f37caadc71b6db7bdc9fff74e9170825`. Independent peers retain exact
TLS1.2/TLS1.3, connection reuse, provider identity, cleanup, SSE reconnect and
backpressure, WebSocket sharing and nested proxy assertions.

| Gate | Workflow | Executed result |
| --- | --- | --- |
| All-nine units | [40644849041](https://github.com/gsmlg-dev/http_fetch/actions/runs/40644849041) | All app jobs pass at `7021474`; final correction changes one integration test only |
| All-nine integration | [40647177489](https://github.com/gsmlg-dev/http_fetch/actions/runs/40647177489) | All jobs pass at `0f4b3dd`, including QUIC and complete nested proxy suites |
| E2E | [40644856812](https://github.com/gsmlg-dev/http_fetch/actions/runs/40644856812) | All configured suites pass at unchanged production source `7021474` |
| Manual full CI | [40644845034](https://github.com/gsmlg-dev/http_fetch/actions/runs/40644845034) | Nine strict compile/format/package jobs, shared H2, current candidates and historical compatibility pass |
| Candidate runtime matrix | [40644860571](https://github.com/gsmlg-dev/http_fetch/actions/runs/40644860571) | Elixir1.19/OTP28 and Elixir1.20/OTP29 pass; manual CI supplies Elixir1.18/OTP28 |
| Independent public H3 | [40647124858](https://github.com/gsmlg-dev/http_fetch/actions/runs/40647124858) | Pass at `0f4b3dd`; supported H3/completion boundaries retained |

Each candidate runtime executes all 71 groups and 3,061 checks with zero failures,
skips or exclusions. Its 62 migration files include the nine default/configuration
and admission files. The frozen-source manifest SHA256 is
`fd40d79dd37d50d32e31eb53fc0391e75efe23f964c1d5c6b4539725027d7ab3`.
All nine archives resolve through isolated Hex.SCM builds. The `0.21.18` candidate
labels do not establish publication of the default promotion.

Independent artifact review verifies 19 H2 log hashes, nine archive hashes, all
271 packaged files, 246 runtime source files and nine portable manifests against
fixed Git objects. The three Fetch documentation symlinks resolve to their exact
frozen target blobs. The uploader omits ExSSL's hidden formatter from stage;
its archived bytes are still verified against Git. No packaged file is skipped.
The H2 source runner retains three real-QUIC opt-in skips; the separate complete
integration gate executes the applicable QUIC cases. Apps without a dedicated
suite retain the P4 boundaries recorded below.

The production and candidate migration sources are identical from `7021474` to
`0f4b3dd`; only the QUIC cleanup integration test changes. Its independent resource
monitors could precede the cleanup observer's own receipt update. The correction
waits for that observer to handle the exact IO/Port DOWN messages, preserving
the original waits, exact intermediate counts, final cleanup and linked caller.
Its deterministic red/green check and all 47 related cases pass before the fresh
full integration gate. Earlier failed local timing and peer-close invocations
remain historical evidence; no unrestricted macOS suite pass is inferred here.

Credo/Dialyzer remain user-deferred, including their automatic CI failures;
performance remains TODO outside this goal. P6 production removal and P7
publication remain open. Receipts, failed diagnostics and the final artifact
identity review are retained at
`/private/tmp/http-fetch-p5-default-root-20261028T0238Z`.

## P4 integrated acceptance — 2026-10-28

P0–P4 are accepted at `3c561646b7f1bc9042c5cadbc37ed7c6b48fae15` with OTP
still the production default. Required advanced policies, TLS1.3 manual tickets,
TLS1.2 EMS reuse, nested HTTPS proxies, public lifecycle, completion and managed
H1/H2 pass the integrated source and candidate gates. H3 completion retains
`unsupported_completion`. Performance is outside this goal; Credo/Dialyzer remain
explicitly deferred, without a quality-pass claim.

| Gate | Workflow | Executed result |
| --- | --- | --- |
| All-nine units | [40620226704](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620226704) | 2,063 executed; 4,699 integration cases excluded; zero failures |
| All-nine integration | [40620230336](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620230336) | 4,699 executed; 2,063 units excluded; zero failures |
| All-nine E2E | [40620233581](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620233581) | 52 ExUnit cases plus independent Caddy/QUIC/H3 checks |
| Automatic functional CI | [40620203449](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620203449) | Every functional job passes; overall failure is deferred Credo |
| Manual full CI | [40621971812](https://github.com/gsmlg-dev/http_fetch/actions/runs/40621971812) | All jobs pass; every app explicitly records Credo/Dialyzer as deferred |
| Candidate Elixir1.19/OTP28 and 1.20/OTP29 | [40620237216](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620237216) | Both runtime selections pass |
| Independent public H3 | [40620203412](https://github.com/gsmlg-dev/http_fetch/actions/runs/40620203412) | Pass |

Units and integration completely partition the 6,762 discovered source cases.
WebTransport has no integration-tagged source cases: its 24 units are excluded
from integration, not executed as integration. Core and Runtime have no standalone
ExUnit E2E suites; their behavior is exercised by the dependent-client gates.

Each candidate runtime (including manual CI's Elixir1.18/OTP28) passes 62 groups
and 2,944 checks with zero failures, skips or exclusions. The exact 53-file
migration selection contributes 2,876 checks. All nine `0.21.18` archives resolve
through isolated Hex.SCM builds; the implementation is the current candidate,
while `fixture_version=0.7.2` remains a historical fixture label. The source-bound
test manifest SHA256 is
`1182291a112f1b7e4dba1984bf3efbd7d32c70f8c0200b5ee2c9eb2301741700`.
The final manual candidate report was downloaded and independently checked
against frozen Git blobs, rather than the prepared, uncommitted P5 tests.

All 19 shared H2 gates pass, including h2c and verified ExSSL package traffic.
The retained report's 19 log hashes and nine archive hashes match. Its H2-only
source runner skips three real-QUIC opt-ins; those run in the separate all-nine
integration gate. Historical published `ex_ssl 0.7.2` compatibility also passes
as a separate job and does not substitute for the current candidate.

Evidence, raw job logs, source partition and candidate/H2 audits are retained at
`/private/tmp/http-fetch-p4-nested-candidate-root-20261028T0215Z/linux-current`.
Earlier failed invocations and older source boundaries remain below. P5 has only
prepared expected-red promotion checks at this acceptance point; P6 removal and
P7 publication remain unexecuted.

## ExSSL nested HTTPS proxy source acceptance — 2026-10-28

Ordinary HTTPS origins through HTTPS proxies now use two independently prepared
ExSSL policies and one lifecycle pair reserved before proxy TCP allocation. The
outer session forces HTTP/1.1 for CONNECT; origin ALPN, trust and identity remain
independent. CONNECT writes, TLS attachments and ownership admission consume the
original deadline. Raw TCP leaves the HTTP ledger only after acknowledged outer
provider adoption; the final socket binds after the inner handshake succeeds.

The new integration suite passes 23 cases. Independent OpenSSL peers cover all
four TLS1.2/TLS1.3 combinations for H1 pooled ownership and H2 reuse after stream
cancellation. Each records one connection, exact TLS/ALPN, no replay and confirmed
retirement of both layers. OTP TLS1.3 peers cover credential separation, identity
negatives, CONNECT refusal, streaming and phase-specific cancellation/deadlines.
The existing OTP TLS1.2-without-EMS rejection remains intentional; those peers
cannot serve as positive references for ExSSL's required EMS profile. An initial
H1 fixture failure came from requiring ALPN without advertising it; the fixture
now explicitly offers HTTP/1.1 and retains exact peer ALPN assertions.

The affected Core, Runtime and Fetch selection passes 42, 29 and 117 cases,
respectively. Strict umbrella compilation, root formatting and diff checks pass.
The default-tier control executes six allocation-free lifecycle unit cases and
excludes all 23 new socket/process integration cases.

The original OTP nested-route suite retains its assertions and deadlines except
the obsolete ExSSL-rejection case, which now rejects invalid origin policy before
proxy dialing. Its IP-alias-dependent positive cases still need Linux execution.
Current candidate packages, supported-platform integration and final source gates
remain pending. P5–P7 remain unopened; performance is outside this goal and
Credo/Dialyzer are user-deferred. Evidence is under
`/private/tmp/http-fetch-tls12-candidate-suite-root-20261027T2340Z` and
`/private/tmp/http-fetch-nested-tls-root-20261027T2345Z`.

## No-OTP peer identity-rejection evidence — 2026-10-27

The independent TCP peer now uses OpenSSL's public MemoryBIO API and retains the
version from the actual outbound ServerHello before a certificate alert can clear
`SSLObject.version()`. ALPN still comes from OpenSSL's public selection API. A
bounded parser handles fragmented records/handshakes, rejects malformed or
duplicate extensions and cross-checks any completed API version. Requested TLS
policy never supplies missing observation evidence. Existing scenario, identity,
request-count and cleanup validators are unchanged.

The original failure reproduced for TLS1.2 and TLS1.3: Python clients rejected a
wrong hostname with verification code 62, but the peer failed because its version
was absent. Both negatives and their success controls now pass. Two independent
Python/OpenSSL configurations, 3.15/4.1.0 and 3.12.15/3.5.9, each pass 24 owned
loopback scenarios: TLS1.2/1.3 success and identity rejection for H1, H2, WSS, SSE
and the managed H1/H2 peer routes. Every peer records one connection, zero live
connections, and exactly zero or one HTTP requests as appropriate. Owned peer
processes and output-reader threads are joined after observation.

All 128 release-automation checks, 21 CI-automation checks, strict umbrella
compilation and root formatting pass. The 36 pure peer tests cover fragmentation,
missing/conflicting evidence, BIO I/O, short writes, EOF and finite deadlines.
These are peer-tool checks with independent Python clients; they do not establish
HTTP client migration or an actual no-OTP production release. H3 and the remaining
timeout/cancellation/shutdown release cells were not rerun for this change.
Evidence is under `/private/tmp/http-fetch-no-otp-peer-identity-diagnosis-root-20261027T2155Z`,
`/private/tmp/http-fetch-no-otp-peer-tcp-matrix-root-20261027T2212Z` and
`/private/tmp/http-fetch-no-otp-peer-tcp-matrix-python312-root-20261027T2218Z`.

## Required no-OTP release workflow — 2026-10-27

The coordinated release workflow now invokes the existing isolated production
release gate before creating a tag or publishing any package, then repeats it
against cold published Hex dependencies before completing GitHub release assets.
Each phase runs separate TLS1.2 and TLS1.3 plans; H3 retains TLS1.3 in both plans.
Every invocation retains the full 35-scenario matrix, source/archive identity,
release closure/import/runtime isolation, independent traffic and cleanup checks.
Peer environments use the existing pinned HTTP/2/WebSocket requirements plus
`aioquic==1.2.0`, with the already verified localhost certificate/CA fixtures.

Release automation passes 123 checks and CI automation passes 21. The workflow
parses as YAML; all three new command blocks pass shell syntax checks. Four
executed shell controls use an inert gate executable: exit 37 stops each phase
after its first TLS plan, while exit 0 reaches both plans. Candidate and published
output directories remain distinct. Failure diagnostics upload only named reports,
command logs and peer observations, excluding release directories and keys.

This accepts workflow integration only. No real candidate or published no-OTP
production release was executed: default promotion, production dependency cleanup
and the remaining compatibility decisions still block that acceptance. The existing
functional validators and their assertions were not changed. Evidence is retained
under `/private/tmp/http-fetch-no-otp-release-wiring-root-20261027T2150Z`.

## Current candidate and provider acceptance — 2026-10-27

At source `a38261ce9a540b700ffc99d36cfdab1e77a2301e`, the current selected package
matrix passes on all supported runtime configurations. Each resolves the same
coordinated nine `0.21.18` archives through Hex.SCM and checks isolated production
module paths. Historical feature-fixture labels remain `0.7.2`; the executed
implementation is the current candidate, with the 40 migration fixtures bound to
the current source commit.

| Runtime | Workflow | Candidate groups | Executed checks |
| --- | --- | ---: | ---: |
| Elixir 1.18 / OTP 28 | [CI](https://github.com/gsmlg-dev/http_fetch/actions/runs/40584575647) | 49 | 2,809 |
| Elixir 1.19 / OTP 28 | [Compatibility](https://github.com/gsmlg-dev/http_fetch/actions/runs/40584597757) | 49 | 2,809 |
| Elixir 1.20 / OTP 29 | [Compatibility](https://github.com/gsmlg-dev/http_fetch/actions/runs/40584597757) | 49 | 2,809 |

Each report's group set matches all nine historical feature suites plus the 40
current migration files. The latter contribute 2,741 checks: policy 2,039,
identity 73, TLS 82, provider 235, Fetch 209, streams 93 and routes 10. Every file
executes a positive number of tests, with zero skips or exclusions. All three
fixture manifests match
`7ef81478023c4fdc05ebbc8b6f67ebd0d2a6a5d70e71d5e037eeed71f80b3802`.
This includes the newly retained 35 native Socket TLS cases and 15 prepared
CONNECT-policy cases, with their original assertions and deadlines.

The shared H2 report passes all 19 gates against independent Node and hyper-h2
peers. All 19 log hashes and nine candidate-archive hashes match the retained
artifact. Package traffic completes both h2c and verified ExSSL H2, each with
four isolated consumers, four connections and actual mixed-client sharing.
Three real-QUIC opt-ins are skipped in this H2-only source runner; they are
executed by the separate all-nine integration job with `HTTP_QUIC_PHASE1_REAL=1`.
The H2 source runner itself is not skip-free. Long soaks remain excluded under
the user's performance-scope decision.

This evidence closes P2's provider lifecycle and duplex exit, including public
preallocation/failure/cancellation/transfer evidence, original-resource cleanup,
stale or lost ACKs, blocked Writer control output and native policy file operations.
It also accepts the P3 direct/pinned H1/H2 and managed-completion requirements,
including immutable policy, generation capacity, sibling isolation and retirement.
Ordinary HTTP CONNECT and forwarding through HTTP/HTTPS proxies retain their
executed coverage. The newly merged HTTPS-over-HTTPS route remains unresolved.

CRL/OCSP/partial-chain and encrypted/multiple-identity P1 acceptance now includes
source and all three candidate runtimes, under the documented finite limits and
managed exclusions. TLS1.3 manual tickets/`use_ticket` now have the local source
coverage recorded below; TLS1.2 session reuse remains unsupported. No full
P1/P3/P4 exit or default-promotion claim follows.
Manual CI explicitly defers Credo/Dialyzer; all nine compile, format and package
jobs pass their remaining steps. The latest automatic push run was cancelled
when manual CI started; final automatic CI remains required after compatibility
work stabilizes. Production OTP removal, actual no-OTP release traffic, major
publication and cold published-consumer acceptance remain unexecuted.

Only documentation changed during this review. The all-nine source gate above
and the candidate reports use identical production/test sources; no test rerun
was needed. Metadata, reports, exact group-set checks, manifest comparisons and
H2 hash verification are retained in
`/private/tmp/http-fetch-p4-acceptance-continuation-root-20261027T211429Z/INTEGRATED-P4-EVIDENCE.json`.

## Current source test tiers — 2026-10-27

Source `a38261ce9a540b700ffc99d36cfdab1e77a2301e` passes manual all-nine
[unit](https://github.com/gsmlg-dev/http_fetch/actions/runs/40584581485),
[integration](https://github.com/gsmlg-dev/http_fetch/actions/runs/40584586869)
and [E2E](https://github.com/gsmlg-dev/http_fetch/actions/runs/40584592063)
workflows on Elixir 1.18 / OTP 28. Each source selection compiles its app's runtime
closure with warnings as errors. Default `mix test` excludes integration/E2E;
the integration workflow uses `--only integration` and enables the real QUIC
opt-ins. Counts below include properties and doctests, subtract excluded cases,
and come from the final per-app ExUnit summaries.

| App | Executed unit cases | Executed integration cases |
| --- | ---: | ---: |
| ex_ssl | 661 | 2,789 |
| elixir_quic | 244 | 68 |
| elixir_quic_http3 | 117 | 14 |
| http_core | 382 | 123 |
| http_runtime | 187 | 101 |
| http_fetch | 321 | 1,227 |
| http_event_source | 39 | 115 |
| http_web_socket | 58 | 167 |
| http_web_transport | 24 | 0 |
| Total | 2,033 | 4,604 |

Both selections have zero failures and partition the same 6,637 discovered source
cases. WebTransport has no integration-tagged source cases; its zero selection
does not establish integration coverage. E2E executes 52 ExUnit cases across Fetch,
EventSource, WebSocket, WebTransport and the ExSSL Caddy check. QUIC client/server,
stream impairment, DATAGRAM and HTTP/3 local UDP checks run as separate successful
steps. Core and Runtime report no standalone ExUnit E2E suite; client and shared
H2 gates own their end-to-end coverage. These results close the source-tier
execution requirement, while current candidate compatibility, unresolved option/
proxy decisions, default promotion, OTP removal and publication remain separate.

No source or assertion changed during this acceptance review. Earlier failing
invocations remain historical evidence. Run metadata, raw logs and parsed counts
are retained in `/private/tmp/http-fetch-p4-acceptance-continuation-root-20261027T211429Z`.

## Published TLS consumer gate preparation — 2026-10-27

The coordinated consumer runner now supports published Hex packages for package,
external-client, runtime, H2 and TLS-feature checks. New TLS modes require all nine
release archives; every published archive must match before any consumer starts.
Published resolution uses fresh private Hex configuration/cache paths and removes
inherited mirrors, offline settings and unsafe registry/HTTPS settings. Candidate
resolution and the existing published HTTP3 checks retain their gates.

The release workflow now repeats package, external-client and TLS-feature consumers
after publication and before completing the GitHub release. TLS checks include the
existing 38-file migration matrix; their logs distinguish published resolution from
the current source fixtures. Local validation passes 113 release-automation tests,
21 CI-automation tests, strict compilation, umbrella formatting and YAML parsing.
These are orchestration checks. The actual published migration matrix, default
promotion and production release without OTP SSL remain unexecuted. Evidence is
in `/private/tmp/http-fetch-published-migration-root-20261027T2005Z`.

The production-release verifier also accepts `--published`. After source/stage/
archive identity checks, it runs the existing nine-package Hex preflight through
its bounded command runner. Missing, mismatched, incomplete or failed preflight
results stop before release construction or peer startup. Published builds use
fresh Hex configuration/cache paths with offline mode disabled and create no
candidate registry. Reports identify the dependency source. Candidate mode and
the full artifact/runtime audit, 35 required scenarios and peer teardown remain
required. All 118 release-automation tests, strict compilation, umbrella formatting
and diff checks pass locally; the five new checks mock build, network and peers.
Neither candidate nor published production traffic was executed in this preparation
step. That acceptance still depends on P5/P6. Evidence is in
`/private/tmp/http-fetch-published-no-otp-root-20261027T2010Z`.

## Integrated source and candidate matrix — 2026-10-27 UTC

At `5011eeb87624403fa5122d20aabe87b99087f0b6`, all nine app jobs pass
[unit](https://github.com/gsmlg-dev/http_fetch/actions/runs/40570202181),
[integration](https://github.com/gsmlg-dev/http_fetch/actions/runs/40570208015)
and [E2E](https://github.com/gsmlg-dev/http_fetch/actions/runs/40570213833)
workflows on Elixir 1.18 / OTP 28. The earlier Fetch native-timeout ordering
failure remains historical; passing focused and integrated runs do not establish
its cause or prove a production fix.

The current candidate passes 47 feature groups with 2,759 checks on Elixir
1.18 / OTP 28 in [CI](https://github.com/gsmlg-dev/http_fetch/actions/runs/40570196458)
and on both Elixir 1.19 / OTP 28 and Elixir 1.20 / OTP 29 in
[compatibility CI](https://github.com/gsmlg-dev/http_fetch/actions/runs/40570218841).
These reports include all 38 selected migration source files, with 2,691 checks,
zero skipped or excluded cases and the matching source manifest
`be2c6cb550f934c5ace8fae364c4fad87ca9141af834045d9dcefacbf5bd64fa`.
The same CI run's 19 H2 gates pass against independent hyper-h2 and Node peers;
isolated nine-package consumers complete both h2c and verified ExSSL H2 traffic.
All 19 retained log hashes and nine archive hashes match the report.

The CI run above fails only in the nine Credo jobs; candidate and H2 jobs pass.
Those failures are retained separately from the explicitly deferred checks.
P4 exit remains open until the remaining HTTPS-over-HTTPS proxy and explicit
resumption-option compatibility decisions are resolved and required integrated
gates pass. OTP is still the default. Default promotion, the actual production
release without OTP SSL, major publication and cold published consumers have
not been accepted. Evidence is retained in
`/private/tmp/http-fetch-static-deferral-root-20261027T1950Z/INTEGRATED-P4-EVIDENCE.json`.

## Explicit static-analysis deferral — 2026-10-27

The user authorized deferring Credo and Dialyzer during this migration. Manual
CI and Release now accept `defer_static_analysis: true` to omit only those two
checks and record each as `DEFERRED` in the job summary. The input defaults to
false; automatic CI continues to require both checks. Formatting, strict
compilation, source tests, independent peers, candidate consumers, package
identity and publication checks retain their existing requirements. A deferred
check is not passing evidence. The final migration release will explicitly
record any use of this accepted exception.

## Stream-client proxy endpoint rejection — 2026-10-27

EventSource and WebSocket previously ignored a supplied `proxy` endpoint and could
connect directly to the origin. Shared stream-client option validation now returns
`{:error, :proxy_not_supported}` before either client starts. Keyword and string
map forms have the same boundary. Omitted/nil proxy endpoints, WebSocket frame
forwarding and H3's existing `proxy_not_supported_for_quic` error remain intact.

New pure scenarios reproduced three failures before the implementation change.
The three option suites, two no-origin-contact integration cases, existing WS
frame-proxy suite and secure Unix regressions pass 55 checks on local Elixir
1.18.5 / OTP 29.0.2. Commands and failures are retained in
`/private/tmp/http-fetch-stream-proxy-root-20261027T1935Z`. Current Linux and
candidate-package acceptance remains separate from these focused local results.

## Secure Unix route correction — 2026-10-27

The shared runtime now rejects HTTPS/WSS with `unix_socket` using
`{:error, :tls_over_unix_socket_not_supported}` before local-socket I/O. Existing
SSE/WS option validation and SSE redirect validation use that boundary; Fetch
checks it at every dial, including redirect destinations. Plain HTTP, SSE and WS
over Unix remain supported. No TLS-over-Unix capability is added.

New pure option scenarios reproduced three failures before the production change.
On local Elixir 1.18.5 / OTP 29.0.2, the corrected option suites and three real Unix
integration suites pass 40 checks; existing Unix Fetch and runtime Dialer suites
pass another 35. Independent listener queues remain empty after direct secure
attempts and Fetch/SSE secure redirects; plain HTTP responses, SSE events and WS
frames still arrive. Strict compilation and umbrella formatting pass. These are
local results; Linux source/candidate CI after this change remains required.
Commands and original failures are retained in
`/private/tmp/http-fetch-secure-unix-root-20261027T1930Z`.

## Linux OTP 29 returned file-error qualification — 2026-10-27

The OTP 29.1.2 candidate run
[40555761698](https://github.com/gsmlg-dev/http_fetch/actions/runs/40555761698)
failed 88 of 1,252 CRL checks. Hash-directory enumeration reaches a missing
`.rN` sentinel; the file executor previously rejected its returned ENOENT on
Linux OTP 29. The same selection passed on Linux OTP 28.

The official OTP-29.1.2 `file`, `raw_file_io`, `prim_file`, `prim_file_nif.c`
and `unix_prim_file.c` sources are byte-identical to the reviewed OTP-29.0.2
sources. In `efile_open`, failed `open` returns its errno with no allocated
file resource; the synchronous wrapper returns that error before any handle
creation. This qualifies normal returned ENOENT on Linux OTP 29 / ERTS 17.1.1.
Other runtimes and non-ENOENT errors retain their existing conservative handling;
actor death during native work still cannot establish completion. This source
comparison does not establish native binary equivalence. Exact source pins and
local validation are retained in
`/private/tmp/http-fetch-otp2912-enoent-root-20261027T1818Z`.
Local Elixir 1.18.5 / OTP 29.0.2 passes all 1,294 focused policy-file, CRL-cache
and CRL integration checks, strict compilation and umbrella formatting. All 1,296
logged independent peers were joined and the command process groups are absent.
The repaired Linux candidate matrix remains a required separate check.

## Historical accepted boundary — 2026-10-24

The public provider lifecycle and duplex source slices are accepted locally. The
original full ExSSL command, with integration, seed101, max_cases24 and unchanged
deadlines, now passes1157 checks (20 properties,1137 tests), with zero failures,
skips or exclusions. Its standalone setup suite passes6. All observed command
roots are reaped; independent checks find221 observed PIDs and153 process groups
absent. Source/Git preservation and evidence are in
`/tmp/http-fetch-r52-astra-bootstrap/HANDOFF.md`. The earlier accept timeout remains
a historical failure with an unproven cause; this run does not establish causality.

The middlebox interoperability matrix passes26 cases/64 authenticated cleanup
exchanges through independent peers, including mixed version order, HRR and mTLS.
ExSSL TLS12 requires actual EMS in both hellos; the OTP29 comparator explicitly
records its absence instead of weakening ExSSL policy. Fetch verify_fun's four
TLS12/TLS13 accept/reject paths also pass. Evidence is in
`/tmp/http-fetch-r51-sol7/HANDOFF.md`; original failed runs remain historical.

P3 HTTP completion/pooling integration is next. Required advanced P1 policies,
remaining option controls, package/platform/CI/performance, default promotion,
production OTP SSL removal and coordinated publication remain open. The sections
below retain the scope and results of their original checkpoints.

## Execution identity and limits

Date: 2026-10-21 (Asia/Shanghai). Source: `main@6b69bde3f43f2270317c38fbe68d5ac9635d3b36`,
all nine packages `0.21.14`, initially clean worktree. The first P0 checkpoint
(`d7442ef`) added documentation and a bounded source inventory. Subsequent local
changes remove compiler warnings and add diagnostic peers/benchmarks; TLS defaults
and provider behavior remain unchanged. An unsuccessful shutdown experiment was
reverted, as recorded below.
Runtime: Elixir 1.20.1 / OTP 29 / ERTS 17.0.2, macOS Intel. OpenSSL 3.6.5.
This does not establish the configured Elixir 1.18/OTP28 or 1.19/OTP28 results.

Use the umbrella root for all Mix commands. Existing local `_build` metadata reports
`http_core` and `elixir_quic_http3` as `0.14.0` despite current manifests `0.21.14`.
The original `MIX_ENV=test unbuffer mix deps.get` failed dependency convergence.
Changing only the build directory made dependency preparation pass without changing
manifests or lockfile. Preserve the original cache; use the isolated path below.

```bash
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build unbuffer mix deps.get
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build unbuffer mix compile --warnings-as-errors
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build unbuffer mix test --seed 36
```

## Baseline results

| Check | Executed result | Scope / next action |
| --- | --- | --- |
| HEAD, worktree, versions | Baseline confirmed; initially clean | New P0 changes uncommitted |
| Isolated dependency preparation | Exit 0, locked versions unchanged | Stale default build cache avoided |
| Strict test compilation | Initial exit 1; after two narrow repairs exit 0 | Inline the identity-only socket_resource callers after wrapper-specific clauses; pin the outer bitstring size. No provider behavior/default change |
| Default umbrella test suite, seed 36 | Stopped with SIGTERM after failures were captured | Missing h2 prerequisite caused repeated startup failures; no final aggregate success claimed. Loopback and ExSSL upload cleanup failures also observed |
| Focused H2 trailers + HTTPS early upload, pinned peer environment | Exit 2: 55/61 passed, 6 failed | All six failures belong to ExSSL early upload timeout/cleanup cases; H2 trailer startup failures disappear with the pinned Python dependencies |
| Nine candidate archives + metadata | Passed | Built from unchanged production source, all nine identities/internal exact requirements validated |
| Isolated external candidate consumer | Passed, `external consumer smoke passed` | Existing fixture includes OTP SSL; not production removal evidence |
| Direct candidate feature invocation | Failed before test execution: EX_SSL_FIXTURE_DIR missing | Invocation did not prepare fixtures; use the existing wrapper below |
| Candidate feature wrapper | Initial exit 127 resolved; rerun exit 0, 68 tests passed in nine groups | coreutils gnubin + pinned venv; Hex.SCM source archives, not published or OTP-free proof |
| Source inventory | Exit 0 | 35 production files matched; category counts: 15 OTP calls/types, 20 private socket matches, 90 backend selections, 7 dynamic-dispatch candidates, 9 application declaration lines; overlapping categories and comments/types are included |
| Existing engine benchmark | Exit 0, 24 exchanges | Preliminary TLS-only evidence below, not HTTP/managed performance acceptance |
| `git diff --check` | Passed for changes so far | Repeat before stage commit |

The default test invocation excludes `:integration` by repository configuration.
Completed portions observed: ex_ssl 469 passed (20 properties + 449 tests), 194
excluded; elixir_quic 249 passed; http_core 381 passed, 3 skipped;
elixir_quic_http3 113 passed; http_runtime 149 passed. These partial results are
not a full successful gate. Mandatory independent coverage still needs explicit execution.

Observed source-suite failures include `:eaddrnotavail` for second loopback bindings,
pinned-address/refusal timeouts, write-idle/trailer and H2 scripted peer timing,
and Python H2 peer startup failure (`ModuleNotFoundError: h2`). Distinguish actual
platform assumptions from product failures with focused reproduction. At that first
checkpoint no production fix, assertion change or skip was applied. The pinned HTTP2
peer requirements were
successfully installed in `/tmp/http-fetch-tls-migration-p0-venv` (h2 4.2.0,
hpack 4.1.0, hyperframe 6.1.0, wsproto 1.2.0, h11 0.16.0). This changes test
prerequisites, not runtime package dependencies.

Focused reproduction after supplying those prerequisites:

```bash
PATH=/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix test apps/http_fetch/test/http/http2_request_trailers_test.exs \
  apps/http_fetch/test/http/https_early_upload_test.exs --seed 36
```

Result: 55/61 passed, six failures, exit 2. Four failures time out waiting two
seconds for ExSSL `send_timeout` cases (HTTP auto/H1, 4000/infinity). Two peer
assertions report `HTTPS socket remained open after confirmed request cleanup`
(ExSSL auto buffered infinity and H1 streamed infinity). These reproduce without
the missing H2 dependency and need lifecycle/writer diagnosis; do not dismiss them
as missing prerequisites or claim their root cause is already proven.

`brew install coreutils` completed successfully (9.12_1). With its gnubin path
and the pinned peer venv available, the unchanged candidate feature wrapper exited 0.
The report at `/tmp/http-fetch-tls-migration-p0-feature-results/ex_ssl_feature_gate-candidate.txt`
records Hex.SCM, runtime `hex-candidate/0.21.14`, fixture 0.7.2 at
`fb47051355c9d0a29caee046fa060a745ad0ce5b`, seed 36, all nine discovered groups,
and 68 passed tests (12/5/2/11/9/6/8/8/7 respectively), with no skips or zero-test
groups. These archives still contain the original production baseline, not subsequent
local repairs, and the fixture includes OTP SSL. This is candidate feature evidence,
not published package or OTP-free production release evidence.

## Follow-up timeout diagnosis and compiler repairs

A bounded non-secret probe captured explicit send_timeout=600 and changing logical
write tokens with fresh original deadlines every approximately 200–500 ms. The
previous 20 ms stable output token did not prove a single logical write remained
blocked for 600 ms. Forwarding was intact; no timeout-forwarding production change
was made. The temporary probe and logging were removed.

For native send-timeout cases only, the upload matrix now uses an independent
Python/OpenSSL peer with no background reads after request headers. Listener and
accepted sockets both receive the small receive-buffer policy. A 150 ms per-send
deadline fits the observed blocked interval rather than allowing each progressing
64 KiB logical send to complete under the old 600 ms deadline. Existing two-second
Promise wait, error classification, one-second request/source/writer cleanup bound,
and peer EOF/reset assertions remain. `tls_outcome` permits focused execution; the
external peer must report actual closure and exit successfully before acknowledgment.
All eight backend × H1/auto × finite/infinite send-timeout cases passed after the
shutdown experiment was reverted, including final peer-exit acknowledgment.

The earlier combined follow-up run passed all 469 ExSSL base checks (194 integration
checks excluded), and 78/81 selected Fetch checks. Three ExSSL peer-open failures
remained: H1 buffered/4000, auto cancel/4000, H1 streamed/infinity. Adding
write_abandoned? to zero-linger selection did not eliminate them and was reverted;
this is not a proven root cause or shipped fix. Next probes must distinguish provider
connection/writer termination, raw port disappearance, and remote TLS receiver state.

Strict compilation now exits 0 after removing the unreachable socket helper branch
without changing either identity path and pinning the external binary size in
HTTP1.IdleTimeout. A separate final run of completion, pooled completion and H2
trailers passed all 54 checks with the pinned peer PATH (see command). Existing H2 test-source
bitstring pin warning remains; it is distinct from production strict compilation.

```bash
PATH=/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix test apps/http_fetch/test/http/request_completion_test.exs \
  apps/http_fetch/test/http/pooled_request_completion_test.exs \
  apps/http_fetch/test/http/http2_request_trailers_test.exs --seed 36
PATH=/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix test apps/http_fetch/test/http/https_early_upload_test.exs \
  --only tls_outcome:send_timeout --seed 36
```

## Reproducible candidate commands

Baseline archives are retained locally at
`/tmp/http-fetch-tls-migration-p0-candidate-20261021/archives` for follow-up gates.
They precede P0 documentation edits. Never publish these baseline archives as new work.

```bash
python3 scripts/release/stage.py build 0.21.14 \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/stage \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/archives
elixir scripts/release/archives.exs 0.21.14 \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/archives
python3 scripts/release/consumer_gate.py 0.21.14 \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/archives --mode external
PATH=/usr/local/opt/coreutils/libexec/gnubin:/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  PYTHONDONTWRITEBYTECODE=1 EX_SSL_DEP_MODE=candidate \
  EX_SSL_CANDIDATE_ARCHIVE_DIR=/tmp/http-fetch-tls-migration-p0-candidate-20261021/archives \
  EX_SSL_RESULTS_DIR=/tmp/http-fetch-tls-migration-p0-feature-results \
  EX_SSL_TEST_SEED=36 bash scripts/ex_ssl_source_smoke.sh
```

Stage/build commands must use a fresh stage destination when retaining old evidence.
The wrapper prepares pinned historical fixture builders; actual TLS runtime in
candidate mode must resolve this umbrella's nine archives through Hex.SCM. Fixture
provenance and runtime source are distinct. Candidate feature acceptance requires
all discovered groups, no failures/skips/zero tests, and independent peer results.

## Preliminary comparative TLS measurement

Executed from root:

```bash
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix run apps/ex_ssl/scripts/resumption_benchmark.exs
```

Independent OpenSSL peer, TLS_AES_128_GCM_SHA256, TLS1.3-only, ALPN http/1.1,
1 MiB echo payload, one warmup + five measured exchanges per backend/mode.
Peer-observed resumption is false for all full exchanges; resumed modes report
false for warmup then true for all five measured exchanges.

| Backend / mode | Handshake median µs (range) | Combined transfer median µs (range) |
| --- | --- | --- |
| OTP / full | 4,355 (3,874–6,338) | 8,321 (6,687–15,644) |
| OTP / resumed | 3,005 (2,524–3,902) | 7,547 (5,964–10,098) |
| ExSSL / full | 5,565 (4,555–12,977) | 14,029 (13,200–19,944) |
| ExSSL / resumed | 3,977 (3,419–22,319) | 13,722 (11,306–17,519) |

Other baseline jobs were active, sample count is small, and transfers combine upload
and download. These values are diagnostic only: no tail latency, resource/cleanup
budget, independent throughput budget or production readiness claim follows.
Run isolated comparable HTTP workloads and set promotion budgets before P5.

## HTTP baseline measurements

The public-API benchmark and independent control peer are
`scripts/tls_migration_benchmark.exs` and `scripts/tls_migration_benchmark_peer.py`.
Full samples, 213 runtime-source/manifest hashes, tracked-patch digest, script/cert
hashes, runtime settings, peer exchanges and resource observations are retained in
[tls-migration-p0-http-baseline.json](tls-migration-p0-http-baseline.json).
The raw stdout SHA256 is included; only redundant intermediate handshake histories
were replaced with counts, with the full final history retained.

```bash
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix run --no-compile scripts/tls_migration_benchmark.exs
```

Actual run exited 0, with no concurrent project tests. Source `d7442ef` plus the
recorded local compiler repairs and scripts. Python 3.15.0 / Python-linked OpenSSL
4.0.3 (the earlier standalone benchmark used OpenSSL CLI 3.6.5). Both providers
negotiated verified TLS1.3, AES256-GCM, ALPN http/1.1, disabled peer tickets, no
resumption; client nodelay enabled. Each workload used three warmups and 30 measured
samples, concurrency one, OTP then ExSSL. Cold requests used distinct connections;
upload/download/reuse each proved the same connection ID through an explicit final
close response. All payloads and lengths were checked. Peer totals: 270 requests,
72 accepted/closed connections, zero active connections, zero peer errors,
69,206,016 uploaded bytes including warmups.

| Backend / workload | Request p50 / p95 / p99 (µs) | Measured goodput (MiB/s) |
| --- | --- | --- |
| OTP / cold small | 12,768 / 21,867 / 22,147 | — |
| ExSSL / cold small | 12,027 / 22,171 / 25,751 | — |
| OTP / 1 MiB upload | 13,048 / 25,758 / 29,224 | 60.77 |
| ExSSL / 1 MiB upload | 22,558 / 54,714 / 63,151 | 39.93 |
| OTP / 1 MiB download | 12,026 / 25,977 / 30,061 | 66.49 |
| ExSSL / 1 MiB download | 15,311 / 44,483 / 83,746 | 41.81 |
| OTP / paced reused small | 16,141 / 23,253 / 25,461 | — |
| ExSSL / paced reused small | 5,296 / 20,133 / 20,855 | — |

Cold server handshake p50/p95/p99 µs: OTP 8,969/18,266/18,486; ExSSL
7,320/10,969/21,181. This measures the peer's wrap_socket duration including client
scheduling, not isolated client handshake latency. Cold request timing includes
connect/TLS/HTTP/body verification. Goodput is sequential application transfer,
including response/body checks; it is not raw TLS bandwidth.

At post-workload observations approximately 304–387 ms after final close, both
providers had 165 VM processes, four ports including the still-live external peer,
and zero peer connections. During reused workloads OTP had 168 processes/five ports,
ExSSL 167/five. Download live binary allocations were approximately 5.10 MB OTP and
9.40 MB ExSSL, returning to approximately 3.72 MB and 3.65 MB respectively in these
observations. These are noisy global BEAM allocations, not RSS or provider cleanup
receipts; no forced global GC or plateau/leak proof is claimed.

Every OTP request's public completion returned :ok; every ExSSL request returned
`{:error, {:unsupported_completion, :tls_backend}}`. OTP measured completion wait
p50/p95/p99 µs: cold 29/49/99, upload 27/73/94, download 30/72/88, reuse 28/45/53.
The ExSSL unsupported-return duration is recorded but does not establish cleanup.
The paced reuse interval was one second, not a production long-duration soak.

Thirty observations make the reported nearest-rank p99 equal to the maximum; these
are reproducible diagnostic baselines, not stable tail acceptance. Other supported
runtimes, TLS1.2, resumption, H2/H3, concurrent loads, managed completion, long soaks
and performance acceptance remain pending. See the later v1 engineering targets;
do not infer acceptance from these ExSSL results or present the run as P5 evidence.

## Formatting and static-analysis checkpoint

Root `mix format --check-formatted` exited 0. Root `mix credo` then exited 1 while
checking 513 files: pinned Credo 1.7.13 crashes in Credo.Code.Token.position/1 on
Elixir 1.20 sigil tokens. The installed matcher for seven-element sigil tuples
requires `{line, column, nil}` metadata; actual tokens contain an ending-position
tuple instead. Failures occur in unchanged HTTP3/options/response/setup-test files,
not a lint finding in the migration edits. No dependency code was patched and no
check was disabled. Compatible supported-toolchain execution or a verified upstream
tooling update remains required; this is not a successful Credo gate.

## Expanded source, tooling and route checkpoint

Credo was upgraded alone in the lockfile from 1.7.13 to 1.7.19; existing manifest
ranges already permit it and no transitive dependency changed. The tagged upstream
[changelog](https://github.com/rrrene/credo/blob/v1.7.19/CHANGELOG.md) records final
Elixir 1.20 compatibility. Complete analysis exposed 20 existing depth-4 nesting
findings. Small helper extractions/ordered rejection checks preserve original error,
transcript/record, stream accounting and ownership-effect order. No check, threshold,
protocol policy or default was disabled/changed. Lead reviewed both disjoint worker
diffs. Final root formatting, warnings-as-errors compilation, Credo (513 files,
54 checks, no issues), and git diff --check all exit 0.

The first full post-extraction umbrella run completed, exit 2:

| App | Passed | Failed | Excluded / skipped |
| --- | ---: | ---: | --- |
| ex_ssl | 469 (including 20 properties) | 0 | 194 integration excluded by default |
| elixir_quic | 249 | 0 | 0 |
| http_core | 381 | 0 | 3 opt-in real QUIC adapter scenarios |
| elixir_quic_http3 | 113 | 0 | 0 |
| http_runtime | 149 | 0 | 0 |
| http_fetch | 1,193 (including 20 doctests) | 33 | 0 |
| http_web_socket | 138 | 0 | 0 |
| http_web_transport | 24 | 0 | 0 |
| http_event_source | 75 | 0 | 0 |

The three initially skipped real QUIC adapter scenarios were then explicitly run
with HTTP_QUIC_PHASE1_REAL=1: all three passed, exit 0 (35.2 seconds). This exercises
authenticated raw streams and negative readiness through the public adapter; it is
not independent H3 interoperability or a new capability claim. A test-only bitstring
pin warning remains visible.

Fetch failures were retained and classified: 13 depended on unavailable 127.0.0.2
binding/refusal semantics on this macOS host; 13 intentionally hit the private
buffer-probe source-hash guard after Connection source changed; six failed remote
upload closure observation; one failed cleanup while observing an earlier timed-out
request Task still present in the shared supervisor. Noninteractive sudo permission
is unavailable, so no loopback alias was installed. These platform cases are not
successful acceptance and still require a prepared host/CI run.

The Connection extraction was reviewed against unchanged closed/size/active fields,
application-data buffering, peer-close and drain transitions. The hash guard remains
enabled and now pins reviewed SHA256
7c891a11c6ea595fcaff9d99767b4d1294a7ec0e876675422c86eff93e6342ae.
All 45 SocketClient H2 plus failed-open cleanup scenarios then passed in a fresh VM,
exit 0. Test-only bitstring pin warnings remain visible; they are distinct from
passing strict production compilation. This targeted result does not turn the
previous complete umbrella run into a green run.

With integration explicitly included, all 663 ex_ssl checks ran: 659 passed, four
failed, exit 2. Three reference-identity scenarios dial unavailable 127.0.0.2. The
remaining connection_backpressure scenario could not establish its expected
KeyUpdate queued-behind-output state. Keep this as an ex_ssl/P2 blocker; the result
proves neither correct occupied-writer control ordering nor a protocol regression
introduced by extraction. The same invocation ran all 24 WebTransport checks
successfully. Its module documentation now correctly describes the unsupported
default network backend. Independent TLS1.2 Python/OpenSSL 4.0.3 RSA/ECDSA AES-GCM
and mTLS exchanges executed in the integration suite; no blanket endpoint claim.

## Local teardown versus remote closure

The upload test now captures exact Connection/writer monitors and raw TCP identity
during the existing test-only stable-output probe. After request/source/upload
termination it requires matching Connection and writer DOWN plus absent raw port
before permitting peer drain. These local checks passed even in scenarios failing
remote closure. No HTTP production code gained private ExSSL inspection or public
cleanup claims.

Repeated seed-36 whole-upload runs yielded 41/44 and 43/44, including an OTP remote
closure failure. Bounded peer diagnostics showed no receiver/sender mailbox backlog,
no server send queue, and receive buffers around 420–485 KiB despite the intended
1 KiB listener setting. Setting accepted-socket recbuf explicitly did not stabilize
the result and was reverted. A temporary close probe observed selected zero linger
returning :ok with pending output, but its eight streamed scenarios did not reproduce
the failure; the probe was removed. No close-predicate change is retained or proved.

The independent no-background-reader peer now has a two-second absolute drain
budget inside the parent's three-second observation. Timeout emits a distinct
bounded drain_timeout event with byte count/receive-buffer size and exits nonzero;
it cannot count as closure. Final native send-timeout selection passed all eight
scenarios, exit 0, with 36 unrelated upload cases excluded. Remote closure remains a
release blocker even when local resources are gone; neither observation is a public
provider receipt and kernel/peer termination is outside a local receipt's proof.

## One-minute reuse observation and v1 acceptance targets

The extended bounded H1 runner preserves default one-second pacing but permits up
to 60 seconds, requiring request intervals at most two seconds. Both providers
completed a separate approximately 60-second fixed-connection reuse interval,
three warmup plus 30 measured requests, concurrency one. Full samples, source hashes,
settings and counters are in [reuse evidence](tls-migration-p0-http-reuse-baseline.json).
As in the original artifact, only repeated intermediate handshake arrays are replaced
by counts; final history and raw-stdout SHA256 remain.

| Observation | OTP | ExSSL |
| --- | --- | --- |
| Reuse duration | 60.272 s | 60.143 s |
| One connection ID across all 33 requests | 36 | 72 |
| Live processes / ports | 168 / 5 throughout | 167 / 5 throughout |
| Live binary allocation range | 3,719,104–3,757,232 bytes | 3,640,072–3,665,216 bytes |
| Reused request p50/p95/p99 | 2,332 / 23,409 / 41,633 µs | 2,145 / 10,870 / 22,993 µs |
| After all workloads, processes / ports | 165 / 4 | 165 / 4 |

Across all rerun workloads the peer verified 270 requests and 69,206,016 upload
bytes, accepted/closed all 72 connections, and reported zero active/errors. Every
OTP public completion returned :ok; every ExSSL completion remained unsupported.
These are BEAM allocation observations without forced GC, not RSS, local receipt
proof, stable tails or the required 30-minute load/soak gate. Numeric v1 promotion
budgets are now recorded in the design before provider implementation/promotion;
they are engineering targets, not acceptance inferred from 30 samples.

Source review completed the public route matrix in the design: origin/proxy TLS
identity, plaintext CONNECT versus unsupported TLS nesting, secure-scheme Unix
plaintext selection, SSE/WS forwarding-option gaps, backend pinning versus trust
snapshots, explicit QUIC/H3, unsupported WebTransport, and provider-dependent Fetch
client-identity redirects. Each remaining difference has an owner/acceptance target.
The reviewed lifecycle v1 API separates stable evidence, revocable control and
recipient-bound handoff; lost unreported allocation must be unconfirmed. None of
those APIs or topology guarantees is implemented by documenting the contract.

## Remaining implementation and release gates

- ex_ssl/P2 owns occupied-writer KeyUpdate, cancellation/teardown, allocation fences,
  durable public evidence and stale-owner authority; retain current failing cases.
- Core/runtime/clients own the version/option, CONNECT preflight, secure Unix,
  redirect/proxy identity and managed/completion boundaries in the design.
- Prepared-host full regression, independent H3/package acceptance, stable tails,
  30-minute load/soak, other supported runtimes, Dialyzer and remote CI remain gates.
- No P1–P7 acceptance, changed default, production OTP removal or publication is
  established. Historical validation remains scoped to its original execution.

## P1 contextual versions and P2 resource foundation (round 4)

The HTTP ExSSL adapter now offers TLS1.3 plus bounded TLS1.2 in one ordinary
handshake. Explicit versions remain exact; concrete WireProfile versions retain
order and GREASE handling. Auto tickets retain TLS1.3 when versions are absent.
An initial mixed-default patch exposed a real regression for explicit TLS1.3-only
ciphers: the unchanged cipher policy worked through OTP and through explicit
ExSSL TLS1.3 but failed when versions were omitted. The regression was retained,
then fixed by preserving the previous ExSSL TLS1.3 context for explicit cipher
policies absent versions/profile. No inference from cipher spellings or mutation
of caller policy was introduced. Broader OTP cipher-option parity remains open.

All 22 [version-policy scenarios](../apps/http_core/test/http/ex_ssl_version_policy_test.exs)
passed, including independent OTP TLS1.3 and Python/OpenSSL TLS1.2 byte exchanges,
direct/upgrade paths, profile/ticket conflicts before direct TCP accepts and an
explicit TLS1.3 rejection against the same EMS-capable OpenSSL TLS1.2-only peer.
The unchanged reverse-order mixed profile works against OpenSSL TLS1.2 and 1.3;
local OTP TLS1.3 rejected that hello with illegal_parameter. OTP28/29 TLS1.2 without
EMS is separately rejected, consistent with the existing bounded engine profile.
Neither peer distinction is fixed or hidden by rewriting profiles/weakening EMS.

The internal ResourceLedger is the first P2 slice, not a public lifecycle API.
Its ten tests cover fixed resource bounds, permit fences, exact ref/type/object
DOWN matching, idempotence, stale tokens, late enrollment, adoption scope and
bounded evidence without arbitrary reasons. Independent read-only review found
that deleting permits on creator death lost late identities. The correction keeps
bounded original tokens, requires late enrollment to stop, keeps proof pending
until exact resource DOWN, and retains irreversible loss. An unresolved lost permit
cannot settle; no matching allocator DOWN substitutes for unknown TCP identity.
Actual monitors, allocator/runtime topology, authority epochs, transfer, terminal
seal and observer exit remain unimplemented.

Final shared formatting, strict compilation and Credo passed (516 source files,
54 checks, 8,594 modules/functions at that invocation). The complete seed-101 root
run then executed all nine apps, exit 2:

| App | Result |
| --- | --- |
| ex_ssl | 479 passed including 20 properties; 194 integration excluded |
| elixir_quic | 249 passed |
| http_core | 402 passed; three real-QUIC opt-ins skipped |
| elixir_quic_http3 | 113 passed |
| http_runtime | 149 passed |
| http_fetch | 1,210/1,226 passed; 16 failed |
| http_web_socket | 138 passed |
| http_web_transport | 24 passed |
| http_event_source | 75 passed |

This full run contains the first 21 policy tests; the additional independent
explicit-version negative was then included in the separate 22-pass run. Fetch
failures were 13 unavailable-127.0.0.2 scenarios, one known remote-upload closure
observation, one raw-stream listener accept returning einval, and one OTP ordinary
reuse fixture unable to observe its expected in-flight send. All source-hash H2
buffer probes passed. A fresh targeted rerun of the two newly failing Fetch files
passed 57/58: stream mismatch passed, OTP reuse again could not establish the
blocked-writer precondition. Keep that reproducible fixture/result open for P2
investigation; this does not establish a production policy regression or green
umbrella acceptance. No assertion/deadline was relaxed to hide it.

The global backend is still OTP; managed and public ExSSL completion remain guarded.
No P1/P2 exit, P4 acceptance, default promotion or publication is claimed.

## P1 native TCP options and P2 authority core (round 5)

Added buffer/tos/tclass/priority to the engine and HTTP adapter allowlists. Real
OTP/raw inet references distinguish effective driver behavior from acceptance:
on this macOS/OTP29, buffer 0/65536/2^31 reads 1/65536/1; IPv4 tos and IPv6 tclass
apply; priority accepts but reads zero. Initial duplicate buffer defaults actually
overrode the caller's 65536 with 16640. Fixed raw dial to supply its default only
when absent, and removed the attach default so STARTTLS preserves existing TCP
buffer state. Explicit ExSSL mutable upgrade settings still apply; OTP instead
retains the old raw settings and requires subsequent setopts. Both paths are
covered, with the distinction documented rather than reported equivalent.

Native wrong-family live setopts returns einval here. The test compares the
actual platform reference, including platforms that permit a setting, and checks
virtual active mode remains unchanged on driver failure. Initial raw connect
exits badarg; a narrow exit clause now returns ExSSL {:error, :badarg}. OTP adds a
formatted detail tuple; ex_ssl does not synthesize that implementation text.
All 16 mandatory TCP tests executed, no skip. Worker root-scoped core/runtime
acceptance passed 406 and 149 tests respectively (three real-QUIC opt-ins were
still skipped in that particular invocation). Core tests include exact buffer
precedence at direct and upgrade boundaries.

Added internal Authority with single-use binding, exact attempt/epoch/capability
validation, cancel/accept serialization, named recipients, exact owner ack,
monitor generations, bounded latest-nonce recovery and idempotent committed replay.
A read-only review caught missing nonce correlation in live snapshots; corrected
and covered pending/accepted/cancelled/expired/replaced outcomes. Thirteen authority
and ten resource-ledger tests passed together. These remain pure models, not a
public API or proof that real monitors/socket ownership were established.

Reviewed Connection diff (only native attach buffer defaults) and renewed the
existing test-only H2 source guard to SHA256
`e3a397587a5b137236afed3210b775f30590a067f3963ffdf4a9410e8964aac2`.
Plaintext closed/size/active state and drain ordering are unchanged; native chunk
sizes can differ. All 43 targeted H2 tests passed without bypassing the guard.
The new core driver probe also pins that audited source and coordinated app
versions; its final transport file passed all 25 tests. Final Credo remained clean.

Strict compilation and Credo passed: 518 files, 54 checks, 8629 modules/functions,
zero issues. Added full umbrella Dialyzer: its first run found one contract_supertype
warning on ResourceLedger.proof's broad map return. Added explicit finite snapshot
and proof types (scope/admission/cleanup enums and 0..31 role masks), without runtime
behavior changes or ignore-list edits. All 23 lifecycle tests passed again and the
second Dialyzer run passed: zero errors/skips; four existing unnecessary-ignore
notices retained per repository instruction.

Full root `mix test --include integration --seed 101` with the pinned
Python environment and HTTP_QUIC_PHASE1_REAL=1 exited 2:

| App | Result |
| --- | --- |
| ex_ssl | 688/692 passed, including all 20 properties; four failed |
| elixir_quic | 249 passed |
| http_core | 409 passed; three real QUIC opt-ins executed, no skips |
| elixir_quic_http3 | 113 passed |
| http_runtime | 149 passed |
| http_fetch | 1208/1226 passed; 18 failed |
| http_web_socket | 138 passed |
| http_web_transport | 24 passed |
| http_event_source | 75 passed |

All 3075 checks executed, 3053 passed and 22 failed; no excluded integration or
skipped opt-ins in this run. The existing real QUIC tests are self-implementation
coverage and do not replace an independent H3 peer/package gate.

The four ExSSL failures remain three unavailable-127.0.0.2 identity scenarios and
the existing KeyUpdate/backpressure pending-input queue assertion. Fetch failures
were 13 unavailable-address cases, the OTP reuse blocked-writer precondition, and
four remote upload closure observations. Local matching Connection/writer DOWN
and Port absence checks passed before those remote failures. One was the Python
native-timeout peer's explicit drain_timeout (16384 bytes, receive buffer491904);
three were OTP peers still waiting after local cleanup. This is failed remote
observation, not a successful closure result. Assertions, two-second Python drain
budget and public deadlines were not relaxed. No newly observed assertion category
is attributed to the option patch without causal evidence; all remain acceptance
blockers. Raw-stream listener einval from round4 did not recur.

P1 verification/signature/advanced-policy decisions and P2 runtime observer,
allocation/use enforcement, immutable terminal seal, socket authority and duplex
control-output handling remain open. Managed/completion gates and OTP default stay
in place. Candidate/release/publication acceptance has not been executed for this
implementation slice.

## Private terminal storage and TCP verification policy (round 6)

Added provider-internal Receipt and Reader, not SSL.Lifecycle or a runtime observer.
Receipt stores eight unsigned atomic words, validates fixed setup/failure/mask/epoch
metadata, restricts publication to its creating observer, and publishes once after
all payload writes. It accepts only a settled, closed-admission ledger; the future
observer must still establish/authenticate the real resource evidence. Terminal
maps retain no TLS material, raw errors, PID/port lists or capability history.

Reader requires observer absence plus a valid final seal for successful await.
Sealed/live is pending; unsealed death is unconfirmed regardless of normal/killed
exit. Late noproc establishes current absence only. A sealed resource-loss receipt
remains readable but await returns unconfirmed. Finite waits retain their original
absolute deadline, match exact monitor/type/PID, and flush their waiter monitor.

Root-scoped lifecycle tests passed 38/38 (23 existing + 15 new) with seed101.
New cases use actual process and port monitors/DOWN, a late identity after creator
loss, adopted-port scope, wrong publisher, immutable repeated seal, invalid metadata,
fixed native storage size, interrupted publication including ALL payload words
written before death, sealed/live and late readers, unsealed normal/killed death,
100 publication/monitor races, 32 waiters, expired deadlines and caller mailbox /
monitor cleanup on timeout and fast terminal/loss/error returns. A read-only
adversarial source review found no concrete defect; it did not execute tests.

Actual observer supervision, inert TLS births, authenticated enrollment/owner ACKs,
allocation-with-no-resource completion, bounded unknown-identity retention and public
socket/HTTP integration remain open. No actual TLS cleanup claim follows from these
private foundations alone.

Explicit TCP `verify: :verify_none` now skips PKIX path/identity policy; omitted
verification remains `:verify_peer`. It still decodes bounded presented credentials,
preserves SPKI/PSS key restrictions, and verifies negotiated CertificateVerify or
TLS1.2 signed ServerKeyExchange, Finished and AEAD. Existing-socket none mode permits
absent SNI/reference without inventing an identity. Unused CA anchors need not be
normalized or system-loaded; explicit CA file read errors remain errors. QUIC still
rejects none mode and uses the shared core's peer-verification default.

The protocol peer boundary checks digitalSignature when leaf keyUsage is present
and rejects duplicate keyUsage in both trust modes. RFC9846 4.5.1.2 requires X.509v3
for ALL presented TLS1.3 certificate entries: both modes and cached peers enforce it,
including a transmitted root. Locally configured v1 anchors omitted from the wire
remain allowed. TLS1.2 uses explicit protocol context and retains its certificate
version policy; generic PKIX verify/decode primitives remain unchanged. Real
OpenSSL TLS1.2 v1 none-mode traffic also passes with OTP as independent client.

An independently constructed, valid TLS1.3 server flight forces a certificate-chain
signature outside the client's actual advertised cert schemes, with offered CV
scheme and valid CV/Finished/CCS. Both OTP and ExSSL none mode connect; peer mode
rejects the chain policy. This distinguishes intentionally skipped PKIX chain policy
from mandatory handshake authentication. RFC9846 4.5.1.2 permits fallback chains and
signature-algorithm exemptions; 4.5.2 still requires offered CV schemes. Ticket
policy partition v2 includes verification mode, and cached credentials revalidate
under current mode/protocol. Actual OpenSSL full/resumed none sessions pass while
default-peer crossover rejects the untrusted peer. Legacy VerifiedPeer is explicitly
documented as a credential container, not a standalone proof of trust. An independent
read-only security review checked mode propagation, default/QUIC trust, unconditional
handshake/record authentication, SPKI restrictions and ticket isolation without
finding a concrete introduced defect; that review ran no tests or network activity.

Final policy-focused gate passed 45/45. Three-app regression executed every new
scenario: ex_ssl 724/728 passed, core 408 passed/3 real opt-ins skipped, runtime149
passed. ExSSL failures were the same three unavailable-127.0.0.2 identity cases and
the KeyUpdate pending-input assertion. Isolated reproduction passed all eight
backpressure cases but reproduced the three address timeouts, so scheduling-sensitive
KeyUpdate acceptance remains open. A raw TCP wildcard-listener probe connected to
127.0.0.1 but timed out on 127.0.0.2 without TLS; no OS network changes or weakened
identity assertions were made. This scoped run is not full acceptance.

Strict compilation and formatting passed. Configured Credo checked523 files /
8695 modules-functions with54 checks and zero issues. Optional `credo --strict`
reported200 style/design suggestions (158 design,30 readability,12 refactoring);
that additional check is not reported green. First Dialyzer found one opaque-type
contract error in Receipt.new: declared reference() did not preserve OTP's opaque
atomics_ref(). Corrected the cell type to :atomics.atomics_ref() without runtime
changes. Rerun passed with zero errors/skips and four preserved pre-existing ignore
notices. No ignore-list entries were removed.

Final full root regression used the pinned Python environment,
`HTTP_QUIC_PHASE1_REAL=1` and `mix test --include integration --seed 101`:

| App | Result |
| --- | --- |
| ex_ssl | 725/728 passed (20 properties executed); three failures |
| elixir_quic | 249 passed |
| http_core | 411 passed; all three real opt-ins executed |
| elixir_quic_http3 | 113 passed |
| http_runtime | 149 passed |
| http_fetch | 1210/1226 passed; sixteen failures |
| http_web_socket | 138 passed |
| http_web_transport | 24 passed |
| http_event_source | 75 passed |

All3113 checks executed,3094 passed,19 failed; no excluded integration or skipped
real opt-ins. New none/protocol/receipt tests passed. Existing43 H2 tests were
included without failure. Connection's production diff is only forwarding the
validated verify mode: TCP/closed/size/active/plaintext-drain layout is unchanged.
Both test-only probes were re-audited and pinned to SHA256
`96628c634cb07f924f54bc67d6f9e6e014092d65e47e88ed778c3519efa9d5b5`;
coordinated app-version guards remain in place.

The19 failures are16 unavailable-127.0.0.2 scenarios, the OTP reused-writer test's
unobserved in-flight-send precondition, an early_data raw-stream listener/accept
`:einval`, and one ExSSL streamed4000 upload peer still open after local cleanup.
That peer reported recv_oct102032 / recbuf485936. Matching local Connection/writer
DOWN and Port absence assertions passed before remote drain; remote closure is
still failed evidence. The raw-stream einval category was seen in round4, absent
in round5, and recurred here. KeyUpdate passed this full run but failed the earlier
three-app run; it remains an ordering/scheduling acceptance issue until causally
resolved. Other upload closure cases passing this run do not resolve earlier
failures. No timing/buffer/identity assertions or two-second peer-drain limits were
relaxed. Full source acceptance is not green.

A read-only proxy contract audit confirmed HTTPS-proxy plus HTTPS-origin nested
TLS is explicitly rejected today. Supported CONNECT and HTTPS-proxy forwarding
have one TLS leg, targeting origin and proxy identity respectively. Corrected stale
Fetch option documentation about supported ExSSL IP-origin CONNECT. The next P1
slice needs provider-owned prepared upgrade policy before raw proxy dial, exact
upgrade-context validation and zero-proxy-accept negatives; full trust/key/profile
resolution must not independently change later in the same attempt. Existing bind
option rejection and the nested-route rejection remain explicit. Public provider
attempt/adoption, managed/completion, platform/runtime/package/performance/CI and
release/publication gates remain open; OTP remains the default backend.

## Round7 — private observer and prepared CONNECT policy

Private observer/runtime foundation now executes under a separate DynamicSupervisor
with temporary children. Isolated all-lifecycle run passed58 checks; root focused
run after the final bootstrap corrections passed59 (38 prior +21 observer cases).
Actual helper processes and native owned ports cover foreign-port preservation,
independent exact DOWN, late delegated identity/creator loss, duplicate objects,
replayed permits, fixed role graph, distinct controller/owner death, original finite
deadlines, infinite setup, large native timers, unknown call acceptance and
nonextendable1000ms grace. Unknown permits leave unsealed evidence rather than
inferred cleanup. No native TLS Connection or public lifecycle integration is claimed.

Independent source review found and corrected two initial runtime defects: setup
helper completion could leave pending infinite setup without a result producer;
and synchronous public DynamicSupervisor admission could exceed the start budget.
Setup completion now rejects pending outcome and its actual unexpected DOWN retires
failed/internal. A disposable monitored control proxy bounds admission, preserves
the original finite budget, uses reply aliases, waits actual normal worker DOWN
before successful publication, and leaves late unbound reservations with their
original expiry. Follow-up review identified a parent-death window before caller
installed the proxy kill timer, plus budget origin sampled after validation. Timer
installation/cancellation moved inside the worker BEFORE blocking admission, and
control budget origin moved to API entry. Regression suspends the supervisor and
kills the caller after public process-spawn tracing identifies its actual proxy;
three trials observe independent bounded proxy death. Tests use no private OTP
supervisor messages or fabricated data-resource DOWN.

Initial standalone harness exited its linked supervisor before ExUnit autorun;
fixed the harness to run ExUnit while its parent is alive. The one subsequent race
was a test assuming kill implied the observer had already processed creator DOWN;
changed the test barrier to wait real snapshot evidence with one original deadline.
Production evidence requirements were not weakened.

Prepared-policy work is under exact nine-file scope: public provider-owned immutable
configuration snapshot before raw CONNECT allocation, consume the same snapshot at
upgrade, preserve fresh per-connection keys/randomness/binders and upgrade-context
option rejection. Current focused run passed lifecycle, fresh ClientHello,
context bounds and actual full+two-resumed prepared-upgrade references. The two
TLS1.2 failures were isolated with public legacy-upgrade/prepared/direct comparisons,
combined and explicit TLS1.2 offers: all six fail identically. Public ServerHello
wire contains renegotiation/EC-point-format/ALPN extensions but no EMS(23); OTP29
client accepts that peer, while ExSSL correctly enforces its documented bounded
ECDHE/EMS subset. This is a fixture mismatch, not a prepared-snapshot regression.
The new positive CONNECT fixtures are being changed to the existing independent
OpenSSL EMS-capable peer behind a byte bridge, preserving combined client versions,
CA/identity/ALPN/option-precedence assertions and mandatory integration execution.
No production certificate/CV/version/EMS checks are relaxed. Final combined focused
run passed133/133 with ZERO exclusions/skips, --include integration and pinned Python
PATH: ex_ssl66 (59 lifecycle +7 prepared), http_core34 (27 existing transport +7 proxy),
Fetch33. Both mandatory new OpenSSL TLS1.2 positives executed with combined offers;
real IPv6 SAN negative, malformed reference zero-accept, source-file replacement/
deletion, wire freshness and full+two-resumed policy reuse passed. Strict root compile
and scoped formatting13 code paths passed. Configured Credo ran54 checks over530
files /8811 modules-functions with no issues. Initial Dialyzer reported two discarded
timer-cancellation return values in Observer; explicit `_ =` acknowledgments preserve
behavior. Final Dialyzer:0 errors,0 skipped; four prior unnecessary-ignore notices
remain untouched. Full source regression used pinned Python PATH and
HTTP_QUIC_PHASE1_REAL=1, --include integration, seed101. Exit2:3153 checks,
3131 passed,22 failed, no exclusions/opt-in skips. The40 new checks all passed.

| App | Full source result |
| --- | --- |
| ex_ssl | 752/756, including20/20 properties |
| elixir_quic | 249/249 |
| http_core | 418/418, all three real opt-ins included |
| elixir_quic_http3 | 113/113 |
| http_runtime | 149/149 |
| http_fetch | 1213/1231, including20/20 doctests |
| http_web_socket | 138/138 |
| http_web_transport | 24/24 |
| http_event_source | 75/75 |

All16 unroutable127.0.0.2 scenarios remain (3ExSSL +13 Fetch). Six other failures:
ExSSL requested KeyUpdate was not observed queued behind output (seen in prior
round6 scoped run too); OTP reuse could not establish in-flight bounded send;
a raw request-stream length-mismatch listener accept returned :einval; and THREE
ExSSL remote peers remained open after proven local cleanup (auto/buffered/infinity,
http1/cancel/infinity, http1/buffered/infinity). Remote counters were103979/101008
bytes, recbuf483984/486960. Exact local Connection/writer DOWN and native Port absence
passed BEFORE remote drain; those observations do not prove remote closure. The
prior early_data fixture and streamed4000 case passing this run do not causally
resolve their earlier failures. Additional failure isolation ran the backpressure file plus request-stream line160:
7/8 backpressure cases passed, queued-KeyUpdate failure reproduced; all3 selected
length-mismatch cases passed (28 other stream cases deliberately excluded by line
filter). That rerun does not resolve the full-run raw-accept :einval. Final configured
Credo again found0 issues; whole-root `mix format --check-formatted` passed.

No full acceptance is claimed. Read-only task-9 portability design keeps identity
proof nonvacuous by dialing routable127.0.0.1 with a dedicated certificate that has
SAN127.0.0.2/::2 but excludes actual dial1. True destination-isolation/refusal/
saturation cases require separate127.0.0.1 and IPv6-only::1 listeners at the SAME
port, reserved before clients. Preserve Host/:authority/pool scope/first-connection
reuse, exact refusal, independently proven saturation and no-fallback/no-replay
accept queues. No OS aliases, skips or weaker negative assertions are proposed.
 Pre-existing auto-ticket partition for CONNECT uses
proxy peer IP:port plus origin identity/profile/trust, lacking target origin port;
this remains a separate explicit P1 cache-isolation gate, with tickets disabled by
default. Preparation does not establish adoption or cleanup and does not enable
managed/completion/default promotion.

## Round8 — portable pin fixtures and authenticated KeyUpdate progress

Task9 changed seven existing test/support paths and three explicit Fetch PEM/key
fixtures. Physical test endpoints use127.0.0.1 and IPv6-only::1; logical certificate
references127.0.0.2/::2 remain. Optional ClientAuthFixtures server_sans defaults are
unchanged and the original mTLS suite still executes. Dedicated ExSSL certificates
have SANexssl.test,127.0.0.2,::2 and EXCLUDE actual dial1; direct/upgrade, IP tuple/
string, DNS, disabled/unrelated SNI, exact peercert, wrong CA and trusted wrong-dial
reference tests are retained. Independent TLS1.2 positives/negatives use the
mandatory EMS-capable OpenSSL peer. Fetch's new test leaf has ONLY SAN127.0.0.2,
excludes127.0.0.1/::1, matches its private key and serverAuth purpose, and expires
2036-10-18T14:09:43Z. Only public test CA/server cert and server key enter the repo;
the generating CA private key stayed in a disposable external directory.

Pin H1/H2 isolation/reuse/refusal/retry tests reserve both actual families at the
SAMEport before dialing. Preserve identical URL/Host/:authority/pool scope; prove
first-v4 ->second-v6 ->first-v4 connection reuse, exact refused pin, complete
mutation body and empty extra/fallback accept queues. Native saturation initially
failed honestly: backlog0 accepted64 bounded probes on this kernel, while backlog1
accepted1 then timed out. Fixture uses explicit backlog1 and requires TWO native
timeout probes with fill sockets still alive before HTTP's unchanged100ms connect
budget/overall deadline and explicit caller retry. No OS alias, skips or relaxed
negative assertions. String-host raw/proxy/redirect refusal controls instead use
separately reserved/closed IPv4 ports, retaining the live origin/first mutation and
original1271 Host. This is endpoint refusal evidence, not same-port pool isolation.

Focused85/85 (ExSSL17 +Fetch68) passed with --include integration, seed101 and pinned
Python PATH, zero exclusions/skips. Includes all six changed test modules plus the
unchanged-default ClientAuthInterop suite. Worker strict compile and scoped format
passed. Separate observed gap: literal IPv6 string hosts without explicit family
options can return:nxdomain through the existing TCP/OTP adapters; tuple-pin tests
infer family. Adding inet6 to a shared option set made literal IPv4 controls fail,
so the tests do not silently adopt such an invalid fallback control. Production
IPv6 string-family resolution is not fixed or claimed here.

KeyUpdate original line9 repro failed on current production source. Three metadata
probes also failed. Public OTP send_oct1386->1413 immediately after update_keys
proved27 update bytes emitted; an application marker raised it to1452. Client
recv_oct matched but raw input_size stayed0, nativeactive:once/packet0 and correct
controller remained. A public raw inet record-sized blocked-writer control still
delivered5 reverse bytes with send_pend16644; optional socket-backend counter
inspection stalled and was stopped, with no socket-backend support claim. Finally,
the ORIGINAL marker-free failure showed read_generation1/write_generation1 despite
input_size0 and a still-blocked application writer. The update had already been
authenticated between native output jobs of the SAME logical write. Waiting only
for a transient raw-input queue was an incorrect test oracle, not an engine failure.

The corrected oracle accepts queued bytes OR both epochs incremented, reasserts
real TCP writer blockage BEFORE resuming the proxy, retains exact16MiB payload/no
replay, asserts final read/write generation+1, and makes the independent OTP peer
authenticate a distinct12-byte client marker AFTER the complete payload/update ACK
before returning its recovery response under the new server key. This strengthens
end-to-end update evidence. Backpressure/input-ordering/lifecycle/abandonment:
48/48 passed, integration included, zero exclusions/skips. Independent read-only
review found no blocker to the broad recovery/no-replay contract. Raw queued bytes
alone do not authenticate KeyUpdate identity or prove deferral behind the SAME
immutable native job; final epoch/independent-marker assertions establish actual
update/ACK, and separate gated ordering tests cover exact job deferral. All DEBUG-ku8 diagnostics
were removed; production Connection/Writer, private-layout pins and policy/defaults
are unchanged. Strict compile and whole-root formatting passed. Initial configured
Credo found one unused final HPACK decoder return in the new repeated H2 fixture;
explicit `_decoder = Enum.reduce(...)` preserves decoder threading and acknowledges
the final state. Final configured Credo:54 checks,530 files,8819 mods/functions,
zero issues. Dialyzer:0 errors,0 skipped; four existing unnecessary-ignore notices
remain unchanged.

Final full source used pinned Python PATH, HTTP_QUIC_PHASE1_REAL=1,
--include integration, seed101. Exit2:3155 checks,3153 passed,TWO failed,
zero exclusions/opt-in skips. All16 formerly unroutable address cases and the
corrected requested-KeyUpdate case passed. Both newly added trusted wrong-dial
reference negatives passed. These are executed improvements, not a full gate pass.

| App | Full source result |
| --- | --- |
| ex_ssl | 757/757, including20/20 properties |
| elixir_quic | 249/249 |
| http_core | 418/418, including all three real opt-ins |
| elixir_quic_http3 | 113/113 |
| http_runtime | 149/149 |
| http_fetch | 1230/1232, including20/20 doctests |
| http_web_socket | 138/138 |
| http_web_transport | 24/24 |
| http_event_source | 75/75 |

Remaining actual failures:
- TLSSetupEvidenceTest early_data negative: raw listener accept returned:einval
  (line182); linked task MatchError, previously observed full-suite fixture race.
- HTTP1WriteIdleWireTest ExSSL cancellation after an OBSERVED blocked upload:
  `finish/3` did not receive peer_closed within its EXISTING8000ms bound. This is
  remote-close observation, NOT failure to establish the blocked-send precondition.

The prior three HTTPS-early-upload remote2s failures, OTP in-flight-send
precondition failure and request-stream raw-accept race passed this run without
production changes; they are NOT causally fixed by fixture portability or the
KeyUpdate oracle. Keep them as unresolved regression history. Read-only analysis
found an abort-intent boundary to test next: begin_shutdown/close_transport inspect
current output/driver send_pend but ignore retained write_abandoned?. Driver queue
empty does not prove kernel queue empty or remote acknowledgement. Pending task10
requires a deterministic abandoned-vs-completed first-hop RST/FIN test, retained
response reads, exact local DOWN/Port absence <=1s BEFORE remote2s drain, and original
failure reruns before any remote-failure fix claim. No production fix is made here.
Full P0–P7, public/native lifecycle integration, managed completion, default
promotion, production OTP dependency removal and package publication remain open.

## Round9 — exact early-data rejection and persistent upload abort

Task11 old whole-file14 checks plus30 extra filtered repetitions passed. That did
not reproduce the intermittent natural root failure. Controlled public/native late
accept AFTER HTTP.Promise.await did:100/100 late accept attempts returned:einval while
the SAME listener retained its owner and public [:listen,:open] states. A fresh
native control connected/accepted on that same listener afterward. Exact public
error100/100 was RequestError reason `{:options,:incompatible,
[:early_data,{:session_tickets,:disabled}]}`, phase/request_started:unknown. OTP
rejects this option combination BEFORE TLS; expecting a CA-alert handshake helper
was invalid. Listener retirement/foreign-port capture was not the cause at this seam.
An actual gated OLD ExUnit run retained original2s accept/3s handshake/4s Task.await:
4/5 passed, early_data alone failed MatchError:einval. Diagnostic gate was removed.

The final single-file patch removes early_data from the handshake matrix and adds
a dedicated exact public option-rejection test with its live owned listener and
NO handshake helper. It retains unknown phase/request_started and pre_send?false;
no native errors are swallowed, no timeout/error set is broadened, no skip or
production change. Other four matrix cases retain real peers. Final repeat flag10
ran11 whole-file rounds:154 passed, zero exclusions/skips. Scoped format passed.
The old default-build dependency/version failure encountered by another worker was
setup-only, NOT a regression RED; all accepted tests use the shared /tmp build.

Task10 added a separate private test-owned FIFO TCP relay and independent OTP peer.
Original logical upload16MiB; only the original <=16384-byte application record
survives public abandonment. Both matched ordinary/abandoned cases authenticate an
early response while the real immutable native writer job is held. After release,
require output=nil/write=nil/driverpending0 and sticky abandonment flag; this does
NOT assert kernel queue empty. The relay records FIRST client FIN/RST before any
cleanup/propagation can manufacture it. Test first observes exact Connection/writer
DOWN +Port absence within1s, then authorizes the peer's2s drain. The retained prefix
is authenticated through public OTP recv BEFORE the relay releases gated final
bytes/terminal FIFO, avoiding an assumption that a native send ACK is a peer TLS ACK.
Ordinary prefix16384 bytes == the abandoned case's committed prefix; the remaining
16,760,832-byte logical tail cannot be replayed. No machine/keys/cursors are returned by scalar snapshots.

Correct old-source shared-build test:1/2 passed; ordinary FIN PASS, abandoned ONLY
failed final semantic comparison actual:fin vs expected:reset. Both cases had already
passed every precondition/local cleanup/prefix/drain assertion; no fixture timeout.
Production fix changes TWO decisions only: write_abandoned? short-circuits
begin_shutdown before close_notify, and close_transport retains zero-linger abort
when that flag survives output completion/driverpending0. Existing single actor,
writer, timers, state fields, key epochs and bytes are unchanged. Same tests2/2 GREEN.
Independent read-only review confirms authenticated plaintext buffer/size/recv/active
are retained by close_transport and drained normally; flagfalse keeps exact old
orderly-close behavior. COMPATIBILITY and root design record the narrow policy.

Connection exact SHA256 is now
371201570752d6d090d78bd8760547998e9bff25640d4b436c45719fa4cf98a0.
Both cross-app private probes were explicitly re-audited and repinned; no private
field/layout, threshold or equality/version check was weakened. Unabandoned raw
option forwarding and plaintext peer-close drainage paths remain unchanged.

Combined focused integration seed101:208/210 passed, zero exclusions/skips:
ExSSL55/55 (new2 plus backpressure/ordering/lifecycle/abandon/closure), core27/27,
Fetch126/128 (setup evidence, original HTTPS early uploads/write idle and H2).
Original ExSSL cancellation/early-upload cases and all source guards passed.
Remaining actual focus failures are BOTH OTP reference paths: ordinary reuse could
not establish an observed in-flight bounded send; SSL auto/buffered4000 peer remained
open after proven local cleanup, with public recv_oct247546/send_pend0/recbuf340472.
The respective1s observation/2s remote bounds are unchanged. These are not claimed
fixed by an ExSSL-only terminal decision patch. Strict compile/whole-root format
passed. Configured Credo54 checks/531 files/8835 mods-functions found0 issues;
Dialyzer0 errors/0 skipped, four existing unnecessary-ignore notices retained.
First round9 full source with pinned Python/real QUIC/integration/seed101 exited2:
3157 checks,3154 passed,THREE failed, zero exclusions/opt-in skips. ExSSL759/759
(20 properties), QUIC249, core418, H3 companion113, runtime149, WS138, WebTransport24,
SSE75 passed; Fetch1229/1232 (20/20 doctests). Failures: fixed-length upload abort
GET and DELETE raw accept:einval at227, plus ExSSL http1/streamed/infinity HTTPS
peer2s timeout after local proof (recv_oct103961/send_oct1461/send_pend0/recbuf484000).
Thus the persistent-abort semantic fix does NOT causally resolve every remote-close
failure; task14 preserves the remaining local/native/remote diagnosis and all bounds.

Task13 then reproduced the UNCHANGED abort test naturally: POST failed on16th
focused repeat after15 rounds passed. Valid late-accept gating reproduced old
ExUnit3/3 failed for POST/GET/DELETE, same live parent-owned/open listeners. Source
review corrects an important distinction: HTTP1.Upload acknowledges read_chunk ONLY
after send_data:ok. HTTP.Stream.chunk therefore confirms TRANSPORT ACCEPTANCE, not
mere source admission and not peer receipt. Plain-TCP abort's existing zero linger
can discard bytes before peer acceptance. The fixture expected an observed partial
body without establishing that prerequisite; no production method/framing bug found.

Only those three generated tests now use bounded5s accept, assert exact wire method,
Content-Length6/no Transfer-Encoding, preserve header-rest bytes, read exactlyabc,
and send a unique ref/PID peer receipt BEFORE parent abort. Exact-length native
reads preserve later bytes for the final EOF reader; no body truncation hides replay.
The source is still alive and final three bytes remain unproduced when abort occurs.
Original public:aborted, source DOWN:normal, exact final bodyabc/EOF remain; normal
peer DOWN is now also required before test exit. No errors swallowed/broadened,
no finite timeout widened, no helpers/global raw-server semantics or production
changed. Existing already-aborted-controller/no-dial coverage stays separate.
Old natural/gated diagnostics were removed. Final303 focused checks across101 runs
passed (28 deliberate location exclusions per run); six whole-file rounds186/186
passed with ZERO exclusions/skips. Source frozen before final root below.

Final whole-root format/Credo after the last fixture change passed again:54 checks,
531 files,8835 mods/functions, zero issues. Production source did not change after
the strict compile and successful Dialyzer above. Final full source with pinned
Python PATH, real QUIC flag, integration included and seed101:exit2,3157 checks,
3155 passed,TWO failed, zero exclusions/opt-in skips. App counts match the first
root except Fetch improved to1230/1232 (20/20 doctests). ExSSL759/759 again passed,
including both FIN/RST regression cases; early_data and all three fixed-length
partial-upload cancellation cases passed in the complete suite.

Remaining final-root failures:
- OTP SSL ordinary reuse at HTTP1WriteIdleWireTest167 could not establish its
  observed bounded-send prerequisite within the unchanged1s (line198). Task16
  distinguishes pressure/capacity, real stale-policy failure and sampling before
  changing either fixture or runtime; no cause claimed yet.
- ExSSL AUTO/streamed/infinity HTTPS early upload still timed out on peer2s drain
  AFTER exact local cleanup:recv_oct103074/send_oct1461/send_pend0/recbuf484896,
  receiver/sender idle. The first root'sHTTP1 variant happened to pass final run;
  that is not causal resolution. Task14 retains native-close/linger/4tuple/reference
  investigation with unchanged local1s/remote2s bounds. Do not infer remote terminal
  delivery from local DOWN/Port absence or from the deterministic semantic RST test.

Round9 accepts only the narrow abort-intent fix and the two causally established
fixture corrections. Full acceptance remains failed. No default/managed/completion
promotion, native lifecycle/public facade enablement, production OTP removal,
package publication or full P0–P7 completion is claimed.

Read-only next-P2 architecture review identifies ordered work: constructor no-resource
settlement BEFORE entering native allocation, inert Connection/writer enrollment,
real allocator->TCP/setup->Connection/Connection->writer orchestration, then public
facade admission. Setup outcome must be acknowledged before result/normal failure
exit; unexpected Connection DOWN can retire the current observer before later setup
publication. Public upgrade/authority transfer remain separate. All source runtime
integration is still absent; private observer/plan is not exposed as cleanup support.

A bounded separate-VM OTP29 tracing probe investigated hidden ports on native refusal.
Allocator-only ports tracing produced no open events; procs tracing exposed link/
unlink identities but complete native coverage is unproved. Session-wide NEWport
tracing exposed exact open/closed identity and matching monitor DOWN:noproc after
close, a valid current absence for THAT identity. Global new-port scope is not local
allocator scope. Public trace_delivered/delivered guarantees messages 'to be delivered',
not tracing completeness; port-stream barrier, DNS/multiple-attempt coverage,
backend compatibility, event authentication and mailbox bounds remain unproved.
No tracing/provider implementation was added. Native error or helper DOWN still
cannot substitute for exact native-resource proof; missing evidence stays unconfirmed.

## Round10 — pre-native constructor settlement and measured pressure

Task15 adds private ResourceLedger/Observer.reject_before_native/4. A trusted
provider constructor asserts it rejected BEFORE entering native allocation and
fenced all future allocation. This is not an interpretation of a native connect
error/timeout/helper DOWN. The exact permit/role/creator and live enrolled parent
monitor generation with done:false are authenticated; root permits match bound
owner/recorded owner monitor. Consuming a genuine permit sets a private fixed5bit
role-use tombstone: no reuse/late enrollment, fabricated resource/DOWN, reopened
admission or erased own/other sticky loss. Accounting may settle after admission
closed. Snapshot/Receipt dimensions, Reader rules and immutable grace stay unchanged.

Initial test-first shared-build RED:31/33 passed, exactly TWO missing-API
UndefinedFunctionErrors; log/tmp/http-fetch-task15-old-lifecycle-red.log. Final
2file focused GREEN:43/43 seed101 in3.9s, log/tmp/http-fetch-tls-round10-lifecycle-green.log.
Twelve added tests cover caller/token/role/attempt/generation, replay, closed fence,
forbidden role reuse/late enrollment, own/other sticky loss, helper_done and real
setup-helper options failure. Root setup rejection deliberately leaves setup pending
until explicit cancellation; constructor-owner outcome needs later driver integration.
It does not invent failure.
Lead reviewed both runtime files and all12 added cases. Actual native births/inert
Connection/writer/adoption/transfer/public lifecycle remain absent. All71 lifecycle tests passed in3.9s. Strictcompile/wholeformat passed;
configuredCredo54checks/531files/8844mods-funs found0issues; Dialyzer0errors/
0skips/four intentional unnecessary-ignore notices retained. Logs/tmp/http-fetch-
tls-round10-{all-lifecycle,compile,format,credo,dialyzer}.log.

Task16 reproduced the unchanged OTP SSL ordinary-reuse blocked-send prerequisite
failure on the second repeated trial. Public classification then established the
old fixed1MiB pressure FITS: all64 chunks produced, source exact DOWN:normal,
source info:nil, public request still awaiting peer response; peer public SSL
recv_oct1,052,147/recv_cnt64. Once authorized, peer read EXACT1,048,576 application
bytes, then HTTP200 and completion:ok. ExSSL control stopped at35/64 produced and
TCP25/64 with stable blocked workers across350ms. Thus this observed OTP failure
was neither a missed existing worker nor a stale-send-limit error: no unfinished
send remained. Log/tmp/http-fetch-write-idle-old-pressure-evidence.log8-39.
The2MiB candidate also fit OTP buffers. Final finite4MiB (256x16384) uses one
immutable1s observation budget: continuously poll5ms for the same waiting upload
worker/production counter for>=90ms, then keep the peer paused350ms total since
that observation. Source and the same monitored worker must still be alive, with
produced<256. The original peer/native defaults are restored; attempted post-TLS
receive buffer controls did not impose a fixed cap because OS autotuning persisted.
Exact4MiB/HTTP200/sourceDOWNnormal/backend-specific completion remain required.
Six focused3-backend repetitions:18/18 passed; log/tmp/http-fetch-write-idle-pressure-
256-stable90.log. Proper controlled native80 negative uses identical socket_opts
on BOTH requests to preserve pool identity: ALL3 received the second header on
SAME peer, sourceDOWNnormal and publicTask {:ok,{:error,:timeout}} before90ms
observation could settle; log/tmp/http-fetch-write-idle-final-native80-negative.log.
A prior second-request-only socket_opts control changed pool identity and is INVALID,
not negative proof. All pressure/env/rescue/stats diagnostics were removed before
final acceptance; only the finite workload/counter and bounded observer remain.
Final CLEAN whole-file3x27=81/81 passed, zero exclusions/skips; log/tmp/http-fetch-
write-idle-final-whole.log. Scoped formatter/diff checks passed. No production write
policy/native buffers/completion expectations/other24 wire cases changed. Final
umbrella results follow below.

Task14 separate bounded OTP29 native control used true prim_inet.send/4 WAITING,
pending16592–16800 bytes before/after17 reverse bytes, verified linger setopts:ok
and getopts{true,0}, exact owner+writer DOWN/Portnil within1s BEFORE peer2s drain.
Four cases: warmup0/65536 times Port.close/gen_tcp.close, reset mask true; another
four same cases reset mask false. All8 passed: local0ms, remoteECONNRESET/CLOSED
0–1ms after180224–326712 bytes drained. Logs/tmp/http-fetch-tls-round10-native-close-
control.log and native-close-default-mask.log. This demotes GENERIC backlog/API/
reset-mask failure, not every TLS-native configuration.

Approved temporary payload-free Connection and HTTPS fixture diagnostics correlated
actor/owner/native4tuple/monotonic time, close flag/output kind/write?/driverpending,
actual linger result and public getopts/getstat, exact local retirement, peer receive
byte/chunk counts and terminal. Peer metadata workers were asynchronous/bounded50ms;
original gates/assertions/ssl.recv(...,2000) were unchanged. Bounded two44-case
matrices seed101+102:88/88 passed (19.3s+17.6s), logs/tmp/http-fetch-tls-round10-
https-diag-{1,2}.log. No timeout/failing4tuple was captured; NO causal fix claimed.
All44 ExSSL close events used successful/effective zero linger via existing flag
or active output/driver-pending branch. Formerly failing auto/streamed/infinity
positive example: actor2716,tuple56361->56360,abandonedtrue,pending13378,linger:ok,
Port absent1ms,peerclosed after98313 bytes/6chunks <=1ms. Passed-case evidence
cannot establish the branch used by a historical failed case.

Material configuration gap: actual TLS client native sndbuf1024/buffer16640;
initial raw controls auto-tuned to sndbuf65328/buffer9216 despite the requested
small buffers. Eight ADDITIONAL exact-effective controls reapplied sndbuf1024/buffer16640/client
activeonce AFTERconnect and matched readbacks BOTH before write and close:4passive
+4active100, warmup0/65536 x bothcloseAPIs. Real16406byteprim_inetsend4job/pending
8346–15470 survived17 reverse bytes; linger:ok/effectivezero, exactlocalDOWN/Portnil
0ms BEFOREdrain and allremoteCLOSED0ms. Logs/tmp/http-fetch-tls-round10-native-
exact-{passive,active100}.log. ALL16 nativecontrols pass, also demoting generic
effective-small-buffer/active100 failure. No TLS failure was captured; no causal
fix/universal native claim follows.
Temporary Connection+HTTPS changes were removed before next Mix owner; exact
Connection source hash restored371201570752d6d090d78bd8760547998e9bff25640d4b436c45719fa4cf98a0,
and both files diff-identical to HEAD. Original local1s/remote2s bounds unchanged.

Final ALL-NINE source run (integration included, HTTP_QUIC_PHASE1_REAL=1, seed101)
EXIT2:3166/3169passed, ZERO exclusions/opt-in skips. ExSSL771/771(20props),
QUIC249,core418,H3comp113,runtime149,Fetch1229/1232(20/20doctests),WS138,WT24,SSE75.
Log/tmp/http-fetch-tls-round10-source.log. THREE failures remain:

- UNCHANGED fixedlength mismatch abc/def fixture accept:eINVAL at RequestStream165;
  listener/abort ordering needs controlled proof (Task18); no error allowance added.
- UNCHANGED ExSSL cancellation wirecase119: publicaborted/uploadworkerDOWN/source
  DOWNnormal passed; finish peer_closed8s timed out. This is NOT separate proof that
  providerConnection/writer/nativePort had retired; Task14 must correlate those.
- ExSSL http1/streamed/4000 HTTPS peer2s timeout AFTER exactlocalretirement; recv_oct
  102032/send_oct1461/send_pend0,active99/buffer9216/recbuf485936; sender/receiver
  idle with empty mailboxes. Actual failing close tuple/branch still uncaptured.

Corrected ordinaryreuse case passed in the full run; no causal remote-close fix
claimed. Private pre-native settlement is accepted at71 lifecycle checks, while
full umbrella/default/public/managed gates remain OPEN. Next ordered private work:
inert Connection/writer births BEFORE any timer/writer/TLS/native work (Task17),
then realallocator/setup/directfacade with actualnativeidentity proof. Native
errors/helperDOWN remain unconfirmed; no default switch/public lifecycle admission.

## Round11 — inert process births and peer-fenced length mismatch

Task17 adds a private tagged Connection constructor under the existing temporary
DynamicSupervisor. Init returns before Observer RPC, with no writer, handshake
timer, record/TLS state or TCP port. It enrolls itself, reserves/enrolls a writer,
then matches recorded PIDs/separate nonce/original Observer before release/readiness.
Both actors monitor the original Observer; already-born late actors attempt
accounting after parent loss. Unknown/replayed/missing/expired authority cannot
authorize readiness or invent resource absence. Private attach/data calls remain
rejected even after readiness. Classic tuple5 startup, native writer operation,
plaintext drainage and buffer/active/closed probe fields remain unchanged.

Actual firstRED: one valid setup/permit and suspended Observer, old tagged init
returned function_clause; /tmp/http-fetch-task17-old-inert-red.log. Initial15 cases
then passed. Lead review found Observer call waits used the longer control budget
even when setup expired earlier: two new suspended-Observer exact-DOWN tests RED
15/17 (no DOWN within373/377ms). Clip min(original control,original setup) ONCE
before the first RPC and carry unchanged across enrollment/reservation/readiness/
release; original setup remains the later handshake timer anchor. Corrected17/17
passed. Logs/tmp/http-fetch-task17-setup-deadline-{red,green}.log.

A second review moved unsupported context validation BEFORE process construction,
rather than interpreting an init error as no child. Precise private context types
and defensive init validation retained; other constructor failures still unknown.
Final17/17 seed101 in8.6s/no exclusions/skips after entry guards;
/tmp/http-fetch-task17-final-entry-green.log. Tests include actual supervisor/
Observer barriers, finite/expired original budgets, dead Observer, parent loss,
independent suspended writer exactDOWN, queued/rejected attach with no bytes or
ownership change, wrong PID/nonce/Observer release and real post-release bytes.
Those raw sockets are test-owned: role14 process receipts do NOT attest TCP adoption.

Task18 unchanged natural baseline33/33 passed, but a controlled schedule reproduced
ALL3 accept:eINVAL AFTER public content_length_mismatch, with the listener still
owned by a live test and [:listen,:open]. /tmp/http-fetch-task18-old-controlled.log.
Fixed trio gates the actual lazy producer BEFORE first yield on verified PUT/CL4/
no-TE/header-only peer receipt; abc cases also require exact peer abc receipt BEFORE
releasing EOF or def. Exact mismatch, abc/abc/empty bytes and source/peer normalDOWN
plus exact producer absence retained; no native-error allowances/Task13 changes.
First3+8x3 focused=27GREEN; two full31-test runs=62GREEN, zero full-file exclusions/
skips. /tmp/http-fetch-task18-{first-green,focused-repeat,final-whole}.log.

Lead reviewed all17 tests/runtime branches and repins BOTH private source guards
to 0f0ad762fed7bb6307e374ea7e83d0699bd45cb21309cdb5140a1c74e2220e98 after auditing the unchanged classic paths.
Initial root strictcompile/wholeformat/Credo passed; Dialyzer found ONE actual
call_without_opaque at Connection.init Receipt.observer because the untyped
callback narrowed receipt to a local struct. A one-line flow correction removes
that narrowing; prebirth validation/opaque type/specs/ignore entries unchanged.
Original RED/tmp/http-fetch-tls-round11-dialyzer.log preserved. Final strictcompile/
wholeformat/Credo532files54checks0issues/Dialyzer0errors0skips passed; four intentional
unnecessary-ignore notices retained. Final logs/tmp/http-fetch-tls-round11-final-
{compile,format,credo,dialyzer}.log. No production TLS protocol/crypto change.

Final root-scoped88/88 lifecycle+inert (71+17), coreTLS27/27 and FetchH2 43/43 =
158/158 PASS after opacity correction and BOTH exact SHA guard updates;
/tmp/http-fetch-tls-round11-scoped.log. This checks classic options/peer-close
plaintext buffer drainage as well as the new private actor boundary.
All-nine source outcome pending below.

Read-only Task14 review FALSIFIED the idle-send-gap hypothesis: successful owner-
authenticated abandon_send unconditionally sets the sticky flag even with write:nil.
HTTP abandons before joining upload writer/source, then closes provider; public
:aborted is published before cleanup. Thus wire writer/source DOWN alone cannot
establish provider/Port retirement. Native send_timeout_close:true may retire a
port before final linger; this remains UNPROVEN, not a reason to change policy.
Future mixed-suite capture must correlate actual failing native tuple/actors,
abandon result/caller-owner identity, writer/output/timeouts, pre-linger Portalive,
setopts result/readback and actual close outcome/Portnil. No new raw campaign,
production instrumentation or causal remote-close fix was performed this round.

A separate read-only review of official current OTP29.1.2 socket docs identifies
a possible future split open -> known opaque socket -> original socket monitor
enrollment ACK -> connect seam. It improves ordinary dial-error identity coverage,
but open failure/killed opener before identity publication still cannot prove
absence; owner/helper DOWN and operation-abort/connect errors are not socket DOWN.
Current v1 is port-only; no backend/contract revision was made. Supporting socket
resources needs explicit monitor-kind/owner/I-O/select/STARTTLS/buffer/performance
review; no equivalence to inet active-once/buffer/send-timeout is assumed.
Sources: [socket open](https://www.erlang.org/doc/apps/kernel/socket.html#open/4),
[original monitor](https://www.erlang.org/doc/apps/kernel/socket.html#monitor/1),
[connect uncertainty](https://www.erlang.org/doc/apps/kernel/socket.html#connect/3).
This was documentation research, not installed OTP29.0.2 runtime proof.

### Round11 full source result: NOT accepted

Actual root command used isolated existing build/venv, integration included,
HTTP_QUIC_PHASE1_REAL=1 andseed101. All9apps ran:3185/3186 passed, EXIT2 confirmed
by ROUND11_FINAL_ACCEPTANCE_EXIT=2 AND shell prompt; inferred_idle was not exit
evidence. /tmp/http-fetch-tls-round11-source.log; no exclusions/opt-in skips.

| App | Actual result |
| --- | --- |
| ex_ssl | 788/788 (20 properties +768 tests) |
| elixir_quic | 249/249 |
| http_core | 418/418 |
| elixir_quic_http3 | 113/113 |
| http_runtime | 149/149 |
| http_fetch | 1231/1232 (20/20 doctests) |
| http_web_socket | 138/138 |
| http_web_transport | 24/24 |
| http_event_source | 75/75 |

The ONE failure remains the unchanged ex_ssl/http1/streamed/4000 HTTPS blocked-
write case (log1058–1080). Exact provider Connection/writer DOWN and Portnil passed
before the existing peer read; peer recv still timed out at its original2s. Public
metadata: recv_oct103056/send_oct1461/send_pend0; active99/buffer9216/recbuf484912;
receiver/sender waiting in gen_statem.loop with empty mailboxes. No exact failed
native4tuple/abandon/linger/close branch captured yet, so no causal claim.
Corrected length-mismatch trio and unchanged wire-cancellation case passed this
full run; the latter passing once does not resolve its prior intermittent history.
All17 new inert cases passed inside full ex_ssl788 as well as scoped88.

Private Task17 and fixture Task18 are accepted in their stated scopes; full source/
P0 remote closure remain OPEN. Actual native constructor identity, real allocator/
setup/TCP adoption, public facade/managed completion/transfer, performance/soak,
backend default/removing productionOTPssl, package/CI/publication/cold consumer
gates are not admitted by these private proofs. Goal remains active. No source
instrumentation, timeout widening, forcedGC, skipped failures or default change.

## Round12 — actual correlated remote-close failure

Temporary diagnostics only: Connection SHA
aea15e04e3b385b89775be4bde0163c6f427d4883a03c09ebd45ed0ec10a0953,
both strict guards repinned without removing assertions; TLS_P0_CLOSE_DIAG=1
arms only the selected provider PID. Scalar events capped64 per Connection;
no keys, plaintext, native message dumps, extra peer readers or changed timeouts.
Original recv2s/local retirement1s/parent peer3s remain. Compile strict0, then
root all9/include integration/HTTP_QUIC_PHASE1_REAL=1/seed101:3183/3186, EXIT2
verified by ROUND12_DIAG_EXIT=2 and prompt, no exclusions. Log
/tmp/http-fetch-round12-diag-source.log. This instrumented run is diagnostic,
not final-source acceptance. ex_ssl788, QUIC249, core418, H3comp113, runtime149,
Fetch1229/1232, WS138, WT24, SSE75.

Three failures: H3 field-section budget fixture on_exit Port.close ArgumentError
(log950–956); OTP ssl/auto/buffered/4000 peer2s timeout (log2122); and ExSSL
auto/buffered/infinity peer2s timeout (log3346–3607). The historical ExSSL
http1/streamed/4000 case passed THIS run; its prior failure is not resolved.

### Exact failed ExSSL connection, not a nearby successful tuple

TestPID23368, peer23371, HTTPowner23376, HTTPwriter23383, source23372,
Connection23378, nativewriter23379, Port5240 (full PIDs/Port in the log).
Client127.0.0.1:56781 -> server127.0.0.1:56780; live public peer endpoints
reverse exactly. Original Connection/writer monitors were established before
stimulus; case metadata ties all identities before the response.

- abandon entry caller IS controlling owner; application output pending, finite
  timer, write remaining119961ms; write owner is the HTTP upload worker.
- abandon succeeds and preserves sticky flag TRUE, drops write cursor, retains
  exactly the same immutable application output token.
- local close enters connected with flag TRUE and that pending output.
- BEFORE linger: Port alive, send_pend13378; linger{false,0}, send_timeout120000,
  send_timeout_close:true, buffer16640, sndbuf1024.
- linger setopts returns :ok; readback is {true,0}; Port STILL alive.
- Port.close returns true; Port.info subsequently nil; exact Connection/writer
  DOWN and HTTPwriter/source/owner DOWN pass BEFORE existing peer drain.
- peer drains98313 public plaintext bytes across6 recv calls, then original2s
  recv times out; recv_oct102050/send_oct1416/send_pend0, active99/buffer9216/
  recbuf485920; OTP receiver/sender waiting gen_statem.loop, empty mailboxes.

No matching writer error/output timeout/write timeout precedes this close.
For THIS actual failure, forgotten abandonment, native port retirement BEFORE
linger and failed zero-linger application are falsified. Port absence is not
a peer receipt, and this trace does not establish kernel TCP state/RST emission
or where native terminal delivery stalls. Six public recv calls are NOT six
TLS records; header collection may consume an accompanying body prefix, and
recv_oct includes TLS overhead. Do not infer missing ciphertext length by
subtracting drained plaintext from native counters.

Independent OTP client tuple127.0.0.1:56763 ->56762 also times out after48 recv
calls/786540 plaintext bytes. This weakens an ExSSL-only crypto explanation;
it does not prove a shared cause. Earlier16 native controls used infinite
send_timeout and did not enable send_timeout_close; finite120000/close:true
is an untested driver dimension, not a newly established cause.

Installed OTP29.0.2 public TCP close path was read directly (kernel11.0.2 and
erts17.0.2 source): inet.tcp_close -> prim_inet.close; zero-linger branch175–179
uses close_port;270–275 invokes erlang.port_close. A blind Port.close ->
gen_tcp.close substitution would reach the SAME primitive for this trace and
is not justified. No production behavior change made from that hypothesis.

### Accepted independent fixture correction

H3 test on_exit used Port.info(peer) followed by Port.close(peer), racing the
locally-created external peer natural exit. Task19 changes ONLY this cleanup
to close directly and tolerate ArgumentError for the already-closed known Port;
all test bodies/assertions/bounds/native error policy unchanged. Root wholefile
HTTP_QUIC_PHASE1_REAL=1/include integration/seed101:10/10 in6.5s, actual
ROUND12_H3_EXIT=0 + prompt. /tmp/http-fetch-round12-h3-cleanup.log.

### Next discriminator and remaining scope

First correlated-failure campaign STOPPED. A separate failure-only kernel
snapshot campaign is being prepared: exact bidirectional tuple after original
peer_timeout and before unconditional flunk, no extra network read. An initial
requirement for hard200ms spawn/read/reap was rejected as unsupported by public
Port.close external-child semantics; no misleading implementation was run.
Revised diagnostic-only authorization uses supervised Python kill/wait, bounded
output/collection and explicit elapsed/cleanup/inconclusive reporting; no hard
real-time OS guarantee, no weakened TLS assertion or production cleanup claim.
Final kernel campaign outcome is recorded below; restored-source checks follow.

### Kernel campaign: green run, discriminator NOT triggered

The bounded helper preflight used a dummy loopback tuple1<->2, not an actual
failed connection:32.444ms,83478bytes scanned, no matched rows, EOF/exit0 and
child12590 REAPED. Header layout recognized; no full host connection list logged.
/tmp/http-fetch-round12-kernel-preflight.log. This validates collection mechanics,
not any TLS or native-close hypothesis.

ONE fresh mixed full source run with failure-only helper, original assertions and
all previous scalar hooks:3186/3186, EXIT0 verified by ROUND12_KERNEL_EXIT=0 and
prompt; all9apps ran/integration+realQUIC optins/noexclusions. Log
/tmp/http-fetch-round12-kernel-source.log. ex_ssl788, QUIC249, core418, H3comp113,
runtime149, Fetch1232(including20doctests), WS138, WT24, SSE75. NO peer_timeout
or peer_kernel event occurred, so there is NO actual failing kernel snapshot.
No extra campaign launched to manufacture one. H3 cleanup passed this full run.
This green instrumented run does NOT resolve historical remote-close failures,
prove that H3 cleanup fixes TLS, or establish driver-vs-kernel-vs-OTP causality.

Temporary Source Connection hooks, HTTPS test hooks/helper invocation, and BOTH
strict guards were restored exactly from reviewed HEAD; four-file diff matched
the archived patch byte-for-byte before restoration. Original ConnectionSHA
0f0ad762fed7bb6307e374ea7e83d0699bd45cb21309cdb5140a1c74e2220e98 restored.
Diagnostic-only patch /tmp/http-fetch-round12-close-diagnostics-v2.patch (19823B)
and /tmp/http-fetch-round12-kernel-probe.py retained as audit/next-probe artifacts;
neither is an installed production path. Only the accepted H3 cleanup and docs
remain in the repository diff. No helper child was launched during the mixed
run; the preflight child was reaped. No changed public defaults or native policy.

Private direct-dial success orchestration was reviewed read-only: authentic
allocator/Connection/port enrollment+ownership-commit ACK before TLS, helper
done/outcome ACK before normal exit, exact original deadlines, all unpublished
native failure/creator-loss gaps remain unknown/unconfirmed. Current inert ready
attach/writer dispatch cannot support it unchanged. No new prototype or public
admission, no v1 revision, and no permission to silently clip a public infinite
setup with a short control budget was inferred from this design review.

Goal remains active. Task14 still needs a failing kernel/terminal-delivery
discriminator before a justified production fix; source/default/performance/
package/publication gates retain their explicit prior open conditions. AgentNote
search timed out again; repository execution evidence remains authoritative.

### Restored final source verification

Strict compile, whole-root format, Credo and Dialyzer all PASS (zeroerrors, zero
skips, same4 intentional unnecessary-ignore notices). Credo532files/54checks/
8876mods-funs, noissues. Root scoped lifecycle/inert+coreTLS+FetchH2+H3trailers
with integration/realQUIC/seed101:168/168 (88+27+53), noexclusions/opt-in skips.
Both exact final0f0 SHA guards pass; ordinary classic option forwarding and
peer-close plaintext drainage assertions retained. Actual ROUND12_FINAL_EXIT=0
AND prompt verified. /tmp/http-fetch-round12-final-{compile,format,credo,
dialyzer,scoped}.log. These are final restored-source checks; the3186 full run
above used explicitly described temporary diagnostics, and its green outcome
is not a production remote-close fix. git diff --check PASS.

## Round13 — finite native counterpart and private ownership protocol

Fresh HEADa050c62 clean before work; no round12 instrumentation installed.
Matched native control /tmp/http-fetch-round13-finite-native-close.exs runs
EXACTLYone active100/65536warmup/Port.close case per fresh VM, with native
client sndbuf1024/buffer16640/active:once; peer buffer9216/recbuf requested1024.
Both cases enable send_timeout_close:true, comparing ONLY client send_timeout
infinity vs120000. Both effective option sets checked BEFORE write AND close;
writer prim_inet.send/4 stably waiting with positive send_pend before/after
reverse17B, successful live zero-linger readback, original independent Port
monitor DOWN and owner/writer DOWN within original1s, then original2s peer drain.
Wire write units16406B are raw bytes here, not TLS records. No TLS or keys.

Initial control setup failed before native entry due module-attribute case
parentheses syntax; corrected without touching repository production code.
Actual paired logs /tmp/http-fetch-round13-native-{infinity,120000}-v2.log:
BOTH peer:econnreset in0ms, local retirement0ms, matching_options:true, Portnil;
ROUND13_NATIVE_EXIT=0 and prompt. Finite case native preclose send_pend10482
(client62661 -> peer62660), actual send_timeout120000/closeTRUE. Requested
recbuf is not effective recbuf (peer522416 at ready). This demonstrates that
finite-timeout mode alone is insufficient in this raw counterpart; it does NOT
falsify every TLS/OS interaction, identify cause, or resolve actual P0 failures.

ONE independent OTP public TLS pair using exact current HTTPS fixture listener
options and verified OTP client completed EXIT0, original monitors/cleanup:
/tmp/http-fetch-round13-otp-peer-opts.{exs,log}. Native peer tuple62975<-62976:
AFTERhandshake packet0/active98/buffer9216/recbuf325016/sndbuf146988/
exit_on_closeTRUE; AFTERcontrolledheader packet0/active97/recbuf324936, other
options same. Native mode is RAW at both observed stages; no framed-packet
control is justified or executed from this fixture. Public recv calls remain
distinct from TCP messages/TLS records. Test-only existing eight-field SSL
socket extraction yielded only native Port; no private TLS state was accessed.

Task20 private protocol tracer tests valid bound Observer, actual enrolled
allocator/setup/Connection/writer, allocator-owned REAL passive TCP with
acknowledged enrollment and roles31/allocations0/losses0/open before first new
API. Root meaningful missing-feature RED0/1: UndefinedFunctionError at
Observer.writer_ready/2, actual ROUND13_HANDOFF_RED_EXIT=2, no fixture error.
/tmp/http-fetch-round13-handoff-first-red.log. Runtime phase follows this one
vertical tracer, not a bulk imagined test suite. All implementation/negative
behavior results will be recorded below; no public/default capability admitted.

### Filtered terminal-message trace baseline and FD-close source audit

OTP29 isolated public :trace sessions can install receive match specification
BEFORE flags. RECEIVE head is [Node,Sender,Message]; the filter accepts ONLY
{:tcp_closed,exact_token} or {:tcp_error,exact_token,ATOMreason}, all other
messages suppressed in VM. Local artificial reference-token verification is
NOT native terminal visibility/origin, TLS handler processing, wire RST or a
privacy conclusion for sensitive TLS processes. No privacy flag was disabled.

First /tmp/http-fetch-round13-filtered-trace.{exs,log} executes once EXIT2: all
filter/disable/delivery/owned-actor checks passed, but harness incorrectly
compared session_destroy to:ok. Keep failed source/log unchanged. Corrected
v2 standalone source/log runs once EXIT0:2allowed/no unexpected, verified MS
before receive enable, flags[] after disable+delivery barrier, no postdisable
event, RAWsession_destroy:true, weak identity obtained via PUBLICsession_info
all/absent afterdestroy, receiver/tracer/watchdog original DOWN alltrue. No
opaque handle decomposition in v2; no network, native/TLS positive control,
repository trace hooks or shared root-VM flag changes. Tool baseline only.

Exact OTP-29.0.2 PUBLIC C networking/port source (not private SSL) was audited.
Parent read the relevant cached excerpts. inet_drv.c7382 sets
TCP_ADDF_LINGER_ZERO. [tcp_inet_flush12622](https://github.com/erlang/otp/blob/OTP-29.0.2/erts/emulator/drivers/common/inet_drv.c#L12622)
ORs this flag into discard_output and clears the ENTIRE queued output via
tcp_clear_output11713. Thus wait-for-driver-queue-flush DESPITE successful
zero-linger is not supported by this source branch. No full-window/kill-port
control was executed and no blind abort API change is justified.

[io.c3923](https://github.com/erlang/otp/blob/OTP-29.0.2/erts/emulator/beam/io.c#L3923)
issues monitor notifications BEFORE flush/terminate. The TCP stop path onUnix
reaches [desc_close5053](https://github.com/erlang/otp/blob/OTP-29.0.2/erts/emulator/drivers/common/inet_drv.c#L5053),
which hands the FD to driver_select(ERL_DRV_USE,0), invalidates its descriptor,
and actual sock_close occurs at [inet_stop_select12687](https://github.com/erlang/otp/blob/OTP-29.0.2/erts/emulator/drivers/common/inet_drv.c#L12687).
The [exact-tag callback contract](https://github.com/erlang/otp/blob/OTP-29.0.2/erts/doc/references/driver_entry.md)
permits stop_select after the port is closed (or inline). Logical Portnil/DOWN
therefore DOES NOT by itself attest physical FD absence. This supports a
possible handoff gap, NOT an actual2s delay or cause in the failed R12 tuple.
Runtime-specific kernel/FD observation still missing; version-tag source alone
is not instrumentation of the installed binary.

Public exit(Port,kill) is supported; its generic port-exit branch bypasses
flush, while Port.close uses normal. With successful zero linger normal flush
already discards output; both reach the SAME TCP stop/select-FD handoff. No
source evidence establishes that kill fixes this gap, so no substitution made.
Private role31 receipts attest original VM resource monitors only, not an
additional OS-FD/peer-receipt guarantee; public completion/default admission
remains gated on the original supported contracts and separate survivor/wire
evidence. No frozen v1 word, role bit, deadline or cleanup policy was changed.

A current upstream search found [OTPissue11319](https://github.com/erlang/otp/issues/11319):
it describes a triggered send-timeout with FD closed but Port still open, and
missing active-owner notification. The actual R12 client has ~119961ms
remaining, no matching native timeout and an explicitly closed/gone Port.
Those observations are NOT the same failure shape; no attribution or runtime
upgrade recommendation follows from that report. Its issue status alone is
not proof of a relevant fix. No upstream reproduction was executed.

### Private cooperative TCP ownership core — incremental acceptance

ROOTtracermeaningfulRED0/1 missingwriter_ready/2 then minimalruntimeGREEN1/1.
ONEbehavioratatime followups pass2/2,3/3,4/4,5/5,6/6 withactualexit0+prompt;
logs /tmp/http-fetch-round13-handoff-{first-green,owner-grant,pending-deadline,
committed-deadline,lost-commit-ack,six}.log. Lastsix run3.6s seed101.
ALLfixturesREALpassiveTCP created/ownedallocator,enrolledACK beforehandoff,
originalindependentportmonitor; noTLSactorattach/handshake/successpublication.
Reader31/31confirmed refersoriginalVMresourceobservations, notextraOSFDproof.

PrivateHandoffpurestate fixedroleidentities/originalObserver/challenge/grant/
spentphase; typedLedger.enrollment_view retains originalconsumedcreator tags,
Observer keepscreatorPID/monitor and verifiesmirror/liveoriginalparents.
Prepare requiresoriginalallocator-ownedexactenrolledPort andacknowledgedlive
Connection/writer; commitrequiresoriginalConnection actualNativeownership.
CooperativeGenServercaller convention+capability, notindependentSender/spawn
authentication. Originalrolebits/atomics/snapshots/ledgerproofstayfixed.

Sixbehaviors: genuineownershiptransfer/commit/cancel/exactoriginalPortDOWN;
wrongcaller/substitutedpeerPort/Connection/earlycommit/wrongnonce/replay/remint;
firstD500ms expiry despite later3000ms callerbudgets, helper_doneblocked;
COMMITTEDportoutlivesD500ms, freshbudgetreplay/remintdenied, helper_doneACK
thenoriginalallocatorDOWNnormalwhileportstillConn-owned/open/downmask1;
LOSTCOMMITACK viaPUBLICsys.suspend/resume: originalcallcap1000ms returns
EXACTacceptance_unconfirmed withinoriginalD5000ms (setupinfinity), native
ownershipunchanged, SAMEConn FIFOretryrejectsconsumedgrant, thenrealcleanup;
twoindependentattemptscrossready/grantsdenied, correctbothcommit, cancelA
withoutaffectingliveB/open31/down0 thenB independentcleanup. Ownelapsedtimer
only inpostcommitcase; nooriginaltimerprivateinspection/injectionclaimed.

Task20 REMAINSIN_PROGRESS: pendingactor/parentdeath/queuedDOWN, explicit
pendingcancel/latecommit, actualoriginalTCPclose orunexpectedthirdpartyowner,
purecreator/ref/Observermismatch/doneparent/wrongwriterparent, andpending
unknownpermit/stickyloss combinations stillneeddirectcases. Existingfoundation
regressions arenotindependentcoverageofallnewcombinations. Nopublic/default/
managed/completion/adoption gateisclosedbythiscore. Nativeconstructorfailure
identity remains a separate architecture gate.

OptionalEXTRAGLOBALmixcredo--strict EXIT14 (165design,30readability,16refactor
suggestions), includingfournewinitialtracerapplycalls. Existingbaseline
styleelsewhereuntouched; changedthosefourtoDIRECTtypedAPIafterGREEN. Required
configuredmixcredo reportsnoissues. InitialconfiguredpipelineDialyzerEXIT2
newObserver.update_handoff intentionallyignoredcancel_timerreturn; fixedwith
explicitdiscard matchingexistingObserverstyle. No ignoring/suppressingnew
warning. Failedlogs preserved /tmp/http-fetch-round13-static.log and
/tmp/http-fetch-round13-configured-static.log; finalchecksrecordbelow.

Independentread-onlyreviewfoundnoconcreteintroducedlogicbugs; noadditional
testswereclaimedbyreviewer. FirstCodexreviewproductfailedbeforeresult; fresh
reviewcompleted. Proceduraldeviation: reviewerthreeREADONLYshellcallsincluded
forbiddensandbox_permissionsparameterdespiteexplicitconstraint, noapprovalor
mutation. Lead stoppedthatcallpath; ownwritescontinueownedterminalwithout
thatparameter. Parentfinalsource/inert/publiccompatchecksremaingates.

### Round13 final source gates — P0 remains OPEN

Afterexplicitdiscardfix, ROOTcompile--warnings-as-errors +WHOLEformatcheck
+configuredCredo+Dialyzer allEXIT0. ActualROUND13_FINAL_STATIC_EXIT=0.
/tmp/http-fetch-round13-final-static.log:534files/noCredopriorityissues;
Dialyzer0errors/0skipped/4UNCHANGEDunnecessary-ignore notices. Noignore
entriesremovedornewwarninghidden. Fourdirecttracercallsandfinaldiscard
change ARE included in subsequentfullsourceExSSL794passed.

FinalrootpinnedPATH/MIX_ENVtest/sharedMIX_BUILD_PATH,
HTTP_QUIC_PHASE1_REAL=1 mix test --include integration --seed101:
3190/3192, actualROUND13_SOURCE_EXIT=2+prompt. No diagnostic hooks/pinchanges
installed, noexclusions. Appcounts794/794ExSSL (20properties774tests),
249QUIC,418Core,113H3companion,149Runtime,1230/1232Fetch,138WebSocket,
24WebTransport,75EventSource. Source log /tmp/http-fetch-round13-source.log.

TwoP0failures: log862-871 HTTP1WriteIdleWireTest:119 cancellationinterrupts
observedblockedupload, no {:peer_closed,peer} atORIGINAL8000ms finish/3:457.
Log1073-1080 HTTPSEarlyUploadTest:15 ex_ssl/http1/buffered/4000, peerstillopen
afterlocalcleanup atORIGINALsole2srecv; native countersrecv_oct103056/
send_oct1416/send_pend0, active99/buffer9216/recbuf484912, receiver/sender
waiting/gen_statemloop3/mailbox0. These are the historical failure shapes.
This run has NOcorrelatednativeclosehooks/kernel/FDsnapshot, so doNOT
projecttheearlierR12tuplelinger/closefactsontoit orclaimnewcausalevidence.
Wirecase stillneedsOWNproviderretirementproof. No re-run to minepassing
evidence, no deadline/error/pressure changes orproductionabortAPI swap.

CurrentConnectionSHA0f0ad762fed7bb6307e374ea7e83d0699bd45cb21309cdb5140a1c74e2220e98
andBOTHexistingstrictguards checkedunchanged; classicpublicConnection/writer/
HTTPfixturebodiesuntouched. NewprivateObservercode is not wired to classic
constructor paths. SourceP0gateNOTGREEN; sixprivatecorepasses/ExSSL794
are not a teardown fix, actualnativebirth/adoption/publicfacade/default/
managed/performance/package/publication admission. Task14 andTask20 remain
inprogress; nextprivateacceptance focuspendingcancel/death/actualportloss
andunknownpermits, nextP0focusACTUALfailingtuplekernel/physicalFDmetadata.

## Round14 — private handoff race coverage and physical-FD discriminator

Base1846fca/clean verified atroot; SourceConnection/runtime unchanged. All
implementation guards already existed: these are incremental negative coverage,
not fabricated REDs or a claimed new public feature. Parent owns new pure
handoff_test.exs; worker owns only observer_handoff_test.exs; Lead soleMix.

IncrementalROOT seed101: pendingcancelafterREALtransferbeforecommit plusONE
pureoriginalObserveridentitycase8/8 EXIT0; secondpurecase unchangedPID with
substitutedmonitorref rejected2/2 EXIT0; queuedWriterDOWN10/10 EXIT0; genuine
originalPortunexpectedowner11/11 EXIT0; queuedoriginalTCPDOWN12/12 EXIT0.
Logs /tmp/http-fetch-round14-{pending-cancel,pure-generation,queued-writer,
actual-owner,original-tcp-down}.log; actualexitmarkers+promptscollected.
Pure references are input facts, NOT actual monitor evidence. Initial local
Pythonfile-writing heredoc had SyntaxError before creating any test/native
resource; correctedwritercommand, no runtime workaround or hidden test failure.

Prepared/nativeConnection-ownedport cancel: originalcontrollerACK thenexact
ORIGINALportmonitorDOWN andReaderclosed31/down31/loss0/confirmed/cancelled.
QueuedWriterdeath: PUBLICsys.suspend Observer, killoriginalWriter/independent
exactDOWN whilePortstillConn-owned/Connlive, ALWAYSresume; thenoriginalPort
DOWN and31/31 confirmed failed/internal beforefirstD5000ms. No commit
rejection is inferred from cleanup. Genuinewrongowner: SAMEenrolledport
Conn->testPID, samevalidgrantcommitEXACTport_not_owned/open31/down0; actual
currentownerrestore->originalConn, SAMEgrantcommitsOK thennormalcancelproof.
OriginalTCPdeath: suspendObserver, originalowningConn Port.close(SAMEport),
exactoriginalPortDOWN/Portnil WHILEConn+Writerstillalive, ALWAYSresume then
31/31 confirmed failed/internal. This is nativeVMobject evidence independent
of actor death, not physical UnixFD or remote terminal receipt. Original
helper fixtures and P0 local1s/peer2s/parent3s/wire1s350ms8s unchanged.

PUBLICSDK26.2 headers read directly: libproc.h/proc_info.h declarations for
proc_pidinfo(PROC_PIDLISTFDS/PROC_PIDTBSDINFO),proc_pidfdinfo
(PROC_PIDFDSOCKETINFO), realstructsocket_fdinfo/in_sockinfo. Standalone
/tmp/http-fetch-round14-fd-snapshot.c218lines compiled-Wall-Wextra-Werror/
C11/-lproc EXIT0. ParentREADALL218lines plusSDKtypes. ChelpermetadataONLY: UID
checks/nonroot/noelevation, explicitoriginalBEAMPIDstartidentity andrequested
127.0.0.1clientlocalport->peerremoteport, nootherrows/payload/kernelhandles.
8192FDentries/list/512socketqueriesTOTAL/4matches/2KiBJSON/100mscooperative
budget; parent150msdecision+50mscleanup NOTkernelcall/reaphardguarantees.
Exactreturnedstructuresizes/truncation/races/errors=>inconclusive+emptymatches.
RepeatmatchedFD resamples generation/opaquehandles internally; comparePID
start and sortedFDlistsbefore/after. Positive observed ONLYwithinsample
readinterval; crossinvocationoriginalidentity stillrequires parentbaseline.
Negative alwayscomplete_scan_no_match_observed/negative_is_absence_proof:false;
no atomicFD+socketmetadatasnapshot, equalcompleteFDlists cannot excludeABA.
Compiledbinary notexecuted atthis checkpoint; onecontrolledpublicRAWpositive
fixture is being prepared for separate review BEFOREexecution. No native/TLS
Sourcehooks/diagnosticstrictpinchangesinstalled; actualP0physicalFDunproven.

### Round14 final private acceptance and control results

UnknownTCPpermit/readinesscaseGREEN: realroles15/open/alloc16/loss0; after
controllercancel allknownrolesDOWN15/admissionclosed/alloc16/LOSS16. NoTCP
identitywasreported, noNativeconstructorrejectionasserted. Fixedoriginal
1000msgrace thenoriginalObserverDOWNnormal; ReaderEXACTunconfirmed/
observer_unsealed, neverfalseconfirmed. Scopedpair13/13actualROOT
ROUND14_UNKNOWN_EXIT=0 /tmp/http-fetch-round14-unknown-permit.log.

FINALROOTcompilewarningsErrors+WHOLEformat+configuredCredo+Dialyzer EXIT0,
actualROUND14_STATIC_EXIT=0 /tmp/http-fetch-round14-static.log:535files/
noCredopriorityissues, Dial0errors/0skipped/4unchangedunnecessaryignores.
EntireROOTscoped apps/ex_ssl/test --include integration --seed101:801/801
(20properties781tests),83.3s; ROUND14_FINAL_EXIT=0+prompt,
/tmp/http-fetch-round14-exssl-source.log. This includesall13handoffcases.
Onlytestcode/documentationchanges; no publicSSL/production/runtime changes.
No newall9campaign to mine a pass: lastactualfullSource3190/3192 EXIT2 at
R13 remains the OPENP0gate. NoFixturepressure/deadline/error/strictpinchanges.
Selfauditofall11Observercases foundnoconcretefalseproof/unboundedwait;
finiteunknownsnapshotwithin1sgrace and500msprivateDcasesremain scheduler
headroom-sensitive. DirectqueuedcommitvsDOWN/doneallocator/wrongcreator
parent/morepreparationphaseedges stillOPEN; task20notmarkedcomplete.

FDcontrolscripts /tmp/http-fetch-round14-fd-control.exs53lines + .py125lines
were readfully beforeONEactualpublicRAWpositivecontrol. FreshBEAM46564,
client127.0.0.1:55619->55618. InitialPRE snapshot producedNOJSONby150ms;
helperkilled/reaped at152.763ms. ActualROUND14_FD_CONTROL_EXIT=2,
/tmp/http-fetch-round14-fd-control.log outcomeinconclusive/read_deadline,
actual_p0_cause_proven:false. No preFDmetadata/closecommand/postsample exists!
Fixturestoppednormally: allownedportsclosed/watchdogDOWN, allPYTHONdirect
childrenreaped, exitcodes[0,-9]. DoNOTcallpositivecontrolpassed, orinterpret
timeoutasFDpresence/absence/permission/APIcause. No actualP0hooksinstalled.

SeparateONE no-network/no-libproc ENTRYnegativecounterpart,
/tmp/http-fetch-round14-fd-entry-control.py/log: samebinary invalidPID0
rejectsbeforeprocqueries,150msdecision+50mscleanupunchanged. Actual
ROUND14_FD_ENTRY_EXIT=0; helperEXPECTEDexit2 invalid_arguments,fd_count0/
socket_queries0/emptymatches, reaped;9.475msparentelapsed. Itsuid0fieldis
unpopulatedidentitybecauseNO PIDwasinspected, NOTprivilegedexecution.
Thisdemotesa PERSISTENTgenericentry/argumentpathblockeratthatlaterinstant;
DOESNOTdistinguishinitialcoldlaunch frominitiallibproccall/socketquerydelay.
No positive rerun/pressure/budget widening. Next discriminator must separate
pre-main/entry/PID-info/FD-list/socket-info phases withboundedscalarstage
markers, thenreviewbeforeanyfreshcontrol; firstfailedartifactsstayunchanged.
ObserverNOTYETvalidatedforactualfailingTLSconnections. Csource/SDKcompile
isnotFDvisibilityproof. Metadata-controlwork staysinprogress alongsideP0.

## Round15 — creator provenance and bounded FD stage discrimination

BaseHEADf048d9c verified; production runtime/P0budgets/pins unchanged.
Scoped31/31: completedallocatorhelper_done BEFOREready forbids prepare
(handoff_resources_pending), actualTCPstaysallocatorowned; cancel31/31.
PureLedger.view retainsconsumedcreatorref+childidentity through unrelated
andoriginalDOWN; puredata NOTactualmonitorproof. Task21verified.
Setup->Writer alreadyrejectedATreservation invalid_role_edge; newrole6
casealloc0 thenlegitimateConn->Writer/privateReady+ConnACK/closed14/14.
Finalscoped32/32 actualROUND15_ROLE_EDGE_EXIT=0. No forgedunreachablestate.

C240lines/Python148lines stageobservercompiled0/publicSDK26.2; Parent
READALLinpages BEFOREonecontrol. Independentnonblockingpipe max16
constant E/B/L/S/R/O bytes/noFDvalues/handles/otherrows; JSONunchanged.
100mscoop/150msdecision50mscleanup unchanged. ActualR15controlEXIT2:
BEAM56257client56668->56667, NOJSON/NOstagebyteby150.005ms, killed/reaped
150.451ms. Fixtureportsclosed/watchdogDOWN/directchildrenreaped[0,-9].
NOPREmetadata/closeinstruction/POST. No-entryreceipt NOTpre-mainproof:
pipevalidation/write/delivery/schedulingalsomatter. Nolibprocstageobserved.
OriginalR14/R15failedartifacts preserved. Stage timestampsRECEIPTonly.
Separate44linewrapperreviewedBEFOREoneconditionalcontrol: ENTRYpreflight
PID0mustreturnexpectedexit2/invalid_arguments/EO withsamebudget, ONLYthen
freshnetworkfixture. Changedprecondition NOTcoldcauseproof. Resultbelow.

### Round15 final gates and changed-precondition visibility control

ACTUALROOT32/32 role-edge scoped exit0; requiredcompilewarningsErrors/
wholeformat/configuredCredo/Dial EXIT0 (535files/noCredopriorityissues,
Dial0errors/0skipped/4unchangedunnecessaryignore). WHOLEExSSLintegration
seed101:804/804 (20properties784tests),87.0s, ROUND15_FINAL_EXIT=0+prompt.
Logs /tmp/http-fetch-round15-{creator,role-edge,static,exssl-source}.log.
Runtime/publicAPI/sourceConnection andbothstrictpins unchanged. Lastall9
sourceR13 3190/3192 EXIT2 remainsP0OPEN; no rerunto minepass/defaultflip.

EXACTONE reviewedpreflightconditionalcontrol EXIT0 log
/tmp/http-fetch-round15-fd-preflight-control.log. ENTRYrejectPID0 expected
helperexit2/EO15.453ms BEFOREanyVM/network; uid0UNPOPULATEDnotprivilege.
FreshBEAM58214/client57867->peer57866/UID502/start1792614661.669483. PRE
5.993ms/exactFD44/generation8189179/TCPstateESTABLISHED4/queues0/0/
hiwats408300,146988/46fds5queries. EBLSRLBO observedbeforedecision.
PubliczeroLingerreadback+actualPort.close+exactoriginalPortDOWN+Portnil.
POST6.060ms/45fds3queries/EBLSLBO/complete_scan_no_match_observed,
NOTabsencecertificate. IdentitysamePID/start; no opaquehandlesprinted.
Allfixtureportsclosed/watchdogDOWN, allPYTHONdirectchildrenREAPED
[2,0,0,0], outcome pass_local_metadata_control, actual_p0_cause_proven:false.
Cold_stall_cause_proven:false; warmth/preflightchangedconditionEXPLICIT.
Original150msfailedcontrols stillinconclusive; no relabel/retrymining.
Thisvalidatesmetadata visibility ONLYunderobservedpreflightcondition,
notactualfailingTLSconnection/FDclosure/RST/cause. Nextpublic-peer
sockname/peername armingplan underread-onlyreview; NOproductionhooks.

Proceduralrecord: TWOdocedittoolcalls mistakenlysuppliedforbiddenSandbox
field, bothREJECTEDbyargumentvalidation BEFOREfilesystemoperation/no
approvalprompt. Writesmovedtoownedterminalwithoutsuchfield. Anoversized
terminaldraftleftanopenquote; grepverifiedNOdocmutation, SIGINTclearedit.
Shortboundedappendcommands thenwroteactualrecords. DoNOTuseedit/write/
bashtool schemasrequiringforbiddenfields; useownedterminalforwrites.

## Round16 — public peer correlation and original Wire resource monitors

Base HEAD9626135 was clean. Production runtime and strict pins stay unchanged.
Lead owns Mix and docs; Wire worker owns only its test; diagnostic worker owns
new temporary helpers and the temporary HTTPS fixture. No sandbox fields used.
The original HTTPS fixture was saved before edits as
/tmp/http-fetch-round16-https-original.exs, SHA256
b4f4f8b375d72aadf9799f8261199c478e4f85dd34bfdd601c3e873e0429c9d3.

Ranked predictions: same original FD/generation after failure supports delayed
physical retirement; no-match with valid baseline only narrows that hypothesis;
Wire original resource DOWN versus missing peer receipt distinguishes local
VM retirement from remote observation. Neither Port DOWN nor no-match proves
physical FD absence or remote reset delivery. No P0 fix is claimed.

Temporary FD supervisor72lines/preflight9/Elixir runner64 were read in full
before execution. Python owns C-child kill/reap and bounded stage/output;
runner monitors caller and recipient, requires child-reap receipt + wrapper
exit status + exact original diagnostic Port DOWN. The caller gets at most
200ms absolute budget; final cleanup never adds time to that caller budget.
Missing confirmation stays unconfirmed; Port.close is only disconnection.

First end-to-end RAW control passed actual ROUND16_RUNNER_CONTROL_EXIT=0.
Entry before VM: expected helper2/EO12.486ms/no PID inspected. TargetBEAM61680
client58957->peer58956, PRE FD44/generation8199621/ESTABLISHED4, POST no-match
with same PID/start1792616018.583976. C-wrapper elapses8.568/8.805ms; both
within caller deadline/child_reaped/helper0/wrapper0/diagnostic PortDOWN.
Original RAW Port.close/DOWN/Portnil + all fixture ports closed confirmed.
Logs /tmp/http-fetch-round16-{control-entry,runner-control}.log.

### Accepted Wire resource evidence

Only existing ExSSL cancellation adds public accepted-peer endpoints and a
unique reversed-tuple TCP-port discovery (one snapshot, cap2048, tcp_inet
filter before queries). Original client Port and connected owner PID are
monitored and rechecked live BEFORE abort. The exact two DOWN events plus
peer receipt share the ORIGINAL single8s finish window, with no added wait
before drain. Original peer recv8s-reset, pressure, source/writer assertions,
completion and other backends remain unchanged. VM resource evidence only,
not physical FD, RST or OTP sender proof. Task22 verified.

Whole Wire27/27 in20.2s, actual ROUND16_WIRE_EXIT=0. Two generated-constant
comparison warnings were fixed by function-head backend dispatch; focused
three cancellation variants passed3/3 in3.0s with warnings-as-errors, actual
ROUND16_WIRE_FINAL_EXIT=0. No repetition to mine a pass.

### First actual HTTPS failure with bounded postscan

Temporary fixture adds only public ssl peername/sockname baseline arming
after handshake/before headers, asynchronous/no added wait. Main accepts
only baseline already received before the trigger. At the ORIGINAL recv2s
timeout, one postscan is limited to min(now+200ms, original parent3s D).
Original local1s/peer2s/parent3s assertions and failure message unchanged.
Warm entry preflight ran before the Source VM, not a cold-launch proof.
Lead read all helper and changed fixture regions before one campaign.

Actual ROUND16_HTTPS_EXIT=2: seed101/max-failures1,11.8s,4/5executed passed,
aborted at FIRST failure, not a44-test gate. Case ex_ssl/auto/streamed/4000.
Target BEAM63146/client59360->peer59359, UID502/start1792616401.962086.
Baseline UNAVAILABLE before trigger: no original FD/generation correlation.

Postscan was observed/within_deadline: child_reaped/helper0/wrapper0/exact
diagnostic PortDOWN,9.459ms,53FDs4queries/EBLSLBO. Complete-scan no-match
for recorded tuple; NOT original-FD correlation or physical absence proof.
Original provider Connection/Writer DOWN and Portnil/local cleanup assertion
had passed before drain. Do NOT project R12 linger/Port.close hooks onto this
new tuple. Peer native counters105003/1461/send_pend0; active99/buffer9216/
recbuf482960; receiver/sender waiting gen_statem:loop/3, empty mailboxes.
The failure remains the original peer2s timeout, not a helper timeout.

Logs /tmp/http-fetch-round16-https.log and source-entry.log. Formatted
diagnostic source preserved /tmp/http-fetch-round16-https-instrumented.exs;
original371-line fixture restored BYTE EXACT before static gates. No rerun
after first meaningful failure; no production TLS hooks or hash-pin changes.

Required restored-tree compilewarningsErrors/wholeformat/configuredCredo/
Dial all actual ROUND16_STATIC_EXIT=0 +prompt;535files, Dial0errors0skipped,
4unchanged unnecessary-ignore notices. No strict-Credo/full9-green claim.
The last full9 R13 gate remains3190/3192 EXIT2; focused Wire acceptance and
actual HTTPS metadata do not resolve P0 or public lifecycle/default gates.

Next discriminator (read-only plan): installed OTP29 ssl public peername and
sockname dispatch transport metadata without established-state requirement;
transport_accept docs still warn most APIs need TLS. Before changing arming,
validate public tuple APIs on accepted TCP before handshake in ONE standalone
control. Launch baseline then allow normal handshake/readiness; consume only
already-ready data, no delay. Earlier natural TLS latency may help, never
guarantees baseline readiness. No custom-transport/DTLS/portable API claim.
All temporary artifacts retained as debug evidence; Source hooks removed.

## Round17 — prehandshake public metadata and startup latency

Base1962618 verified clean. No production/default/API/pin change. Read exact
OTP29 ssl peername2838/sockname3432 dispatch and transport_accept2384 warning:
current TCP implementation supports direct address queries, without a general
prehandshake/custom-transport/DTLS promise. Root read99-line standalone control
before one native run. Raw owner sent ZERO TLS bytes before address validation.

Actual ROUND17_PREHANDSHAKE_CONTROL_EXIT=0, targetBEAM65224/client60288->60287,
valid FD44/gen8211582/ESTABLISHED4. Entry EO13.52ms before VM. Public tuple
queries passed before handshake; client/server public closes, original raw
Port monitor, client actor, FD worker and watchdog cleanup all confirmed.

The baseline was NOT already ready at the handshake boundary:76ms boundary,
120ms full receipt delivery, versus6.115ms inside the Python C-probe interval.
Pending collection used only the original200ms probe deadline AFTER the zero-
wait boundary observation. Valid late receipt is not a ready-before-trigger
receipt. No earlier-arm-only Source campaign was run to repeat this gap.
A prepared diagnostic process before HTTP.fetch is now under source review;
changed preparation condition must be explicit, never production performance
or root-cause proof. Original R17 control/logs and all R14–16 failures retained.

Secondary source analysis: incomplete ciphertext can delay plaintext, but raw
recv0 delivers available plaintext; missing close_notify alone cannot explain
an outstanding2s recv timeout after transport termination is handled. Passive
close deferral between receives differs from an outstanding receive. Active99
excludes credit exhaustion at that snapshot, not read readiness. No new cause
established. Capacity recbuf is not kernel queue occupancy.

PeerNativeProbe62lines was read before ONE owned RAW public-metadata control.
Actual ROUND17_PEER_CONTROL_EXIT=0; captured exactly the original accepted
peer Port, open/connected/activefalse/packet0/exit_on_close true, zero counters.
After actual Port.close plus an independent original Port DOWN, observeafter0
consumed its own exact monitor DOWN: statesclosed, native APIseinval,
Portinfo nil; port_downtrue while original owner remained alive. All owned
fixture ports closed. This validates monitor discrimination, not kernel FD
absence. Same actor must capture/observe. The pre-TLS captured owner may be
the peer actor and is NOT the later OTP receiver; current connected PID is
separate metadata. No private TLS state or payload inspected.

Prepared bootstrap: Root read Python33/Elixir95/control104 lines before ONE
run. Python emits exact READY before any C entry, waits one bounded target
frame/5sTTL, then reuses immutable R16 probe once. Combined output2KiB and
metadata1KiB caps stay unchanged. Elixir enforces preparation200ms, observes
only once with independent original200ms absolute D, and requires C-child
reap + wrapper exit + exact diagnostic Port DOWN. Final owned50ms is outside
caller D. Caller/recipient/peer death cancels; no production supervisor or
TLS state inspection. Readiness is not a cleanup receipt.

Actual ROUND17_PREPARED_CONTROL_EXIT=0, BEAM66816/client60810->60809,
FD45/gen8216494/ESTABLISHED4. Prep67ms BEFORE any native client, completed
observation22ms BEFORE normal handshake boundary53ms; receipt already ready,
valid, all socket/actor/original raw Port/worker/watchdog cleanup confirmed.
C-probe6.616ms is only part of22ms. Explicit PREPARED changed precondition,
not performance or production-cause proof, not guaranteed ExSSL timing.

### One Source campaign: first failure outside probe coverage

Root read all changed fixture regions and immutable helpers, formatted only
the temporary HTTPS fixture, ran entry preflight then ONE root-scoped seed101
warnings-as-errors/max-failures1 campaign. Actual ROUND17_HTTPS_EXIT=2+prompt,
17.0s,27/28executed passed; remaining cases aborted. FIRSTfailure was
OTP ssl/auto/streamed/infinity, NOTExSSL. Original recv2s timeout persisted;
peer counters789772/2565/send_pend0, active96/buffer9216/recbuf320936,
receiver/sender waiting gen_statem:loop/3 with empty mailboxes.

This slice armed ONLYExSSL, so NOFD/native-debug records exist for the failing
OTP tuple. Success-case baselines were not logged either: cannot claim actual
ExSSL source baseline readiness or associate a control FD with this failure.
Same symptom across backends is NOT proof of one shared cause. No rerun after
first failure. This result identifies observation coverage, not a TLS fix.

Temporary Source prototype (+169lines before formatting) saved formatted at
/tmp/http-fetch-round17-https-instrumented.exs; original fixture restored
BYTE EXACT b4f4f8b375d72aadf9799f8261199c478e4f85dd34bfdd601c3e873e0429c9d3.
All diagnostics remain under clearly named /tmp debug artifacts. Runtime,
strict pins, public/default behavior unchanged; no production source shipped.
Logs /tmp/http-fetch-round17-{control-entry,prehandshake-control,peer-control,
prepared-entry,prepared-control,source-entry,https}.log retained.

Next fresh scope: prepare/capture BOTH original TCP TLS backends so the first
failure is observable. Keep all44 cases, first-failure stop, no skipped failing
OTP reference case, same1s/2s/3s bounds/pressure. A success-only summary after
original peer-closed assertion can record baseline-ready validity without IO
before trigger; timeout retains full original-identity observations. No new
control required merely to include OTP client: the prepared control already
uses that client. Do not repeat ExSSL-only observation hoping for a new order.
P0/default/public lifecycle/performance/package/publication gates remain open.

Restored-tree wholeformat/diffcheck/apps-diff actual
ROUND17_RESTORED_CHECK_EXIT=0+prompt. Only this evidence document remains
changed; no additional compile/Credo/Dial run was warranted after byte-exact
restoration of every app file (R16 checks remain applicable, not rerun totals).
Full-nine R13 gate remains3190/3192 EXIT2. No P0 completion claim.

## Round18 — first correlated actual ExSSL failure

Base5f6ca78 clean apps verified. Sole temporary HTTPS change extends frozen
R17 prepared baseline/native-peer coverage to BOTH normal backends, preserving
all original pressure/1s local/2s recv/3s parent assertions. Original private
provider checks stay ExSSL-only. Six small diff hunks reviewed; helpers and
original blocked-writer/pending/Python-timeout/peer-state blocks unchanged.
Success summary only after original peer-closed assertion, receiveafter0,
scalar booleans/backend; no IO before target assertions. Root read changed
regions then formatted fixture and ran entry preflight before ONE campaign.

Actual ROUND18_HTTPS_EXIT=2+prompt, seed101/warnings-as-errors/max-failures1,
18.3s,26/27executed passed; FIRSTfailure ex_ssl/http1/buffered/4000.
Remaining cases aborted, no rerun. The failure is the ORIGINAL recv2s timeout.

BEAM69211/UID502/start1792619431.864333, client61885->peer61884. Before trigger
validated original prepared worker receipt: FD50/generation8226334/ESTABLISHED4,
54FDs6queries, queues0/0, rcv_hiwat407040/snd_hiwat1024, Cportion8.683ms.
Completed proof at BEAMmono-576460733953, before drain snapshot-576460733927.
Same PID/start/tuple POST:53FDs4queries, Cportion8.814ms, no match observed.
Both receipts observed/within_deadline/child_reaped/helper0/wrapper0/exact
diagnostic PortDOWN. baseline_correlated and post_process_correlated TRUE,
original_fd_observed_in_sample FALSE. This is the first actual failing tuple
with original FD/generation baseline; no-match remains NOT physical absence
proof. Sampling intervals are not atomic, and postscan occurs after timeout.
Original ExSSL Connection/Writer DOWN+Portnil/local cleanup assertions passed;
R12 actual-linger/readback/Port.close hooks must NOT be projected onto this tuple.

Peer original captured owner0.843 remained alive/connected, no exact owner or
Port DOWN, driver states connected/open, packet0/exit_on_close true. BEFORE
drain at-576460733927: activefalse, recv_cnt100 EXACT, recv_oct98960, max1024.
At original timeout at-576460731925: active99, recv_cnt101, recv_oct101008,
max2048. Only ONE2048-byte native read was added across2002ms; send_oct1416/
pend0 unchanged. These are DRIVER observations, not kernel TCP state or queue
occupancy. Reference Rx/Tx waiting gen_statem:loop/3/mailbox0, buffer9216 and
recbuf486960 CAPACITY. No original peer Port retirement observed.

Success logs establish real Source pretrigger ready+valid for11successful
ExSSL cases (plus this failing ExSSL), and2successful OTP cases. Eight other
OTP successes logged readyfalse/validfalse, so prepared control is NOT a
uniform readiness guarantee. Five executed raw-timeout-peer cases have no
summary; total successful normal summaries21. Baseline timing coverage for
fast OTP paths remains incomplete, no new waits are authorized by these data.

Source qualification: Darwin FD_CLOSE=0; passive-to-active-N SETOPTS performs
synchronous tcp_recv BEFORE registering read selection. ONE2048 delivery can
come from immediate retained/raw input; it does NOT prove a subsequent poll
callback occurred. Default TLS internal window100 fits the observed transition;
no source rule intentionally suppresses EOF at credit99. R13 RAW already used
active100/reactivation and drained101chunks104448B/econnreset in0ms, weakening
generic active-N failure. It did NOT verify an exhausted/passive checkpoint
BEFORE client close. These are falsifiable hypotheses, not root-cause findings.

OTP blocked-upload cleanup aborts retained raw TCP with zero linger/close,
bypassing ssl.close; HTTP owner DOWN alone cannot prove TLS actors retired.
ExSSL abandoned branch calls close_transport BEFORE stop_and_reply(:ok);
the separate graceful waiter ordering must not be applied to this branch.

Next targeted observation: reverse the ONE postscan to original public peer
endpoints while original peer Port/actor still live, before timeout cleanup.
Same PID/start/UID; positive peer FD/gen and kernel tcp_state/rcv_cc distinguish
kernel state from driver-open. CLOSED0/CLOSE_WAIT5 differ from ESTABLISHED4;
rcv_cc positive with flat native counters supports further delivery investigation.
Negative remains no absence proof. Include launch/report/reap in remaining
ORIGINAL parent3sD, skip/inconclusive if insufficient; no added200ms outside D.
A separate RAW control can assert native credit delta100+tcp_passive BEFORE
close, hold passive while abandoning/zero-linger/readback/close original client,
then rearm100 ONCE under one absolute3s drain D. R13 has no such pre-close
checkpoint. Neither proposal has been executed or granted implementation yet.

Original HTTPS fixture restored BYTEEXACT b4f4f8b375d72aadf9799f8261199c478e4f85dd34bfdd601c3e873e0429c9d3
from /tmp/http-fetch-round18-https-original.exs. Formatted prototype retained at
/tmp/http-fetch-round18-https-instrumented.exs. Actual full metadata/error log
/tmp/http-fetch-round18-https.log and source-entry.log retained. Immutable
R15–17 helpers unchanged. No new runtime/TLS policy/default/public API shipped.
Whole restored format/diffcheck/apps-diff actualROUND18_RESTORED_CHECK_EXIT=0
plus prompt. Runtime/pins checked unchanged; last full-nine remains R13 red.
No additional compile/Credo/Dial totals after byte-exact restoration.
P0 remains OPEN; actual source identity correlation is progress, not a fix.

## Round19 — peer kernel remained established with empty queues

Base8b4a954 clean verified. One temporary fd_timeout observation change only:
reverse the single postscan to peer endpoints; preserve all R18 baseline and
assertion/pressure/success-summary code. Root read changed region before
format/preflight/ONE44-case campaign seed101/warnings-as-errors/maxfail1.
Probe D=min(now+200,parentD-50), >50 launch guard, reserved final owned50ms
inside original parent3sD. Stored original peer-live driver witness gates
launch; no new native queries/modes/recv waits. Roles baseline_client/post_peer
are explicit, client post NOT_SAMPLED and original peer FD baseline NOT_CAPTURED.

Actual ROUND19_HTTPS_EXIT=2+prompt,20.5s31/32executedpassed, FIRSTfailure
ex_ssl/http1/streamed/4000. Remaining tests aborted, no rerun. Initial terminal
inferred_idle was NOT treated as exit; actual marker/prompt were collected.

BEAM71482 UID502/start1792620642.508763, client62923->peer62922. Pretrigger
CLIENT baseline valid FD50/gen8235782/ESTABLISHED4,54FD6queries, queues0/0,
snd_hiwat1024, Cportion7.407ms/fullproof beforetrigger. Peer post reversed
62922->62923 positively observed CURRENTFD51/gen8235784, ESTABLISHED4,
rcv_cc0/snd_cc0, rcv_hiwat484000/snd_hiwat146988,53FD5queries,Cportion7.341ms.
Same PID/start/UID and reversedtuple correlated, childreaped/helper0/wrapper0/
exactdiagnosticPortDOWN/withinD. These elapsed values exclude Python bootstrap;
full delivery is bounded by probe D, not claimed7ms. Client post NOT_SAMPLED;
no original peer FD/gen baseline. Do NOT import R18 client-no-match here.

Original peer Port/owner0.932 alive connected/open throughout driver snapshots.
Before drain-576460731844 activefalse/count100/100889B; timeout2001mslater
active99/count101/103961B, ONE3072-byte added delivery. Post-kernel-sample
error counters still103961B/send1461/pend0; Rx/Txwaiting/empty, buffer9216,
recbuf484000 CAPACITY. Original ExSSLactor/Portnil assertions passed locally.

At sampled interval, kernel ESTABLISHED with empty queues does NOT support
already-kernel-closed-but-driver-open or queued-unread explanations. It leaves
transport termination unresolved; no causal fix claimed. Snapshots are not
atomic/continuous, original P0 case differs from R18 and earlier examples.

R13 RAW ALREADY used CLIENTactiveonce, rearmed after synthetic reverse bytes,
verified effective once at close, and separate blocked writer. Server ENV mode
active100 is different from client mode. None of those generic conditions is
a new control. Missing checkpoint: peer had not consumed+acknowledged EXACT
100native messages+tcp_passive/recv-countDELTA100+activefalse BEFOREclose.
Next one-control extension retains R13 everything else: prepare C baselines
BEFOREpressure; finish original writer-blocked/reverse-byte/client-once checks
BEFORE final peer-passive acknowledgement, then close immediately with no
extra scan/wait. Since passive event is consumed, explicitly rearm100 ONCE at
original drain authorization, observe under one original absolute deadline.
This is only a proposed RAW synthetic control, not implemented/executed yet.

Original fixture restored BYTEEXACT b4f4f8b375d72aadf9799f8261199c478e4f85dd34bfdd601c3e873e0429c9d3
from /tmp/http-fetch-round19-https-original.exs. Root-formatted prototype
/tmp/http-fetch-round19-https-instrumented.exs and full source-entry/https logs
retained. All immutable native/helpers remain unchanged. Runtime Connection
SHA and strict pins verified unchanged, no source hooks left. Actual restored
wholeformat/diffcheck/apps-diff ROUND19_RESTORED_CHECK_EXIT=0+prompt. Only
this evidence document changed; no repeated compile/Credo/Dial totals.
Last full-nine R13 gate still red; P0/public/default/package/publication OPEN.

## Round20 — RAW pre-close passive checkpoint control

Base7c52843 clean verified. Root read complete frozen R13 control218lines.
R13 already has clientactiveonce, reverse17-byte read/rearm, separate native
blocked writer and active100 peer drain; these conditions are NOT novel.
Fresh source-only scope is one NEW /tmp RAW clone with verified100-message
plus tcp_passive/activefalse/recv_cntDELTA100 checkpoint BEFORE close, after
original writer/reverse-byte checks. Close follows checkpoint ACK immediately,
no inserted scan/wait. Drain explicitly rearms100 once because checkpoint
consumed passive event, retains ORIGINAL2s absolute deadline/2.1s reporting.

FD integration deferred explicitly: two helper start/receipt/worker-retirement
paths plus prepressure gating would expand focused clone beyond100newlines.
No kernel FD/generation proof will be claimed from this VM-only control.
Original socket options/payload/zero-linger readback/public Port.close then
writer-kill order retained. Strict result oracle separates terminal timeout
from setup/checkpoint/cleanup inconclusive; exit0 must not mask rescued error.

Root read ALL311newlines before ONE execution with explicit active100/infinity/
show_reset=true; old218line R13 unchanged. Actual
ROUND20_NATIVE_PASSIVE_CONTROL_EXIT=0+prompt. Client63786->peer63785.
Checkpoint100messages/102400B and originaltcp_passive; recv_cnt1->101 EXACT
delta100, activefalse, original client owner/Portlive. Existing writer blocked
in prim_inet:send4 with send_pend10482; effective clientactiveonce. Checkpoint,
actualclose and terminal metadata share BEAMmono-576460750497 (ms resolution;
not atomic). ZeroLinger setoptsOK/readbacktrue0, actualPort.closeTRUE,
matching_optionsTRUE. Local original owner/writer/clientPort DOWN0ms. One
explicit peer rearm delivered ONE2048B then econnreset0ms under original2sD.
Original peer/peerPort DOWN confirmed before report D, captured6object cleanup
VMretiredtrue, watchdog retired; no OS-FD absence claim.

Conclusion limited to this control: verified pre-close credit exhaustion plus
clientonce/blockedwriter/zeroLinger was NOT sufficient to reproduce missing
terminal. TLS/P0 still red; no framework/default/native primitive fix inferred.
No pass mining/matrix/repeated control executed. Newsource frozen at
/tmp/http-fetch-round20-native-passive-control.exs SHA256
16d87caa9c9fab89c08bc5b97024bb02b9c957c5c99446cff370ffeb15fa366f;
full log samebasename.log. Original R13 SHA256
722943427221d857dce118c84430d0ff0d0b1b5d29154a3d44dd9b1f9b9870fe unchanged.
All preexisting debug helpers/logs/source snapshots immutable. No production
or test source changes in this round, only this evidence document.

Next discriminator proposal (NOT implemented): actual same-instance close
receipt plus both endpoint baselines/postscans. R12 close-diagnostics-v2.patch
exists:139 actual linger/readback/Port.close and39 abandon ack; do NOT reapply
its broad IO.inspect hooks. A pinned parent/tag can receive one bounded scalar
receipt after native close: original VM Port/Connection PID, abandoned/output
booleans, existing pending result, actual linger set/readback and close return/
error class, monotonic call bounds. No IO/helper/waits or whole TLS state.
Strict source pins require temporary Root-owned coordination/restoration.
Client+peer FD baselines before pressure, postscans at original timeout before
peer cleanup within SAME original parent3sD including cleanup reserves.
Timestamp/interval boundaries non-atomic; negative scans not absence proof.
This would close the current instance-correlation gap rather than combine
R12 actual calls, R18 client negative and R19 peer established across instances.
No implementation or execution grant was issued for this proposal.

Verified apps-diff empty, runtime/strict pins unchanged, frozen R20 hash exact.
Documentation-only boundary: no new Mix/compile/Credo/Dial runs justified;
R19 restored wholeformat check and historical test results remain applicable,
not new totals. P0/public/default/native lifecycle/package/publication OPEN.

## Round21 — same-instance executed close and dual endpoint observations

Base3dd7dab clean verified. Root read current close_transport, R12 preserved
patch139ff and original strict-pin regions before exact backup. Temporary
Root-owned hook only at native terminal boundary: per-Connection persistent
parent/tag pin, existing pending lookup and unchanged sticky abort decision,
actual linger-set result, pinned-only ONEpublic linger readback, actual
Port.close return/ArgumentError class, original VMPort/selfPID/before-after
monotonic microseconds. One2KiB-bounded receipt asynchronously sent AFTER call.
No IO/helpers/waits/whole TLS-state/key inspection in Connection; missing
receipt remains unconfirmed. Port.close=true/VMDown still not kernel proof.

Root formatted that temporary source and coordinated both strict test hashes
to074b93f8d0496210595025e42bd4b4a211113fc118e0cf0308e9cc8ddcb6b1b9.
Original source and pins backed up separately before changes, all to restore.

Temporary diagnostic compile actualROUND21_DIAG_COMPILE_EXIT=0+prompt.
Source audit qualification: desc_close invalidates driver fields/drops
ERL_DRV_USE, inet_stop_select later performs sock_close. This permits VM/kernel
ordering gap but does NOT hide a still-open OS descriptor from proc_pidinfo.
R15 same_socket stabilizes FOUND rows only; equal FD-number/type lists cannot
make unobserved contents atomic or prove no other holder. If same-instance
client-no-match/peer-original-EST4 occurs, current validated public observers
will not establish callback-stage completion or alias ownership. Positive
original FD-slot/generation evidence would be a possible later discriminator;
no helper/native instrumentation is changed or authorized in this slice.

Root read changed HTTPS sections before format: shared200ms preparation for
TWOworkers BEFOREfetch, async client+peer at accept/shared200D, each baseline
ONLYafter0 beforetrigger. ExactConn/tag/Port close receipt ONLYafter0 after
original local assertions, same-parent FIFOcontext beforedrain. Original2s
timeout launches ONEclientpost THENONEpeerpost each within
min(now+200,parent3sD-50), >50guard/ownedcleanupreserve. SAMEroleFD/gen only;
PIDepochUID/tuples validated. FiveFDlogs2KiB+boundedclose/nativeINSPECT<16KiB.

FIRST instrumented campaign actualROUND21_HTTPS_EXIT=0+prompt,20.0s44/44.
No failing close/bothrole capture; success logs cover CLIENT only. No uniform
peer readiness or actual close result claim from scalar success logs.

Fresh explicit counterfactual: restored ONLYConnection+both source pins,
kept EXACT same formatted dual-role HTTPS diagnostic including pin registry.
This changes actual close hook, not pressure/assertions/timeouts. ONEcampaign
seed101/warnings-as-errors/maxfail1, no repeats/pass mining. Actual
ROUND21_NO_CLOSE_HOOK_EXIT=2+prompt,14.7s16/17executedpassed, FIRST
ex_ssl/http1/streamed/infinity original2s timeout. Rest aborted, no rerun.

Same-instance BEAM76829 UID502/start1792622875.910589/client64732->peer64731:
PRE clientFD49/gen8253198 EST4 queues0/0 sndhi1024; PRE peerFD51/gen8253200
EST4 queues0/0 rcvhi279008. Both ORIGINAL workers already received before
trigger: completed BEAMmono-576460736155/-576460736154. Cportions7.466/8.723ms
exclude full startup. Same PID/start/UID/role tuple POSTclient completeNoMatch
53FD4query/C5.686ms; POSTpeer SAMEORIGINALFD51/gen8253200 ESTABLISHED4,
queues0/0 rcvhi485936,53FD5query/C7.107ms. All four full receipts observed/
withinD/childreaped/helper0/wrapper0/exactdiagnosticPortDOWN. Both-role
baseline/process/tuple validated. Client original observedfalse (NOTabsence
proof); peer original observedTRUE first same-instance positive correlation.

Original peerowner0.751/Port live/openconnected, BEFOREcnt100/98960B/active
false at-576460736126; timeout2001ms later cnt101/102032B/active99, ONE3072B.
After BOTHpostscans counters102032/1461/pend0 unchanged, RxTxwaitingempty,
buffer9216 recbuf485936 CAPACITY. Originallocalactor/Portnilassertionspassed.
CLOSEreceipt UNAVAILABLE is EXPECTED because this counterfactual removedhook.
Cannot project actual calls from R12 or successful hooked campaign onto this
failing instance. Hooked44pass versus restored-hookfailure suggests observer
perturbation, TWO runs do NOT establish cause or readback as repair.

No further Source campaign21. Both endpoint correlation gap is now narrowed;
executed-close-plus-failure correlation is still missing. No native primitive
fix or P0 completion inferred. Snapshots remain non-atomic/negative-limited.

Source audit rules out shutdown(read_write) as guaranteed pre-close barrier
when driver_sizeq>0: inet_drv12356 setsPENDING_SHUT_RDWR and returnsOKWITHOUT
kernelshutdown; 14216/13878 trigger onlyafteroutputempty. ZeroLinger discards
queue onlyatflush12622. Empty queue inside12364 permitsimmediatekernelcall
but priorpublicsend_pend snapshot is not atomic. No swap justified.

Next proposal: reduce ONLYthe actual-close observer (no readback/extra native
queries), retain original-call return/event before-after scalars, same dual
baseline/timeout capture; no callback-stage proof from VMDown/negativeFD.
If failure persists, original client FD-SLOT query regardlesstuple would
narrow positive-current-generation versus reuse, but needs independently
reviewed NEWhelper/controlledtest; immutable existingC cannot report that.
No next source/helper grant issued here. No hidden-pollset-FD explanation.

All FOUR files restored BYTEEXACT: Connection+2strictpins+HTTPSoriginal,
sourceSHA0f0ad762fed7bb6307e374ea7e83d0699bd45cb21309cdb5140a1c74e2220e98
andHTTPSb4f4f8b375d72aadf9799f8261199c478e4f85dd34bfdd601c3e873e0429c9d3.
Original/Rootformatted snapshots at/tmp/http-fetch-round21-{connection,tls-pin,
h2-pin,https}-{original,instrumented}.exs. Full diagcompile/https/counterfactual/
entry/restored-static logs retained; immutable older artifacts untouched.
Actual restored compilewarningsErrors/wholeformat/configuredCredo/Dialyzer/
diffcheck/apps-diff ROUND21_RESTORED_STATIC_EXIT=0+prompt. Credo535files/
noissues; Dial0errors0skipped/4unchanged ignore notices. Build artifacts now
originalsource. LastfullnineR13 red remains; P0/public/default/packages OPEN.

## Round22 — reduced after-call-only observer did not reproduce

Base896dc39 clean verified. Root read current close_transport and frozen R21
hook, backed up FOURoriginal files before installing exact R21formatted HTTPS.
Reduced ONLYnativeCloseobserver: removed preclose persistent lookup, preclose
clock and EXTRAlinger readback. Original pending lookup/stickydecision/native
setopts/Port.close order unchanged. Actual result variables are captured; only
AFTERPort.close lookup perConnection test pin, boundedsend<=2KiB with original
Port/Conn/abandoned/outputBool/pending/actualLingerSet/actualCloseReturn/post
monotime. readback:not_sampled/observer:after_native_call_only explicit.
No nativequery added, no IO/helper/sleep/wait or wholeTLSstate.

Root readback+formatted hook; strictpins temporarily coordinated to
2014a43a6f4a4e7ee2bf6822cd74c0ec9b51529ee85cf9a2365a1237aad5aec8.
CompilewarningsErrors0 then entrypreflight before ONEsourcecampaign. Actual
ROUND22_HTTPS_EXIT=0+prompt,21.2s44/44 seed101/warnings-as-errors/maxfail1.
No firstfailure, so NOactualclose-receipt output or failingbothrolecapture.
SuccesssummaryCLIENTONLY; no uniformpeerReady/completion/cause claim.

R21hooked44pass/R21unhooked16of17fail/R22postonly44pass are differentVM
observations. These do NOT establish causality or a repair. Removing extra
readback did not make failure reappear this time; readback is not established
as necessary for the observed passes. After-call send and broader diagnostic
scheduling remain possible perturbations. No repeatedmatrix/passmining.

Read-only upstream XNU audit (NOThost-build-pinned): kern_descrip
fp_close_and_unlock runs knote_fdclose/fileproc_drain before fdrelse, then
fg_drop calls fo_close only on final fileglob reference. FDtable removal MAY
precede close completion; no specific alias/knote/callback holder established.
soclose_locked initiates protocol disconnect/detach before final socket-ref
release, so retained memory ALONE does not explain retainedESTABLISHED.
Sources: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_descrip.c
and https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c
Actual host kernel stage/duration/holder UNKNOWN. Not a pollset-hidden-FD claim.

Future runtime inventory can record public erlang:system_info(check_io) and
(kernel_poll), implementation-dependent, no socket-specific proof. OTP29 flags
+IOt pollthread count/+IOp pollsets both default1 with platform qualifiers:
https://github.com/erlang/otp/blob/OTP-29.0.2/erts/doc/references/erl_cmd.md
Do NOTassume +IOt1 changes current runtime; inventory REQUIREDbeforeany
changed-runtime control. No runtime flag/control executed this round.

Next measurement proposal: independent NEWoriginalFD-slot helper mode, query
client-original numeric FD regardless tuple and return only type/gen/state.
Current immutable tuple-scan helper cannot discriminate a filtered-out original
slot. Newsource/control must be read before native exec; negative notsocket
destruction/callbackproof. No source/helper implementation grant issued yet.

All FOUR files BYTEEXACTrestored: Connection original0f0ad762..e2220e98,
HTTPSb4f4f8b3..429c9d3, both strictpins originalfullsourceSHA. Freshsnapshot
/tmp/http-fetch-round22-{connection,tls-pin,h2-pin,https}-{original,instrumented}.exs;
fragment22-receipt-fragment.txt/diag-compile/source-entry/https/restored-static
logs retained, all priorhelpers unchanged. Actual restored
ROUND22_RESTORED_STATIC_EXIT=0+prompt compilewarningsErrors/wholeformat/
configuredCredo/Dial/diffcheck/apps-diff. Credo535filesnoissues, Dial0errors/
0skipped/4unchangedignorenotices. Runtimebuild noworiginalsource. Lastwhole9
R13red3190of3192 unchanged, P0/public/default/perf/packagepublication OPEN.

### Independent private native allocation foundation

Fresh task24 scope TWOnewfiles only, coordinated task20owner ACK beforewrite.
Lead+worker read ALLfive ex_ssl architecture docs/currentObserver+Receipt+
manualhandofffixture+P1/P2plan. NativeTCP is private P2 transport allocation,
not public lifecycle/P1compatibility acceptance. Alreadyenrolled trusted
allocator supplies original ABSdeadline alreadyclipped to setup. Validate
literalIPv4/port/ABS BEFOREpermit; reserveTCPbefore nativeentry, recalculate
SAMEremainingtime beforedial; force inet_backend:inet/inet/binary/passive/raw.
NoDNS/newactor/newprotocol/adoption/transfer/TLS/publicAPI/default changes.

ReturnexactnativePort ONLYafterObserverenroll_port:use+postD/alivecheck.
Observer records ORIGINAL typed Portmonitor+creatorgeneration beforeexposure.
Knownlate/rejectedPortsclose; attempt is not physicalretirementproof. Native
errno/exception afterentry NEVERreject_before_native or releaseunknownpermit.
Hiddenobjectinterval ofgen_tcp remainsunproved; allocatorbirth/failed-dial
identity/TLSactorattach/setupoutcome/publicfacade integrations stayOPEN.
Before opaque-boundary correction: NativeTCP67lines/test136lines. IndependentREADONLYreview
foundnoblockingdefect, scopedtrustedcaller/provenance limits explicit. Four
tests do NOT directlyforce late-success or lost-enrollment-ACK cleanup branch.

Rootactualcompilewarnings0 +ALLlifecycle91/91 seed1019.6s actual
ROUND22_NATIVE_FOCUSED_EXIT=0+prompt. Fournew async tests: original allocator
Portownership/passive/raw/binary/roles17alloc0 thenEXACToriginalPort+allocator
DOWN andReaderconfirmedroles/down17 AFTERObserverabsence; unauthorizedNOdial
accept0; invalidIPv4/IPv6/DNS/port/infinite/expiredD NOreservation+NOdial;
realclosedloopbacknativeREFUSED retainsalloc16/roles1/down0/loss0, allocator
kill thenoriginalfixed1000ms grace exitsUNSEALED+Readerunconfirmed.
No syntheticDOWN/proof from mere nativeerrno/helperdeath. Fixture2sReader
wait leavesfixedobservergrace unchanged; no P0timeouts/assertions changed.

NewlibrarySource justifiesONE fresh whole-nine run rather than repeatedly
mining the HTTPS case: HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test
--include integration --warnings-as-errors --seed101 (no maxfail/no exclusions
beyond repository-authored defaults). OriginalHTTPS/Connection/strictpins are
restored; noR22nativeFDdiagnostic instrumentation present. WholeExSSL portion
808/808 (20properties788tests)82.7s; QUIC249/2498.5s, finalsource result below.

FRESHWHOLE9 actualROUND22_FULL_SOURCE_EXIT=1+prompt, all nine executed:
ExSSL808/808,QUIC249/249,Core418/418,H3companion113/113,Runtime149/149,
Fetch1228/1232,WebSocket137/138,WebTransport24/24,EventSource75/75.
Sum3201/3206, FIVEactual assertion failures, NOTa greenumbrella. ExSSL four
new tests passbothfocused+fullgate. Fetch200.4s/WebSocket10.3s.
--warnings-as-errors also reports existing bitstring-size pin warnings in
unchanged test sources; finalERRORabortedduetowarnings, explainsEXIT1 instead
ofordinaryassertionEXIT2. Productioncompile/newmodule warnings0 separate.
No rerun droppingflags, no warning hiding/source exclusions.

Five failures retained verbatim in /tmp/http-fetch-round22-full-source.log:
1. Fetch trailer-wire: undeclared upload trailers, peer accept202 returned
   {:error,:einval}, linked peer MatchError; unchanged test61. Cause unresolved.
2. Fetch Wire119 ExSSL blocked-upload cancel: missingpeer_closed8s.
3. Original HTTPS ExSSL/auto/buffered/infinity peer2s stillopen, recv101026B,
   send1416/pend0/active99/buffer9216/recbuf486944(capacity),RxTxwaitingempty.
4. Original HTTPS ExSSL/auto/streamed/infinity peer2s stillopen, recv104098B,
   send1461/pend0/active99/buffer9216/recbuf483872(capacity),RxTxwaitingempty.
5. WebSocket verifiedWSSslowpeer ExSSL cancellation proxy_boundary200/222:
   WSSsocketnotclosed. No per-tuple nativeFDmetadata/hook in this whole run.

First post-feature static actualROUND22_NATIVE_STATIC_EXIT=2: compile/format/
Credo537filesnoissues PASSED; Dial1NEWcall_without_opaque atNativeTCP20.
Head destructured Receipt.cell/observer and passed structurally refined map
to Observer.reserve_child expecting opaqueReceipt.t. No ignore added. Lead
fix keeps opaque struct identity and uses existing Receipt.observer accessor,
then localPID/nodevalidation; no cell-field introspection outsideReceipt owner.
Original validReceipt contract/trustedprovenance/port/deadline/order unchanged.
Forged internalReceipt.cell authentication is NOTclaimed by this private helper.
Focused regression +finalstatic below; no whole-nine repeat/passmining.

First opaque fix stillRED2: empty %Receipt{} head also peeled opaqueness at
Receipt.observer; redundant is_pid on the accessor-returnPID created unreachable
false-pattern. Final69line constructor keeps opaqueReceipt argument untouched
through its accessor, node-onlylocal check; no internalcell/typepeek. Valid
Receipt.t is a trusted programmer precondition. Malformed internal Receipts
mayraise ataccessor; publicdrivercontext validation remainsfuturework.
Ordinary badtargets/port/ABS still return invalid_arguments. No observer/receipt
API or ignore changes. ActualROUND22_NATIVE_OPAQUE2_EXIT=0+prompt, compile0
Dial0errors0skipped4unchangedignores/18.8s. Worker reviewedfinalfixread-only.

FINALacceptedcode actualROUND22_NATIVE_FINAL_EXIT=0+prompt: production
compilewarningsErrors0, ALLlifecycle91/91 again8.6s, wholeformat0, configured
Credo537files/8943mods-funs/noissues0, diffcheck0. FinalDial0 fromopaque2
checks same accepted69line source. Whole9/ExSSL808 above precedes this type
boundary correction; finalfocused/type/static gates coveracceptedcode. No new
full-nine repeat because publicruntime/validReceipt resourcepath unchanged.

Acceptedtask24increment is nativeentry/enrollment foundation, NOT actual
allocator/setup birth, hidden-error object proof, TLS attach/readiness/public
lifecycle/default/managed/completion support. P0fivecurrentfailures+oldtest
warnings stayreleasegates. Next independentfoundation: inertallocatorbirth
withoriginalpermit beforecallingNativeTCP, separatefuturegrant/review needed.

## Round23 — actual allocator birth and isolated original-FD-slot control

StartHEAD847556a/worktreeclean verified by Root. Task25 owns ONLYtwoNEW
allocator module/test files; task26 owns ONLYthreeNEW/tmp FDslot diagnostic
files. Allold provider/observer/receipt/nativeTCP/handoff/tests and R15–22
helpers immutable. Root owns docs/format/build/native execution. Existingfive
ExSSLarchitecture documents are unchanged from fullRound22read; worker freshly
read five/currentP1-P2/task20/task24 before proposal, task20owner ACKed disjoint
scopes beforewrite. No publicSSL/default/completion/managed acceptance implied.

Allocator design correction: GenServer.start is UNLINKED so Observer killing
allocator cannot kill original caller/controller. Inert init creates original
parent/recipient/Observer monitors+fenced original expiry, returns BEFORE ANY
ObserverRPC/native. Selfenroll precedesNativeTCP, publication is nonce-bound
allocation only, NOT deliveryACK/TLSready/setupoutcome. Holds original TCP
ownership while pending; no handoff support/lifetime-TLS deadline introduced.
Startup/native errors do not reject/clear unresolved original permits. Valid
opaqueReceipt is a trusted programmer precondition/accessors only.

Late process identity nuance: Observer530 permits the original self-PID even
after death and installs typed monitor, BUT handle_call130 first checks
now<requestD. Thus RPCcap1000ms expiring before a longerD can still admit
late PID if resumed BEFORE D. A testD200ms suspended until actorDOWN/AFTER D
must reject its queued enrollment, retain unknown rootallocator1, and remain
unsealed after original fixed grace. No TCPpermit/nativecall existed in this
case. Separate precancel-then-construct with STILLvalidD may account actual
late born PID, kill it and seal confirmed allocator/down1. These cases are
distinct from native connect REFUSED, which leaves unknownTCP16 after birth.

Readonly shutdown follow-up from Round22: queued-output test at inet_drv12356
excludes SHUT_RD; public gen_tcp.shutdown(tcp,:read) goes directly to kernel
shutdown even with pendingoutput. It sets no pending/write-done flags, clears
no pendingflags and changes no selection/connected bookkeeping in this
handler. Validation/errno still apply. It proves an immediate syscall attempt
ONLY: local read shutdown proves neither peerFIN/RST, write termination, FD
destruction nor peer protocol termination. Observer-sensitive passes do not
justify swapping production abort primitives. No such source change executed.

### Allocator actual source and execution

Task25 worker froze76lib/88test lines with fullreadback/hash/guards and closed
TTY63. Root reviewed ALLsource, replaced broad stop catchall with explicit
:stop/false/error clauses (unexpected programmer failures stay visible), removed
tautological alive(self) assertion; links check plus Reader aftercancel prove
caller survival. Rootformat final118librarylines/113testlines. Readonly review
confirmed original exactPID/ref monitor matching, absolute monotonic timer/ref
fence, before-native enrollment and post-native gates; no blocking scope defect.

ActualROUND23_ALLOCATOR_FOCUSED_EXIT=0+prompt: compilewarnings0 then ALL
lifecycle95/95 seed1019.4s. Fournew actualconstructor async cases: role17
alloc0/originalPort ownedbyactualallocator/unlinkedcaller survivescancel/
EXACTprocess+PortDOWN/Readerconfirmedroles-down17; pre-enrollcancel accepts
late original process thenDOWN/Readerconfirmed1/NODIAL; Observer suspended,
inertstartreturns/D200ms boundsnormalactorDOWN/now>=D before resume/NOdial/
queuedrequestexpired/unknownRootallocator1/unsealed+Readerunconfirmed; real
REFUSED afteractualbirth retainsunknownTCP16 afteractorDOWN/fixedgrace.

ONEproviderregression: HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test
apps/ex_ssl/test apps/elixir_quic/test apps/http_core/test --include integration
--seed 101. ActualROUND23_PROVIDER_REGRESSION_EXIT=2+prompt. ExSSL811/812
(20/20properties,791/792tests),90.4s; QUIC249/249,11.8s; Core418/418,23.6s; total
1478/1479. NativeTCPTest6 fails attempt80 Observer.start with acceptance_unconfirmed
BEFORE native/Allocator. Fournew cases pass. No retry/deadlinewiden/oldsourceedit.
SharedprovidergateRED. Latestwhole-nine remainsRound22fiveassertions+testwarnings;
not rerun and not superseded by this three-app provider scope.

Readonlytriage ranks: shared1s budget (Observer20–26, Bootstrap51–65 and
reservationRPC683–690); abnormal bootstrapworker death; globalmutation. None
established. Known globalsupervisorsuspend/appstop tests async:false; new
allocator test suspends only its own Observer. Plain start_child failure maps
observer_start_failed, notthis tuple. Need exact original phase/workerDOWN
reason before choosing a fix. No implicated provider source was changed.

ActualROUND23_ALLOCATOR_STATIC_EXIT=0+prompt: compilewarnings0; root formatter
check0; configuredCredo539files/8960mods-funs/NOissues; Dialyzer0errors/0skips
and4unchangedunnecessary-ignore notices; diffcheck0. OpaqueReceipt remains
intact through contextmap/accessor; no peeling/ignoredwarnings/newReceiptAPI.
SourceCode unused by public dispatch, but changed cohort does NOT establish
causal independence from the observed bootstrap admission failure. This is
accepted private component coverage, never whole-provider/release acceptance.

### Original FD-slot source prototype and bounded independent controls

Task26SourceOnly: threeNEWfrozen/tmp/http-fetch-round23-fd-slot files: C113
lines, supervisor.py67lines, control.exs134lines. RootREADALL3 plus imported
immutableR15Python148lines/Child16–29/reap55–61 and R16runner64lines before
execution. PublicSDKC: atmost2EXACT-FD socketqueries+2PIDepochchecks, NONE
forzeroD, NOenumeration/retries/address/opaqueIDs/foreigngeneration output.
Only stable originalTCPgeneration emits type/generation/state. EBADF remains
intervalnegative, otherkind/API errors inconclusive. Cooperative100ms only.
FixedbinaryPython strict512Bchild/1024Breceipt, explicitwait beforechild_reaped.

OriginalC SHA0d5337d3bfd63563ed23be896a7ab883af5ade3632f8be1de6ffa72cc38ef354;
supervisorSHAff712144e6b005225b812822c239e871b99c621bbafa162f77cbe94765fb9f50;
controllerSHA5d3504ae72bceed681719d93ae47b97a3cb46a0372b0d710b48aa4596d48c955.
WorkerSourceOnly/TTY64closed/nojobs; allR15–22helpers and app fixtures frozen.
Rootclang -std=c11 -Wall -Wextra -Werror C -lproc to fixednewbinary plus Python
ASTcheck: ROUND23_FD_SLOT_BUILD_EXIT=0+prompt. No targetexecutionbeforeRootread.
Controller ONE4sABS and perprobe200ms INCLUDINGreserved50ms cancellation/reap;
requiresCchildreaped+wrapperexit+originaltypeddiagnosticPortDOWN.

ONEoriginalcontrol: ROUND23_FD_SLOT_CONTROL_EXIT=2+prompt, late/cleanup
inconclusive before first acceptedprobe, measurements[]. CapturedVMobjects
retiredtrue ONLY, noOSchild-reap/physicalabsence certificate fromthatfailure.
RootdidNOTretryunchangedorwidenD. RootcreatedSEPARATEnewcontrol-v2.exs137lines:
ONLYlatefailurebranch adds boundeddecodedpartial/after-decision-ms diagnostics.
Allthreeoriginalsources immutable; RootREADALLv2 then ranONCEsame200ms/4s.
ActualROUND23_FD_SLOT_V2_EXIT=2+prompt; open and reuse valid, closed unknown.
No LATE23branch executed in v2; cannot retroactively explain v1 timing.

V2 exacttarget: BEAM88651/UID502/start1792627160.842827/FD47/gen8314695.
Open: original_socket/type2/gen8314695/TCPstate4,2queries,C18000ns, wrapper
12.479ms/helper0. AFTER EXACToriginalowner+PortDOWN, closed-slot query:1query
C12000ns/socket_info errno38/inconclusive, wrapper9.869ms/helper2. ONEreplacement
allocation actuallyreusednumericFD47 withdifferentgeneration (independent
secondfrozenbaseline); probe2queries/C18000ns/reason slot_reused_or_other/
inconclusive, wrapper7.553ms/helper2, NOforeignmetadata. ALL3newprobes: actual
Cchildreaped, wrapperexit0, ORIGINALtypeddiagPortDOWN and withinoriginalD.

V2 finalcleanup capturedVMobjectsretiredtrue. OverallEXIT2 iscorrect: closed
slot negative control is NOT validated. Darwin errno38=ENOTSOCK (publicSDK
sys/errno.h135): failedsocketquery neither identifiescurrentFDkind nor proves
socketdestruction/absence. DoNOTinferdiagnosticpipeownerorphysicalclose. Valid
controls establishoriginal-open identity and real numeric-slot reuse only. No
closednegativecertificate/Sourcefailurecapture/P0causality/default acceptance.
ReadonlyTWOwebqueries found no matchingverifiedOTP29/macOSreport; not evidence
that no upstreambug exists. No primitiveswap/runtimechange was executed.

Artifacts: /tmp/http-fetch-round23-allocator-focused.log; provider-regression.log
and allocator-static.log sharethe same http-fetch-round23- prefix. Native
control.log/control-v2.log and control-v2.exs share fd-slot- prefix. ALLactual
markers+prompts checked/PTYjobs collected. KnownlatePort/ACKloss cleanupbranches
arenotdirectlyforcedbythese4cases. Newprivateallocator coversactualsuccessful
constructor birth ONLY, notall-pathnativeidentity/sourcecleanup/lifecyclev1.
Next: actualsetup/helper handoff orchestration plus ORIGINAL-phase bootstrap
unknown diagnosis; any futureFDslotSourceattachment needs fresh exactscope and
preparation/deadline proof. P0fiveRound22assertions/testwarnings and all release,
performance/publicHex gates remainopen. Existingbackenddispatch/strictpins untouched.

FinalRootartifactSHA256:
apps/ex_ssl/lib/ssl/lifecycle/allocator.ex a5a324f954d32b83f52ce42b01e7685c2c5897321d65462be6ed2ee37a79e312
apps/ex_ssl/test/ssl/lifecycle/allocator_test.exs caf03e2e831dde2386a4e2f8e3caae4eb474b230e1085db5221e53e34932c472
/tmp/http-fetch-round23-fd-slot-control-v2.exs 7234347ddd4372eba62e6a396e91ab2374b3d723b564a761fd1b8d2816567fbd

PrestagingexistingAPPSgitdiff0; allfourConnection/pins/HTTPS byte guards equal
Round22original snapshots. Filteredexactnamed-diagnosticprocess check foundNONE
now (pgrepEXIT1), NOT retrospective child-reap/absence proof for v1. Only
twoNEWappfiles+threeRootdocs changed. No otherSource/backend/pins/hooks edits.

## Round24 — explicit readiness through actual actors

Entry: HEAD e984fe0, clean worktree, active goal round24. Task27 owns only
Connection, ConnectionWriter and one new inert-handoff-ready test. Root owns
format/build/tests, docs and commits. Task20 owner acknowledged the exact
three-path prerequisite scope before edits. No allocator/Observer/Handoff or
existing birth-test writes are granted. Five ExSSL architecture documents are
byte-unchanged from the prior full read; worker reviewed complete touched
source plus current P2 design and task25 before its source-only changes.

The missing prerequisite is actual-actor readiness: prior Writer only sent a
birth acknowledgment, and Connection released it without either Observer
readiness operation. The selected change is explicit preparation after birth,
not automatic readiness. It authenticates the captured ready-recipient PID,
ready nonce and original socket reference. The first admitted request consumes
one preparation and fixes D=min(request absolute D, original setup D). This
is a separate pending-operation budget; it neither renews setup nor turns an
expired startup control budget into a connection lifetime limit.

The actual Writer must call Observer.writer_ready with its retained opaque
Receipt. A separate Observer challenge returns to the exact Connection, fenced
by writer identity, observer, birth nonce and request reference. Only the
actual Connection acknowledgment can produce preparation success. Spent or
in-flight requests cannot mint another challenge or extend D. Unknown/lost
acknowledgments never restore ordinary birth-ready state. This slice does not
transfer a TCP Port, attach TLS, report setup completion, admit public lifecycle
v1, change the backend default, or establish a P0 cleanup repair.

### Actual source and focused verification

Worker froze 1419 Connection lines, 152 Writer lines and four tests/116 lines.
Root reviewed all new branches and the complete test, then added a fifth case:
with original setup D=400ms and requested preparation D=5s, suspend the actual
Connection after its preparation ACK. Its own handshake callback cannot run;
the Observer must still retire it and its actual Writer under the clipped D.
Only this test fixture gained an optional original setup deadline.

Root formatter is authoritative: final Connection1447/Writer172/new test167
lines, five cases. Actual ROUND24_READINESS_FOCUSED_EXIT=0 plus shell prompt:
warning-free compilation of two files, then 117/117 in14.5s (3.2async/11.2sync),
seed101/max_cases24. Scope is lifecycle directory plus all17 unchanged original
birth cases. The fifth case and the four new actor cases all pass. A separate
full formatted-source review found no blocking defect. Original classic Writer
loop/native write, TCP abort/close body and birth-only semantics stay unchanged.
PID/nonce checks use the existing cooperative bearer model, not sender attestation.

### Narrow bootstrap diagnostic contract and independent API control

Task28 supplied only the [trace helper](</tmp/http-fetch-round24-bootstrap-trace.exs>) (125 lines).
Root read every line before any execution. Fixed TTL1500ms/64 events/1024B event
array/2000B total JSON; only exact caller and first spawned worker inherit trace
flags. The Collector installs four Bootstrap local-MFA patterns plus reservation
request CALL only. Arity mode suppresses arguments; guarded annotations expose
only original numeric API expiry and awaited worker PID. No Observer reservation
return, Receipt, lease, alias, closure arguments, TLS state or traffic is logged.

Pinned public OTP29.0.2 API evidence: [trace arity, first-spawn and custom messages](https://github.com/erlang/otp/blob/OTP-29.0.2/lib/kernel/src/trace.erl#L401);
[delivery fencing](https://github.com/erlang/otp/blob/OTP-29.0.2/erts/preloaded/src/erlang.erl#L6688).
First-spawn is cleared in BOTH parent and child: no recursive tracing of timer
service descendants. Session destruction removes settings. Only the Collector
waits on typed caller/worker delivery fences. The original operation runs ONCE
and returns its exact result immediately after an asynchronous sanitized stop;
initial attach may cost100ms and is explicitly an observer perturbation.

Root separately wrote/read all46 lines of the [bootstrap control](</tmp/http-fetch-round24-bootstrap-control.exs>). ONE root mix-run
API control returned actual ROUND24_BOOTSTRAP_CONTROL_EXIT=0 plus prompt. Report
correlated caller101 with original spawn/await worker341, original numeric
expiry, launch/return/await_down/reservation phases, and actual normal worker exit.
Both typed delivery fences completed, status=captured/cleanup_ack=true, no
overflow/TTL expiry. IO proxy monitored the original Collector BEFORE replying
to its IO request; actual normal Collector DOWN and original proxy DOWN followed.
Observer cancellation/Reader confirmed cleanup also passed. No TLS/native dial.

ONE diagnostic campaign temporarily wrapped ONLY NativeTCPTest attempt line80
with Round24BootstrapTrace.run. Root invoked Mix.Tasks.Test.run directly under
mix run -r; this bypassed normal umbrella task recursion and combined the three
app corpora into ONE ExUnit run. That changed scheduling/helper context; it is
NOT a normal provider acceptance gate. Actual BOOTSTRAP_PROVIDER_EXIT=2 plus
prompt: 1483/1484 (20/20 properties,1463/1464 tests),105.1s (23.1async/82.0sync).
Only failure: Core TLS270/290 still pinned previous whole Connection SHA.
All NativeTCP cases passed here; no R23 startup failure instance was captured.

The four diagnostic reports contain one consistent normal worker sample and
three EMPTY/inconclusive reports; every report says session cleanup ACK, which
is not worker absence or per-Collector DOWN proof. Empty results lose caught
setup/capture error and partial state in helper43–56. Stop handling may overwrite
attach_unknown with a later ok tag. Thus operation:ok is not attachment ACK.
Ranked candidates: hidden setup/capture exception,100ms attach race, effective
pattern/flag differences. None established. The successful API control/sample
cannot promote the three failed captures or explain the R23 bootstrap failure.

No second diagnostic campaign/prototype repair was attempted. A future narrow
failure-only version should retain bounded partial identity/events and report
sticky attach_status plus error_stage/caught_kind/reason_class enums only. No
exception structs, stacks, arguments or capabilities. Original125-line helper
remains frozen. Root preserved the one-line instrumented NativeTCP fixture in
a NEW tmp snapshot and restored the original136-line file BYTE EXACT before
normal acceptance. No Bootstrap/Observer production source was changed.

### Restored source gate and strict probe revalidation

Root revalidated private buffer/verify/peer-close probes against the reviewed
Connection diff: new branches are private-lifecycle-only; all original code
(including classic tuple5 attach, buffer/verify forwarding, drain/abort/close)
is byte-exact after removing only the two new private regions and restoring the
two-line scope comment. The two source guards now pin ONLY the reviewed current
SHA092bd3893b4d7fc1a7e05b99cd69a8e78e75d8ac64ee995353131c7b92947fbb.
No fallback hash, removed assertion, test-option change or relaxed comparison.

One normal restored run:

```bash
HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test apps/ex_ssl/test apps/elixir_quic/test apps/http_core/test apps/http_fetch/test/http/socket_client_http2_test.exs --include integration --seed 101
```

Actual ROUND24_RESTORED_PROVIDER_EXIT=0 plus prompt. Standard root
umbrella recursion ran ExSSL817/817 (20properties797tests),78.2s; QUIC249/249,8.3s;
Core418/418,23.3s; FetchH2-file43/43,5.7s. Total1527/1527. Original NativeTCP
fixture is restored and trace helper is NOT loaded in this run. Both strict
private source probes pass. This supersedes R23 red only for this selected scope.

The prior admission failure remains unexplained, not repaired by this pass.
Latest whole-nine gate is still R22 five assertions plus existing test warnings;
these selected four-app paths do NOT supersede it. Existing Elixir1.20 test
bitstring-size warnings were not hidden or edited; this test command has no
WAE flag, same as R23 provider scope. Production compile with WAE is separate.
Actual ROUND24_READINESS_STATIC_EXIT=0 plus prompt: compilewarnings0; root
formatter check0; configured Credo540files/8974mods-funs/no issues; Dialyzer
0errors/0skips/four unchanged unnecessary-ignore notices. No new suppression.

Final Root guards: original Connection code exact after subtracting the admitted
private addition/comment, Writer constructor/birth prefix and native/classic
suffix exact, NativeTCP136 fixture byte-restored; Core/Fetch probe files differ
from original ONLY by their one current SHA literal each; HTTPS fixture byte
exact. No production trace hooks, new public options or backend switch. Existing
birth545 test file and all Observer/Handoff/Allocator sources remain untouched.
Next actual allocator/Connection TCP transfer and commit need new protocol
integration, self-ownership-gated allocator cleanup and acknowledged helper
retirement. P0 cleanup/whole-nine/performance/candidate/publication remain open.

Final SHA256 artifacts (helper125/control46 are tmp-only):

```text
apps/ex_ssl/lib/ssl/connection.ex 092bd3893b4d7fc1a7e05b99cd69a8e78e75d8ac64ee995353131c7b92947fbb
apps/ex_ssl/lib/ssl/connection_writer.ex 011cb4ff2eedc97d4b611dbf286d384b3cb49aff1b49f6d509cff36d112c743b
apps/ex_ssl/test/ssl/lifecycle/inert_handoff_ready_test.exs ba1404ebb5c0a85dcc6f9ce9c0207d9613efb900a695c0956393c9ca35827d3b
/tmp/http-fetch-round24-bootstrap-trace.exs 08a1b89a9e278e56ea68a2f4b9781e2c81eb5c800934abbede39f7711286143d
/tmp/http-fetch-round24-bootstrap-control.exs 3faa66e7904fc007227a11dd9761b6d332878f77596a854e39566335994ce944
```

All executed jobs collected with actual exit markers and prompts, not inferred
idle. Runtime sources/five actor tests were fully reviewed after formatter;
final diffcheck0. Only three app implementation/test files, two exact probe-hash
literals and three root design/plan/validation documents belong to this change.

## Round25 — actual passive TCP handoff and exact commit

Entry: main a51b4db, worktree clean, goal active/armed25/100. Root used fresh
CURRENT-HEAD snapshots of three runtime files, old handoff test and six strict
probe/classic fixtures in /tmp/http-fetch-round25-originals. Historical R22/R23
and pre-feature R24 Connection snapshots must not overwrite accepted readiness
code. Root owns all formatting, Mix/build/native/network, probe hashes and commit.
Task29 reviewed the actual protocol; task20 owner explicitly coordinated the
five-path task30 grant before edits. No runtime execution by either worker.

Contract: actual Allocator authenticates its captured recipient/allocation nonce,
prepares the original stored Port through Observer, transfers passive ownership,
and asynchronously calls the actual prepared Connection. That receiver checks
original socket reference, ready recipient/nonce, Observer and actual caller, then
uses a new private exact-identity commit variant. Both offered TCP and Allocator
must match the canonical typed identities before owner verification and commit.
The original commit/3 remains intact; a role mask or two Conn-owned Ports cannot
substitute for this exact match. No offered Port is adopted before commit ACK.

A bounded-prepare variant delegates to the original prepare operation exactly
once and derives min(request D, original Handoff deadline) from its successful
next state. Old prepare/4 and commit/3 stay intact. Allocator tightens its original
reference-fenced absolute timer to this returned bound BEFORE native gates and
transfer; an ACK arriving after the bound cannot revive it. Connection clamps
again. No snapshot dimension, constructor-context field or receipt capability is added.
Own-Observer suspension after a FIFO replay/ownership fact isolates allocator
expiry from Observer cleanup; both earlier-request and earlier-readiness orders
require separate actual-constructor cases. No sleeps, polling or global suspension.

Allocator uses an asynchronous original-Connection request; its mailbox remains
responsive to replay and original typed DOWN/expiry while awaiting commit. Only
the actual commit ACK plus still-recorded native owner and helper_done ACK permit
normal retirement. Termination may close only a Port STILL self-owned. It must
never roll back or reclose a recipient-owned Port after a lost acknowledgment.
Persisted helper_done can make allocator DOWN benign even if its caller sees an
unknown result: committed Connection/TCP may remain under original authority until
setup deadline/death/cancel. A caller reply is not delivery, setup success, TLS
readiness or cleanup proof. Public lifecycle and TLS attachment stay unsupported.

### Source review and compiler boundary

Worker froze224 Allocator/1480 Connection/764 Observer lines plus158 new fixture
lines and one30-line additive manual case. Root read all new runtime/test code.
Initial focused attempt exited1 in compilation: Elixir1.20 inferred transfer-map
input while the callback supplied transfer:nil. No tests ran. Splitting admission,
prepare and native offer alone still exited1 with the same warning; no test retry
was involved. A separate eight-line single-update control compiled with WAE exit0,
so this does not establish a general compiler bug. Both failed logs are retained.

Root kept the three phase functions and made transfer a uniform internal record
from init, using from:nil for unspent state. The immutable seven-field constructor
context is unchanged. No cast, compiler suppression, deadline or test weakening.
Root also made the bounded wrapper error branch explicit. Final formatted source
is Allocator254/Connection1494/Observer767, new actual-constructor fixture237 and
manual suite1089 lines. Separate full formatted review found no blocking defect.
Actual-actor commit/helper_done ACK loss remains unforced; existing manual protocol
coverage and source review are not newly measured dropped-ACK proof.

### Actual verification

ROUND25_HANDOFF_FOCUSED_V3_EXIT=0 plus shell prompt: warning-free compile, then
124/124 in15.4s (4.1async/11.2sync), seed101/max_cases24. Six actual-constructor
cases and one added real-TCP canonical-parameter case pass. The success case keeps
Connection/TCP past the original2s allocation bound and native handoff budget, with no
TLS bytes and setup still pending, then explicitly cancels/observes typed31 cleanup.
Both200ms timer cases keep Connection and its Port alive after original normal
Allocator DOWN while own Observer is still suspended, then resume/confirm31.

ROUND25_HANDOFF_STATIC_EXIT=0 plus prompt: warning-free compilation, umbrella
format check, configured Credo541 files/9002 mods-funs/no issues, Dialyzer0 errors/
0 skips/four unchanged unnecessary-ignore notices, diffcheck0. No strict-mode
baseline changes or ignore edits.

One standard root umbrella regression, without any trace helper or instrumentation:

```bash
HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test apps/ex_ssl/test apps/elixir_quic/test apps/http_core/test apps/http_fetch/test/http/socket_client_http2_test.exs --include integration --seed 101
```

Actual ROUND25_PROVIDER_REGRESSION_EXIT=0 plus prompt: ExSSL824/824 (20 properties,
804 tests)95.4s; QUIC249/24915.6s; Core418/41828.3s; Fetch H2-file43/436.4s.
Total1534/1534. This is the current selected provider/consumer gate, not whole-nine
acceptance. Existing Elixir1.20 test bitstring warnings AND Request.put_body_headers
test type warning remain; the same warnings occur in Round24 restored log. They
were neither suppressed nor edited. The test command has no WAE, as in Round24;
application compile WAE passes. No R23 bootstrap failing instance captured/repaired.

### Scope and remaining gates

Final Root scope guard exits0: subtracting only the two new private Connection
regions reproduces ALL original1494-minus47=1447 lines byte-exact; similarly
subtracting new Observer APIs/normalization/handlers restores ALL726 original
lines, including old prepare4/commit3/timers/authority. Removing the ONE added
manual case restores all1046 lines exactly. Allocator public constructor/start,
original native enrollment/allocation path and liveness tail remain byte-exact.
Writer, pure Handoff, NativeTCP, old545 birth/113 allocator/167 readiness fixtures
and all five architecture documents match their frozen baselines.

Both strict probes differ from their fresh baseline ONLY by one exact64-character
Connection hash each; all assertions/pressure remain. HTTPS is byte-exact. No
trace hooks, private TLS-state inspection, test drop hooks, backend/default switch,
public options or support claims were added. Loopback Port ownership/typed DOWN
do not certify physical Unix FD destruction or general P0 terminal delivery.

Latest whole-nine remains R22 RED3201/3206 plus existing test WAE failure, not
superseded here. Full setup orchestration/all-error constructor identity, TLS
attach and handshake outcome, public lifecycle/STARTTLS/owner transfer, managed
H1/H2, P0 closure, performance/candidate/CI/publication/cold consumer remain open.

Final source SHA256:

```text
apps/ex_ssl/lib/ssl/connection.ex 8500194db0331490b0e30bdc4ca82ea754b20146ad8058d6531f047922e186fd
apps/ex_ssl/lib/ssl/lifecycle/allocator.ex 955b4e7e0a226bfd6f10f4ba1fedb04bb565110489388a7883f79bc2360db8c7
apps/ex_ssl/lib/ssl/lifecycle/observer.ex d2fbae9b1155f0ce87698016ea5a5cf20e7ba6b0384a0113d0eca9d1f6d3cf75
apps/ex_ssl/test/ssl/lifecycle/native_handoff_test.exs 7548c24c2d68b079fde90c04f48ab02300b6b85a8c504be07fe178fbbfd79ae1
apps/ex_ssl/test/ssl/lifecycle/observer_handoff_test.exs 3bb8ceb12f7090c0273b80aa1c2c5de2e9c0611473b080d86699b6d0482e9ead
```

All executed jobs collected and actual exit markers/prompts checked, including
both compile-only failures; inferred idle never treated as command exit. Runtime
diff and all new fixture lines fully reviewed after formatter; separate read-only
review found no blocking issue. Ten intended deliverables only: three runtime
files, two handoff tests, two exact probe literals, three root documents.
Next diagnostics MUST snapshot the new accepted HEAD; Round25-original snapshots
precede this native-handoff feature and cannot restore over it. Goal stays active.

## Round26 — actual Setup orchestration and bounded inert construction

Entry main d79472e5395988e6a1bc9e4fec0160a6cd2fe97d, clean, goal active/armed26/100.
Root checked actual working directory/HEAD, prior five full architecture reads
remain byte-exact847556a, fresh CURRENT HEAD Connection/two-probe snapshots in
/tmp/http-fetch-round26-originals. Task31 follows completed task30. Task20 owner
explicitly coordinated EXACT3source paths: additive private Connection constructor,
new Setup and new actual-Setup tests. No worker formatter/build/native execution.
Root retains all execution, hashes, documentation and commit authority.

Design review: DynamicSupervisor.start_child has no caller timeout parameter;
waiting on that supervisor inside Setup cannot enforce its own pending budget.
The private bounded alternative uses public gen_statem.start/3, unlinked and
without automatic restart, only for inert lifecycle actors. Existing supervised/
classic start_link paths stay intact. Its timeout covers initial acknowledgment
ONLY, not enrollment/readiness. Post-entry failure is unknown; late {:ok,pid}
MUST retain/store/monitor that identity before a post-return deadline gate.
No helper/proxy, private supervisor protocol, role or receipt dimension is added.

Contract: ROOT binds/reserves setup AND allocator permits. Setup uses exactly
seven trusted context fields: receipt, permit, allocator_permit, endpoint, classic,
control_deadline, ready. Classic owner and ready recipient equal the actual ROOT
caller. Effective E=min(controlD, original classic setupD), fixed once. Actual
Setup self-enrolls/reserves Connection; Connection keeps ROOT as application owner,
sends readiness to Setup and creates actual Writer. Actual Allocator has unchanged seven fields,
recipient/constructor-parent Setup, logical root-permit creator ROOT. This is
cooperative bearer/provenance accounting, not process-ancestry attestation.

Preparation and Allocator handoff use public asynchronous request/check_response
APIs from the actual Setup PID under SAME E. Original typed monitors and request
IDs stay distinct; normal Allocator DOWN alone cannot substitute for its commit/
helper-completion ACK. Both observations plus ownership/live/E gates permit ONE
nonce/Observer/PID/socket-fenced native-owned candidate message to ROOT.
Setup remains alive with setup:pending and E STILL ARMED. NativeReady cannot
publish connected/helper_done or cancel/renew this pending budget. Unknown
acceptance alone holds bounded uncertainty; it cannot cause rollback/early
Setup exit/cancellation, retry or no-resource rejection.

Independent timer oracle: actual Conn/Observer original setup budget is LATER
(e.g.2s) than Setup pendingE(200ms). Suspend OWN Observer only AFTER actual native
notification and ONE original Portowner fact; Setup normalDOWN atE must leave
Conn/Port still live/Connowned BEFORE Observer resume. Equal Conn/setup E could
confound this with Conn handshake expiry and is not this oracle. On resume,
existing not-done SetupDOWN retires authority; its reason may be internal rather
than timeout. ROOT keeps original receipt/lease cancellation throughout.
Public docs: [gen_statem.start/3](https://www.erlang.org/doc/apps/stdlib/gen_statem.html#start/3).

Initial Root execution: formatter EXIT0; compile warnings-as-errors and
lifecycle+birth focus EXIT0,130/13018.1s(6.8async/11.2sync),seed101/max_cases24.
Actual terminal exit marker and prompt checked after collecting inferred-idle job.
Static first EXIT8: compile/format passed; configured Credo543files9044mods/funs
reported ONLY two new admission functions cyclomatic18>max15. Dialyzer was NOT
run because the chain stopped. Source reopened only to extract admission helpers
without dropping checks/raising limits/suppression or changing old bodies.

Independent full formatted review (Setup339/tests222/newCtor34 lines) found no
FSM blocker, but found a NEW fixture gap: requested controlD is made AFTER root
bootstrap while classic/Observer2s starts BEFORE it, so slow admission could clip
E earlier than the assertion used. Correction normalizes fixtures to actual minE;
ONLY the SDK-soft-timeout case gets a separate original4s horizon and explicit
remainingE>1250ms precondition. Its pendingE1500/probeE-250/closed-call200ms and
original Setup control-D assertions stay fixed. IndependentE200/classic2s and every old
fixture/peer deadline remain unchanged. This isolates the earlier pending timer.

Final Root refactor/fixture validation EXIT0 plus terminal prompt:
formatter-v2, compile warnings-as-errors, lifecycle+birth130/13017.9s
(6.6async/11.2sync), seed101/max_cases24; root format check; configured Credo
543files9048mods/funs NO issues; Dialyzer0errors/0skips/fourunchanged unnecessary
ignore notices17.55s; git diff --check0. /tmp/http-fetch-round26-setup-validated.log.
No checks removed/ignored, no Credo or Dialyzer config changes. All entry/initial
failures and final jobs collected; actual markers/prompts checked, inferred idle
never substituted for foreground completion. Standard provider gate follows.

Standard restored ROOT separate-app provider/consumer command:

```bash
HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test apps/ex_ssl/test apps/elixir_quic/test apps/http_core/test apps/http_fetch/test/http/socket_client_http2_test.exs --include integration --seed 101
```

Actual ROUND26_PROVIDER_REGRESSION_EXIT=0 plus terminal prompt, job collected.
ExSSL 830/830 (20 properties,810 tests),78.5s; QUIC249/249,9.3s;
Core418/418,24.0s; Fetch H2 file43/43,5.7s: TOTAL1540/1540.
/tmp/http-fetch-round26-provider-regression.log. No trace/helper hooks loaded.
Existing test-only bitstring and Request.put_body_headers type warnings remain
(as recorded R24/R25); no suppressions, no test-WAE claim. Application WAE clean.

Six actual-Setup cases execute: real chain/passive/no TLS bytes/pending+explicit
cancel/typed31; wrong caller/expired-before-entry ctor/foreign queued frames/
replay cannot spend or duplicate the genuine candidate; nativeE200/classic2s
own-Observer suspension isolates Setup normalDOWN while Conn/Writer/Port remain
live/Connowned BEFOREresume; precancel birth leaves unissuedROOTallocatorpermit
unknown/unsealed; ONE closed-owned-listener refusal leaves TCPidentityunknown/
unsealed; suspended own Observer produces SDK1s unknown, closed probeE-250 sees
responsive Setup, originalE1500 ends it normally, later explicitcancel/unsealed.
No actual native commit/helper_done ACK loss was injected; do not claim that proof.

Final source guards: subtract ONLY new44line Connection constructor/helper block
to recover ALL1494 original lines byte-exact. All201 other tracked ExSSL lib/test
files and five prior fully-read architecture documents are byte-exact; Writer,
Allocator, Observer, ledger, pure Handoff, NativeTCP and priorbirth/readiness/native
handoff tests unchanged. Both strict probes differ from CURRENTpre-round snapshots
by EXACTLY ONE64char SHA literal each; no pressure/assertion/fallback changes.
HTTPS371 exact SHA b4f4f8b375d72aadf9799f8261199c478e4f85dd34bfdd601c3e873e0429c9d3.
Separate final fullformatted review Setup355/Test228/newCtor44 found no blockers;
fixture timing caveat closed. Root fully reviewed newruntime/tests/final diff.

Final formatted SHA256:
- Connection1538:10ade3e28f6c024841e30406864226971a520fad325fcd1d8e5b62a3af38ab18
- Setup355:851c8669a64fe719168954c497d1a4e0224802ea4d1888a1150237a0a8571aec
- NewTest228:7b2d2826a1d996b1fbcf1373068c34bbf399b0971a81b257227f1a64cd4bf725

Eight deliverables only: two runtime files, one new test, two exact strict-probe
literals and three root documents. No TLS attach/machine/I/O/outcome/public lifecycle
or Root-publicACK/default change. Private native candidate is NOT TLS readiness.

Whole-nine remains R22 RED3201/3206 plus test-WAE; selected1540 pass does not
supersede it. Native constructor all-error identity, hidden/late births, actual
ACK loss, R23bootstrapcause, P0physicalFD/remote terminal delivery remain OPEN.
Port/ownerDOWN and typed31 do not certify physicalFD destruction/peerFIN-RST.
No new diagnostic attach, primitive change, trace, GC, deadline widening of old
fixtures, candidate/CI/release/performance or published-consumer acceptance.
Next implement actualTLSattach and acknowledged realsetupoutcome/constructor
identity before public integration. Goal stays active. Future diagnostics MUST
fresh-snapshot accepted HEAD: /tmp/http-fetch-round26-originals predates this
Setup/unlinked-constructor feature and cannot restore over it.

## Round27 — private TLS attach and acknowledged successful setup

Entry main d45816b3a6db4867a59d6c4ec2b3f31ecd4a7611 clean, actualpwd/HEAD/status
EXIT0, goalactive/armed27/100. Five prior fully-read architecture documents
remain byte-exact847556a. Fresh CURRENT6file snapshots /tmp/http-fetch-round27-originals.
Root retained formatter/Mix/native/network/strictpins/docs/commit ownership.
Task32 follows31; task20owner explicitly acknowledged EXACT3sourcepaths:
Connection, Setup, NEWsetup_tls_test; NOObserver/Writer/oldtests/purecore changes.
Worker sourceonly/NEWtestsfirst; independent design review readonly/noexec.

Design evidence: enrolledWriter accepts nonce-fenced lifecycle_send, not classic
send; inertConn.records nil must become RecordFramer.new at explicitattach.
Alreadycommitted Allocator may be helperDone/DOWN; re-runningliveallocator
handoff-context would incorrectlyreject valid adoptedTCP. Use storedcanonical
Conn-owned Port and originalSetupPID/nonce/Observer/socketRef/oneattachRef.
Private passive-only policy rejected BEFOREspending; publiccall gate remains
closed to prevent active/application delivery before future Root-publicACK.
Classic materialize/machine/startup body is factored mechanically, send-envelope
and connected-notify are the ONLY existing runtime dispatch sites changed.

Authoritative variant SDKadmissionACK + SEPARATE connectednotice: Connrequest
repliesONCE {:ok,attachRef} afterstartupdispatch andpostlive/E checks; private
connect_from=nil. ActualclientFinished WriterACK later reachesapply_events
connected and sends independently fencedcanonicalTLScompletion. Botharrivalorders
may beheld, butcompletionalone cannotreplace admissionACK/advancephase/publish.
NativeE checked beforefirstWriterENQUEUE andagainbeforeACK; nohard-realtime
claim for scheduling/nativeBIFwalltime. Invalidframes cannotspendgenuineentry.
AfterSetupexactSDKACK/postgatesbeforeE, ref-fencetimer andretainORIGINALclassicD
(infinity->nil), notnewhandshakeTTL. Connection originaltimeralreadyarmed.

OnlyrealTLSsuccess+admissionACK begin ONCE P=min(originalClassicD,successNow+1000).
P shares connectedpublish/helperDone/unknownhold; no per-RPCrefresh, expiredEreuse
or connection-lifetime cap. Setupfenceshandshaketimer; ObserveroriginalD can still
beatpublication. ACKedconnected+ACKedhelperDone+P/live/canonicalpostgates required
beforeprivateROOTnotice+normalSetupretirement. No publicRootadoption/deliveryACK.
Source-onlysuccessscope: classic fail_now replies/close/stop andfatalalert paths
can triggeroriginaltypedretirement beforeSetup publishesfailed; publishfailed
itselfretires/killsSetup beforeitsreply. Preserve alert/close behavior; precise
failedclassification/failedpublicationACK remainOPEN, never inferred fromDOWN.

Test-first SOURCE boundary: NEWtest204lines completed while FULLConn1538 AND
Setup355 still byte-exactacceptedHEAD (worker guard); noRED execution claimed.
Root readall204 andidentified weak nonpassive noCHoracle: absence ofcompleted
peerhandshake did not establishbyteabsence. CorrectedONLYNEWtest toownedrawTCP
listener/acceptedpeer recv0timeoutafterrepeatreject. Existingfixturesunchanged.
Root requested8thcase delaysactualoriginalWriter afterCH/ownedrecordgate, waits
owned200msABStimer, assertsnoRootTLSready/nopeerconnected/setupPending while
Writerheld, alwaysresumes thenactualsuccess/cancel31. Thisisdelay, NOTACKloss.

Rootfreeze/finalreviews: worker noexec/TTY77closed/nojobs. PRE-FMTRootindependent
reverse-reconstruction restoresFULLacceptedConn1538exact, includingnewCtor44 and
ALLP0fail/close/drain/app/timeout. RootformatterEXIT0; privatehandler/newhelpers
plus3legacydispatchsites fullyread. WholeSetup523/newTest291 fullyread byRoot
andindependentreviewer; no blocker in success-onlyscope. Reviewerlimits: early
completion-before-SDKACK cachebranch source-inspected, notforced; suspendedObs is
unansweredpublication, NOTlostACKafterpersistedconnected/helperDone. No dedicated
newhandshake-phasecancelcase; sourceP0/constructoridentity/publicACKstillopen.

Initial Root compile-WAE+focus138/138 GREEN,28.3s(7async/21.3sync),seed101/max24;
explicit --include integration (test_helper normallyexcludesintegration).
ActualROUND27_TLS_FOCUSED_EXIT=0 plusprompt, jobcollected.
/tmp/http-fetch-round27-tls-focused.log. Eightnewcasesreallyexecuted.
Initialstatic RED actualEXIT2: compile/format/Credo544files9089mods-funs clean;
Dialyzer1 unmatched_return Setup.arm cancel_timer result ignored,18.62s.
Rootminimalexplicit _=discard onNEWcancel-expressionONLY; formatter525lines
(upfrom523). No logic/config/ignorechanges. LaterFULLproviderincludesall138.
/tmp/http-fetch-round27-tls-static.log preservesinitialfailure.

Final Root static actualROUND27_TLS_STATIC_FIXED_EXIT=0 plusprompt/jobcollected:
formatter, compilewarnings-as-errors, rootformatcheck, configuredCredo544files/
9089mods-funs NOissues(17.1s), Dialyzer0errors/0skips/fourUNCHANGEDunnecessary
ignore notices(20.38s), gitdiffcheck0. No suppressions/stricterbaselinecleanup.
/tmp/http-fetch-round27-tls-static-fixed.log. Rootfullformattedreview ofnew
armdiscard completesfinal525Setup; original523review otherwiseidentical.

Standard ROOTseparate-app provider regression (sameold deadlines/peerpressure):
```bash
HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test apps/ex_ssl/test apps/elixir_quic/test apps/http_core/test apps/http_fetch/test/http/socket_client_http2_test.exs --include integration --seed 101
```

ActualROUND27_PROVIDER_REGRESSION_EXIT=0 plusprompt, jobcollected.
ExSSL838/838(20properties818tests),106.0s(24.5async/81.4sync);
QUIC249/249,9.5s; Core418/418,29.4s; FetchH2file43/43,8.9s:
TOTAL1548/1548. /tmp/http-fetch-round27-provider-regression.log.
Existing test-only bitstring+Request.put_body_headers typewarnings remain asR24-26;
no tests-WAEclaim/suppressions. No trace/helperhooks loaded, noGC/primitivechanges.
Whole-nine latest remainsR22 RED3201/3206 plus test-WAE; this selected1548 gate
does NOTsupersede it. No performance/candidate/CI/publication/cold-consumer acceptance.

Final Root scope guards: trackedapps789; EXACT4changed (Conn/Setup/twostrictpins),
785othersbyte-exact; ONLYuntrackedappfileNEWsetup_tls_test. Worker787others
baseline beforeRootpins alsoexact. RootfirstHEADblobguard naivelydereferenced
3trackedhttp_fetch symlinks andfailed; correctedtarget-bytecomparison identifies
EXACT4expectedchanges, no source repairneeded. Final formattedConn reconstruct
firstdiff wasONLYone formatter-added blank beforetoucheddispatch; normalizeONLY
thatblank plusreverse3authorizedsites/remove2newregions => FULL1538accepted
Connbyteexact AGAIN. NewCtor44/allP0fail-close-drain-app-timeouts preserved.

Bothstrictprobes normalize EXACTLYONE64char SHA eachbacktocurrentpre-round
snapshots; no assertions/pressure/fallbackchange. HTTPS371sourceSHAunchanged:
b4f4f8b375d72aadf9799f8261199c478e4f85dd34bfdd601c3e873e0429c9d3.
Fivefullyreadarchitecturefilesremainbyteexact847556a. Purecore/Profile/Writer/
Allocator/Observer/Handoff/NativeTCP/oldbirth-readiness-nativeSetup testsunchanged.
FinalformattedSHA256:
- Conn1636:835f39f40059f0b14b3d402f74c241d56724f9492ee70e55ea9fa864eb10f9e1
- Setup525:b1378257963ceb7754c5e8e0d526b4dbd008f6d0dce0c9cc719c9e13e107ca81
- NEWtest291:b14026d00b6f433509d8f51e00ec7ae1769ddd2ee53c418c4fbe9d5cc4a9cbb4

Eightdeliverables:2runtime+1newtest+2strictliterals+3Rootdocs. No publicSSL/API/
lifecycle/managed/I-O/ROOTpublicadoptionACK/default/dependency/versionchange.
NativeReady remainsnativeonly unlessexplicitauthenticatedprivateattach. RealTLS
verifiedprivatecandidate is NOT publicapplicationacceptance/delivery.
Classifiedfailed-outcomeACK/all-errorconstructoridentity/actualdroppedACKs/R23
bootstrapcause/P0physicalFD/remoteFIN-RST remainOPEN. Typed31/Portnil/ownerDOWN
nevercertifyphysicaldescriptorclosure. No olddeadlinewidening/GC/nativeprimitive
change. Wholegoalcontinues; nextacknowledgedrealTLSfailurepublication preserving
boundedbest-effortalert/typedcleanup, thenconstructoridentity/publicintegration.
FutureworkMUSTfreshsnapshotacceptedcurrentHEAD; oldround27originalspredateTLS
attach andcannotrestoreoverthisfeature.


## Round28 — bounded private TLS failure recording

Entry main f612cd6f35c5b2b1296c0d6c7d19a81d90a7ca61, clean; actual pwd,
HEAD and status EXIT0. Goal active/armed28/100. Five fully read architecture
files remain byte-exact847556a. Fresh eight current snapshots are under
/tmp/http-fetch-round28-originals; earlier snapshots predate accepted features.
Root retains all formatter/Mix/native/network/strict-pin/docs/commit ownership.
Task33 follows completed32. Task20 owner explicitly acknowledged Observer and
Handoff overlap; all other task20 scopes remain frozen. Source grant is exactly
Connection, Observer, additive Handoff.committed?/1, NEW setup_tls_failure_test.

Design review chose a Connection-origin leaf record RPC before existing failure
handling; a Setup barrier would add a distributed continuation protocol. Two
independent reviewers agreed. Existing publish_setup({failed,...}) immediately
retires its caller, so it cannot supply this acknowledgment. New private recording
must close authority/admission without retirement or sealing, then preserve old
typed DOWN/cancel/expiry retirement. Original Root lease remains valid.

A full1000ms RPC wait against a1000ms drain budget could suppress the alert when
an ACK is lost. Capture one P=min(originalClassicD,entry+1000); derive RPC cutoff
R=min(P-250,entry+250), skip expiredR, send both R and unchanged P. Only shorten
receiver expiry; no retry/renewal on acceptance unknown. Existing250ms alert
logic remains best-effort under original deadline, cancellation and VM scheduling.

Scope requires explicit local outcome-pending/attempted markers: the machine may
be connected before Finished writer ACK, and an infinite handshake has no timer
reference. Clear pending only at the actual existing connected event. Narrow
structured TLS/peer alerts map to tls; other errors keep their existing paths.
Old two fail heads and fail_now head may be mechanically renamed behind wrappers;
all old failure/alert/close/drain bodies must reconstruct byte-exact. Public/classic
connections pass through the helper unchanged. Setup/Writer/all old tests freeze.

Positive Handoff.committed?/1 is required: !pending also admits idle state.
TCP authentication retains the original allocator creator generation across normal
helper completion/DOWN; it must not require a dead allocator to be live. This is
a trusted provider assertion, not independent cryptographic or spawn provenance.
ACK means persisted classification and closed admission, not TLS alert delivery,
Root acceptance or cleanup. Original typed Reader proof remains the cleanup oracle;
Port DOWN/owner DOWN do not establish physical descriptor destruction or peer FIN.
Source tests must distinguish protocol actors held through P from actual TLS
closing via its old250ms alert timer, and unaccepted expired RPC from lost ACK.

Test-first checkpoint: worker wrote/full-read NEW319lines/seven cases while all
eight snapshots and every other tracked app remained exact f612. Root requested
a source freeze; no runtime implementation had begun. Root read all319 lines.
Root then ran only NEWfile:9, --include integration --max-failures1 --seed101,
against the unchanged runtime. Actual ROUND28_TLS_RED_EXIT=2 AND terminal prompt;
job collected. /tmp/http-fetch-round28-tls-red.log63lines fully read. In2.1s the
finite5s wrong-SNI handshake after native E sealed role/down masks31 and confirmed cleanup
with setup=failed but setup_failure=internal instead of tls. Result0/1passed,
5excluded and max-failures abort: a real contract failure, not a missing API error.

Baseline peer independently logged Fatal Certificate Unknown; exact Peer.task
result assertion follows failed_tls and was NOT reached on this red run. New SDK
references elsewhere produce expected undefined-function warnings in the baseline,
but the selected actual TLS case calls no new SDK. A new unused-default helper
warning was also noted for removal without suppression. Root did not format or
edit the new test during this checkpoint. Only after actual marker/prompt and
log review did Root explicitly resume the exact four-path source grant.

New oracle refinements requested before green: replay near original P and assert
original Connection DOWN before a hypothetical extended P; add a250ms Connection
DOWN bound after explicit old-lease cancellation, separate from P1000 expiry.
Port/Reader typed cleanup bounds remain unchanged. Neither test claims physical
FD destruction, actual dropped persisted ACK, or unconditional wire alert delivery.

Root pre-format independent guards passed FULL Connection1636 reconstruction,
Observer767 additive-only reconstruction and Handoff123 removal of three lines.
Root authoritative format EXIT0/prompt. Formatted Connection1684 SHA256
61b2fa41a60fb00d01335ea8486e698aecac8fc0a45a47e10d5adecb34cc3f91;
both strict probes change exactly one64-character literal, independently normalized
against current snapshots. Setup525/Writer/all remaining old tests/pure bodies freeze.
Root final formatted Connection1636 and post-review Observer767 reconstructions
also passed; Handoff123 remains exact. No native/crypto/alert/close primitive changed.

First focused run: compile WAE passed;144/145 in30.7s(7.2async/23.4sync),
new7/7 passed. Existing setup_tls_test128 linked peer Task failed at259 because
ssl.send(private) returned closed. Single unchanged target passed1/1 in2.0s;
its proxy also logged a post-teardown closed send. Unchanged target with
--repeat-until-failure20 reproduced the linked peer failure on run3 (58line log,
actual EXIT2/prompt). Reader/peer-send ordering inspection found no causal edge
between client private readiness and server application send. Root readiness is
not peer app delivery: immediate cancellation and proxy teardown may win.

Root task34 explicit sole old-test exception: add existing peer_connected1000ms
assert AFTER success and BEFORE cancel in Writer-ACK case. No held200ms absence
check, timeout, helper or implementation changed. This adds server-send-ok before
intentional cancellation/teardown. Latch-only repeat-until-failure20 executes21
runs(remaining20..0): ALL21passed, no closed-send errors, actual EXIT0/prompt.
Unmodified and synchronized logs remain separate; this repairs missing test
ordering without making client TLS readiness wait for server application data.
Exact closure chronology in the initial failure was not instrumented/proven.

Independent review found NEW allocator-auth edge: exact lineage alone accepted
an unfinished dead allocator while its DOWN was queued. Actual driver already
requires allocator done+normalDOWN, but protocol gate must enforce DONE or live
resource+live ledger+actual live PID. Root wrote negative first: own Observer
suspended, actual cooperative Conn send_request queued; one public queue-length
snapshot1 BEFORE allocator stop, actual DOWN and live-R precondition before resume.
Old guard RED EXIT2/prompt in1.4s,0/1passed7excluded, sealed TLS versus required
INTERNAL (39line log): admission witness, not expiration/timeout or mere source test.

Root added only NEW failure_allocator_live? guard; exact original monitor/PID/
Root lineage remains. Subsequent focus new8/8 green(5cooperative/3actual). Guard
postfix Observer767 reverse exact. Formatted Observer881, new failure test440,
old success test292(+one assert). Final tracked apps790: exactly6 authorized
changed paths(Conn/Observer/Handoff/oldsuccess/2pins), all784 others byte-exact;
only NEWfailure test untracked. Symlink targets compared with Git blob bytes.
Old success full291 bytes reconstruct by removing that single added assertion.
Independent final reviewer read all8 cases/newguard/latch: no source blocker.

Review-fixed focused run: compile WAE passed;145/146 in32.4s(7.8async/24.5sync).
All NEW8 passed; existing ObserverHandoffTest190 failed its OWN elapsed-time fence
at231: target original500+100ms, receive1000ms reported matching message after
timeout. No new recording operation is called. Unchanged recheck145/146 in33.4s
(8.0async/25.3sync), all8 again passed; handoff case passed, but old ObserverTest363
bootstrap-caller-dies case missed worker-killed DOWN within500ms. These are
UNPROVEN transient timing causes, not fixed or waived by later green. Their
source/budgets remain exact. Host load6.58/9.12/8.72 observed, not a cause proof;
no unrelated process was stopped. Exact failing logs retained.

Root static pipeline actual ROUND28_TLS_STATIC_EXIT=0 AND prompt: compile WAE,
root format check, configured Credo, Dialyzer, git diff --check. Credo545files/
9126mods-funs/noissues15.6s; Dialyzer0errors/0skips, four unchanged unnecessary
ignore notices21.31s. No new suppression/shared config/dependency/runtime version
change. Earlier explicit timer-discard fix prevents R27 unmatched-return recurrence.
Five fully read ex_ssl architecture files remain exact847556a; root architecture
contract carries the narrow new provider assertion, not public support promotion.

Final standard provider gate actual ROUND28_PROVIDER_REGRESSION_EXIT=0 AND prompt;
job collected. HTTP_QUIC_PHASE1_REAL=1 root Mix --include integration --seed101/
max24: ExSSL846(20properties/826tests)101.2s; QUIC249/10.9s; Core418/24.4s;
FetchH2file43/5.9s. TOTAL1556/1556. This full ExSSL run includes all146 lifecycle/
birth cases, including both earlier legacy timing failures and new8. No separate
focused146/146 claim: last focused result remains145/146; later broader green
does not explain or fix earlier transients. Existing bitstring and Request
put_body_headers test warnings remain; no test-WAE or whole-nine green claim.

Acceptance is this narrow provider slice only. ACK does not prove peer delivery,
ROOT acceptance or cleanup; actual persisted-then-lost ACK was not forced. No new
actual post-Finished/pre-publication error-race proof, Setup failed ACK or all-error
constructor identity proof. Broader timeout/options/native/write/internal outcomes
retain existing behavior. Default OTP backend/public lifecycle remain unchanged.
Latest whole-nine execution remains R22 RED3201/3206+test-WAE; this selected green
does not supersede it. Original R21 physical-FD evidence and R23 ENOTSOCK result
remain unresolved; no native primitive, new FD campaign or release promotion.


## Round29 — bounded native connect-failure attribution

Entry main983913dedd6d9b10b974c937728443b7f48b7d14 clean; goal active/armed29/100.
Actual pwd/HEAD/status and six fresh accepted snapshots verified; prior FULL-read
five ex_ssl architecture files byte-exact847556a. Root owns formatter/Mix/build/
native/network/hash/pins/docs/commit. Task35 follows34; task20 owner explicitly
ACKs Observer-only additive overlap. Exact worker source scope Allocator+Observer
+ONE NEW connect_failure_test. NativeTCP/Setup/Conn/Writer/Ledger/Handoff/oldtests
and both strict source pins frozen. Test-first selected actual refusal must fail
with INTERNAL instead of CONNECT before implementation; no new API in that case.

Two independent READONLY reviews completed without commands/native execution.
Public OTP29 gen_tcp connect creates and connects, exposing its Port only on
success; no documented connect-existing-unconnected-Port or public fdopen route
was established. FD ingress does not document atomic socket-to-inet ownership
transfer, detach or close-on-failure continuity. A descriptor may be reused and
is not a typed monitor identity. Do not assume either duplication or transfer.
[gen_tcp connect docs](https://www.erlang.org/doc/apps/kernel/gen_tcp.html#connect/4).

Public socket.open gives an opaque identity before socket.connect; socket.monitor
delivers DOWN with type socket. Retaining that identity requires explicit ledger,
monitor, owner-transfer and send/recv transport support. It is NOT a drop-in inet
Port replacement or verified bridge. Allocation errors around open itself remain
conservative. This is a future design route, not implemented/executed this round.
[monitor](https://www.erlang.org/doc/apps/kernel/socket.html#monitor/1),
[connect](https://www.erlang.org/doc/apps/kernel/socket.html#connect/3),
[fd options](https://www.erlang.org/doc/apps/kernel/socket.html#t:otp_socket_option/0).

Test-first checkpoint NEW124lines/two actual cases FULLread by worker and Root;
all6current source snapshots exact; all789 other tracked apps exact983913d.
Root selected NEWfile:7 --include integration --max-failures1 --seed101 before
ANY runtime edit. Actual ROUND29_CONNECT_RED_EXIT=2 AND prompt; job collected,
38line log FULLread.0.4s,0/1passed1excluded. Actual Allocator normal DOWN followed
by snapshot roles1/allocations16/down1/losses16/closed/failed INTERNAL versus
required CONNECT. No new API calls or warnings; Reader assertions follow failure
and were not reached on RED. Only then Root explicitly resumed source grant.

Ranked diagnosis shown before GREEN: (1) unfinished Allocator DOWN uses generic
internal because no error attribution precedes stop: predicts CONNECT after new
record while allocation16 stays pending; (2) original deadline wins: predicts
timeout, inconsistent with0.4s versus5s budget/internal; (3) erroneous native
absence mapping: predicts cleared allocation, contradicted by retained16.
No debug instrumentation is needed for this deterministic interface witness.
Trace starts with real Allocator refusal; manual protocol cases separately
exercise trusted provider assertions, not independent native-phase attestation.

Source delivery task35 completed SOURCEONLY; Root task36 owns acceptance. Worker
TTY83 closed/nojobs/grant CLOSED. Root whole format, compile WAE and original
selected actual:7 GREEN actual EXIT0+prompt:1passed8excluded/2.6s,9loglines.
Then lifecycle+inert_birth focused actual EXIT0+prompt:155/155 in39.1s
(9.2async/29.9sync), all NEW9 included. Logs collected/FULLread. No additional
source fix was needed after the meaningful RED. Full new file is412formatted
lines; runtime Allocator272/Observer976. Cleanup after these errors remains unconfirmed.

Root static actual EXIT0+prompt: compile WAE/root format check/configured Credo/
Dialyzer/git diff --check. Credo546files/9154mods-funs/noissues22.4s; Dial0errors/
0skips/four unchanged unnecessary-ignore notices33.22s. No suppression change.
Formatted whole Observer881 reconstructs by removing FOUR additive blocks only;
whole Allocator254 reconstructs by replacing only continue/new-helper range.
Root independent reverse guards PASS. Tracked apps791:exactly2authorizedchanged/
all789others byte-exact983913d including symlink target bytes. ONLY NEWtest
untracked. Conn61b2fa41... and frozen HTTPSpressureb4f4f8b3... unchanged.

Required read-only final Quic review: full formatted Allocator272/NEWtest412
and all95Observer additions plus reused predicates; no blocking source finding.
Two actual tests prove loopback refusal only; reachability errors and direct SDK
ACK are cooperative/source coverage. Actual snapshot CONNECT is not independent
Allocator ACK-delivery evidence. No old tests, deadlines or source pins changed.

First standard provider run actual EXIT2+prompt: ExSSL854/855 in127.6s
(26.1async/101.5sync), QUIC249/18.2s, Core418/39.8s, FetchH2file43/9.4s.
TOTAL1564/1565. Only failure: old NativeTCPTest:6 at attempt:81 BIND returns
deadline_exceeded, budget captured BEFORE Observer.start; NOT a start failure.
Observer.start had succeeded. No TCP allocation or new recorder at this seam.
Initial commentary mistakenly named start, then corrected after source read.

Ranked follow-up: inherited 1s budget consumed during concurrent startup; defect
in unchanged startup/bind path; indirect new-code/build-context effect. Isolated
unchanged NativeTCPTest:6 repeat5 means SIX executions:6/6,49lines FULLread,
actual EXIT0+prompt. Same original provider command then reran unchanged: EXIT2
+prompt, ExSSL854/855 in126.1s(28.2async/97.8sync), QUIC249/14.7s, Core418/27.2s,
FetchH2file43/9.9s, TOTAL1564/1565. This time same test fails at attempt:80 START
with acceptance_unconfirmed. Neither run enters its TCP call. No widening,
async-flag change, repeat-until-green loop or global concurrency knob was used.
Two old warm-build failures are UNEXPLAINED; isolated green is not their repair.

Isolated baseline control: detached /tmp/http-fetch-round29-baseline at exact
983913d; own /tmp/http-fetch-round29-baseline-build and existing root deps.
No current-worktree replacement or snapshot restoration. Full clean root compile
WAE then baseline ExSSL846/846(20properties826tests) in107.9s(24.3async/83.6sync),
actual EXIT0+prompt. Baseline logs also contain old LocalTLSPeer forward_records
closed MatchError after a test; ExUnit reports allpassed, no claim it was fixed.
Baseline did NOT reproduce startup failure, so preexistence is NOT established.

Next one-variable build-context check: same CURRENT source and standard four-scope
provider command/seed101/maxcases24 in NEW /tmp/http-fetch-round29-current-build.
Clean root compile WAE and actual EXIT0+prompt: ExSSL855/855(20properties835tests)
107.9s(22.2async85.6sync); QUIC249/12.4s; Core418/25.2s; FetchH2file43/8.0s.
TOTAL1565/1565. No source/test/budget/config changed between provider runs.
This supplies fresh-source regression evidence, not a diagnosis of cache damage,
host load or a timing repair. Existing bitstring/Request test warnings remain;
NOT test-WAE or full-nine evidence. No more broad repeats after this pass.

Boundary: only cooperative LIVE failure attribution has advanced. NativeTCP69,
Setup525, Connection1684, Writer, ledger, handoff, Reader/Receipt, all old tests,
original budgets, both SHA pins, default backend and public capability stay fixed.
Unknown TCP permit prevents seal; Reader observer_unsealed remains UNCONFIRMED.
No original errno is durably stored, no native absence or physical FD closure
is established; no complete all-error constructor identity, Setup failure ACK,
actual persisted-then-lost ACK delivery or public lifecycle/socket acceptance.
Latest whole-nine remains R22 RED3201/3206+test-WAE; R21/R23 physical FD evidence
remains unresolved. No new FD/native diagnostic campaign or descriptor bridge.
Goal remains active; P0--P7/default switch/nine publication/cold consumer open.


## Round30 — public socket identity prototype

Entry clean main17f85c98d439fae7b513990960ca619bf5b1426d. Human continue;
goal re-read confirms revision2/armed, engine roundsStarted29 (work slice30).
Repeated resume calls wrongly retained edit-only fields; stopped repeating and
re-read actual state. No further resume calls or goal completion/blocking.
Root TTY84 uses accepted fresh R29 build, MIX_ENV=test, existing Python venv.
Five previously FULL-read architecture docs freshly byte-exact847556a.
Task37 Root temporary prototype/docs only; production/tests/default frozen.

Readonly independent source review: five-module patch insufficient. Ledger TCP
accepts Port only; Observer monitors/owner facts, Allocator transfer/close, Setup
allocation/ownership/second monitor, Connection attach/commit/close/active-once,
Writer send/shutdown all need deliberate opaque-socket transport support.
Pure Handoff compares canonical identities but inherits their restricted type.
R29 connect recording requires pending permit with NO enrolled TCP: do not reuse
it for a known pre-enrolled socket or infer phase from errno. Keep open failures
and successful-open/interrupted-enrollment gap conservative. Review no execution,
edits, native/network/hash/TTY; all source locations returned to Root.

Installed runtime Elixir1.20.1/OTP29.0.2/ERTS17.0.2. Root Code.fetch_docs(:socket)
reads installed PUBLIC open3/connect3/close1/monitor1 docs; actual EXIT0. Readable
118line log FULL-read. Unversioned web page now29.1.2 is not runtime version.
Connect timeout/cancel leaves uncertain platform connection state: close known
socket; never infer native absence. Public monitor produces exact DOWN/ref/socket/
opaqueObject/Info; missing object may report nosock. Close is no peer-delivery ACK.
Root temporary207line script formatted/fully read. Memory-only interactive TUI
uses pure record reducer + explicit I/O; no tests/deps/runtime hooks added.

One batch supplies r/c/k/t/q to the same interactive interface through root mix run.
Actual ROUND30_SOCKET_PROTOTYPE_EXIT=0 AND prompt; job collected.453line log:
all four final snapshots reviewed plus event search, not a full-log-read claim.
Each scenario native/control operations share original entry+1000ms, observation
parent entry+3000ms, independent inet peer entry+2000ms including accept/read.
No sleeps/forcedGC/rawFD/lsof/BPF/nativeC/SSL internals/descriptor bridge. Native
open/close themselves expose no timeout argument; observed completion here does
not establish a universal bounded syscall or cleanup guarantee under load.

Observed original public identities and events (manual prototype, NOT test suite):
- Refusal: opened owner338; original monitor194890 captured BEFORE connect;
  econnrefused with owner338 still queryable; explicit close then matching
  original monitor closed.9ms observed whole scenario, no peer connection.
- Connected close: owner341/monitor194892, non-owner caller101 sends ping; inet
  peer reads exact ping; owner close OK; matching socket DOWN closed; separately
  peer recv error closed.6ms. Close return alone was not used as terminal proof.
- Owner kill: owner344/monitor186168, peer exact ping; original owner DOWN killed,
  original socket DOWN closed, separately peer recv closed.3ms.
- Transfer: owner347 ->348 via public setopt otp controlling_process. Original
  socket monitor186221 retained;347 DOWN killed before non-owner101 sends pong;
  inet peer reads exact pingpong.348 closes; SAME original monitor closed and
  separate peer recv closed.3ms. No monitor replacement or former-owner close.
All printed opaque socket terms are kept whole, never parsed as a private shape.
Only exact original monitor/ref/socket accepted by receive. These measurements
are single observations, NOT latency distribution/performance/FD reclamation.
No unreachable/timeout/cancel/blocked output/TLS/STARTTLS/public owner-ACK matrix.

Answer: pre-connect canonical identity and monitor continuity are viable for
successful open and ordinary loopback lifetime. First runtime step must be a
separate private enrollment path for actual opaque socket; preserve inet Port
behavior and exact monitor identity, sticky unknown permits and original leases.
A known enrolled connect error needs a separate authenticated phase transition.
The open-to-enrollment gap/open errors remain unknown, NOT pre-native rejection.
Prototype removed after literal absolute target check. A REPL archive attempt
had a compound-statement syntax error and created NO archive; its combined
archive/removal marker was NOT archive proof. Full207line source is captured
in session and453line result log remains; durable findings retained here. No production capability promoted. R29
warm-build failures and latest R22 whole-nine RED/FD21+23 remain unresolved.


### Round30 continuation — dial-only typed socket ledger

Entry accepted6873138. Task38 initially source-only; required-field write schema
conflicted with forbidden sandbox fields. Worker attempts were REJECTED before
FS changes; no approval/escalation or worker execution. Stopped retries, reassigned
to Root; Root authored via TTY84 from readonly proposal. Quic/task20 scope ACK:
all old scopes frozen, no conflict. Fresh8originals at687 before first source edit.
Root initial86line case with actual public socket/original kernel monitors:
existing Ledger.enroll BEFOREconnect expects use; actual RED invalid_monitor_identity
at23 in0.1s,21line log FULL-read, actual EXIT2 AND prompt, before runtime edits.

Only runtime file ResourceLedger223->231: public identity union adds socket;
valid_identity gets scope and admits socket ONLY dial/TCP. Opaque object validity
and actual monitor establishment belong to trusted runtime, not pure attestation.
No native calls/opaque-shape guessing. Upgrade adopt/direct-enroll socket and
process-role socket still reject; old Port/process any-scope guards preserved.
Existing exact ref/type/object/live DOWN matcher, unique monitors, masks, unknown
permits, late stop, loss and proof body unchanged. First actual GREEN1/1 in0.1s,
27line log FULL-read, actual EXIT0+prompt. Then focused3/3 in0.5s EXIT0+prompt.

New actual native three-case file: kernel original process/socket monitors and
public opaque objects retained, no runtime/private-state hooks or VM sender spoof.
Wrong ref/kind/object are DIRECT PURE event data; cannot advance; real socket DOWN
settles bit16 only, replay idempotent, actual owner DOWN completes17. Negative
role/upgrade acceptance checked. In loss case actual opened owner dies BEFORE TCP
identity enrollment: actual socket DOWN alone cannot resolve pending16. Explicit
admission OPEN/loss16 assertion, late enrollment MUSTstop BEFORE closing admission;
original socket DOWN finally settles17/17 with LOSS16 still UNCONFIRMED.

Standard provider command (HTTP_QUIC_PHASE1_REAL=1, root, includeintegration,
seed101/max24, same accepted fresh R29 build) actual EXIT0 AND prompt, jobcollected:
ExSSL858(20properties838tests)116.8s(34.4async82.4sync); QUIC249/8.5s;
Core418/23.2s; H2file43/5.7s. TOTAL1568/1568 applies INITIAL195line fixture.
Existing bitstring/Request test warnings persist; not test-WAE/full-nine proof.
Readonly review suggested canonical permit ordering. AFTER provider EXIT, Root
refined ONLY new test: Allocator permit BEFORE inert spawn, original process
enrollment/TCP permit BEFORE :open, socket monitor BEFORE TCP enroll/connect.
Original absolute native entry+1s and parent entry+3s passed unchanged, timer
created once, inert owner checks original native E before open. All3samecases
final211lines, no extra case/oldtest/async flag changes. Final refined3/3 in0.3s,
actual EXIT0+prompt,8line log FULL-read, jobcollected. Runtime ledger unchanged
since1568green; scoped final fixture rerun is separate evidence. No broad repeat.
Root/independent reviewer FULLfinal211+231 read, no blockers, no further edits.

Static: root compile WAE0; root format check0. Root mistakenly selected EXTRA
credo --strict: EXIT14 stops chain BEFORE Dialyzer.547files/66checks found212
suggestions (12refactor/35readability/165design); no entries in two changed files.
No strict-baseline cleanup authorized/performed. Preserve failed extra log.
Configured mix credo:547files/54checks/9162mods-funs/noissues13.0s. Then Dialyzer
0errors/0skips/4unchanged unnecessary ignores16.45s. Combined actualEXIT0+prompt,
jobcollected. No config/ignore suppression edits. Source boundaries rechecked:
HEAD687 trackedapps792; all791 OTHER files byte-exact, including symlink target
bytes. Ledger original223 reverse-exact after removing new branch/type/scope-arity
changes. Connection61b2fa41... and HTTPSpressureb4f4f8b3... fullSHA match unchanged.
Alloldtests/roles/flags/budgets/pins/Setup/Allocator/NativeTCP/Writer/Reader/Receipt
and Observer remain frozen; docs3 updated with actual narrow compatibility.

Boundary: pure ledger fragment only. Kernel/socket DOWN proves its defined local
termination fact, not physical FD/kernel reclamation, peer EOF, Observer absence
or receipt seal. Real Observer has NO socket enrollment/ownership API yet; no
transport/facade/default change, no durable all-error settlement or STARTTLS.
Next separate scope must authenticate original creator/owner, establish original
public socket monitor and preserve late known accounting without :use after
expired admission/request deadline. Public monitor1 has no timeout argument:
receiver needs fresh checks after monitor establishment as well as before entry.
Known-socket connect attribution remains separate from R29 pending-permit path.
R22whole-nineRED/FD21+23/R29warm startup failures remain unresolved; goal ongoing.


### Round31 — closed-owner reference prerequisite for Observer enrollment

Entry clean1da5d6c, goal automatic30/100, task40 claimed then narrowed before SDK
implementation after concrete public-API uncertainty. Fresh8current source snapshots
/tmp/http-fetch-round31-originals; five previously FULL-read architecture docs
freshbyte-exact847556a. Task20 advisory explicitACK/alloldscopesfrozen. Root85 sole
writer/native executor; peers readonly. No sandbox fields/escalation or private
OTP/socket registry state, forcedGC or FD campaign.

Public OTP29.0.2 standalone37line scenario actual EXIT0+prompt/jobcollected,
131line result FULL-read: open info.owner/current controlling_process matches
actual creator; after explicit close ownerundefined/getopt errorclosed; NEW actual
monitor stillDOWNclosed. Actual creatorKILL shows same ownerundefined/getoptclosed
afteroriginal process/socket DOWN. This is current public-state evidence, NOT
past-owner/constructor authentication or physicalFD reclamation. No peer/TLS claim.
Source/result retained in /tmp/http-fetch-round31-socket-metadata.exs/.log.

Durable NEWsocket_owner_reference_test77lines TWO independent reference cases:
explicit self-close ACK while owner remains alive before AND after original socket
DOWN; separate original processKILL/DOWN case. Both assert public positive owner
beforeclose, ownerundefined/getoptclosed after; differentlateactualmonitor ref and
itsown exact typedDOWNclosed. No manufactured VM DOWN or opaque shape parsing.
Single originalnativeE1s/parent3s, remainingclipped, parenttimeronce, ownedcleanup.
Root and independent reviewer FULL77 source accepted, no blockers/runtime change.

Root depsget unchanged18lineFULLread +compileWAE actual0+prompt. New2 plus accepted
SocketLedger3 scoped rootseed101/max24/includeintegration:5/5 in0.3s, actual0+prompt,
8line logFULLread. Reference expected results are public OTP observations, not a
provider implementation RED/GREEN claim. Rootformat/configuredCredo548files/9166
mods/noissues11.9s/Dial0errors0skips4unchangedunnecessaryignores20.09s combined
actual0+prompt; alljobscollected. All793OLDtrackedapps byteexact to1da including
symlinktargetbytes, hence allruntime/oldtests/pins/flags/deadlines frozen.

Architecture correction BEFORE SDK: CLOSED at FIRST enrollment cannot establish
past creator/current owner. Even a valid original permit and lateDOWN must not
consume unknownTCP from a closed-foreign object. Leave permit unknown. Distinct
case: owner positively authenticated BEFORE real monitor creation, then closure
or R/E/admission expiry DURING the operation: retain successfully established known
monitor identity, preserve losses and deny use. Publicmetadata lacks timeout arg;
fresh post-monitor checks constrain authorization, not native preemption.

Readonly FULLObserver976/Handoff126 audit found latent integration hazards, NOT
reachable newruntimefeatures today: handoff_identity_live?691-692 has no Socket
clause; handoff_owner694-701 assumes Port.info; publishconnected809-817 liveflags
alone could admit unsupported kind. Fence these BEFORE new enrollment. TLSfailure
569-582 already requires Port; R29connect516-525 requiresNOknownTCP; preserve.
writer/connectionready are process-only beforeTCPbirth; stop_process892-895 never
nativecloses; actualtypedDOWN221/838 alreadyexact. NoLedger/Handoffeditneeded.

No broadprovider/fullnine repeats for reference-only newtest with zero runtime
changes. Prior R30selected1568/1568 not superseded; latestfullnineR22RED andFD21/23,
R29warmstartup failures remain unresolved. Task40 actual SDK/Observer implementation
remains INPROGRESS: meaningful existingAPI actualSocket RED, authenticated original
liveAllocator generation/currentowner, realmonitor/postR checks/unsupportedkind
fences/foreign-live+closed-first negatives still required before separate acceptance.
Publicsockettransport/TLS/default/publiclifecycle/wholegoal not promoted.


### Round32 — private socket enrollment implementation; source gate still RED

Entry cleand29cab3/goal31-of100; Root86solewriter/formatter/Mix/native/hash/docs/
commit. Task40implementation scope ObserverONLY +NEWtest +docs3, task20explicit
advisoryACK/allotherappsfrozen. FreshCURRENT8snapshots/tmp/http-fetch-round32-originals,
five priorFULLarchitectureDocs byteexact847556a before architecture changes.
Newruntime1109lines (not interim1111 label), original976 reverseBYTEEXACT after
removing only new socket blocks and restoring one typed Port ownership signature.

First meaningful RED: original enrolled Allocator with real owned pre-connectSocket
calls existing enroll_port, expected use got invalid_resource, actualEXIT2+prompt,
0/1 in0.1s/log21FULLread BEFOREproductionedit. DedicatednewSDK/wire enroll_socket
added; ONEfixtureSDKcall moved after RED, entire legacyPortSDK/errorprecedence
retained. Sameownership/accountingoracle GREEN1/1 in0.1s +compileWAE0. Not an
undefined-new-function RED. Publicinstalledsocket monitor/cancel_monitor docs10
FULLread actual0: independent real monitors; cancel true/false semantics respected.

Receiver review found an actual new bug: rawfourfield operation bypassed outerR
normalization, and noninteger outerR passed Erlang term ordering. SECOND realRED:
originalAllocator sends raw3outeratom, expected invalid_deadline got USE, EXIT2,
1/2 in0.6s/maxfail1/log20FULLread. FIX dedicated Socket-onlyhandle_call BEFORElegacy:
integerouter3 accepted; malformed3/allinjected4 reject; guardedoperate+fallback.
Legacygeneric restored original bytes. Actual3/3 in0.2s/WAE0 then4/4 in0.3s.
No flaky1ms/post-monitor-overrun repro or SDK-only validation claim.

SDK scope: dial/TCPstreaminet/inet6 only; exact original live unfinishedAllocator/
creator-monitor/Rootlineage +public currentowner BEFORE actualObserver socketmonitor.
AFTERmonitor recheckowner, expiry, authority, Ledgeradmission, physicalprovider/
controller/owner alive and fresh integerR before use. Already authenticated actual
identities survive lateauthdenial asknownstop afterretire, withoutloss/grace reset.
ClosedFIRSTrejects beforemonitor and leavesunknownpermit. Cancelabandonedmonitor
withpublicsocket.cancel_monitor, NOTProcess.demonitor. NoNativeclose inObserver.
Socketkind DENIEDbyPort-onlyhandoff andconnectedpublication; TLSfailurePorttyped,
R29no-knownTCP guard preserved; actualtypedDOWN/Receipt/Reader bodies unchanged.

NEW207line testcase5 +acceptedledger3+closedownerreference2 actual10/10 in1.4s,
EXIT0+prompt, freshrootdeps.get/compileWAE0. Five behavioraloracles: ownedbefore-
connect17/17actualDOWN; wrongPID/liveforeign/closedforeign pending16thenownuse;
raw3outeratom/raw4inneratom rejectpending16thenownuse; FULLreal31rolegraph with
processreadiness rejectsSocketprepare/connected andremainsalive/pendingthen31/31;
ownclosedFIRST actualORIGINALcollectorDOWN whileAllocatorALIVE stillrejects,
keepsroles1/alloc16/loss0, cancelactualOwnerDOWN thenReaderobserver_unsealed and
Receiptunsealed. Realmonitors only/no spoofedDOWN/privatestate/timinghooks.

Independenttls-http-static FULLreadfinalruntime1109/newtest207/base976/docs10:
FINAL_SOURCE_ACCEPT/nofindings AFTERdeadlinefix; workerNOexec/native/write/hash/TTY.
RootONLY actualsource reverse976 +all793othertrackedappfiles/symlinkbytes exactd29.
OriginalConnection1684/upload371/strictpins503:291and2558:2312 untouched bythatguard.
Originalnative1s/parent3s and legacyasyncflags/caps unchanged. Publicgetter/monitor
lacknative timeout; fresh checks constrainAUTHORIZATION, not hardNifpreemption.
Cooperative provenance only, notVMsender/constructorphase/physicalFDattestation.

First four-scope provider EXACTR30command/seed101/max24/realQUIC1 under accepted
R29-current-build EXIT2+prompt: ExSSL864/865(20/20props,844/845tests)115.2s,
Quic249/24913.9s,Core418/41825.1s,H2file43/436.6s =>1574/1575.
ONLYfailure oldNativeTCPTest:6 attempt:80 Observer.start ->acceptance_unconfirmed,
BEFOREListener/Allocatorbirth/TCPpermit/nativeentry. Allnew5pass. FAILUREretained
/tmp/http-fetch-round32-provider.log396lines, actualfailure7–16/statsall4read.
SameSource freshMIXbuild32 (literalnewpath existenceguard) ALL9compileWAE0,
compilelog54FULLread; SAMEseed101/max24/4scopes no source/deadlinechange.

Freshprovider EXIT2+prompt: ExSSL864/865100.3s,Quic249/24910.3s,Core418/41823.6s,
H2file43/435.7s =>1574/1575 AGAIN. SameoldNativeTCPTest:6 NOWattempt:81 BIND
->deadline_exceeded, samefixturebudgetcapturedBEFOREstart. FAILURE396lineremains
/tmp/http-fetch-round32-fresh-provider.log; actualfailure7–16/allstatsread.
FreshartifactaloneNOTrepair; start/bind failuresdoNOTidentifyonecause. R29sameold
case variants/R30greenhistory persist; no preexistence/cache/hostload diagnosis.
Rootconfiguredstatic actualEXIT0+prompt: format0, Credo549files/9195mods14.5s0issues,
Dial0errors0skips4unnecessary21.1s. ALLlogsretained; no strictCredo runthisround.

Task41 READONLYaudit (claimedrev2) FULLBootstrap70/NativeTCP69/oldfixture136/
ObserverSupervisor10/parent17: ONLYObserverTestdirectglobalObserverSupervisorpause,
asyncFALSE; inertbirthpausesConnectionSupervisor, asyncFALSE; appstopsalsoFALSE.
Directasyncoverlap theory WEAKENED, notproved. Bootstrap requiresDSlaunch, alias
result, workerNORMAL-DOWN AFTERtimer.cancel, thenreservationRPC underSAMEentryR;
unknown collapsesmultiplephases. SeparatefixtureB=entry+1000 BEFOREstart reused
bind/reserve/enroll explainsdifferentfailurelocations, nottheunderlyingdelay.

Next task41 Rootphasecapture: originalfixturePREFIXthroughAllocatorready, ORIGINAL
1sB/parent3s/startinfinity, freshcontrolledcallerPERtrial/failureendscaller, firsttrial
retained thenbounded24stress; ifnotrepro minimizeactualasynccompetitormoduleswith
originalcase/seed/max24. One-shotpublicOWNprocessmetadata(~750ms)maydistinguish
Bootstrapawait/await_down/workerarm/DSRPC/timercancel/reservationRPC; no polling/
statehooks/trace/privateOTP. No synchronousDSenumerationoncriticalpath. Killing
Bootstrapworker DOESNOTcancelalreadyqueuedDSstart; livinginfinite-deadlinecontroller
canleavelateUNBOUND30sreservation(noNative); neverretryfromsamestilllivingcontroller.

No task41instrumentation/loop/nativeexecution/write was performedthisround; cause
UNPROVED, allruntimefrozen aftersourceacceptedSDK. Task40 remainsIN_PROGRESS/source
integrationgateOPEN despitefocused10/staticgreen. GoalACTIVE/ARMED/notcomplete/
notblocked. Task41needsactualphasefeedback BEFOREfix; no repeatedfreshbuildasrepair.
SocketTLSbyteI/O/fullnativeLifetime/known-socketfailure/publiclifecycle/default/
managedH1H2/completion/duplex/H3productscope/FD/perf/publicationstayUNACCEPTED.
Latestwhole-nineR22RED3201/3206+testWAE andFD21/23 gaps remainunrepaired; selected
Quic/Core/H2greens doNOTsupersedethem. No budget/assertion/pin/flag/cap weakening,
GC/privateOTPSSL/NSS/keylog/BPF/lsof/rawFD/SIP/helperFDcampaign/publish/defaultflip.


## R33 — control-code readiness before timed admission

Baseline cf5ef51; task41 startup regression and task40 private enrollment acceptance.
The production change is confined to ObserverSupervisor: load seven private control
modules plus the directly called OTP :timer/:atomics modules before returning the
original DynamicSupervisor flags. Code.ensure_loaded! errors fail startup. This
loads code, without constructors, timer-service priming, key generation or native
transport allocation. Successful supervisor/application startup is the readiness
boundary; registration/name visibility alone is not. Original attempt, cleanup,
native1s/peer2s/parent3s/Wire8s budgets and every old/new assertion remain unchanged.

Minimization did not initially reproduce the failure: corrected owned-prefix30/30
(6 sequential, then24 concurrent), five original async modules25/25 in6.1s,
57 async files511/511 in9.1s, and all ExSSL files with --only async:true511/511,
354 excluded,21.2s. Seed101/max24 throughout. The inventory has58 async module
headers across57 files. Standalone mix-run script compilation can load referenced
API modules before its first trial; retaining that trial is not an application-cold
proof. The first diagnostic run's weak cleanup oracle is not upgraded by v2.

V2 asserts cancellation and exact Reader role1/down1/confirmed cleanup before
trial_done; success additionally requires normal controller DOWN. Each failure
ends its fresh controller; no surviving caller retries. Stale watchdog messages
must match a current trial. Output is deferred until the cohort ends. The3s
coordinator watchdog is soft; metadata sampling is non-atomic. No listener/native
connect occurs in this prefix. Public metadata is limited to status, queue length,
MFA arities and, in the extended probe, initial_call/file/line and at most16 related
PIDs. No messages, capability values, private state, tracing or FD campaign.

A temporary public ExUnit formatter, loaded before Mix, launched one owned prefix
when the first NativeTCP test started. Production Bootstrap and original tests were
unchanged; diagnostics used --max-failures1, integration, seed101/max24/realQUIC1.
The initial750ms probe reproduced original NativeTCPTest:81 bind deadline failure:
138/139 passed,19.2s, actual exit2. At born+752ms the owned caller awaited Bootstrap,
its actual monitored worker awaited the supervisor RPC, and the shared supervisor
awaited proc_lib.sync_start with queue1. Owned start returned ok at1390ms, then bind
rejected with original budget remaining -390ms.

The separate extended750ms run passed865/865 in100.5s, exit0: owned start522ms,
cancel523ms; at born+773ms its caller was in code.ensure_loaded/error_handler from
the Reader.await call site, with the supervisor idle. Reader completed856ms.
Moving ONLY the one-shot sample to250ms reproduced original NativeTCPTest:80
acceptance_unconfirmed:132/133,19.0s, exit2. At born+251ms the owned caller was in
code_server.call -> code.ensure_loaded -> error_handler.undefined_function ->
Observer.start/3 line25 (the remote Bootstrap entry), with no monitored worker and
an idle supervisor. Owned start later failed at1235ms.

These are direct runtime autoload observations on a matching failing path, not a
partition of the entire delay. The outer fixture clock precedes Observer.start's
internal clock;1390ms does not prove an internal deadline violation. Supervisor
relations do not identify the pending child or attach it to the owned request.
The code-server occupant is unproved; the audited16MiB synchronous test module
attribute is load work, not an established cause. The formatter's coordinator was
unjoined, so incomplete output would be inconclusive; the recorded witnesses have
complete outcomes. Six pre-Mix helper warnings reflect absent project code paths,
not production compile failures or runtime undefined APIs.

Paired control: same fresh-VM entry, formatter name, literal seven-module list,
logging, full ExSSL selection, seed101/max24, integration, realQUIC1 and max-failures1.
Only the Enum.each callback changed: Code.ensure_loaded! versus fn _ -> :ok end.
No prefix sidecar, constructors or Bootstrap override ran in either control.
Preloading passed865/865 (20 properties,845 tests),99.9s (18.6async/81.2sync), exit0.
The no-op reproduced NativeTCPTest:80 acceptance_unconfirmed,144/145
(5 properties,139/140 tests),23.3s, exit2. This supports preparing the code before
operational readiness; the bundle does not isolate each module's necessity.

The production list adds :timer and :atomics because Bootstrap calls kill_after/
cancel and Receipt calls atomics.new directly. Loading a module does not call these
operations. It does not pin code against later purges or cover all TLS/transport
modules. The original registered name, start_link and supervisor strategy remain.
Independent review read all28 source lines against the original10: SOURCE_ACCEPT.
All795 tracked app/symlink bytes matched cf5ef51 before editing; all794 OTHER app
files matched after normal gates, including the five previously read architecture
files, Connection, Upload, strict pins and all old/new tests. Only the supervisor
and these three canonical documents change.

Normal source gates, using fresh Mix VMs and the current build, with no diagnostic
require/formatter/preload flag/max-failure limit:

| Gate | Actual result |
| --- | --- |
| Root nine-app compile --warnings-as-errors | Exit0 |
| Entire lifecycle test directory | 148/148;32.2s;exit0 |
| Entire ExSSL | 865/865;97.8s;17.6async/80.2sync |
| Entire Quic | 249/249;9.7s |
| Entire Core | 418/418;23.6s |
| Existing Fetch H2 test file | 43/43;6.0s |
| Original four-scope command | 1575/1575;exit0 |
| Root format/configured Credo/Dialyzer | Exit0 throughout |

Credo:549 files/9195 modules/functions,13.2s, no issues. Dialyzer:0 errors/0 skips,
four existing unnecessary ignores unchanged,17.91s. All command chains have actual
exit markers and returned prompts. No strict-Credo cleanup or source/test workaround.

```bash
HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test apps/ex_ssl/test apps/elixir_quic/test apps/http_core/test apps/http_fetch/test/http/socket_client_http2_test.exs --include integration --seed 101
```

Retained local evidence (initial119-line probe was iterated in place; the current
v2 standalone source applies only to the v2 log; first aggregate remains weaker):

```text
/tmp/http-fetch-round33-start-prefix.exs
/tmp/http-fetch-round33-prefix.log
/tmp/http-fetch-round33-prefix-v2.log
/tmp/http-fetch-round33-five-module.log
/tmp/http-fetch-round33-async-files.json
/tmp/http-fetch-round33-async.log
/tmp/http-fetch-round33-all-files-async.log
/tmp/http-fetch-round33-prefix-lib.exs
/tmp/http-fetch-round33-formatter.exs
/tmp/http-fetch-round33-probed-suite.log
/tmp/http-fetch-round33-prefix-links.exs
/tmp/http-fetch-round33-formatter-links.exs
/tmp/http-fetch-round33-probed-links-suite.log
/tmp/http-fetch-round33-prefix-early.exs
/tmp/http-fetch-round33-formatter-early.exs
/tmp/http-fetch-round33-probed-early-suite.log
/tmp/http-fetch-round33-preload-formatter.exs
/tmp/http-fetch-round33-preload-suite.log
/tmp/http-fetch-round33-noop-formatter.exs
/tmp/http-fetch-round33-noop-suite.log
/tmp/http-fetch-round33-observer-supervisor.original.ex
/tmp/http-fetch-round33-source-compile.log
/tmp/http-fetch-round33-lifecycle.log
/tmp/http-fetch-round33-source-provider.log
/tmp/http-fetch-round33-format.log
/tmp/http-fetch-round33-credo.log
/tmp/http-fetch-round33-dialyzer.log
```

Task41 startup correction and task40 private socket enrollment now pass their source
integration acceptance. This does not implement Socket TLS byte I/O, handoff or
known-socket connect-failure settlement, public lifecycle/completion/duplex,
managed H1/H2, default-backend replacement or publication. Latest whole-nine R22
3201/3206 plus test-WAE failures and FD21/23 evidence gaps remain unrepaired and
are not superseded by these selected greens. No physical-FD/peer-terminal guarantee,
capability promotion, timeout widening, forced GC or private OTP SSL/state access.
Unit/integration/E2E separation (unit-only mix test/test.yml, external collaborators
mocked in unit tests), final GitHub push and next-major coordinated release also
remain required by the active goal and unaccepted here.
The P0-P7 goal remains ACTIVE/ARMED and incomplete. Next: test-tier isolation and authenticated native Socket
transport lifetime/failure settlement before public/default promotion.


## R34 — classify actual lifecycle I/O without losing VM-only cases

Baseline cdc4c4a7b224d2c70d7692b688b296d3a587fbb4, Goal33/100 active/armed,
task42 IN_PROGRESS. Root checked clean HEAD, root instructions and root Mix/CI entries; two read-only
reviewers audited app helpers/support and classified100 ExSSL and
213 other test files, including transitive fixture/normalizer effects. These are
static behavior classes, not current default eligibility or executed case totals.
U below includes VM actors/crypto and static runner fixtures; I includes actual
external/environment/application-lifecycle work; M preserves mixed-case boundaries.

| App | Whole U | Mixed | Whole I | Files |
| --- | --- | --- | --- | --- |
| ex_ssl | 47 (9 with static runner fixtures) | 10 | 43 | 100 |
| elixir_quic | 30 | 3 | 5 | 38 |
| elixir_quic_http3 | 10 | 0 | 1 | 11 |
| http_core | 29 | 3 | 4 | 36 |
| http_runtime | 9 | 5 | 2 | 16 |
| http_fetch | 22 | 14 | 49 | 85 |
| http_event_source | 3 | 1 | 3 | 7 |
| http_web_socket | 5 | 4 | 6 | 15 |
| http_web_transport | 5 | 0 | 0 | 5 |
| Total | 160 | 40 | 113 | 313 |

Fetch has85 files and86 top-level test modules: request_completion has a second
VM-only BackendTest. The eight-app subtotal is213=113U+30M+70I. Counts include
SUT file reads as integration, even when the transport itself is a VM fake.

The first authorized implementation touches ONLY nine ExSSL test files: four whole
native-I/O modules and five mixed files. Four module attributes plus21 case attributes
add25 lines. Module tags cover Allocator4, NativeTCP4, NativeHandoff6 (generated
cases included) and Setup6. Mixed native cases add17 inside lifecycle/ and4 in
inert_lifecycle_birth, outside that directory.

| Scope | Existing cases | Unit | Integration |
| --- | --- | --- | --- |
| Lifecycle directory | 148 | 76 | 72 |
| Separate inert lifecycle birth file | 17 | 13 | 4 |
| Combined pilot | 165 | 89 | 76 |

Existing directory integration cases were35; new tags classify37 more, plus4 outside.
Authority13, Handoff2, Reader8 and InertHandoffReady5 remain VM-only. Mixed files retain
Observer25/27, ObserverHandoff2/14, ResourceLedger16/17, Receipt5/7 and InertBirth13/17
as units. Real TCP/socket creation and ownership/monitor/peer facts stay integration.
A model Ledger DOWN/proof, including the case that keeps its Port alive, remains
model evidence rather than physical resource retirement proof.

Actual baseline NativeTCP default command (no integration flag) ran all4 real-TCP
cases:4 passed in1.2s, exit0. This exposed a classification policy gap, not a failing
application assertion. After tags, the identical command selects0 with4 excluded,
0.3s. No test was deleted or weakened. Actual combined normal commands, seed101,
max24: default89 passed/76 excluded in10.1s (4.5async/5.6sync); --only integration
76 passed/89 excluded in32.6s (7.8async/24.7sync). Both use the existing helper and
no temporary formatter/probe; their chain returned actual exit0 and prompt.

The original four-scope command, no probes/formatter/extra filters, still passes
1575/1575: ExSSL865/865 in104.4s (20.4async/83.9sync), Quic249 in10.3s, Core418
in24.8s and Fetch H2 file43 in6.3s. Same seed101/max24/real-QUIC flag/integration
selection. Actual exit0 and prompt. Root test-environment deps/compile-WAE prep0;
configured format0; Credo549 files/9195 modules-functions/no issues13.2s; Dialyzer
0 errors/0 skips, four unchanged unnecessary ignores,17.84s. Static chain0+prompt.
Global python lacked h2 (probe exit1); existing P0 venv restored on PATH, verified
OpenSSL4.0.3/h2 4.2.0 exit0 before full regression. No dependency install or source
change was used to fix an environment probe.

Before editing, all795 tracked app/symlink bytes matched HEAD. After formatting,
removing ONLY the25 inserted attribute lines reconstructs all nine original test
files exactly; all786 other tracked app/symlink bytes match cdc4c4a, including all
production code, strict pins and the R33 supervisor. Independent review read the
full232-line diff and original contexts: SOURCE_ACCEPT/NOBLOCKER. No callback,
helper, async flag, fixture, peer pin, assertion or deadline changed.

Deferred boundaries are concrete. ExSSL Options.normalize resolves system trust
before later offer/identity validation; cached cacerts_get is not deterministic
fixture input. Options25 has only6 currently VM-only cases; PKIX has27 fixture units
plus one live-trust case. Protocol resumption-HRR and TLS1.2 dispatch also use live
trust. Existing tcp_options whole integration tag hides two VM-only parser cases.
Generated certificate setup_all callbacks in signature_expansion, client_identity,
client_authentication and quic_config must be separated from their7 pure bodies
before those bodies can be selected as units. Preserve generated-cert negatives.

Other apps preserve fake-transport units: QUIC external_endpoint/phase1_io_tls,
HTTP3 Ops-based wp1/wp2/transport_quic and WebTransport FakeBackend/FakeOps do not
open native sockets. Conversely Core quic/tls_options and Runtime HTTP3 pool-key
watchdog/scope cases pass certificate paths into real SUT normalization: preload
fixture bytes for their pure logic or retain file-I/O integration coverage. Runtime
tunnel_stream validation also opens a peer. Mixed Fetch request_completion contains
a second pure BackendTest; response and body-reader policy cases need case-level
routing, not whole-file exclusion.

Tags do not prevent module loading: the16MiB test attribute remains CPU/memory load,
and eager static PEM inputs still read runner fixtures. Inspected support modules
have no eager external constructor; HTTP3 transport_smoke.exs explicitly runs at
top level and remains a separately selected script. Eight-app E2E inventory has14
test files plus that script; two WebTransport E2E-labelled files are fake/capability
checks, not successful wire acceptance. ExSSL's separate Caddy harness remains
CI/release-only; its13-scenario aioquic TLS boundary script uses stdin/stdout,
not actual UDP. Preserve independent interop and release checks separately.

Exact pilot selections (from the umbrella root after test-environment preparation):

```bash
unbuffer mix test apps/ex_ssl/test/ssl/lifecycle apps/ex_ssl/test/ssl/inert_lifecycle_birth_test.exs --seed 101
unbuffer mix test apps/ex_ssl/test/ssl/lifecycle apps/ex_ssl/test/ssl/inert_lifecycle_birth_test.exs --only integration --seed 101
HTTP_QUIC_PHASE1_REAL=1 unbuffer mix test apps/ex_ssl/test apps/elixir_quic/test apps/http_core/test apps/http_fetch/test/http/socket_client_http2_test.exs --include integration --seed 101
```

Retained local evidence:

```text
/tmp/http-fetch-round34-prep.log
/tmp/http-fetch-round34-native-default-before.log
/tmp/http-fetch-round34-native-default-after.log
/tmp/http-fetch-round34-unit.log
/tmp/http-fetch-round34-integration.log
/tmp/http-fetch-round34-provider.log
/tmp/http-fetch-round34-format.log
/tmp/http-fetch-round34-credo.log
/tmp/http-fetch-round34-dialyzer.log
/tmp/http-fetch-round34-tags.diff
/tmp/http-fetch-round34-originals/
```

Task42 stays IN_PROGRESS. Default mix test over the whole umbrella or even all of
ExSSL is NOT yet accepted as unit-only. Eight other helpers still have no default
exclusions; test.yml, mandatory integration routing, fixture/mocking refactors and
E2E alignment remain unchanged and required. Shared routing changes need full-nine
regression and prescribed manual CI, not a claim based on this pilot.

Whole-nine R22 3201/3206 plus test-WAE failures and FD21/23 gaps remain unaccepted.
No public lifecycle, native Socket TLS/failure settlement, default backend change,
physical-FD guarantee or publication follows. Final reviewed GitHub push and next
coordinated major release remain after the whole migration's gates. Goal stays
ACTIVE/ARMED and incomplete. Next: finish ExSSL fixture/trust eligibility while
retaining pure bodies, then other app tags/helpers and explicit CI routing.


## R35 — separate generated fixtures, host trust and native peers from units

Base184173862ba025da6930ad291ca61a2cdc7ffa02; task42 stays IN_PROGRESS and
Goal remains active/armed across automatic rounds34–35. Fifteen test files change;
production, support helpers, Mix, CI and the other eight apps remain frozen.

Five files retain79 cases: Options6U/19I, PKIX27U/1I, PreparedUpgrade2U/5I,
TCPOptions2U/14I and ClientIdentityOptions0U/3I. Case tags route real filesystem,
system trust and native transport work to integration. Removing TCPOptions' module
tag recovers its first two pure parser cases. No assertion, deadline or peer pin
changes. Runner static fixtures remain inputs; SUT file loading remains integration.

Seven pure test bodies move BYTE-UNCHANGED into four new second top-level UnitTest
modules in the SAME files, keeping async:false. Old generated-fixture modules keep
their callbacks, integration bodies and helpers. Four pure helpers copy verbatim;
only the now-unused original SignatureExpansion Capabilities alias moves away.

| File | Unit | Integration | Existing total |
| --- | --- | --- | --- |
| crypto/signature_expansion | 2 | 7 | 9 |
| client_identity | 1 | 9 | 10 |
| protocol/client_authentication | 1 | 7 | 8 |
| quic_config_contract | 3 | 4 | 7 |
| Total | 7 | 27 | 34 |

Those units exercise literal registry schemes, actual signed-content crypto,
identity rejection before file access, opaque DER decoding and real fresh QUIC
random/key shares with stable fingerprints. Copied QUIC helpers read checked-in
root bytes as runner inputs and pass explicit cacerts into the SUT. They inherit
no setup_all. Across these files old default25/excluded9 becomes7/excluded27;
reporting only +7 would hide newly excluded generated-fixture work.

Nine original modules gain whole integration tags: client_identity, diagnostics,
protocol/client_authentication, protocol/resumption_hrr, protocol/tls12_dispatch,
quic_config_contract, resumption_cache_lifecycle, resumption_context, local_tls_peer.
Existing signature_expansion and tls12_machine integration tags remain intact.

Review caught two omissions after initial greens. The initial five-file38U/41I and
whole-ExSSL518U/347I were not isolation proof. ClientIdentityOptions' last case
includes key:%{engine: :external}; Options resolves host trust before rejecting the
identity, so that entire unchanged case is integration. local_tls_peer has two real
TCP/proxy/closed-port cases; its omitted module tag is now added. Two read-only
reviewers checked all100 paths and transitive normalizers/fixtures, found no further
candidate gap, and accepted the corrected15-file source. This is reviewed source
classification, not a VM security sandbox or a claim of zero runner filesystem I/O.

Final actual root-scoped commands, seed101/max24: default ExSSL515 passed
(20 properties,495 tests),350 excluded in32.7s (27.1async/5.5sync); integration-only
350 passed/515 excluded in111.6s (27.2async/84.3sync). Chain exit0 and returned
prompt observed. All865 cases remain selected across the two tiers. Earlier generator
subsets passed7/27 and27/7, but their old terminal/job was lost overnight; retained
logs are not an independently recovered exit status. Fresh final whole-app runs
supersede that uncertainty. Initial five-file38/41 remains historical, corrected37/42.

Before the final two attribute corrections, the unchanged full inclusion command
passed1575/1575: ExSSL865 in109.3s, Quic249 in11.0s, Core418 in25.3s and Fetch H2
file43 in7.7s. It used real-QUIC flag1, integration inclusion, seed101 and no helper,
probe, alternate formatter or max-failure filter. Configured format0; Credo549 files,
9203 modules/functions, no issues18.3s; Dialyzer0 errors/0 skips, four unchanged
unnecessary ignores24.32s. Full chain exit0+prompt observed. Subsequent edits add
ONLY two routing attributes, then the complete corrected ExSSL partition and root
format check pass0. No production or analysis-input implementation changes follow.

Byte guards: all795 app/symlink files matched baseline before edits. Final780 other
files match HEAD exactly; eleven annotation-only files preserve original nonblank
content after stripping integration attributes. Seven moved test blocks each occur
once unchanged; four copied helpers each occur twice unchanged. Four original
integration modules preserve all remaining content apart from attributes/blank lines
and removal of the now-unused alias. An initial guard REPL syntax error was corrected
and actual checks rerun; premature print output is not evidence. Root read the full
810-line initial diff; both reviewers accepted the two final routing corrections.

Reproduce final partition from the umbrella root after MIX_ENV=test dependency and
warnings-as-errors preparation:

```bash
mix test apps/ex_ssl/test --seed 101
mix test apps/ex_ssl/test --only integration --seed 101
```

Evidence lives under /tmp/http-fetch-round35-*: final-unit.log,
final-integration.log, final-format.log, provider.log, credo.log, dialyzer.log;
extraction-spec.json and originals/ retain exact pre-edit blocks. Existing isolated
build32 and P0 pinned Python venv were reused. No dependency changes or new peer
pins. The old unknown job/PTY was not assumed to remain alive after runtime reset.

This accepts the bounded ExSSL source routing and executed partition. Whole umbrella
mix test, eight other helper defaults, test.yml, mandatory integration/E2E routing,
shared-change full-nine/manual CI and successful public wire flows remain required.
The P0 checkbox stays unchecked. R22 whole-nine3201/3206 plus test-WAE failures,
FD21/23 gaps, native Socket TLS/failure settlement and public lifecycle/completion/
managed H1/H2/default-backend/P6/P7 gates remain unaccepted. No physical-FD guarantee
or publication follows. Final GitHub push and next coordinated major release remain
after all migration gates. Goal stays ACTIVE/ARMED and incomplete.

## R36 — umbrella unit default and separate integration CI

Base 47a2a030b00082cee534431057f5b677b08c1602. Task42 stays IN_PROGRESS;
P0 acceptance remains unchecked and Goal active/armed. Two disjoint writer tasks
classify the other eight apps. Root owns shared tooling, formatting and all runtime
execution. Both workers froze their sources before Root formatting or source tests.
Production, transport support, assertions, wire payloads, peer pins, async settings,
case names and deadlines remain unchanged. No constructor or crypto primitive is
replaced by a fake cleanup fact. All source cases retain their original discovery.

All nine source test helpers exclude integration and E2E by default. Test CI now runs
units without Python/uv/independent-peer provisioning. New integration.yml uses the
same owner/H2 closure and manual all-nine selector, provisions the previous Fetch
peer dependencies and selects --only integration with HTTP_QUIC_PHASE1_REAL=1.
It has no continue-on-error escape. CLI allowlists and workflow regressions include
this fourth entry workflow. Release full-source and shared H2 consumer gates include
integration explicitly. E2E destination commands include e2e; both test.e2e overloads
supply it. Independent imported/pinned historical gates remain unchanged. Separate
consumer source-smoke helpers already use plain ExUnit.start and need no tag change.

The corrected eight-app file census is 113 unit, 33 mixed, 67 integration (213 files):

| App | Unit files | Mixed files | Integration files |
| --- | --- | --- | --- |
| elixir_quic | 30 | 4 | 4 |
| elixir_quic_http3 | 10 | 0 | 1 |
| http_core | 29 | 3 | 4 |
| http_runtime | 9 | 5 | 2 |
| http_fetch | 22 | 16 | 47 |
| http_event_source | 3 | 1 | 3 |
| http_web_socket | 5 | 4 | 6 |
| http_web_transport | 5 | 0 | 0 |

File classes are source-boundary inventory, distinct from executed case counts.
Fetch has 85 files/86 modules; the second RequestCompletionBackendTest remains unit.

The new metadata is 67 module attributes, 236 literal case attributes and two generated
reader conditionals. QUIC/Core/Runtime/HTTP3 change 27 files; four consumers change 81;
ExSSL changes only its helper. Root normalized all 109 app changes against HEAD:
case content is identical after reversing tags/helper options and ONLY the H3
callback wrappers, ignoring blank lines. All 686 other app files/symlink targets are
byte-exact; the original Connection production SHA is unchanged. Root reviewed the
provider (812 lines), consumer (2027 lines) and shared (319 lines) diffs using
normalized all-file guards; both reviewers accepted their source scopes, with an independent consumer/transitive audit.

Review recovered pure cases instead of excluding mixed modules wholesale. QUIC
DATAGRAM's first two profile/codec cases remain units. Fetch HTTP3's pure flat-options
case bypasses the original File/Quic.listen fixture through a named integration:true
callback; its fixture body stays verbatim, with a :ok unit fallback. Pooled completion
retains local-tracker and already-aborted request cases. Only write_to iterations
receive filesystem integration tags; read_all siblings remain units. WS proxy-frame
constructor and option-validation units remain; Fetch's profile/ALPN conflict case
moves to integration because Options loads host trust before reporting that conflict.
Pure WebTransport fake/capability cases remain units and provide no wire evidence.

Actual root prep: MIX_ENV=test, HTTP_FETCH_CI_APP unset, existing isolated build32
and P0 Python venv; deps.get --check-locked plus compile --warnings-as-errors both
pass0. Root format applies/checks pass0. Plain mix test --seed 101 then executes all
nine apps with max 24: 1676 passed and 1587 excluded; actual exit0+returned prompt.

| App | Unit passed | Integration excluded | Unit seconds |
| --- | --- | --- | --- |
| ex_ssl | 515 | 350 | 30.9 |
| elixir_quic | 215 | 34 | 13.6 |
| http_core | 339 | 79 | 3.3 |
| elixir_quic_http3 | 109 | 4 | 2.1 |
| http_runtime | 90 | 59 | 5.6 |
| http_fetch | 303 | 929 | 23.8 |
| http_web_socket | 51 | 87 | 9.4 |
| http_web_transport | 24 | 0 | 0.5 |
| http_event_source | 30 | 45 | 2.9 |
| Total | 1676 | 1587 | — |

Counts include20 ExSSL properties and20 Fetch doctests. Existing Elixir1.20 bitstring
pin/type warnings still appear while loading some test modules; this plain default
run is green, not a new test --warnings-as-errors acceptance. The separate library
compile uses warnings-as-errors. Source loading/static fixture inputs and runner
report output remain preparation, not a zero-filesystem or security-sandbox claim.

Explicit real integration command: HTTP_QUIC_PHASE1_REAL=1 mix test --only integration
--seed 101. Actual1584/1587 pass,1676 excluded, exit2+returned prompt. ExSSL350/350
105.7s; QUIC34/34 8.7s; Core79/79 27.2s; HTTP3 4/4 2.0s; Runtime59/59 6.5s;
Fetch927/929 212.6s; WS86/87 12.8s; WT0 cases/24 excluded0.6s; SSE45/45 2.9s.
Together the two runs account for all 3263 currently discovered source cases.
The integration tier stays red. The failed original bodies are unchanged:

- HTTPS early upload16: ex_ssl auto streamed infinity and ex_ssl http1 streamed 4000
  both reach the original peer drain, which remains open after its 2-second recv.
  Original source/writer/owner/Connection/Writer DOWN and Port.info/1 returning nil
  assertions precede that drain; they do not establish physical descriptor destruction or FIN.
- WS proxy_boundary264/339: ex_ssl WSS owner loss observes connection/writer DOWN,
  then misses original lost_owner_closed notification within 1000ms. Existing peer
  does ssl_drain before sending that notification. No observation budget changes.

These belong to the existing blocked-TLS teardown family. Exact failed variants
vary from historical R22; this run does not clear its FD/peer-cleanup findings.
No retry, fallback, GC, new trace/introspection or descriptor campaign was added.

Required static checks pass0: Credo549 files/9205 modules/functions, no issues19.0s;
Dialyzer0 errors/0 skipped/4 unchanged unnecessary ignores25.36s. CI Python16 tests
pass5.325s; release-automation34 tests pass44.202s; app closure4 cases pass0.08s.
The scoped test.e2e apps/http_web_transport/e2e --seed 101 check runs2 existing cases
with e2e INCLUDED (0.2s/exit0). This verifies the changed alias routing only; these
capability/fake cases are not independent WebTransport wire evidence. Actual full
public E2E, all-nine GitHub manual workflows and release/candidate consumer gates
remain pending. The combined static/automation/routing chain returns0+prompt.

Evidence /tmp/http-fetch-round36-*: prep.log, unit.log, integration.log, format.log,
credo.log, dialyzer.log, ci-python.log, release-python.log, closures.log,
e2e-routing.log; quic-core-runtime.diff and fetch-clients.diff retain source review.
Final reviewed source routing and local unit partition are accepted at this scope.
P0 remains open: the integration tier is RED and actual manual remote CI is pending.
The native Socket TLS/failure-settlement path, known-socket lifetime, collector error
retention, public lifecycle/completion/duplex/managed H1/H2/default flip, independent
interop/performance/soak and publication/cold-published-consumer gates remain open.
No push or next major release yet; Goal ACTIVE/ARMED and incomplete.

## Round37 — raw Socket allocation and known connect-failure attribution

Scope is private IPv4 dial construction through the existing Allocator actor.
NativeSocket reserves TCP before open, enrolls the exact object before connect,
and preserves one absolute NativeE. Allocator.start_socket is explicit; the old
Port start entry remains the production Setup path. Raw handoff rejects before
Port operations. Owned close checks the public current owner; its return is not
cleanup proof. Open/enrollment unknowns and sticky losses remain unresolved.

The separate known-socket failure operation accepts only refused/unreachable
errors, authenticates the original live unfinished Allocator PID/monitor and
canonical typed Socket/ledger creator generation, checks current public owner,
fresh Root/controller/provider liveness and original expiry, and rejects prepared
or committed transfer. NativeE cannot exceed its captured enrollment deadline.
RPC R=min(NativeE,entry+250ms); completion only shortens. Acceptance closes
admission/records failed-connect BEFORE close, without reminting a permit,
monitor, lease or receipt. Original resource DOWNs and Reader settle cleanup.

Receiver audit found an internal five-element frame could bypass the generic
outer deadline. The focused regression actually failed: exit2, 0/1, returned
:ok instead of invalid_connect_failure. A dedicated canonical four-element
receiver now requires integer NativeE and canonical outer RPC deadlines and rejects injected
internal frames before generic dispatch. The R29 pending/no-TCP path is unchanged.
Final independent source review accepts only this cooperative phase protocol,
not native preemption, complete constructor identity or public TLS support.

First constructor/auth run passed16/17 (exit2): the new bound/non-listening
fixture did not yield Allocator DOWN within1000ms. Direct public references
on that endpoint returned timeout for BOTH raw Socket (1000802us) and classic
inet (1002135us), each with1000ms. This established a fixture timing error,
not a Socket-only failure. Replaced only the new fixture with the existing
closed-local-listener pattern; keep NativeE5000ms, DOWN1000ms, Reader2000ms
and all assertions. No retries, fallback, timeout extension or old-test edits.

Corrected focused17/17 passes0.5s/exit0: four actual Allocator cases exercise
real peer probe/closure, recipient/owner loss, gated handoff and refused connect
with failed/connect sealed receipt and actual roles17/observed_down17. The other
thirteen cases cover authentication/deadline negatives and three pure argument
units. All fourteen native cases are integration-tagged; unit fixtures do no I/O.
Plain all-nine mix test --seed 101:1679 pass,1601 excluded, exit0+prompt.
ExSSL518, QUIC215, Core339, H3companion109, Runtime90, Fetch303, WS51, WT24, SSE30.

The original four-scope source command, real QUIC enabled, include integration,
seed101/max24, passes1592/1592 exit0+prompt: ExSSL882/102.1s (20 properties),
QUIC249/13.2s, Core418/27.8s, Fetch H2 file43/7.2s. Existing test-module
bitstring warnings persist; this does not accept test --warnings-as-errors.
Configured Credo552files/9257mods-funs has no issues15.3s. Initial Dialyzer had
one new generated unreachable-false warning: redundant is_pid on typed Receipt
observer. Removing only that test retains the local-node guard. Final compile-WAE,
format, focused17/17 (1.6s) and Dialyzer pass0:0errors/0skips/4 old unnecessary
ignores,29.02s. This one-line type simplification followed the broad source run.

Root byte guards confirm793 of795 previously tracked app paths unchanged.
Reversing declared Observer additions and its private captured-deadline field
reconstructs the complete R36 file exactly; Root reviewed the full Allocator diff.
Connection retains SHA256 61b2fa41a60fb00d01335ea8486e698aecac8fc0a45a47e10d5adecb34cc3f91.
All original tests, assertions, payloads, pins, deadlines, Setup/Writer/Connection
and public backend selection remain unchanged. Three new files contain the raw
constructor and two tier-separated regression suites; no new provider actor exists.

This accepts the private Allocator/known-refusal slice only. Full Socket Setup,
raw TLS I/O and handoff/connected publication, all-error constructor proof,
STARTTLS adoption, public lifecycle/completion/duplex/managed H1/H2 and removal
of production OTP SSL remain open. No physical-FD/drain or full P2 claim follows.
The last all-nine integration run remains R36 RED (two HTTPS early-upload cases
and one WSS peer-close case); those unchanged cases were not rerun this round.
All-nine remote CI, independent peers/performance/soak, candidate/publication
and cold-published-consumer gates remain pending. No push/major release yet.

A subsequent default Credo returned0 while omitting36 parser-timeout files;
that partial pass is NOT accepted. With ERL_FLAGS='+S 4:4', unchanged rules
and timeouts parse all552 files/9257mods-funs: no issues57.6s, exit0+prompt.
Working-tree and staged diff checks also pass. No test budget changed.

Evidence: /tmp/http-fetch-round37-{compile,receiver-red,native-focus,
refusal-reference,native-focus-final,unit,source,compile-final,format-check,
credo,dialyzer,native-final,dialyzer-final,credo-final,credo-complete,diff-check}.log and allocator.diff. Actual exit
markers and returned prompts were checked; silent/inferred-idle job status alone
was not completion evidence. Goal remains ACTIVE/ARMED and incomplete.

## R38 continuation — current-source verification (2026-10-23)

The inherited uncommitted Socket Setup/handoff implementation is under review,
not accepted. The other writing session was explicitly confirmed stopped before
continuing. Preserve its source changes and the supplied plan copy. No provider
default, manifest dependency, public lifecycle API or release version has changed.

Current-source compile with warnings-as-errors and format checks return exit0.
Focused native Setup/Allocator/Observer integration passes13/13 (exit0), and the
complete lifecycle directory passes169/169 (exit0). Core TLS and Fetch H2 consumers
pass43/43 (exit0) after revalidating the classic-path private probes against
Connection SHA256 7ececbbfbbad9040811c12b3975ffa77a7948a3283e966625e775bd18fd8d19f.
Configured Credo parses553 files/9300mods-funs with no issues (exit0).

The historical HTTPS early-upload/WSS peer-close failures do not reproduce in
the two-file focused run:44+10 pass (exit0). This does not resolve their earlier
intermittent failures and is not a full integration acceptance result.

The current default all-nine unit run returns exit2:1677/1679 pass. Two existing
ResponseStreamIdlePolicyTest cases fail (compressed-header chunk reaches an
already-dead stream; finite wait notification misses350ms). The concurrent full
integration run also fails the new NativeSocketSetupTest first native-owned
notification after1000ms. Suite-level process contention is a hypothesis, not a
confirmed cause. Keep assertions/deadlines unchanged; serial reproduction and
diagnosis remain required. No test retry replaces these failures in the record.

Logs: /tmp/http-fetch-r38-{compile,focus,lifecycle,consumers,units,format,credo}.log
and /tmp/http-fetch-cleanup-repro.log. Dialyzer subsequently passes (exit0,
0errors/0skips/4 unchanged unnecessary ignores). Serial idle-policy replay passes
8/8,2 integration cases excluded (exit0; /tmp/http-fetch-r38-idle-serial.log);
the full default unit gate remains red until independently revalidated.

The first full integration invocation omitted the Python peer environment:
direct `python3 -c 'import h2'` reproduces ModuleNotFoundError. H2 trailer/admission
peers consequently exit before readiness; their traceback is not JSON, producing
fixture JSON.DecodeError as well. This is BLOCKED_ENV for those cases, separate
from the native Setup failure. The known-invalid run was explicitly terminated
with SIGTERM (notice in its log), not reported as a completed/pass result even
though the unbuffer wrapper returns0. Its three real-QUIC opt-ins were also skipped.

Prepared /tmp/http-fetch-migration-peers-venv using the unchanged pinned
scripts/requirements-http2-stream-clients.txt, matching integration.yml. Installation
passes (exit0). A new serial full integration run uses that environment plus
HTTP_QUIC_PHASE1_REAL=1; result pending in
/tmp/http-fetch-r38-integration-prepared.log. P2 acceptance, P3–P7, remote CI and
publication remain incomplete; no commit/push or major release in this continuation.

Prepared serial integration completes with exit0:1605/1605 pass, zero skips.
Per app: ExSSL368, QUIC34, Core79, H3companion4, Runtime59, Fetch929, WS87,
WT0 (all24 cases are unit/capability cases), SSE45. Core includes the three
explicit real-QUIC cases. This passes the current source integration gate,
including the new native Setup and the previously failing HTTPS/WSS cases,
without source/timeout/assertion changes. It does not explain the earlier
timing failures or establish candidate, platform, public lifecycle or E2E gates.
Final all-nine unit replay is now running serially, with output in
/tmp/http-fetch-r38-units-serial.log; initial failed results remain above.

README now explains the three tiers and pinned local Python preparation,
and fixes the scoped E2E command to include the required `--include e2e` flag.

Final serial default unit run completes with exit0:1679/1679 pass,1605 integration
cases excluded. ExSSL518, QUIC215, Core339, H3companion109, Runtime90, Fetch303,
WS51, WT24, SSE30. This revalidates the local default unit gate; it does not erase
the initial two timing failures or establish their root cause. No timeouts,
assertions, test concurrency settings or implementation were changed to get green.

R38 private inert Setup/handoff is accepted at this current-source boundary.
It uses the original typed identities/permits/deadlines and confirms actual peer
closure plus process/socket DOWN in its new integration cases. Raw TLS attachment,
connected publication and public I/O remain explicitly refused. P2 overall remains
open, including complete native transport lifetime, all-error identity, public
lifecycle/transfer and duplex-control correctness. No candidate/publication,
performance/soak, supported-runtime matrix, remote CI or production-without-OTP-SSL
acceptance follows. Changes remain uncommitted; no push or release was performed.

## R39 — native Socket TLS lifetime (private slice accepted)

ROUTE task=R39 agent=sol_worker reason=implement native Socket TLS lifetime under accepted P2 design

Baseline: d770327 plus the accepted uncommitted R38 slice. R39 owns native
TLS I/O, private Setup orchestration and truthful Socket closure, retaining the
original actors, typed identities, deadlines and existing Port behavior. Public
lifecycle/default promotion remain separate acceptance gates. An independent
read-only Sol audit checks coverage while implementation proceeds; root owns
consumer private-probe revalidation and serial umbrella gates. No new Agent Note
scope is inferred from the missing .agents/current.md declaration.

Task record: initial_worker=sol_worker; current_worker=sol_worker;
sol_escalated=false; astra_escalated=false; sol_repair_rounds=0;
astra_repair_rounds=0. Initial missing-behavior red tests are TDD evidence,
not a repair round. No R39 acceptance result yet.

R39 initial TDD red is reproduced by the new integration case
apps/ex_ssl/test/ssl/lifecycle/native_socket_tls_test.exs: expected private
Setup.attach=:ok, actual socket_transport_not_implemented (0/1). No repair
round consumed. Independent read-only audit confirms remaining Port assumptions
in Setup/Observer/Connection, failure attribution and writer deadlines; it also
identifies the retained-plaintext peer-close path as requiring distinct handling.

R39 expanded initial matrix runs20 cases:18 pass, two fixture failures remain.
OTP reference listen rejects integer-only cipher input; empty cacerts fails local
normalization before the intended wrong-root handshake, leaving the reference
acceptor unused. These are implementation/test acceptance failures, not an agreed
TDD red or evidence of a protocol defect. Worker is correcting only those fixture
inputs. Cumulative sol_repair_rounds=1; astra_repair_rounds=0. No R39 acceptance yet.

R39 repair1 validation stops at test compilation with SystemLimitError: a generated
test function name interpolates the full wrong-root DER and exceeds the255-byte
atom limit. No test body executes in that invocation. Repair2 uses fixed short
wrong_ca/wrong_name labels with the same DER inputs/assertions, then validates the
bounded native matrix. This is the final Sol repair round for R39; another
implementation acceptance failure requires a stopped-writer handoff and escalation.
Current sol_repair_rounds=2; astra_repair_rounds=0. No green repair2 result yet.

R39 repair2 completes26/27, exit2. Command: MIX_ENV=test unbuffer mix test
apps/ex_ssl/test/ssl/lifecycle/native_socket_tls_test.exs
apps/ex_ssl/test/ssl/lifecycle/native_socket_setup_test.exs
apps/ex_ssl/test/ssl/lifecycle/socket_observer_test.exs --include integration --seed101.
Original output is exec session50962/chunk5d260a; no filesystem log was captured.
Remaining failure: OTP TLS1.2 native protected-record test receives no
lifecycle_tls_ready within5000ms; reference server logs CLIENT ALERT Fatal Handshake
Failure in certify. Root cause unresolved; independent OpenSSL TLS1.2/1.3 and
the other26 scenarios pass. Original typed resource termination was observed in
the failing case; that cleanup is not handshake success. Broader gates remain unrun.
Predecessor confirms all commands finished and all writes stopped; changes retained.

ROUTE task=R39 agent=astra_worker reason=SOL_REPEATED_FAILURE bounded recovery of remaining OTP TLS1.2 native handshake acceptance

astra_gate=SOL_REPEATED_FAILURE: two completed unsuccessful Sol repair/validation
rounds remain evidenced above (compile atom limit, then real OTP TLS1.2 failure).
Task record: initial_worker=sol_worker; current_worker=astra_worker;
sol_escalated=false; astra_escalated=true; sol_repair_rounds=2;
astra_repair_rounds=0. Recovery must establish exact root cause and preserve the
original native resource/deadline and independent interoperability checks. A
proven pre-existing P1 signature gap remains visible; it cannot be called native
success or silently masked by weakening the test.

Astra read-only diagnosis reproduces the unchanged26/27 matrix in
/tmp/http-fetch-r39-astra-before.log (exit2). Exact same OTP29 peer/cipher also
fails ordinary Port TLS in /tmp/http-fetch-r39-port-probe.log. An independent
HandshakeMachine probe of its real ServerHello reports
{:fatal_alert, :handshake_failure, :extended_master_secret_required}; extension
IDs are11 and65281, with23 (EMS) absent. Probe evidence is retained in
/tmp/http-fetch-r39-hello-probe.log. Thus the new fixture's expected positive
result contradicts the accepted mandatory-EMS profile; this is an evidenced
existing policy boundary, not a native transport regression or PKCS1 failure.
An initial consumed-Task diagnostic failed separately; successful probe commands
exit0 and do not constitute a source gate.

Coordinator preserves mandatory EMS and authorizes bounded Astra repair1:
correct the OTP29/no-EMS case to explicit rejection with precise missing-EMS
evidence and original durable resource cleanup; retain independent OpenSSL TLS1.2
multi-record protected-traffic success and TLS1.3 success unchanged. No no-EMS
support, protocol weakening, deadline increase or P1 signature scope expansion.
Current sol_repair_rounds=2; astra_repair_rounds=1. Repair result remains pending.

Astra repair1 focused validation passes29/29, exit0 in
/tmp/http-fetch-r39-astra-repair1-focus.log. This includes the unchanged existing
TLS12MachineTest cases that independently observe missing ServerHello extension23
and exact extended_master_secret_required. Only the newly authored R39 OTP29
expectation changes; runtime/protocol source does not change in recovery.
OpenSSL TLS1.2 multi-record positive remains intact. Full ExSSL source and strict
compile/scoped-format validation are in progress; overall R39 acceptance remains open.

R39 bounded recovery handoff completes with all commands finished and writes stopped.
Full ExSSL source suite passes904/904 (20 properties,884 tests), exit0 in105.0s,
including integration/classic/backpressure cases; log:
/tmp/http-fetch-r39-astra-exssl.log. MIX_ENV=test compile --warnings-as-errors and
eight-owned-file format checks pass, with empty compile/format logs. Scoped diff
check passes. Cumulative counters remain sol_repair_rounds=2 and
astra_repair_rounds=1. No runtime source changes occurred during Astra recovery.

Coordinator reviews native read/select identity fencing, absolute output deadlines,
failure publication and original-resource retained-plaintext cleanup against R38.
The classic Port call bodies, driver preparation and buffered-close fields remain
compatible with the two HTTP private probes. Their source pins are updated only
after that review to Connection SHA256
8cba6246d1d03426d6be2ce817999ecdf9eba82b928ad914b521259919c5db60.
Their actual43-case consumer replay passes, exit0 in6.3s, using root-scoped
tls_transport_test.exs and socket_client_http2_test.exs with --include integration
--seed101; log: /tmp/http-fetch-r39-consumers.log. Existing Elixir1.20 bitstring
pin warnings occur in those test files; library strict compilation passes separately.
The private R39 slice is accepted within these evidence boundaries.
Native blocked-writer/KeyUpdate,
public lifecycle, unsupported native options and integrated umbrella/package/CI
gates remain separate open requirements; full ExSSL success does not close P2.

ROUTE task=R40 agent=sol_worker reason=make candidate TLS checks and QUIC/H3 selection automatic for relevant changes

R40 is independent P4 harness preparation allowed alongside P2: selector/workflow
changes only, using existing candidates and actual dependency graph. Preserve
manual all-nine/full/historical gates and cheap unrelated documentation changes.
Task record: initial_worker=sol_worker; current_worker=sol_worker;
sol_escalated=false; astra_escalated=false; sol_repair_rounds=0;
astra_repair_rounds=0. No remote CI execution or P4 acceptance result yet.

R40 local implementation is accepted after coordinator diff review. The selector
now exposes candidate_tls for non-documentation app code/tests/manifests and
relevant root/harness inputs. Actual dependency closures select affected QUIC/H3
companions as well as H2 clients. Reusable workflow outputs and CI trigger paths
match; the existing candidate job is required automatically, and a missing TLS
feature artifact fails. Full shared checks and historical compatibility remain
manual-only. Unrelated documentation avoids candidate acceptance.

Executed: python3 -m unittest discover -s scripts/ci -p 'test_*.py' -v,
20/20 pass in14.238s; scoped git diff --check passes. Initial expected red exposed
the missing output/API, QUIC fanout and workflow gate. Fixtures exercise actual
Git push/PR ranges, renames/deletes/new branches, malformed input, source/tests/
manifests/harnesses, docs exclusions, manual outputs and synthetic graph changes.
No Mix gate or remote workflow ran for R40. This accepts P4 harness preparation,
not integrated candidate TLS or P4 completion. Sol/Astra repair counters remain0.

## R41 — mixed-package TLS harness (actual traffic pending)

ROUTE task=R41 agent=sol_worker reason=extend existing isolated package traffic with verified ExSSL TLS

Baseline: d770327 plus accepted R38/R40 and in-progress R39. Worker owns the
existing package-traffic Python/Elixir harness and narrowly scoped automation
tests. Retain four h2c consumers and add the same four over verified ExSSL+h2,
including WSS mapping, independent peer ALPN/protocol evidence, exact archives,
standalone dependency isolation, shared mixed connection and client stop/restart.
Runtime/package execution waits for stable integrated source; mock record checks
alone cannot establish encrypted package interoperability.

Task record: initial_worker=sol_worker; current_worker=sol_worker;
sol_escalated=false; astra_escalated=false; sol_repair_rounds=0;
astra_repair_rounds=0. No real R41 package traffic executed yet.

R41 implementation/bounded validation is accepted after coordinator review of all
five files: package traffic Python/Elixir drivers, package-consumer automation test,
H2 CI evidence validator and its test. One exact archive set serves both four-client
modes. Verified ExSSL uses fixture CA, verify_peer and localhost SNI/hostname checks;
HTTPS WebSocket routes use WSS. Peer h2/ALPN, exact per-connection traffic counts,
clean WebSocket completion, four traffic/startup receipts and isolated provider
Hex/code-path provenance are required. Aggregate success needs both distinct modes
and8 consumers/connections; old h2c-only evidence is rejected by CI.

Executed: five new pure/mocked package-harness checks and two CI-evidence checks
pass; four changed Python files compile; scoped Elixir formatting and git diff
--check pass. Agreed initial red exposed missing dual-mode APIs/aggregate support.
No real sockets, package build or traffic gate ran. Sol/Astra repair counters0.
Integrated acceptance remains pending, using fresh validated archives:

```bash
HTTP_FETCH_ARCHIVE_DIR="$ARCHIVE_DIR" HTTP_FETCH_RELEASE_VERSION="$VERSION" \
  python3 scripts/http_runtime_package_traffic_gate.py
```

## R42 — version-specific TLS1.2 PKCS1 compatibility

ROUTE task=R42 agent=sol_worker reason=prepare required TLS1.2 RSA-PKCS1 compatibility implementation

Diagnosis owns no files and runs no runtime gates while R39 recovery validates.
The settled P1 target is SHA256/384/512 only for TLS1.2 handshake signatures,
including client authentication, with independent forced-scheme evidence and
strict TLS1.3/QUIC exclusion. No static RSA/CBC or explicit-profile reordering.
Deliverable is the smallest concrete resolver/identity/profile interface and
unit/integration plan; implementation waits for stable R39 source.
Task record: initial_worker=sol_worker; current_worker=sol_worker;
sol_escalated=false; astra_escalated=false; sol_repair_rounds=0;
astra_repair_rounds=0.

Read-only mapping completes: preserve strict global TLS1.3 registries or explicitly
filter both QUIC config/capabilities; raw TLS1.2 signatures need their own resolver.
ClientIdentity currently derives/proves only TLS1.3 schemes, so TLS1.2 mTLS needs
separate eligibility plus explicit protocol-context selection. Options, identifier
encoding and ordered profile validation must follow offered versions. Existing
OpenSSL wrappers lack forced-signature controls; independent server/mTLS tests
must verify actual scheme IDs and certificate-signature compatibility per hash.

R42 implementation is assigned with unchanged0 repair counters. PhaseA prepares
fixed-key independent vectors and forced-scheme peer assets only under
/tmp/http-fetch-r42-prep, without repository edits or Mix execution. PhaseB source
and test changes wait for the R39 stable-source gate. Planned ownership excludes
Connection/Writer/lifecycle and root documentation, preserving R39 recovery.

R42 PhaseA independent OpenSSL3.6.5 evidence is ready: fixed-key SHA256/384/512
PKCS1 vectors verify independently; forced TLS1.2 ECDHE-RSA-AES128-GCM peers record
server SKE and client CertificateVerify IDs0401/0501/0601 with6738 response bytes
for each mTLS handshake. Assets and receipts remain under /tmp/http-fetch-r42-prep;
these are peer/vector preparation, not engine acceptance. All peer processes reaped.
After the904-case ExSSL and43-case consumer gates, coordinator authorizes PhaseB
implementation and exclusive Mix validation. Repair counters remain0.

R42 agreed initial red: fixed-vector tests1/3 pass, two fail with
{:unsupported_signature_scheme,1025}. Initial version-specific implementation
passes strict compile and179/180 focused units (26 integration excluded).
One new pure mTLS case requests only SHA384/512 while its static certificate is
SHA256-signed, so existing certificate policy correctly suppresses selection.
Initial six integrations also fail before handshake on lazy-module
String.to_existing_atom inputs. These are retained initial acceptance failures.

Grouped Sol repair1 corrects the test request to permit its SHA256 certificate
signature while retaining target-scheme-first selection and exact CV assertion,
uses fixed scheme atoms, and extracts generated-case bodies into a runtime helper
to remove literal-branch warnings. Production implementation remains unchanged.
All18 new checks, including six real OpenSSL forced server/mTLS handshakes, then
pass exit0 in4.1s. Current sol_repair_rounds=1; astra_repair_rounds=0. Full ExSSL,
affected QUIC and final compile/format gates remain in progress.

R42 final source gate passes922/922 ExSSL (20 properties,902 tests), exit0 in123.5s;
shared QUIC profile/TLS-driver/phase1 checks14/14 pass, exit0 in0.7s. Final strict
compile, twelve-owned-file formatting and scoped diff checks pass. Logs:
/tmp/http-fetch-r42-{exssl,quic,compile,format}.log. Coordinator reviews all eight
production diffs plus versioned policy/identity/negative and independent-vector
tests. Global TLS1.3/QUIC registry remains strict; public ordered policy is preserved.
R42 slice is accepted, with no candidate/remote or whole-umbrella claim.
Worker confirms all commands/peers finished and writes stopped. Runtime ownership
transfers to R43; cumulative Sol1 successful repair, Astra0.

## R43 — bounded busy-writer control output accepted source slice

ROUTE task=R43 agent=sol_worker reason=implement required busy-writer control output
ROUTE task=R43 agent=astra_worker reason=SOL_REPEATED_FAILURE after two failed repair-and-validation rounds
Task record: initial_worker=sol_worker; current_worker=astra_worker;
sol_escalated=false; astra_escalated=true; sol_repair_rounds=2;
astra_repair_rounds=1; astra_gate=SOL_REPEATED_FAILURE. Recovery passed; all
writers, commands and owned peers stopped before coordinator consumer validation.

Connection retains one immutable application output and at most one protected
mandatory control. It preserves epochs, exact ciphertext, ACK tokens and original
absolute deadlines; queue residence consumes the budget, including the250ms
reciprocal-close cap. Pending control blocks further parsing/encryption. Abandonment
discards unsent application bytes while preserving these two bounded outputs;
close/cancel/owner loss retain abort intent. Terminal recv waits for pending peer
shutdown output to retire. No new actor, Writer queue, re-encryption or replay.

The agreed red failed5/6 before implementation. Expanded source validation exposed
an actual premature Port terminal-read regression and invalid new fixture oracles;
the Port assertion and Writer sensitive protection remain intact. Recovery reproduced
a stale pre-admission token comparison: legitimate ACK advancement was mistaken for
mutation. The final test instead proves genuine native send blocking overlaps control
admission, exact saved dispatch, full16MiB delivery and authenticated new-key traffic.
The earlier no-pending timeout's exact mechanism remains unproven; no separate
runtime-readiness fix is inferred from that symptom.

Accepted evidence: focused53/53, nearby75/75, strict compile, scoped format and diff
checks. Coordinator reviewed Connection and both private HTTP probes, updated their
source pin to33e0dbd7f002bcb52504e8dc7cbc9ca988b7ed9ef44345dd513467105ede1aef,
and replayed43/43 consumer checks plus scoped formatting. Logs and exact commands:
/tmp/http-fetch-r43-astra-handoff.txt and /tmp/http-fetch-r43-consumers{,-format}.log.
Full-stage ExSSL/umbrella/Credo/Dialyzer, public P2 lifecycle and package/remote
acceptance remain pending; no P2 completion or default promotion is claimed.

## R44 — ordinary TCP verification callback diagnosis

ROUTE task=R44 agent=sol_worker reason=diagnose required verify_fun compatibility preservation

Read-only source mapping while R43 owns implementation/runtime. Locate ordinary
HTTP usage and pure PKIX/protocol plumbing, supported OTP callback events/state,
hostname/extension behavior, error/exception handling and cancellation/setup
evidence. Return minimal fixed interfaces and actual reference/red checks; do not
implement wholesale PKIX or other advanced-policy extensions. Managed callbacks
remain excluded and QUIC remains strict. No repository writes or runtime commands.
Task record: initial_worker=sol_worker; current_worker=sol_worker;
sol_escalated=false; astra_escalated=false; sol_repair_rounds=0;
astra_repair_rounds=0. No agreed TDD red yet.

R44 mapping completes without writes/runtime execution. Besides Options/PKIX,
callback plumbing crosses HandshakeMachine whitelist, HandshakeCore parser/config
split, TLS12 forwarding and one Connection verifier-option line. That final line
waits for R43 stopped-writer handoff. Existing trust-anchor-only candidate selection
cannot deliver unknown_ca; hostname mismatch must replace valid_peer for the user
callback. Installed OTP29 sources inform the reference plan but are not observed
event transcripts. Callback failure/exception boundaries must use fixed redacted
categories and never retain user state in peer evidence, tickets or receipts.

ResumptionContext currently lacks callback partitioning/reverification. Root chooses
full certificate handshake/cache bypass when verify_fun is present, retaining the
accepted auto option without serializing arbitrary function/state into cache keys.
This preserves current callback policy rather than silently resuming around it.
PhaseA prepares bounded OTP reference probes and drafts only under
/tmp/http-fetch-r44-prep, with no repository edits or runtime commands while R43
validates. Real callback transcripts precede any emulation in PhaseB. Full HTTP
completion/setup adaptation remains a P3 gate until public lifecycle exists.
Counters remain Sol0/Astra0.

PhaseA preparation is complete in /tmp/http-fetch-r44-prep/MANIFEST.md; drafts and
OTP reference probes remain uncompiled/unexecuted. Source implementation waits
behind integrated P2. The user requires complete CRL/OCSP, partial_chain, encrypted
keys and multiple identities before OTP removal; these are separate required P1
capabilities, not approved next-major removals.

## R45 — public lifecycle integration; full P2 acceptance remains open

Public `SSL.Lifecycle` now connects the existing observer, authority and receipt to
ordinary TLS1.3/TLS1.2 dialing, owned STARTTLS and per-attempt prepared upgrades.
Status separates setup, logical closure and cleanup. Transfer replaces controller
and application-owner monitors, revokes stale authority and reconciles late ACKs.
The current Connection source hash is
`988058dc49bd5d7c3bca70e8293b40ef1c05959b65d7d3b9f3acfa53827dbe63`;
HTTP consumer source-pin review/replay and full stage gates remain pending.

ROUTE task=R45 agent=astra_worker reason=SOL_REPEATED_FAILURE
Initial worker Sol; two unsuccessful repair rounds ended at374/376. Bounded Astra
repair1 corrects two test fixtures: valid reserved DNS name for exact nxdomain,
and sustained actual native-send quiescence before requesting KeyUpdate. Diagnosis
observed authenticated KeyUpdate processing during legitimate partial-write progress;
it did not establish a production protocol defect. No runtime source changed in
this recovery. Protected ciphertext, epochs, original deadlines, full16MiB/new-key
peer checks and resource-cleanup assertions remain intact.

Executed: target seed601887 passes3/3; original integrated lifecycle/duplex/nearby/
TCP/prepared/QUIC selection passes376/376 at seed101. The native case passes six
consecutive executions; strict compilation, scoped formatting and diff checks pass.
Evidence: `/tmp/http-fetch-r45-astra-repair1-{two,focus}.log` and the stopped handoff.
Cumulative R45 counters: Sol2/Astra1. The same native test consumes R43's final
Astra repair2; R43 counters remain Sol2/Astra2, with no further repair budget.

Two P2 acceptance failures are now reproduced. An isolated file-only resolver
returns an assigned local interface address followed by loopback; the first
refuses and the second has a TLS listener. Ordinary ExSSL and OTP authenticate
and exchange bytes within the same3000ms budget, while lifecycle dialing returns
the first `:econnrefused`. Its cleanup is confirmed, but address fallback is absent.
The unchanged native allocator suite also fails3/4 at seed101: the original Socket
DOWN is missing within1000ms. A trace of that same test shows the exact allocator
enter `:prim_socket.finalize_close/1` before Observer kills it, with no return from
finalization. Controls with complete explicit close or owner exit pass; this is
not evidence that every explicit close suppresses socket monitors.

The stopped diagnosis and commands are in
`/tmp/http-fetch-p2-followup-diagnosis/HANDOFF.md`. Coordinator accepts bounded
pre-TLS TCP-candidate rollover only after each original Socket DOWN, with the
original deadline and cancellation fence retained. The next recovery also removes
redundant allocator termination close and addresses deliberate candidate-close
overlap. R39 and R45 each enter their final Astra repair2; R43 remains exhausted.
Neither reproduced failure is waived by the earlier green batch.
Full ExSSL/umbrella, Credo, Dialyzer, consumer/package/platform and P3 gates are
not established by this focused result. OTP remains the production default.

The combined recovery changes allocator exit, sequential address dialing,
Observer close coordination and bounded ledger rollover. Its initial27/29 result
exposed a finite-deadline representation error and a pending-proof terminal path
that could miss the deferred allocator kill. The accepted follow-up changes only
Observer: retain the original minimum deadline using the helper's tagged argument,
and perform process termination at every pending-proof grace-expiry exit. Missing
exact resource DOWN still leaves cleanup unconfirmed; deadlines are unchanged.

The original29 checks pass, and allocator checks pass11 executions of6 cases.
The current lifecycle/duplex/TCP/prepared/QUIC selection passes384/384, including
independent TLS12 controls. An initial379/384 run failed before five peer startups:
Xcode Python's LibreSSL lacks OP_NO_RENEGOTIATION. A child-command PATH selecting
installed Python3.14/OpenSSL3.6.5 resolves that prerequisite without source, helper
or global configuration changes; the failed log remains preserved. Strict compile,
scoped format, configured Credo and whitespace checks pass. All1075 baseline files
are preserved except the owned Observer change; protected tests and canonical0400
remain unchanged, and all owned runtime processes exit.

Recovery evidence is in `/tmp/http-fetch-p2-astra-round3-validation/HANDOFF.md`;
the earlier failed diff remains in `/tmp/http-fetch-p2-final-recovery/HANDOFF.md`.
The public failure/cancellation slice now passes seven integration checks: killed
Connection with a genuinely native-blocked Writer, connect after confirmed
pre-cancel, wrong CA/identity, invalid options, setup cancellation and established
cancellation. Original resource identities, typed termination evidence, durable
public receipts and warmed resource baselines are retained. The combined
provider/lifecycle/duplex/QUIC selection passes391/391; default selection excludes
all seven new integration cases. Scoped formatting, strict compilation, configured
and strict Credo, whitespace and source-preservation checks pass.

The new test observes original Setup/Allocator retirement without assuming that
connect success already implies their absence. The inert expiry module runs
serially and proves suspension acknowledgement before its unchanged400ms deadline.
The earlier KeyUpdate observation timeout was not reproduced by one instrumented
check or the unchanged native test in the combined run; its cause remains unknown.
No production code, protected native TLS assertion or deadline changed in this
slice. Formatter-only changes have identical normalized syntax trees.

Evidence is retained in `/tmp/http-fetch-p2-fixture-recovery-astra/HANDOFF.md` and
`/tmp/http-fetch-p2-format-validation/HANDOFF.md`; the original failed391 run remains
in `/tmp/http-fetch-p2-coverage-astra-next2/HANDOFF.md`. Full P2 still requires
integrated ExSSL source acceptance, including the open R44/R51 checks. P3,
default promotion and publication remain open.

## R46 — encrypted single-client keys; required provider gates remain open

Options and ClientIdentity now accept transient byte-iodata passwords or fun/0
callbacks for encrypted PEM. Bounded preflight checks precede public
`:public_key` decryption. Normalized/prepared credentials retain decoded keys,
with no password, callback, source path or raw PEM. Existing leaf/key proof,
version-specific schemes, auto-ticket identity rejection and managed/QUIC
exclusions remain. The accepted callback and finite-work policy is recorded in
`tls-migration-design.md` and the ExSSL compatibility guide.

Actual focused checks pass:49 ExSSL and17 Fetch tests, plus26 existing ExSSL and11
managed regressions. Required-mTLS Fetch verifies exact leaf, ALPN, TLS version
and HTTP200/body for RSA/EC x TLS12/TLS13 x H1/H2 x direct/CONNECT. Public SSL
prepared snapshots survive certificate/key deletion or replacement and callback
state mutation across two attaches without reloading. Wrong-password/pre-dial,
malformed/KDF bounds, negative authentication and privacy checks pass. The three
new filesystem/socket suites are integration-tagged: default execution runs zero
of their51 tests; parameter checks remain single-VM units. Strict compile,
ten-file format, scoped Credo and whitespace checks pass.

The42-format x8-password-form loader matrix distinguishes32 actual positive
formats from10 unavailable DES/RC2 formats in the default environment. All80
unavailable cells return finite redacted errors there. Under the isolated
configuration below, all336 loader/password cells pass, with zero blocked.
OTP29.0.2 crypto5.9 links OpenSSL3.5.7; CLI OpenSSL3.6.5 with explicit legacy
provider generates all fixtures. A single process-local `OPENSSL_CONF` and
`OPENSSL_MODULES` probe activates the installed x86_64 MacPorts3.6.5 legacy module:
public OTP reports static linked/compiled3.5.7, DES/RC2 available, and all ten
public decodes equal their clear keys (exit0, empty stderr). The absent build-time
module directory explains a viable provider-discovery fix; no global provider
or FIPS configuration changed. Exact evidence is in
`/tmp/http-fetch-r46-provider-diagnosis/PROBE-HANDOFF.md`.

The same child-only provider configuration subsequently passes49 ExSSL and17
Fetch focused tests and40 independent required-mTLS exchanges: ten formerly
blocked formats x TLS12/TLS13 x public host/prepared attach. Every exchange checks
exact client/server leaf DER, CertificateVerify, Finished, authenticated HTTP and
peer exit0; all20 TLS12 exchanges negotiate EMS. The first Fetch attempt failed
before handshake because Xcode Python3.9/LibreSSL lacks `OP_NO_RENEGOTIATION`.
That failure remains preserved. Prepending a child-only shim for the installed
MacPorts Python3.14/OpenSSL3.6.5 fixes the peer prerequisite; no dependency install,
global configuration or source change occurred. Root verifies all113 evidence
hashes, the1,051-path source snapshot and40 unique actual mTLS rows. All owned
commands and peers stop. Exact environment, commands, raw logs and original failure
are retained in `/tmp/http-fetch-r46-provider-acceptance/FINAL-HANDOFF.md`.
Full encrypted-key acceptance and OTP removal remain open; default-provider,
remote/platform and package/CI matrices are not run.

An extra post-CONNECT file-deletion probe reproduces the same authenticated H2
failure for plaintext and encrypted credentials: the existing pool-key path
re-stats `certfile` and returns `tls_file_unavailable`/`enoent`. This is separate
from the accepted unchanged-file Fetch matrix and public SSL snapshot guarantee;
HTTP H2 mutation-safe snapshots are not claimed. No HTTP production source changed.

Handoff, exact diff, E01–E22 mapping and hashes are in
`/tmp/http-fetch-r46-phase-b/HANDOFF.md` and `final-manifest.json`; detailed failed
checks remain there. Root verified all ten source and thirteen log hashes.
Initial/current worker is Sol, cumulative Sol2/Astra0; final repair succeeds.
All owned commands stop and ownership is released. Full ExSSL/umbrella,
Dialyzer, package/platform and CI gates are not run for this slice. P2 remains
unaccepted and P3/default promotion/publication have not begun.

## R47 — bounded ordinary multiple-identity functionality accepted

Public OTP29 references cover190 observations:149 exact HTTP exchanges and41
malformed/no-identity/rejection outcomes. They establish later actual CA-match
precedence, EC/restricted-PSS ordering and intermediate-only wire chains in both
versions. Evidence is in `/tmp/http-fetch-r47-live-20261023-1/` and
`/tmp/http-fetch-r47-phase-b/intermediate-reference.jsonl`. OTP TLS12 EMS0 is
reference evidence only; ExSSL positives retain EMS1.

The accepted independent implementation preserves modern source precedence,
per-map passwords, validation of every candidate before dialing and immutable
prepared snapshots. Independent peers verify selected DER, wire chains,
CertificateVerify and authenticated application bytes, including ordinary Fetch
direct/CONNECT H1/H2 and EventSource/WebSocket. Negative authentication checks
cover live TLS13 and constructed TLS12 core flows; the latter are not new socket
mutation evidence. Signature/options/selector regressions and scoped compile,
format and Credo checks pass. Exact M01–M19 evidence and limits are in
`/tmp/http-fetch-r47-astra/FINAL-HANDOFF.md`.

Final acceptance fixes an isolated-test tracing initialization dependency and
checks the actual1,048,576 charged issuer visits with the normal ExUnit timeout:
the isolated aggregate passes in6.2s and the full seven-case file in22.0s.
The aggregate charges revisited DERs; the separate per-identity bound retains
unrelated-issuer decoding coverage. Final evidence and source preservation are in
`/tmp/http-fetch-r47-astra-round2/FINAL-HANDOFF.md`. Cumulative Sol2/Astra2 used;
all owned commands and peers stop. M15/M16/M18 public diagnostics, lifecycle,
cleanup and integrated P3 gates remain blocked. Full migration acceptance is open.

## R44 — ordinary verification callback boundary

The original86 OTP29 observations retain a failed validator with16 oracle or
certificate-role errors; that result is not overwritten. A separate22-observation
supplement passes its exact event/role/outcome checks in both TLS versions.
Together they establish original-state reset on distinct cross-signed paths,
native DER callback arguments, extension/EKU handling and custom `verify_none`
validation. Trusted and empty-CA controls both reach `valid_peer`; paired callback
rejections produce the observed TLS alert instead of an application exchange.
All peers exit normally. Original and supplemental evidence remain in
`/tmp/http-fetch-r44-reference-run/actual-20261023T095122Z/` and
`/tmp/http-fetch-r44-supplement/actual-20261023T101531Z/`.
The ordinary callback slice passes22 policy/security checks, all seven live
ExSSL/Core/Fetch checks and the369-check regression selection. Both prepared
attachments independently assert the complete ordered SAN/SKI/AKI/valid_peer
events and states0/1/2/3, immutable trust and authenticated HTTP. Callback ticket
bypass removes the deferred PSK slot before ClientHello materialization.
Required regressions also restore owned-socket closure for malformed upgrade
options, preserve foreign-socket ownership and reconcile TLS12 authority hints
with the accepted R47 fallback policy. The final source passes85 focused
PKIX/Core/Fetch checks, the391-check P2 selection,21-file formatting/Credo and
warnings-as-errors compilation. Four existing Fetch test bitstring warnings
remain recorded; that compile gate does not compile test files.
Evidence and the retained earlier failures are in
`/tmp/http-fetch-r44-astra-round4/HANDOFF.md` and
`/tmp/http-fetch-r44-astra-round5/HANDOFF.md`. Four additional TLS13 integration
cases cover an actually blocked trusted callback on native dial and prepared
upgrade, each cancelled explicitly or by its original lifecycle deadline. They
assert the same callback/Connection identity, exact original resource DOWN,
confirmed durable receipts, peer termination and callback-state privacy. Native
and strict Credo, formatting and callback-extraction AST equivalence pass; default
selection excludes all four. Evidence is in
`/tmp/http-fetch-r44-callback-astra8/HANDOFF.md`.
The complete current ExSSL default unit gate executes580 checks with zero failures
or skips;577 integration/E2E cases are excluded. All1077 source files/modes remain
unchanged after that run; evidence is in
`/tmp/http-fetch-p2-source-validation/HANDOFF.md`. A source review matches129 scoped
files to the accepted391 selection, including shared QUIC TLS contracts, so those
unchanged checks are reused. Complete ExSSL integration/P1/P2 and P3 acceptance
remain open. Peer tests require compatible
Python selected only through a child-process PATH; default Xcode Python lacks
their TLS prerequisites. No broader migration or release gate is implied.

## R49 — preliminary policy reference blocked during peer cleanup

The pinned tool/probe preflight passes. One subsequent invocation generates
fixtures and completes independent certificate, CRL and OCSP material oracles.
Its first TLS12 partial-chain probe reaches `valid_peer` and bounded HTTP200,
but peer cleanup records `PermissionError` before a complete ledger row is saved.
Probe shutdown and port checks pass; a later independent check finds all18 owned
groups absent. The exact syscall/cause remains unknown; no TLS or revocation
failure is inferred. The remaining23 rows are unrun, including every CRL/OCSP
policy row. Positive staple transmission/consumption evidence is still missing.
No retry or permission change occurs. Reproduction and raw evidence are in
`/tmp/http-fetch-r49-observations-REVIEW1/FINAL-HANDOFF.md`.
A controlled two-child diagnostic subsequently observes successful signaling of
a live owned group, `EPERM` for an exited/unreaped owned group and `ESRCH` after
reaping. This supports a cleanup-order hypothesis; the original row's process
state/syscall was not recorded, so its cause remains unproven. The matrix is not
retried. Evidence is in `/tmp/http-fetch-r49-signal-diagnosis/FINAL-HANDOFF.md`.


## R51 — remaining-option reference boundary

One pinned OTP29.0.2/ssl11.7.2 invocation completes all42 planned observations;
its validator reports no errors, and all owned processes stop. Both explicit
`honor_cipher_order` booleans return the client-role server-only error in TLS12,
TLS13 and mixed offers. Explicit `middlebox_comp_mode` booleans require an offer
including TLS13: true produces an initial32-byte compatibility session ID, false
an empty ID. Explicit `reuse_sessions` true/false/save requires an offer including
TLS12. Manual bootstrap reaches the initial hello for TLS13/mixed; empty tickets,
disabled+use_ticket and wrong-SNI material receive distinct configuration errors.
These are configuration and initial-ClientHello observations only. The synthetic
sink closes before a server handshake; authentication, CCS placement, ticket
receipt, session resumption and HTTP remain untested by this reference.
Preparation, actual results and exact classifications are retained in
`/tmp/http-fetch-r51-pin-update/FINAL-HANDOFF.md`. Root verifies all18 checkpoint
and7 actual artifacts against the structured manifest. This reference does not
complete option support, P1 or the migration gates.


## R51 — client-role option acceptance

The bounded `honor_cipher_order` slice now returns the exact OTP29 client-role
error before trust or dialing, and explicit `:undefined` normalizes as omission.
Six single-VM checks cover value/version matrices, direct/prepared public entry
points, payload-free errors, profile equality and existing validation order.
The related unit selection, strict compilation, formatting, whitespace and native
configured Credo gates pass. Strict Credo on the new test alone also passes.
An additional strict-source run retains four pre-existing findings outside the
patch; its exit6 is preserved rather than presented as passing. Repository config
uses strict:false and CI runs the native check. Root verifies unchanged bytes
outside the option-validation block and all1071 baseline files except the owned
source; the new test is the only added source artifact. Evidence is retained in
`/tmp/http-fetch-r51-honor-repair1/FINAL-HANDOFF.md` and
`/tmp/http-fetch-r51-honor-native-lint/FINAL-HANDOFF.md`.
This completes the rejection-only slice; middlebox, session reuse, manual tickets,
managed integration and broader migration acceptance remain open.

## R51 — middlebox interoperability blocker

The candidate middlebox change adds boolean/version/profile checks and one literal
compatibility CCS before CH2 or the ordinary encrypted client flight when the
actual offered session ID is nonempty. Single-VM option, HRR/transcript, incoming
CCS and frozen authenticated SID0 controls pass. The independent ordinary TLS13
true-mode exchange passes with ExSSL and OTP clients, including authenticated HTTP
and connection, proxy-child, peer and listener shutdown. Full support is not accepted.

The expanded independent matrix stops with a peer-generated `illegal_parameter`
for ExSSL's ordered `[TLS12,TLS13]` offer, omitted mode and ordinary handshake.
Installed OTP29.0.2/ssl11.7.2 source identifies the logged rejection branch: the
TLS13 handler rejects legacy-decoded groups. Its extension decoder uses the first
offered version, providing a source-backed explanation for this mixed-order case.
A single-case diagnostic now captures the original221-byte record and216-byte
ClientHello. Independent decoding confirms versions `[0303,0304]`, groups
`[001d,0017]`, key share `001d`, session ID32 and the peer's fatal alert47.
All six loaded-module MD5 values match their disk BEAMs; the three reviewed OTP
source hashes match. This corroborates the decoder explanation, without proving
a pre-change baseline, independent upstream reproducer or reproducible build.
The original connect still fails and its OTP-client counterpart is unreached.
Peer/proxy/children, VM and listeners stop; all1076 repository files/modes remain
unchanged. Evidence is in `/tmp/http-fetch-r51-wire-runtime-handoff/HANDOFF.md`.
Preserve caller preference order; sorting versions would alter the wire contract.

The complete matrix, large mTLS, TLS12 EMS controls, remaining tagged regressions
and final formatting, compilation and lint gates are unrun. Existing protected and
wrong-phase CCS rejection still uses its previous `decode_error` mapping; broader
alert-code conformance is not established. Exact stopped changes and results are
retained in `/tmp/http-fetch-r51-middlebox-repair2/STOPPED-HANDOFF.md`; source
diagnosis and the missing-wire discriminator are in
`/tmp/http-fetch-r51-mixed-offer-diagnosis/REPORT.md`. This blocker leaves middlebox,
P1 and all later migration gates open.

## Ordinary ExSSL H1 completion and reuse accepted

Direct/pinned HTTPS H1 passes exact TLS1.2/TLS1.3 checks for same-connection reuse,
completion, stale cancellation, queued abort/deadline without a POST, peer close
without replay and committed transfer recovery after a lost HTTP acknowledgment.
Caller waits remain finite while the pool is suspended; expired prepare/activation
cannot publish. Unknown offers without a returned ticket retain bounded capacity
and truthful unconfirmed evidence rather than closing or redialing speculatively.

Focused units pass34 checks;14 actual TLS integration cases pass. The exact ten-file
stable regression passes157 checks across Core, Runtime and Fetch. Warnings-as-errors,
formatting and native/strict Credo on all eight selected Elixir files pass. Root
reviewed the production changes and independently verified source preservation and
all15 command roots reaped, with89 known PIDs and86 process groups absent.
Evidence: `/tmp/http-fetch-p3-h1-astra-recovery1/HANDOFF.md` and
`/tmp/http-fetch-p3-h1-coordinator-acceptance.md`. H2, managed/proxy/prepared paths,
advanced policies, performance, package/CI, OTP removal and publication remain open.

## Ordinary ExSSL H2 completion and reuse accepted

Direct/pinned HTTPS H2 passes exact TLS1.2/TLS1.3 integration checks for request
completion while the pooled provider stays live, sibling cancellation and later
same-connection reuse. Admission retains the original deadline through tracker
registration, provider binding and activation; a caller that dies during transport
configuration cannot send the H2 preface. Unknown handoff authority retains bounded
unpublished capacity and unconfirmed cleanup evidence.

Focused units pass37 checks, focused integrations54, stable H2 regressions219 and
affected H1 regressions161. Compilation with warnings as errors, formatting and
native/strict Credo on13 selected Elixir files pass. Public SSE/Fetch mixed,
WebSocket/SSE/Fetch mixed and SSE fault gates pass with exact `--count 10000`
configuration; their actual observed traffic is105,8 and7 requests respectively.
The configured count does not establish10000 observed HTTP exchanges.

Root reviewed the changes and independently verified all310 sealed artifacts,
14 source paths, preservation of1063 unrelated nonkey files and five key-file
stats, and shutdown of93 command roots,958 PIDs and942 process groups.
Evidence: `/tmp/http-fetch-p3-h2-astra-recovery/HANDOFF.md` and
`/tmp/http-fetch-p3-h2-coordinator-acceptance.json`. Managed/proxy/prepared paths,
advanced policies, performance, package/CI, OTP removal and publication remain open.


## Ordinary ExSSL Managed H1/H2 accepted

Explicit ExSSL Managed HTTPS H1/H2 freezes backend and trust/identity material
once per scope. Request completion can release or hand off its obligation while
Scope retains authenticated provider proof across request and pool lifetimes.
Retired capacity remains occupied until public provider await confirms cleanup
and HTTP obligations end. A 100-handle snapshot uses one absolute deadline.

Thirty real TLS cases pass, including exact TLS1.2/TLS1.3 H1/H2 reuse, blocked
Writer retirement, sibling cancellation, trust/identity rotation, overlapping
generations and a 100-connection snapshot with a suspended Observer. Affected H1
and H2 regressions pass161 and219 checks. Relevant unchanged-module Managed and
provider checks, scoped formatting, warnings-as-errors and native/strict Credo
also pass. Earlier unchanged-module checks are retained as scoped evidence; their
whole-source fingerprints are not claimed as final reruns.

Root reviewed flow and independently verified150 sealed artifacts,16 source pins,
1,060 unrelated nonkey files, nine private-key metadata records, exact Git state,
and all39 command roots stopped (372 PIDs/367 process groups absent).
Evidence: `/tmp/http-fetch-p3-managed-astra-recovery/HANDOFF.md` and
`/tmp/http-fetch-p3-managed-coordinator-acceptance.json`. Proxy, client durable
completion, advanced policies, performance and remaining P4-P7 gates remain open.

## Manual TLS 1.3 tickets — local source validation, 2026-10-28

The public engine accepts explicit manual mode and delivers provider-owned maps as
`{:ssl, :session_ticket, ticket}` without consuming application active-once credit.
`use_ticket` accepts one to eight bounded candidates; wrong-context or expired
candidates take a full handshake on the original connection. The saved server
chain is checked against current verification policy. Client identity, concrete
origin, trust, verification mode, ALPN and ordered profile remain partitioned.
Automatic tickets retain their previous TLS1.3-only, verify-peer, no-client-identity
restriction; manual mode supports mTLS and mixed offers without TLS1.2 resumption.

Installed public OTP29 documentation and an independent OpenSSL exchange confirm
manual message/SNI semantics and resumed mTLS identity. OTP29 returns
`{:error, :no_peercert}` after manual resumption; ExSSL intentionally retains its
existing authenticated cached-DER result. OTP29 also rejects explicit
`use_ticket: []`; omission initiates a full handshake. OpenSSL emits multiple
initial tickets, so the test helper consumes the remaining tickets after each
connection closes rather than confusing tickets from successive peers.

Executed locally with Elixir1.18.5/OTP29, existing offline dependencies and peers:

- Manual option/integration, policy-context and PSK verifier checks: **27 passed**.
- Existing automatic resumption, HRR, cache/resource/closure/blocked-write,
  callback and connection/client-auth lifecycle checks: **70 passed**.
- Core TLS transport and contextual-version checks: **49 passed** after refreshing
  the reviewed Connection source pin. All Port/buffer/tos/priority assertions remain.
- `mix compile --warnings-as-errors`, root `mix format --check-formatted` and
  `git diff --check`: passed.

The first regression run exposed the stale Connection pin (70 engine checks and
48 of49 adapter checks passed); its refresh followed review that the Connection
diff changes only ticket delivery and ticket enablement. No TCP ownership or driver
option handling changed. Evidence and exact commands are retained in
`/private/tmp/http-fetch-manual-ticket-root-20261027T2215Z/astra-*.json` and matching
logs. Credo/Dialyzer remain user-deferred; performance, the full remote/runtime and
candidate-package matrices, final CI and release gates were not run for this slice.
This source result does not complete P1 or authorize default-provider promotion.


## P1 — TLS1.2 EMS session reuse (source acceptance)

The independently implemented EMS abbreviated path passes55 focused checks on
Elixir1.18.5 / OTP29.0.2. OpenSSL peers observe a full then resumed exchange for
each existing ECDHE RSA/ECDSA AES128/256 GCM suite, with exact once-only HTTP request
hashes and fresh record keys. The selection covers automatic opt-in, false/default
no-cache behavior, save-only public IDs, false/save opaque capability exports,
forged/evicted capabilities, explicit-true promotion without lifetime renewal,
server-observed mTLS identity and credential changes, callback full handshakes,
profile/ALPN partitions, trust/reference rejection, same-connection cache decline,
bad-master failure without replay, mixed TLS12/TLS13, current PKIX revalidation,
bounded cache expiry/privacy, live secret/timer cleanup, and independent
Finished/key-expansion vectors with fragmentation and negative AEAD/Finished/EMS.
Raw reuse remains disabled by default.

RFC7301 section3.1 requires ALPN to be negotiated for the current handshake.
An agreed red check reproduced `tls12_session_mismatch` when a saved h2 session
selected offered http/1.1. The corrected path accepts this selection and refreshes
live saved metadata without renewing lifetime; unoffered or malformed ALPN still
fails. An independent OpenSSL context preserves its session cache while changing
preference from h2 to http/1.1: the server confirms actual reuse, both sides report
the new ALPN, absolute lifetime stays fixed and record keys differ. This is a TLS
framed-echo scenario, not an HTTP/2 application-readiness claim. Root independently
recomputed all12 existing fixed Finished/key-block vector values and found matches.

The separate TLS1.2 cache holds128 entries/four MiB/256 KiB per entry, with a
ten-minute absolute lifetime, owned binaries, redacted state and one cleanup timer.
Explicit `:session_id` and `:session_data` diagnostics leave default keys unchanged.
Session data is a40-byte VM-local ExSSL capability; no OTP-private serialization or
master secret is exported. false does not cache a fresh session until explicit
export. Advanced policies bypass lookup/saving and cannot export a session.
Default-provider promotion, candidate/platform integration and release gates are
not claimed; performance is outside this goal, Credo/Dialyzer user-deferred.

Installed OTP29.0.2/ssl11.7.2 public references accept true/false/save and expose
32-byte IDs. Public opaque tuples resume against OpenSSL, including false/save
exports followed by explicit true. Automatic and saved-ID references have not
resumed, including clean close, open sockets, OTP server, Python/CLI OpenSSL,
valid server-observed mTLS identities and a documented public cache callback that
stores only opaque terms. Subsequent auto after explicit-true reuse also remains
full in that runtime. Loaded modules and compile metadata confirm the intended
installed OTP29 artifacts. No private OTP session structures are copied or
accepted by production. This observed reference difference remains unresolved.
OTP documents automatic reuse as "if possible", so a full fallback alone is not
an ExSSL implementation failure; independent ExSSL positive interoperability and
reference observations are separate evidence.

Strict umbrella compile passes. Round3 focused receipt is `repair3-focused.json`;
the agreed red receipt is `repair3-alpn-red.json`. The earlier full ExSSL run
reached its600s process cap and recorded a native setup400ms control deadline
failure before TLS attach; isolated unchanged current and original Connection
runs each pass4/4, which does not establish aggregate causality. The capped run
is not a passing suite; its process audit confirms owned children stopped. An
adequate1800s aggregate run subsequently passes20 properties/3485 tests,0 failures
in677.9s (679.566s process wall). All1836 ledgered OpenSSL peers join and the
post-run process audit finds no owned run/peer remaining. Core source-pin/transport
checks pass27/27, and the complete Fetch H2 source suite passes43/43 with unchanged
assertions/deadlines after its audited Connection pin update. Root formatter and
diff checks pass. The earlier isolated setup
passes and final aggregate green do not prove the cause of the original deadline.
The whitelisted OTP cache-config read finds no configured cache overrides.
Commands, actual terminal receipts,
booleans/length-only OTP output, and independent vector recipe remain under
`/private/tmp/http-fetch-tls12-session-reuse-sol-20261027T2320Z/`.
The H2, vector and pin-audit receipts are retained under
`/private/tmp/http-fetch-tls12-candidate-suite-root-20261027T2340Z/`.

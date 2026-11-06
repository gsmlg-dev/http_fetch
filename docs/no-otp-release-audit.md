# Directed production release audit

## Logger configuration review — 2026-11-07

The root formatter now includes the literal metadata keys `:event`, `:metadata`
and `:measurements` used by the imported Abyss logger. Independent source review
confirmed that this changes log rendering only: no application startup, callback,
transport or TLS selection changed. All 244 original package source hashes, ten
review documents, 94 producer inputs and 175 reviewed occurrences remain equal.
Only the `config/config.exs` hash in the release bundle was rebound. This review
does not replace fresh candidate/published runtime verification or extend the
nine-package no-OTP-SSL proof to Abyss, Hell or `abyss_raw`. Hell still uses OTP
`:ssl` for its server transport.

P6's non-deferred gates **pass** at `658bbd5`. The strict production no-OTP-SSL
gate passes at `31a8a15`, with identical production sources through `658bbd5`;
the complete nine-app integration workflow now also passes. General
static-analysis development is paused. The proof covers
actual shipped implementations from supported public entries and the user-approved
callback boundaries. The original dispatch inventory remains intact.
All nine `1.0.0-rc.0` packages are now published at `233a653`, and cold
published-consumer verification passes the complete release workflow.
Performance, Credo and Dialyzer work remain deferred by the user.

## Published RC acceptance — 2026-11-02

[Release workflow 41424352487](https://github.com/gsmlg-dev/http_fetch/actions/runs/41424352487)
passes all non-deferred source, candidate and cold published-consumer gates.
Both candidate and published releases pass two 35-scenario TLS plans: 140 actual
consumer-peer pairs. Each release retains all 175 original findings and proves
them against 350 inspected BEAMs and 256 reviewed sources, with zero unproved
sites. OTP SSL remains unavailable, unloaded and unstarted before and after
traffic. Independent peers confirm the requested protocol, no fallback/replay
and complete cleanup, with zero active connections or errors.

Root independently matches all nine actual archives to Hex checksums, GitHub
asset digests and tag sources, and reconciles all four native reports, wrapper
path records and peer observations. Published TLS consumers pass 71 groups /
3,066 checks without failures, skips or exclusions; published public H3 also
passes. The [publication ledger](tls-migration-validation.md#p7-coordinated-rc-publication--2026-11-02)
records exact commits, artifacts and receipts. The
[GitHub release](https://github.com/gsmlg-dev/http_fetch/releases/tag/v1.0.0-rc.0)
is a prerelease; `v0.21.19` remains latest stable.

## Integrated P6 acceptance — 2026-11-02

All nine jobs in [integration run 41417340062](https://github.com/gsmlg-dev/http_fetch/actions/runs/41417340062)
pass at `658bbd5b77964535bd1756f8ad8dbf8bac08041d` on Elixir 1.18 / OTP 28.
Fetch reports 20 doctests and 1,591 tests, zero failures and 351 selection
exclusions. WebTransport has no integration-tagged cases; its successful empty
selection is not counted as executed coverage. Root reconciles every app's
summary and log hash in
`/private/tmp/http-fetch-directed-p6-20261102T0522Z/ALL9-INTEGRATION-ACCEPTANCE.json`.

The unchanged production implementation retains the passing full manual CI,
all-nine unit and configured E2E results below. The additional
[runtime matrix](https://github.com/gsmlg-dev/http_fetch/actions/runs/41407872020)
passes 71 current-candidate groups and 3,066 checks on both Elixir 1.19 / OTP 28
and Elixir 1.20 / OTP 29, with zero failures, skips or exclusions. Historical
published `ex_ssl` 0.7.2 reference results remain separate. The
[independent public H3 gate](https://github.com/gsmlg-dev/http_fetch/actions/runs/41408366124)
also passes.

Four integration fixtures changed after `31a8a15`: nested proxy and WSS fixtures
complete verified initialization before their original timing assertions; the
pinned native timeout fixture uses its explicit test CA; blocked-upload checks
confirm public cleanup and original provider DOWN before releasing the deliberately
nonreading peer. Existing errors, identities, resource assertions and time limits
remain intact. No production code, manifest, configuration or gate changed.

The earlier single 8-second upload peer-closure observation failure was not
reproduced by the focused diagnostic or three full-context diagnostic jobs.
The cleanup-order change strengthens an independent precondition; it does not
establish or claim a production root-cause repair. The original failure and all
diagnostic receipts remain recorded. Current full integration supplies the
acceptance result. The complete release workflow, coordinated publication and
cold published-consumer verification remain mandatory P7 gates.

## Reference regression acceptance — 2026-11-02

At `31a8a15da424d4ee658cedef0d9be7c477c597e3`, the full manual
[CI run 41405668874](https://github.com/gsmlg-dev/http_fetch/actions/runs/41405668874)
passes all nine compile/format/package jobs, all candidate TLS feature groups,
candidate consumers, shared H2 compatibility and the strict no-OTP release gate.
Both isolated TLS plans again prove all 175 dispatch occurrences and pass all
35 traffic scenarios. Root independently reconciles the artifacts in
`/private/tmp/http-fetch-directed-p6-20261102T0522Z/STRICT-31A-ACCEPTANCE.json`.

The earlier OTP 28 failures concern its hybrid X25519MLKEM768 reference handshake
after HelloRetryRequest. A bounded OTP 28/29 comparison verifies that the classical
X25519 reference resumes correctly. The reference fixture now selects that common
supported group and adds a real forced classical HelloRetryRequest resumption
case. ExSSL production behavior is unchanged. All ten manual-ticket cases and
40 targeted resumption checks pass locally; the complete OTP 28 ExSSL integration
job passes 3,541 tests and 20 properties with 692 integration-selection exclusions.
All candidate TLS feature groups also pass, including manual tickets and resumed
mTLS. No resumption, identity or cleanup assertion is removed.

All-nine [units](https://github.com/gsmlg-dev/http_fetch/actions/runs/41405674076)
and configured [E2E](https://github.com/gsmlg-dev/http_fetch/actions/runs/41405683173)
pass. Eight [integration](https://github.com/gsmlg-dev/http_fetch/actions/runs/41405678859)
jobs pass. Fetch reports one failure: the 500ms total deadline expires during
proxy TLS before the `origin_gate` fixture reaches its required phase. This was
a release blocker at that checkpoint. The later full integration result above
closes it; a passing focused local file alone was insufficient.

## Strict release acceptance — 2026-11-02

At `bf13e6248b7e33e2de9c2b899dabcb0399036e2a`,
[CI run 41402393470](https://github.com/gsmlg-dev/http_fetch/actions/runs/41402393470),
job `125137168973`, artifact `13122326455`, both strict candidate release gates
pass on Elixir 1.18.6 / OTP 28 / ERTS 16.4.0.7. Neither uses blocked-traffic mode.
Each release inspects 350 BEAMs and retains all 175 original dynamic findings.
The five concrete source reviews bind every occurrence exactly once to the
reviewed producer, retained state and approved callback boundary; zero findings
remain unproved. The complete binding covers 256 source inputs, including the
production dependency and the three release fixture modules.

Both TLS plans pass all 35 actual scenarios, with independent peer confirmation
of TLS/ALPN, request counts, no fallback/replay and provider cleanup. All peers
report zero active connections and no errors. OTP SSL is absent from application,
boot, bundle and direct-import inventories and is unavailable, unloaded and
unstarted before and after traffic. Root independently reconciled the native
binding receipt, unchanged findings and all 70 peer/consumer pairs against the
current sources. Evidence is retained in
`/private/tmp/http-fetch-directed-p6-20261102T0522Z/STRICT-70-ACCEPTANCE.json`.

The same source passes all-nine
[unit](https://github.com/gsmlg-dev/http_fetch/actions/runs/41402395490) and
[E2E](https://github.com/gsmlg-dev/http_fetch/actions/runs/41402399467) workflows.
Eight applications pass their
[integration](https://github.com/gsmlg-dev/http_fetch/actions/runs/41402397411)
jobs. ExSSL's integration job reports 3,540 tests, two failures and 692 exclusions:
the OTP manual-ticket and OTP resumed-mTLS reference cases receive a peer
`decrypt_error`. Candidate TLS feature consumption reports the same two failures.
They were release blockers at that checkpoint; the passing no-OTP production
release did not waive them. The subsequent OTP 28 reference acceptance above
closes them. A local OTP 29 pass alone did not establish that result.

## Original artifact and baseline evidence

The inventory uses the production release from commit
`e1cc63619e2c4146eac9e0367828278792110ee6`, CI run
[41391670111](https://github.com/gsmlg-dev/http_fetch/actions/runs/41391670111),
job `125104458335`, artifact `13117204316`
(`no-otp-candidate-release-diagnostics`). Runtime: Elixir 1.18.6, OTP 28,
ERTS 16.4.0.7. The candidate version is `0.21.19`; the coordinated release
target remains `1.0.0-rc.0`.

The release contains 349 inspected non-OTP BEAMs and 175 unresolved dispatch
occurrences in 32 modules. The
[complete inventory](no-otp-release-dispatch-inventory.csv) preserves each
occurrence, package, module, owning function, line, dispatch kind and BEAM hash.
Owning functions were cross-checked against raw abstract code from the local
candidate with matching library sources. Hashes bind review to these bytes;
they do not establish callable safety.

No OTP SSL application dependency, bundled SSL directory, boot entry, direct SSL
import, missing abstract code or duplicate candidate application was reported.
Before and after the audit, OTP SSL was unavailable, unloaded and unstarted.
At that baseline, the strict dispatch check rejected the release before traffic:
**zero scenarios executed**. The later traffic evidence below preserves that
static failure.

## Actual no-OTP SSL traffic — 2026-11-02

At `524edb284aa26b92a0dd2aace4d5dd8a3d395c0a`,
[CI run 41395793221](https://github.com/gsmlg-dev/http_fetch/actions/runs/41395793221),
job `125116856947`, artifact `13119243608`, builds isolated candidate releases
on Elixir 1.18.6 / OTP 28 / ERTS 16.4.0.7. Both TLS plans pass all 35 scenarios:
H1, H2, WebSocket, EventSource, managed H1/H2 and explicit H3, each with success,
invalid identity, timeout, cancellation and shutdown. The TLS1.2 plan still uses
TLS1.3 for H3, as required by QUIC.

The 70 consumer results and independent peer observations agree on nonce,
identity, TLS/ALPN, request counts, no fallback/replay and confirmed cleanup.
All peer statistics report zero active connections and no errors; peer teardown
has no errors. OTP SSL remains unavailable, unloaded and unstarted before and
after traffic. All 269 packaged source hashes match the current sources, with
the existing portable `mix.exs` transformation applied.

This is passing **traffic evidence**. Both strict release commands and overall
gates still fail with all 175 unresolved dispatch findings retained. No directed
proof or P6 acceptance is inferred from successful traffic. Root's independent
artifact/peer/source verification is retained in
`/private/tmp/http-fetch-directed-p6-20261102T0522Z/TRAFFIC-70-ACCEPTANCE.json`.

| Production package | Remaining occurrences |
| --- | ---: |
| `ex_ssl` | 14 |
| `elixir_quic` | 28 |
| `http_core` | 19 |
| `elixir_quic_http3` | 32 |
| `http_runtime` | 33 |
| `http_fetch` | 16 |
| `http_web_socket` | 7 |
| `http_event_source` | 9 |
| `http_web_transport` | 10 |
| Third-party `telemetry` 1.4.2 | 7 |
| **Total** | **175** |

## Supported proof boundary

The guarantee starts at supported public Fetch, managed H1/H2, EventSource,
WebSocket, explicit H3, TLS and QUIC operations. It includes ordinary failure,
timeout, cancellation, reconnect, shutdown, and library-created stale messages.
Hot replacement, `sys.replace_state`, fabricated private state and unrelated
private messages are outside the approved boundary.

User callback bodies are arbitrary external code and are not certified free of
OTP SSL. Their origins must still be established, including every library-created
alternative, nested closure and possible library reentry. The approved module
extension roots are Session `:transport`, WebTransport `:backend`, TLSDriver
`:adapter`, and Transport.Quic `:ops` (user decision on 2026-11-02).
Default and library implementations remain fully audited.

Direct arbitrary calls into internal `HTTP.HTTP3.request/3`, H2 initialization
and framework callbacks are outside the supported input guarantee. Their actual
production callers and state transfers remain in scope. This boundary does not
turn transport maps, callback throws or unknown return values into safe sources.
The approved `:ops` boundary still requires origin and built-in-body proofs.
A public struct or an exported helper alone establishes no approved extension
contract.

## Reviewed obligations

Each identifier below maps to exact occurrences in the CSV. These are concrete
source findings and the original proof obligations. The accepted source-bound
native binding above discharges every occurrence for this release while retaining
the original inventory. No new general interpreter, callable reducer, or origin
graph is required. Missing producer, state-transfer, reentry, or contract evidence
keeps a finding blocked; changed inputs require fresh acceptance.

The [directed TLS source review](no-otp-directed-tls-proof.md) now traces all 14
TLS-1 through TLS-6 occurrences against 26 selected source inputs and the complete
244-file production-source census. The compiled findings remain retained and
are discharged only by the accepted source-bound native binding.

The [directed QUIC source review](no-otp-directed-quic-proof.md) traces all 28
Q1–Q4 occurrences: opaque cleanup capability construction, the two concrete IO
implementations, the external datagram callback and the approved TLS adapter.
It likewise preserves the compiled findings and their reviewed derivations for
the native binding.

The [directed HTTP source review](no-otp-directed-http-proof.md) covers 76
HTTP-1–HTTP-9 and WT-1 occurrences, including actual pool/owner constructors,
stale connection replies and the unsupported built-in WebTransport backend.

The [directed HTTP3 source review](no-otp-directed-h3-proof.md) covers 50
H3-1–H3-5 occurrences. It records the approved `:ops` boundary and audits the
default Quic implementation, shared endpoints and retained stream selectors.

The [directed telemetry review](no-otp-directed-telemetry-proof.md) covers the
remaining seven TEL-1/TEL-2 occurrences. Logger/metrics attachment examples are
documentation only; actual handler origins and the two storage implementations
are reviewed separately.

| Proof | Actual implementation and entry | Source finding and remaining proof |
| --- | --- | --- |
| Q1 | `Quic.Cleanup.new/1 -> retire/2` | `new/1` constructs the retirement closure around its handle, secret and atomics fence. Bind all library leases reaching `retire/2` to this constructor; do not treat arbitrary `%Lease{}` values as safe. |
| Q2 | `Quic.Endpoint.open_io/2 -> Quic.Connection` | Endpoint chooses `Quic.IO.GenUDP` or `Quic.IO.ExternalWriter` and supplies `{adapter, writer}` to Connection. Prove every supported connection constructor and subsequent state update retains that finite adapter set; include endpoint retry output. |
| Q3 | Public QUIC external server IO -> `ExternalWriter` | `{:external, local, send_fun}` is validated as a two-argument callback and stored by `ExternalWriter.init/1`. Bind its sole invocation to that origin, including library-supplied callback alternatives. |
| Q4 | `Quic.TLSDriver.new/2` | Approved `:adapter` root, default `SSL.QUIC`, retained in the driver. Check all feed/info/abort/receive-level paths and state updates; audit `SSL.QUIC` and any library-supplied adapters. |
| H3-1 | `QuicHttp3.Session.new/1` | Approved `:transport` root, default `QuicHttp3.Transport.Quic`. Prove transport retention, all operation wrappers, resume, and ready paths; retain native cleanup restrictions. |
| H3-2 | `QuicHttp3.Transport.Quic.client/1, connect/3` | `:ops` is an approved user-module root as of 2026-11-02. Its retained connection/stream selectors, shared endpoint equality checks, default Quic bodies and unchanged native cleanup restrictions are traced in the HTTP3 review. |
| H3-3 | Internal `HTTP.QUIC.ExQuic` wrappers | Production wrappers default to `Quic`; the extra driver parameter is a test seam. Inventory actual production incoming calls, including explicit driver arguments, before restricting targets to `Quic`. |
| H3-4 | `HTTP.HTTP3.Stream` connector | `connector_wait/5` invokes a callback obtained by the descriptor path. Prove all supported connector producers and retained-worker handoffs; do not classify an unknown callback from its name. |
| H3-5 | Fetch -> `HTTP.HTTP3.request/3 -> await/5` | Production SocketClient supplies `handle_http3_event/2`; the recursive loop preserves the handler. Bind both callsites and any library reentry to that caller. Arbitrary direct handlers at this internal entry are outside the approved guarantee. |
| TLS-1 | `SSL.ClientHello.Materializer` | Generator defaults to `KeyExchange.generate/1`; `:test_key_share_generator` permits a function. Prove supported production option construction and all library/test-hook alternatives separately. |
| TLS-2 | `SSL.ClientIdentity` password resolution | `password_option/1` recognizes a zero-argument user password callback. Prove propagation from supported identity options and audit library-supplied alternatives. |
| TLS-3 | `SSL.PKIX.Revocation` | Built-in `:ssl_crl_cache` and `:ssl_crl_hash_dir` names are routed to owned ExSSL implementations before generic cache callbacks. Prove normalization and every lookup/select/refresh path; these compatibility atoms do not authorize OTP SSL calls. |
| TLS-4 | `SSL.PKIX`, `VerifyFun` | Supported verify and hostname callbacks are external boundaries. `policy_event/3` also receives a library hostname closure from PKIX. Prove that closure and every callback-producing caller; keep internal and external alternatives distinct. |
| TLS-5 | `SSL.PolicyIO` partial-chain selection | Supported `:partial_chain` callback reaches `partial_selection/2` through normalized policy. Bind every candidate-selection path and library-created alternative. |
| TLS-6 | `SSL.Connection -> PolicyIO.prepare -> TLS13/TLS12` | Certificate verification selects `PKIX.peer/6` or the policy closure returned by `PolicyIO.prepare`. Public normalized options do not directly choose the internal `certificate_policy` field. Prove both constructors and handshake-machine propagation, including TLS1.2. |
| HTTP-1 | Runtime dialer and proxy upgrade | Transport selection is built-in TCP/ExSSL/Unix; proxy TLS upgrade resolves ExSSL. Bind every internal connect/transfer/close/upgrade call to the selector and preserve failure/handoff branches. |
| HTTP-2 | `HTTP.RequestLifecycle` workers | Launch, worker body and rejection callbacks come from concrete library worker creators. Enumerate all callers and nested closures; supported user body callbacks remain external only at their approved projection. |
| HTTP-3 | `HTTP.EventSource` -> connection | HTTP1 selection chooses TCP/ExSSL/Unix. Prove generation-tagged connection replies, stale-reply closure, reconnect and state retention through rearm/detach/close. |
| HTTP-4 | Fetch SocketClient and idle writes | Bind `transport` to TCP/ExSSL/Unix and `protocol_module` to HTTP1/HTTP2 through initialization, response reducers, streaming state and failure cleanup. Prove every worker argument and returned/thrown state preserves those fields. |
| HTTP-5 | `HTTP.Promise.then/2,3` | Success/error functions are approved public callbacks. Inventory library-supplied callbacks and compatible higher-order library reentry before accepting the `apply/2` origin. |
| HTTP-6 | HTTP1 pool checkin/checkout | Actual entry retains the selected transport. Prove checkin messages, leased entries, stale entries, activation, expiry and retirement; a module-typed parameter alone is insufficient. |
| HTTP-7 | H2 owner creation from supported clients | Production callers supply a selected built-in module. Prove initialization and every normal/throw/callback state transfer. Internal arbitrary map transports are outside the approved direct-call guarantee, but must be proved unreachable from supported roots. |
| HTTP-8 | H2 pool owner factory | `init/1` accepts `:owner_factory`; production application starts its pool with the default. Enumerate custom pool/scope constructors and prove whether supported public clients can reach an injected factory. |
| HTTP-9 | Public WebSocket -> connection | Prove built-in transport selection and retention through connect, reconnect, queued frames, backpressure, EOF, abort, rearm and detach. |
| WT-1 | `HTTP.WebTransport.new/2` | Approved `:backend` root flows through Options into Session. Audit the unsupported built-in QUIC backend and all library alternatives; no native WebTransport capability is added. |
| TEL-1 | `telemetry:attach[_many]`, `span/3` | Handler/span functions originate at supported callbacks. The production source and BEAM census contains no library-supplied handler/span; HTTP.Telemetry's logging/metrics examples are documentation only. Attachment storage and reentry are traced in the telemetry review. |
| TEL-2 | Telemetry application initialization and `persist/0` | `init/1` stores `telemetry_ets` and its list function; successful persistence switches to `telemetry_pt`. Default state has a literal empty-list closure. Prove every implementation-tuple writer and audit both built-in modules. Arbitrary external `persistent_term` mutation is not a supported callback root. |

## Acceptance sequence

The finite binding in [no-otp-directed-release.json](no-otp-directed-release.json)
identifies the ten reviewed documents, the complete 244-file production source
census, configuration and the actual telemetry source. The release-specific
`no_otp_directed_review` helpers check these inputs without adding origin analysis.
The native helper checks every inspected module's compiled source, owning
function and call line, and requires byte identity between the fresh build and
the release. Its receipt retains the original findings and identifies the source
proof for each occurrence; a separate Python check reconciles the complete
receipt. New sources, changed producers, extra or missing sites, and mismatched
build bytes fail closed. These bindings identify the concrete derivations above;
hash equality alone does not establish their safety.

`--directed-review` enables this binding in the strict candidate and published
release gates. It cannot be combined with blocked-traffic diagnostics. Review
input changes trigger candidate acceptance in CI. The binding, complete
release/CI tooling regressions and actual strict release and traffic gates pass
as recorded above. The generic audit remains unchanged.

1. Complete each directed producer/state/callback proof, bound to the selected
   sources and original occurrence identities. Preserve all remaining blockers.
2. Collect real traffic even while static dispatch blockers remain. Keep the
   strict release result failed, record traffic and static results separately,
   and retain code-path, package, TLS identity, no-replay and cleanup assertions.
3. Require both static proof and the full real-traffic matrix before accepting P6.
   The earlier OTP manual-ticket `decrypt_error` failures were separate blockers;
   their later full-suite acceptance is recorded above.
4. Publish all nine packages as `1.0.0-rc.0` through the existing coordinated
   release workflow, then validate cold published consumers and actual releases.
   The published RC acceptance above completes this sequence.

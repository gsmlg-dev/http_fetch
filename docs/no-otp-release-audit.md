# Directed production release audit

P6 is **blocked**. General static-analysis development is paused. The remaining
work proves the actual shipped implementations from supported public entries and
the user-approved callback boundaries. No dispatch is cleared by this inventory.
`1.0.0-rc.0` publication and cold published-consumer verification follow P6.
Performance, Credo and Dialyzer work remain deferred by the user.

## Artifact and current evidence

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
extension roots are Session `:transport`, WebTransport `:backend`, and TLSDriver
`:adapter`. Default and library implementations remain fully audited.

Direct arbitrary calls into internal `HTTP.HTTP3.request/3`, H2 initialization
and framework callbacks are outside the supported input guarantee. Their actual
production callers and state transfers remain in scope. This boundary does not
turn transport maps, callback throws, unknown return values, or `:ops` injection
into safe sources. A public struct or an exported helper alone establishes no
approved extension contract.

## Directed obligations

Each identifier below maps to exact occurrences in the CSV. These are concrete
source findings and remaining obligations, **not accepted certificates**. No new
general interpreter, callable reducer, or origin graph is required to classify
these sites. Missing producer, state-transfer, reentry, or contract evidence keeps
the original finding blocked.

| Proof | Actual implementation and entry | Source finding and remaining proof |
| --- | --- | --- |
| Q1 | `Quic.Cleanup.new/1 -> retire/2` | `new/1` constructs the retirement closure around its handle, secret and atomics fence. Bind all library leases reaching `retire/2` to this constructor; do not treat arbitrary `%Lease{}` values as safe. |
| Q2 | `Quic.Endpoint.open_io/2 -> Quic.Connection` | Endpoint chooses `Quic.IO.GenUDP` or `Quic.IO.ExternalWriter` and supplies `{adapter, writer}` to Connection. Prove every supported connection constructor and subsequent state update retains that finite adapter set; include endpoint retry output. |
| Q3 | Public QUIC external server IO -> `ExternalWriter` | `{:external, local, send_fun}` is validated as a two-argument callback and stored by `ExternalWriter.init/1`. Bind its sole invocation to that origin, including library-supplied callback alternatives. |
| Q4 | `Quic.TLSDriver.new/2` | Approved `:adapter` root, default `SSL.QUIC`, retained in the driver. Check all feed/info/abort/receive-level paths and state updates; audit `SSL.QUIC` and any library-supplied adapters. |
| H3-1 | `QuicHttp3.Session.new/1` | Approved `:transport` root, default `QuicHttp3.Transport.Quic`. Prove transport retention, all operation wrappers, resume, and ready paths; retain native cleanup restrictions. |
| H3-2 | `QuicHttp3.Transport.Quic.client/1, connect/3` | `:ops` defaults to `Quic` and is retained in endpoint/connection/stream descriptors. Arbitrary `:ops` is not an approved root. Prove production options exclude injection and cover shared endpoints, or retain this contract blocker. |
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
| TEL-1 | `telemetry:attach[_many]`, `span/3` | Handler/span functions are callback roots. Audit HTTP.Telemetry's built-in logging/metrics handlers and every library-supplied span; establish attachment-table provenance. |
| TEL-2 | Telemetry application initialization and `persist/0` | `init/1` stores `telemetry_ets` and its list function; successful persistence switches to `telemetry_pt`. Default state has a literal empty-list closure. Prove every implementation-tuple writer and audit both built-in modules. Arbitrary external `persistent_term` mutation is not a supported callback root. |

## Acceptance sequence

1. Complete each directed producer/state/callback proof, bound to the selected
   sources and original occurrence identities. Preserve all remaining blockers.
2. Collect real traffic even while static dispatch blockers remain. Keep the
   strict release result failed, record traffic and static results separately,
   and retain code-path, package, TLS identity, no-replay and cleanup assertions.
3. Require both static proof and the full real-traffic matrix before accepting P6.
   The current two OTP manual-ticket `decrypt_error` integration failures are
   separate release blockers; they cannot be hidden by focused traffic success.
4. Publish all nine packages as `1.0.0-rc.0` through the existing coordinated
   release workflow, then validate cold published consumers and actual releases.

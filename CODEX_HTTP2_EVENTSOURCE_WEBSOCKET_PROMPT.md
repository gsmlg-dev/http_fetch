# Codex task: HTTP/2 support for EventSource and WebSocket

## Mission and baseline

Work in `https://github.com/gsmlg-dev/http_fetch`.

Implement production-quality HTTP/2 support for both `HTTP.EventSource` and
`HTTP.WebSocket`. Deliver executable code, regressions, independent-peer gates,
package-consumer verification, and documentation—not just an implementation plan.

Start with shared runtime extraction and EventSource; implement WebSocket using
RFC 8441 after the shared runtime and SSE gates pass. Preserve the existing HTTP/1
implementations and the accepted Fetch HTTP/2 behavior throughout.

Planning baseline: `b5d17bfe3a6be9fbb20a3f3c185dc36773b9f367`, v0.15.1.
The repository's default branch still pointed to this commit when this prompt was
prepared on 2026-10-01. Reconcile against the actual checkout before editing; do
not reset newer changes to this baseline.

At this baseline:

- Fetch has a hardened, pooled HTTP/2 implementation. The prior F1 early-response
  upload cleanup and F2 waiter/connector progress fixes have been accepted.
- EventSource establishes its own connection and feeds `HTTP.HTTP1` before the
  SSE parser. WebSocket establishes its own HTTP/1.1 Upgrade connection.
- Neither EventSource nor WebSocket currently uses the shared HTTP/2 owner.
- `HTTP.HTTP2.Settings` recognizes standard settings 1–6 but does not model the
  RFC 8441 setting 0x8 as a capability.
- AGENTS.md requires independently consumable child apps: protocol clients depend
  on shared layers, not on one another.

Do not reopen resolved findings merely because old NOT MET sections remain in the
historical validation report. Preserve those records and extend the tested scope.

## 1. Read and map before changing code

Read root and applicable nested AGENTS.md files, the current Mix dependency graph,
README/CLAUDE guidance, `docs/http2-production-validation.md`, and the existing
closure evidence and gate runners. Inspect these concrete areas:

| Area | Baseline paths |
| --- | --- |
| Pure H2 state | `apps/http_core/lib/http/http2/{connection,stream_state,settings,boundary,hpack,scheduler,wire_profile}.ex` and `http2.ex` |
| Existing H2 runtime | `apps/http_fetch/lib/http/http2/{connection_owner,connection_supervisor,pool,pool_key,body_bridge}.ex` |
| Fetch integration | `apps/http_fetch/lib/http/{socket_client,stream,telemetry,fetch_options}.ex`, `lib/http_fetch.ex` |
| SSE | `apps/http_event_source/lib/http/event_source/{connection,options,parser}.ex` and its public API/application |
| WebSocket | `apps/http_web_socket/lib/http/web_socket/{connection,options,handshake,frame}.ex` and its public API/application |
| Distribution | All relevant `mix.exs`, `.github/workflows/`, external-consumer, published-ex_ssl, H2 interop/package scripts |

Create `docs/http2-stream-clients-plan.md` with the dependency graph, stream
contracts, API option matrix, risks, test mapping and implementation sequence.
Then execute it in this task. Keep the document updated rather than stopping at
its creation. Inspect actual APIs before choosing final names.

Use the standards linked in section 10 for wire semantics. Reuse repository
fixtures where useful, but not as the only interoperability oracle.

## 2. Shared architecture: one reusable HTTP/2 runtime

### 2.1 Dependency direction

Prefer a dedicated `apps/http_runtime` OTP application, unless current HEAD already
has an equivalent shared runtime. The intended dependency direction is:

    http_core                         pure protocol state/codecs + transport primitives
        ^
        |
    http_runtime                      pooled connection owners, supervision, stream I/O
        ^
        |
    http_fetch / http_event_source / http_web_socket

Clients may also depend directly on `http_core`. Do not add EventSource/WebSocket
as clients of `http_fetch`, create circular dependencies, or copy the H2 engine
into either client. Do not move a Fetch implementation wholesale into `http_core`
merely to hide a dependency cycle.

Extract the existing ConnectionOwner, ConnectionSupervisor, Pool and PoolKey
implementation rather than replacing their algorithms. Keep existing module names
where practical; avoid duplicate BEAM module definitions and multiple supervision
owners. Retain compatibility delegates only where necessary.

Move generic dialing, capability observation, admission and stream lifecycle behind
a small internal stream API. Preserve TLS/backend/profile/scope identity rules.
Fetch-specific `HTTP.Stream`, response construction, Promise, BodyBridge and abort
integration may remain Fetch adapters. The shared runtime must not invoke
Fetch-only modules or require `:http_fetch_task_supervisor`/`HTTP.Telemetry` to be
started. Split shared telemetry emission from client wrappers as necessary while
preserving established Fetch telemetry contracts.

Use pure transformations and explicit effects in `http_core`; OTP processes own
sockets, timers, monitors and coordination. Do not add an object hierarchy or a
second H2 library. Do not rearchitect HTTP/1 beyond the adapter seams needed here.

### 2.2 Internal stream contract

Implement the smallest typed contract supporting: deadline-aware admission;
opening a request or Extended CONNECT stream; informational/final headers;
ordered DATA/trailers/remote-end events; bounded writes; receive-credit settlement;
local half-close; stream reset; capability updates; terminal errors; and idempotent
release. Use connection/stream/generation identifiers so stale events or ACKs
cannot affect a reconnected SSE session or another stream.

The connection owner remains the only transport writer. Neither SSE nor WebSocket
may read, write, close, change ownership of, or rearm the shared socket directly.
Closing one logical client releases only its stream/reservation. Starting or
stopping one client application must not create duplicate shared pools or kill a
shared connection still used by another client. Runtime restart must settle its
clients rather than orphan them.

Pool admission must support required peer capabilities without occupying a stream
slot indefinitely or opening an unsupported CONNECT. Reuse compatible connections
across Fetch/SSE/WebSocket, including normalized `wss -> https` origin identities.
Do not add adapter type to the key solely to avoid exercising mixed clients.
Retain intentional isolation by origin, TLS configuration, profile, route, scope,
and explicit reuse controls. Opaque TLS configuration remains conservatively
non-reusable. Do not introduce cross-origin connection coalescing.

### 2.3 Explicit request versus tunnel policy — mandatory

Record an immutable stream purpose when opening it. An ordinary request and an
Extended CONNECT tunnel are different protocol lifecycles, not inferred from a
Content-Type or guessed from a response.

- Ordinary Fetch: retain F1. A final response abandons unfinished upload work, and
  completion/cleanup correctly closes the unfinished request direction.
- SSE: an ordinary GET with no upload and a potentially indefinite response body.
  Its adapter controls response streaming and reconnect policy.
- WebSocket: successful Extended CONNECT establishes a duplex byte stream. It
  must not stop outbound data or release the reservation at final response
  headers. Ordinary response Content-Length/body-forbidden/end-of-upload rules
  must not accidentally apply to established tunnel data.
- A rejected Extended CONNECT never becomes a tunnel. Bound/discard its HTTP
  response safely and release its stream without exposing it as WebSocket data.

Make this policy explicit in pure state validation, scheduler behavior, response
handling and cleanup. The accepted Fetch F1 and F2 tests must remain meaningful
and pass without globally disabling either fix.

### 2.4 Real resource bounds

Keep existing directional windows, bounded writer behavior, fair scheduling,
connection receive budget, header limits and monitoring. A stream parked on zero
credit must not block control processing, cancellation or unrelated streams.

Bound bytes and counts at every new stage: pending writes, parser fragments,
assembled event/message, queued deliveries, workers, timers and reservations.
One bounded H2 window is not a bound on an application's mailbox.

Reuse legacy public push delivery by default, but do not describe it as strict
consumer-acknowledged backpressure. Add an explicit acknowledged or pull delivery
mode for strict bounds, with opaque delivery references and idempotent settlement.
Keep the existing event envelope unchanged in legacy mode. For that mode, provide
a finite internal queue plus a documented slow-owner overload policy; do not
silently drop events or enter an overload/reconnect storm. Do not claim a hard
bound on messages placed in that owner's mailbox by unrelated processes.

Distinguish transport consumption from complete application-message delivery.
SSE events and WebSocket frames may exceed one H2 window: return credit on safe
admission to a bounded parser/reassembly buffer, not only after an entire event or
frame is assembled. Otherwise large messages deadlock. Include retained binaries,
partially assembled messages and unused in-flight allowance in budget accounting.
Malformed/oversized input must not be made acceptable by raising all limits.

## 3. Public selection and compatibility contract

Add validated `http_version`, `http2_profile`, `http2_scope` and `http2_reuse` to both
client option pipelines, following existing flat-option conventions. Preserve
existing string-key aliases and all current constructor/message shapes.

Keep the default at HTTP/1 for this change. New H2 behavior is explicitly selected
or negotiated under `:auto`; no silent default migration.

| Option / route | Required behavior |
| --- | --- |
| `:http1` | Current HTTP/1 SSE or RFC 6455 Upgrade; advertise only compatible ALPN |
| `:http2` + HTTPS/WSS | Require negotiated h2; typed failure otherwise |
| `:h2c` + HTTP/WS | Prior-knowledge HTTP/2 only; no HTTP/1 Upgrade-to-h2c implementation |
| `:auto` + HTTPS/WSS | ALPN negotiation; H2 when usable, documented bounded HTTP/1 fallback |
| `:auto` + HTTP/WS | Preserve HTTP/1 behavior; do not silently send h2c prefaces |
| H2 with Unix sockets | Preserve the existing unsupported combination unless already supported at HEAD; reject before networking |

Reconcile explicit-profile strict negotiation with Fetch's existing semantics.
Do not silently ignore a profile or pretend HTTP/1 fallback preserved its H2 wire
identity. Reject contradictory options before dialing, including incompatible
caller ALPN configuration. Preserve both OTP `:ssl` and explicit `:ex_ssl`; never
switch TLS backend after an error.

Expose the actual negotiated HTTP version through an additive accessor/status and
telemetry field. Do not repurpose WebSocket's `protocol` field: that represents the
negotiated WebSocket subprotocol, not HTTP/1 versus HTTP/2.

Connection, admission, opening-handshake, application-idle and close-handshake
timeouts have distinct purposes. Established SSE/WS sessions must not inherit
Fetch's total request timeout. Default established idle duration may remain
`:infinity`; finite idle settings are explicit. Timeouts/cancellation while
connecting must remain responsive; no blocking connect in a client GenServer that
prevents `close` or owner-death cleanup.

## 4. Phase A: EventSource over HTTP/2

### 4.1 HTTP adapter and event semantics

Keep one transport-independent SSE parser. Feed it ordered response bytes from
the shared H2 stream API; never send H2 DATA bytes through `HTTP.HTTP1`. Force
incremental delivery from headers onward, regardless of Fetch buffering thresholds
or the presence/value of Content-Length. SSE has no special CONNECT handshake.

Use an ordinary GET, `Accept: text/event-stream`, the existing cache/header policy,
and the appropriate last-event cursor. The request direction may END_STREAM with
its initial HEADERS; the response remains open. Informational headers do not emit
Open; validate the final response before emitting exactly one Open per successful
connection attempt. Handle empty END_STREAM and trailers without feeding trailers
to the event parser. A normal EOF may schedule EventSource reconnection.

Preserve event types, multiline data, comments, line-ending/BOM behavior, UTF-8
chunk boundaries, retry hints and last-event cursor behavior. Add regression cases
for an empty ID reset and incomplete input at EOF. Keep protocol parsing separate
from application acknowledgements; document cursor/replay behavior and do not
promise exactly-once delivery. Reuse current invalid-UTF8 policy unless deliberately
fixing it with compatibility documentation; do not claim full browser conformance
for an intentional deviation.

Enforce not only `max_line_size` but also a finite total event/reassembly limit:
short `data:` lines without a dispatch delimiter cannot grow memory indefinitely.
Sanitize any cursor reused in a header against invalid header values. Preserve
204 as a permanent stop, validate the event-stream media type, and bound redirects.
Explicitly classify fatal response errors versus retryable transport errors.

Keep redirects and credentials secure: resolve relative targets, enforce a redirect
cap, reject disallowed schemes/downgrades, strip cross-origin authorization/cookies,
and apply the existing client-certificate policy without leaking client identity.
Do not expand `with_credentials` into an invented browser cookie/CORS subsystem.

### 4.2 Reconnection and shared connection behavior

Reconnect by opening a new logical stream, reusing an eligible connection when
possible. Preserve last-event ID and retry policy across transport attempts; do
not inherit parser fragments or stale DATA from an earlier attempt. Introduce
attempt tokens for timer and worker results; explicit close/owner death prevents
later reconnects. Reconnect delay/backoff must be bounded and cancellable.

GOAWAY stops new stream admission; it does not automatically close an existing
accepted SSE stream or lose queued events. When that stream actually ends or a
documented drain policy terminates it, SSE reconnects under its own policy on an
eligible/replacement owner. Stream errors must not unnecessarily kill Fetch/WS
siblings. Apply F2 promotion to queued reconnect attempts.

Count per-stream idle time using that stream's incoming body activity, including
SSE comment heartbeats. A connection PING or another stream's DATA is not SSE
activity. Local consumer backpressure is not proof of remote inactivity: define
and test how a configured idle policy distinguishes deliberate pausing.

## 5. Phase B: WebSocket over HTTP/2

### 5.1 Capability and wire contract

Implement RFC 8441, not an HTTP/1 Upgrade request inside H2 DATA. Model setting
0x8 (`ENABLE_CONNECT_PROTOCOL`), default 0; validate 0/1 and reject 1-to-0 reversal.
Only send Extended CONNECT after receiving peer value 1. Own advertisement is not
peer permission. Capability is per connection, not a permanent origin cache.

Open with `:method=CONNECT`, `:protocol=websocket`, `:scheme` (`https` for wss,
`http` for ws), `:authority`, and `:path`. Include lower-case version/subprotocol
and permitted ordinary headers. Do not send Connection, Upgrade or
Sec-WebSocket-Key, and do not require Sec-WebSocket-Accept. Apply successful
CONNECT 2xx semantics, normally 200—not the HTTP/1 101 validator. Validate selected
subprotocols and the currently supported extension policy. Keep masking, WebSocket
framing and close semantics from RFC 6455.

Treat those as separate handshake tests from the existing HTTP/1 validator.
Profile compilation/serialization must support the extra pseudo-header explicitly
without changing ordinary Fetch profile bytes or sorting headers twice. Do not
accept user-supplied pseudo-headers or profile settings that bypass capability
validation. No default advertising of setting 0x8 is needed simply because this
client wants to use server Extended CONNECT.

Wait for initial SETTINGS/capability within the opening deadline without blocking
the owner. Ordinary Fetch/SSE streams may still use an otherwise healthy owner.
For `:auto`, a peer that completes initial SETTINGS without permission may trigger
one separate HTTP/1 WebSocket connection; strict H2 returns a capability error.
A later legitimate enablement updates that owner's capability for future attempts.

Fallback is allowed only before establishment for explicit protocol/capability
unavailability. Never downgrade after certificate/hostname/authentication failures,
a malformed H2 response, rejected subprotocol/extension, or an ambiguous handshake
write. Do not retry an established session or replay messages automatically.
Release an unused reservation without closing an H2 connection serving siblings.
Record any fallback and the actual protocol so tests cannot pass by using HTTP/1.

### 5.2 Full-duplex stream integration

Reuse the existing WebSocket frame codec and public event API. Replace direct
socket access with the tunnel-stream adapter for H2. Treat DATA as arbitrary byte
chunks: one WS frame can span many DATA frames, and one DATA frame can contain
several WS frames. Do not bypass masking under TLS. Preserve fragmentation,
control frames, message limits and UTF-8 checks across all H2 boundary splits.

Do not mark initial CONNECT HEADERS END_STREAM. Do not send application data
before tunnel acceptance, even if an internal queue accepted it. On success,
client writes and peer reads stay usable for the session lifetime. Keep send
operations bounded and cancellable under zero stream/connection credit; make
`buffered_amount` reflect the documented pending application bytes rather than a
constant or an unbounded hidden queue. Preserve existing API error conventions.

WebSocket Ping/Pong/Close are WebSocket bytes carried by H2 DATA and still consume
DATA credit. HTTP/2 PING is different. Prioritize WS control frames within bounded
scheduling without violating byte order of a partially transmitted WS frame or
bypassing flow control. Bound close-handshake waiting when DATA cannot progress.

Implement and test the WS close exchange plus stream half-close/reset mapping.
An HTTP/2 END_STREAM alone must not manufacture a clean WebSocket close; missing
or truncated WS Close is abnormal. Never transmit code 1006. A peer reset or owner
death yields one terminal error/close sequence and releases reservations. Preserve
valid inbound bytes preceding the terminal event. Local close must not close a
shared socket, and later send/close calls must follow existing public semantics.

GOAWAY does not silently reconnect or replay an established WS session. Retain
accepted streams until completion or the documented finite drain policy, reject
new admission on the draining owner, and classify unprocessed opening streams
without misreporting an established connection.

## 6. Required tests and independent acceptance

Write deterministic regressions before or alongside implementation. Raw-wire
fixtures must use ordering barriers, not sleeps that assume the scheduler has
already completed cleanup. Preserve prior negative assertions and the original
Fetch F1/F2, flow, peer-close, HPACK and profile suites.

Minimum acceptance families:

| ID | Required evidence |
| --- | --- |
| A0 | Shared runtime works with each client installed alone; extraction keeps current Fetch tests and F1/F2 behavior green |
| A1 | SSE h2/h2c: fragmented UTF-8/BOM/CRLF, multiple/split events, comments, empty IDs, retry hints, MIME/status validation, 204, bounded redirects and credentials |
| A2 | SSE: Last-Event-ID on reconnect, zero stale events after close, owner death during connect/admission/open, reset/GOAWAY recovery, stream-specific idle behavior |
| A3 | SSE: an event larger than one H2 window succeeds within limits; many short lines without a delimiter hit the finite event bound; paused acknowledged consumer has measured limits |
| B1 | RFC 8441 capability absent/0/1/invalid/reversed/delayed; exact CONNECT headers; valid 2xx versus HTTP/1 101; strict error versus bounded auto fallback |
| B2 | WS: bidirectional text/binary after 2xx, large and fragmented frames across DATA, independent mask validation, subprotocol policy, Ping/Pong, Close/END_STREAM/reset and malformed/truncated input |
| B3 | WS: producer faster than network, receiver slower than peer, both windows zero, SETTINGS shrink/resume, close while blocked; bytes/queue/worker bounds and correct buffered_amount |
| C1 | Mixed Fetch + multiple SSE + multiple WS streams simultaneously on one independently observed h2 connection, with compatible keys/options |
| C2 | Closing/resetting/overloading one mixed stream leaves siblings live; a paused consumer does not starve eligible siblings or connection control traffic |
| C3 | Isolation for differing TLS/profile/scope; shared peer capacity, saturated-survivor replacement and cross-key waiter promotion still work |
| D1 | Each supported TLS backend and cleartext path; proof of actual negotiated protocol and no silent backend/protocol substitution |
| D2 | Clean individual and combined package consumers, complete dependency closure, metadata and supervision startup/shutdown |
| D3 | Final-source full tests, static checks, existing Fetch acceptance, new interoperability/churn/soak and accessible provenance |

Use two independently implemented HTTP/2 servers for SSE and mixed transfer tests,
preferably the existing pinned hyper-h2 and Node/nghttp2 peers. For WS, provide at
least one actual RFC 8441 end-to-end interoperability server with an independent
WebSocket codec, plus a separately implemented raw-wire capability/frame oracle.
A generic HTTP/1 WebSocket echo server does not qualify. Verify actual peer
capabilities/version support before choosing the fixture. Never substitute the
library's own H2/HPACK/WebSocket codecs as both sides of an acceptance test.

Run protocol-selection and positive-path gates over h2c and TLS with both `:ssl`
and `:ex_ssl`. Capture negotiated ALPN, received settings, stream IDs and sanitized
wire assertions. A skipped backend is NOT RUN, not PASS.

Proposed project acceptance workloads (explicit test targets, not performance
claims):

- At least 10,000 numbered SSE events with varying DATA splits and a forced
  reconnect; assert order/cursor handling under the controlled peer contract.
- At least 10,000 bidirectional WS messages, text/binary/control mixtures and a
  message larger than an H2 window but below the configured message limit.
- At least 1,000 controlled SSE reconnects and 1,000 WS open/close cycles with
  bounded peer stream limits; prove resources return to the expected baseline.
- At least one >=30-minute mixed run with long-lived SSE/WS streams while Fetch
  requests continue. Exercise slow consumers, controlled stream cancellation and
  connection draining in separate defined intervals. Keep true live-stream counts
  while sessions are active; require zero streams/reservations after final cleanup.
- Rerun the existing accepted Fetch 42-gate workload suite on the final executable
  candidate after shared-runtime changes. Adapt package paths/counts only where
  extraction requires it; do not reduce workload sizes or remove assertions.

Freeze finite budgets for owner/session heap, referenced binaries, event/message
queue bytes/counts, workers and active connections before running. Include all new
processes, not only ConnectionOwner. Log sampled maxima and distinguish them from
continuous peaks. A test proves boundedness by assertions, not merely absence of
OOM. Use larger thresholds only with a measured, explained architecture change.

## 7. Packaging, CI and operational contracts

Preserve independent installation of `http_fetch`, `http_event_source` and
`http_web_socket`. A new shared app must be included in every affected dependency,
package, test and external-consumer inventory—not only in a new test script.
Update version metadata checks, release dependency ordering/rewrites, formatter,
Dialyzer inputs and documented app lists consistently. Work at the current version
unless a version change is independently authorized. Test package construction;
do not publish as part of this task.

Run consumers with only the selected top-level client dependency, no umbrella code
path, no direct hidden Fetch dependency, and no explicit ex_ssl dependency merely
to make startup work. Include one mixed consumer. Verify metadata for the full
transitive shared-app closure and retain published-ex_ssl feature/provenance gates.
New code must not depend on developer tools at runtime.

Add new deterministic suites to normal CI. Provide an explicit slower acceptance
entrypoint for interop/churn/soak; gate failures propagate. Preserve raw command
outputs, seeds, peer versions, exact source tree and artifact checksums. Require an
explicit completed-workload marker and the requested elapsed duration for soak;
an interrupted command or a wrapper exit zero is insufficient. Runtime changes
after freezing invalidate the corresponding executable acceptance evidence.

Add privacy-safe telemetry for negotiated version, stream type, capability/fallback,
opening/reconnect/close outcomes, pool admission, queued bytes and flow stalls.
Do not export raw URLs/headers/payloads/TLS identities as unbounded metric labels.
Preserve existing telemetry event names or document compatible forwarding.

## 8. Execution order and deliverables

Use these dependency-ordered local change groups:

1. **P0 — Baseline and contracts.** Read guidance, inspect current paths, record
   tests, write the concise plan and requirement-to-test table.
2. **P1 — Shared runtime extraction.** Add the neutral shared app and stream API,
   migrate Fetch without behavioral changes, and prove standalone consumers and
   accepted F1/F2 regressions still pass.
3. **P2 — SSE adapter.** Implement options, long-lived H2 body delivery, reconnect,
   bounds and EventSource tests; pass independent SSE gates.
4. **P3 — Extended CONNECT core.** Add peer capability and explicit duplex state,
   profile/header handling and negative protocol tests while keeping Fetch/SSE
   behavior unchanged.
5. **P4 — WS adapter.** Implement handshake/duplex I/O/close, fallback and bounded
   delivery; pass an independent RFC 8441 peer and mixed-client tests.
6. **P5 — Final acceptance.** Freeze executable source; run full regression,
   packaging, interoperability, churn and soak; audit evidence and document scope.

Required documents:

- `docs/http2-stream-clients-plan.md`
- `docs/http2-stream-clients-validation.md`, with A0–D3 mapped to actual commands
  and outcomes, current candidate provenance, budgets and remaining blockers
- Updated relevant public API docs/READMEs and an accurate support matrix
- Sanitized, accessible evidence archive or CI artifacts, with a checksum manifest
  and reproducible runners; do not rely only on ephemeral `/tmp` paths

In final output, report changed apps/modules, the final dependency graph, supported
option combinations, public API usage, exact tests executed, actual peer/backend
matrix, package startup proof, mixed-connection proof and resource observations.
Separate implementation completeness, local acceptance, remote CI status and
production rollout. Do not use the previous Fetch-only acceptance to claim these
new clients passed tests that were never executed.

## 9. Scope and completion rules

Preserve user work and existing history/evidence. Use small reviewable changes and
conventional local commits where repository guidance permits; no push, merge,
remote workflow dispatch, package publication, release or deployment is authorized.

In scope: shared runtime extraction, required H2 capability/lifecycle extension,
SSE/WS integration, bounded delivery, targeted fixture stabilization, independent
peers, directly impacted package/CI inventories and docs. Out of scope: implementing
HTTP/3, WebTransport, generic proxy CONNECT, h2c Upgrade, TLS cryptography, a cookie
jar, new compression extensions or real-browser fingerprint equivalence. Preserve
existing behavior/tests in those areas without expanding them.

Do not disable reuse globally, add silent backend fallback, weaken F1/F2, remove
assertions, mark unsupported behavior successful, or manufacture green gates via
blanket rescue/retries. Report genuine tooling or out-of-scope failures precisely
and finish other safe in-scope work; never call an unrun test PASS.

Completion requires public EventSource and WebSocket APIs actually using HTTP/2,
correct distinct lifecycles, preserved HTTP/1 and Fetch behavior, independent and
mixed-client wire evidence, bounded resources, standalone package consumers, and
executed final-candidate gates. Do not stop after exposing option names or schemas.

## 10. Primary references

Read the relevant sections and current errata; use these as protocol authorities,
not third-party summaries.

- RFC 8441, WebSocket over HTTP/2: https://www.rfc-editor.org/rfc/rfc8441.html
- RFC 6455, framing/control/closing: https://www.rfc-editor.org/rfc/rfc6455.html
- RFC 9113, HTTP/2 streams/settings/flow/CONNECT/errors: https://www.rfc-editor.org/rfc/rfc9113.html
- WHATWG HTML, Server-sent events: https://html.spec.whatwg.org/multipage/server-sent-events.html
- Repository guidance at the planning baseline: https://github.com/gsmlg-dev/http_fetch/blob/b5d17bfe3a6be9fbb20a3f3c185dc36773b9f367/AGENTS.md
- Accepted Fetch validation and historical evidence: https://github.com/gsmlg-dev/http_fetch/blob/b5d17bfe3a6be9fbb20a3f3c185dc36773b9f367/docs/http2-production-validation.md

The architecture, delivery modes, phase order, workloads and acceptance thresholds
above are requirements for this implementation task. They are not claims that the
current repository already supplies EventSource/WebSocket HTTP/2 support.

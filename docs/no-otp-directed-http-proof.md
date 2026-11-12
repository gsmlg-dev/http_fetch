# Directed HTTP callable-origin review

This review covers HTTP-1–HTTP-9 and WT-1: 76 original occurrences across the
HTTP packages. The [binding](no-otp-directed-http-proof.json) records the exact
inputs and compiled inventory. It starts from Fetch, managed transport,
EventSource, WebSocket and WebTransport construction, rather than accepting
arbitrary internal state or framework callback arguments.

## HTTP-1: dialer and proxy upgrade

`HTTP.TLSBackend.resolve/1` accepts only ExSSL, including its default application
configuration. `:ssl` and unknown values fail configuration; `transport/1`
returns only `HTTP.Transport.ExSSL`. `Dialer.select_transport/2` chooses that
module for TLS origins or HTTPS proxies, TCP for plaintext, and Unix for a Unix
route. The Unix/TLS combination is rejected. Caller socket options select socket
data and address policy, not a transport module.

Fetch and `Runtime.Stream` obtain their module from this selector. The dial
worker captures it, and socket transfer, abort, timeout and failed publication
reuse that capture. A worker's result contains a socket or error, not a new
module. `Proxy.prepare_tunnel_upgrade/4` selects the owned prepared ExSSL path
for ExSSL. Its legacy tuple retains the same input module; the only supported
TLS selector is ExSSL, so a supported request cannot use that tuple to introduce
another TLS provider. Nested HTTPS proxy handling also uses literal ExSSL.
The three built-in transport bodies use `:gen_tcp`/`:inet`, ExSSL, or local Unix
sockets; none selects OTP SSL.

## HTTP-2: lifecycle worker callbacks

There are nine production callsites for the three lifecycle invocation sinks:

- `HTTP.fetch/2` supplies `launch/2` a closure starting its supervised request
  task. The task performs managed admission and invokes the socket client.
- EventSource and WebSocket each supply a dial closure; WebSocket additionally
  supplies a bounded write closure retaining its selected transport.
- `Runtime.Stream.start/3` supplies `run/5` and a rejection closure that only
  sends a typed opening failure to the subscriber.
- HTTP3 Stream supplies its relay, connector and connector-watchdog closures.
- HTTP3 ConnectionOwner supplies its watchdog closure.

`start_worker/5` retains these functions in its inert worker closure.
`run_worker/7` invokes the original worker body only after admission;
`reject_worker/2` invokes the original rejection function or does nothing.
Admission messages carry a launch reference or failure data, not functions.
Worker results do not update either callable. The nested connector callback is
addressed separately in H3-4; the captured transport writes are covered here and
in HTTP-3/HTTP-9. There is no public lifecycle worker-function option.

## HTTP-3 and HTTP-9: EventSource and WebSocket connections

Both public constructors normalize dedicated option structures before starting
their connection process. Their HTTP1 selectors choose TCP, Unix, or the
validated ExSSL backend. Each dial worker closes over the connection's attempt
state. EventSource's `open_transport/1` returns the chosen module with its
socket. WebSocket sends the chosen module and socket after validating the
upgrade and before transferring ownership.

Current-attempt replies match both generation and worker PID before storing
the module. Library-created stale replies carry the same selected module and
close their own socket. They cannot introduce another module. The guarantee
does not include fabricated private `http1_connected`/`http1_ready` messages.
Both connection implementations have one non-nil transport assignment, from
these worker replies. Reconnect creates another normalized attempt; rearm,
message normalization, queued writes, backpressure, deferred EOF, abort and
detachment retain that selection or clear it to `nil`. A backend error does
not become connection state. HTTP2 and HTTP3 streams use the fixed library
stream modules instead of assigning a module supplied by a stream event.

## HTTP-4: Fetch socket state and idle writes

Fetch builds a fresh `HTTP.Request` from `FetchOptions.to_transport_options/1`.
That projection has no transport-module, protocol-module or arbitrary state
option. `SocketClient` obtains its transport from HTTP-1 or an HTTP1 pool entry.
`initialize_protocol/4` selects only `HTTP.HTTP1` or `HTTP.HTTP2` from the
connected protocol. `serialize_request/2` returns those literal modules.
`initialize_legacy_owner/4` installs both selectors explicitly after merging the
request context, so caller context cannot override them.

The HTTP1/HTTP2 codecs return protocol state and typed events, not the outer
socket state. `handle_data/2`, `handle_closed/1`, event reducers and buffered or
streamed response handlers update protocol, response, timers, upload and writer
fields while retaining both selectors. The H1 upload worker receives the
selected transport explicitly; its completion contains only success/error.
Failed writes, upload abandonment and cleanup use the retained transport.
Caught exits become errors or cleanup evidence, never replacement socket state.

`IdleTimeout.send/4` is called only by SocketClient and HTTP1.Upload. Both pass
the module above. Recursive vector writes retain it; the special ExSSL clause
uses its public bounded send, while TCP/Unix use their bounded socket options.
The helper's exported module parameter is an internal seam, not a public
transport extension.

## HTTP-5: Promise callbacks

`Promise.then/2,3` retains the caller's success and optional error function in
its supervised task. `apply_callback/2` checks the actual arity before invoking
it. The callback result is interpreted only as a Promise, an outcome tuple or
ordinary result data; a returned function is not invoked again.

All apparent calls in `HTTP` and `HTTP.Promise` are documentation examples.
There are no production library-created `then` callbacks. A caller may pass a
compatible public library capture, such as `HTTP.Response.json/1`; that body
remains ordinary audited library code. Calling back into another supported
public operation follows that operation's normalized entry again. This does
not make arbitrary internal state constructors approved callable roots.

## HTTP-6: H1 pool entry retention

SocketClient's `finish_completed/1` is the only production checkin caller. It
passes its retained transport after the response is complete and reuse is
eligible. `prepare_entry/7` stores that exact argument as `entry.transport`.
Activation, provider transfer, leasing, expiry, discard and retirement update
entry status, owner, provider evidence and deadlines; none replaces transport.
Checkout returns that retained module to SocketClient. Token-qualified control
messages and genuine stale entries preserve the original producer.

The ordinary application pool and managed scope's private pool use the same
entry constructor. The managed scope injects only its own pool PID and selected
policy. Fabricated prepare messages or manually constructed entries are not
supported public input. A callable-looking value in response data cannot reach
this field.

## HTTP-7 and HTTP-8: H2 owner and factory

The complete production owner-creation census is SocketClient,
`Runtime.Stream`, and `ProtocolClient.Session`. The first two pass the selected
transport explicitly through `ConnectionSupervisor.start_connection`; the
supervisor forwards the same options. ProtocolClient passes literal TCP.
`ConnectionOwner.init/1` stores the module once. All normal, initialization,
activation, socket-error, peer-frame and shutdown paths retain it. Module maps
accepted by its internal test seam do not originate in supported clients.

`HTTP.Runtime` starts its H2 pool with only a name. ManagedTransport.Scope
starts its private H2 pool with explicit capacity and idle limits. Neither
passes `:owner_factory`; `Pool.init/1` consequently stores `nil`.
Fetch/EventSource/WebSocket option projections do not expose owner factories or
arbitrary pool PIDs. The only production pool override is the managed scope's
own pool. No later pool state update assigns `owner_factory`. Thus the custom
factory invocation is unreachable from supported client construction. Direct
custom initialization of this internal pool remains outside the approved API
guarantee, rather than being mislabeled an external callback exemption.

## WT-1: WebTransport backend

`HTTP.WebTransport.new/2` normalizes Options and starts Session with that
structure. The approved `:backend` extension is retained separately as
`state.backend`. Connect responses contain session references and selected
metadata; `connect_success/4` copies explicit metadata fields, not a backend.
All stream, datagram, statistics and close operations use the retained module.
Queue updates and callback messages never replace it.

The sole library backend is `HTTP.WebTransport.Transport.QUIC`. Its connect
returns the existing unsupported-capability error, close returns `:ok`, and its
remaining methods return that error or empty statistics. It neither starts a
TLS connection nor enables WebTransport. User backend bodies remain outside the
no-OTP guarantee. Every library implementation remains included.

## Evidence and remaining acceptance

The binding matches the 244-file production-source census and selected inputs
to CI artifact `13119243608` at `524edb2`. Constructor arguments, field retention
and actual built-in bodies supply the proof; hashes only bind it to a revision.
The 76 original compiled findings remain visible until directed gate validation.
The independent 70-case traffic result does not substitute for these derivations.
P6 and publication still require all package proofs and release regressions.

## 2026-11-05 source review amendment: managed admission retry

This amendment reviews the runtime source at commit
`7b2c7c1153b884ade1b7adb027c7387f234422d5` against the previously pinned inputs.
The complete 244-file production-source census has one changed file:
`apps/http_runtime/lib/http/managed_transport.ex`, from SHA-256
`74b17c5450acd6834647b3fc305c0246120dae8bbbdd495de92a6f71f1d8d95f` to
`d3b3eeb9fea115aaeab8cd6ec4780665164ccabee79ba437c44973852119af16`.
The other 243 files match. All 175 original occurrence dictionaries across the
five package proofs remain byte-for-byte unchanged; this module has none.

The `claim/1` delta names the existing free-row tuple and retries its exact
compare-and-swap after the initial claim and completed-row reclamation fail.
Both claim attempts call the existing local `replace_claim/3`, whose only
operation is literal `:ets.select_replace/2`. The replacement still contains
only the slot ID, fresh reference, caller PID, `:preparing` and `nil`. No module
or function value is introduced, invoked or copied into a producer field.

`open/1` still freezes policy through `Policy.freeze/1`; `prepare/2` still
merges that policy and the scope-owned pool/coordinator injection after claiming
a lease. The policy's ExSSL-only TLS validation, the TCP/Unix/ExSSL dialer
selection, private pool construction, transport retention and callback producers
reviewed above are unchanged. The retry therefore adds no dynamic module or
function dispatch and no route to OTP SSL from supported construction.

The binding's `source_inputs_sha256` and release source manifest now identify
these current reviewed inputs. Its original `source_commit`, `artifact`,
`production_source_census`, `occurrences` and `checks` retain their historical
meaning: artifact `13119243608` does not cover the amended source. No new generic
dispatch findings are expected from this delta. Compiled source/BEAM binding,
the exact 175-finding reconciliation and release acceptance remain pending the
new candidate's compiled no-OTP release gate.

## 2026-11-05 source review amendment: RC2 static checks

Production commit `5050bfcfd82c7a650d7d87113d30ca8360d91edf` changes three reviewed
HTTP inputs. Proxy's single-clause `with` becomes a `case` with the same timeout
mapping and result; origin failure cleanup retains its literal ExSSL close and
primary error. Its legacy upgrade's retained transport is unchanged (HTTP-1).

The H2 acknowledgment helper moves the same byte acknowledgment, queue update,
less-than-64 flush, response flush, error notification and terminal reply. It
does not assign transport or callable fields (HTTP-7). EventSource now uses
`Enum.each/2` for the same reversed acknowledgment references and returns the
same state. Its stream selector still returns only the fixed H2/H3 stream modules,
and its dial/reconnect transport producers are unchanged (HTTP-3).

Fresh BEAM abstract forms preserve all 20 original occurrences in these modules.
The Proxy call and ten H2 calls move lines; every owning MFA is unchanged. The
EventSource acknowledgment change adds no raw unresolved occurrence, and its
nine original occurrence dictionaries remain unchanged. The JSON amendment lists
the 11 exact old-to-new line bindings. All 175 original inventory IDs remain in
one-to-one correspondence with the fresh raw audit; no finding is exempted.

Historical artifacts, checks, source commits, census and BEAM hashes are retained.
The current selected inputs and full 244-file census are recorded separately.
Collection's 35 TLS1.3 scenarios passed while its raw static failure stayed
visible; strict candidate and published gates must bind the current BEAMs.
The source-pinned transport and buffered-close tests retain their driver/option
and plaintext-buffer assertions with the newly reviewed `SSL.Connection` hash.

## 2026-11-06 source review amendment: finite waits and WebSocket controls

This amendment reviews production commit `27e5fe617d31b0eaa8dd4e36487c89e1b0258ab2`
against RC2 (`df99a0325a8c7769a9abc4a336359beb8d5e4e9d`). Seven of the 244 production
library files change; the other 237 match. The JSON amendment records every
old/new source digest, adds the four newly selected WebSocket codec/event/API
inputs, and preserves the historical artifact, checks, source commit and BEAM
hashes. Those historical results do not certify these amended sources.

`Promise.await/2` now invokes literal `Task.yield/2` and returns the task's data,
a timeout tuple, or the existing task-exit shape. It acquires no callable field
and does not invoke a returned value. `then/2,3`, retained success/error callbacks
and the arity-checked `apply_callback/2` sink keep the HTTP-5 derivation above.

WebSocket construction still normalizes Options before starting Connection.
Address normalization retains the first keyword value, consistently with the
constructed Options structure. Its projection forwards only the literal address
plus manual redirect policy beyond the existing transport option whitelist.
`Options.new/3` validates the IPv4/IPv6 tuple, unsupported routes and TLS identity
through the existing `Dialer.select_transport/2` before
constructing the retained structure. HTTP1's finite selector still chooses TCP,
Unix, or the validated ExSSL backend; HTTP2 retains the runtime dialer and
address-qualified pool key. A pin changes a dial address, never the selected
module, Host/authority or certificate identity. Built-in address/TLS transport
bodies remain those reviewed in HTTP-1.

The dial worker retains that selected module through request writes, handshake
reads, ownership transfer and failed-upgrade cleanup. Generation/worker-qualified
metadata messages assign only `state.handshake`; they never assign transport or
a callback. `response_metadata/2` uses literal Headers/Enum/binary operations over
two fixed names, copies at most one 1024-byte value per name, and returns only a
status, header data and truncation flag. Open/Error add that map as data. Neither
response values nor the new frame/read/message limits become callable origins.

The frame parser's new positive-integer bound is checked against declared
payload lengths before awaiting payload. Read admission compares integer raw
and parser-buffer sizes before copying input. Error, ACK-credit settlement,
queue clearing, protocol Close and completion paths retain the existing selected
transport or clear it to nil. The sole non-nil transport assignment still comes
from the current dial worker's qualified `http1_ready` reply. The existing send
worker capture, rearm, deferred EOF, abort and detachment therefore retain HTTP-9.

A diagnostic snapshot copied current production BEAMs into an owned clone of the
prior release runtime, excluding test-support modules by their compiled source
paths. The unchanged generic auditor and consumer origin requests inspected
350 BEAMs, found no direct OTP SSL imports or missing abstract code, and retained
all 175 raw findings. Raw abstract forms reconcile every original inventory ID
one-to-one with its exact MFA, line and kind. Eight line bindings move: Promise
ID 106 and WebSocket IDs 152-158; no owning MFA or finding is added or removed.
This inventory check does not certify a rebuilt candidate or publication. The
strict candidate and published gates must bind the current packaged source and
BEAM bytes independently; no generic finding is hidden by this amendment.

## 2026-11-08 source review amendment: pool extraction and explicit adapters

The Phase 1 candidate declares `1.0.0-rc.9`, based on `main` at `266eb9a`.
Current source hashes bind this amendment; previous commits, artifacts, BEAM
hashes and failed diagnostics above remain historical evidence.

H1 pool transport authority (HTTP-6) moves unchanged to `http_pool`. Its entry
constructor still stores the admitted TCP, Unix or ExSSL transport. Policy limits
and aggregate snapshots add no transport selector. H2 owner factories (HTTP-8)
remain monitored asynchronous connectors. Default, named and managed families
leave `owner_factory` nil; public family configuration rejects factory/provider
injection and unknown options. Protocol owners remain in runtime.

One new H2 callable site invokes the explicit `activate_owner` function. The
production registration callers are SocketClient and Runtime.Stream; both provide
`&ConnectionOwner.activate/2`. The request actor invokes it after provider
acceptance/release and before pool publication, retaining the original absolute
deadline and retirement on failure. The Pool GenServer never synchronously calls
the waiting actor or starts dialing. The callback cannot replace the connection's
transport. Existing H1/H2 identity hashing, provider authority and cleanup evidence
are preserved. The extracted pool telemetry emitter uses literal `:telemetry`
with the established event and opt-outs.

Named family policy accepts bounded capacities, names and existing opaque pool
references. Runtime captures actual family process identities in the caller.
The same binding reaches H1 checkout/checkin and H2 reservation/registration;
stale processes or a subsequently non-reusable identity fail closed. Registry
names do not create atoms from external strings. These operations neither select
a TLS implementation nor introduce an unpooled fallback.

### HTTP-10: explicit adapter callbacks

`HTTP.Adapter.prepare/2` has one variable-module `prepare/2` call and
`execute/3` has one variable-module `execute/3` call. The module originates only
from the caller's explicit `adapter: Module` or `{Module, configuration}` option.
The helper checks the two exported callbacks and applies the existing H1
envelope validation without reading a stream or dialing. File-backed multipart
parts use empty validation placeholders; the original request reaches the adapter
unchanged and no file is opened during preparation. The returned context is
stored with that original module; a callback result cannot replace the module.
Execution runs in the existing Promise worker with that captured tuple.

These two sites are approved caller extension boundaries, like caller-provided
Promise callbacks and WebTransport backends. Arbitrary external adapter bodies
are outside the built-in no-OTP guarantee. Every library implementation remains
audited. The default nil selection invokes SocketClient directly. The only
library test adapter belongs to `http_test`, which is absent from the production
Fetch and no-OTP package closures; Plug and ExUnit are absent as well. Missing or
invalid adapters fail without network fallback. A test adapter branches before
ManagedTransport admission, pool checkout, DNS, TCP and TLS.

The source binding adds the three reviewed sites and rebinds moved pool and
SocketClient lines by unchanged call expression and owning MFA. The local
production-BEAM diagnostic finds all 180 reviewed identities. It also retains
nine previously documented host-context findings in ResourceLedger/managed
resource collectors; that diagnostic is not a strict isolated-release pass.
Candidate and published release gates must independently reconcile the complete
raw inventory, source census and actual in-release BEAMs. No finding is removed
from the generic audit and no pending/unconfirmed cleanup becomes success.

The lock adds optional Test-only Plug and plug_crypto pins. The production
consumer gate resolves Fetch without Test/Plug/ExUnit and executes named H1 reuse;
separate candidate Test consumers compile and run with and without Plug. These
checks do not replace the strict no-OTP release or real protocol acceptance.

## 2026-11-10 source review amendment: rc.11 Alt-Svc, H3 options and live WebTransport

This amendment reviews the production sources at `4ae97fc` against the census
bound at `1a1f81d`. Thirteen selected HTTP inputs change. The census is now 267
files.

### WT-1: retained backend and the live library backend

`Session.init/1` is still the only assignment of `backend`, taken from the
normalized `Options` (literal default `HTTP.WebTransport.Transport.QUIC`). New
sites call that retained module: `migrate/3` (ID 202), `handle_message/2`
(203) and `acknowledge/2` (204), each after a `function_exported?/3` check.
`backend_or_invalid_state/2` (205) and `finish_send/3` (206) invoke only the
closures built in `handle_call/3` around the same retained backend. Backend close
moved from `close_session/2` to `cleanup_backend/2` (ID 159). The send-close and
abort calls moved into `finish_send/3` closures (IDs 163 and 164). Callback
results and owner messages are data. They never replace the backend.

The sole library backend is no longer an unsupported stub. `connect/2` creates a
`Quic.Cleanup.new/1` scope and starts an exclusive HTTP3 `ConnectionOwner`. It
passes caller `ssl` keywords that `SSL.QUIC.Config` validates, plus literal
WebTransport session limits. Its stream, datagram, migration and close bodies
make literal `ConnectionOwner` and `Quic.Cleanup` calls. Those paths are covered
by H3-1, H3-2 and Q1. External backend bodies remain outside the guarantee.

### HTTP-1, HTTP-4 and HTTP-9

Fetch's opt-in Alt-Svc keeps `tls_backend` nil only until a TCP fallback pins it
through `TLSBackend.resolve/1`, which accepts only ExSSL. HTTP/3 requests lift
an `ex_ssl` reference identity into flat QUIC `ssl` data. SocketClient's
transport and protocol selectors and its literal H3 handler are unchanged.
WebSocket over HTTP/3 leaves `tls_backend` unresolved; `Runtime.Options`
rejects an explicit backend for HTTP/3, and the HTTP1 selector maps only
`:ex_ssl`. The nine RequestLifecycle worker producers (HTTP-2) are unchanged.

The 12 SocketClient and seven WebSocket occurrences keep their expressions and
owning functions; their new lines are recorded in the JSON. The HTTP review now
has 84 occurrences. The complete compiled inventory of a locally built isolated
candidate release matches the five reviews exactly at 206 sites. CI strict
candidate and published gates remain required.

### Follow-up: graceful HTTP/3 connection close (2026-11-10)

`apps/http_runtime/lib/http/http3/connection_owner.ex` and
`apps/http_web_socket/lib/http/web_socket/connection.ex` changed after the
rc.11 renewal (`4c1bf8f`). The owner closes an orderly-stopped connection with
H3_NO_ERROR before retiring its cleanup lease. `HTTP.WebSocket.Connection.finish/4`
retires a cleanly closed HTTP/3 attempt with the literal
`RequestLifecycle.retire_owner/1` before `detach/1` instead of aborting it. The
new `orderly_retire/2` sits after every reviewed occurrence, so the seven HTTP-9
WebSocket occurrences keep their lines and functions; no occurrence is added or
rebound. The producer hashes, the release census entries and every group's
rc.11 census digest are updated.

### Follow-up: capability reporting (2026-11-10)

`capabilities/0` values and `migrate/2` documentation changed after the
CI-confirmed M2, reliable-reset, R1 and R2 matrices (`b2239e7`, `b1276f9`,
`f70e874`) and the `QuicHttp3` extension flags. These are literal map values and
documentation only: no dynamic dispatch is added or moved, and no reviewed
occurrence is rebound. Producer hashes, the release census and every group's
rc.11 census digest are updated.

### Follow-up: final review fixes (2026-11-10)

`HTTP.HTTP3.ConnectionOwner` (`51fd8fe`) marks itself `:retiring` when its
watchdog, attempt tracker or creator goes DOWN, so `terminate/2` no longer runs
a graceful close on the already retired connection, and sends H3_NO_ERROR only
when no request remains. The change is a lifecycle field update and a guard; the
file holds no reviewed occurrence, so no occurrence is added or rebound. The
producer hashes, the release census entry and every group's rc.11 census digest
are updated (the census also covers the `Quic.IO.GenUDP` link fix, `d460225`).

An extended CONNECT whose response stream has finished (`512fd3c`) no longer
counts as a live request, so a WebTransport session closed by a compliant peer
still ends with H3_NO_ERROR; this adds only a request field and literal calls.

### Follow-up: rc.12 review fixes (2026-11-11)

`HTTP.Promise.then/3` (`abcc548`) no longer starts a supervised task per
callback. It accepts only a 1-arity success function and `nil` or a 1-arity
error function, and appends them to the returned promise's `callbacks` list.
`HTTP.fetch/2` builds the only production promise, with no callbacks, and
`then/3` is the only writer. `await/2` settles the request and then runs the
retained callbacks in the awaiting caller's process under one deadline.
`run_callbacks/3` calls `error_fun.(reason)` only when `is_function(error_fun, 1)`
and calls `success_fun.(value)` otherwise. A callback result is only settled as
a promise or passed on as data; a returned function is never invoked. HTTP-5's
origin is unchanged: caller-supplied public-API callbacks. The sink changes
shape:

- occurrence 106 (`unresolved_apply` in `apply_callback/2`, line 135) is rebound
  to `success_fun.(value)` (`unresolved_fun_invocation`, `run_callbacks/3`, line
  161). The rebinding records `previous_kind`, `previous_mfa` and
  `previous_line`.
- the `error_fun.(reason)` call is the new occurrence 207 (line 159).

SocketClient (`0186b4e`) passes `max_decoded_body_size` to every response stream
and to buffered decoding. These are literal calls. The 12 HTTP-4 sites keep
their expressions, retained selectors and owning functions, and move 2 or 15
lines; their current lines are recorded in the amendment rebindings and the
follow-up entry. The `request_deadline/1` change (`7e83803`) does not move any
line. FetchOptions validates `timeout`/`connect_timeout` and accepts
`max_decoded_body_size`. The WebSocket handshake parses its header lines with
`HTTP.HTTP1.parse_header_lines/1`. The HTTP/3 ConnectionOwner computes its
opening deadline through `HTTP.HTTP3.opening_timeout/1`. The `HTTP` changes are
documentation only. All of these use only literal calls.

The HTTP review now has 85 occurrences. The complete compiled inventory of a
locally built isolated candidate release matches the five reviews exactly at 207
sites. The release census also covers the hardened HTTP/1 field parser
(`198148f`, `baa438c`), the multipart header escaping (`4d02164`) and the
decoded-body bound in `HTTP.ContentDecoder`, `HTTP.Config` and `HTTP.Stream`
(`0186b4e`). None of those files is a reviewed input, and the compiled
inventory shows that none adds a dispatch site.

### Follow-up: rc.13 review fixes (2026-11-11)

Occurrence 166 (WT-1, `state.backend.get_stats/1` in `handle_call/3`) is
removed: `HTTP.WebTransport.Session` (`89107e7`) now answers `:get_stats` from
the counters it keeps at its API boundary and never calls the backend. The
amendment records the site under `removed_occurrences` with its `previous_line`
so the history rewind restores it. The other thirteen WT-1 sites keep their
expressions and the retained `state.backend` selector; twelve move by 4 to 41
lines. The backend closes a pending connect through `interruptible/1`, which
spawns a monitored helper around a literal closure; its `fun.()` runs only the
closures built at three literal call sites and the compiled inventory reports no
site in that module.

The twelve HTTP-4 `HTTP.SocketClient` sites move by 66 or 68 lines (HTTP/1
redirect parity `e95bb5c` and HTTP/2 replay `cff6e9a`), the nine HTTP-3
`HTTP.EventSource.Connection` sites move by 1 to 34 lines (`e03c828`) and the
seven HTTP-9 `HTTP.WebSocket.Connection` sites move by 7 or 12 lines
(`c08c93f`). All keep their expressions, retained selectors and owning functions
and are rebound in the amendment and the follow-up entries. The `HTTP` module
documents the redirect limit; the WebSocket handshake brackets IPv6 Host
literals; the WebTransport options reject pooling and socket options. These add
only literal calls. The HTTP review now has 84 occurrences. The complete compiled
inventory of a locally built isolated candidate release matches the five reviews
exactly at 207 sites.

### Follow-up: rc.14 production changes (2026-11-11)

The production changes after `v1.0.0-rc.13` (`5b1adbd`, reviewed at `722a99a`)
change twenty selected HTTP inputs and delete a twenty-first. `HTTP.TLSBackend`
is removed with the `tls_backend` option and its `:http_core` configuration
(`c7fada8`). Its `resolve/1` accepted only `:ex_ssl` and its `transport/1`
returned only `HTTP.Transport.ExSSL`. The four former `transport/1` calls are now
the literal `HTTP.Transport.ExSSL`: two in `Dialer.select_transport/2` and one
each in `select_transport/1` for EventSource and WebSocket. The HTTP-1, HTTP-3,
HTTP-4 and HTTP-9 TLS selectors therefore name a literal module instead of
calling a resolver with one value. The deleted file leaves the selected inputs
and the census. It is recorded under `removed_selected_inputs`. The census stays
at 267 files because `HTTP.ResponseError` is added. That file holds only literal
code and is not a selected input.

No dynamic dispatch is added or removed. These sites keep their expressions,
retained selectors and owning functions, and move:

- 12 HTTP-4 `HTTP.SocketClient` sites by 5, 6 or 10 lines;
- 12 HTTP-6 `HTTP.HTTP1.Pool` sites by 1 line;
- 9 HTTP-3 `HTTP.EventSource.Connection` sites by 2 or 5 lines;
- 5 HTTP-9 `HTTP.WebSocket.Connection` sites by 3 lines;
- the 2 HTTP-5 `HTTP.Promise` invocations (106, 207) by 3 lines.

The rc.11 amendment did not rebind the HTTP-6 pool sites, so they are added to
its `occurrence_rebindings` with their rc.11 lines as `previous_line`. The
history rewind still restores them. The Dialer sites (145–151) and WebSocket
sites 155–156 keep their lines.

The other changes add only literal calls, guards and key lists:

- strict options: Fetch, EventSource, WebSocket, WebTransport, ProtocolClient and
  `Runtime.Pool` raise `ArgumentError` for unknown or invalid options (`bcbc0e9`,
  `f261a03`);
- Fetch reports deadline expiry as `:timeout` (`c7a3c19`) and `Promise.await/2`
  reports its own wait expiry as `:await_timeout` (`8f35305`);
- the `:legacy` delivery mode is renamed `:push` (`c222551`);
- EventSource origins use WHATWG serialization (`914d2b6`);
- the remaining edits are documentation.

The HTTP/1 pool now uses provider checkout whenever a request lifecycle is
current. The managed scope uses `:birth` for every https origin. Neither change
selects a transport module. `options.backend` is still the only WT-1 backend
producer. The HTTP review still has 84 occurrences. The compiled inventory of a
locally built isolated candidate release matches the five reviews exactly at
207 sites.

### Follow-up: rc.14 retry policy and ex_ssl server fixes (2026-11-12)

The opt-in retry policy (`5eae73d`) adds `HTTP.Retry` as a selected input. It
also changes `HTTP`, `FetchOptions` and `SocketClient`. The new module adds two
dynamic invocations under the new proof HTTP-11:

- `fun.(request, result)` in `retry?/3` (ID 209, line 133);
- `fun.(attempt)` in `configured_delay/2` (ID 210, line 165).

`HTTP.Retry.normalize/3` is the only constructor of `%HTTP.Retry{}`. It stores a
function only when the caller's `retry:` value passes `is_function(fun, 2)` or
the caller's `retry_delay:` value passes `is_function(fun, 1)`. Any other value
is a built-in mode, `nil`, a non-negative integer or an `ArgumentError`.
`FetchOptions` validates both through `normalize/3`, and `retry_policy/1`
rebuilds the policy through it again. `HTTP.fetch/2` hands that policy to its
task; `handle_async_request/6` and `run_attempts/3` pass it unchanged to
`HTTP.Retry.decide/5`, which only reads it.

`retry?/3` calls the function only in its arity-guarded clause and only after
the hard rules. Those rules cover `max_retries`, no streamed or half-duplex
body, and no `:aborted` or `:timeout`. `configured_delay/2` calls it only after
the `nil` and integer clauses. Both results are checked data: a non-boolean
decision or an invalid delay raises `ArgumentError`. The delay is still bounded
by the request deadline. No library caller supplies either function. They are
caller-supplied public-API callbacks, the same approved boundary as the HTTP-5
Promise callbacks. `HTTP.Retry` is `@moduledoc false`, and a manually built
policy is not supported input.

`run_attempt/2` calls the literal `HTTP.SocketClient.request/3` and
`HTTP.Adapter.execute/3`. The SocketClient attempt-owner bookkeeping moves the
twelve HTTP-4 sites by 10 lines with unchanged expressions and selectors. They
are rebound in the amendment and the follow-up entry. The census is now 268
files. The HTTP review now has 86 occurrences. The compiled inventory of a
locally built isolated candidate release matches the five reviews exactly at 209
sites.

### Follow-up: rc.15 ex_ssl client recv and trust-store fixes (2026-11-12)

No HTTP input changes. Only the census digest is updated; the ex_ssl changes
add, remove or move no reviewed occurrence, and the total stays 209.

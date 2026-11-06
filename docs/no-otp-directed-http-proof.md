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

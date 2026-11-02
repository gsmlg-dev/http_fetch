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

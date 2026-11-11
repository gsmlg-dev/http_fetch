# Directed HTTP3 callable-origin review

This review covers H3-1–H3-5, the 50 original occurrences in the companion,
Core and Runtime packages. The [binding](no-otp-directed-h3-proof.json) records
the source inputs and compiled inventory. The user approved preserving `:ops`
under the existing user-module callback boundary on 2026-11-02. The default
`Quic` and every library implementation remain audited; an external callback
body is not certified free of OTP SSL. Runtime behavior is unchanged.

## H3-1: Session transport

`QuicHttp3.Session.new/1` reads the approved `:transport` option with literal
default `QuicHttp3.Transport.Quic`. Its validated constructor sets that field
once. Ready, resume, cleanup and all operation wrappers use the retained field.
Operation replies update connection, requests, pending work and continuations,
not the transport selector. `Continuation` retains operation state separately;
resuming it does not supply a new transport module. No library caller supplies
a different transport.

The HTTP3 owner constructs Session with normalized budgets, timeouts and
optional native cleanup. It does not derive a transport from peer frames or
responses. Native cleanup is accepted only with Transport.Quic. External
transport callbacks retain the approved extension boundary; their opaque
connection and stream results do not modify Session's selector.

## H3-2: native transport operations and shared endpoints

`Transport.Quic.client/1` and `connect/3` remove `:ops` from the caller options,
using literal `Quic` when absent. This is the newly approved module callback
origin. No library producer supplies an alternative `:ops` implementation.
The authenticated public-API probe demonstrated the option actually reaches
`ops.client/1`; it was not assumed to be unreachable or test-only.

`client/1` stores the chosen module in its Endpoint descriptor. An owned
`connect/3` calls that module's client and connect functions, then stores the
same module in the connection descriptor. Borrowing a shared endpoint requires
the descriptor's `ops` to equal the selected `ops`, together with matching host,
TLS, profile and stream policy. A raw/unverified endpoint is rejected. Thus a
shared endpoint cannot silently substitute a different implementation.

The connection's open-stream result and normalized operation results construct
Stream descriptors with the connection's retained `ops`. Event normalization
does the same for authenticated stream handles bound to that connection;
stale stream handles fail. Attach, ready, info, event/read, reset/stop, close and
operation-status reconciliation all retain the connection or stream selector.
Neither a module's result nor peer event data is interpreted as a replacement
`ops` value.

Owned-endpoint cleanup calls `ops.stop_endpoint/1` only if exported; otherwise
it stops the endpoint process directly. The built-in `Quic` operations route
to the endpoint and connection implementations reviewed in
[Q1–Q4](no-otp-directed-quic-proof.md), or inspect public capability data.
No built-in target uses OTP SSL. Tracked native cleanup still rejects
`ops != Quic` and borrowed endpoints; preserving the extension does not widen
the cleanup contract or claim external-module cleanup evidence.

## H3-3: internal raw QUIC wrappers

`HTTP.QUIC.ExQuic` has no incoming library caller or module producer in the
complete production-source census. It is an internal raw-stream/test boundary,
not the public Fetch H3 implementation. Each default-argument wrapper supplies
literal `Quic` to its implementation; an explicit driver argument exists only
at the internal seam. Direct arbitrary arguments at internal entries are
outside the approved guarantee.

This establishes two separate facts: no supported production entry reaches an
injected driver here, and the default wrapper bodies call the same audited
Quic API as H3-2. It does not infer safety merely from an empty caller list or
grant every exported raw wrapper an external callback exemption.

## H3-4: cleanup connector callback

`HTTP.HTTP3.Stream.cleanup_descriptor/3` accepts a `:quic_cleanup` function only from
its internal connection options and only for an exclusive connection. It
retains the arity-one function through `callback_descriptor/4` and the inert
connector worker; `connector_wait/5` invokes that exact function after its
tag-qualified launch. The callback reply is validated as an opaque native
cleanup descriptor, not stored as a future callable.

The complete actual producer census is Fetch's `HTTP.HTTP3.request/3` and
EventSource's fixed H3 stream selection. Fetch constructs its HTTP3 state with
no `http3_runtime_opts` field; request/3 therefore starts from `[]` and adds
only opening timeout, deadline and lifecycle. EventSource passes explicit
generation and opening timeout. Neither public option
projection exposes `quic_cleanup` or arbitrary runtime options.
`PoolKey.build/2` likewise constructs connection options with an explicit key
list that excludes this callback; Stream's subsequent merge obtains it only
from the same internal start options. There is no library-created connector
callback. Consequently the invocation is unreachable from supported client
construction. Direct internal Stream options do not establish a new approved
callback root. Fabricated private cleanup descriptors remain excluded.

## H3-5: Fetch response handler

`SocketClient.http3_owner/6` is the sole library caller of
`HTTP.HTTP3.request/3`, supplying `&handle_http3_event/2`. Both invocation sites
are in `await/5`, which retains that exact function through its recursive data
and event branches. The handler's result changes response state only; it does
not supply another handler. Its actual body builds buffered/streamed responses,
delivers chunks/trailers and reports typed failures through library functions.
Redirects create another owner with the same literal handler.

Direct arbitrary state/handler arguments to this internal request entry were
explicitly excluded from the public-input guarantee. All library-created
handlers and their reentry through supported Fetch remain included here.

## Evidence and remaining acceptance

All selected inputs and the full production-source census match artifact
`13119243608` at `524edb2`. The bound original inventory retains all 50 findings.
The user decision resolves the H3-2 contract blocker; it does not erase the
findings or replace their constructor and retention proof. P6 still requires
the directed release gate, complete real traffic and the release regressions.
H3 completion receipts and unsupported application capabilities retain their
previous boundaries.

## 2026-11-05 source review amendment: RC2 static checks

Production commit `5050bfcfd82c7a650d7d87113d30ca8360d91edf` changes the pinned
EventSource acknowledgment body from an unused comprehension to `Enum.each/2`.
Both traverse the same reversed references, acknowledge through the same literal
H2/H3 selector and retain the original state. No H3 connector, `:ops` constructor,
callback assignment or retained producer changes. No H3 occurrence line or MFA
changes. The fresh compiled inventory has exactly the original 175 dispatches;
the changed closure adds no raw unresolved finding.

The JSON amendment records the new selected-input hash and current full-source
census, keeping historical artifact/check/census/BEAM evidence intact. The 35
TLS1.3 collection scenarios passed with the generic static failure retained;
strict candidate and published gates must still bind current source and BEAMs.

## 2026-11-08 source review amendment: shared Fetch adapter entry

Phase 1 changes the shared Fetch entry, option projection and SocketClient
validation. With no explicit adapter or pool selection, the same request reaches
ManagedTransport and the existing SocketClient/H3 branch. Explicit named pools
reject HTTP/3 before I/O. Adapter contexts take a separate explicit extension
path; they cannot alter the retained built-in H3 connector or operation callbacks.
The H3 engines, owner construction and all 50 bound H3 occurrences are unchanged.
The HTTP review covers the two new caller adapter dispatches and the H2 provider
activation callback. This amendment refreshes the three shared source hashes;
historical artifacts remain historical, and strict candidate/published compiled
reconciliation is still required.

## 2026-11-10 source review amendment: rc.11 resumption, extensions and migration

This amendment reviews the production sources at `4ae97fc` against the census
bound at `1a1f81d`. Eight selected inputs change. `HTTP.HTTP3.Resumption` is
added as a selected input because it creates shared endpoints.

### H3-1 and H3-2

`Session.new/1` still assigns `transport` once, with literal default
`QuicHttp3.Transport.Quic`. New sites 189–199 call the retained
`session.transport`. They cover early-data and resumption queries, extension
requirements, unidirectional and kind-selected stream opens, `reset_stream_at`,
datagrams and `migrate`. The only library producer of `:session_options` is the
WebTransport backend, which supplies only WebTransport limits.

`Transport.Quic.reset_stream_at/4` (ID 200) and `migrate/2` (ID 201) call the
retained stream or connection `ops`. `HTTP.HTTP3.Resumption` creates its shared
endpoint with `QuicTransport.client/1`. The options are an explicit key projection
plus a literal resumption policy, without `:ops`, so the endpoint retains literal
`Quic`. Borrowing still requires equal `ops`. `Quic.reset_stream_at/4` and
`Quic.migrate/2` route to the reviewed Connection operations.

### H3-4: library-created connector callback

The earlier statement that no library connector callback exists is superseded
for certified streams. `HTTP.HTTP3.Stream.relay_cleanup/2` creates exactly one,
`fn _deadline -> native_scope(relay) end`, under four conditions: the stream is
an extended CONNECT with a request lifecycle, the connection is exclusive, and
neither a caller callback nor a descriptor is present. Its body calls only
`Quic.Cleanup.new/1` (Q1) and returns that opaque handle and lease.
`connector_wait/5` still invokes the retained function once after its tagged
launch; it moves from line 333 to 520. Public option projections still do not
expose `:quic_cleanup`, so caller-supplied connector callbacks remain unreachable
from supported construction.

H3-3 wrappers and SocketClient's literal H3-5 handler are unchanged. H3 now has
63 reviewed occurrences. The complete compiled inventory of a locally built
isolated candidate release matches the five reviews exactly at 206 sites. CI
strict candidate and published gates remain required.

### Follow-up: graceful HTTP/3 connection close (2026-11-10)

`HTTP.HTTP3.ConnectionOwner` and `HTTP.HTTP3.Pool` changed after the rc.11
renewal (`4c1bf8f`). On an orderly `:normal` stop of a ready or draining owner,
`terminate/2` runs `QuicHttp3.Session.close/1` (CONNECTION_CLOSE with
H3_NO_ERROR, then transport cleanup) under `guarded/4` before it retires the
cleanup lease. The pool no longer retires an exclusive owner's lease on release;
it sends `:http3_retire` and still retires on owner DOWN. The new calls are
literal; `Session.close/1` reaches only the reviewed H3-1 `session.transport`
close and cleanup sites. Neither file holds a reviewed occurrence, so no
occurrence is added or rebound. The producer hashes, the release census entries
and every group's rc.11 census digest are updated.

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

Infinite timeouts on HTTP/3 (`7e83803`): `HTTP.HTTP3.request/3` uses the new
`opening_timeout/1` to compute its opening budget, which is 5,000 ms for `nil` or
`:infinity`. `await/5` waits with `remaining/1`. `HTTP.HTTP3.ConnectionOwner`
and SocketClient's `request_http3` use the infinity-aware helpers. All of these
are literal calls. The H3-5 handler invocations (143, 144) stay at `await/5`
lines 40 and 53. FetchOptions and SocketClient also gain the decoded-body bound
(`0186b4e`), and the `HTTP` documentation changes (`abcc548`). This group holds
none of the moved SocketClient sites; the HTTP review rebinds them. No H3
occurrence is added or rebound. The release now has 207 sites, because HTTP
gains one Promise callback site.

### Follow-up: rc.13 review fixes (2026-11-11)

`QuicHttp3.Session` (`3a5522c`) sends RFC 9114 connection error codes by closing
the QUIC connection with the detected code. The `{:close, code, phrase}`
operation calls `session.transport.close(session.connection, code, phrase,
opts)`, the same retained H3-1 transport as its siblings, and is new occurrence
208 (`operation/3`, line 1092). `Session.new/1` still assigns the transport once
and the only library `session_options` producer is the WebTransport backend. The
other 26 H3-1 sites keep their expressions and owning functions and move by 5 to
13 lines; they are rebound in the amendment and the follow-up entry. The H3 review
now has 64 occurrences. SocketClient, `HTTP` and the EventSource files change as
described in the HTTP review, which holds the moved sites.

### Follow-up: rc.14 production changes (2026-11-11)

`QuicHttp3.Transport.Quic` (`c7fada8`) no longer carries `:tls_backend` in its
endpoint option projection and drops the `:tls_backend_not_supported_for_quic`
clause. The H3-2 sites `start_endpoint/5` (58) and `stop_owned_endpoint/2` (59)
move by one line with unchanged expressions and retained ops. They are rebound in
the amendment and the follow-up entry. The other H3-2 sites keep their lines.
`HTTP.HTTP3.PoolKey` drops its `tls_backend` rejection clause. The Fetch,
SocketClient and EventSource inputs change as described in the HTTP review,
which holds their moved sites. SocketClient still supplies only
`&handle_http3_event/2`. No H3 occurrence is added or removed, and the H3 review
still has 64 occurrences.

### Follow-up: rc.14 retry policy (2026-11-12)

`HTTP`, `FetchOptions` and `SocketClient` change for the opt-in retry policy
(`5eae73d`), as described in the HTTP review, which holds their moved sites and
the two new HTTP-11 sites. SocketClient still supplies only
`&handle_http3_event/2`. No H3 occurrence is added, removed or rebound.

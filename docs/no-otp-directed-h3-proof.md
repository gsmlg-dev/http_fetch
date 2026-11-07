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

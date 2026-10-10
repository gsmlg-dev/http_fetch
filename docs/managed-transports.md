# Managed transport generations

`HTTP.ManagedTransport` owns private reusable HTTP/1 and multiplexed HTTP/2
transports for one immutable route generation. Independent scopes never share a
pool or connection, including when their origin and policy are identical.

```elixir
{:ok, scope} = HTTP.ManagedTransport.open(
  origin: "https://upstream.example",
  connect_address: {192, 0, 2, 10},
  http_version: :http2,
  max_requests: 100,
  max_connections: 2,
  max_pending: 0,
  idle_timeout: 30_000
)

promise = HTTP.fetch("https://upstream.example/data",
  transport_scope: scope,
  request_mode: :proxy,
  redirect: :manual,
  decode_body: false,
  stream_response: true,
  timeout: 5_000,
  connect_timeout: 1_000
)

response = HTTP.Promise.await(promise)
# Consume response.stream with acknowledged reads, read_all/1 or write_to/2.
{:ok, snapshot} = HTTP.ManagedTransport.snapshot(scope, 100)
{:ok, receipt} = HTTP.ManagedTransport.retire(scope, mode: :graceful)

case HTTP.ManagedTransport.await_retired(receipt, 1_000) do
  :ok -> :generation_resources_confirmed_gone
  {:error, :cleanup_pending} -> :wait_again_later
  {:error, :cleanup_unconfirmed} -> :cleanup_evidence_lost
end
```

The scope and receipt are opaque. A scope accepts only its normalized origin
(scheme, hostname and port) and numeric IPv4/IPv6 destination. `:http1` supports
HTTP or HTTPS; `:http2` requires HTTPS; `:h2c` requires cleartext HTTP. Only direct
TCP and the OTP `:ssl` backend are supported. Automatic protocol selection,
HTTP/3, proxy/Unix routes, ExSSL, followed redirects, decoded or automatically
buffered responses are rejected. Request headers, raw bodies and ordered duplicate
request/response trailers retain the ordinary Fetch contract. No request is
retried or replayed, including when an idle HTTP/1 peer has become stale.

## Capacity and retained state

Admission fails immediately with
`{:error, {:transport_scope_capacity, :requests | :connections}}`; there is no
pool waiting queue. A fixed ingress ledger claims a request slot before retaining
the prepared request or contacting transport processes. Preparing requests and
requests with unread response streams occupy slots. A request slot is released
only after its lifecycle tracker terminates. Connection slots include connecting,
checked-out and idle connections, and remain occupied until every independently
tracked resource for the connection (including OTP TLS/protocol owners and their
retained buffers) has terminated. Raw socket closure alone cannot free capacity.
The HTTP/1 idle pool keeps at most
`min(max_connections, 16)` sockets.

| Retained state | Enforced bound |
| --- | --- |
| Preparing and live requests combined | `max_requests`: 1..2,048, default 100 |
| Connecting, checked-out and idle connections combined | `max_connections`: 1..256, default 2 |
| Pending pool waiters | `max_pending`: exactly 0 |
| Idle retention | `idle_timeout`: 1..60,000 ms, default 30,000 |
| Frozen TLS/socket policy | 1 MiB serialized with compact owned binary backing; nesting/list sizes also bounded |
| Request headers and target | 64 KiB accounted metadata, at most 256 fields |
| Non-streamed request body | 1 MiB iodata |
| Upload worker/source chunk and H2 body bridge | 64 KiB per chunk/bridge |
| HTTP/1 response head and trailers | 64 KiB each; chunk-size lines bounded |
| HTTP/2 writer queue and receive budget | 1 MiB each per connection with frozen `:native_v1` |
| HTTP/2 encoded/decoded header block | 64 KiB each, at most 256 decoded fields |
| HTTP/2 field-block frame count | At most 256 total HEADERS/CONTINUATION frames, including empty frames |
| Retained informational responses | At most 128 and 64 KiB metadata per request |

These bounds describe library-owned admission and transport state. They do not
bound the whole VM, caller-created producer input, data accumulated by the
caller, arbitrary messages sent to public control operations, or OS/TLS internal
allocation. Stream producers should submit one acknowledged chunk at a time.
Oversized chunks fail with `:buffer_limit` (H2 wraps this as
`{:body_error, :buffer_limit}` on the request). The H1 writer signals the exact
error to its source before terminating, so its producer also observes the error.

### Managed request normalization

Before admission, managed requests discard redundant URI `authority` metadata
and retain only scheme, host, port, path and query. Supported URL, header,
buffered-body and convenience Content-Type binaries receive compact owned
backing. Bounded iodata is flattened to one binary; its original list structure
is not retained by the admitted request. Buffered bodies remain limited to
1 MiB. Body and Content-Type list traversal additionally permits at most 65,536
nodes (cons cells and leaves, including empty lists) and 32 nesting levels before
conversion, so zero-byte and deeply nested representations have finite work.

Both retained input metadata (headers, used URI strings and convenience
Content-Type) and effective request metadata must fit 64 KiB. Fields cost their
name and value bytes plus 32 bytes each; effective fields plus the HTTP/1 origin-form
target must fit the same byte limit and contain at most 256 fields. Effective
fields include generated Content-Type/framing, HTTP/1 Host/Connection and HTTP/2
pseudo-fields. The original explicit fields stay intact for protocol framing
validation; explicit Content-Type takes precedence over the convenience value.
Over-budget or unsupported managed representations return
`:transport_scope_request_limit` before dialing or sending request bytes.

These are conservative payload and structure charges, not an exact heap-memory
envelope. Caller input, rejected-request handling, preparation traversal and
temporary conversion/copy allocations are outside the retained-input contract.
The normalized payload may have several references or bounded preparation
copies; the charges do not claim one allocation per reference or bound OTP/OS
transport internals. Non-managed Fetch keeps its ordinary input contract.

`snapshot/2` accepts a finite nonnegative millisecond timeout and returns aggregate
`active_requests`, `preparing_requests`, `pending`, `connections`, `resources`,
`limits`, `identity` and `lifecycle`. It returns no request history, URLs, headers,
TLS material or credentials. The identity is a policy digest, not a public pool
key. Expired control-operation waits return `{:error, :cleanup_pending}`.

## HTTP/2 peer notifications

The native owner admits at most 128 informational heads and 65,536 regular-field
metadata bytes over each stream's entire lifetime, before queueing or notifying
the recipient. Flushing or consuming events does not replenish this allowance.
Overflow resets only the offending stream with `:http2_informational_limit`;
the rejected block still advances the shared HPACK decoder. Terminal streams
cannot renew recipient notifications or upload-stop messages. Final headers and
trailers are each allowed once. These limits also apply to ordinary H2 clients.

A request can therefore create at most 130 header notifications and 33,280 field
pairs. A conservative accounted-data allowance is 218,368 bytes per request:
65,536 informational regular metadata, 128 status fields of at most 42 accounted
bytes, and two final/trailer blocks of at most `65,536 + 256 * 32` bytes each.
Reserve this allowance for both owner events and recipient representations;
Fetch's retained response/header representation can add another allowance. List,
tuple and map overhead must be reserved for the finite event/field counts; these
figures are not byte-exact BEAM heap sizes.

Managed request leases remain occupied until the lifecycle tracker and its
recipient resources terminate, including after a protocol stream slot is freed.
The notification envelope uses `max_requests`, rather than current protocol
stream count. Ordinary subscribers accumulating history after releasing their
own streams own that history themselves.

Raw decoded literal strings and retained encoded fragments own compact backing.
The native HPACK dynamic table is bounded to 4,096 accounted bytes. Decode/copy
scratch is separately finite: reserve three 64-KiB encoded-block representations
for fragment concatenation overlap, a 64-KiB decoded block and up to 256 fields,
old/new 4,096-byte dynamic tables, and Huffman scratch: at most 524,288
bit-list cells, 65,536 one-byte binary entries, their original and reversed
lists, the resulting output binary and the fixed decoding trie. Header/event
list reversal and dynamic-table insertion/eviction also overlap; reserve
structural storage using the bounded field/event/table-entry counts.
Raw current transport deliveries, the library's `state.buffer <> delivery`
concatenation and their copy overlap require a separate ingress allowance. The
notification figures above do not bound that delivery allocation or claim a
complete whole-generation heap envelope. Retained partial-frame backing is
compacted; complete deliveries are processed and released within the callback.

SETTINGS reporting keeps one constant-size unacknowledged pool snapshot and one
current desired state per connection. New SETTINGS coalesce into the current
connection state; a matching pool/token acknowledgement permits only the latest
differing snapshot. All wire SETTINGS acknowledgements continue while the pool
is busy. Pool capacity may briefly lag the peer, but the owner checks stream
admission before sending request headers. Pool death or lost registration cannot
block retirement waiting for a capacity acknowledgement.

GOAWAY sends one draining update per connection and at most one nonterminal
notice per surviving stream. Lower subsequent cutoffs still terminate newly
excluded streams once, without replay or extending the original drain deadline.

## Immutable security and deadlines

`open/1` freezes authority/SNI, dial destination, TLS verification/CA/client
credentials, socket settings and the HTTP/2 `:native_v1` profile. TLS defaults
are peer verification, TLS 1.2/1.3, depth 4, system CAs and SNI from the original
hostname. `cacertfile`, `certfile` and `keyfile` are read once into OTP TLS values;
later file changes cannot change an existing generation. File reads and final
policy size are bounded. Unencrypted RSA, EC and PKCS8 private keys are accepted.
Unsupported TLS callbacks/options, encrypted/malformed files, conflicting SNI
and invalid socket options reject at open. Use a new scope for rotated policy.

After final structural and 1-MiB serialized-policy validation, every retained
TLS/socket binary is copied into compact owned backing. This covers in-memory
CA/certificate/private-key values, materialized files, system CA defaults and
supported nested option representations; accepted origin binaries are compact
as well. A small borrowed slice cannot pin its caller's larger carrier binary
through the frozen policy. Copying preserves values, verification, override
equality and the policy digest.

The sum of owned policy binary payload is bounded by the serialized-policy
budget. Repeated occurrences are copied independently at freezing; later scope,
configuration, request and connection references can share ref-counted payload.
Conservative reservations must account for each retained representation and its
bounded list/tuple structures rather than assume physical sharing. Caller-owned
source backing, file/PEM processing and freeze/preparation copy overlap are
transients outside the retained-policy payload bound. This does not bound OTP
TLS's internal parsed credential state or the whole VM heap.

TLS/socket overrides that conflict with the frozen policy reject before dialing.
The supported socket policy uses finite `send_timeout` and
`send_timeout_close: true`; buffer settings are finite. Request/connect deadlines
may differ between requests (1..86,400,000 ms). The same request deadline covers
managed upload attachment, scope binding, admission and transport establishment.
Socket writer settings remain frozen rather than being overwritten by the last
request's deadline; stream deadlines remain independent.

## Retirement proof

`retire/2` stops new admission (`:transport_scope_retired`) and closes idle sockets
immediately. `mode: :graceful` lets admitted live requests and unread responses
drain; `mode: :abort` additionally requests cancellation. The default is graceful.
Creator death initiates abort retirement. Opening a new route generation does
not interfere with the old generation's live siblings.

`await_retired/2` accepts a finite nonnegative millisecond timeout. `:ok` requires
all generation request trackers, connectors, raw socket ports, OTP TLS handler
processes, connection owners, private pools, connection supervisor and coordinator
to have terminated. A timeout leaves cleanup running and returns
`:cleanup_pending`. Lost coordinator evidence returns `:cleanup_unconfirmed`;
unexpected coordinator death never manufactures success. Receipts survive normal
coordinator termination and support repeated/concurrent waits.

A caller-supplied upload PID that never acknowledges attachment still produces a
finite request timeout, receives a cooperative stop, and cannot cause a late dial.
If it ignores shutdown, its request slot and cleanup remain pending until the
caller terminates it. The library never force-kills an arbitrary caller source.
Ordinary `HTTP.Stream` sources respond to stop even before acquiring a reader.
Caller-created producer processes remain caller-owned.

`HTTP.RequestCompletion` remains the per-request barrier: a healthy reusable
socket may remain after a request completes. Individual request evidence may be
conservative after abnormal termination while generation retirement independently
proves every monitored resource gone. Neither barrier establishes whether a
remote application received bytes before cancellation.

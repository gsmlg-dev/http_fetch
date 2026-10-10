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
| Frozen TLS/socket policy | 1 MiB serialized; policy nesting and list sizes also bounded |
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

`snapshot/2` accepts a finite nonnegative millisecond timeout and returns aggregate
`active_requests`, `preparing_requests`, `pending`, `connections`, `resources`,
`limits`, `identity` and `lifecycle`. It returns no request history, URLs, headers,
TLS material or credentials. The identity is a policy digest, not a public pool
key. Expired control-operation waits return `{:error, :cleanup_pending}`.

## Immutable security and deadlines

`open/1` freezes authority/SNI, dial destination, TLS verification/CA/client
credentials, socket settings and the HTTP/2 `:native_v1` profile. TLS defaults
are peer verification, TLS 1.2/1.3, depth 4, system CAs and SNI from the original
hostname. `cacertfile`, `certfile` and `keyfile` are read once into OTP TLS values;
later file changes cannot change an existing generation. File reads and final
policy size are bounded. Unencrypted RSA, EC and PKCS8 private keys are accepted.
Unsupported TLS callbacks/options, encrypted/malformed files, conflicting SNI
and invalid socket options reject at open. Use a new scope for rotated policy.

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

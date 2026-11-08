# Explicit HTTP/3 Fetch contract

`HTTP.fetch(url, http_version: :http3)` selects the supervised HTTP/3 runtime.
The URL must use HTTPS. Selection is strict: an opening, TLS, ALPN or protocol
failure returns an error; it does not send the request over HTTP/1 or HTTP/2.

```elixir
response =
  HTTP.fetch("https://example.test/", http_version: :http3,
    ssl: [cacertfile: "/path/to/ca.pem"], http3_profile: :ordered)
  |> HTTP.Promise.await()

:http3 = response.http_version
body = HTTP.Response.text(response)
```

Trust, reference identity and SNI are normalized independently of DNS resolution.
When dialing an IP for a named service, supply the actual reference identity,
for example `ssl: [cacertfile: ca, reference_identity: {:dns_id, "example.test"}]`.
Verification cannot be disabled. Explicit TCP TLS backends, Unix sockets, proxies,
TCP socket options and HTTP/2 wire profiles are rejected for this route.
`http3_reuse: false` requests a separate connection; reuse otherwise incorporates
origin, trust, reference identity, client identity, wire profile and endpoint
ownership. Connections drain on GOAWAY and rotate before native lifetime limits.
If a reserved owner refuses an open before it enters the session, the untouched
request can move to a fresh owner under the same absolute deadline (at most three
owner attempts). Producer demand starts only after successful stream opening.
Allocated, sent and unknown native outcomes never use that transfer path.

Binary POST/PUT bodies and PID bodies with `duplex: :half` use HTTP/3 DATA frames.
Upload producers receive acknowledgement only after all slices are definitively
admitted. Source chunks are limited to 64 KiB, native slices to 16 KiB. Early final
responses stop the upload; errors, cancellation and unknown admission never
manufacture an acknowledgement or replay the request. A native-call watchdog
returns `{:indeterminate_operation, operation_ref}` when admission cannot be
resolved; the identity is `:unknown` if the synchronous call never exposed its
native reference. `HTTP.Stream.finish(upload, ordered_fields)` sends one trailing
HEADERS section with FIN after all admitted DATA, including for zero-DATA uploads.
Repeated fields retain their order. `Trailer` declarations are optional and
validated independently of HTTP/1 chunk framing. Session field-section and encoding
limits or native admission failures propagate asynchronously through the existing
promise/response result. Raw session callers use
`QuicHttp3.Session.send_trailers(session, request_ref, fields, options)` and retain
the returned session for blocked/unknown reconciliation, just as for DATA.
Redirects that preserve a streamed body return `:streaming_body_redirect_not_replayable`. Cross-origin
redirects with client certificate/key identity return an explicit error.

Network responses expose their actual `http_version` as `:http1`, `:http2` or
`:http3`. The existing request-stop telemetry event includes that value as
`metadata.http_version`. Constructed responses may leave it `nil`.
HTTP/3 informational fields appear in `response.informational` as `{status,
HTTP.Headers}` pairs; retention is capped at 128 responses and 64 KiB of decoded
field accounting. The final status and headers remain the ordinary response.
Buffered trailers are in `response.trailers`. For streamed responses, consumers
receive `{:stream_trailers, stream_pid, HTTP.Headers}` before `:stream_end`.
`HTTP.Response.text/1` and `write_to/2` consume body bytes; callers can receive the
trailer message separately after either returns.

Large or unknown-length downloads keep the existing process-backed Response
body contract and acknowledgement-driven backpressure. Aborting one request
cancels its stream and preserves pooled siblings. The request timeout covers
opening, upload, response headers and streamed-body delivery. EventSource has a
separate finite opening deadline and its own established idle/reconnect policy.
It requires explicit `http_version: :http3` and reports the actual protocol after
verified readiness.

Response QPACK decoding supports the dynamic table (RFC 9204). The client
advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY` 4096 and
`SETTINGS_QPACK_BLOCKED_STREAMS` 16 by default, configurable per session with
`QuicHttp3.Session` options `:qpack_max_table_capacity` (0..65536) and
`:qpack_blocked_streams` (0..128), for example through the runtime
`session_options`; `0`/`0` restores the static/literal profile without QPACK
streams. With a nonzero capacity the client opens its QPACK encoder and decoder
streams, applies peer encoder instructions to a bounded table (capacity above
the advertised maximum, oversized inserts, invalid references and partial
instructions beyond `4 * capacity + 64` bytes are `QPACK_ENCODER_STREAM_ERROR`),
and decodes Required Insert Count/Base, dynamic, post-base and name references.
A section whose Required Insert Count is not yet satisfied blocks only its own
stream: further reads of that stream stop, held bytes and FIN count against the
session retained-byte budget, and sections resume in blocking order. More
blocked streams than advertised, or invalid section references, are
`QPACK_DECOMPRESSION_FAILED`. The decoder stream carries Section
Acknowledgment, Stream Cancellation for abandoned incomplete streams, and
Insert Count Increment through normal write admission; peer decoder
instructions other than Stream Cancellation are `QPACK_DECODER_STREAM_ERROR`.
The local encoder stays static/literal; Huffman strings are decoded. The independent
gate is `uv run --python 3.12 --with aioquic==1.2.0 python
scripts/http3/qpack_dynamic_gate.py`. 0-RTT, connection migration, connection
racing and WebTransport remain unsupported.
WebSocket over HTTP/3 is supported (explicit opt-in, no fallback) with a stream-level cleanup receipt; see `http3-extensions-contract.md`. Raw `Quic.capabilities().http3` remains false because raw QUIC owns
transport rather than HTTP semantics.

Validation evidence is separated in the implementation audit: native regression
results, independent peer traffic, load/rotation, artifact consumers, CI and
canary are distinct gates. An authenticated ALPN alone is not evidence of public
HTTP/3 behavior.

## Opt-in Alt-Svc discovery

`HTTP.fetch(url, http_version: :auto, alt_svc: true)` learns same-host `h3`
alternatives from `Alt-Svc` on final HTTPS responses into a bounded per-origin
cache (1024 origins, `ma` default 86400 s, `clear` honoured). A later eligible
request with a fresh entry uses HTTP/3 on the alternative port, keeping the
origin authority, SNI and certificate identity. Requests with a proxy, Unix
socket, connect address, explicit `tls_backend`, socket options, HTTP/2 profile,
transport scope or pool stay on TCP. `alt_svc: true` with any other
`http_version` raises `ArgumentError`; `:auto` without it is unchanged.

Fallback to H2/H1 happens only when the QUIC connection never became ready
(`{:http3_not_established, _}` or `:opening_timeout` before the runtime's
`:connection_ready` event), so no request stream was admitted. It runs within
the original deadline and marks the origin broken for 300 s (no H3 routing or
re-learning). Failures after readiness, including indeterminate admission, are
returned without replay. Redirect hops on an Alt-Svc route re-select per origin.
Alternatives on a different host are ignored.
On the H3 route a TCP-form `ssl: [ex_ssl: [reference_identity: id]]` is lifted
to the flat QUIC `reference_identity` when it is the only `ex_ssl` setting; any
other `ex_ssl` setting keeps the request on TCP.

## Session resumption and 0-RTT (beta)

Both features are opt-in and beta; defaults are unchanged and
`Quic.capabilities()` keeps reporting `resumption: false`. EventSource accepts
`http3_resumption` and never sends 0-RTT. WebSocket and WebTransport over
HTTP/3 do not take these options: their certified exclusive owners retire a
per-relay `Quic.Cleanup` scope that requires an owned endpoint.

### Resumption (`http3_resumption: true`)

- New connections dial through a shared client endpoint owned by
  `HTTP.HTTP3.Resumption` (supervised by `:http_runtime`) instead of an
  endpoint per connection. The engine-local store keeps the tickets (default
  256 tickets / 1 MiB per endpoint, lifetime <= 600 s, single use).
- A partition is one endpoint: the exact endpoint configuration (origin host,
  TLS trust and reference identity, QUIC profile, stream/datagram limits), the
  dialed UDP port (including an Alt-Svc port) and the 0-RTT policy. The engine
  additionally binds each ticket to remote address, trust, name, ALPN and
  application profile (`http3-fetch-r1-v1`, or `http3-fetch-0rtt-v1` for early
  partitions). The authority holds at most 64 partitions; when full the least
  recently used partition with no live connection is stopped, and when none is
  idle the connection proceeds without resumption. Nothing is persisted.
- The pool identity gains `{:resumption, early?}`, so resumed, early and plain
  connections never share a pooled connection. Resumption only affects new
  connections; a pooled connection is reused as before (use
  `http3_reuse: false` to observe a new handshake per request).
- A user-supplied `endpoint` together with `http3_resumption` is rejected with
  `:http3_resumption_endpoint_conflict`.
- Observability: Fetch HTTP/3 responses carry
  `response.http3 == %{resumed: boolean, early_data: boolean}` only when
  `http3_resumption: true`; otherwise `response.http3` is `nil`.

### 0-RTT (`early_data: true`)

- Only GET, HEAD and OPTIONS without a body may set `early_data: true`; any
  other method or a body raises `ArgumentError` at option normalization.
  Without `http3_resumption: true`, without a 0-RTT-capable ticket or without
  remembered SETTINGS the option has no effect and the request is sent after
  the handshake. Unsafe methods are never sent early.
- The 0-RTT partition requires that the server's remembered transport
  parameters fit the engine's immutable early envelope (<= 64 KiB credit, <= 8
  streams, `active_connection_id_limit` <= 8); otherwise the engine does not
  offer 0-RTT and requests wait for the handshake.
- Admission: after `Quic.connect` the owner offers early admission only when the
  connection reports `early_data: :pending` and SETTINGS are remembered for the
  partition. Only the request stream (HEADERS with FIN) is sent as replayable
  early operations; control and QPACK streams open after the handshake. At most
  eight requests are admitted early per connection. If the session cannot admit
  an open early, it waits for the handshake like any other open.
- Remembered SETTINGS contract (RFC 9114 Section 7.2.4.2): the owner records the
  peer SETTINGS frame received on each connection of a 0-RTT partition (at most
  32 settings). An early request must fit the remembered
  `SETTINGS_MAX_FIELD_SECTION_SIZE`. When 0-RTT is accepted, a new SETTINGS
  frame that omits or reduces a remembered non-default value of
  `QPACK_MAX_TABLE_CAPACITY`, `MAX_FIELD_SECTION_SIZE`, `QPACK_BLOCKED_STREAMS`,
  `ENABLE_CONNECT_PROTOCOL` or `H3_DATAGRAM` is an `H3_SETTINGS_ERROR` (0x109)
  connection error. Remembered settings are the latest received on the
  partition rather than those of the exact ticket's connection; a server that
  changes SETTINGS between tickets may therefore fail an accepted 0-RTT
  connection with this error instead of resuming silently.
- QPACK: the client encoder is static/literal and never references the dynamic
  table, so the server's remembered `QPACK_MAX_TABLE_CAPACITY` and
  `QPACK_BLOCKED_STREAMS` constrain nothing the client sends. The client's own
  decoder SETTINGS travel on the control stream after the handshake; until the
  server has them it must encode with the RFC 9204 defaults (no dynamic table),
  which the decoder accepts.
- Rejection: if the server rejects 0-RTT (including a full-handshake fallback),
  the session re-sends each early request once on a fresh stream after the
  handshake under the same request reference; `response.http3.early_data` is
  `false`. There is no automatic replay of anything else.
- 425 Too Early (RFC 8470): a 425 to a request that was carried in accepted
  0-RTT is retried once after the handshake with `early_data` cleared (on the
  non-early partition); a 425 to any other request is returned as is.
- `response.http3.early_data` is `true` when the request was admitted under
  0-RTT keys and the connection's 0-RTT was accepted.
- Alt-Svc: the `:connection_ready` invariant is kept — it is still emitted
  before any request admission. For a 0-RTT partition it is emitted once the
  resumed connection offers 0-RTT, i.e. before the handshake completes. A
  handshake failure after an early admission is therefore returned as an error
  and never falls back to TCP, so a request is never both sent early and
  replayed over TCP.

Evidence: `apps/http_fetch/test/http/http3_resumption_test.exs` (native QUIC
server with resumption and 0-RTT), `apps/elixir_quic_http3/test/quic_http3_early_data_test.exs`
(admission, remembered SETTINGS, rejection re-send) and the independent aioquic
1.2.0 gate
`uv run --python 3.12 --with aioquic==1.2.0 python scripts/http3/resumption_gate.py`
(full, resumed, 0-RTT GET/HEAD, 425 retry, 425 passthrough, rejected 0-RTT
re-send traced to the session).

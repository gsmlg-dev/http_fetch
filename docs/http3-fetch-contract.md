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

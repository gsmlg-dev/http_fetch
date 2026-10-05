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

Binary POST/PUT bodies and PID bodies with `duplex: :half` use HTTP/3 DATA frames.
Upload producers receive acknowledgement only after all slices are definitively
admitted. Source chunks are limited to 64 KiB, native slices to 16 KiB. Early final
responses stop the upload; errors, cancellation and unknown admission never
manufacture an acknowledgement or replay the request. Redirects that preserve a
streamed body return `:streaming_body_redirect_not_replayable`. Cross-origin
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

The initial profile is static/literal QPACK with Huffman decoding, zero dynamic
table capacity and zero blocked-stream allowance. Dynamic QPACK, 0-RTT,
connection migration, Alt-Svc/racing, WebSocket over HTTP/3 and WebTransport remain
unsupported. Raw `Quic.capabilities().http3` remains false because raw QUIC owns
transport rather than HTTP semantics.

Validation evidence is separated in the implementation audit: native regression
results, independent peer traffic, load/rotation, artifact consumers, CI and
canary are distinct gates. An authenticated ALPN alone is not evidence of public
HTTP/3 behavior.

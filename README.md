# HTTP Fetch

 [![Elixir CI](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml)
 [![Elixir CI](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml)
 [![Hex.pm](https://img.shields.io/hexpm/v/http_fetch.svg)](https://hex.pm/packages/http_fetch)
 [![Hexdocs.pm](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/http_fetch/)
 [![Hex.pm](https://img.shields.io/hexpm/dt/http_fetch.svg)](https://hex.pm/packages/http_fetch)
 [![Hex.pm](https://img.shields.io/hexpm/dw/http_fetch.svg)](https://hex.pm/packages/http_fetch)

A modern HTTP client library for Elixir that provides a fetch API similar to web browsers, built on Erlang's built-in socket modules.

For development, prepare the umbrella before running a scoped app test:
`MIX_ENV=test mix deps.get && MIX_ENV=test mix compile --warnings-as-errors`
followed by `MIX_ENV=test mix test apps/http_fetch/test`. Running the test from
the root keeps runtime applications of `in_umbrella` dependencies, including
`ex_ssl`, on the code path without adding duplicate child dependencies.

The umbrella contains nine independently packaged applications with coordinated
versions and exact internal dependencies. The imported TLS/QUIC source inventory
is recorded in [migration provenance](docs/migration-provenance.md); its original
validation snapshot is [preserved separately](docs/migration-validation.md).
Current HTTP/3 beta acceptance and publication evidence are tracked in the
[implementation audit](docs/http3-implementation-audit.md).

## Features

- **Browser-like API**: Familiar fetch interface with promises and async/await patterns
- **Full HTTP support**: GET, POST, PUT, DELETE, PATCH, HEAD methods
- **Internal HTTP/1.1 transport**: Uses `:gen_tcp` for HTTP, selectable TLS for HTTPS, and Unix domain sockets
- **Explicit HTTP/3 beta**: HTTPS Fetch and EventSource with bounded streams and static/literal QPACK
- **Unix Domain Sockets**: HTTP over Unix sockets for Docker daemon, systemd, and other local services
- **Form data support**: HTTP.FormData for multipart/form-data and file uploads
- **Streaming request bodies**: Fetch-style `duplex: "half"` uploads over HTTP/1.1, HTTP/2 and explicit HTTP/3
- **Type-safe configuration**: HTTP.FetchOptions for structured request configuration
- **Promise-based**: Async operations with chaining support
- **Request cancellation**: AbortController support for cancelling requests
- **Automatic JSON parsing**: Built-in JSON response handling
- **Selectable TLS**: OTP `:ssl` by default, with opt-in `:ex_ssl` for verified TLS 1.3
- **HTTP/2 wire profiles**: Versioned native and synthetic profiles can control
  ordered SETTINGS and header serialization; use `http2_profile` only with an
  explicit HTTP/2 or h2c request.

Explicit HTTP/2 and h2c prior knowledge use supervised pooled connections with
multiplexing, flow-controlled binary/streaming uploads and bounded download
buffers. The default HTTP version remains HTTP/1. Profiles control ordered
SETTINGS, header serialization and supported priority behavior on cold and warm
connections. Available IDs are `native_v1`, `synthetic_test_v1`, and
`synthetic_test_v2`; revision 2 explicitly disables server push. Synthetic
profiles do not claim browser fingerprint equivalence. Use
`HTTP.HTTP2.ProfileCapture.build_manifest/2` for capture provenance.

See the [Fetch validation record](docs/http2-production-validation.md) and
[stream-client validation record](docs/http2-stream-clients-validation.md) for
executed gates, candidate provenance, resource budgets and phase status. These
records distinguish local acceptance, remote CI, publication and rollout.

## Browser Fetch API Compatibility

This library implements the **Browser Fetch API** standard for Elixir with ~85% compatibility. All critical Response properties and methods from the JavaScript Fetch API are supported.

### Response Properties

```elixir
response = HTTP.fetch("https://api.example.com/data") |> HTTP.Promise.await()

# Standard Browser Fetch API properties
response.status        # 200
response.status_text   # "OK"
response.ok            # true (for 200-299 status codes)
response.headers       # HTTP.Headers struct
response.body          # Response body binary, or stream PID for streamed responses
response.body_used     # false (tracks consumption, but doesn't prevent reads in Elixir)
response.redirected    # false (true if response was redirected)
response.type          # :basic
response.url           # URI struct
```

### Response Methods

```elixir
# Read as JSON
{:ok, data} = HTTP.Response.json(response)

# Read as text
text = HTTP.Response.text(response)

# Read as binary (ArrayBuffer equivalent)
binary = HTTP.Response.arrayBuffer(response)

# Read as Blob with metadata
blob = HTTP.Response.blob(response)
IO.puts "Type: #{blob.type}, Size: #{blob.size} bytes"

# Clone for multiple reads
clone = HTTP.Response.clone(response)
json = HTTP.Response.json(response)
text = HTTP.Response.text(clone)  # Read clone independently
```

### Elixir-Specific Differences

**Immutability**: Unlike JavaScript, Elixir responses are immutable. The `body_used` field exists for API compatibility but doesn't prevent multiple reads of the same response value. Use `clone/1` for clarity when reading multiple times.

**Synchronous Returns**: Methods like `json()` and `text()` return values directly instead of Promises, following Elixir conventions.

**Stream Handling**: Large responses expose an Elixir stream process in `response.body`
instead of a JavaScript `ReadableStream`. The legacy `response.stream` field is kept
as an alias for streamed responses.

## Quick Start

```elixir
# Simple GET request
response =
  HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
  |> HTTP.Promise.await()

# Use Browser-like API
IO.puts("Status: #{response.status} #{response.status_text}")
IO.puts("Success: #{response.ok}")
text = HTTP.Response.text(response)
{:ok, json} = HTTP.Response.json(response)

# Read response body as raw binary
response =
  HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
  |> HTTP.Promise.await()

# For buffered responses, response.body contains the raw binary data.
# For streamed responses, use HTTP.Response.read_all/1 or write_to/2.
binary_data = HTTP.Response.read_all(response)

# POST request with JSON
response =
  HTTP.fetch("https://jsonplaceholder.typicode.com/posts", [
    method: "POST",
    headers: %{"Content-Type" => "application/json"},
    body: JSON.encode\!(%{title: "Hello", body: "World"})
  ])
  |> HTTP.Promise.await()

# Unix Domain Socket request (Docker daemon example)
response =
  HTTP.fetch("http://localhost/version",
    unix_socket: "/var/run/docker.sock")
  |> HTTP.Promise.await()

# Parse Docker version info
{:ok, docker_info} = HTTP.Response.json(response)
IO.puts("Docker Version: #{docker_info["Version"]}")
```

## TLS Backend Selection

HTTPS fetch (HTTP/1.1 and HTTP/2), secure WebSocket, and HTTPS EventSource share
one TLS default. OTP `:ssl` remains the default when no configuration is set:

```elixir
# config/config.exs or config/runtime.exs
config :http_core, tls_backend: :ex_ssl
```

A flat per-call option overrides that default:

```elixir
HTTP.fetch("https://example.com", tls_backend: :ssl)

HTTP.fetch("https://example.com",
  tls_backend: :ex_ssl,
  ssl: [cacertfile: "/path/to/ca.pem"]
)

HTTP.WebSocket.new("wss://example.com/socket", [], tls_backend: :ex_ssl)
HTTP.EventSource.new("https://example.com/events", tls_backend: :ex_ssl)
```

`tls_backend` accepts `:ssl`, `:ex_ssl`, `"ssl"`, or `"ex_ssl"`. Maps also accept
`"tls_backend"` and `"tlsBackend"` keys. Omitted or `nil` values inherit the shared
configuration. The backend is captured when the request/client is created and
retained through redirects and EventSource reconnects; runtime configuration
changes affect new operations. Invalid selections fail explicitly.

`http_core` declares `ex_ssl` and `elixir_quic` as transitive runtime dependencies
at the exact coordinated package version. Current artifact and publication
evidence is recorded in the implementation audit. Consumers do not need to add
those dependencies separately. `ssl: [...]` supplies TLS settings
to the selected backend. The `ex_ssl` backend uses its own `SSL` protocol engine
and requires peer verification. TLS 1.3 is the default; verified TLS 1.2 is
explicitly selectable. It uses system CA certificates unless `cacerts` or
`cacertfile` is supplied. DNS names and IP addresses are verified against the
peer certificate. `verify: :verify_none` and unsupported TLS or TCP options
return errors; connections never fall back to another backend automatically.

A complete HTTP/2 response remains deliverable if the peer closes before the
client can write its remaining WINDOW_UPDATE or acknowledgement frames. This
also covers responses buffered across multiple TLS records by `ex_ssl` after a
normal peer shutdown: the client drains the receive side before deciding whether
the response completed. Only `:closed` on optional control writes qualifies.
A complete early response (such as 413) stops the remaining upload, including
request DATA queued by WINDOW_UPDATE in the same batch. It also survives a
subsequent RST_STREAM(NO_ERROR), as required by
[RFC 9113 §8.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1).
Completion requires END_STREAM and the complete HEADERS/CONTINUATION field
block; an unfinished upload neither proves nor prevents response completion.
HTTP/2 also validates Content-Length against unpadded DATA bytes before
completion, rejects body overruns immediately, and reports mismatches as
`:content_length_mismatch`. Valid HEAD/304 representation lengths do not require
a body. Malformed/conflicting lengths, values longer than 20 decimal digits,
and values outside the unsigned 64-bit bound return `:invalid_content_length`.
Inbound frames are limited to the advertised 16,384-byte payload size and
compressed header blocks to 65,536 bytes, including CONTINUATION fragments.
Each header block permits at most 256 frames in total (the initial HEADERS and
all CONTINUATION frames, including empty frames and the final END_HEADERS
frame). Empty payloads are not retained. Exceeding this frame count reports
`{:transport_error, :header_block_too_fragmented}` and closes that HTTP/2
connection, failing its unfinished requests; other connections remain usable.
The existing compressed-byte, HPACK and decoded-header limits still apply.
Content-Length is forbidden on informational/204 responses and in trailers;
DATA or HEADERS after END_STREAM is rejected rather than completed again.
Truncation, required writes before completion, abnormal closure, cancellation
and timeout remain errors. The original deadline and streaming backpressure
are preserved.

HTTP/2 retains ordered informational blocks in `response.informational` and
buffered trailers in `response.trailers`, separate from initial headers.
Streamed trailers arrive as `{:stream_trailers, stream_pid, headers}` after
acknowledged DATA and before `:stream_end`; the immutable response field stays
empty. Metadata retention is bounded and malformed or oversized metadata fails
the response. See `HTTP.Response` for the limits and
[the HTTP/2 beta support contract](docs/http2-beta-support.md) for protocol
availability, workload limits, rollout and rollback.

For `:ex_ssl`, `socket_opts` accepts `send_timeout`,
`send_timeout_close: true`, `nodelay`, `keepalive`, `sndbuf`, `recbuf`, and local
`ip`/`port`. The adapter forwards only this allowlist and ex_ssl validates values.
IPv6 literals infer the family; an IPv6 local `ip` tuple selects IPv6 DNS
resolution. Both option containers must be keyword lists. Socket options
override matching entries in `ssl`. Custom
ClientHello profiles can be passed through `ssl: [ex_ssl: [profile: profile]]`;
any ALPN list added by HTTP/2 selection must match the profile's ALPN list exactly.
Configured ex_ssl client credentials stay within the initial request origin
during automatic redirects. A scheme,
hostname or effective-port change returns
`{:error, :client_identity_cross_origin_redirect}`. To authorize another origin,
use `redirect: :manual` and explicitly make a new request with that identity.
The OTP backend retains its existing redirect behavior.

ex_ssl 0.5.0 supports verified TLS 1.2 for
HTTP/1.1, HTTP/2, WSS and EventSource. Select it with `ssl: [versions:
[:"tlsv1.2"]]`; a mixed TLS 1.3/TLS 1.2 offer selects the peer's supported
version. The independent OpenSSL package gate includes 262,144-byte HTTP/2
responses with observed connection and stream WINDOW_UPDATE frames. The OTP
default is unchanged.

TLS 1.3 session resumption is explicit:
`ssl: [versions: [:"tlsv1.3"], session_tickets: :auto]`. Tickets are disabled
by default. Auto mode currently rejects client identities and mixed/TLS 1.2
version offers; early data and PSK-only exchange are unsupported. When a server
declines a ticket, a full handshake continues on the same connection without
replaying request bytes. The published feature gate checks fresh HTTP/1.1,
HTTP/2, WSS and EventSource connections against an independent OpenSSL peer;
the peer must report a full handshake followed by a resumed handshake.
HTTP version selection (`http_version: :http2`) and TLS version selection
(`ssl: [versions: [:"tlsv1.3"]]`) are independent. Fetch supports streaming request
bodies over HTTP/1.1, HTTP/2 and explicit HTTP/3; the multiplexed runtimes use
bounded upload bridges and preserve early-response upload cleanup.
This is a bounded subset, not full OTP `:ssl` parity.

See the [ex_ssl compatibility contract](https://github.com/gsmlg-dev/ex_ssl/blob/v0.5.0/docs/COMPATIBILITY.md).
The [consumer contract inventory](docs/ex-ssl-consumer-contract.md) maps the
implemented subset and intentional restrictions to its tests.

Plain HTTP, WS, and Unix sockets retain their existing transports. HTTP/3 and
WebTransport use QUIC's separate TLS implementation and ignore the shared
setting. An explicit non-`nil` `tls_backend` on either QUIC API returns
`{:error, :tls_backend_not_supported_for_quic}` (through the promise for fetch).
The raw QUIC transport does not select an application protocol merely from ALPN;
`Quic.capabilities().http3` remains `false`.

## HTTP/3 Beta

Fetch and EventSource support explicit `http_version: :http3` over HTTPS with
verified peer identity. Opening, TLS, ALPN and protocol failures return errors;
there is no automatic protocol fallback.

```elixir
response =
  HTTP.fetch("https://example.test/", http_version: :http3,
    ssl: [cacertfile: "/path/to/ca.pem"])
  |> HTTP.Promise.await()

:http3 = response.http_version
body = HTTP.Response.text(response)
```

`QuicHttp3.capabilities/0` reports `status: :beta`, `http3: true`, `qpack: true`,
`qpack_profile: :static_literal` and `qpack_huffman: true`. The session advertises
zero dynamic-table capacity and zero blocked streams. Dynamic QPACK, 0-RTT,
connection migration, Alt-Svc/racing, WebSocket over HTTP/3 and WebTransport
remain unsupported.

Binary and streamed uploads, pooled siblings, informational responses, trailers,
total request deadlines and cancellation use the shared HTTP/3 runtime.
EventSource retains its established idle/reconnect policy. See the
[Fetch contract](docs/http3-fetch-contract.md) and
[EventSource contract](apps/http_event_source/docs/http3-validation.md) for
options and delivery semantics. Beta support does not imply full conformance
or completed production acceptance; independent peer, artifact, load and canary
results are recorded separately in the
[acceptance record](docs/http3-wp5-acceptance.md).

## Form Data With File Upload

```elixir
file_stream = File.stream!("document.pdf")
form = HTTP.FormData.new()
       |> HTTP.FormData.append_field("name", "John Doe")
       |> HTTP.FormData.append_file("document", "document.pdf", file_stream)

response =
  HTTP.fetch("https://api.example.com/upload", [
    method: "POST",
    body: form
  ])
  |> HTTP.Promise.await()
```

## Proxy Request Bodies

Use `request_mode: :proxy` to send request entities for any admitted method,
including GET, DELETE, and HEAD. The default `:fetch` mode retains the existing
omission of bodies for these methods. HEAD responses remain bodyless in either
mode. For transparent forwarding, use `redirect: :manual` and `decode_body: false`
to avoid automatic redirects and response entity decoding.

```elixir
response = HTTP.fetch(url, method: :delete, request_mode: :proxy,
  body: "abc", headers: [{"Content-Length", "3"}], redirect: :manual,
  decode_body: false) |> HTTP.Promise.await()
```

PID bodies still require `duplex: :half` and retain the same bounded upload,
cancellation, and early-response behavior described below. HTTP/1 streams with
`Content-Length` use fixed framing; streams without it use chunked framing.
Proxy mode also accepts an explicit `Transfer-Encoding: chunked` for an
unknown-length HTTP/1 stream, including declared trailers. Conflicting framing,
other transfer codings, and explicit chunked framing on buffered bodies are
rejected. HTTP/2 and HTTP/3 prohibit Transfer-Encoding headers. HTTP/2 supports
bounded request trailers; HTTP/3 rejects them explicitly.

## Explicit Proxies

```elixir
HTTP.fetch("https://api.example.com/data", proxy:
  {:http, "proxy.example.com", 8080,
    [headers: [{"Proxy-Authorization", "Basic " <> Base.encode64("user:password")}],
     timeout: 5_000]}, http_version: :auto, redirect: :manual)
|> HTTP.Promise.await()
```

`proxy` accepts `{:http, host, port, opts}` and `{:https, host, port, opts}`.
The options are a single optional
`Proxy-Authorization` header (at most 8,192 bytes, without control characters)
and a positive finite `timeout` in milliseconds (default 30,000). Cleartext
HTTP/1 uses absolute-form requests to the proxy. HTTPS establishes CONNECT and
then verifies the origin's certificate and negotiates HTTP/1 or HTTP/2 inside
the tunnel. Proxy credentials appear only on the proxy hop; they are removed
from tunneled origin requests. The same route remains selected across redirects.

An HTTPS proxy supports HTTP origins using TLS to the proxy and absolute-form
HTTP/1 forwarding. `tls_backend` and `ssl` configure proxy TLS; trust and hostname
verification use the proxy host. Scheme, endpoint, credentials, and TLS policy
isolate pooled connections. HTTPS origins through HTTPS proxies are rejected
with `:https_proxy_requires_http_origin` before dialing.

```elixir
HTTP.fetch("http://origin.example/resource",
  proxy: {:https, "proxy.example", 443, []}, request_mode: :proxy,
  redirect: :manual, decode_body: false) |> HTTP.Promise.await()
```

Connecting and establishing the tunnel share the smaller of the proxy timeout,
request timeout, and connect timeout. CONNECT response headers are bounded to
16,384 bytes; malformed responses, failed status codes, framing indicating a
body, and plaintext buffered at the TLS boundary fail closed. Abort cancels an
unfinished tunnel. Proxy failure never retries through a direct-origin route.

Unsupported shapes, H2c, HTTP/3, and Unix socket/proxy combinations fail
explicitly. Both TLS backends verify DNS and literal-IP origins inside CONNECT
tunnels. ExSSL verifies IP origins without DNS SNI by default. For ordinary
direct or proxy connections, caller-supplied DNS SNI also selects the DNS
certificate identity. Use `ssl: [ex_ssl: [reference_identity: {:ip, ...}]]` to
verify a separate IP identity while sending DNS SNI. Environment variables and
NO_PROXY selection remain caller responsibilities.

## Pre-send failure evidence

Use `error_mode: :structured` to receive `{:error, %HTTP.RequestError{}}`.
The default keeps existing raw error reasons. `error.reason` contains the
original reason; `HTTP.RequestError.pre_send?(error)` is true only when direct
TCP or OTP TLS dialing failed before TCP establishment, using manual/error
redirects. A fresh request-local token ties evidence to that attempt. TLS
negotiation, pooled socket failures, partial uploads, source/send/response
errors, cancellation, and uncertain deadline outcomes remain unconfirmed.
Automatic redirect chains and ExSSL never provide positive pre-send evidence.

Fetch performs no automatic address failover or HTTP retry. A caller may try
another independently validated `connect_address` only after positive evidence,
while checking its original absolute deadline and cancellation signal. Set each
attempt's `timeout` to the remaining total budget and keep the same authority,
TLS verification policy, and signal. Confirm cleanup before replacing an upload
source: terminal attempt errors stop its stream, which cannot be reused.

```elixir
result = HTTP.fetch(url, connect_address: validated_ip, redirect: :manual,
  error_mode: :structured, timeout: remaining_budget, signal: controller)
  |> HTTP.Promise.await()

case result do
  {:error, %HTTP.RequestError{} = error} -> HTTP.RequestError.pre_send?(error)
  %HTTP.Response{} -> false
end
```

## Streaming Request Body

```elixir
{:ok, stream} = HTTP.Stream.from_enumerable(["chunk one", "chunk two"])

response =
  HTTP.fetch("https://api.example.com/upload", [
    method: "POST",
    body: stream,
    duplex: "half",
    content_type: "text/plain"
  ])
  |> HTTP.Promise.await()
```

HTTP/1 receives upstream responses while a stream upload is still open. A final
response stops the unfinished upload without replaying it. HTTP/1 uploads keep
one acknowledged source chunk in flight, with a 65,536-byte maximum per chunk;
larger chunks fail with `:buffer_limit`. Split large producer items into smaller
chunks. The response owner retains active-once receive credit even while a write
is blocked. Cancellation signals (`HTTP.AbortController.abort/1` and
`HTTP.Stream.error/2`) return after signalling; monitor the affected stream PID
for `:DOWN` to confirm its cleanup. Terminal request errors also stop the upload
stream and wake blocked producers, including failures before connection setup
on routes without a completion barrier. A stopped stream cannot be reused.
An early response is exposed only after its unfinished upload writer and source
have terminated.

For HTTP/1 upload trailers, use an unknown-length stream, declare trailer names
in the initial headers, and complete the stream with ordered fields:

```elixir
{:ok, upload} = HTTP.Stream.start_link(0)
promise = HTTP.fetch(url, method: :post, body: upload, duplex: :half,
  headers: [{"Trailer", "X-Checksum"}])
:ok = HTTP.Stream.chunk(upload, "data")
:ok = HTTP.Stream.finish(upload, [{"X-Checksum", "expected"}])
response = HTTP.Promise.await(promise)
```

`finish/2` validates at most 128 fields and 65,536 serialized bytes, including
field separators and the final blank line. It returns a validation error without
finishing the stream for invalid fields. Completion is asynchronous; monitor the
stream to confirm termination. For HTTP/1, nonempty trailers require chunked
uploads, and every name must appear in the `Trailer` declaration; undeclared
names fail with `:undeclared_trailer`.

HTTP/2 streams use the same `finish/2` API and limits without requiring a
`Trailer` declaration. Ordered duplicate permitted fields are sent as trailing
HEADERS with END_STREAM after every DATA write is acknowledged. Large blocks
use an atomic HEADERS/CONTINUATION batch and the connection's existing HPACK
encoder. The peer's maximum header-list size also applies; exceeding it fails
only the request with `{:body_error, :trailers_too_large}`. Fixed Content-Length
validates DATA bytes independently from trailers.

An early final response abandons pending DATA and unsent trailers. Cancellation
before transmission discards unsent trailers; cancellation during a trailer
write completes the atomic header batch before resetting the request, preserving
HPACK state for siblings. Cancellation after transmission resets the response
half. Existing request deadlines and transport write timeouts apply. A failed
partial transport write retires the connection and fails its active requests.
HTTP/3 upload trailers remain unsupported (`:request_trailers_unsupported`).

HTTP/1 response trailers preserve ordered duplicate fields and are delivered as
`{:stream_trailers, stream, headers}` after body acknowledgements and before
stream end. They use the same byte/count limits as uploads. Permitted undeclared
response trailers are accepted; declared names are validated but advisory.
Framing, routing, connection-specific, authentication, cookie, and content
processing fields are rejected as trailers. Trailer values remain separate from
the initial response headers.

## Validated connection addresses

A caller enforcing an address policy can pin Fetch to one validated literal
IPv4 or IPv6 tuple while keeping the original URL host for HTTP authority,
TLS SNI and certificate verification:

```elixir
HTTP.fetch("https://api.example.com/resource",
  connect_address: validated_ip,
  http_version: :http1,
  redirect: :manual,
  timeout: remaining_budget)
```

The pin is request-local, participates in connection pool isolation, and never
falls back to DNS, another address or request replay. One tuple is supported;
address-list failover is left to the caller before a request is established.
Request/connect deadlines and cancellation still cover connection establishment.
Use `redirect: :manual` or `:error`: for every permitted redirect, validate its
hostname/addresses independently and submit a new request with that hop's pin.
Invalid tuples and pin combinations with HTTP/3, Unix sockets or proxies are
rejected before network I/O. Caller-supplied SNI must match the original URL
host. Native trust and hostname verification remain enabled by default.

Both TLS backends verify the original URL's DNS or literal-IP certificate
identity when dialing a distinct IPv4 or IPv6 pin. For ExSSL, an explicit
`ssl: [ex_ssl: [reference_identity: ...]]` must match that original identity;
a conflicting reference returns `:connect_address_identity_conflict` before I/O.
Literal-IP pins use no DNS SNI by default and also accept `server_name_indication: :disable`.

## WebSocket Client

The umbrella also includes `HTTP.WebSocket`, a browser-like WebSocket client.
It returns a socket immediately, then delivers `open`, `message`, `error`, and
`close` events to the owner process.

```elixir
socket = HTTP.WebSocket.new("wss://example.com/socket", ["chat.v1"])

receive do
  {HTTP.WebSocket, ^socket, %HTTP.WebSocket.Event.Open{}} ->
    :ok = HTTP.WebSocket.send(socket, "hello")

  {HTTP.WebSocket, ^socket, %HTTP.WebSocket.Event.Message{data: data}} ->
    IO.inspect(data, label: "message")

  {HTTP.WebSocket, ^socket, %HTTP.WebSocket.Event.Close{code: code, reason: reason}} ->
    IO.inspect({code, reason}, label: "closed")
end
```

Browser-compatible accessors are exposed with Elixir naming:

```elixir
HTTP.WebSocket.ready_state(socket)
HTTP.WebSocket.buffered_amount(socket)
HTTP.WebSocket.protocol(socket)
HTTP.WebSocket.extensions(socket)
HTTP.WebSocket.binary_type(socket)
HTTP.WebSocket.url(socket)
HTTP.WebSocket.http_version(socket) # :http1, :http2, or nil while opening
HTTP.WebSocket.status(socket)
```

Plain Elixir binaries are sent as text frames. Use `HTTP.WebSocket.array_buffer/1`
or `HTTP.Blob` for binary frames:

```elixir
:ok = HTTP.WebSocket.send(socket, "text")
:ok = HTTP.WebSocket.send(socket, HTTP.WebSocket.array_buffer(<<0, 1, 2>>))
:ok = HTTP.WebSocket.send(socket, HTTP.Blob.new(<<0, 1, 2>>))
:ok = HTTP.WebSocket.close(socket, 1000, "done")
```

For text/binary/control frame forwarding, opt into HTTP/1 proxy mode:

```elixir
socket = HTTP.WebSocket.new("wss://example.com/socket", [],
  mode: :proxy, http_version: :http1, delivery: :ack, automatic_pong: false)

# Received frames use {HTTP.WebSocket, socket, %Event.Frame{opcode: ..., data: binary}, ref}.
# Acknowledge after downstream consumption; Close keeps the Event.Close envelope.
{:ok, ref} = HTTP.WebSocket.send_frame_ack(socket, {:ping, "probe"})
receive do
  {HTTP.WebSocket, ^socket, {:send_result, ^ref, :ok}} -> :ok
end
:ok = HTTP.WebSocket.close(socket, 1001, "Going Away")
```

Proxy mode delivers validated, reassembled text/binary messages and ping/pong
frames as `HTTP.WebSocket.Event.Frame`, with binary data regardless of
`binary_type`. `send_frame/2` reports bounded FIFO admission;
`send_frame_ack/2` reports local write completion. Wait for every admitted
frame's successful completion before calling `close/3`, because Close discards
unsent queued frames. Empty controls count toward send limits. Control payloads
remain limited to 125 bytes and ACK receive capacity must admit at least 132
bytes. Automatic pong defaults to true; disable it only in proxy mode when
forwarding controls. Proxy close accepts wire codes 1000-1014 except
1004/1005/1006, and 3000-4999, with valid UTF-8 reasons up to 123 bytes.
HTTP/2, h2c and auto proxy mode are rejected with `:proxy_requires_http1`.
Browser behavior remains the default, including hidden controls and restricted
initiated close codes.

For a message-only WebSocket reverse proxy, use `HTTP.WebSocket.new/3` with
`http_version: :http1`, `delivery: :ack`, finite `opening_timeout`,
`idle_timeout`, `write_timeout` and `close_timeout`, and explicit queue/message
limits. The handshake is validated, including coalesced response/frame bytes;
redirects and uncertain writes are never retried. Verified WSS keeps CA,
hostname and SNI checks. This public boundary forwards WebSocket messages;
Ping/Pong and Close are handled by the client, and original frame fragmentation
is not preserved.

`send_ack/2` returns `{:ok, ref}` for bounded admission. The owner then receives
`{HTTP.WebSocket, socket, {:send_result, ref, :ok | {:error, reason}}}` once the
whole frame is accepted by the local transport or fails. A proxy can release
its downstream write credit on this completion. It does not prove peer receipt;
a failed write can be partial and must not be replayed. `write_timeout` defaults
to 5,000 ms and covers queueing plus writing. `send/2` retains admission-only
semantics. Acknowledge received Message events after downstream consumption.
Monitor the socket's public `pid` and wait for `:DOWN` after `close/1` to confirm
resource cleanup; owner death also cancels the connection.

HTTP/1 remains the default. Select `http_version: :http2` for TLS h2 with RFC 8441
peer permission, or `:h2c` for cleartext prior knowledge. `:auto` on WSS permits
one separate HTTP/1 connection before establishment when ALPN or peer capability
is unavailable. Authentication, certificate, malformed-handshake and established
session failures do not trigger fallback or message replay. Cleartext `:auto`
uses HTTP/1. Explicit profiles require their H2 wire identity; contradictory
ALPN and H2 Unix-socket options are rejected before networking. With WSS `:auto`,
a custom `http2_scope` or `http2_reuse: false` requires an explicit H2 profile;
otherwise construction returns `{:error, :http2_options_require_http2}`.

```elixir
socket = HTTP.WebSocket.new("wss://example.com/socket", [],
  http_version: :http2, delivery: :ack, tls_backend: :ssl)

receive do
  {HTTP.WebSocket, ^socket, %HTTP.WebSocket.Event.Message{data: data}, ref} ->
    consume(data)
    :ok = HTTP.WebSocket.acknowledge(socket, ref)
end
```

ACK delivery charges queued and in-flight messages against `max_queue_bytes` and
`max_queue_events` (default 64). Legacy delivery keeps its original envelope and
uses a finite internal queue with terminal slow-owner overload; it cannot bound
unrelated messages in the owner's mailbox. Frames and assembled messages default
to 16 MiB, with at most 16,384 fragment parts. Outbound admission allows 64 pending
application frames and 16 control frames. `buffered_amount/1` counts unsent
application payload bytes, excluding masked frame headers; admission can return
`:send_queue_full` under pressure. Closing finishes the current frame, discards
queued application frames, and prioritizes the Close frame. A missing peer Close
is abnormal, including HTTP/2 END_STREAM without a WebSocket Close.

`opening_timeout` defaults to the legacy `timeout`; `idle_timeout` defaults to
`:infinity` and pauses during local ACK pressure; `close_timeout` defaults to
5,000 ms. An H2 client closes only its logical stream. Compatible TLS, profile,
scope and connection options allow Fetch, SSE and WS to share the same runtime
owner. See [validation](docs/http2-stream-clients-validation.md) for acceptance
commands and measured resource limits.

Elixir differences from the browser API: invalid constructor input returns
`{:error, reason}` instead of raising a DOM exception, and events are process
messages instead of `EventTarget` callbacks.

## EventSource Client

The umbrella includes `HTTP.EventSource`, a browser-like Server-Sent Events
client. It returns an event source immediately, then delivers `open`, `message`,
custom message-type, and `error` events to the owner process.

```elixir
source = HTTP.EventSource.new("https://example.com/events")

receive do
  {HTTP.EventSource, ^source, %HTTP.EventSource.Event.Open{}} ->
    IO.puts("connected")

  {HTTP.EventSource, ^source, %HTTP.EventSource.Event.Message{data: data}} ->
    IO.inspect(data, label: "event")

  {HTTP.EventSource, ^source, %HTTP.EventSource.Event.Error{reason: reason}} ->
    IO.inspect(reason, label: "stream error")
end
```

Browser-compatible accessors are exposed with Elixir naming:

```elixir
HTTP.EventSource.ready_state(source)
HTTP.EventSource.with_credentials(source)
HTTP.EventSource.url(source)
HTTP.EventSource.http_version(source) # :http1, :http2, or nil while opening
HTTP.EventSource.status(source)
HTTP.EventSource.close(source)
```

The client reconnects after dropped streams, honors `retry:` fields, and sends
`Last-Event-ID` after receiving event IDs. Elixir differences from the browser
API: invalid constructor input returns `{:error, reason}`, and events are
process messages instead of `EventTarget` callbacks.

HTTP/1 remains the default. Select `http_version: :http2` for required TLS h2,
`:h2c` for cleartext prior knowledge, or `:auto` for TLS ALPN negotiation.
HTTP/2 uses the shared runtime and can share an eligible connection with Fetch.
An explicit `http2_profile` requires h2; `http2_scope` and `http2_reuse` retain
the same isolation rules. With TLS `:auto`, a custom scope or
`http2_reuse: false` requires an explicit H2 profile; otherwise construction
returns `{:error, :http2_options_require_http2}`. OTP `:ssl` remains the default
TLS backend.

For bounded consumer delivery, use opaque acknowledgements:

```elixir
source = HTTP.EventSource.new("https://example.com/events",
  http_version: :http2, delivery: :ack)

receive do
  {HTTP.EventSource, ^source, %HTTP.EventSource.Event.Message{data: data}, ref} ->
    IO.inspect(data)
    :ok = HTTP.EventSource.acknowledge(source, ref)
end
```

The default parser caps a line at 64 KiB, an assembled event at 1 MiB, and its
parts at 16,384. The acknowledged FIFO includes its in-flight message and defaults
to 2 MiB/64 events; its byte limit must fit `max_event_size + 7`. Raw input reserves
the advertised receive window in addition to a 1 MiB admitted-byte budget and has
a 128-chunk limit. Legacy delivery keeps its original envelope and permanently
stops on conservative owner-mailbox overload. Invalid responses/UTF-8/oversized
events are fatal; 204 permanently stops; ordinary EOF/reset may reconnect.
Accepted acknowledged deliveries drain before terminal errors. The cursor advances
on parsing rather than application acknowledgement, so reconnects can replay.

`[:http_runtime, :stream, :open | :queue | :reconnect | :error | :close | :fallback]`
events add bounded client/version/outcome labels and numeric queue/raw counters.
Established idle timeout defaults to infinity and pauses for local acknowledged
backpressure. See [stream-client validation](docs/http2-stream-clients-validation.md)
for independent peers, resource budgets and current phase status.

## API Reference

### HTTP.fetch/2
Performs an HTTP request and returns a Promise.

```elixir
promise = HTTP.fetch(url, [
  method: "GET",
  headers: %{"Accept" => "application/json"},
  body: "request body",
  content_type: "application/json",
  redirect: :manual,
  timeout: 10_000,
  signal: abort_controller,
  unix_socket: "/var/run/docker.sock"  # Optional: use Unix Domain Socket
])
```

Set `duplex: "half"` only when `body` is an `HTTP.Stream` PID.

Supports both string URLs and URI structs:

```elixir
# String URL
promise = HTTP.fetch("https://api.example.com/data")

# URI struct
uri = URI.parse("https://api.example.com/data")
promise = HTTP.fetch(uri)
```

### HTTP.Promise
Asynchronous promise wrapper for HTTP requests.

```elixir
response = HTTP.Promise.await(promise)

# Promise chaining
HTTP.fetch("https://api.example.com/data")
|> HTTP.Promise.then(fn response -> HTTP.Response.json(response) end)
|> HTTP.Promise.await()
```

### HTTP.Response
Represents an HTTP response.

```elixir
text = HTTP.Response.text(response)
{:ok, json} = HTTP.Response.json(response)

# Access raw response body as binary
response =
  HTTP.fetch("https://api.example.com/large-file")
  |> HTTP.Promise.await()

# For buffered responses, response.body contains raw bytes; streamed responses
# expose a stream PID and can still be read through the helper.
binary_data = HTTP.Response.read_all(response)

# Write response to file (supports both streaming and non-streaming)
:ok = HTTP.Response.write_to(response, "/tmp/downloaded-file.txt")

# Write large file downloads directly to disk
response =
  HTTP.fetch("https://example.com/large-file.zip")
  |> HTTP.Promise.await()

:ok = HTTP.Response.write_to(response, "/tmp/large-file.zip")
```

### HTTP.Headers
Handle HTTP headers with utilities for parsing, normalizing, and manipulating headers.

```elixir
# Create headers
headers = HTTP.Headers.new([{"Content-Type", "application/json"}])

# Get header value
type = HTTP.Headers.get(headers, "content-type")

# Set header
headers = HTTP.Headers.set(headers, "Authorization", "Bearer token")

# Set header only if not already present
headers = HTTP.Headers.set_default(headers, "User-Agent", "CustomAgent/1.0")

# Access default user agent string
default_ua = HTTP.Headers.user_agent()

# Parse Content-Type
{media_type, params} = HTTP.Headers.parse_content_type("application/json; charset=utf-8")
```

### HTTP.Telemetry
Comprehensive telemetry and metrics for HTTP requests and responses.

```elixir
# All HTTP.fetch operations automatically emit telemetry events
# No configuration required - just attach handlers

:telemetry.attach_many(
  "my_handler",
  [
    [:http_fetch, :request, :start],
    [:http_fetch, :request, :stop],
    [:http_fetch, :request, :exception]
  ],
  fn event_name, measurements, metadata, _config ->
    case event_name do
      [:http_fetch, :request, :start] ->
        IO.puts("Starting #{metadata.method} request over #{metadata.scheme}")
      [:http_fetch, :request, :stop] ->
        IO.puts("Request completed: #{measurements.status} in #{measurements.duration}μs")
      [:http_fetch, :request, :exception] ->
        IO.puts("Request failed: #{inspect(metadata.error)}")
    end
  end,
  nil
)

# Manual telemetry events (for custom implementations)
HTTP.Telemetry.request_start("GET", URI.parse("https://example.com"), %HTTP.Headers{})
HTTP.Telemetry.request_stop(200, URI.parse("https://example.com"), 1024, 1500)
HTTP.Telemetry.request_exception(URI.parse("https://example.com"), :timeout, 5000)
```

Request events omit all headers and URI values, including host, path, userinfo,
query and fragment. Method, scheme, protocol and error use finite categories;
unknown failure details appear as `:request_failed`.

Use `HTTP.fetch(url, telemetry: false)` to disable request events and response
stream / internal upload telemetry. Independently created upload producers can
use `HTTP.Stream.from_enumerable(chunks, telemetry: false)`. Shared HTTP/2 pool
and connection counters remain aggregate and contain no request attributes.
For strict global silence, use `config :http_fetch, telemetry: false`, which
also disables both Fetch and shared runtime event prefixes, including other
clients using that runtime. `config :http_runtime, telemetry: false`
independently disables all shared runtime events.
The bundled TLS and QUIC engines do not emit telemetry.

### HTTP.Request
Request configuration struct.

```elixir
request = %HTTP.Request{
  method: :post,
  url: URI.parse("https://api.example.com/data"),
  headers: HTTP.Headers.new([{"Authorization", "Bearer token"}]),
  body: "data",
  transport_options: [timeout: 10_000, connect_timeout: 5_000, redirect: :manual]
}
```

**Transport Options:**
- `transport_options`: Socket transport options such as `timeout`, `connect_timeout`, `tls_backend`, `ssl`,
  `socket_opts`, and `redirect`

`redirect` defaults to `:follow` with the socket transport. Pass `redirect: :manual`
to `HTTP.fetch/2` or `transport_options: [redirect: :manual]` on `%HTTP.Request{}`
to return redirect responses. Pass `redirect: :error` to fail when a redirect response
is received.

### HTTP.FormData
Handle form data and file uploads.

```elixir
# Regular form data
form = HTTP.FormData.new()
       |> HTTP.FormData.append_field("name", "John")
       |> HTTP.FormData.append_field("email", "john@example.com")

# File upload
file_stream = File.stream!("document.pdf")
form = HTTP.FormData.new()
       |> HTTP.FormData.append_field("name", "John")
       |> HTTP.FormData.append_file("document", "document.pdf", file_stream, "application/pdf")

# Use in request
HTTP.fetch("https://api.example.com/upload", method: "POST", body: form)
```

### HTTP.AbortController
Request cancellation.

```elixir
controller = HTTP.AbortController.new()
HTTP.AbortController.abort(controller)
```

## Error Handling

The library handles:
- Network errors and timeouts
- HTTP error status codes
- JSON parsing errors
- Invalid URLs
- Cancelled requests

## Development

This project uses several code quality tools to maintain high standards:

### Code Quality Tools

**Credo** - Static code analysis to enforce Elixir style guidelines and identify code smells:

```bash
# Run standard checks
mix credo

# Run with strict mode (includes readability checks)
mix credo --strict

# Explain a specific issue
mix credo explain <issue_category>
```

**Dialyzer** - Static type analysis to catch type errors and inconsistencies:

```bash
# Run type checking
mix dialyzer

# Generate/rebuild PLT (first time setup, takes 2-3 minutes)
mix dialyzer --plt
```

**ExDoc** - Generate comprehensive documentation:

```bash
# Generate HTML documentation
mix docs

# View generated docs
open doc/index.html
```

### Running Tests

Run these commands from the umbrella root, including when testing one app.
The root dependency graph includes the runtime dependencies of every umbrella
app; invoking Mix inside a child app does not traverse its `in_umbrella`
dependencies in the same way.

```bash
# Prepare dependencies, including on a cold checkout
MIX_ENV=test mix deps.get
MIX_ENV=test mix compile --warnings-as-errors

# Run all unit tests
mix test

# Run one app (replace the app name as needed)
mix test apps/http_fetch/test

# Run specific test file
mix test apps/http_fetch/test/http/response_test.exs

# Run with coverage
mix test --cover
```

### App-scoped GitHub Actions

CI, Test, and E2E run separate jobs for each app under `apps/`. Automatic
push and pull-request runs select changed app owners plus affected H2
Fetch/EventSource/WebSocket consumers, using the actual umbrella dependency
graph. Changes to root manifests/lockfile, configuration, H2 peers/harnesses,
CI selectors, release tooling and workflows also select these consumers.
Unrelated root documentation does not trigger these jobs.

The CI H2 compatibility job checks consumer suites, both independent peers over
h2c and verified TLS with `:ssl` and `:ex_ssl`, and mixed candidate-package
traffic. Its artifact records candidate SHA, archive checksums, commands,
backend/peer, test summaries, and exclusions. Long soaks run separately.
Each app job prepares its dependency closure; WebSocket and EventSource test
closures include Fetch for their existing cross-client tests.

Shared changes still require manual full regression. Dispatching any of these
workflows forces all nine app jobs on the selected branch. Manual CI also runs
candidate package consumers and historical TLS compatibility checks:

```bash
gh workflow run ci.yml --ref main
gh workflow run test.yml --ref main
gh workflow run e2e.yml --ref main
```

The same full runs are available through **Actions → Run workflow**. E2E uses
the selected branch's commit and runs all apps.

### Running E2E Tests

The e2e suite exercises real HTTP behavior against a vendored Go test
server. It requires Go 1.22+ to build the server.

```bash
# 1. Build the test server
(cd apps/http_fetch/priv/test_server && go build -o ../test_server/server .)

# 2. Start it in the background; capture the printed port
./apps/http_fetch/priv/test_server/server > .e2e_port &
PORT=$(grep -oE '[0-9]+' .e2e_port | head -n1)
export E2E_BASE_URL="http://127.0.0.1:$PORT"

# 3. Run the e2e suite
MIX_ENV=test mix test.e2e
```

In CI, the `e2e.yml` and `release.yml` workflows run the applicable E2E gates,
including the pinned Caddy TLS fingerprint fixture on CI runners.
`mix test.e2e` keeps execution at the umbrella root. To run one suite, use
`MIX_ENV=test mix test apps/http_web_socket/e2e` (or another app's `e2e`
directory) after the same preparation as the unit tests.

### Testing Packaged Consumers

```bash
bash scripts/external_consumer_smoke.sh
```

This builds all nine portable candidate archives (`ex_ssl`, `elixir_quic`,
`http_core`, `http_runtime`, `elixir_quic_http3`, `http_fetch`,
`http_web_socket`, `http_event_source`, and `http_web_transport`), serves them
from a signed local Hex registry with the locked `telemetry` tarball, and
resolves a temporary consumer through Hex without repository paths or overrides.
The smoke
checks runtime application startup, verified local TLS 1.3 requests with both
TCP TLS backends, exact dependency metadata, shared runtime startup, and the
unsupported WebTransport boundary. The public HTTP/3 artifact gate is tracked
separately in the acceptance record.
`python3 scripts/release/consumer_gate.py VERSION /absolute/path/to/archives`
checks each package independently; set
`EX_SSL_DEP_MODE=candidate EX_SSL_CANDIDATE_ARCHIVE_DIR=/absolute/path/to/archives`
and run `bash scripts/ex_ssl_source_smoke.sh` for the full candidate TLS feature
suite. The published `ex_ssl` 0.7.2 feature gate is historical compatibility
coverage. Replace `VERSION` with the coordinated version of the candidate
archives; candidate registry checks and published Hex checks are separate gates.

### Code Formatting

```bash
# Format all code
mix format

# Check formatting without changes
mix format --check-formatted
```

## Requirements

- Elixir 1.18+ (for built-in `JSON` module support)
- Erlang OTP with `:ssl` and `:public_key` applications

## License

MIT License

The candidate TLS feature gate runs all nine feature groups against the signed
local Hex registry. It requires the pinned fixture checkout specified by
`scripts/ex_ssl_fixture_manifest.env`. Current outcomes are tracked in
[migration validation](docs/migration-validation.md).

```bash
# From the umbrella root; this builds nine portable archives without publishing.
python3 scripts/release/stage.py build VERSION /tmp/http-fetch-stage /tmp/http-fetch-archives
EX_SSL_DEP_MODE=candidate EX_SSL_CANDIDATE_ARCHIVE_DIR=/tmp/http-fetch-archives \
  EX_SSL_RESULTS_DIR=/tmp/http-fetch-candidate bash scripts/ex_ssl_source_smoke.sh
```

The candidate gate checks `Hex.SCM`, exact package version, startup, and every
feature group. The published `ex_ssl` 0.7.2 gate remains a historical
compatibility check run from the pre-migration `v0.16.1` tag in CI; it cannot
validate this local nine-package graph. The separate scheduled/manual
compatibility workflow covers its existing Elixir/OTP matrix.
See [consumer validation evidence](docs/ex-ssl-consumer-validation.md) for exact
commands, results, provenance, and limits. Independent human security review is
incomplete; green tests do not establish broad production readiness or improved
performance. No connection pooling, automatic WebSocket reconnect, TLS 1.2/mTLS
resumption, persistent tickets, or 0-RTT support is implied.

## Response Content-Encoding

Network responses decode `gzip` and zlib-wrapped `deflate` automatically on
HTTP/1.1, HTTP/2 and HTTP/3, including streaming, JSON/text consumption and
`HTTP.Response.write_to/2`. To request compression explicitly:

```elixir
response =
  HTTP.fetch(url, headers: [{"accept-encoding", "gzip, deflate"}])
  |> HTTP.Promise.await()

{:ok, data} = HTTP.Response.json(response)
```

Decoding uses only `Content-Encoding`: npm `.tgz` archives without that header
retain their gzip bytes for integrity checks and extraction. Supported encoding
chains decode in reverse order; a chain containing any unsupported encoding
passes through entirely unchanged. The client does not add `Accept-Encoding`.

Server headers remain unchanged, so `Content-Length` describes encoded bytes,
not the decoded body size. Streaming selection also uses the encoded length.
Streams are consumed once and preserve backpressure and trailer ordering;
all response consumers see the same decoded bytes. Manually constructed
responses are not decoded.

For object storage and other byte-preserving consumers, disable decoding per
request with `decode_body: false`:

```elixir
response = HTTP.fetch(object_url, decode_body: false) |> HTTP.Promise.await()
stored_bytes = HTTP.Response.read_all(response)
```

This preserves the original entity bytes for buffered and streamed HTTP/1.1,
HTTP/2, and HTTP/3 responses, including gzip/deflate marked by `Content-Encoding`.
Headers, stream acknowledgements, cancellation, and request uploads retain their
usual behavior. HTTP framing (such as chunk boundaries) is still removed.

Malformed or truncated gzip/deflate produces
`{:error, {:invalid_content_encoding, coding}}` for buffered fetches and a
`:stream_error` for streamed bodies. Stream reading methods raise on that error;
`write_to/2` returns it and may leave a partial file. Raw deflate is rejected.
See `HTTP.Response` for the complete header and consumption contract.

### Request cleanup completion

For ownership and retirement of reusable transports across several requests, see
[managed transport generations](https://github.com/gsmlg-dev/http_fetch/blob/main/docs/managed-transports.md). Request completion
and generation retirement are separate barriers.

For an HTTP/1 request (including `http1_reuse: true`) or explicit HTTP/2
request with `redirect: :manual` (or `:error`), retain the original Promise's
completion handle before awaiting headers. The handle is created before the
request starts and is exposed on the original Promise. Another process can use
it, including during service drain:

```elixir
promise = HTTP.fetch(url,
  http_version: :http1,
  http1_reuse: false,
  redirect: :manual,
  stream_response: true
)
completion = HTTP.Promise.completion(promise)
response = HTTP.Promise.await(promise)

case HTTP.RequestCompletion.abort_and_await(completion, 1_000) do
  :ok -> :cleanup_confirmed
  {:error, :cleanup_pending} -> :retry_cleanup_wait_later
  {:error, :cleanup_unconfirmed} -> :cleanup_evidence_lost
end
```

`HTTP.RequestCompletion.await/2` waits without requesting cancellation. Both
operations accept a finite, nonnegative timeout in milliseconds (default 5,000),
covering the entire wait. A timeout leaves cleanup running; later waits can
confirm completion. Repeated and concurrent cancellation/waits are safe.

`:ok` requires the request owner, dial/write/upload helpers, attached streams,
and library-created enumerable producer to terminate. Dedicated transports
must close. A reusable HTTP/1 transport must be safely returned to its pool or
closed; an HTTP/2 request must release its stream, queued deliveries, and pool
reservation. Healthy shared connections and sibling streams remain open. A
response stream terminal event or DOWN alone does not prove this. Abnormal
owner/task termination or loss of the coordinator returns `:cleanup_unconfirmed`
when the cleanup evidence is insufficient. User-created producer processes are
owned by the caller and must respond to their stream's termination themselves.

The barrier supports direct TCP and the default OTP TLS backend, including TLS
handshake cancellation, explicit `:http1`, `:http2`, and direct `:h2c` selection.
Explicit proxies with the OTP TLS backend support the following routes, including
pending TCP connection, CONNECT and TLS negotiation, uploads, response streams,
and safe pooled return:

| Proxy | Origin | HTTP version |
| --- | --- | --- |
| `{:http, host, port, opts}` | HTTP | `:http1` (absolute-form forwarding) |
| `{:http, host, port, opts}` | HTTPS | `:http1` or `:http2` (CONNECT tunnel) |
| `{:https, host, port, opts}` | HTTP | `:http1` (TLS to proxy, absolute form) |

Proxy endpoint, authentication and TLS policy isolate pooled connections.
Proxy authorization is excluded from origin requests inside CONNECT tunnels.
For example, adding `proxy: {:http, "proxy.example", 3128, []}` to the example
above retains the same completion contract. HTTPS proxies to HTTPS origins
(nested TLS), proxy `:h2c`, ExSSL, Unix routes, redirects followed internally,
`:auto`, and HTTP/3 return
`{:error, {:unsupported_completion, reason}}`. Existing asynchronous
`HTTP.AbortController.abort/1` is unchanged; its cancellation can be followed by
`HTTP.RequestCompletion.await/2`. Chained promises return `nil` from
`HTTP.Promise.completion/1`; keep the original request's handle. Confirmation
covers local cleanup, not whether a remote application received earlier bytes.

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

## Features

- **Browser-like API**: Familiar fetch interface with promises and async/await patterns
- **Full HTTP support**: GET, POST, PUT, DELETE, PATCH, HEAD methods
- **Internal HTTP/1.1 transport**: Uses `:gen_tcp` for HTTP, selectable TLS for HTTPS, and Unix domain sockets
- **Unix Domain Sockets**: HTTP over Unix sockets for Docker daemon, systemd, and other local services
- **Form data support**: HTTP.FormData for multipart/form-data and file uploads
- **Streaming request bodies**: Fetch-style `duplex: "half"` uploads over HTTP/1.1
- **Type-safe configuration**: HTTP.FetchOptions for structured request configuration
- **Promise-based**: Async operations with chaining support
- **Request cancellation**: AbortController support for cancelling requests
- **Automatic JSON parsing**: Built-in JSON response handling
- **Selectable TLS**: OTP `:ssl` by default, with opt-in `:ex_ssl` for verified TLS 1.3
- **HTTP/2 wire profiles**: Versioned native and synthetic profiles can control
  ordered SETTINGS and header serialization; use `http2_profile` only with an
  explicit HTTP/2 or h2c request.

HTTP/2 profile support currently covers validated serialization and bounded
wire observation. It does not yet claim pooled multi-stream reuse or browser
fingerprint equivalence. Available profile IDs are `native_v1`,
`synthetic_test_v1`, and `synthetic_test_v2`.

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

`http_core` declares `ex_ssl ~> 0.4.0` as a transitive runtime dependency.
Consumers do not need to add it separately. `ssl: [...]` supplies TLS settings
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
Content-Length is forbidden on informational/204 responses and in trailers;
DATA or HEADERS after END_STREAM is rejected rather than completed again.
Truncation, required writes before completion, abnormal closure, cancellation
and timeout remain errors. The original deadline and streaming backpressure
are preserved.

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

ex_ssl 0.4.0 supports verified TLS 1.2 for
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
replaying request bytes. The package test checks two fresh HTTP/1.1 connections
against an independent OpenSSL peer and requires server-observed session reuse.
This is a bounded subset, not full OTP `:ssl` parity.

See the [ex_ssl compatibility contract](https://github.com/gsmlg-dev/ex_ssl/blob/v0.4.0/docs/COMPATIBILITY.md).
The [consumer contract inventory](docs/ex-ssl-consumer-contract.md) maps the
implemented subset and intentional restrictions to its tests.

Plain HTTP, WS, and Unix sockets retain their existing transports. HTTP/3 and
WebTransport use QUIC's separate TLS implementation and ignore the shared
setting. An explicit non-`nil` `tls_backend` on either QUIC API returns
`{:error, :tls_backend_not_supported_for_quic}` (through the promise for fetch).

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
```

Plain Elixir binaries are sent as text frames. Use `HTTP.WebSocket.array_buffer/1`
or `HTTP.Blob` for binary frames:

```elixir
:ok = HTTP.WebSocket.send(socket, "text")
:ok = HTTP.WebSocket.send(socket, HTTP.WebSocket.array_buffer(<<0, 1, 2>>))
:ok = HTTP.WebSocket.send(socket, HTTP.Blob.new(<<0, 1, 2>>))
:ok = HTTP.WebSocket.close(socket, 1000, "done")
```

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
HTTP.EventSource.close(source)
```

The client reconnects after dropped streams, honors `retry:` fields, and sends
`Last-Event-ID` after receiving event IDs. Elixir differences from the browser
API: invalid constructor input returns `{:error, reason}`, and events are
process messages instead of `EventTarget` callbacks.

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
        IO.puts("Starting request to #{metadata.url}")
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

In CI, the `e2e.yml` workflow handles all of this automatically.
`mix test.e2e` keeps execution at the umbrella root. To run one suite, use
`MIX_ENV=test mix test apps/http_web_socket/e2e` (or another app's `e2e`
directory) after the same preparation as the unit tests.

### Testing Packaged Consumers

```bash
bash scripts/external_consumer_smoke.sh
```

This builds all five current Hex packages and installs their unpacked contents
into a temporary project outside the umbrella, with independent dependencies
and build output and no repository lockfile. Local paths resolve the unpublished
internal packages; `ex_ssl` is resolved only through `http_core`. The smoke
checks runtime application startup, verified local TLS 1.3 requests with both
TCP TLS backends, and the separate WebTransport QUIC boundary.

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

For cross-repository source checks, the source integration gate is
`EX_SSL_SOURCE_DIR=/absolute/path/to/ex_ssl bash scripts/ex_ssl_source_smoke.sh`.
It validates algorithms, mTLS, TLS 1.2, and resumption against all five fresh
package artifacts with a temporary source override. Add
`EX_SSL_DEP_MODE=published` to resolve ex_ssl 0.4.0 from Hex while using the
source checkout only for test certificate fixtures. The external consumer smoke
also checks the published dependency; see
[the consumer contract](docs/ex-ssl-consumer-contract.md).

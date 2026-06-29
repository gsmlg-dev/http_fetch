# HTTP Fetch

 [![Elixir CI](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml)
 [![Elixir CI](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml)
 [![Hex.pm](https://img.shields.io/hexpm/v/http_fetch.svg)](https://hex.pm/packages/http_fetch)
 [![Hexdocs.pm](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/http_fetch/)
 [![Hex.pm](https://img.shields.io/hexpm/dt/http_fetch.svg)](https://hex.pm/packages/http_fetch)
 [![Hex.pm](https://img.shields.io/hexpm/dw/http_fetch.svg)](https://hex.pm/packages/http_fetch)

A modern HTTP client library for Elixir that provides a fetch API similar to web browsers, built on Erlang's built-in socket modules.

## Features

- **Browser-like API**: Familiar fetch interface with promises and async/await patterns
- **Full HTTP support**: GET, POST, PUT, DELETE, PATCH, HEAD methods
- **Internal HTTP/1.1 transport**: Uses `:gen_tcp` for HTTP, `:ssl` for HTTPS, and Unix domain sockets
- **Unix Domain Sockets**: HTTP over Unix sockets for Docker daemon, systemd, and other local services
- **Form data support**: HTTP.FormData for multipart/form-data and file uploads
- **Streaming file uploads**: Efficient large file uploads using streams
- **Type-safe configuration**: HTTP.FetchOptions for structured request configuration
- **Promise-based**: Async operations with chaining support
- **Request cancellation**: AbortController support for cancelling requests
- **Automatic JSON parsing**: Built-in JSON response handling
- **Zero dependencies**: Uses only Erlang/OTP built-in modules

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
response.body          # Response body binary
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

**Stream Handling**: Large responses use Elixir processes for streaming instead of ReadableStream.

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

# response.body contains the raw binary data
binary_data = response.body

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

# Form data with file upload

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

# response.body contains the raw binary response data
binary_data = response.body

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
- `transport_options`: Socket transport options such as `timeout`, `connect_timeout`, `ssl`,
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

```bash
# Run all unit tests
mix test

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

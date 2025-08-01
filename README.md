# HTTP Fetch

 [![Elixir CI](https://github.com/gsmlg-dev/http_fetch/actions/workflows/elixir.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/elixir.yml)
 [![Hex.pm](https://img.shields.io/hexpm/v/http_fetch.svg)](https://hex.pm/packages/phoenix_react_server)
 [![Hexdocs.pm](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/http_fetch/)
 [![Hex.pm](https://img.shields.io/hexpm/dt/http_fetch.svg)](https://hex.pm/packages/http_fetch)
 [![Hex.pm](https://img.shields.io/hexpm/dw/http_fetch.svg)](https://hex.pm/packages/http_fetch)

A modern HTTP client library for Elixir that provides a fetch API similar to web browsers, built on Erlang's built-in `:httpc` module.

## Features

- **Browser-like API**: Familiar fetch interface with promises and async/await patterns
- **Full HTTP support**: GET, POST, PUT, DELETE, PATCH, HEAD methods
- **Complete httpc integration**: Support for all :httpc.request options
- **Form data support**: HTTP.FormData for multipart/form-data and file uploads
- **Streaming file uploads**: Efficient large file uploads using streams
- **Type-safe configuration**: HTTP.FetchOptions for structured request configuration
- **Promise-based**: Async operations with chaining support
- **Request cancellation**: AbortController support for cancelling requests
- **Automatic JSON parsing**: Built-in JSON response handling
- **Zero dependencies**: Uses only Erlang/OTP built-in modules

## Quick Start

```elixir
# Simple GET request
{:ok, response} = 
  HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
  |> HTTP.Promise.await()

# Get response data
IO.puts("Status: #{response.status}")
text = HTTP.Response.text(response)
{:ok, json} = HTTP.Response.json(response)

# Read response body as raw binary
response = 
  HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
  |> HTTP.Promise.await()

# response.body contains the raw binary data
binary_data = response.body

# POST request with JSON
{:ok, response} = 
  HTTP.fetch("https://jsonplaceholder.typicode.com/posts", [
    method: "POST",
    headers: %{"Content-Type" => "application/json"},
    body: JSON.encode\!(%{title: "Hello", body: "World"})
  ])
  |> HTTP.Promise.await()
```

# Form data with file upload

```elixir
file_stream = File.stream!("document.pdf")
form = HTTP.FormData.new()
       |> HTTP.FormData.append_field("name", "John Doe")
       |> HTTP.FormData.append_file("document", "document.pdf", file_stream)

{:ok, response} = 
  HTTP.fetch("https://api.example.com/upload", [
    method: "POST",
    body: form
  ])
  |> HTTP.Promise.await()
```

## API Reference

### HTTP.fetch/2
Performs an HTTP request and returns a Promise.

```elixir
promise = HTTP.fetch(url, [
  method: "GET",
  headers: %{"Accept" => "application/json"},
  body: "request body",
  content_type: "application/json",
  options: [timeout: 10_000],
  signal: abort_controller
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
{:ok, response} = HTTP.Promise.await(promise)

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
{:ok, response} = 
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

### HTTP.Request
Request configuration struct.

```elixir
request = %HTTP.Request{
  method: :post,
  url: URI.parse("https://api.example.com/data"),
  headers: [{"Authorization", "Bearer token"}],
  body: "data",
  http_options: [timeout: 10_000, connect_timeout: 5_000],
  options: [sync: false, body_format: :binary]
}
```

**Field Mapping to :httpc.request/4:**
- `http_options`: 3rd argument (request-specific HTTP options)
- `options`: 4th argument (client-specific options)

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

## License

MIT License


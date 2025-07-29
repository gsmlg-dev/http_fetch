# HTTP Fetch

A modern HTTP client library for Elixir that provides a fetch API similar to web browsers, built on Erlang's built-in `:httpc` module.

## Features

- **Browser-like API**: Familiar fetch interface with promises and async/await patterns
- **Full HTTP support**: GET, POST, PUT, DELETE, PATCH, HEAD methods
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

# POST request with JSON
{:ok, response} = 
  HTTP.fetch("https://jsonplaceholder.typicode.com/posts", [
    method: "POST",
    headers: %{"Content-Type" => "application/json"},
    body: JSON.encode\!(%{title: "Hello", body: "World"})
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
```

### HTTP.Request
Request configuration struct.

```elixir
request = %HTTP.Request{
  method: :post,
  url: "https://api.example.com/data",
  headers: [{"Authorization", "Bearer token"}],
  body: "data"
}
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
EOF < /dev/null
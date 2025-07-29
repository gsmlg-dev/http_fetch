# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an Elixir project that implements a browser-like HTTP fetch API using Erlang's built-in `:httpc` module. It provides a Promise-based asynchronous interface with support for request cancellation via AbortController.

## Key Architecture

The codebase is structured around these core modules:

- **HTTP**: Main module providing the `fetch/2` function and Response struct
- **HTTP.Request**: Struct for building HTTP requests with proper conversion to `:httpc` arguments
- **HTTP.Response**: Struct representing HTTP responses with JSON/text parsing helpers  
- **HTTP.AbortController**: Agent-based request cancellation mechanism
- **HTTP.Promise**: Promise-like wrapper around Elixir Tasks for async operations with chaining support

## Development Commands

```bash
# Install dependencies
mix deps.get

# Run tests
mix test

# Run specific test
mix test test/http_test.exs:5

# Interactive development
iex -S mix

# Build the project
mix compile

# Format code
mix format

# Run in production mode
MIX_ENV=prod mix compile
```

## Key Usage Patterns

```elixir
# Basic fetch
promise = HTTP.fetch("https://api.example.com/data")
{:ok, response} = HTTP.Promise.await(promise)

# JSON parsing
case HTTP.Response.json(response) do
  {:ok, data} -> handle_data(data)
  {:error, reason} -> handle_error(reason)
end

# Promise chaining
HTTP.fetch("https://api.example.com/users")
|> HTTP.Promise.then(&HTTP.Response.json/1)
|> HTTP.Promise.then(fn {:ok, users} -> process_users(users) end)
|> HTTP.Promise.await()

# Request cancellation
controller = HTTP.AbortController.new()
promise = HTTP.fetch("https://slow-api.example.com", signal: controller)
HTTP.AbortController.abort(controller)  # Cancel the request
```

## Important Notes

- Requires Elixir 1.18+ for built-in JSON support
- Uses `:inets` and `:httpc` from Erlang's standard library
- All HTTP operations are asynchronous by default (sync: false)
- Request timeout defaults to 120 seconds
- Content-Type defaults to "application/octet-stream" for requests with bodies
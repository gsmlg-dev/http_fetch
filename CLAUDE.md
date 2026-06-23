# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an Elixir library providing a browser-like HTTP fetch API built on Erlang's `:gen_tcp` and `:ssl` modules. It implements Promise-based async operations with request cancellation, streaming support, and comprehensive telemetry integration.

## Core Architecture

### Main Modules
- **HTTP** (`lib/http.ex`): Entry point providing `fetch/2` function. Handles async request execution via Task.Supervisor, response processing (including streaming detection), and telemetry event emission
- **HTTP.Promise** (`lib/http/promise.ex`): JavaScript-like Promise implementation wrapping Task with chaining via `then/3` and `await/2`
- **HTTP.Request** (`lib/http/request.ex`): Request configuration struct that serializes to HTTP/1.1 wire iodata
- **HTTP.HTTP1** (`lib/http/http1.ex`): Pure HTTP/1.1 serializer and response parser for status, headers, Content-Length, chunked bodies, and read-to-close bodies
- **HTTP.SocketClient** (`lib/http/socket_client.ex`): Socket owner process for one request lifecycle, including TCP/TLS/Unix transport selection, redirects, streaming, deadlines, and aborts
- **HTTP.Response** (`lib/http/response.ex`): Response struct with `json/1`, `text/1`, and `write_to/2` methods. Handles both buffered and streamed responses
- **HTTP.Headers** (`lib/http/headers.ex`): Headers manipulation with case-insensitive operations, Content-Type parsing, and default User-Agent support
- **HTTP.FormData** (`lib/http/form_data.ex`): Multipart/form-data encoding with streaming file upload support
- **HTTP.AbortController** (`lib/http/abort_controller.ex`): Request cancellation via Agent-based controller
- **HTTP.FetchOptions** (`lib/http/fetch_options.ex`): Options processing and validation for `fetch/2`
- **HTTP.Telemetry** (`lib/http/telemetry.ex`): Comprehensive telemetry events for requests, responses, streaming, and errors

### Application Structure
- **HTTPFetch.Application** (`lib/http_fetch.ex`): Supervision tree with `:http_fetch_task_supervisor` Task.Supervisor and HTTP.AbortController Registry

### Key Design Patterns
1. **Async by default**: All requests use Task.Supervisor with `async_nolink/4`
2. **Streaming threshold**: Responses >5MB or with unknown Content-Length automatically stream via `HTTP.Stream`
3. **Telemetry instrumentation**: All operations emit `:telemetry` events (`:http_fetch` prefix) for monitoring and observability
4. **Error propagation**: Expected transport and parser failures return `{:error, reason}` tuples for consistent API behavior

## Development Commands

```bash
# Install dependencies
mix deps.get

# Run all tests
mix test

# Run specific test file
mix test test/http_test.exs

# Run specific test by line number
mix test test/http_test.exs:42

# Interactive development with application started
iex -S mix

# Compile project
mix compile

# Format all code
mix format

# Check formatting without making changes
mix format --check-formatted

# Run Credo code analysis (standard checks)
mix credo

# Run Credo with strict mode (includes readability checks)
mix credo --strict

# Explain a specific Credo issue
mix credo explain <issue_category>

# Run Dialyzer type checking
mix dialyzer

# Generate/rebuild Dialyzer PLT (takes 2-3 minutes)
mix dialyzer --plt

# Build documentation
mix docs

# Production build
MIX_ENV=prod mix compile
```

## Important Implementation Details

### Request Options Mapping
- `fetch/2` accepts flat fetch init options. Use `method`, `headers`, `body`, `signal`, and `redirect` for browser-style options.
- Socket transport extensions are also flat: `timeout`, `connect_timeout`, `ssl`, `socket_opts`, and `unix_socket`.

### Streaming Behavior
- Automatic streaming for responses >5MB or unknown Content-Length
- Stream process receives decoded body chunks from the socket owner
- Stream messages: `{:stream_chunk, pid, data}`, `{:stream_end, pid}`, `{:stream_error, pid, reason}`

### Response Body Handling
- `HTTP.Response.write_to/2` handles both buffered (direct binary write) and streamed responses (receive loop)
- Streamed responses have `body: nil` and `stream: pid`

### Telemetry Events
All events use `[:http_fetch, ...]` prefix:
- `[:request, :start]` - measurements: `start_time`; metadata: `method`, `url`, `headers`
- `[:request, :stop]` - measurements: `duration`, `status`, `response_size`; metadata: `url`, `status`
- `[:request, :exception]` - measurements: `duration`; metadata: `url`, `error`
- `[:streaming, :start]`, `[:streaming, :chunk]`, `[:streaming, :stop]` - for streaming operations

## Dependencies
- **telemetry** (~> 1.0): Event emission for observability
- **briefly** (~> 0.4): Test-only dependency for temporary files
- **ex_doc**: Dev-only for documentation generation
- **credo** (~> 1.7): Dev/test-only for static code analysis
- **dialyxir** (~> 1.4): Dev/test-only for Dialyzer integration and type checking

## Code Quality Tools

### Credo
Credo performs static code analysis to enforce Elixir style guidelines and identify code smells. Configuration in `.credo.exs`.

Current known issues to address:
- Code readability: Number formatting (use underscores for large numbers), sigil usage, alias ordering
- Refactoring: Use `Enum.map_join/3` instead of `Enum.map/2 |> Enum.join/2`, reduce function complexity and nesting depth
- Warnings: Struct specifications in `@spec` declarations

### Dialyzer
Dialyzer performs static type analysis to catch type errors and inconsistencies. PLT (Persistent Lookup Table) stored in `priv/plts/dialyzer.plt`.

Current known issues to address:
- `HTTP.fetch/2`: Spec doesn't match success typing due to Task.Supervisor return inference
- `HTTP.Promise.then/3`: Opaque type violations with Task struct

## Requirements
- Elixir 1.18+ (for built-in `JSON` module support)
- Erlang OTP with `:ssl` and `:public_key` applications

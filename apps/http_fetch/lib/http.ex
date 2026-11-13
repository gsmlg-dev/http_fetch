defmodule HTTP do
  @moduledoc """
  A browser-like HTTP fetch API for Elixir, built on Erlang's `:gen_tcp`, the
  independent `ex_ssl` TLS engine, and the shared QUIC HTTP/3 transport.

  This module provides a modern, Promise-based HTTP client interface similar to the
  browser's `fetch()` API. It supports asynchronous requests, streaming, request
  cancellation, and comprehensive telemetry integration.

  ## Features

  - **Async by default**: All requests use Task.Supervisor with `async_nolink/4`
  - **Automatic streaming**: Responses >5MB or with unknown Content-Length automatically stream
  - **Request streaming**: Pass an `HTTP.Stream` PID as `body` with `duplex: "half"` for HTTP/1.1 or HTTP/2 uploads
    Supply a `Content-Length` header for a known-length stream; HTTP/1.1 sends raw
    body bytes, and both protocols reject a stream whose size differs from the header.
    HTTP/1.1 streams without a declared length use chunked transfer encoding.
  - **Request cancellation**: Via `HTTP.AbortController` for aborting in-flight requests
  - **Promise chaining**: JavaScript-like promise interface with `then/3` support
  - **Unix Domain Sockets**: Support for HTTP over Unix sockets (Docker daemon, systemd, etc.)
  - **Telemetry integration**: Comprehensive event emission for monitoring and observability
  - **HTTP/3 opt-in**: Pass `http_version: :http3` for QUIC-backed HTTP/3 requests

  ## Quick Start

      # Simple GET request
      response =
        HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
        |> HTTP.Promise.await()

      # Parse JSON response
      {:ok, json} = HTTP.Response.json(response)

      # POST with JSON body
      response =
        HTTP.fetch("https://api.example.com/posts", [
          method: "POST",
          headers: %{"Content-Type" => "application/json"},
          body: JSON.encode!(%{title: "Hello", body: "World"})
        ])
        |> HTTP.Promise.await()

      # Unix Domain Socket request (e.g., Docker daemon)
      response =
        HTTP.fetch("http://localhost/version",
          unix_socket: "/var/run/docker.sock")
        |> HTTP.Promise.await()

  ## Architecture

  The library is structured around these core modules:

  - `HTTP` - Main entry point with the `fetch/2` function
  - `HTTP.Promise` - Promise wrapper around Tasks for async operations
  - `HTTP.Request` - Request configuration struct
  - `HTTP.Response` - Response struct with JSON/text parsing helpers
  - `HTTP.Stream` - Process-backed stream for response bodies and streaming uploads
  - `HTTP.Headers` - Header manipulation utilities
  - `HTTP.FormData` - Multipart/form-data encoding with file upload support
  - `HTTP.AbortController` - Request cancellation mechanism
  - `HTTP.FetchOptions` - Options processing and validation
  - `HTTP.Telemetry` - Telemetry event emission for monitoring

  ## Streaming Behavior

  Responses are automatically streamed when:

  - Content-Length > 5MB
  - Content-Length header is missing/unknown

  Streaming responses expose the stream PID in `body`.
  Use `HTTP.Response.read_all/1` or `HTTP.Response.write_to/2` to consume streams.

  ## Error reasons

  HTTP error statuses are ordinary responses. Invalid options raise
  `ArgumentError` before a request starts. Other failures are reason terms:
  `{:error, reason}` from `HTTP.Promise.await/2`, `{:stream_error, stream_pid,
  reason}` to a direct stream reader, `{:error, reason}` from
  `HTTP.Response.json/1`, `read_as_json/1` and `write_to/2`, or the `reason` of an
  `HTTP.ResponseError` raised by the other `HTTP.Response` body readers. With
  `error_mode: :structured`, pre-response reasons are wrapped in
  `%HTTP.RequestError{reason: reason}`.

  Phases: *connect* (DNS, TCP, TLS or QUIC setup), *request* (sending the request
  and waiting for the response head), *body* (streamed response or upload
  delivery) and *await* (the caller's own wait). Reasons marked "any" can occur in
  every request phase.

  | Reason | When | Phase |
  | --- | --- | --- |
  | `:timeout` | The request `timeout:` deadline expired. Also an expired socket send timeout, response stream idle/acknowledgement limit or reader wait. | any |
  | `:await_timeout` | `HTTP.Promise.await/2`'s own wait expired. The request continues and the promise can be awaited again. | await |
  | `:connect_timeout` | `connect_timeout:` expired before the connection (including TLS/QUIC) was established. | connect |
  | `:read_idle_timeout`, `:write_idle_timeout` | An HTTP/1 `read_idle_timeout` / `write_idle_timeout` expired. | request, body |
  | `:aborted` | The request's `HTTP.AbortController` was aborted. | any |
  | `:econnrefused`, `:nxdomain`, `:ehostunreach`, `:enetunreach`, `:econnreset`, ... | Socket/DNS errors from `:gen_tcp` and `:inet`. | connect, request, body |
  | `{:tls_alert, {alert, detail}}` | TLS handshake or certificate verification failed. | connect |
  | `{:options, detail}` | The `ssl` options were rejected by the TLS engine. | connect |
  | `:closed` | The peer closed the connection before a complete response. | request, body |
  | `:redirect` | A redirect was received with `redirect: :error`. | request |
  | `:too_many_redirects` | More than 20 redirects were followed. | request |
  | `:streaming_body_redirect_not_replayable` | A 307/308 would replay a streamed (`duplex: :half`) body. | request |
  | `:invalid_http_response`, `:invalid_status_line`, `:invalid_response_headers`, `:invalid_content_length`, `:conflicting_response_framing`, `{:unsupported_transfer_encoding, coding}` | A malformed HTTP/1 response head or framing. | request |
  | `:content_length_mismatch` | The body length differs from its `Content-Length` (response or upload). | body |
  | `{:invalid_content_encoding, coding}`, `:decoded_body_too_large` | A `gzip`/`deflate` body is malformed or decodes past the limit. | body |
  | `:http2_informational_limit`, `:http2_trailers_limit` | HTTP/2 informational or trailer retention budgets were exceeded. | request, body |
  | `{:stream_reset, code}`, `:protocol_error`, `:flow_control_error`, ... | HTTP/2 stream reset or protocol violation. | request, body |
  | `{:goaway, last_stream_id, error_code, :unprocessed}`, `{:stream_reset, :refused_stream}`, `:draining` | The server did not process the HTTP/2 request (above a GOAWAY last-stream-id, `REFUSED_STREAM`, or a draining pooled connection) and it was not replayed: `http2_unprocessed_retry: false`, a streamed body, or three connection attempts exhausted. | request |
  | `{:http3_error, scope, code, reason}` | HTTP/3 stream or connection error. | request, body |
  | `{:connection_owner_down, reason}` | The shared HTTP/2 or HTTP/3 connection owner exited. | request, body |
  | `{:proxy_connect_status, status}`, `:proxy_tunnel_timeout`, `:invalid_proxy_response` | An explicit proxy refused or failed the CONNECT tunnel. | connect |
  | `:unknown_pool`, `:stale_pool`, `{:invalid_pool_option, key, why}` | A `pool:` selection is unknown, restarted, or incompatible with the request. | request |
  | `{:invalid_adapter, why}` | An `adapter:` is missing callbacks or returned an invalid result. | request |
  | `{:stream_down, reason}` | A response or upload stream process exited. | body |
  | `{:source_failure, kind, reason}` or the raised exception | An `HTTP.Stream.from_enumerable/2` upload source raised or threw. | body |

  Other protocol-specific reasons may be returned; match on the rows above and
  treat any other term as a request failure.

  ## Telemetry Events

  All events use the `[:http_fetch, ...]` prefix:

  - `[:http_fetch, :request, :start]` - Request initiated
  - `[:http_fetch, :request, :stop]` - Request completed
  - `[:http_fetch, :request, :exception]` - Request failed
  - `[:http_fetch, :request, :retry]` - A `retry:` policy or a transparent
    HTTP/2 replay (`source: :http2_unprocessed`) starts another attempt
  - `[:http_fetch, :streaming, :start]` - Streaming started
  - `[:http_fetch, :streaming, :chunk]` - Stream chunk received
  - `[:http_fetch, :streaming, :stop]` - Streaming completed

  See `HTTP.Telemetry` for detailed event documentation.
  """

  alias HTTP.Promise
  alias HTTP.Request
  alias HTTP.Response

  @attempt_cleanup_budget 5_000

  @doc """
  Performs an HTTP request, similar to `global.fetch` in web browsers.
  Uses an internal socket transport (HTTP/1.1 by default; HTTP/2 and HTTP/3 by option) asynchronously.

  Arguments:
    - `url`: The URL to fetch (string or URI struct).
    - `init`: An optional keyword list or map of options for the request.
              Supported options:
                - `:method`: The HTTP method (e.g., "GET", "POST"). Defaults to "GET".
                             Can be a string or an atom (e.g., "GET" or :get).
                - `:proxy`: Explicit proxy `{:http, host, port, opts}` or `{:https, host, port, opts}`. Options are
                            proxy-only authorization headers and a bounded timeout.
                            HTTP/1 forwards cleartext requests; HTTPS uses CONNECT
                            before origin TLS and HTTP/1 or HTTP/2 negotiation.
                - `:headers`: A list of request headers as `{name, value}` tuples (e.g., [{"Content-Type", "application/json"}])
                              or a map that will be converted to the tuple format.
                - `:body`: The request body. Buffered bodies may be binary or iodata; streaming
                           bodies may be an `HTTP.Stream` PID when `duplex: "half"` is set.
                - `:request_mode`: `:fetch` (default) or `:proxy`. Proxy mode preserves
                                   request bodies for all admitted methods, including GET,
                                   DELETE, and HEAD. HEAD response bodies remain empty.
                                   Proxy mode adds no default `User-Agent`; a caller-supplied
                                   one is sent unchanged.
                - `:duplex`: Set to `:half` or `"half"` to enable Fetch-style request body streaming.
                             HTTP/1.1 uses chunked framing; HTTP/2 and HTTP/3 use flow-controlled DATA frames.
                - `:content_type`: The Content-Type header value. If not provided for methods with body,
                                   defaults to "application/octet-stream" when a body is present.
                - `:redirect`: Redirect mode, one of `:follow`, `:manual`, or `:error`. Defaults to `:follow`.
                - `:signal`: An `HTTP.AbortController` PID. If provided, the request can be aborted
                             via this controller.
                - `:http_version`: `:http1`, `:http2`, `:http3`, `:h2c`, or `:auto`.
                - `:timeout`, `:connect_timeout`, `:ssl`, and `:socket_opts`: Elixir-specific transport
                  extensions used by the socket or QUIC transport.
                - `:connect_address`: Caller-validated IPv4/IPv6 tuple, preserving the URL authority/TLS hostname. Requires manual/error redirects.
                - `:unix_socket`: Path to a Unix Domain Socket file (e.g., "/var/run/docker.sock").
                                  When provided, the request is sent over the Unix socket instead of TCP/IP.
                - `:retry`, `:max_retries`, `:retry_delay`: Opt-in request-scoped retry policy;
                  see "Retries" below. Defaults to `retry: false` (exactly one attempt).

  Returns:
    - `%HTTP.Promise{}`: A Promise struct. The caller should `HTTP.Promise.await(promise_struct)` to get the final
                 `%HTTP.Response{}` or `{:error, reason}`. Transport and protocol failures are delivered
                 in the awaited result. Invalid options raise
                 `ArgumentError` in the caller before any request starts.

  The socket transport defaults `redirect` to `:follow`; pass `redirect: :manual`
  to return redirect responses, or `redirect: :error` to fail on redirect. Following stops
  after 20 redirects (the Fetch limit): the next redirect returns
  `{:error, :too_many_redirects}` on HTTP/1, HTTP/2 and HTTP/3, and a 307/308 that would
  replay a streamed (`duplex: :half`) body returns
  `{:error, :streaming_body_redirect_not_replayable}`. Request timeout handling
  gives the internal socket owner up to one additional second to report its timeout before the
  awaiting caller aborts it. For HTTP/1, HTTP/2 and HTTP/3, `timeout: :infinity`
  removes the total request deadline, including response body reads. `connect_timeout`
  independently bounds connection establishment (including TLS); it accepts `:infinity`
  and defaults to at most 30 seconds. HTTP/3 QUIC handshakes stay finite and use the
  default 5,000 ms opening budget for `connect_timeout: :infinity`. The total request deadline still caps a longer
  connection timeout. `HTTP.Promise.await/2` has its own independent wait timeout.
  Cancellation and caller/reader cleanup remain active for infinite requests.
  Stream idle and chunk acknowledgement timeouts, explicit socket send timeouts,
  and proxy timeouts remain separate limits. ExSSL streaming uploads require a
  finite per-write send timeout; when absent, an infinite request uses
  `HTTP.Config.default_request_timeout/0` for that limit. Managed transport scopes
  require finite, positive request and connection timeouts.

  `read_idle_timeout` and `write_idle_timeout` are independent positive millisecond
  limits for HTTP/1 requests (TCP and ExSSL). They default to
  `nil`; automatic protocol selection, HTTP/2, HTTP/3 and managed transport scopes
  are unsupported. Read idle measures armed response reads and resets on nonempty
  transport data, pausing during consumer acknowledgement backpressure. Write
  idle bounds each transport write of at most 16 KiB and resets before the next
  write; successful transport acceptance does not establish peer receipt. Waiting
  for the upload producer does not consume the write budget. Expiry reports
  `:read_idle_timeout` or `:write_idle_timeout`, with existing structured-error
  wrapping before response delivery and stream errors afterwards. Overall and
  connection deadlines, socket send limits and cancellation remain independent.

  `response_stream_idle_timeout` sets a per-request response-body inactivity
  policy for ordinary HTTP/1 (TCP and ExSSL). It accepts positive
  milliseconds up to 4_294_967_295 or `:infinity`; `nil` keeps the existing global
  stream timeout. Set it to `:infinity` to leave network stalls to
  `read_idle_timeout` or to allow uncapped response reads. Response convenience
  readers follow this policy. Consumer chunk acknowledgement budgets, total
  deadlines, cancellation and owned cleanup remain independent. Automatic/H2/H3
  protocols and managed transport scopes reject an explicit policy.

  `response_stream_ack_timeout` sets a separate ordinary HTTP/1 response
  consumer delivery/acknowledgement deadline in positive milliseconds up to
  4_294_967_295 or `:infinity`; omitted/nil retains the global streaming-operation
  limit. Both the Stream and socket producer use this policy. Network inactivity,
  total request deadlines, cancellation and reader cleanup stay independent.
  Automatic/H2/H3 protocols and managed scopes reject explicit values; upload
  sources retain their existing policy.

  For an ordinary HTTP/1 fixed-length stream upload, a response after the final
  declared bytes waits for source completion, including enumerable resource
  finalization, under a finite completion budget capped by the total deadline.
  Source/finalizer exceptions fail the request even if the peer sent success.
  Cancellation or expiry may forcibly stop the source; process termination alone
  does not certify callback completion.

  ## Retries

  `retry:` opts in to retrying one `fetch/2` call. Invalid values raise `ArgumentError`.

  - `false` (default) - exactly one attempt.
  - `:safe_transient` - retries only attempts that received no response:
    `:econnrefused`, `:connect_timeout`, `:closed`, `:econnreset`,
    `:ehostunreach` and `:enetunreach`. A status the server chose to send is
    never retried.
  - `:transient` - the `:safe_transient` failures plus 408, 429, 500, 502, 503
    and 504 responses.
  - `fun(request, response_or_error)` - returns a boolean for each attempt's
    `%HTTP.Response{}` or `{:error, reason}`, overriding classification and the
    method rule. Any other return raises `ArgumentError` in the request worker,
    which exits the awaiting caller.

  Built-in modes retry only idempotent methods: GET, HEAD, OPTIONS, PUT, DELETE
  and TRACE. `max_retries` is the number of additional attempts, a
  non-negative integer defaulting to 3. `retry_delay` is milliseconds to wait
  before each retry, either a non-negative integer or a function receiving the
  1-based number of the attempt being retried. The default is exponential,
  `500 * 2 ** (n - 1)` capped at 10,000 ms (500, 1000, 2000, ...). A 429 or
  503 response with a valid `Retry-After` (delta-seconds or HTTP-date) uses
  that delay instead.

  These rules apply even to a custom function. A request whose body is a
  streamed `HTTP.Stream` (`duplex: :half`) is never replayed. A failure of
  `:aborted` or `:timeout` is never retried. An aborted `signal` also
  cancels a pending retry delay, returning `{:error, :aborted}`. The returned
  response is final; a retried response's unread streamed body is cancelled
  and its connection closed before the next attempt. One `timeout` deadline
  covers every attempt and delay: each later attempt receives the remaining
  budget. When a delay would reach the deadline, Fetch returns the last
  result instead of waiting.

  Each `HTTP.Adapter` attempt calls `execute/3` again. `HTTP.Test` fixtures
  therefore claim one expectation per attempt. Telemetry emits
  `[:http_fetch, :request, :retry]` before each retry, while request
  start/stop/exception stay one per call (see `HTTP.Telemetry`). With retry
  enabled, `HTTP.Promise.completion/1` reports `{:unsupported_completion,
  :retry}`, and `transport_scope` is rejected because a managed admission
  covers one attempt.

      HTTP.fetch(url, retry: :transient, max_retries: 2, timeout: 10_000)
      |> HTTP.Promise.await()

  Example Usage:

      # GET request and awaiting JSON
      promise_json = HTTP.fetch("https://jsonplaceholder.typicode.com/todos/1")
      case HTTP.Promise.await(promise_json) do
        %HTTP.Response{} = response ->
          case HTTP.Response.json(response) do
            {:ok, json_body} ->
              IO.puts "GET JSON successful! Title: \#{json_body["title"]}"
            {:error, reason} ->
              IO.inspect reason, label: "JSON Parse Error"
          end
        {:error, reason} ->
          IO.inspect reason, label: "GET Error for JSON"
      end

      # GET request and awaiting text
      promise_text = HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
      case HTTP.Promise.await(promise_text) do
        %HTTP.Response{} = response ->
          text_body = HTTP.Response.text(response)
          IO.puts "GET Text successful! First 50 chars: \#{String.slice(text_body, 0, 50)}..."
        {:error, reason} ->
          IO.inspect reason, label: "GET Error for Text"
      end

      # Simple Promise chaining: fetch -> parse JSON -> print title
      HTTP.fetch("https://jsonplaceholder.typicode.com/todos/2")
      |> HTTP.Promise.then(fn %HTTP.Response{} = response ->
        HTTP.Response.json(response)
      end)
      |> HTTP.Promise.then(fn {:ok, json_body} ->
        IO.puts "Chained JSON successful! Title: \#{json_body["title"]}"
      end)
      |> HTTP.Promise.await() # Await the final chained promise to ensure execution

      # Promise chaining with error handling. HTTP error statuses such as 404
      # still resolve with a response; the error callback handles request failures.
      HTTP.fetch("http://127.0.0.1:1/unreachable") # The connection will be refused
      |> HTTP.Promise.then(
        fn %HTTP.Response{} = response ->
          IO.puts "This success branch is not called for a failed connection"
          HTTP.Response.json(response)
        end,
        fn reason ->
          IO.inspect reason, label: "Chained Error Handler Caught"
          {:error, :handled_error} # Return an error tuple to propagate rejection
        end
      )
      |> HTTP.Promise.await() # Await the final chained promise

      # Chaining where a callback returns another promise
      HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
      |> HTTP.Promise.then(fn %HTTP.Response{} = response ->
        # Simulate fetching comments for the post
        post_id = case HTTP.Response.json(response) do
          {:ok, %{"id" => id}} -> id
          _ -> nil
        end
        if post_id do
          IO.puts "Fetched post \#{post_id}. Now fetching comments..."
          HTTP.fetch("https://jsonplaceholder.typicode.com/posts/\#{post_id}/comments")
        else
          # Returning an error tuple rejects this branch of the promise chain
          {:error, :post_id_not_found}
        end
      end)
      |> HTTP.Promise.then(fn comments_response ->
        case HTTP.Response.json(comments_response) do
          {:ok, comments} ->
            IO.puts "Successfully fetched \#{length(comments)} comments for the post."
          {:error, reason} ->
            IO.inspect reason, label: "Failed to parse comments JSON"
        end
      end)
      |> HTTP.Promise.await()


      # POST request with JSON body and headers
      # If you're using Elixir 1.18+, JSON.encode! is built-in. Otherwise, you'd need a library like Poison.
      # promise_post = HTTP.fetch("https://jsonplaceholder.typicode.com/posts",
      #        method: "POST",
      #        headers: [{"Accept", "application/json"}],
      #        content_type: "application/json",
      #        body: JSON.encode!(%{title: "foo", body: "bar", userId: 1})
      #      )
      # case HTTP.Promise.await(promise_post) do
      #   %HTTP.Response{status: 201, body: body} ->
      #     IO.puts "POST successful! Body: \#{body}"
      #   {:error, reason} ->
      #     IO.inspect reason, label: "POST Error"
      # end

      # Request with a longer timeout
      delayed_promise = HTTP.fetch("https://httpbin.org/delay/5", timeout: 10_000)
      case HTTP.Promise.await(delayed_promise) do
        %HTTP.Response{status: status} ->
          IO.puts "Delayed request successful! Status: \#{status}"
        {:error, reason} ->
          IO.inspect reason, label: "Delayed Request Result"
      end

      # Abortable request example
      controller = HTTP.AbortController.new() # Create a new controller
      IO.puts "Fetching a long request that will be aborted..."
      abortable_promise = HTTP.fetch("https://httpbin.org/delay/10", signal: controller, timeout: 20_000)

      # Simulate some work, then abort after a short delay
      Task.start_link(fn ->
        :timer.sleep(2000) # Wait 2 seconds
        IO.puts "Attempting to abort the request after 2 seconds..."
        HTTP.AbortController.abort(controller)
      end)

      # Await the result of the abortable promise
      case HTTP.Promise.await(abortable_promise) do
        %HTTP.Response{status: status} ->
          IO.puts "Abortable request completed successfully! Status: \#{status}"
        {:error, reason} ->
          IO.inspect reason, label: "Abortable Request Result"
          if reason == :aborted or reason == :timeout do
            IO.puts "Request was likely aborted. Reason: \#{inspect(reason)}"
          end
      end

      # Unix Domain Socket request to Docker daemon
      docker_promise = HTTP.fetch("http://localhost/version", unix_socket: "/var/run/docker.sock")
      case HTTP.Promise.await(docker_promise) do
        %HTTP.Response{status: 200} = response ->
          case HTTP.Response.json(response) do
            {:ok, json} ->
              IO.puts "Docker Version: \#{json["Version"]}"
              IO.puts "API Version: \#{json["ApiVersion"]}"
            {:error, reason} ->
              IO.inspect reason, label: "JSON Parse Error"
          end
        {:error, reason} ->
          IO.inspect reason, label: "Docker Request Error"
      end
  """
  @spec fetch(String.t() | URI.t(), Keyword.t() | map()) :: HTTP.Promise.t()
  def fetch(url, init \\ []) do
    uri = if is_binary(url), do: URI.parse(url), else: url
    options = HTTP.FetchOptions.new(init)

    request = %Request{
      url: uri,
      method: HTTP.FetchOptions.get_method(options),
      request_mode: options.request_mode,
      headers: request_headers(options),
      body: HTTP.FetchOptions.get_body(options),
      duplex: HTTP.FetchOptions.get_duplex(options),
      content_type: HTTP.FetchOptions.get_content_type(options),
      transport_options: HTTP.FetchOptions.to_transport_options(options)
    }

    # Extract AbortController PID and unix_socket from FetchOptions
    abort_controller_pid = options.signal
    unix_socket_path = options.unix_socket
    retry = HTTP.FetchOptions.retry_policy(options)

    # Emit telemetry event for request start
    if HTTP.Telemetry.enabled?(options.telemetry),
      do: HTTP.Telemetry.request_start(request.method, request.url, request.headers)

    adapter = HTTP.Adapter.prepare(request, options.adapter)

    preparation =
      case adapter do
        {:ok, nil} ->
          with {:ok, bound} <- HTTP.Runtime.Pool.prepare(request, init),
               do: HTTP.ManagedTransport.prepare(bound, init)

        {:ok, _context} ->
          {:ok, request}

        {:error, _} = error ->
          error
      end

    request =
      case preparation do
        {:ok, prepared} -> prepared
        _ -> request
      end

    options = %{
      options
      | http_version: request.transport_options[:http_version]
    }

    completion = HTTP.RequestCompletion.new(options, request)
    tracker = HTTP.RequestCompletion.tracker(completion)

    association =
      case preparation do
        {:ok, _} ->
          if adapter == {:ok, nil},
            do: HTTP.ManagedTransport.associate(request, tracker),
            else: :ok

        error ->
          error
      end

    request = %{
      request
      | transport_options: Keyword.put(request.transport_options, :request_lifecycle, tracker)
    }

    # Bind the task before releasing it, including cancellation before startup.
    calling_pid = self()

    task =
      HTTP.RequestLifecycle.launch(tracker, fn ->
        Task.Supervisor.async_nolink(
          :http_fetch_task_supervisor,
          fn ->
            launch_monitor = Process.monitor(calling_pid)

            receive do
              :request_launch ->
                Process.demonitor(launch_monitor, [:flush])
                Process.put(HTTP.RequestLifecycle, tracker)

                run_prepared_request(
                  request,
                  abort_controller_pid,
                  unix_socket_path,
                  adapter,
                  association,
                  tracker,
                  retry
                )

              {:DOWN, ^launch_monitor, :process, ^calling_pid, _reason} ->
                exit(:request_launch_abandoned)
            end
          end
        )
      end)

    # Wrap the task in our new Promise struct
    HTTP.RequestLifecycle.register(tracker, task.pid, :task)
    send(task.pid, :request_launch)
    %Promise{task: task, completion: completion}
  end

  # Proxy mode relays the caller's fields as given and adds no User-Agent.
  defp request_headers(%HTTP.FetchOptions{request_mode: :proxy} = options),
    do: HTTP.FetchOptions.get_headers(options)

  defp request_headers(options) do
    options
    |> HTTP.FetchOptions.get_headers()
    |> HTTP.Headers.set_default("User-Agent", HTTP.Headers.user_agent(:http_fetch))
  end

  defp run_prepared_request(
         request,
         abort_controller_pid,
         unix_socket_path,
         adapter,
         association,
         tracker,
         retry
       ) do
    admission =
      with :ok <- association,
           :ok <- attach_upload(tracker, request),
           do:
             if(adapter == {:ok, nil},
               do: HTTP.ManagedTransport.admit(request, tracker),
               else: :ok
             )

    result =
      case admission do
        :ok ->
          handle_async_request(
            request,
            self(),
            abort_controller_pid,
            unix_socket_path,
            elem(adapter, 1),
            retry
          )

        {:error, reason} ->
          {:error, public_reason(reason)}

        error ->
          error
      end

    stop_failed_upload(result, request.body)
    if match?({:error, _}, result), do: HTTP.RequestLifecycle.abort(tracker)

    HTTP.RequestLifecycle.complete(
      tracker,
      request.transport_options[:managed_deadline_at]
    )

    result
  end

  defp attach_upload(tracker, %{body: body} = request) when is_pid(body),
    do:
      HTTP.RequestLifecycle.attach_stream(
        tracker,
        body,
        request.transport_options[:managed_deadline_at]
      )

  defp attach_upload(_, _), do: :ok

  # Internal function, not part of public API
  @doc false
  @spec handle_async_request(
          Request.t(),
          pid(),
          pid() | nil,
          String.t() | nil,
          term(),
          HTTP.Retry.t() | nil
        ) :: Response.t() | {:error, term()}
  def handle_async_request(
        request,
        _calling_pid,
        abort_controller_pid,
        unix_socket_path \\ nil,
        adapter_context \\ nil,
        retry \\ nil
      ) do
    start_time = System.monotonic_time(:microsecond)

    attempts = %{
      signal: abort_controller_pid,
      unix_socket: unix_socket_path,
      adapter: adapter_context,
      retry: retry,
      deadline: retry_deadline(request, retry)
    }

    {result, failure_token} = run_attempts(request, attempts, 1)

    duration = System.monotonic_time(:microsecond) - start_time

    case result do
      %Response{} = response ->
        if HTTP.Telemetry.enabled?(Keyword.get(request.transport_options, :telemetry, true)) do
          HTTP.Telemetry.request_stop(
            response.status,
            request.url,
            response_body_size(response),
            duration,
            response.http_version
          )
        end

        response

      {:error, reason} ->
        reason = public_reason(reason)

        if HTTP.Telemetry.enabled?(Keyword.get(request.transport_options, :telemetry, true)),
          do: HTTP.Telemetry.request_exception(request.url, reason, duration)

        error =
          if Keyword.get(request.transport_options, :error_mode, :raw) == :structured and
               not match?(%HTTP.RequestError{}, reason),
             do: reason |> HTTP.RequestError.new(failure_token) |> public_reason(),
             else: reason

        {:error, error}
    end
  end

  # One retry loop per fetch: every attempt shares the request deadline, and
  # telemetry start/stop/exception stay one per fetch.
  defp run_attempts(request, attempts, attempt) do
    {result, failure_token, owner} =
      run_attempt(attempt_request(request, attempts, attempt), attempts)

    decision =
      if attempts.retry,
        do:
          HTTP.Retry.decide(
            attempts.retry,
            request,
            retry_result(result),
            attempt,
            remaining(attempts.deadline)
          ),
        else: :stop

    case decision do
      {:retry, delay, reason} ->
        discard_attempt(result, owner, attempts.deadline)

        if HTTP.Telemetry.enabled?(Keyword.get(request.transport_options, :telemetry, true)),
          do: HTTP.Telemetry.request_retry(request.url, reason, attempt, delay)

        case retry_wait(attempts.signal, delay) do
          :ok -> run_attempts(request, attempts, attempt + 1)
          :aborted -> {{:error, :aborted}, nil}
        end

      :stop ->
        {result, failure_token}
    end
  end

  defp run_attempt(request, attempts) do
    failure_token =
      if Keyword.get(request.transport_options, :error_mode, :raw) == :structured do
        if Keyword.get(request.transport_options, :redirect, :follow) in [:manual, :error],
          do: make_ref()
      end

    request = %{
      request
      | transport_options:
          Keyword.put(request.transport_options, :connect_failure_token, failure_token)
    }

    result =
      if attempts.adapter == nil,
        do: HTTP.SocketClient.request(request, attempts.signal, attempts.unix_socket),
        else: HTTP.Adapter.execute(request, attempts.adapter, attempts.signal)

    {result, failure_token, HTTP.SocketClient.take_attempt_owner()}
  end

  defp retry_deadline(_request, nil), do: :infinity

  defp retry_deadline(request, _retry) do
    case Keyword.get(request.transport_options, :timeout) ||
           HTTP.Config.default_request_timeout() do
      :infinity -> :infinity
      timeout -> System.monotonic_time(:millisecond) + timeout
    end
  end

  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  # Later attempts receive the remaining budget of the one request deadline.
  defp attempt_request(request, %{deadline: :infinity}, _attempt), do: request
  defp attempt_request(request, _attempts, 1), do: request

  defp attempt_request(request, attempts, _attempt) do
    timeout = remaining(attempts.deadline)
    %{request | transport_options: Keyword.put(request.transport_options, :timeout, timeout)}
  end

  defp retry_result(%Response{} = response), do: response
  defp retry_result({:error, reason}), do: {:error, reason |> attempt_reason() |> public_reason()}

  defp attempt_reason({kind, token, reason})
       when kind in [:connect_failure, :tls_setup_failure] and is_reference(token),
       do: reason

  defp attempt_reason(reason), do: reason

  # An unread streamed body is cancelled and its socket owner aborted, as an
  # AbortController would, and both exit before the next attempt starts.
  # Buffered responses and failures have already released their connection.
  defp discard_attempt(%Response{body: stream}, owner, deadline) when is_pid(stream) do
    monitors = [
      Process.monitor(stream) | if(is_pid(owner), do: [Process.monitor(owner)], else: [])
    ]

    HTTP.Stream.stop(stream, :aborted)
    if is_pid(owner), do: send(owner, :abort)
    budget = min(remaining(deadline), @attempt_cleanup_budget)
    await_down(monitors, System.monotonic_time(:millisecond) + budget)
  end

  defp discard_attempt(_result, _owner, _deadline), do: :ok

  defp await_down([], _deadline), do: :ok

  defp await_down([monitor | rest], deadline) do
    receive do
      {:DOWN, ^monitor, :process, _pid, _reason} -> await_down(rest, deadline)
    after
      max(deadline - System.monotonic_time(:millisecond), 0) ->
        Enum.each([monitor | rest], &Process.demonitor(&1, [:flush]))
    end
  end

  # The worker is the abort target while it waits between attempts.
  defp retry_wait(signal, delay) do
    if is_pid(signal), do: HTTP.AbortController.set_request_id(signal, self())

    receive do
      :abort -> :aborted
    after
      delay -> :ok
    end
  end

  # Request deadline expiry is `:request_timeout` inside the shared lifecycle
  # and runtime; Fetch reports it as `:timeout`.
  defp public_reason(:request_timeout), do: :timeout

  defp public_reason(%HTTP.RequestError{reason: :request_timeout} = error),
    do: %{error | reason: :timeout}

  defp public_reason(reason), do: reason

  defp response_body_size(%Response{} = response), do: Response.body_size(response)

  defp stop_failed_upload({:error, reason}, body) when is_pid(body),
    do: HTTP.Stream.stop(body, reason)

  defp stop_failed_upload(_result, _body), do: :ok
end

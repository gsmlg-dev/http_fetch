defmodule HTTP do
  @moduledoc """
  A browser-like HTTP fetch API for Elixir, built on Erlang's `:gen_tcp` and `:ssl`.

  This module provides a modern, Promise-based HTTP client interface similar to the
  browser's `fetch()` API. It supports asynchronous requests, streaming, request
  cancellation, and comprehensive telemetry integration.

  ## Features

  - **Async by default**: All requests use Task.Supervisor with `async_nolink/4`
  - **Automatic streaming**: Responses >5MB or with unknown Content-Length automatically stream
  - **Request cancellation**: Via `HTTP.AbortController` for aborting in-flight requests
  - **Promise chaining**: JavaScript-like promise interface with `then/3` support
  - **Unix Domain Sockets**: Support for HTTP over Unix sockets (Docker daemon, systemd, etc.)
  - **Telemetry integration**: Comprehensive event emission for monitoring and observability
  - **Zero external dependencies**: Uses only Erlang/OTP built-in modules (except telemetry)

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
  - `HTTP.Headers` - Header manipulation utilities
  - `HTTP.FormData` - Multipart/form-data encoding with file upload support
  - `HTTP.AbortController` - Request cancellation mechanism
  - `HTTP.FetchOptions` - Options processing and validation
  - `HTTP.Telemetry` - Telemetry event emission for monitoring

  ## Streaming Behavior

  Responses are automatically streamed when:

  - Content-Length > 5MB
  - Content-Length header is missing/unknown

  Streaming responses have `body: nil` and `stream: pid` in the Response struct.
  Use `HTTP.Response.read_all/1` or `HTTP.Response.write_to/2` to consume streams.

  ## Telemetry Events

  All events use the `[:http_fetch, ...]` prefix:

  - `[:http_fetch, :request, :start]` - Request initiated
  - `[:http_fetch, :request, :stop]` - Request completed
  - `[:http_fetch, :request, :exception]` - Request failed
  - `[:http_fetch, :streaming, :start]` - Streaming started
  - `[:http_fetch, :streaming, :chunk]` - Stream chunk received
  - `[:http_fetch, :streaming, :stop]` - Streaming completed

  See `HTTP.Telemetry` for detailed event documentation.
  """

  alias HTTP.Promise
  alias HTTP.Request
  alias HTTP.Response

  @doc """
  Performs an HTTP request, similar to `global.fetch` in web browsers.
  Uses an internal HTTP/1.1 socket transport asynchronously.

  Arguments:
    - `url`: The URL to fetch (string or URI struct).
    - `init`: An optional keyword list or map of options for the request.
              Supported options:
                - `:method`: The HTTP method (e.g., "GET", "POST"). Defaults to "GET".
                             Can be a string or an atom (e.g., "GET" or :get).
                - `:headers`: A list of request headers as `{name, value}` tuples (e.g., [{"Content-Type", "application/json"}])
                              or a map that will be converted to the tuple format.
                - `:body`: The request body (should be a binary or a string that can be coerced to binary).
                - `:content_type`: The Content-Type header value. If not provided for methods with body,
                                   defaults to "application/octet-stream" when a body is present.
                - `:redirect`: Redirect mode, one of `:follow`, `:manual`, or `:error`. Defaults to `:follow`.
                - `:signal`: An `HTTP.AbortController` PID. If provided, the request can be aborted
                             via this controller.
                - `:timeout`, `:connect_timeout`, `:ssl`, and `:socket_opts`: Elixir-specific transport
                  extensions used by the socket transport.
                - `:unix_socket`: Path to a Unix Domain Socket file (e.g., "/var/run/docker.sock").
                                  When provided, the request is sent over the Unix socket instead of TCP/IP.

  Returns:
    - `%HTTP.Promise{}`: A Promise struct. The caller should `HTTP.Promise.await(promise_struct)` to get the final
                 `%HTTP.Response{}` or `{:error, reason}`. If the request cannot be initiated
                 (e.g., invalid URL, bad arguments), the Promise will contain an error result
                 when awaited.

  The socket transport defaults `redirect` to `:follow`; pass `redirect: :manual`
  to return redirect responses, or `redirect: :error` to fail on redirect. Request timeout handling
  gives the internal socket owner up to one additional second to report its timeout before the
  awaiting caller aborts it.

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

      # Promise chaining with error handling: fetch -> parse JSON -> handle success or error
      HTTP.fetch("https://jsonplaceholder.typicode.com/nonexistent") # This URL will cause an error
      |> HTTP.Promise.then(
        fn %HTTP.Response{} = response ->
          IO.puts "This success branch should not be called for a 404!"
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
          # If post_id is nil, we want to reject this branch of the promise chain
          throw {:error, :post_id_not_found}
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
          if reason == :aborted or reason == :request_timeout do
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
  @spec fetch(String.t() | URI.t(), Keyword.t() | map()) :: %HTTP.Promise{}
  def fetch(url, init \\ []) do
    uri = if is_binary(url), do: URI.parse(url), else: url
    options = HTTP.FetchOptions.new(init)

    request = %Request{
      url: uri,
      method: HTTP.FetchOptions.get_method(options),
      headers:
        options
        |> HTTP.FetchOptions.get_headers()
        |> HTTP.Headers.set_default("User-Agent", HTTP.Headers.user_agent(:http_fetch)),
      body: HTTP.FetchOptions.get_body(options),
      content_type: HTTP.FetchOptions.get_content_type(options),
      transport_options: HTTP.FetchOptions.to_transport_options(options)
    }

    # Extract AbortController PID and unix_socket from FetchOptions
    abort_controller_pid = options.signal
    unix_socket_path = options.unix_socket

    # Emit telemetry event for request start
    HTTP.Telemetry.request_start(request.method, request.url, request.headers)

    # Spawn a task to handle the asynchronous HTTP request
    task =
      Task.Supervisor.async_nolink(
        :http_fetch_task_supervisor,
        HTTP,
        :handle_async_request,
        [request, self(), abort_controller_pid, unix_socket_path]
      )

    # Wrap the task in our new Promise struct
    %Promise{task: task}
  end

  # Internal function, not part of public API
  @doc false
  @spec handle_async_request(
          Request.t(),
          pid(),
          pid() | nil,
          String.t() | nil
        ) :: Response.t() | {:error, term()}
  def handle_async_request(request, _calling_pid, abort_controller_pid, unix_socket_path \\ nil) do
    start_time = System.monotonic_time(:microsecond)

    result = HTTP.SocketClient.request(request, abort_controller_pid, unix_socket_path)
    duration = System.monotonic_time(:microsecond) - start_time

    case result do
      %Response{} = response ->
        HTTP.Telemetry.request_stop(
          response.status,
          request.url,
          response_body_size(response),
          duration
        )

        response

      {:error, reason} ->
        HTTP.Telemetry.request_exception(request.url, reason, duration)
        {:error, reason}
    end
  end

  defp response_body_size(%Response{body: body}) when is_binary(body), do: byte_size(body)
  defp response_body_size(%Response{}), do: 0
end

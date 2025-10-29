defmodule HTTP do
  @moduledoc """
  A browser-like HTTP fetch API for Elixir, built on Erlang's `:httpc` module.

  This module provides a modern, Promise-based HTTP client interface similar to the
  browser's `fetch()` API. It supports asynchronous requests, streaming, request
  cancellation, and comprehensive telemetry integration.

  ## Features

  - **Async by default**: All requests use Task.Supervisor with `async_nolink/4`
  - **Automatic streaming**: Responses >5MB or with unknown Content-Length automatically stream
  - **Request cancellation**: Via `HTTP.AbortController` for aborting in-flight requests
  - **Promise chaining**: JavaScript-like promise interface with `then/3` support
  - **Telemetry integration**: Comprehensive event emission for monitoring and observability
  - **Zero external dependencies**: Uses only Erlang/OTP built-in modules (except telemetry)

  ## Quick Start

      # Simple GET request
      {:ok, response} =
        HTTP.fetch("https://jsonplaceholder.typicode.com/posts/1")
        |> HTTP.Promise.await()

      # Parse JSON response
      {:ok, json} = HTTP.Response.json(response)

      # POST with JSON body
      {:ok, response} =
        HTTP.fetch("https://api.example.com/posts", [
          method: "POST",
          headers: %{"Content-Type" => "application/json"},
          body: JSON.encode!(%{title: "Hello", body: "World"})
        ])
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
  Uses Erlang's built-in `:httpc` module asynchronously (`sync: false`).

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
                                   defaults to "application/octet-stream" in `Request.to_httpc_args`.
                - `:options`: A keyword list of options directly passed as the 3rd argument to `:httpc.request`
                              (e.g., `timeout: 10_000`, `connect_timeout: 5_000`).
                - `:client_opts`: A keyword list of options directly passed as the 4th argument to `:httpc.request`
                                  (e.g., `sync: false`, `body_format: :binary`). Overrides `Request` defaults.
                - `:signal`: An `HTTP.AbortController` PID. If provided, the request can be aborted
                             via this controller.

  Returns:
    - `%HTTP.Promise{}`: A Promise struct. The caller should `HTTP.Promise.await(promise_struct)` to get the final
                 `%HTTP.Response{}` or `{:error, reason}`. If the request cannot be initiated
                 (e.g., invalid URL, bad arguments), the Promise will contain an error result
                 when awaited.

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
      #   {:ok, %HTTP.Response{status: 201, body: body}} ->
      #     IO.puts "POST successful! Body: \#{body}"
      #   {:error, reason} ->
      #     IO.inspect reason, label: "POST Error"
      # end

      # Request with custom :httpc options (e.g., longer timeout for request options)
      delayed_promise = HTTP.fetch("https://httpbin.org/delay/5", options: [timeout: 10_000])
      case HTTP.Promise.await(delayed_promise) do
        %HTTP.Response{status: status} ->
          IO.puts "Delayed request successful! Status: \#{status}"
        {:error, reason} ->
          IO.inspect reason, label: "Delayed Request Result"
      end

      # Abortable request example
      controller = HTTP.AbortController.new() # Create a new controller
      IO.puts "Fetching a long request that will be aborted..."
      abortable_promise = HTTP.fetch("https://httpbin.org/delay/10", signal: controller, options: [timeout: 20_000])

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
          if reason == :econnrefused or reason == :nxdomain do # Common errors for aborted :httpc requests
            IO.puts "Request was likely aborted. Reason: \#{inspect(reason)}"
          end
      end
  """
  @spec fetch(String.t() | URI.t(), Keyword.t() | map()) :: %HTTP.Promise{}
  def fetch(url, init \\ []) do
    uri = if is_binary(url), do: URI.parse(url), else: url
    options = HTTP.FetchOptions.new(init)

    request = %Request{
      url: uri,
      method: HTTP.FetchOptions.get_method(options),
      headers: HTTP.FetchOptions.get_headers(options),
      body: HTTP.FetchOptions.get_body(options),
      content_type: HTTP.FetchOptions.get_content_type(options),
      # Maps to Request.http_options (3rd arg for :httpc.request)
      http_options: options.options,
      # Maps to Request.options (4th arg for :httpc.request)
      options: Keyword.merge(Request.__struct__().options, options.opts)
    }

    # Extract AbortController PID from FetchOptions
    abort_controller_pid = options.signal

    # Emit telemetry event for request start
    HTTP.Telemetry.request_start(request.method, request.url, request.headers)

    # Spawn a task to handle the asynchronous HTTP request
    task =
      Task.Supervisor.async_nolink(
        :http_fetch_task_supervisor,
        HTTP,
        :handle_async_request,
        [request, self(), abort_controller_pid]
      )

    # Wrap the task in our new Promise struct
    %Promise{task: task}
  end

  @type httpc_response_tuple ::
          {:ok, pid()}
          | {:error, term()}
          | {{:http_version, integer(), String.t()}, [{atom() | String.t(), String.t()}],
             binary()}

  defp handle_response(request_id, url) do
    receive do
      {:http, {^request_id, response_from_httpc}} ->
        handle_httpc_response(response_from_httpc, url)

      _ ->
        throw(:request_interrupted_or_unexpected_message)
    after
      120_000 ->
        throw(:request_timeout)
    end
  end

  # Internal function, not part of public API
  @doc false
  @spec handle_async_request(
          Request.t(),
          pid(),
          pid() | nil
        ) :: Response.t() | {:error, term()}
  def handle_async_request(request, _calling_pid, abort_controller_pid) do
    start_time = System.monotonic_time(:microsecond)

    # Use a try/catch block to convert `throw` from handle_httpc_response into an {:error, reason} tuple
    try do
      case Request.to_httpc_args(request) do
        [method, request_tuple, options, client_options] ->
          # Configure httpc options - body_format should be in client_opts (4th arg)
          httpc_client_opts = Keyword.put(client_options, :body_format, :binary)

          # Send the request and get the RequestId (PID of the httpc client process)
          case :httpc.request(method, request_tuple, options, httpc_client_opts) do
            {:ok, request_id} ->
              # If an AbortController was provided, link it to this request_id
              if abort_controller_pid && is_pid(abort_controller_pid) do
                HTTP.AbortController.set_request_id(abort_controller_pid, request_id)
              end

              # Handle response (simplified - streaming handled in handle_httpc_response)
              result = handle_response(request_id, request.url)

              # Emit telemetry event for request completion
              duration = System.monotonic_time(:microsecond) - start_time

              case result do
                %Response{status: status, body: body} when is_binary(body) ->
                  HTTP.Telemetry.request_stop(status, request.url, byte_size(body), duration)

                %Response{status: status, stream: nil} ->
                  # Non-streaming response with nil body (unlikely, but handle)
                  HTTP.Telemetry.request_stop(status, request.url, 0, duration)

                %Response{status: status} ->
                  # Streaming response - we'll emit telemetry when streaming completes
                  HTTP.Telemetry.request_stop(status, request.url, 0, duration)

                {:error, _} ->
                  # Error will be handled in catch block
                  :ok
              end

              result

            {:error, reason} ->
              duration = System.monotonic_time(:microsecond) - start_time
              HTTP.Telemetry.request_exception(request.url, reason, duration)
              throw(reason)
          end

        # Fallback for unexpected return from Request.to_httpc_args
        other_args ->
          duration = System.monotonic_time(:microsecond) - start_time
          HTTP.Telemetry.request_exception(request.url, {:bad_request_args, other_args}, duration)
          throw({:bad_request_args, other_args})
      end
    catch
      reason ->
        duration = System.monotonic_time(:microsecond) - start_time
        HTTP.Telemetry.request_exception(request.url, reason, duration)
        {:error, reason}
    end
  end

  # Success case: returns %Response{} directly
  @spec handle_httpc_response(httpc_response_tuple(), URI.t() | nil) :: Response.t()
  defp handle_httpc_response(response_tuple, url) do
    case response_tuple do
      {{_version, status, _reason_phrase}, httpc_headers, body} ->
        # Convert :httpc's header list to HTTP.Headers struct
        response_headers =
          httpc_headers
          |> Enum.map(fn {key, val} -> {to_string(key), to_string(val)} end)
          |> HTTP.Headers.new()

        # Check if we should use streaming
        content_length = HTTP.Headers.get(response_headers, "content-length")
        should_stream = should_use_streaming?(content_length)

        if should_stream do
          # Create a streaming process
          {:ok, stream_pid} = start_httpc_stream_process(url, response_headers)

          %Response{
            status: status,
            headers: response_headers,
            body: nil,
            url: url,
            stream: stream_pid
          }
        else
          # Non-streaming response - handle as before
          binary_body =
            if is_list(body) do
              IO.iodata_to_binary(body)
            else
              body
            end

          %Response{
            status: status,
            headers: response_headers,
            body: binary_body,
            url: url,
            stream: nil
          }
        end

      {:error, reason} ->
        throw(reason)

      other ->
        throw({:unexpected_response, other})
    end
  end

  defp should_use_streaming?(content_length) do
    # Stream responses larger than 5MB to avoid issues with large files
    case Integer.parse(content_length || "") do
      {size, _} when size > 5_000_000 ->
        # Emit telemetry for streaming start
        HTTP.Telemetry.streaming_start(size)
        true

      # Stream when size is unknown
      _ ->
        if content_length == nil do
          HTTP.Telemetry.streaming_start(0)
        end

        content_length == nil
    end
  end

  defp start_httpc_stream_process(uri, headers) do
    start_time = System.monotonic_time(:microsecond)

    {:ok, pid} =
      Task.start_link(fn ->
        stream_httpc_response(uri, headers, start_time)
      end)

    {:ok, pid}
  end

  defp stream_httpc_response(uri, headers, start_time) do
    # Use the URI directly (it's already parsed)
    _host = uri.host
    _port = uri.port || 80
    _path = uri.path || "/"

    # Build headers for the request
    request_headers =
      headers.headers
      |> Enum.map(fn {name, value} -> {String.to_charlist(name), String.to_charlist(value)} end)

    # Start the HTTP request with streaming
    case :httpc.request(
           :get,
           {String.to_charlist(URI.to_string(uri)), request_headers},
           [],
           sync: false
         ) do
      {:ok, request_id} ->
        stream_loop(request_id, self(), 0, start_time)

      {:error, reason} ->
        send(self(), {:stream_error, self(), reason})
    end
  end

  defp stream_loop(request_id, caller, total_bytes, start_time) do
    receive do
      {:http, {^request_id, {:http_response, _http_version, _status, _reason}}} ->
        stream_loop(request_id, caller, total_bytes, start_time)

      {:http, {^request_id, {:http_header, _, _header_name, _, _header_value}}} ->
        stream_loop(request_id, caller, total_bytes, start_time)

      {:http, {^request_id, :http_eoh}} ->
        stream_loop(request_id, caller, total_bytes, start_time)

      {:http, {^request_id, {:http_error, reason}}} ->
        send(caller, {:stream_error, self(), reason})

      {:http, {^request_id, :stream_end}} ->
        duration = System.monotonic_time(:microsecond) - start_time
        HTTP.Telemetry.streaming_stop(total_bytes, duration)
        send(caller, {:stream_end, self()})

      {:http, {^request_id, {:http_chunk, chunk}}} ->
        chunk_size = byte_size(chunk)
        new_total = total_bytes + chunk_size
        HTTP.Telemetry.streaming_chunk(chunk_size, new_total)
        send(caller, {:stream_chunk, self(), to_string(chunk)})
        stream_loop(request_id, caller, new_total, start_time)

      {:http, {^request_id, {:http_body, body}}} ->
        chunk_size = byte_size(body)
        new_total = total_bytes + chunk_size
        HTTP.Telemetry.streaming_chunk(chunk_size, new_total)
        send(caller, {:stream_chunk, self(), to_string(body)})
        duration = System.monotonic_time(:microsecond) - start_time
        HTTP.Telemetry.streaming_stop(new_total, duration)
        send(caller, {:stream_end, self()})

      {:http, {^request_id, {_status_line, _headers, body}}} ->
        # Handle complete response (non-streaming case)
        binary_body = if is_list(body), do: IO.iodata_to_binary(body), else: body
        chunk_size = byte_size(binary_body)
        new_total = total_bytes + chunk_size
        HTTP.Telemetry.streaming_chunk(chunk_size, new_total)
        send(caller, {:stream_chunk, self(), binary_body})
        duration = System.monotonic_time(:microsecond) - start_time
        HTTP.Telemetry.streaming_stop(new_total, duration)
        send(caller, {:stream_end, self()})
    after
      60_000 ->
        duration = System.monotonic_time(:microsecond) - start_time
        HTTP.Telemetry.streaming_stop(total_bytes, duration)
        send(caller, {:stream_error, self(), :timeout})
    end
  end
end

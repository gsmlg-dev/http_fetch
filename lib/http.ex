defmodule HTTP do
  @moduledoc """
  A module simulating the web browser's Fetch API in Elixir, using :httpc as the foundation.
  Provides HTTP.Request, HTTP.Response, HTTP.Promise and a global-like fetch function with asynchronous
  capabilities and an AbortController for request cancellation.
  """

  alias HTTP.Request
  alias HTTP.Response
  alias HTTP.Promise

  @doc """
  Performs an HTTP request, similar to `global.fetch` in web browsers.
  Uses Erlang's built-in `:httpc` module asynchronously (`sync: false`).

  Arguments:
    - `url`: The URL to fetch (string).
    - `init`: An optional keyword list or map of options for the request.
              Supported options:
                - `:method`: The HTTP method (e.g., "GET", "POST"). Defaults to "GET".
                             Can be a string or an atom (e.g., "GET" or :get).
                - `:headers`: A map of request headers (e.g., %{"Content-Type" => "application/json"}).
                              These will be converted to a list of `{key, value}` tuples.
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
                 `{:ok, %HTTP.Response{}}` or `{:error, reason}`. If the request cannot be initiated
                 (e.g., invalid URL, bad arguments), the Promise will contain an error result
                 when awaited.

  Example Usage:

      # GET request and awaiting JSON
      promise_json = HTTP.fetch("https://jsonplaceholder.typicode.com/todos/1")
      case HTTP.Promise.await(promise_json) do
        {:ok, %HTTP.Response{} = response} ->
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
        {:ok, %HTTP.Response{} = response} ->
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
      #        headers: %{"Accept" => "application/json"},
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
        {:ok, %HTTP.Response{status: status}} ->
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
        {:ok, %HTTP.Response{status: status}} ->
          IO.puts "Abortable request completed successfully! Status: \#{status}"
        {:error, reason} ->
          IO.inspect reason, label: "Abortable Request Result"
          if reason == :econnrefused or reason == :nxdomain do # Common errors for aborted :httpc requests
            IO.puts "Request was likely aborted. Reason: \#{inspect(reason)}"
          end
      end
  """
  @spec fetch(String.t(), Keyword.t() | map()) :: %HTTP.Promise{}
  def fetch(url, init \\ []) do
    method = Keyword.get(init, :method, "GET")
    # Ensure method is an atom for Request struct
    erlang_method =
      if is_atom(method), do: method, else: String.to_existing_atom(String.downcase(method))

    headers = Keyword.get(init, :headers, %{})
    # Convert headers map to list of tuples as expected by Request.headers
    formatted_headers = Enum.into(headers, [])

    # Extract AbortController PID if provided
    abort_controller_pid = Keyword.get(init, :signal)

    request = %Request{
      url: url,
      method: erlang_method,
      headers: formatted_headers,
      body: Keyword.get(init, :body),
      content_type: Keyword.get(init, :content_type),
      # Maps to Request.options (3rd arg for :httpc.request)
      options: Keyword.get(init, :options, []),
      # Maps to Request.opts (4th arg for :httpc.request)
      opts: Keyword.get(init, :client_opts, Request.__struct__().opts)
    }

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

  # Internal function, not part of public API
  @doc false
  @spec handle_async_request(
          Request.t(),
          pid(),
          pid() | nil
        ) :: {:ok, Response.t()} | {:error, term()}
  def handle_async_request(request, _calling_pid, abort_controller_pid) do
    # Use a try/catch block to convert `throw` from handle_httpc_response into an {:error, reason} tuple
    try do
      case Request.to_httpc_args(request) do
        [method, request_tuple, options, client_options] ->
          # Send the request and get the RequestId (PID of the httpc client process)
          case :httpc.request(method, request_tuple, options, client_options) do
            {:ok, request_id} ->
              # If an AbortController was provided, link it to this request_id
              if abort_controller_pid && is_pid(abort_controller_pid) do
                HTTP.AbortController.set_request_id(abort_controller_pid, request_id)
              end

              # Now, receive the response message from :httpc
              # The message format is {:httpc, {RequestId, ResponseTuple}}
              # Default 2 minute timeout if no response received
              receive do
                {:http, {^request_id, response_from_httpc}} ->
                  # This will return %Response{} or throw
                  response = handle_httpc_response(response_from_httpc, request.url)
                  # Wrap in :ok for the Task result
                  {:ok, response}

                _ ->
                  # This catch-all can happen if the process is killed or another message arrives
                  throw(:request_interrupted_or_unexpected_message)
              after
                120_000 ->
                  throw(:request_timeout)
              end

            {:error, reason} ->
              throw(reason)
          end

        # Fallback for unexpected return from Request.to_httpc_args
        other_args ->
          throw({:bad_request_args, other_args})
      end
    catch
      reason ->
        {:error, reason}
    end
  end

  # Success case: returns %Response{} directly
  @spec handle_httpc_response(httpc_response_tuple(), String.t() | nil) :: Response.t()
  defp handle_httpc_response({{_version, status, _reason_phrase}, httpc_headers, body}, url) do
    # Convert :httpc's header list to a map for HTTP.Response
    response_headers =
      httpc_headers
      |> Enum.map(fn {key, val} -> {to_string(key), to_string(val)} end)
      |> Enum.into(%{})

    # Convert body from charlist (iodata) to binary if it's not already
    binary_body =
      if is_list(body) do
        IO.iodata_to_binary(body)
      else
        body
      end

    %Response{status: status, headers: response_headers, body: binary_body, url: url}
  end

  # Error case: throws the reason
  @spec handle_httpc_response({:error, term()}, String.t() | nil) :: no_return()
  defp handle_httpc_response({:error, reason}, _original_url) do
    throw(reason)
  end

  # Unexpected response case: throws an explicit error
  @spec handle_httpc_response(term(), String.t() | nil) :: no_return()
  defp handle_httpc_response(other, _original_url) do
    throw({:unexpected_response, other})
  end
end

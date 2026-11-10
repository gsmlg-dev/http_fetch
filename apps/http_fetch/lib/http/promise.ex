defmodule HTTP.Promise do
  @moduledoc """
  JavaScript-like Promise implementation for asynchronous HTTP operations.

  This module provides a Promise-based interface for handling asynchronous HTTP
  requests, wrapping Elixir's `Task` with familiar Promise semantics including
  chaining via `then/3` and error handling.

  ## Features

  - **Async/await pattern**: Similar to JavaScript's Promise.await()
  - **Promise chaining**: Chain operations with `then/3` for sequential async operations
  - **Error handling**: Separate success and error callbacks
  - **Task-based**: Built on Elixir's Task.Supervisor for reliability

  ## Basic Usage

      # Simple await
      response =
        HTTP.fetch("https://api.example.com/data")
        |> HTTP.Promise.await()

      # Promise chaining
      HTTP.fetch("https://api.example.com/users/1")
      |> HTTP.Promise.then(&HTTP.Response.json/1)
      |> HTTP.Promise.then(fn {:ok, user} ->
        IO.puts("User: " <> user["name"])
      end)
      |> HTTP.Promise.await()

  ## Chaining with Error Handling

      HTTP.fetch("https://api.example.com/data")
      |> HTTP.Promise.then(
        fn response -> HTTP.Response.json(response) end,
        fn _reason -> {:error, :request_failed} end
      )
      |> HTTP.Promise.await()

  ## Returning Promises from Callbacks

  Callbacks in `then/3` can return another Promise, enabling sequential async operations:

      HTTP.fetch("https://api.example.com/posts/1")
      |> HTTP.Promise.then(fn response ->
        {:ok, post} = HTTP.Response.json(response)
        # Fetch comments for this post
        HTTP.fetch("https://api.example.com/posts/\#{post["id"]}/comments")
      end)
      |> HTTP.Promise.then(fn comments_response ->
        HTTP.Response.json(comments_response)
      end)
      |> HTTP.Promise.await()

  `then/3` returns immediately. Its callbacks run in the process that calls
  `await/2`, after the request settles. A callback result of `{:error, reason}`
  rejects the chain; any other result is passed unchanged to the next success
  callback, and a returned promise is awaited first.
  """

  defstruct task: nil, completion: nil, callbacks: []

  @typedoc false
  @type callback :: {success_callback_fun(), error_callback_fun() | nil}

  @type t :: %__MODULE__{
          task: Task.t(),
          completion: HTTP.RequestCompletion.t() | nil,
          callbacks: [callback()]
        }
  @doc """
  Returns the original request's cleanup handle. Promises derived with `then/3`
  keep the handle of the request they chain from.
  """
  @spec completion(t()) :: HTTP.RequestCompletion.t() | nil
  def completion(%__MODULE__{completion: completion}), do: completion

  @type success_callback_fun :: (term() -> any())
  @type error_callback_fun :: (term() -> any())

  @doc """
  Awaits the completion of the HTTP promise.

  Arguments:
    - `promise`: The `HTTP.Promise` instance to await.
    - `timeout`: Optional timeout in milliseconds or `:infinity`. Defaults to `:infinity`.

  Returns:
    - `%HTTP.Response{}` on successful completion.
    - `{:error, reason}` if the request fails or is aborted.
    - `{:error, :timeout}` if the timeout is reached.
    - For a promise derived with `then/3`, the final value of its callback chain.

  The wait timeout is independent of the request's `timeout:` option. Expiring
  a wait does not cancel the request or confirm cleanup, and the same promise
  can be awaited again. To cancel and confirm supported request cleanup, retain
  the original handle from `completion/1` and use
  `HTTP.RequestCompletion.abort_and_await/2`. Other task exits still exit the
  caller.

  `then/3` callbacks run in the awaiting process once the request settles. The
  timeout covers the request and any promise a callback returns. A timeout while
  waiting for the request leaves the chain re-awaitable; once callbacks have
  started, the request result has been consumed and the chain cannot be resumed.
  """
  @spec await(t(), timeout :: non_neg_integer() | :infinity) :: term()
  def await(%__MODULE__{} = promise, timeout \\ :infinity) do
    case settle(promise, timeout, deadline(timeout)) do
      {:settled, result} -> result
      :timeout -> {:error, :timeout}
    end
  end

  @doc """
  Attaches callbacks for the resolution or rejection of the Promise.
  Returns a new `HTTP.Promise` for chaining without waiting for the request.

  Arguments:
    - `promise`: The current `HTTP.Promise` instance.
    - `success_fun`: A 1-arity function called with the fulfilled value: the
                     `HTTP.Response.t()` for a request promise, or the previous
                     callback's result for a chained promise.
                     Can return a value, `{:ok, value}`, `{:error, reason}`, or another `HTTP.Promise`.
    - `error_fun`: An optional 1-arity function to be called if the promise is rejected.
                   It receives the reason for rejection as an argument.
                   Can return a value, `{:ok, value}`, `{:error, reason}`, or another `HTTP.Promise`.

  A result of `{:error, reason}` rejects the chained promise; any other value
  (including `{:ok, value}`) fulfills it and is passed unchanged to the next
  success callback. A returned `HTTP.Promise` is awaited and its result is used.
  Without `error_fun`, a rejection skips `success_fun` and propagates.

  Callbacks run in the process that calls `await/2`, so a returned promise is
  owned by, and can be awaited from, that process. `await/2` returns the final
  value, or `{:error, reason}` for a rejected chain.

  Returns:
    - `%HTTP.Promise{}`: A new promise representing the outcome of the callbacks.
  """
  @spec then(t(), success_callback_fun(), error_callback_fun() | nil) :: t()
  def then(%__MODULE__{callbacks: callbacks} = promise, success_fun, error_fun \\ nil)
      when is_function(success_fun, 1) and (is_nil(error_fun) or is_function(error_fun, 1)) do
    %{promise | callbacks: callbacks ++ [{success_fun, error_fun}]}
  end

  defp settle(%__MODULE__{task: task, callbacks: callbacks}, timeout, deadline) do
    case Task.yield(task, timeout) do
      {:ok, result} -> run_callbacks(callbacks, result, deadline)
      nil -> :timeout
      {:exit, reason} -> exit({reason, {Task, :await, [task, timeout]}})
    end
  end

  defp run_callbacks([], result, _deadline), do: {:settled, result}

  defp run_callbacks([{success_fun, error_fun} | rest], result, deadline) do
    next =
      case result do
        {:error, reason} when is_function(error_fun, 1) -> error_fun.(reason)
        {:error, _reason} = error -> error
        value -> success_fun.(value)
      end

    case resolve(next, deadline) do
      {:settled, value} -> run_callbacks(rest, value, deadline)
      :timeout -> :timeout
    end
  end

  defp resolve(%__MODULE__{} = promise, deadline),
    do: settle(promise, remaining(deadline), deadline)

  defp resolve(value, _deadline), do: {:settled, value}

  defp deadline(:infinity), do: :infinity

  defp deadline(timeout) when is_integer(timeout) and timeout >= 0,
    do: System.monotonic_time(:millisecond) + timeout

  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end

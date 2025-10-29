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
      {:ok, response} =
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
        fn error -> {:error, :request_failed} end
      )
      |> HTTP.Promise.await()

  ## Returning Promises from Callbacks

  Callbacks in `then/3` can return another Promise, enabling sequential async operations:

      HTTP.fetch("https://api.example.com/posts/1")
      |> HTTP.Promise.then(fn response ->
        {:ok, post} = HTTP.Response.json(response)
        # Fetch comments for this post
        HTTP.fetch("https://api.example.com/posts/1/comments")
      end)
      |> HTTP.Promise.then(fn comments_response ->
        HTTP.Response.json(comments_response)
      end)
      |> HTTP.Promise.await()
  """

  defstruct task: nil

  @type t :: %__MODULE__{task: Task.t()}
  @type success_callback_fun :: (HTTP.Response.t() -> any())
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
  """
  @spec await(t(), timeout :: non_neg_integer() | :infinity) ::
          HTTP.Response.t() | {:error, term()}
  def await(%__MODULE__{task: task}, timeout \\ :infinity) do
    Task.await(task, timeout)
  end

  @doc """
  Attaches callbacks for the resolution or rejection of the Promise.
  Returns a new `HTTP.Promise` for chaining.

  Arguments:
    - `promise`: The current `HTTP.Promise` instance.
    - `success_fun`: A 1-arity function to be called if the promise resolves successfully.
                     It receives the `HTTP.Response.t()` as an argument.
                     Can return a value, `{:ok, value}`, `{:error, reason}`, or another `HTTP.Promise`.
    - `error_fun`: An optional 1-arity function to be called if the promise is rejected.
                   It receives the reason for rejection as an argument.
                   Can return a value, `{:ok, value}`, `{:error, reason}`, or another `HTTP.Promise`.

  Returns:
    - `%HTTP.Promise{}`: A new promise representing the outcome of the callbacks.
  """
  @spec then(t(), success_callback_fun(), error_callback_fun() | nil) :: t()
  def then(%__MODULE__{task: current_task}, success_fun, error_fun \\ nil) do
    new_task =
      Task.Supervisor.async_nolink(:http_fetch_task_supervisor, fn ->
        case Task.await(current_task) do
          %HTTP.Response{} = response ->
            # Call the success function and handle its result
            apply_callback(success_fun, [response]) |> handle_chained_result()

          {:error, reason} ->
            if error_fun do
              # Call the error function if provided and handle its result
              apply_callback(error_fun, [reason]) |> handle_chained_result()
            else
              # If no error_fun, just propagate the error
              {:error, reason}
            end
        end
      end)

    %__MODULE__{task: new_task}
  end

  @spec apply_callback(fun :: (any() -> any()), args :: list()) :: any()
  defp apply_callback(fun, args) when is_function(fun, length(args)), do: apply(fun, args)
  # Should ideally not happen with @spec
  defp apply_callback(_fun, _args), do: {:error, :invalid_callback_function}

  @spec handle_chained_result(any()) :: {:ok, any()} | {:error, term()}
  defp handle_chained_result(%HTTP.Promise{} = promise), do: Task.await(promise.task)
  defp handle_chained_result({:ok, _} = result), do: result
  defp handle_chained_result({:error, _} = result), do: result
  # Wrap non-tuple results in :ok
  defp handle_chained_result(other), do: {:ok, other}
end

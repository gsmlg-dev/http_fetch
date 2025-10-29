defmodule HTTP.AbortController do
  use Agent

  @moduledoc """
  Request cancellation mechanism similar to the browser's AbortController API.

  This module provides a way to abort in-flight HTTP requests using an Agent-based
  controller. It's designed to work with the `HTTP.fetch/2` function via the
  `:signal` option.

  ## How It Works

  1. Create an AbortController before making the request
  2. Pass the controller to `HTTP.fetch/2` via the `:signal` option
  3. Call `abort/1` on the controller to cancel the request
  4. The awaiting Promise will receive an error result

  ## Basic Usage

      # Create a controller
      controller = HTTP.AbortController.new()

      # Start a long-running request with the controller
      promise = HTTP.fetch("https://httpbin.org/delay/10",
        signal: controller,
        options: [timeout: 20_000]
      )

      # Abort the request (e.g., after 2 seconds)
      :timer.sleep(2000)
      HTTP.AbortController.abort(controller)

      # The awaited promise will return an error
      case HTTP.Promise.await(promise) do
        {:error, reason} ->
          IO.puts("Request was aborted: " <> inspect(reason))
        response ->
          IO.puts("Request completed before abort")
      end

  ## Advanced Usage

      # Abort from another process
      controller = HTTP.AbortController.new()

      # Start request in background
      Task.start(fn ->
        promise = HTTP.fetch("https://slow-api.example.com", signal: controller)
        result = HTTP.Promise.await(promise)
        IO.inspect(result)
      end)

      # Abort from main process after some condition
      :timer.sleep(1000)
      if some_condition?() do
        HTTP.AbortController.abort(controller)
      end

  ## Implementation Details

  - Uses Elixir's `Agent` for state management
  - Registers with a `Registry` for process tracking
  - Calls `:httpc.cancel_request/1` internally to abort the request
  - Thread-safe and can be called from any process
  - Idempotent - calling `abort/1` multiple times is safe

  ## State Management

  The controller maintains the following state:

  - `request_id` - PID of the active `:httpc` request (set automatically)
  - `signal_ref` - Unique reference for registry lookup
  - `aborted` - Boolean flag indicating abort status
  """

  @type state :: %{request_id: pid() | nil, signal_ref: reference(), aborted: boolean()}

  @doc """
  Starts a new AbortController agent.
  Returns `{:ok, pid}` of the agent.
  """
  @spec start_link(state()) :: {:ok, pid()}
  def start_link(initial_state \\ %{request_id: nil, signal_ref: make_ref(), aborted: false}) do
    # Using Registry for named processes, allowing lookup by signal_ref if needed in more complex scenarios
    Agent.start_link(fn -> initial_state end,
      name: {:via, Registry, {__MODULE__, initial_state.signal_ref}}
    )
  end

  @doc """
  Creates a new AbortController instance.
  Returns the PID of the agent, which acts as the controller reference.
  """
  @spec new() :: pid()
  def new do
    {:ok, pid} = start_link()
    pid
  end

  @doc """
  Sets the `:httpc` request_id for the given controller.
  This links the controller to an active request.
  """
  @spec set_request_id(pid(), pid()) :: :ok
  def set_request_id(controller_pid, request_id) when is_pid(controller_pid) do
    Agent.update(controller_pid, fn state -> %{state | request_id: request_id} end)
  end

  @doc """
  Checks if the controller has been aborted.
  """
  @spec aborted?(pid()) :: boolean()
  def aborted?(controller_pid) when is_pid(controller_pid) do
    Agent.get(controller_pid, & &1.aborted)
  end

  @doc """
  Aborts the associated HTTP request.
  Sends a stop signal to :httpc if a request is active and not already aborted.
  """
  @spec abort(pid()) :: :ok
  def abort(controller_pid) when is_pid(controller_pid) do
    Agent.update(controller_pid, fn state ->
      if state.request_id && !state.aborted do
        # CORRECTED: Use :httpc.cancel_request/1
        :httpc.cancel_request(state.request_id)
        %{state | aborted: true}
      else
        state
      end
    end)

    # Always return :ok as the agent update itself is successful.
    # The actual abort status would be observed by the request's Task.await result.
    :ok
  end
end

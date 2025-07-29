defmodule HTTP.AbortController do
  use Agent

  @type state :: %{request_id: pid() | nil, signal_ref: reference(), aborted: boolean()}

  @moduledoc """
  Provides request cancellation functionality similar to the browser's AbortController.
  """

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
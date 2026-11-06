defmodule Abyss.ShutdownListener do
  @moduledoc """
  Stops admission and drains ordinary handlers before supervisor teardown,
  using one absolute deadline across all endpoints. It obtains live owners
  from ETS so shutdown never calls its blocked parent supervisor.
  """
  use GenServer

  def start_link(args), do: GenServer.start_link(__MODULE__, args)

  @impl true
  def init({server, timeout}) do
    Process.flag(:trap_exit, true)
    {:ok, %{server_pid: server, timeout: timeout}}
  end

  def init(server), do: init({server, 15_000})

  @impl true
  def terminate(_reason, %{server_pid: server, timeout: timeout}) do
    deadline =
      if timeout == :infinity, do: :infinity, else: System.monotonic_time(:millisecond) + timeout

    listeners = Abyss.Listener.for_server(server)
    Enum.each(listeners, &Abyss.Listener.pause/1)

    for listener <- listeners do
      try do
        Abyss.Listener.drain(listener, deadline)
      catch
        :exit, _ -> :ok
      end
    end

    Abyss.Listener.clear_desired(server)
    Abyss.Telemetry.clear_scope(server)
    :ok
  end

  def terminate(reason, %{server_pid: server}),
    do: terminate(reason, %{server_pid: server, timeout: 15_000})

  def terminate(_reason, %{}), do: :ok
end

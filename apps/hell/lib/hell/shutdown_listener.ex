defmodule Hell.ShutdownListener do
  @moduledoc false

  # Used as part of the `Hell.Server` supervision tree to facilitate
  # stopping the server's listener process early in the shutdown process, in order
  # to allow existing connections to drain without accepting new ones

  use GenServer

  @type state :: %{listener: pid(), acceptor_pool_supervisor: pid()} | nil

  @doc false
  @spec start_link({pid(), any()}) :: :ignore | {:error, any} | {:ok, pid}
  def start_link({server_pid, key}) do
    GenServer.start_link(__MODULE__, {server_pid, key})
  end

  @doc false
  @impl GenServer
  @spec init({pid(), any()}) ::
          {:ok, state, {:continue, {:setup_listener_pid, server_pid :: pid()}}}
  def init({server_pid, key}) do
    Process.flag(:trap_exit, true)
    Hell.ProcessLabel.set(:shutdown_listener, key)
    {:ok, nil, {:continue, {:setup_listener_pid, server_pid}}}
  end

  @doc false
  @impl GenServer
  @spec handle_continue({:setup_listener_pid, pid()}, state) :: {:noreply, state}
  def handle_continue({:setup_listener_pid, server_pid}, nil) do
    children =
      server_pid
      |> Supervisor.which_children()
      |> Map.new(fn {id, pid, _, _} -> {id, pid} end)

    {:noreply, Map.take(children, [:listener, :acceptor_pool_supervisor])}
  end

  @doc false
  @impl GenServer
  @spec terminate(reason, state) :: :ok
        when reason: :normal | :shutdown | {:shutdown, term} | term
  def terminate(:shutdown, %{listener: listener_pid, acceptor_pool_supervisor: pool_pid})
      when is_pid(listener_pid) and is_pid(pool_pid) do
    if Process.alive?(pool_pid) do
      stop_listener(listener_pid, pool_pid)
    end

    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp stop_listener(listener_pid, pool_pid) do
    monitors =
      for {_, supervisor, _, _} <- children(pool_pid),
          is_pid(supervisor),
          {:acceptor, acceptor, _, _} <- children(supervisor),
          is_pid(acceptor),
          do: Process.monitor(acceptor)

    Hell.Listener.stop(listener_pid)

    # Let acceptors observe the closed listener and finish their telemetry spans
    # before the parent tears down the pool. The existing child shutdown timeout
    # still bounds this wait if an acceptor cannot finish.
    Enum.each(monitors, fn monitor ->
      receive do
        {:DOWN, ^monitor, :process, _, _} -> :ok
      end
    end)
  end

  defp children(pid) when is_pid(pid) do
    Supervisor.which_children(pid)
  catch
    :exit, {:noproc, _} -> []
  end

  defp children(_pid), do: []
end

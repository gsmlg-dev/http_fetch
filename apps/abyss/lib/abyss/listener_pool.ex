defmodule Abyss.ListenerPool do
  @moduledoc """
  Supervisor that manages a pool of UDP listener processes.

  This module creates and supervises multiple listener processes based on the
  `num_listeners` configuration. In broadcast mode, only a single listener
  is created regardless of the `num_listeners` setting.

  ## Listener Management

  - **Regular Mode**: Creates `num_listeners` separate listener processes
  - **Broadcast Mode**: Creates a single listener process for broadcast/multicast

  ## Supervision Strategy

  Uses `:one_for_one` strategy so that if one listener crashes,
  other listeners continue to operate normally.

  This module is primarily used internally by `Abyss.Server`.
  """

  use Supervisor

  @doc """
  Start the listener pool supervisor.

  ## Parameters
  - `arg` - Tuple containing `{server_pid, server_config}`

  ## Returns
  - Standard Supervisor start result
  """
  @spec start_link({server_pid :: pid, Abyss.ServerConfig.t()}) :: Supervisor.on_start()
  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg)
  end

  @doc """
  Get PIDs of all active listener processes in the pool.

  ## Parameters
  - `supervisor` - The listener pool supervisor PID

  ## Returns
  - List of listener PIDs, empty list if supervisor is not alive
  """
  @spec listener_pids(Supervisor.supervisor()) :: [pid()]
  def listener_pids(supervisor) do
    try do
      if Process.alive?(supervisor) do
        for {_, pid, _, _} when is_pid(pid) <- Supervisor.which_children(supervisor), do: pid
      else
        []
      end
    rescue
      _e in [ArgumentError, UndefinedFunctionError] -> []
    catch
      :exit, _ -> []
    end
  end

  @doc """
  Pause admission on the existing owners. Sockets, ports and memberships stay
  available for admitted handlers. Datagrams received while paused are dropped;
  packets retained in the bounded kernel queue can be received after resume.

  ## Parameters
  - `pid` - The listener pool supervisor PID

  ## Returns
  - `:ok` if suspend was successful, `:error` if supervisor is not alive
  """
  @spec suspend(Supervisor.supervisor()) :: :ok | :error
  def suspend(pid) do
    apply_to_listeners(pid, &Abyss.Listener.pause/1)
  end

  @doc """
  Resume admission on the retained sockets. Return actual receive-rearm errors
  and retain the original ephemeral port and desired memberships.

  ## Parameters
  - `pid` - The listener pool supervisor PID

  ## Returns
  - `:ok` if resume was successful, `:error` if supervisor is not alive
  """
  @spec resume(Supervisor.supervisor()) :: :ok | :error
  def resume(pid) do
    apply_to_listeners(pid, &Abyss.Listener.resume/1)
  end

  defp apply_to_listeners(pid, operation) do
    if is_pid(pid) and Process.alive?(pid) do
      Enum.reduce_while(listener_pids(pid), :ok, fn child, :ok ->
        operation.(child) |> operation_result()
      end)
    else
      :error
    end
  catch
    :exit, _ -> :error
  end

  defp operation_result(:ok), do: {:cont, :ok}
  defp operation_result(error), do: {:halt, error}

  @doc """
  Send start listening message to all listener processes.

  This is typically used during server startup to trigger listeners
  to begin accepting connections.

  ## Parameters
  - `pid` - The listener pool supervisor PID
  """
  @spec start_listening(Supervisor.supervisor()) :: :ok
  def start_listening(pid) do
    pid
    |> listener_pids()
    |> Enum.each(&send(&1, :start_listening))
  end

  @impl Supervisor
  @spec init({server_pid :: pid, Abyss.ServerConfig.t()}) ::
          {:ok,
           {Supervisor.sup_flags(),
            [Supervisor.child_spec() | (old_erlang_child_spec :: :supervisor.child_spec())]}}
  def init({server_pid, config}) do
    one_endpoint? =
      not is_nil(config.datagram_options.datagram_handler) or config.port == 0 or config.broadcast or
        config.transport_module == Abyss.Transport.UDP.Multicast or
        Enum.any?(config.transport_options, &match?({:add_membership, _}, &1))

    count = if one_endpoint?, do: 1, else: config.num_listeners

    Enum.map(1..count, fn index ->
      id = "listener-#{index}"
      Supervisor.child_spec({Abyss.Listener, {id, server_pid, config}}, id: id)
    end)
    |> Supervisor.init(strategy: :one_for_one)
  end
end

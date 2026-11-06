defmodule Abyss.Server do
  @moduledoc """
  Internal server supervisor that manages the Abyss supervision tree.

  This module is responsible for managing all components of an Abyss server instance,
  including the listener pool, connection supervisor, and shutdown coordination.

  ## Architecture

  The server manages the following children:

  - **Listener Pool**: Supervisor managing UDP listener processes
  - **Connection Supervisor**: Dynamic supervisor managing handler processes
  - **Activator Task**: Starts listener processes after initialization
  - **Shutdown Listener**: Coordinates graceful shutdown process

  ## Configuration

  The server is configured via `Abyss.ServerConfig` which contains all server
  options including port, handler module, and timeouts.

  This module is primarily used internally by `Abyss.start_link/1` and should
  not be used directly by end users.
  """

  use Supervisor

  @spec start_link(Abyss.ServerConfig.t()) :: Supervisor.on_start()
  def start_link(%Abyss.ServerConfig{} = config) do
    Supervisor.start_link(__MODULE__, config, config.supervisor_options)
  end

  def start_link(invalid_config) do
    raise ArgumentError, "invalid configuration: #{inspect(invalid_config)}"
  end

  @doc """
  Resume a suspended server by resuming the listener pool.

  This resumes admission using the original socket.
  If the server is not currently suspended or the listener pool cannot be found,
  this function returns nil.

  ## Parameters
  - `supervisor` - The server supervisor PID
  """
  @spec resume(Supervisor.supervisor()) :: :ok | :error | nil
  def resume(supervisor) do
    try do
      case listener_pool_pid(supervisor) do
        nil -> nil
        pid -> Abyss.ListenerPool.resume(pid)
      end
    rescue
      _e in [ArgumentError, UndefinedFunctionError] -> nil
    catch
      :exit, _ -> nil
    end
  end

  @doc """
  Suspend a running server by suspending the listener pool.

  This pauses admission while retaining the socket.
  Existing connections will continue to be processed. If the listener pool
  cannot be found, this function returns nil.

  ## Parameters
  - `supervisor` - The server supervisor PID
  """
  @spec suspend(Supervisor.supervisor()) :: :ok | :error | nil
  def suspend(supervisor) do
    try do
      case listener_pool_pid(supervisor) do
        nil -> nil
        pid -> Abyss.ListenerPool.suspend(pid)
      end
    rescue
      _e in [ArgumentError, UndefinedFunctionError] -> nil
    catch
      :exit, _ -> nil
    end
  end

  @doc """
  Get the PID of the listener pool for a server.

  ## Parameters
  - `supervisor` - The server supervisor PID

  ## Returns
  - The listener pool PID if found and alive, `nil` otherwise
  """
  @spec listener_pool_pid(Supervisor.supervisor()) :: pid() | nil
  def listener_pool_pid(supervisor), do: find_child_pid(supervisor, :listener_pool)

  @doc """
  Get the PID of the connection supervisor for a server.

  ## Parameters
  - `supervisor` - The server supervisor PID

  ## Returns
  - The connection supervisor PID if found and alive, `nil` otherwise
  """
  @spec connection_sup_pid(Supervisor.supervisor()) :: pid() | nil
  def connection_sup_pid(supervisor), do: find_child_pid(supervisor, :connection_sup)

  @doc """
  Get the PID of the listener pool scaler for a server.

  The scaler is only started when the server is configured with
  `dynamic_listeners: true` in unicast mode.

  ## Parameters
  - `supervisor` - The server supervisor PID

  ## Returns
  - The scaler PID if found and alive, `nil` otherwise
  """
  @spec listener_pool_scaler_pid(Supervisor.supervisor()) :: pid() | nil
  def listener_pool_scaler_pid(supervisor),
    do: find_child_pid(supervisor, :listener_pool_scaler)

  defp find_child_pid(supervisor, child_id) do
    try do
      if Process.alive?(supervisor) do
        supervisor
        |> Supervisor.which_children()
        |> Enum.find_value(fn
          {^child_id, pid, _, _} when is_pid(pid) -> pid
          _ -> nil
        end)
      else
        nil
      end
    rescue
      _e in [ArgumentError, UndefinedFunctionError] -> nil
    catch
      :exit, _ -> nil
    end
  end

  @doc false
  def memberships(server), do: endpoint_operation(server, &Abyss.Listener.memberships/1)

  def join(server, membership),
    do: endpoint_operation(server, &Abyss.Listener.join(&1, membership))

  def leave(server, membership),
    do: endpoint_operation(server, &Abyss.Listener.leave(&1, membership))

  defp endpoint_operation(server, operation) do
    case listener_pool_pid(server) do
      nil ->
        {:error, :not_running}

      pool ->
        case Abyss.ListenerPool.listener_pids(pool) do
          [listener] -> operation.(listener)
          _ -> {:error, :multiple_receive_endpoints}
        end
    end
  end

  def stop(server, timeout) when timeout == :infinity or (is_integer(timeout) and timeout >= 0) do
    deadline =
      if timeout == :infinity, do: :infinity, else: System.monotonic_time(:millisecond) + timeout

    listeners = Abyss.Listener.for_server(server)
    Enum.each(listeners, &Abyss.Listener.pause/1)
    Enum.each(listeners, &Abyss.Listener.drain(&1, deadline))

    Supervisor.stop(server, :normal, :infinity)
  end

  @impl Supervisor
  @spec init(Abyss.ServerConfig.t()) ::
          {:ok,
           {Supervisor.sup_flags(),
            [Supervisor.child_spec() | (old_erlang_child_spec :: :supervisor.child_spec())]}}
  def init(config) do
    server_pid = self()

    # Initialize telemetry metrics
    Abyss.Telemetry.init_metrics()
    Abyss.Telemetry.register_scope(server_pid, config.handler_module)

    children =
      [
        {Abyss.ListenerPool, {server_pid, config}}
        |> Supervisor.child_spec(id: :listener_pool),
        {DynamicSupervisor, strategy: :one_for_one, max_children: config.num_connections}
        |> Supervisor.child_spec(id: :connection_sup, shutdown: :brutal_kill),
        Supervisor.child_spec(
          {Task,
           fn ->
             server_pid
             |> Abyss.Server.listener_pool_pid()
             |> Abyss.ListenerPool.start_listening()
           end},
          id: :activator
        )
      ] ++
        scaler_child_specs(config, server_pid) ++
        [
          {Abyss.ShutdownListener, {server_pid, config.shutdown_timeout}}
          |> Supervisor.child_spec(id: :shutdown_listener, shutdown: :infinity)
        ]

    Supervisor.init(children, strategy: :rest_for_one)
  end

  # The scaler only makes sense for unicast listener pools; broadcast mode
  # always uses a single listener.
  defp scaler_child_specs(
         %Abyss.ServerConfig{dynamic_listeners: true, broadcast: false} = config,
         server_pid
       ) do
    [
      {Abyss.ListenerPoolScaler, [server_supervisor: server_pid, server_config: config]}
      |> Supervisor.child_spec(id: :listener_pool_scaler)
    ]
  end

  defp scaler_child_specs(_config, _server_pid), do: []
end

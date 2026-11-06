defmodule Hell.Connection do
  @moduledoc false

  @type start_error() ::
          :too_many_connections
          | {:spawn_error, term()}
          | {:controlling_process, Hell.Transport.controlling_process_error()}

  @spec start(
          Supervisor.supervisor(),
          Hell.Transport.socket(),
          Hell.ServerConfig.t(),
          Hell.HandlerConfig.t(),
          Hell.Telemetry.t()
        ) ::
          :ok | {:error, start_error()}
  def start(
        sup_pid,
        raw_socket,
        %Hell.ServerConfig{} = server_config,
        %Hell.HandlerConfig{} = handler_config,
        acceptor_span
      ) do
    # This is a multi-step process since we need to do a bit of work from within
    # the process which owns the socket (us, at this point).

    # First, capture the start time for telemetry purposes
    start_time = Hell.Telemetry.monotonic_time()

    acceptor = self()
    handoff_ref = make_ref()

    # Start by defining the worker process which will eventually handle this socket
    child_spec =
      {server_config.handler_module,
       {server_config.handler_options, server_config.genserver_options}}
      |> Supervisor.child_spec(shutdown: server_config.shutdown_timeout)
      |> then(fn spec ->
        %{spec | start: {__MODULE__, :start_handler, [spec.start, acceptor, handoff_ref]}}
      end)

    # Then try to create it
    case start_child_with_retry(
           sup_pid,
           child_spec,
           server_config.max_connections_retry_wait,
           server_config.max_connections_retry_count
         ) do
      result when elem(result, 0) == :ok and tuple_size(result) in [2, 3] ->
        pid = elem(result, 1)

        guard =
          receive do
            {^handoff_ref, guard} -> guard
          end

        case handler_config.transport_module.controlling_process(raw_socket, pid) do
          :ok ->
            # The guard forwards readiness itself. Messages and the acceptor's DOWN signal are
            # ordered, so a successful handoff survives the acceptor exiting immediately after it.
            send(
              guard,
              {:ready, {:hell_ready, raw_socket, handler_config, acceptor_span, start_time}}
            )

            :ok

          {:error, reason} ->
            _ = handler_config.transport_module.close(raw_socket)
            _ = DynamicSupervisor.terminate_child(sup_pid, pid)
            {:error, {:controlling_process, reason}}
        end

      {:error, :max_children} ->
        # We gave up trying to find room for this connection in our supervisor.
        # Close the raw socket here and let the acceptor process handle propagating the error
        handler_config.transport_module.close(raw_socket)
        {:error, :too_many_connections}

      {:error, reason} ->
        # The handler process could not be started, for example because its
        # init returned `{:stop, reason}`. We still own the raw socket at this
        # point, so close it (rather than leaving it open until this acceptor
        # exits), and report a spawn error so the acceptor can carry on rather
        # than crashing on an otherwise-successful accept
        _ = handler_config.transport_module.close(raw_socket)
        {:error, {:spawn_error, reason}}

      other ->
        # `:ignore`, or a nonstandard return from the handler's start_link.
        # Handled exactly as above
        _ = handler_config.transport_module.close(raw_socket)
        {:error, {:spawn_error, other}}
    end
  end

  @doc false
  @spec start_handler({module(), atom(), [term()]}, pid(), reference()) ::
          Supervisor.on_start_child()
  def start_handler({module, function, arguments}, acceptor, handoff_ref) do
    result = apply(module, function, arguments)

    case result do
      result when elem(result, 0) == :ok and tuple_size(result) in [2, 3] ->
        handler = elem(result, 1)
        guard = spawn(__MODULE__, :guard_handoff, [acceptor, handler])
        send(acceptor, {handoff_ref, guard})

      _ ->
        :ok
    end

    result
  end

  @doc false
  @spec guard_handoff(pid(), pid()) :: :ok
  def guard_handoff(acceptor, handler) do
    acceptor_monitor = Process.monitor(acceptor)
    handler_monitor = Process.monitor(handler)

    receive do
      {:ready, message} ->
        Process.demonitor(acceptor_monitor, [:flush])
        Process.demonitor(handler_monitor, [:flush])
        send(handler, message)

      {:DOWN, ^acceptor_monitor, :process, ^acceptor, _} ->
        # Startup did not finish. The child may trap exits, so guarantee that its socket and
        # admission slot are released instead of leaving it waiting forever for readiness.
        Process.exit(handler, :kill)

      {:DOWN, ^handler_monitor, :process, ^handler, _} ->
        :ok
    end

    :ok
  end

  defp start_child_with_retry(sup_pid, child_spec, retry_wait, retries) do
    case DynamicSupervisor.start_child(sup_pid, child_spec) do
      {:error, :max_children} when retries > 0 ->
        # We're in a tricky spot here; we have a client connection in hand, but no room to put it
        # into the connection supervisor. We try to wait a maximum number of times to see if any
        # room opens up before we give up
        Process.sleep(retry_wait)
        start_child_with_retry(sup_pid, child_spec, retry_wait, retries - 1)

      result ->
        result
    end
  end
end

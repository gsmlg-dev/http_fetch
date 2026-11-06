defmodule Hell.LifecycleRegressionTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  defmodule Echo do
    use Hell.Handler

    @impl Hell.Handler
    def handle_connection(_socket, test_pid) when is_pid(test_pid) do
      send(test_pid, {:handler_monitors, Process.info(self(), :monitored_by)})
      {:continue, test_pid}
    end

    def handle_connection(_socket, state), do: {:continue, state}

    @impl Hell.Handler
    def handle_data(data, socket, state) do
      Hell.Socket.send(socket, data)
      {:continue, state}
    end
  end

  defmodule BlockingStartHandler do
    use GenServer, restart: :temporary

    def start_link({handler_options, options}) do
      {test_pid, extra} =
        case handler_options do
          {pid, value} -> {pid, value}
          pid -> {pid, nil}
        end

      {:ok, handler} = GenServer.start_link(__MODULE__, test_pid, options)
      send(test_pid, {:handler_starting, self(), handler})

      receive do
        :continue_start -> if extra, do: {:ok, handler, extra}, else: {:ok, handler}
      end
    end

    @impl true
    def init(test_pid), do: {:ok, test_pid}

    @impl true
    def handle_info({:hell_ready, socket, config, span, start_time}, test_pid) do
      send(test_pid, {:custom_handler_ready, self(), config, span, start_time})
      {:noreply, {test_pid, socket}}
    end

    @impl true
    def handle_call(:echo, _from, {_, socket} = state) do
      {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)
      :ok = :gen_tcp.send(socket, data)
      {:reply, :ok, state}
    end
  end

  defmodule PausedTCP do
    import Kernel, except: [send: 2]

    for {name, arity} <- Hell.Transports.TCP.__info__(:functions),
        name != :controlling_process do
      args = Macro.generate_arguments(arity, __MODULE__)

      def unquote(name)(unquote_splicing(args)),
        do: apply(Hell.Transports.TCP, unquote(name), [unquote_splicing(args)])
    end

    def controlling_process(socket, handler) do
      {test_pid, stage} = :persistent_term.get(__MODULE__)

      if stage == :ownership_error do
        {:error, :badarg}
      else
        if stage == :after_transfer do
          :ok = Hell.Transports.TCP.controlling_process(socket, handler)
        end

        Kernel.send(test_pid, {:handoff_paused, self(), handler, socket})

        receive do
          :continue_handoff -> :ok
        end
      end
    end
  end

  @tag capture_log: true
  test "an acceptor pool crash preserves the listener and recovers acceptance" do
    server = start_supervised!({Hell, port: 0, num_acceptors: 1, handler_module: Echo})
    {:ok, {_ip, port}} = Hell.listener_info(server)
    listener = Hell.Server.listener_pid(server)
    pool = Hell.Server.acceptor_pool_supervisor_pid(server)
    {_, helper, _, _} = List.keyfind(Supervisor.which_children(server), :shutdown_listener, 0)
    assert %{listener: ^listener} = :sys.get_state(helper)
    ref = Process.monitor(helper)
    Process.exit(pool, :kill)
    assert_receive {:DOWN, ^ref, :process, ^helper, _}, 1_000

    assert Hell.Server.listener_pid(server) == listener
    {:ok, client} = :gen_tcp.connect(~c"localhost", port, active: false, mode: :binary)
    assert :ok = :gen_tcp.send(client, "recovered")
    assert {:ok, "recovered"} = :gen_tcp.recv(client, 0, 1_000)
    :gen_tcp.close(client)
  end

  @tag capture_log: true
  test "an abnormal shutdown helper exit preserves the healthy listener" do
    server = start_supervised!({Hell, port: 0, num_acceptors: 1, handler_module: Echo})
    listener = Hell.Server.listener_pid(server)
    {_, helper, _, _} = List.keyfind(Supervisor.which_children(server), :shutdown_listener, 0)
    assert %{listener: ^listener} = :sys.get_state(helper)
    assert :ok = GenServer.stop(helper, :review_crash)
    assert Hell.Server.listener_pid(server) == listener
  end

  test "shutdown tolerates a missing pool during partial setup" do
    assert :ok = Hell.ShutdownListener.terminate(:shutdown, %{listener: self()})

    assert :ok =
             Hell.ShutdownListener.terminate(:shutdown, %{
               listener: self(),
               acceptor_pool_supervisor: nil
             })
  end

  test "an acceptor dying during custom handler startup cannot leave an idle handler" do
    server =
      start_supervised!(
        {Hell,
         port: 0, num_acceptors: 1, handler_module: BlockingStartHandler, handler_options: self()}
      )

    {:ok, {_ip, port}} = Hell.listener_info(server)
    {:ok, client} = :gen_tcp.connect(~c"localhost", port, active: false)
    assert_receive {:handler_starting, connection_supervisor, handler}, 1_000
    ref = Process.monitor(handler)
    assert :ok = Hell.suspend(server)
    send(connection_supervisor, :continue_start)
    assert_receive {:DOWN, ^ref, :process, ^handler, _}, 1_000
    assert {:ok, []} = Hell.connection_pids(server)
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1_000)
    :gen_tcp.close(client)
  end

  test "successful default handoff releases its guard and survives suspension" do
    server =
      start_supervised!(
        {Hell, port: 0, num_acceptors: 1, handler_module: Echo, handler_options: self()}
      )

    connection_supervisor = trace_connection_supervisor(server)
    {:ok, {_ip, port}} = Hell.listener_info(server)
    {:ok, client} = :gen_tcp.connect(~c"localhost", port, active: false, mode: :binary)

    assert_receive {:trace, ^connection_supervisor, :spawn, guard,
                    {Hell.Connection, :guard_handoff, [_acceptor, _handler]}},
                   1_000

    assert_receive {:trace, ^guard, :exit, :normal}, 1_000
    assert_receive {:handler_monitors, {:monitored_by, []}}, 1_000
    assert :ok = Hell.suspend(server)
    assert :ok = :gen_tcp.send(client, "still connected")
    assert {:ok, "still connected"} = :gen_tcp.recv(client, 0, 1_000)
    :gen_tcp.close(client)
  end

  test "custom start information and the original readiness tuple remain supported" do
    server =
      start_supervised!(
        {Hell,
         port: 0,
         num_acceptors: 1,
         handler_module: BlockingStartHandler,
         handler_options: {self(), :custom_start_info}}
      )

    connection_supervisor = trace_connection_supervisor(server)
    {:ok, {_ip, port}} = Hell.listener_info(server)
    {:ok, client} = :gen_tcp.connect(~c"localhost", port, active: false, mode: :binary)
    assert_receive {:handler_starting, ^connection_supervisor, handler}, 1_000
    send(connection_supervisor, :continue_start)

    assert_receive {:trace, ^connection_supervisor, :spawn, guard,
                    {Hell.Connection, :guard_handoff, [_acceptor, ^handler]}},
                   1_000

    assert_receive {:custom_handler_ready, ^handler,
                    %Hell.HandlerConfig{handler_module: BlockingStartHandler},
                    %Hell.Telemetry{span_name: :acceptor}, start_time},
                   1_000

    assert is_integer(start_time)
    assert_receive {:trace, ^guard, :exit, :normal}, 1_000
    assert :ok = :gen_tcp.send(client, "custom")
    assert :ok = GenServer.call(handler, :echo)
    assert {:ok, "custom"} = :gen_tcp.recv(client, 0, 1_000)
    :gen_tcp.close(client)
  end

  test "a handler dying before readiness also releases its guard" do
    :persistent_term.put(PausedTCP, {self(), :after_transfer})
    on_exit(fn -> :persistent_term.erase(PausedTCP) end)

    server =
      start_supervised!(
        {Hell, port: 0, num_acceptors: 1, handler_module: Echo, transport_module: PausedTCP}
      )

    connection_supervisor = trace_connection_supervisor(server)
    {:ok, {_ip, port}} = Hell.listener_info(server)
    {:ok, client} = :gen_tcp.connect(~c"localhost", port, active: false)
    assert_receive {:handoff_paused, acceptor, handler, _socket}, 1_000

    assert_receive {:trace, ^connection_supervisor, :spawn, guard,
                    {Hell.Connection, :guard_handoff, [^acceptor, ^handler]}},
                   1_000

    Process.exit(handler, :kill)
    assert_receive {:trace, ^guard, :exit, :normal}, 1_000
    send(acceptor, :continue_handoff)
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1_000)
    :gen_tcp.close(client)
  end

  test "an ownership transfer error releases the idle handler and guard" do
    :persistent_term.put(PausedTCP, {self(), :ownership_error})
    on_exit(fn -> :persistent_term.erase(PausedTCP) end)

    server =
      start_supervised!(
        {Hell, port: 0, num_acceptors: 1, handler_module: Echo, transport_module: PausedTCP}
      )

    connection_supervisor = trace_connection_supervisor(server)
    {:ok, {_ip, port}} = Hell.listener_info(server)
    {:ok, client} = :gen_tcp.connect(~c"localhost", port, active: false)

    assert_receive {:trace, ^connection_supervisor, :spawn, guard,
                    {Hell.Connection, :guard_handoff, [_acceptor, handler]}},
                   1_000

    assert_receive {:trace, ^guard, :exit, :normal}, 1_000
    refute Process.alive?(handler)
    assert {:ok, []} = Hell.connection_pids(server)
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1_000)
    :gen_tcp.close(client)
  end

  for stage <- [:before_transfer, :after_transfer] do
    @tag stage: stage
    test "suspension during handoff #{stage} releases the handler and its connection slot", %{
      stage: stage
    } do
      :persistent_term.put(PausedTCP, {self(), stage})
      on_exit(fn -> :persistent_term.erase(PausedTCP) end)

      server =
        start_supervised!(
          {Hell,
           port: 0,
           num_acceptors: 1,
           num_connections: 1,
           max_connections_retry_count: 0,
           handler_module: Echo,
           transport_module: PausedTCP}
        )

      {:ok, {_ip, port}} = Hell.listener_info(server)
      {:ok, client} = :gen_tcp.connect(~c"localhost", port, active: false)
      assert_receive {:handoff_paused, _acceptor, handler, _socket}, 1_000
      ref = Process.monitor(handler)
      assert :ok = Hell.suspend(server)
      assert_receive {:DOWN, ^ref, :process, ^handler, _}, 1_000
      assert {:ok, []} = Hell.connection_pids(server)
      assert {:error, :closed} = :gen_tcp.recv(client, 0, 1_000)
      :gen_tcp.close(client)
    end
  end

  defp trace_connection_supervisor(server) do
    pool = Hell.Server.acceptor_pool_supervisor_pid(server)
    [acceptor_supervisor] = Hell.AcceptorPoolSupervisor.acceptor_supervisor_pids(pool)
    connection_supervisor = Hell.AcceptorSupervisor.connection_sup_pid(acceptor_supervisor)
    :erlang.trace(connection_supervisor, true, [:procs, :set_on_spawn])
    connection_supervisor
  end
end

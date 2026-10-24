defmodule SSL.Lifecycle.PublicCleanupBoundariesTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.Lifecycle

  @ip {127, 0, 0, 1}

  test "killed public Connection retires a genuinely native-blocked Writer and its Socket" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ssl.close(socket)
      end)

    {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(5_000))

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(proxy.task.pid), do: Task.shutdown(proxy.task, :brutal_kill)
      Process.exit(proxy.controller, :kill)
      :gen_tcp.close(proxy.listener)
      if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end)

    options = Peer.client_options() ++ [send_timeout: 10_000, sndbuf: 4_096]
    options = options ++ [ex_ssl: [lifecycle: {handle, lease}]]
    assert {:ok, socket} = SSL.connect(@ip, proxy.port, options, 3_000)

    assert {:pending, %{setup: :connected, logical: :open, cleanup: :pending}} =
             Lifecycle.status(handle)

    # Provider fault instrumentation captures original enrolled identities. The
    # consumer observations below use only SSL and Lifecycle's public facade.
    observer = handle.receipt.observer
    %{resources: resources} = :sys.get_state(observer)
    %{identity: {_, :process, connection}, live: true} = resources.connection
    %{identity: {_, :process, writer}, live: true} = resources.writer
    %{identity: {_, :socket, tcp}, live: true} = resources.tcp
    assert connection == socket.pid

    helpers =
      for role <- [:setup, :allocator] do
        assert %{identity: {_, :process, pid} = identity, done: true, live: live} =
                 resources[role]

        monitor =
          if live and Process.alive?(pid) do
            Process.monitor(pid)
          else
            refute Process.alive?(pid)
            nil
          end

        {identity, monitor}
      end

    connection_monitor = Process.monitor(connection)
    writer_monitor = Process.monitor(writer)
    tcp_monitor = :socket.monitor(tcp)
    observer_monitor = Process.monitor(observer)
    proxy_monitor = Process.monitor(proxy.task.pid)
    controller_monitor = Process.monitor(proxy.controller)
    peer_monitor = Process.monitor(peer.task.pid)

    ref = proxy.ref
    assert :ok = Peer.pause_client_to_server(proxy, self())
    assert_receive {:backpressure_proxy, ^ref, :paused}, 1_000
    send_started = absolute(0)
    sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 16 * 1_048_576)) end)
    assert_receive {:backpressure_proxy, ^ref, :held, count}, 5_000
    assert count > 0
    blocked = native_blocked(connection, writer, tcp, absolute(2_000))
    assert blocked.write.deadline == blocked.output.deadline
    assert blocked.write.deadline >= send_started + 10_000
    assert is_integer(Process.read_timer(blocked.output.timer))
    assert Task.yield(sender, 0) == nil

    killed_at = absolute(0)
    Process.exit(connection, :kill)
    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, :killed}, 1_000
    assert {:error, :econnreset} = Task.await(sender, 1_000)
    assert {:error, :econnreset} = SSL.recv(socket, 0, 0)
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000
    assert_receive {:DOWN, ^tcp_monitor, :socket, ^tcp, :closed}, 1_000

    for {{_, :process, pid}, monitor} <- helpers do
      if monitor do
        remaining = max(killed_at + 1_000 - absolute(0), 0)
        # A raced :noproc establishes absence, not the historical exit reason.
        assert_receive {:DOWN, ^monitor, :process, ^pid, _reason}, remaining
      end

      refute Process.alive?(pid)
    end

    assert absolute(0) - killed_at < 1_000

    assert {:ok,
            %{
              setup: :connected,
              logical: :closed,
              cleanup: :confirmed,
              roles: 31,
              observed_down: 31,
              losses: 0
            } = receipt} =
             Lifecycle.await(handle, deadline(1_000))

    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1_000
    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))
    refute tcp in :socket.which_sockets()

    assert {:ok, :ok} = Peer.stop_backpressure_proxy(proxy)
    assert_receive {:DOWN, ^proxy_monitor, :process, _, :normal}, 1_000
    assert_receive {:DOWN, ^controller_monitor, :process, _, _}, 1_000
    assert :ok = Peer.stop(peer)
    assert_receive {:DOWN, ^peer_monitor, :process, _, :normal}, 1_000
    assert Port.info(proxy.listener) == nil
  end

  test "public connect after confirmed cancellation cannot allocate or accept a peer" do
    options = Peer.client_options()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {@ip, port}} = :inet.sockname(listener)
    sockets_before = MapSet.new(:socket.which_sockets())
    connections_before = DynamicSupervisor.which_children(SSL.ConnectionSupervisor)
    observers_before = DynamicSupervisor.which_children(SSL.Lifecycle.ObserverSupervisor)
    listener_owner = Port.info(listener, :connected)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)

    assert {:pending, %{setup: :not_started, roles: 0, allocations: 0}} =
             Lifecycle.status(handle)

    assert :ok = Lifecycle.cancel(lease, deadline(1_000))

    receipt = %{
      version: 1,
      scope: :dial,
      setup: :cancelled,
      setup_failure: :cancelled,
      logical: :closed,
      cleanup: :confirmed,
      roles: 0,
      observed_down: 0,
      losses: 0,
      epoch: 0
    }

    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(1_000))
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1_000

    assert {:error, :acceptance_unconfirmed} =
             SSL.connect(
               @ip,
               port,
               options ++ [ex_ssl: [lifecycle: {handle, lease}]],
               1_000
             )

    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    assert MapSet.new(:socket.which_sockets()) == sockets_before
    assert DynamicSupervisor.which_children(SSL.ConnectionSupervisor) == connections_before
    assert DynamicSupervisor.which_children(SSL.Lifecycle.ObserverSupervisor) == observers_before
    assert Port.info(listener, :connected) == listener_owner
  end

  test "wrong CA retires the original public setup graph to its warmed baseline" do
    root = Path.expand("../../fixtures/pkix/wrong_root.pem", __DIR__)
    certificates = for {:Certificate, der, _} <- :public_key.pem_decode(File.read!(root)), do: der
    failed_authentication([cacerts: certificates], :unknown_ca)
  end

  test "wrong identity retires the original public setup graph to its warmed baseline" do
    failed_authentication([server_name_indication: ~c"wrong.test"], :certificate_unknown)
  end

  test "option rejection has no provider data birth and restores the warmed baseline" do
    options = Peer.client_options() |> Enum.reject(&(&1 == :binary)) |> Keyword.put(:active, true)
    baseline = provider_baseline()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
    on_exit(fn -> :gen_tcp.close(listener) end)
    listener_monitor = :erlang.monitor(:port, listener)
    {:ok, {@ip, port}} = :inet.sockname(listener)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)

    assert {:pending, %{setup: :not_started, roles: 0, allocations: 0}} =
             Lifecycle.status(handle)

    assert {:error, {:options, {:active, :unsupported_or_invalid}}} =
             SSL.connect(@ip, port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], 1_000)

    receipt = terminal_receipt(:failed, :options, 0)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(1_000))
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1_000
    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    assert :ok = :gen_tcp.close(listener)
    assert_receive {:DOWN, ^listener_monitor, :port, ^listener, :normal}, 1_000
    assert provider_baseline() == baseline
  end

  test "setup cancellation retires the original graph after the ClientHello attach ACK" do
    options = Peer.client_options()
    baseline = provider_baseline()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
    on_exit(fn -> :gen_tcp.close(listener) end)
    listener_monitor = :erlang.monitor(:port, listener)
    {:ok, {@ip, port}} = :inet.sockname(listener)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)

    caller =
      Task.async(fn ->
        SSL.connect(@ip, port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], :infinity)
      end)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
    end)

    {:ok, accepted} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(accepted) end)
    accepted_monitor = :erlang.monitor(:port, accepted)
    assert {:ok, <<22, _major, _minor, length::16>>} = :gen_tcp.recv(accepted, 5, 1_000)

    assert {:ok, <<1, _handshake_length::24, _hello::binary>>} =
             :gen_tcp.recv(accepted, length, 1_000)

    await_setup_handshake(handle, absolute(1_000))
    assert {:pending, %{setup: :pending, roles: 31, allocations: 0}} = Lifecycle.status(handle)
    graph = capture_graph(handle)
    cancelled_at = absolute(0)
    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    assert {:error, :closed} = Task.await(caller, 1_000)
    assert_graph_closed(graph)
    assert absolute(0) - cancelled_at < 1_000
    receipt = terminal_receipt(:cancelled, :cancelled, 31)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(1_000))
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1_000
    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))
    assert {:error, :closed} = :gen_tcp.recv(accepted, 0, 1_000)
    assert :ok = :gen_tcp.close(accepted)
    assert :ok = :gen_tcp.close(listener)
    assert_receive {:DOWN, ^accepted_monitor, :port, ^accepted, :normal}, 1_000
    assert_receive {:DOWN, ^listener_monitor, :port, ^listener, :normal}, 1_000
    assert provider_baseline() == baseline
  end

  test "established cancellation restores the warmed provider baseline after authenticated traffic" do
    options = Peer.client_options()
    :ok = :ssl.start()
    baseline = provider_baseline()

    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:ok, "ping"} = :ssl.recv(socket, 4, 1_000)
        assert :ok = :ssl.send(socket, "pong")
        assert {:error, :closed} = :ssl.recv(socket, 0, 1_000)
        :ssl.close(socket)
      end)

    peer_monitor = Process.monitor(peer.task.pid)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(5_000))
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end)

    assert {:ok, socket} =
             SSL.connect(@ip, peer.port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], 3_000)

    assert :ok = SSL.send(socket, "ping")
    assert {:ok, "pong"} = SSL.recv(socket, 4, 1_000)
    assert {:pending, %{setup: :connected, roles: 31, allocations: 0}} = Lifecycle.status(handle)
    graph = capture_graph(handle)
    cancelled_at = absolute(0)
    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    assert_graph_closed(graph)
    assert absolute(0) - cancelled_at < 1_000
    receipt = terminal_receipt(:connected, :none, 31)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(1_000))
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1_000
    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))
    assert :ok = Peer.stop(peer)
    assert_receive {:DOWN, ^peer_monitor, :process, _, :normal}, 1_000
    assert provider_baseline() == baseline
  end

  defp await_setup_handshake(handle, limit) do
    assert absolute(0) < limit

    %{resources: %{setup: %{identity: {_, :process, setup}}}} =
      :sys.get_state(handle.receipt.observer)

    case :sys.get_state(setup) do
      %{phase: :tls_handshaking} ->
        :ok

      _ ->
        receive do
        after
          1 -> await_setup_handshake(handle, limit)
        end
    end
  end

  defp failed_authentication(overrides, expected_alert) do
    options = Peer.client_options() |> Enum.reject(&(&1 == :binary)) |> Keyword.merge(overrides)
    :ok = :ssl.start()
    baseline = provider_baseline()
    {:ok, peer} = Peer.start(fn socket -> :ssl.close(socket) end)
    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self(), initially_gated: true)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(5_000))
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)
    peer_monitor = Process.monitor(peer.task.pid)
    proxy_monitor = Process.monitor(proxy.task.pid)
    controller_monitor = Process.monitor(proxy.controller)
    listener_monitor = :erlang.monitor(:port, proxy.listener)

    caller =
      Task.async(fn ->
        SSL.connect(@ip, proxy.port, options ++ [ex_ssl: [lifecycle: {handle, lease}]], 3_000)
      end)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
      Process.exit(proxy.controller, :kill)
      :gen_tcp.close(proxy.listener)
      if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end)

    ref = proxy.ref
    assert_receive {:tls_record_proxy, ^ref, :gated}, 1_000
    assert_receive {:tls_record_proxy, ^ref, :queued, _}, 1_000
    assert {:pending, %{setup: :pending, roles: 31, allocations: 0}} = Lifecycle.status(handle)
    graph = capture_graph(handle)
    for _ <- 1..32, do: Peer.release_server_record(proxy)

    assert {:error, {:tls_alert, {^expected_alert, ~c"TLS protocol error"}}} =
             Task.await(caller, 3_000)

    assert_graph_closed(graph)
    receipt = terminal_receipt(:failed, :tls, 31)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(1_000))
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1_000
    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))

    assert {:handshake_error, _reason} = Peer.stop(peer)
    assert_receive {:DOWN, ^peer_monitor, :process, _, :normal}, 1_000
    Peer.stop_record_gate_proxy(proxy)
    assert_receive {:DOWN, ^proxy_monitor, :process, _, _}, 1_000
    assert_receive {:DOWN, ^controller_monitor, :process, _, _}, 1_000
    assert_receive {:DOWN, ^listener_monitor, :port, _, _}, 1_000
    assert Port.info(proxy.listener) == nil
    assert provider_baseline() == baseline
  end

  defp capture_graph(handle) do
    %{resources: resources, permits: permits} = :sys.get_state(handle.receipt.observer)
    assert map_size(permits) == 0
    assert Enum.sort(Map.keys(resources)) == [:allocator, :connection, :setup, :tcp, :writer]

    Enum.map(resources, fn
      {role, %{identity: {_, :process, pid}, live: true}} ->
        {role, :process, pid, Process.monitor(pid)}

      {role, %{identity: {_, :process, pid}, live: false, done: true}}
      when role in [:setup, :allocator] ->
        refute Process.alive?(pid)
        {role, :retired_process, pid, nil}

      {:tcp, %{identity: {_, :socket, socket}, live: true}} ->
        {:tcp, :socket, socket, :socket.monitor(socket)}
    end)
  end

  defp assert_graph_closed(graph) do
    for {_role, type, object, monitor} <- graph do
      case type do
        :retired_process ->
          refute Process.alive?(object)

        :process ->
          assert_receive {:DOWN, ^monitor, :process, ^object, _}, 1_000
          refute Process.alive?(object)

        :socket ->
          assert_receive {:DOWN, ^monitor, :socket, ^object, :closed}, 1_000
          refute object in :socket.which_sockets()
      end
    end
  end

  defp provider_baseline do
    %{
      sockets: MapSet.new(:socket.which_sockets()),
      connections: DynamicSupervisor.which_children(SSL.ConnectionSupervisor),
      observers: DynamicSupervisor.which_children(SSL.Lifecycle.ObserverSupervisor)
    }
  end

  defp terminal_receipt(setup, failure, roles) do
    %{
      version: 1,
      scope: :dial,
      setup: setup,
      setup_failure: failure,
      logical: :closed,
      cleanup: :confirmed,
      roles: roles,
      observed_down: roles,
      losses: 0,
      epoch: 0
    }
  end

  defp native_blocked(connection, writer, tcp, limit) do
    assert absolute(0) < limit
    {:connected, state} = :sys.get_state(connection)
    before = :socket.info(tcp)

    if match?(%{output: %{kind: :application}}, state) and native_waiting?(writer, before) do
      receive do
      after
        50 -> :ok
      end

      after_wait = :socket.info(tcp)
      {:connected, current} = :sys.get_state(connection)
      counters = [:write_byte, :write_pkg, :write_tries, :write_waits]

      if native_waiting?(writer, after_wait) and current.output == state.output and
           Map.take(before.counters, counters) == Map.take(after_wait.counters, counters) do
        current
      else
        native_blocked(connection, writer, tcp, limit)
      end
    else
      receive do
      after
        1 -> native_blocked(connection, writer, tcp, limit)
      end
    end
  end

  defp native_waiting?(writer, %{counters: %{write_waits: waits}, num_writers: 1, wstates: states})
       when waits > 0 do
    :selected in states and
      match?(
        [status: :waiting, current_function: {:socket, _function, _arity}],
        Process.info(writer, [:status, :current_function])
      )
  end

  defp native_waiting?(_writer, _info), do: false
  defp absolute(ms), do: System.monotonic_time(:millisecond) + ms
  defp deadline(ms), do: {:abs_ms, absolute(ms)}
end

defmodule SSL.VerifyFunLifecycleTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.Lifecycle

  @ip {127, 0, 0, 1}

  for route <- [:dial, :prepared], trigger <- [:cancel, :deadline] do
    @tag :verify_fun_lifecycle
    test "blocked verify_fun #{route} setup honors #{trigger} and confirms original resources DOWN" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          callback_setup_boundary(unquote(route), unquote(trigger))
        end)

      refute log =~ "R44_CALLBACK_LIFECYCLE_PRIVATE"
    end
  end

  defp callback_setup_boundary(route, trigger) do
    parent = self()
    ref = make_ref()

    private = %{
      marker: "R44_CALLBACK_LIFECYCLE_PRIVATE",
      token: make_ref(),
      fun: fn -> :private end
    }

    verify = blocking_verify_fun(parent, ref)

    options =
      Peer.client_options()
      |> Enum.reject(&(&1 == :binary))
      |> Keyword.put(:verify_fun, {verify, private})

    prepared =
      if route == :prepared do
        assert {:ok, prepared} = SSL.prepare_upgrade(options)
        refute_receive {^ref, :callback_entered, _, _}, 0
        prepared
      end

    baseline = provider_baseline()

    {:ok, peer} =
      Peer.start(fn socket ->
        send(parent, {ref, :peer_authenticated})
        :ssl.close(socket)
      end)

    setup_deadline = if trigger == :deadline, do: deadline(3_000), else: :infinity
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: setup_deadline)
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)
    peer_monitor = Process.monitor(peer.task.pid)
    attempt = [ex_ssl: [lifecycle: {handle, lease}]]

    caller =
      Task.async(fn ->
        case route do
          :dial ->
            SSL.connect(@ip, peer.port, options ++ attempt, :infinity)

          :prepared ->
            assert {:ok, tcp} = :gen_tcp.connect(@ip, peer.port, [:binary, active: false], 1_000)
            SSL.connect_prepared(tcp, prepared, attempt, :infinity)
        end
      end)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
      if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end)

    assert_receive {^ref, :callback_entered, callback_pid, ^private}, 1_000
    assert Task.yield(caller, 0) == nil
    scope = if route == :dial, do: :dial, else: :upgrade
    roles = if route == :dial, do: 31, else: 30

    assert {:pending,
            %{
              setup: :pending,
              logical: :pending,
              cleanup: :pending,
              roles: ^roles,
              allocations: 0
            } =
              snapshot} = Lifecycle.status(handle)

    # Only the observer is inspected for fault-proof identities. Querying the
    # callback-blocked Connection with :sys.get_state would itself block.
    graph = capture_graph(handle, scope)
    assert {:connection, :process, ^callback_pid, _monitor} = List.keyfind(graph, :connection, 0)

    cutoff =
      case trigger do
        :cancel ->
          assert Lifecycle.await(handle, deadline(1_150)) ==
                   {:pending, %{observer: :alive, receipt: :unsealed}}

          assert {:pending,
                  %{
                    setup: :pending,
                    logical: :pending,
                    cleanup: :pending,
                    roles: ^roles,
                    allocations: 0
                  }} = Lifecycle.status(handle)

          assert Task.yield(caller, 0) == nil
          limit = absolute(1_000)
          assert :ok = Lifecycle.cancel(lease, {:abs_ms, limit})
          limit

        :deadline ->
          {:abs_ms, original_expiry} = setup_deadline
          assert absolute(0) < original_expiry

          assert Lifecycle.await(handle, deadline(0)) ==
                   {:pending, %{observer: :alive, receipt: :unsealed}}

          assert {:pending,
                  %{
                    setup: :pending,
                    logical: :pending,
                    cleanup: :pending,
                    roles: ^roles,
                    allocations: 0
                  }} = Lifecycle.status(handle)

          original_expiry + 1_000
      end

    # Infinite connect timeout isolates the original Lifecycle setup deadline:
    # both retirement causes resolve the existing connect call as :closed.
    result = Task.await(caller, max(cutoff - absolute(0), 0))
    assert {:error, :closed} = result
    assert_graph_closed(graph, cutoff)
    failure = if trigger == :cancel, do: :cancelled, else: :timeout
    receipt = terminal_receipt(:cancelled, failure, roles) |> Map.put(:scope, scope)
    assert {:ok, ^receipt} = Lifecycle.await(handle, {:abs_ms, cutoff})

    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal},
                   max(cutoff - absolute(0), 0)

    assert absolute(0) < cutoff

    if trigger == :deadline do
      {:abs_ms, original_expiry} = setup_deadline
      assert absolute(0) >= original_expiry
    end

    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    assert {:ok, ^receipt} = Lifecycle.await(handle, deadline(0))

    refute inspect({result, snapshot, receipt}, limit: :infinity, printable_limit: :infinity) =~
             "R44_CALLBACK_LIFECYCLE_PRIVATE"

    refute_receive {^ref, :callback_released}, 0
    refute_receive {^ref, :peer_authenticated}, 0
    assert {:handshake_error, _reason} = Peer.stop(peer)
    assert_receive {:DOWN, ^peer_monitor, :process, _, :normal}, 1_000
    assert provider_baseline() == baseline
  end

  defp blocking_verify_fun(parent, ref) do
    fn _, event, state ->
      case event do
        :valid_peer ->
          send(parent, {ref, :callback_entered, self(), state})

          receive do
            {^ref, :release_callback} ->
              send(parent, {ref, :callback_released})
              {:valid, state}
          end

        {:bad_cert, reason} ->
          {:fail, reason}

        _ ->
          {:valid, state}
      end
    end
  end

  defp capture_graph(handle, scope) do
    %{resources: resources, permits: permits} = :sys.get_state(handle.receipt.observer)
    assert map_size(permits) == 0

    expected =
      if scope == :dial,
        do: [:allocator, :connection, :setup, :tcp, :writer],
        else: [:connection, :setup, :tcp, :writer]

    assert Enum.sort(Map.keys(resources)) == expected

    Enum.map(resources, fn
      {role, %{identity: {_, :process, pid}, live: true}} ->
        {role, :process, pid, Process.monitor(pid)}

      {role, %{identity: {_, :process, pid}, live: false, done: true}}
      when role in [:setup, :allocator] ->
        refute Process.alive?(pid)
        {role, :retired_process, pid, nil}

      {:tcp, %{identity: {_, :socket, socket}, live: true}} ->
        {:tcp, :socket, socket, :socket.monitor(socket)}

      {:tcp, %{identity: {_, :port, port}, live: true}} ->
        {:tcp, :port, port, :erlang.monitor(:port, port)}
    end)
  end

  defp assert_graph_closed(graph, limit) do
    for {_role, type, object, monitor} <- graph do
      timeout = max(limit - absolute(0), 0)

      case type do
        :retired_process ->
          refute Process.alive?(object)

        :process ->
          assert_receive {:DOWN, ^monitor, :process, ^object, _}, timeout
          refute Process.alive?(object)

        :port ->
          assert_receive {:DOWN, ^monitor, :port, ^object, _}, timeout
          assert Port.info(object) == nil

        :socket ->
          assert_receive {:DOWN, ^monitor, :socket, ^object, :closed}, timeout
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

  defp absolute(ms), do: System.monotonic_time(:millisecond) + ms
  defp deadline(ms), do: {:abs_ms, absolute(ms)}
end

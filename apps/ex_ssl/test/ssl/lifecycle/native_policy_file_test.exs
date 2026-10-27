defmodule SSL.Lifecycle.NativePolicyFileTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :tmp_dir

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.{Lifecycle, PolicyIO}

  for operation <- [:open, :read], trigger <- [:cancel, :deadline, :actor_down, :ack_loss] do
    test "native file #{operation} keeps truthful evidence through #{trigger}", context do
      file_boundary(context.tmp_dir, unquote(operation), unquote(trigger))
    end
  end

  defp file_boundary(directory, operation, trigger) do
    path = Path.join(directory, "policy.fifo")
    assert {"", 0} = System.cmd("mkfifo", [path])

    # Also release a pending open if an assertion or test-process exit interrupts
    # the normal drain. O_RDWR opens this test-owned FIFO without a partner.
    on_exit(fn ->
      assert {:ok, release} = :file.open(path, [:raw, :read, :write, :binary])
      assert :ok = :file.close(release)
    end)

    writer = if operation == :read, do: open_writer(path)
    {:ok, peer} = Peer.start(&:ssl.close/1)
    expiry = now() + 3_000
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: {:abs_ms, expiry})
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)
    parent = self()
    reference = make_ref()

    # Run the actual policy executor in the original authenticated Connection.
    # The callback selects the fault boundary; peer authentication stays enabled.
    verify = fn
      _, :valid_peer, state ->
        {:ok, policy} = PolicyIO.install(handle, self(), expiry)
        send(parent, {reference, :entered, self()})
        _ = PolicyIO.read_file(policy, path)
        {:fail, state}

      _, {:extension, _}, state ->
        {:unknown, state}

      _, {:bad_cert, reason}, _ ->
        {:fail, reason}

      _, _, state ->
        {:valid, state}
    end

    options =
      Peer.client_options()
      |> Enum.reject(&(&1 == :binary))
      |> Keyword.put(:mode, :binary)
      |> Keyword.put(:verify_fun, {verify, nil})
      |> Keyword.put(:ex_ssl, lifecycle: {handle, lease})

    caller = Task.async(fn -> SSL.connect({127, 0, 0, 1}, peer.port, options, :infinity) end)

    on_exit(fn ->
      if trigger == :ack_loss, do: resume_observer(observer)
      Lifecycle.cancel(lease, {:abs_ms, now() + 500})
      stop_process(caller.pid)
      stop_process(peer.task.pid)
      :ssl.close(peer.listener)
    end)

    try do
      assert_receive {^reference, :entered, connection}, 1_000
      {actor, graph} = native_actor(observer, operation, now() + 1_000)
      actor_monitor = Process.monitor(actor)
      assert {:connection, :process, ^connection, _} = List.keyfind(graph, :connection, 0)
      assert Task.yield(caller, 0) == nil

      assert {:pending,
              %{
                cleanup: :pending,
                auxiliary: %{roles: 2, native_operation: :pending, observed_down: 0, losses: 0}
              }} = Lifecycle.status(handle)

      cutoff = expiry + 1_000

      case trigger do
        :cancel ->
          assert :ok = Lifecycle.cancel(lease, {:abs_ms, min(expiry, now() + 1_000)})

        :deadline ->
          assert {:pending, _} = Lifecycle.await(handle, {:abs_ms, expiry})
          assert now() >= expiry

          assert {:pending,
                  %{
                    setup: :cancelled,
                    setup_failure: :timeout,
                    auxiliary: %{native_operation: :pending, losses: 0}
                  }} = Lifecycle.status(handle)

        :actor_down ->
          Process.exit(actor, :kill)

        :ack_loss ->
          :ok = :sys.suspend(observer)
      end

      # An entered native operation is outstanding even when cancellation or a
      # kill signal has already closed the logical connection.
      assert {:pending, %{observer: :alive, receipt: :unsealed}} =
               Lifecycle.await(handle, {:abs_ms, now()})

      released_at = now()
      release_file(operation, path, writer, actor, actor_monitor, cutoff)

      if trigger == :ack_loss do
        # Both real GenServer.call aliases expire while the observer is paused:
        # native completion, then the single contingent native close/drain.
        assert now() - released_at >= 2_000
        assert :ok = :sys.resume(observer)
      end

      assert {:error, _} = Task.await(caller, remaining(cutoff))
      assert_graph_down(graph, cutoff)

      if trigger in [:actor_down, :ack_loss] do
        assert {:unconfirmed, _} = result = Lifecycle.await(handle, {:abs_ms, cutoff})
        assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, remaining(cutoff)
        assert Lifecycle.status(handle) == result
      else
        assert {:ok,
                %{
                  version: 2,
                  cleanup: :confirmed,
                  roles: 31,
                  observed_down: 31,
                  losses: 0,
                  auxiliary: %{roles: 2, observed_down: 2, losses: 0}
                } = receipt} = Lifecycle.await(handle, {:abs_ms, cutoff})

        assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, remaining(cutoff)
        assert Lifecycle.status(handle) == {:terminal, receipt}
      end
    after
      if trigger == :ack_loss, do: resume_observer(observer)
      if writer, do: :file.close(writer)
      Lifecycle.cancel(lease, {:abs_ms, now() + 500})
      Task.shutdown(caller, :brutal_kill)
      Task.shutdown(peer.task, :brutal_kill)
    end
  end

  defp native_actor(observer, operation, deadline) do
    state = :sys.get_state(observer, remaining(deadline))
    expected = if operation == :open, do: :open_nif, else: :read_nif

    case state do
      %{
        policy: %{
          actor: %{pid: actor},
          ledger: %{current: %{operation: {token, ^operation}, identity: {_, :process, actor}}}
        }
      } ->
        case Process.info(actor, :current_function) do
          {:current_function, {:prim_file, ^expected, _}} ->
            receive do
            after
              50 -> :ok
            end

            assert {:current_function, {:prim_file, ^expected, _}} =
                     Process.info(actor, :current_function)

            assert %{
                     policy: %{
                       actor: %{pid: ^actor},
                       ledger: %{current: %{operation: {^token, ^operation}}}
                     }
                   } = :sys.get_state(observer, remaining(deadline))

            graph = monitor_graph(state.resources)

            assert Enum.sort(Enum.map(graph, &elem(&1, 0))) ==
                     [:allocator, :connection, :setup, :tcp, :writer]

            {actor, graph}

          _ ->
            retry_native(observer, operation, deadline)
        end

      _ ->
        retry_native(observer, operation, deadline)
    end
  end

  defp monitor_graph(resources) do
    for {role, %{identity: {_, type, object}}} <- resources do
      monitor =
        case type do
          :process -> Process.monitor(object)
          :socket -> :socket.monitor(object)
        end

      {role, type, object, monitor}
    end
  end

  defp retry_native(observer, operation, deadline) do
    assert remaining(deadline) > 0,
           "native #{operation} was not observed before the fixed deadline"

    receive do
    after
      1 -> native_actor(observer, operation, deadline)
    end
  end

  defp release_file(:open, path, _writer, actor, monitor, deadline) do
    writer = open_writer(path)

    try do
      assert_receive {:DOWN, ^monitor, :process, ^actor, _}, remaining(deadline)
    after
      assert :ok = :file.close(writer)
    end
  end

  defp release_file(:read, _path, writer, actor, monitor, deadline) do
    assert :ok = :file.close(writer)
    assert_receive {:DOWN, ^monitor, :process, ^actor, _}, remaining(deadline)
  end

  defp assert_graph_down(graph, deadline) do
    for {_role, type, object, monitor} <- graph do
      assert_receive {:DOWN, ^monitor, ^type, ^object, _}, remaining(deadline)
    end
  end

  defp open_writer(path) do
    assert {:ok, writer} = :file.open(path, [:raw, :read, :write, :binary])
    writer
  end

  defp stop_process(pid) do
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1_000
  end

  defp resume_observer(observer) do
    if Process.alive?(observer), do: :sys.resume(observer)
  catch
    :exit, _ -> :ok
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp remaining(deadline), do: max(0, deadline - now())
end

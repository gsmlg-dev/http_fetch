defmodule ExSSL.TestSupport.NativeFileClose do
  @moduledoc false
  import ExUnit.Assertions

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.{Lifecycle, PolicyIO}

  def run do
    {:ok, _} = Application.ensure_all_started(:ex_ssl)
    directory = System.fetch_env!("HTTP_FETCH_NATIVE_CLOSE_DIRECTORY")
    scenario = System.fetch_env!("HTTP_FETCH_NATIVE_CLOSE_SCENARIO")
    {:ok, peer} = Peer.start(&:ssl.close/1)
    expiry = now() + 3_000
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: {:abs_ms, expiry})
    observer = handle.receipt.observer
    observer_monitor = Process.monitor(observer)
    parent = self()
    reference = make_ref()

    verify = fn
      _, :valid_peer, state ->
        {:ok, policy} = PolicyIO.install(handle, self(), expiry)
        send(parent, {reference, :entered, self()})
        _ = PolicyIO.read_file(policy, Path.join(directory, "policy"))
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

    try do
      assert_receive {^reference, :entered, connection}, 1_000
      {actor, graph} = native_actor(observer, now() + 1_000)
      actor_monitor = Process.monitor(actor)
      assert {:connection, :process, ^connection, _} = List.keyfind(graph, :connection, 0)
      assert Task.yield(caller, 0) == nil

      assert {:pending,
              %{
                cleanup: :pending,
                auxiliary: %{roles: 2, native_operation: :pending, observed_down: 0, losses: 0}
              }} = Lifecycle.status(handle)

      cutoff = expiry + 1_000

      case scenario do
        "cancel" ->
          assert :ok = Lifecycle.cancel(lease, {:abs_ms, min(expiry, now() + 1_000)})

        "deadline" ->
          assert {:pending, _} = Lifecycle.await(handle, {:abs_ms, expiry})
          assert now() >= expiry

          assert {:pending,
                  %{
                    setup: :cancelled,
                    setup_failure: :timeout,
                    auxiliary: %{native_operation: :pending, losses: 0}
                  }} = Lifecycle.status(handle)

        "actor_down" ->
          Process.exit(actor, :kill)

        paused when paused in ["ack_loss", "late_ack"] ->
          assert :ok = :sys.suspend(observer)
      end

      assert {:pending, %{observer: :alive, receipt: :unsealed}} =
               Lifecycle.await(handle, {:abs_ms, now()})

      File.write!(Path.join(directory, "ready"), "native close observed; receipt pending")
      await_release(directory, cutoff)
      released_at = now()

      if scenario == "late_ack",
        do: resume_after_ack_timeout(observer, actor, released_at, expiry)

      assert_receive {:DOWN, ^actor_monitor, :process, ^actor, _}, remaining(cutoff)

      if scenario == "ack_loss" do
        assert now() - released_at >= 2_000
        assert :ok = :sys.resume(observer)
      end

      assert {:error, _} = Task.await(caller, remaining(cutoff))

      for {_role, type, object, monitor} <- graph do
        assert_receive {:DOWN, ^monitor, ^type, ^object, _}, remaining(cutoff)
      end

      if scenario in ["actor_down", "ack_loss"] do
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

      IO.puts("NATIVE_POLICY_CLOSE_PASS")
    after
      File.touch!(Path.join(directory, "release"))
      if Process.alive?(observer), do: :sys.resume(observer)
      Lifecycle.cancel(lease, {:abs_ms, now() + 500})
      Task.shutdown(caller, :brutal_kill)
      Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end
  end

  defp native_actor(observer, deadline) do
    state = :sys.get_state(observer, remaining(deadline))

    case state do
      %{
        policy: %{
          actor: %{pid: actor},
          ledger: %{current: %{operation: {token, :close}, identity: {_, :process, actor}}}
        }
      } ->
        case Process.info(actor, :current_function) do
          {:current_function, {:prim_file, :close_nif, _}} ->
            receive do
            after
              50 -> :ok
            end

            assert {:current_function, {:prim_file, :close_nif, _}} =
                     Process.info(actor, :current_function)

            assert %{
                     policy: %{
                       actor: %{pid: ^actor},
                       ledger: %{current: %{operation: {^token, :close}}}
                     }
                   } = :sys.get_state(observer, remaining(deadline))

            graph =
              for {role, %{identity: {_, type, object}}} <- state.resources do
                monitor =
                  case type do
                    :process -> Process.monitor(object)
                    :socket -> :socket.monitor(object)
                  end

                {role, type, object, monitor}
              end

            assert Enum.sort(Enum.map(graph, &elem(&1, 0))) ==
                     [:allocator, :connection, :setup, :tcp, :writer]

            {actor, graph}

          _ ->
            retry_native(observer, deadline)
        end

      _ ->
        retry_native(observer, deadline)
    end
  end

  defp retry_native(observer, deadline) do
    assert remaining(deadline) > 0, "native close was not observed before the fixed deadline"

    receive do
    after
      1 -> native_actor(observer, deadline)
    end
  end

  defp await_release(directory, deadline) do
    assert remaining(deadline) > 0

    unless File.exists?(Path.join(directory, "release")) do
      receive do
      after
        1 -> await_release(directory, deadline)
      end
    end
  end

  defp resume_after_ack_timeout(observer, actor, released_at, deadline) do
    assert remaining(deadline) > 0

    case Process.info(observer, :message_queue_len) do
      {:message_queue_len, count} when count >= 2 ->
        assert now() - released_at >= 1_000
        assert Process.alive?(actor)
        assert :ok = :sys.resume(observer)

      _ ->
        receive do
        after
          1 -> resume_after_ack_timeout(observer, actor, released_at, deadline)
        end
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp remaining(deadline), do: max(0, deadline - now())
end

ExSSL.TestSupport.NativeFileClose.run()

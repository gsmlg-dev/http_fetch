defmodule HTTP.HTTP2AdmissionPoolTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{ConnectionOwner, Frame, Pool}

  test "automatic admission allows one initial reservation and obeys zero and changing SETTINGS" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1})
    transport = %{send: fn _, _ -> :ok end, close: fn _ -> :ok end, setopts: fn _, _ -> :ok end}

    {:ok, owner} =
      start_supervised(
        {ConnectionOwner, transport: transport, activate?: false, limit_initial_capacity?: true}
      )

    :ok = Pool.register(pool, :key, owner, max_streams: 0)
    ConnectionOwner.status(owner)
    assert {:ok, ^owner, token} = Pool.try_reserve(pool, :key)
    assert :none = Pool.try_reserve(pool, :key)
    :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, <<3::16, 0::32>>))
    :ok = Pool.release(pool, :key, token)
    assert :none = Pool.try_reserve(pool, :key)
    :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0, 0, <<3::16, 2::32>>))
    assert {:ok, ^owner, first} = Pool.try_reserve(pool, :key)
    assert {:ok, ^owner, second} = Pool.try_reserve(pool, :key)
    assert :none = Pool.try_reserve(pool, :key)
    :ok = Pool.release(pool, :key, first)
    :ok = Pool.release(pool, :key, second)
  end

  test "the admitted connector can wait for SETTINGS when the external queue is full" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1, max_pending: 1})

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    assert :start = Pool.claim_connect(pool, :key)
    queued = Task.async(fn -> Pool.reserve(pool, :key) end)
    await_pending(pool, 1)
    assert :ok = Pool.register(pool, :key, owner, connecting?: true, max_streams: 0)
    request = :gen_server.send_request(pool, {:reserve, :key, [registered_owner: owner]})
    assert :timeout = :gen_server.wait_response(request, 50)
    assert %{pending: 2} = Pool.stats(pool)[:key]
    assert :ok = Pool.update_capacity(pool, :key, owner, 1)
    assert {:ok, ^owner, first} = Task.await(queued)
    :ok = Pool.release(pool, :key, first)
    assert {:reply, {:ok, ^owner, second}} = :gen_server.wait_response(request, 1_000)
    :ok = Pool.release(pool, :key, second)
    assert :ok = Pool.update_capacity(pool, :key, owner, 0)
    # The admitted wait is a one-time entitlement; it does not bypass bounds again.
    blocker = Task.async(fn -> Pool.reserve(pool, :key) end)
    await_pending(pool, 1)
    assert {:error, :pending_capacity} = Pool.reserve(pool, :key, registered_owner: owner)
    Task.shutdown(blocker, :brutal_kill)
  end

  for deadline <- [nil, :infinity], terminal <- [:cancel, :caller_down] do
    test "#{inspect(deadline)} queued deadline retains capacity bounds and settles on #{terminal}" do
      {:ok, pool} = start_supervised({Pool, max_connections: 0, max_pending: 1})
      token = make_ref()

      caller =
        Task.async(fn ->
          Pool.reserve(pool, :key, token: token, deadline_at: unquote(deadline))
        end)

      await_pending(pool, 1)
      assert {:error, :pending_capacity} = Pool.reserve(pool, :key)
      assert :sys.get_state(pool).deadlines == %{}

      case unquote(terminal) do
        :cancel ->
          assert :ok = Pool.cancel(pool, token)
          assert Pool.stats(pool) == %{}
          assert :sys.get_state(pool).callers == %{}
          assert :sys.get_state(pool).monitors == %{}
          assert nil == Task.shutdown(caller, :brutal_kill)

        :caller_down ->
          assert nil == Task.shutdown(caller, :brutal_kill)
          await_pending(pool, 0)
      end

      assert Pool.stats(pool) == %{}
      state = :sys.get_state(pool)
      assert state.callers == %{}
      assert state.monitors == %{}
      assert state.deadlines == %{}
      assert {:error, :unknown_reservation} = Pool.cancel(pool, token)
    end
  end

  for cleanup <- [:confirmed, :pending, :unconfirmed, :missing],
      key <- [:key, :other],
      queued? <- if(cleanup == :confirmed, do: [false, true], else: [false]) do
    @tag cleanup: cleanup, replacement_key: key, queued?: queued?
    test "#{cleanup} provider cleanup preserves bounded replacement admission for #{key}, queued: #{queued?}",
         %{
           cleanup: cleanup,
           replacement_key: key,
           queued?: queued?
         } do
      {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: :infinity)
      {owner, owner_monitor} = spawn_monitor(fn -> receive do: (:stop -> :ok) end)
      on_exit(fn -> if Process.alive?(owner), do: Process.exit(owner, :kill) end)

      try do
        case cleanup do
          :confirmed ->
            assert :ok = SSL.Lifecycle.cancel(lease, lifecycle_deadline())

            assert {:ok, %{cleanup: :confirmed}} =
                     SSL.Lifecycle.await(handle, lifecycle_deadline())

          :unconfirmed ->
            observer = handle.receipt.observer
            monitor = Process.monitor(observer)
            Process.exit(observer, :kill)
            assert_receive {:DOWN, ^monitor, :process, ^observer, :killed}, 1_000

            assert {:unconfirmed, :observer_unsealed} =
                     SSL.Lifecycle.await(handle, lifecycle_deadline())

          _ ->
            assert {:pending, _} =
                     SSL.Lifecycle.await(handle, {:abs_ms, System.monotonic_time(:millisecond)})
        end

        max_pending = if queued?, do: 1, else: 0

        {:ok, initial} =
          Pool.init(max_connections: 1, max_total_connections: 1, max_pending: max_pending)

        from = {self(), make_ref()}
        deadline = System.monotonic_time(:millisecond) + 1_000

        {:reply, :ok, prepared} =
          Pool.handle_call(
            {:prepare_provider, :key, owner, [request_lifecycle: self()], deadline},
            from,
            initial
          )

        carrier = if cleanup == :missing, do: nil, else: %{handle: handle}
        prepared = put_in(prepared.providers[owner].carrier, carrier)
        {:noreply, retained} = Pool.handle_cast({:retire_provider, owner}, prepared)
        send(owner, :stop)
        assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000

        # Invoke callbacks directly so the housekeeping timer cannot erase the
        # stale capacity between the genuine cleanup receipt and admission.
        if cleanup == :confirmed do
          token = make_ref()
          reply_tag = make_ref()

          retained =
            if queued? do
              assert {:noreply, queued} =
                       Pool.handle_call(
                         {:reserve, :key, [connect?: true, token: token]},
                         {self(), reply_tag},
                         retained
                       )

              refute_receive {^reply_tag, _}, 0
              queued
            else
              retained
            end

          expected = if queued?, do: :wait, else: :start
          admitted_key = if queued?, do: :key, else: key

          assert {:reply, ^expected, admitted} =
                   Pool.handle_call({:claim_connect, key}, from, retained)

          if queued?, do: assert_receive({^reply_tag, {:connect, ^token}}, 1_000)
          assert admitted.providers == %{}
          assert map_size(admitted.entries) == 1
          assert admitted.entries[admitted_key].connecting == 1
          assert admitted.max_connections == 1
          assert admitted.max_total_connections == 1
          assert admitted.max_pending == max_pending

          {:reply, :ok, settled} =
            Pool.handle_call({:complete_connect, admitted_key}, from, admitted)

          assert settled.entries == %{}
          assert settled.monitors == %{}
          assert settled.callers == %{}
          assert settled.promotions == %{}
        else
          assert {:reply, :wait, ^retained} =
                   Pool.handle_call({:claim_connect, key}, from, retained)

          assert map_size(retained.providers) == 1
          Process.demonitor(retained.providers[owner].monitor, [:flush])

          if cleanup in [:pending, :missing] do
            assert {:pending, _} =
                     SSL.Lifecycle.await(handle, {:abs_ms, System.monotonic_time(:millisecond)})
          end
        end
      after
        if cleanup in [:pending, :missing] do
          assert :ok = SSL.Lifecycle.cancel(lease, lifecycle_deadline())
        end

        if cleanup != :unconfirmed do
          assert {:ok, %{cleanup: :confirmed}} = SSL.Lifecycle.await(handle, lifecycle_deadline())
        end
      end
    end
  end

  defp lifecycle_deadline, do: {:abs_ms, System.monotonic_time(:millisecond) + 1_000}

  defp await_pending(pool, count, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 5_000

    if (get_in(Pool.stats(pool), [:key, :pending]) || 0) != count do
      assert System.monotonic_time(:millisecond) < deadline,
             "pending count did not reach #{count}: #{inspect(Pool.stats(pool))}"

      receive do
      after
        1 -> :ok
      end

      await_pending(pool, count, deadline)
    end
  end
end

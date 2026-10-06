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

  defp await_pending(pool, count, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 5_000

    if Pool.stats(pool)[:key].pending != count do
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

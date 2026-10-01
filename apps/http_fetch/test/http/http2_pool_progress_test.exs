defmodule HTTP.HTTP2PoolProgressTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP2.Pool

  defmodule Owner do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, nil}
    def handle_info(_, state), do: {:noreply, state}
  end

  for event <- [:down, :draining] do
    test "queued unsent caller is promoted after owner #{event}" do
      {:ok, pool} = start_supervised({Pool, max_connections: 1, max_total_connections: 2})
      {:ok, owner} = start_supervised({Owner, nil})
      :ok = Pool.register(pool, :key, owner, max_streams: 0)
      {caller, token} = waiter(pool, :key)
      queued_barrier(pool, token)

      if unquote(event) == :down,
        do: Process.exit(owner, :kill),
        else: Pool.mark_draining(pool, :key, owner)

      assert_receive {:result, ^caller, {:connect, ^token}}, 2_000
      assert :wait = Pool.claim_connect(pool, :key)
      :ok = Pool.cancel(pool, token)
      send(caller, :stop)
    end
  end

  for event <- [:down, :draining] do
    test "queued caller replaces an owner after #{event} while its sibling is saturated" do
      {:ok, pool} =
        start_supervised({Pool, max_connections: 2, max_total_connections: 3, idle_timeout: 0})

      {:ok, first_owner} = start_supervised({Owner, nil}, id: :first_owner)
      {:ok, sibling_owner} = start_supervised({Owner, nil}, id: :sibling_owner)
      :ok = Pool.register(pool, :key, first_owner, max_streams: 1)
      assert {:ok, ^first_owner, first_reservation} = Pool.reserve(pool, :key)
      :ok = Pool.register(pool, :key, sibling_owner, max_streams: 1)
      assert {:ok, ^sibling_owner, sibling_reservation} = Pool.reserve(pool, :key)
      {caller, token} = waiter(pool, :key)
      queued_barrier(pool, token)

      if unquote(event) == :down,
        do: Process.exit(first_owner, :kill),
        else: Pool.mark_draining(pool, :key, first_owner)

      assert_receive {:result, ^caller, {:connect, ^token}}, 2_000
      assert :wait = Pool.claim_connect(pool, :key)
      assert Process.alive?(sibling_owner)
      assert :sys.get_state(pool).reservations[sibling_reservation].owner == sibling_owner
      stats = Pool.stats(pool).key
      assert stats.connecting == 1
      assert stats.connections + stats.connecting <= 3
      :ok = Pool.cancel(pool, token)
      :ok = Pool.release(pool, :key, first_reservation)
      :ok = Pool.release(pool, :key, sibling_reservation)
      send(caller, :stop)
      assert :sys.get_state(pool).reservations == %{}
      assert Pool.stats(pool).key.connecting == 0
    end
  end

  test "global capacity freed by idle expiry promotes a different key without a new call" do
    {:ok, pool} = start_supervised({Pool, max_total_connections: 1, idle_timeout: 60_000})
    {:ok, owner} = start_supervised({Owner, nil})
    :ok = Pool.register(pool, :first, owner)
    {caller, token} = waiter(pool, :second)
    queued_barrier(pool, token)
    %{entries: %{first: %{connections: connections}}} = :sys.get_state(pool)
    send(pool, {:idle_expire, :first, owner, connections[owner].idle_token})
    assert_receive {:result, ^caller, {:connect, ^token}}, 2_000
    :ok = Pool.cancel(pool, token)
    send(caller, :stop)
    assert_empty(pool)
  end

  test "zero peer stream capacity wakes on a positive SETTINGS update" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1, max_total_connections: 1})
    {:ok, owner} = start_supervised({Owner, nil})
    :ok = Pool.register(pool, :key, owner, max_streams: 0)
    {caller, token} = waiter(pool, :key)
    queued_barrier(pool, token)
    :ok = Pool.update_capacity(pool, :key, owner, 1)
    assert_receive {:result, ^caller, {:ok, ^owner, ^token}}, 2_000
    :ok = Pool.release(pool, :key, token)
    send(caller, :stop)
  end

  test "a dead newly registered owner cannot strand eligible callers behind its reservation" do
    {:ok, pool} = start_supervised({Pool, max_total_connections: 1, idle_timeout: 0})
    {:ok, owner} = start_supervised({Owner, nil})
    :ok = Pool.register(pool, :key, owner, max_streams: 0)
    {first, first_token} = waiter(pool, :key, connect?: false, registered_owner: owner)
    queued_barrier(pool, first_token)
    {second, second_token} = waiter(pool, :key)
    queued_barrier(pool, second_token)
    Process.exit(owner, :kill)
    assert_receive {:result, ^first, {:error, :owner_closed}}, 2_000
    assert_receive {:result, ^second, {:connect, ^second_token}}, 2_000
    :ok = Pool.cancel(pool, second_token)
    send(first, :stop)
    send(second, :stop)
    assert_empty(pool)
  end

  for event <- [:death, :cancel, :deadline] do
    test "promotion #{event} cleans state and promotes the next eligible caller" do
      {:ok, pool} = start_supervised({Pool, max_total_connections: 1, idle_timeout: 0})
      assert :start = Pool.claim_connect(pool, :blocker)
      {first, first_token} = waiter(pool, :key)
      queued_barrier(pool, first_token)
      {second, second_token} = waiter(pool, :key)
      queued_barrier(pool, second_token)
      :ok = Pool.fail_connect(pool, :blocker, :test)
      assert_receive {:result, ^first, {:connect, ^first_token}}, 2_000

      case unquote(event) do
        :death -> Process.exit(first, :kill)
        :cancel -> assert :ok = Pool.cancel(pool, first_token)
        :deadline -> send(pool, {:reservation_deadline, first_token})
      end

      assert_receive {:result, ^second, {:connect, ^second_token}}, 2_000
      :ok = Pool.cancel(pool, second_token)
      send(first, :stop)
      send(second, :stop)
      assert_empty(pool)
    end
  end

  test "the last global slot is assigned to exactly one cold connector" do
    {:ok, pool} = start_supervised({Pool, max_total_connections: 1, idle_timeout: 0})
    assert :start = Pool.claim_connect(pool, :blocker)
    {first, first_token} = waiter(pool, :first)
    queued_barrier(pool, first_token)
    {second, second_token} = waiter(pool, :second)
    queued_barrier(pool, second_token)
    :ok = Pool.fail_connect(pool, :blocker, :test)
    assert_receive {:result, promoted, {:connect, promoted_token}}, 2_000
    assert Enum.sum(for {_key, entry} <- Pool.stats(pool), do: entry.connecting) == 1
    assert :wait = Pool.claim_connect(pool, :third)
    :ok = Pool.cancel(pool, promoted_token)
    assert_receive {:result, next, {:connect, next_token}}, 2_000
    refute next == promoted
    :ok = Pool.cancel(pool, next_token)
    send(first, :stop)
    send(second, :stop)
    assert_empty(pool)
  end

  test "cancelled promotion cannot register against a successor's claim" do
    {:ok, pool} = start_supervised({Pool, max_total_connections: 1, idle_timeout: 0})
    {first, token} = waiter(pool, :key)
    assert_receive {:result, ^first, {:connect, ^token}}, 2_000
    :ok = Pool.cancel(pool, token)
    {second, successor} = waiter(pool, :key)
    assert_receive {:result, ^second, {:connect, ^successor}}, 2_000
    {:ok, owner} = start_supervised({Owner, nil})
    assert {:error, :connector_cancelled} = Pool.register(pool, :key, owner, connecting?: true)
    :ok = Pool.cancel(pool, successor)
    send(first, :stop)
    send(second, :stop)
    assert_empty(pool)
  end

  test "connection failure removes a promoted caller's timer and monitors" do
    {:ok, pool} = start_supervised({Pool, max_total_connections: 1, idle_timeout: 0})
    test_pid = self()
    token = make_ref()

    caller =
      spawn(fn ->
        {:connect, ^token} =
          Pool.reserve(pool, :key,
            token: token,
            connect?: true,
            deadline_at: System.monotonic_time(:millisecond) + 10_000
          )

        :ok = Pool.fail_connect(pool, :key, :econnrefused)
        send(test_pid, :failed_connection_cleaned)
      end)

    on_exit(fn -> Process.exit(caller, :kill) end)
    assert_receive :failed_connection_cleaned, 2_000
    assert_empty(pool)
  end

  defp waiter(pool, key, opts \\ []) do
    test_pid = self()
    token = make_ref()

    caller =
      spawn(fn ->
        :sys.get_state(pool)

        result =
          Pool.reserve(
            pool,
            key,
            Keyword.merge(
              [
                token: token,
                connect?: true,
                deadline_at: System.monotonic_time(:millisecond) + 10_000
              ],
              opts
            )
          )

        send(test_pid, {:result, self(), result})
        receive do: (:stop -> :ok)
      end)

    on_exit(fn -> Process.exit(caller, :kill) end)
    {caller, token}
  end

  defp queued_barrier(pool, token) do
    test_pid = self()
    handler = make_ref()

    :telemetry.attach(
      handler,
      [:http_fetch, :http2, :pool],
      fn _, _, metadata, _ ->
        if self() == pool and metadata.event == :queued, do: send(test_pid, {:queued, handler})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
    state = :sys.get_state(pool)
    unless Map.has_key?(state.callers, token), do: assert_receive({:queued, ^handler}, 2_000)
    :telemetry.detach(handler)
    assert Map.has_key?(:sys.get_state(pool).callers, token)
  end

  defp assert_empty(pool) do
    state = :sys.get_state(pool)

    for key <- [
          :entries,
          :reservations,
          :callers,
          :connectors,
          :promotions,
          :deadlines,
          :monitors
        ] do
      assert Map.fetch!(state, key) == %{}, "leaked #{key}"
    end
  end
end

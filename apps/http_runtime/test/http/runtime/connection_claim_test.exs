defmodule HTTP.Runtime.ConnectionClaimTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.Pool

  defmodule Owner do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, nil}
    def handle_info(_, state), do: {:noreply, state}
  end

  setup do
    pool = start_supervised!({Pool, max_connections: 2, idle_timeout: 0})
    owner = start_supervised!({Owner, nil})
    %{pool: pool, owner: owner}
  end

  test "an owner becoming ready after an empty reservation prevents a redundant claim", %{
    pool: pool,
    owner: owner
  } do
    assert :none = Pool.try_reserve(pool, :key)
    assert :ok = Pool.register(pool, :key, owner, max_streams: 1)
    assert :wait = Pool.claim_connect(pool, :key)
    assert {:ok, ^owner, token} = Pool.reserve(pool, :key)
    assert %{connections: 1, connecting: 0, streams: 1} = Pool.stats(pool).key
    assert :ok = Pool.release(pool, :key, token)
  end

  test "a registered owner awaiting initial SETTINGS keeps cold claims coalesced", %{
    pool: pool,
    owner: owner
  } do
    assert :ok = Pool.register(pool, :key, owner, max_streams: 0)
    assert :none = Pool.try_reserve(pool, :key)
    assert :wait = Pool.claim_connect(pool, :key)
    assert %{connections: 1, connecting: 0, streams: 0} = Pool.stats(pool).key
    assert :ok = Pool.update_capacity(pool, :key, owner, 1)
    assert {:ok, ^owner, token} = Pool.reserve(pool, :key)
    assert :ok = Pool.release(pool, :key, token)
  end

  test "a saturated ready owner permits one additional connection claim", %{
    pool: pool,
    owner: owner
  } do
    assert :ok = Pool.register(pool, :key, owner, max_streams: 1)
    assert {:ok, ^owner, token} = Pool.reserve(pool, :key)
    assert :none = Pool.try_reserve(pool, :key)
    assert :start = Pool.claim_connect(pool, :key)
    assert :wait = Pool.claim_connect(pool, :key)
    assert %{connections: 1, connecting: 1, streams: 1} = Pool.stats(pool).key
    assert :ok = Pool.fail_connect(pool, :key, :test_cleanup)
    assert :ok = Pool.release(pool, :key, token)
  end
end

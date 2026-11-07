defmodule HTTP.PoolTest do
  use ExUnit.Case, async: true

  test "policy preserves defaults and rejects unknown, duplicate and unsafe limits" do
    assert {:ok, policy} = HTTP.Pool.policy()
    assert policy.http1[:max_idle] == 256
    assert policy.http2[:max_connections] == 2
    assert policy.http2[:max_total_connections] == 20

    assert {:error, {:invalid_pool_option, :secret, :unknown}} =
             HTTP.Pool.policy(secret: "hidden")

    assert {:error, _} = HTTP.Pool.policy(http1: [max_idle_per_key: 17])
    assert {:error, _} = HTTP.Pool.policy(http2: [max_streams: 0])
    assert {:error, _} = HTTP.Pool.policy(http2: [max_keys: 1, max_keys: 2])
  end

  test "H2 idle timeout rejects values outside the finite timer policy before startup" do
    assert {:ok, policy} = HTTP.Pool.policy(http2: [idle_timeout: 4_294_967_295])
    assert policy.http2[:idle_timeout] == 4_294_967_295

    for timeout <- [0, -1, :infinity, 4_294_967_296, Integer.pow(2, 128)] do
      assert {:error, {:invalid_pool_option, :idle_timeout, :out_of_range}} =
               HTTP.Pool.policy(http2: [idle_timeout: timeout])
    end
  end

  test "H2 pool enforces nondefault stream and pending limits without runtime owners" do
    pool =
      start_supervised!(
        {HTTP.HTTP2.Pool,
         max_connections: 1, max_total_connections: 1, max_streams: 1, max_pending: 0}
      )

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    assert :ok = HTTP.HTTP2.Pool.register(pool, :key, owner, max_streams: 50)
    assert {:ok, ^owner, token} = HTTP.HTTP2.Pool.reserve(pool, :key)
    assert {:error, :pending_capacity} = HTTP.HTTP2.Pool.reserve(pool, :key)
    assert :ok = HTTP.HTTP2.Pool.update_capacity(pool, :key, owner, 0)
    assert :ok = HTTP.HTTP2.Pool.release(pool, :key, token)
    assert :none = HTTP.HTTP2.Pool.try_reserve(pool, :key)
    assert :ok = HTTP.HTTP2.Pool.update_capacity(pool, :key, owner, 99)
    assert {:ok, ^owner, second} = HTTP.HTTP2.Pool.try_reserve(pool, :key)
    assert :ok = HTTP.HTTP2.Pool.release(pool, :key, second)
  end

  test "connecting capacity transfers to an unpublished provider without freeing the total slot" do
    pool = start_supervised!({HTTP.HTTP2.Pool, max_connections: 2, max_total_connections: 1})

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    other =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn ->
      send(owner, :stop)
      send(other, :stop)
    end)

    assert :start = HTTP.HTTP2.Pool.claim_connect(pool, :first)

    assert :ok =
             GenServer.call(
               pool,
               {:prepare_provider, :first, owner, [connecting?: true],
                System.monotonic_time(:millisecond) + 2_000}
             )

    assert %{connecting: 0, connections: 0, provider_pending: 1} =
             HTTP.HTTP2.Pool.stats(pool).first

    assert :wait = HTTP.HTTP2.Pool.claim_connect(pool, :second)
    assert {:error, :connection_capacity} = HTTP.HTTP2.Pool.register(pool, :second, other)
  end
end

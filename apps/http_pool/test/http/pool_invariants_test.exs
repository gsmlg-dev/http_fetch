defmodule HTTP.PoolInvariantsTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.Pool

  defp live_owner do
    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    owner
  end

  describe "H2 key and connection limits" do
    test "a full key table rejects new keys but keeps serving existing ones" do
      pool = start_supervised!({Pool, max_keys: 1})
      owner = live_owner()

      assert :ok = Pool.register(pool, :a, owner)
      assert {:error, :key_capacity} = Pool.reserve(pool, :b)
      assert :none = Pool.try_reserve(pool, :b)
      assert {:ok, ^owner, token} = Pool.reserve(pool, :a)
      assert :ok = Pool.release(pool, :a, token)
      assert [:a] = Map.keys(Pool.stats(pool))
    end

    test "max_connections bounds registered owners per key" do
      pool = start_supervised!({Pool, max_connections: 1})

      assert :ok = Pool.register(pool, :a, live_owner())
      assert {:error, :connection_capacity} = Pool.register(pool, :a, live_owner())
      assert :wait = Pool.claim_connect(pool, :a)
    end

    test "a draining connection keeps occupying total capacity and is not reservable" do
      pool = start_supervised!({Pool, max_connections: 2, max_total_connections: 1})
      owner = live_owner()

      assert :ok = Pool.register(pool, :a, owner)
      assert :ok = Pool.mark_draining(pool, :a, owner)

      assert %{connections: 1, draining: 1} = Pool.stats(pool).a
      assert :none = Pool.try_reserve(pool, :a)
      assert :wait = Pool.claim_connect(pool, :b)
      assert {:error, :connection_capacity} = Pool.register(pool, :b, live_owner())
    end
  end

  describe "H2 reservations" do
    test "a reservation holds one stream until released, and release is idempotent" do
      pool = start_supervised!({Pool, max_streams: 1})
      owner = live_owner()
      assert :ok = Pool.register(pool, :a, owner)

      assert {:ok, ^owner, token} = Pool.reserve(pool, :a)
      assert %{streams: 1} = Pool.stats(pool).a
      assert :none = Pool.try_reserve(pool, :a)

      assert :ok = Pool.release(pool, :a, token)
      assert :ok = Pool.release(pool, :a, token)
      assert %{streams: 0} = Pool.stats(pool).a
      assert {:ok, ^owner, second} = Pool.try_reserve(pool, :a)
      assert :ok = Pool.cancel(pool, second)
      assert {:error, :unknown_reservation} = Pool.cancel(pool, second)
      assert %{streams: 0} = Pool.stats(pool).a
    end

    test "a release under another key leaves the reservation in place" do
      pool = start_supervised!({Pool, max_streams: 1})
      assert :ok = Pool.register(pool, :a, live_owner())
      assert {:ok, _owner, token} = Pool.reserve(pool, :a)

      assert :ok = Pool.release(pool, :other, token)
      assert %{streams: 1} = Pool.stats(pool).a
    end

    test "a dead owner releases its reservations and connection" do
      pool = start_supervised!({Pool, max_streams: 2})
      owner = live_owner()
      assert :ok = Pool.register(pool, :a, owner)
      assert {:ok, ^owner, _token} = Pool.reserve(pool, :a)

      ref = Process.monitor(owner)
      send(owner, :stop)
      assert_receive {:DOWN, ^ref, :process, ^owner, _}
      _ = Pool.stats(pool)

      assert stats = Pool.stats(pool)
      assert stats == %{} or match?(%{connections: 0, streams: 0}, stats.a)
    end
  end

  describe "generation-bound references and snapshots" do
    defp family do
      {:ok, policy} = HTTP.Pool.policy()
      h1 = start_supervised!(List.first(HTTP.Pool.child_specs(policy)), id: :h1)
      h2 = start_supervised!(List.last(HTTP.Pool.child_specs(policy)), id: :h2)

      %HTTP.Pool{
        instance: self(),
        generation: make_ref(),
        http1: h1,
        http2: h2,
        policy: policy
      }
    end

    test "snapshots aggregate H2 counts across keys without exposing the keys" do
      ref = family()
      a = live_owner()
      b = live_owner()
      assert :ok = Pool.register(ref.http2, :a, a)
      assert :ok = Pool.register(ref.http2, :b, b)
      assert {:ok, ^a, _token} = Pool.reserve(ref.http2, :a)
      assert :ok = Pool.mark_draining(ref.http2, :b, b)

      assert :ok = HTTP.Pool.validate(ref)
      assert {:ok, %{http1: h1, http2: h2}} = HTTP.Pool.snapshot(ref)
      assert is_map(h1)
      assert %{keys: 2, connections: 2, draining: 1, streams: 1, pending: 0} = h2
      refute inspect(h2) =~ ":a"
    end

    test "a reference whose family process stopped is stale and never falls back" do
      ref = family()
      assert {:ok, _} = HTTP.Pool.snapshot(ref)

      :ok = stop_supervised(:h2)

      assert {:error, :stale_pool} = HTTP.Pool.validate(ref)
      assert {:error, :stale_pool} = HTTP.Pool.snapshot(ref)
    end

    test "non-references are invalid" do
      assert {:error, :invalid_pool} = HTTP.Pool.validate(:pool)
      assert {:error, :invalid_pool} = HTTP.Pool.snapshot("pool")
    end

    test "a request without a binding passes binding validation" do
      assert :ok = HTTP.Pool.validate_binding(%{transport_options: []})

      {dead, monitor} = spawn_monitor(fn -> :ok end)
      assert_receive {:DOWN, ^monitor, :process, ^dead, _}

      assert {:error, :stale_pool} =
               HTTP.Pool.validate_binding(%{
                 transport_options: [pool_binding: %{family() | http1: dead}]
               })
    end
  end
end

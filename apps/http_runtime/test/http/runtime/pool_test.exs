defmodule HTTP.Runtime.PoolTest do
  use ExUnit.Case, async: true
  alias HTTP.Runtime.Pool

  test "named references bind both pools and retain identity through caller preparation" do
    name = "pool-#{System.unique_integer([:positive])}"
    family = start_supervised!({Pool, name: name, http1: [max_idle_per_key: 1]})
    assert {:ok, ref} = Pool.reference(name)
    assert {:ok, ^ref} = Pool.reference(family)
    request = request(pool: name)
    assert {:ok, bound} = Pool.prepare(request, pool: name)
    assert bound.transport_options[:http1_pool] == ref.http1
    assert bound.transport_options[:http2_pool] == ref.http2
    assert bound.transport_options[:http1_reuse]
    assert bound.transport_options[:http1_pool_size] == 1
    assert {:ok, %{http1: %{idle: 0}, http2: %{connections: 0}}} = HTTP.Pool.snapshot(ref)
  end

  test "old references fail after the same name is restarted" do
    name = "restart-#{System.unique_integer([:positive])}"
    start_supervised!({Pool, name: name})
    assert {:ok, first} = Pool.reference(name)
    :ok = stop_supervised({Pool, name})
    start_supervised!({Pool, name: name})
    assert {:ok, second} = Pool.reference(name)
    refute first.generation == second.generation
    assert {:error, :stale_pool} = Pool.reference(first)
    assert {:error, :stale_pool} = Pool.prepare(request(pool: first), pool: first)
    assert {:error, :stale_pool} = HTTP.Pool.snapshot(first)
    assert :ok = HTTP.Pool.validate(second)
  end

  test "an unrelated process is rejected without messaging or crashing it" do
    unrelated = start_supervised!({Agent, fn -> :untouched end})
    assert {:error, :invalid_pool} = Pool.reference(unrelated)
    assert Process.alive?(unrelated)
    assert Agent.get(unrelated, & &1) == :untouched
  end

  test "unknown, incompatible and over-limit explicit policies fail before transport" do
    assert {:error, :unknown_pool} = Pool.prepare(request(pool: "missing"), pool: "missing")
    family = start_supervised!({Pool, http1: [max_idle_per_key: 1, idle_timeout: 500]})

    for {options, init, key} <- [
          {[http_version: :http3], [], :http_version},
          {[http_version: :auto], [], :http_version},
          {[transport_scope: make_ref()], [], :transport_scope},
          {[], [http1_reuse: false], :http1_reuse},
          {[], [http1_pool_size: 2], :http1_pool_size},
          {[], [http1_idle_timeout: 501], :http1_idle_timeout},
          {[http_version: :h2c, http2_reuse: false], [], :http2_reuse}
        ] do
      assert {:error, {:invalid_pool_option, ^key, _}} =
               Pool.prepare(request(Keyword.put(options, :pool, family)), init)
    end
  end

  test "stale reservation tokens and repeated releases cannot change a replacement family" do
    name = "leases-#{System.unique_integer([:positive])}"
    start_supervised!({Pool, name: name})
    {:ok, first} = Pool.reference(name)

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    assert :ok = HTTP.HTTP2.Pool.register(first.http2, :key, owner)
    assert {:ok, ^owner, old_token} = HTTP.HTTP2.Pool.reserve(first.http2, :key)
    :ok = stop_supervised({Pool, name})
    start_supervised!({Pool, name: name})
    {:ok, second} = Pool.reference(name)
    assert :ok = HTTP.HTTP2.Pool.register(second.http2, :key, owner)
    assert {:ok, ^owner, token} = HTTP.HTTP2.Pool.reserve(second.http2, :key)
    assert :ok = HTTP.HTTP2.Pool.release(second.http2, :key, old_token)
    assert :ok = HTTP.HTTP2.Pool.release(second.http2, :wrong_key, token)
    assert %{streams: 1} = HTTP.HTTP2.Pool.stats(second.http2).key
    assert :ok = HTTP.HTTP2.Pool.release(second.http2, :key, token)
    assert :ok = HTTP.HTTP2.Pool.release(second.http2, :key, token)
    assert %{streams: 0} = HTTP.HTTP2.Pool.stats(second.http2).key
  end

  defp request(opts) do
    %HTTP.Request{
      url: URI.parse("http://example.test/"),
      transport_options: Keyword.merge([http_version: :http1], opts)
    }
  end

  test "unknown keys and invalid policies raise ArgumentError at start" do
    for {opts, reason} <- [
          {[tls_backend: :ssl], {:invalid_pool_option, :tls_backend, :unknown}},
          {[name: 1], {:invalid_pool_option, :name, :expected_atom_or_string}},
          {[:bad], {:invalid_pool_option, :options, :expected_keyword}}
        ] do
      assert_raise ArgumentError,
                   "invalid HTTP.Runtime.Pool options: #{inspect(reason)}",
                   fn -> Pool.start_link(opts) end
    end
  end
end

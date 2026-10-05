defmodule HTTP.HTTP3.RuntimeTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP3.{BodyBridge, ConnectionOwner, Pool, PoolKey, ReceiveBudget, Stream}

  setup do
    fixture = Path.expand("../../../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    tls = [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
    %{tls: tls, cert: cert.("leaf.pem"), key: {type, key}}
  end

  test "pool identity separates trust, origin, profile and endpoint ownership", %{tls: tls} do
    request = %HTTP.Request{url: URI.parse("https://localhost/"), transport_options: [ssl: tls]}
    assert {:ok, key, _} = PoolKey.build(request)
    assert {:ok, same, _} = PoolKey.build(%{request | url: URI.parse("https://localhost/other")})
    assert same == key
    assert {:ok, other, _} = PoolKey.build(%{request | url: URI.parse("https://localhost:444/")})
    refute key == other
    assert {:ok, compact, _} = PoolKey.build(request, profile: :compact)
    refute key == compact
    changed = Keyword.put(tls, :reference_identity, {:dns_id, "other.test"})

    assert {:ok, other_identity, _} =
             PoolKey.build(%{request | transport_options: [ssl: changed]})

    refute key == other_identity

    assert {:error, :tls_backend_not_supported_for_quic} =
             PoolKey.build(%{request | transport_options: [ssl: tls, tls_backend: :ssl]})

    assert {:error, :socket_opts_not_supported_for_quic} =
             PoolKey.build(request, socket_opts: [active: false])

    assert {:error, :http2_profile_not_supported_for_quic} =
             PoolKey.build(request, http2_profile: :native_v1)
  end

  test "receive budgets reserve finite native capacity for all admitted requests and peer streams" do
    assert {:ok, options} = ReceiveBudget.normalize([])
    assert options[:streams][:max_data] == 2_293_760
    assert options[:streams][:max_buffer] == 2_293_760
    assert options[:streams][:max_ready_bytes] == 2_293_760
    assert options[:streams][:max_streams_bidi] == 0
    assert options[:streams][:max_streams_uni] == 3

    assert {:error, :http3_receive_budget_too_small} =
             ReceiveBudget.normalize(streams: [max_ready_bytes: 262_144])

    assert {:error, :invalid_http3_receive_budget} = ReceiveBudget.normalize(max_streams: 129)
    actual = QuicHttp3.Transport.Quic.stream_budget(options[:streams])

    endpoint = %QuicHttp3.Transport.Quic.Endpoint{
      pid: self(),
      tls: [],
      profile: nil,
      ops: Quic,
      host: "test",
      streams: actual
    }

    assert {:ok, _} = ReceiveBudget.normalize(endpoint: endpoint)

    assert {:error, :http3_endpoint_receive_budget_mismatch} =
             ReceiveBudget.normalize(endpoint: endpoint, max_streams: 33)

    missing = %{endpoint | streams: Map.drop(actual, [:max_data, :max_buffer, :max_ready_bytes])}

    assert {:error, :http3_endpoint_receive_budget_mismatch} =
             ReceiveBudget.normalize(endpoint: missing)

    assert {:error, :invalid_http3_receive_budget} =
             ReceiveBudget.normalize(streams: [max_buffer: -1])

    undersized = %{endpoint | streams: QuicHttp3.Transport.Quic.stream_budget([])}

    assert {:error, :http3_endpoint_receive_budget_mismatch} =
             ReceiveBudget.normalize(endpoint: undersized)
  end

  test "upload bridge retains producer acknowledgement until definitive admission" do
    source = self()
    {:ok, bridge} = BodyBridge.start_link(source, self(), max_chunk_bytes: 3)
    assert :ok = BodyBridge.credit(bridge, 3)
    assert_receive {:read_chunk, ^bridge, :ack}
    ref = make_ref()
    send(bridge, {:stream_chunk, source, "abcdef", ref})
    assert_receive {:body_chunk, ^bridge, "abc", admitted}
    refute_receive {:stream_chunk_ack, ^ref}, 10
    assert :ok = BodyBridge.ack(bridge, admitted)
    assert_receive {:body_chunk, ^bridge, "def", second}
    refute_receive {:stream_chunk_ack, ^ref}, 10
    assert :ok = BodyBridge.ack(bridge, second)
    assert_receive {:stream_chunk_ack, ^ref}
    assert %{buffered_bytes: 0} = BodyBridge.status(bridge)
    GenServer.stop(bridge)
  end

  test "rotation respects effective native lifetime records before opening" do
    assert {:ok, options} =
             ReceiveBudget.normalize(max_streams: 1, streams: [max_stream_records: 7])

    assert options[:rotation_after] == 4

    assert {:error, :http3_stream_record_budget_too_small} =
             ReceiveBudget.normalize(max_streams: 2, streams: [max_stream_records: 5])

    assert {:error, :http3_rotation_budget_mismatch} =
             ReceiveBudget.normalize(
               max_streams: 1,
               rotation_after: 5,
               streams: [max_stream_records: 7]
             )

    actual = QuicHttp3.Transport.Quic.stream_budget(options[:streams])

    endpoint = %QuicHttp3.Transport.Quic.Endpoint{
      pid: self(),
      tls: [],
      profile: nil,
      ops: Quic,
      host: "test",
      streams: actual
    }

    assert {:ok, borrowed} = ReceiveBudget.normalize(endpoint: endpoint, max_streams: 1)
    assert borrowed[:rotation_after] == 4

    legacy = %{
      endpoint
      | streams: Map.drop(actual, [:max_stream_records, :max_local_stream_records])
    }

    assert {:error, :http3_endpoint_receive_budget_mismatch} =
             ReceiveBudget.normalize(endpoint: legacy, max_streams: 1)
  end

  test "an explicit pool stream limit remains a bound on a larger owner capacity" do
    {:ok, pool} = Pool.start_link(max_streams: 1, max_connections: 1)
    on_exit(fn -> if Process.alive?(pool), do: GenServer.stop(pool) end)

    owner =
      spawn(fn ->
        receive do
          :http3_pool_down -> :ok
        end
      end)

    assert :ok = Pool.register(pool, :key, owner, nil, 2)
    assert {:ok, ^owner, first} = Pool.reserve(pool, :key)
    parent = self()
    spawn(fn -> send(parent, {:capacity_waiter, Pool.reserve(pool, :key, timeout: 1_000)}) end)
    assert %{pending: 1} = await_pending(pool, 1)
    assert :ok = Pool.release(pool, first)
    assert_receive {:capacity_waiter, {:ok, ^owner, second}}, 1_000
    assert :ok = Pool.release(pool, second)
  end

  test "request deadline releases native admission while DATA awaits settlement", ctx do
    {:ok, server} = Quic.listen(tls: [cert: [ctx.cert], key: ctx.key, alpn: ["h3"]])
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {_, port} = Quic.local(server)
    {:ok, pool} = Pool.start_link()
    on_exit(fn -> if Process.alive?(pool), do: GenServer.stop(pool) end)

    request = %HTTP.Request{
      url: URI.parse("https://127.0.0.1:#{port}/deadline"),
      transport_options: [ssl: ctx.tls, timeout: 1_000]
    }

    assert {:ok, stream, generation} = Stream.start(request, self(), pool: pool)
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    request_stream = incoming(accepted, 0)

    {:ok, headers} =
      QuicHttp3.Qpack.encode_header_block([{":status", "200"}, {"content-length", "100"}])

    bytes = QuicHttp3.Frame.encode!(:headers, headers) <> QuicHttp3.Frame.encode!(:data, "paused")
    assert {:ok, _} = Quic.send_stream(request_stream, bytes, false)
    assert_receive {:http_runtime, ^generation, ^stream, {:data, "paused", ref}}, 2_000
    [owner] = Map.keys(:sys.get_state(pool).owners)
    assert %{requests: 1} = ConnectionOwner.status(owner)
    marker = make_ref()
    Process.send_after(self(), marker, 1_100)
    assert_receive ^marker, 2_000
    assert %{leases: 0} = Pool.status(pool)
    assert %{requests: 0} = ConnectionOwner.status(owner)
    assert Process.alive?(stream)
    refute_receive {:http_runtime, ^generation, ^stream, {:error, _}}, 0
    monitor = Process.monitor(stream)
    Stream.acknowledge(stream, ref)
    assert_receive {:http_runtime, ^generation, ^stream, {:error, :request_timeout}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
  end

  test "pool admits the actual owner concurrency and queues until that slot releases", ctx do
    {:ok, server} = Quic.listen(tls: [cert: [ctx.cert], key: ctx.key, alpn: ["h3"]])
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {_, port} = Quic.local(server)
    {:ok, pool} = Pool.start_link(max_connections: 1)
    on_exit(fn -> if Process.alive?(pool), do: GenServer.stop(pool) end)

    request = %HTTP.Request{
      url: URI.parse("https://127.0.0.1:#{port}/one"),
      transport_options: [ssl: ctx.tls, timeout: 5_000]
    }

    assert {:ok, first, _} = Stream.start(request, self(), pool: pool, max_streams: 1)
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    _ = incoming(accepted, 0)
    assert {:ok, second, generation} = Stream.start(request, self(), pool: pool, max_streams: 1)
    assert %{pending: 1} = await_pending(pool, 1)
    Stream.close(first)
    request_stream = incoming(accepted, 4)
    send_response(request_stream, "second")
    assert collect(second, generation, "") == "second"
    assert %{owners: 1, leases: 0, pending: 0} = await_released(pool)
  end

  test "pool bounds FIFO waiters and reserves released slots without another connection" do
    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    {:ok, pool} = Pool.start_link(max_streams: 1, max_pending: 1, max_connections: 1)
    :ok = Pool.register(pool, :key, owner)
    assert {:ok, ^owner, first} = Pool.reserve(pool, :key)
    parent = self()
    waiter = spawn(fn -> send(parent, {:waiter, Pool.reserve(pool, :key, timeout: 1_000)}) end)
    assert %{pending: 1} = await_pending(pool, 1)
    assert {:error, :pool_queue_full} = Pool.reserve(pool, :key)
    assert :ok = Pool.release(pool, first)
    assert_receive {:waiter, {:ok, ^owner, second}}
    refute Process.alive?(waiter)
    assert :ok = Pool.release(pool, second)
    assert %{leases: 0, pending: 0} = Pool.status(pool)
    GenServer.stop(pool)
  end

  test "native owner opens 32 requests on one connection and exposes cleanup accounting", ctx do
    {:ok, server} =
      Quic.listen(
        tls: [cert: [ctx.cert], key: ctx.key, alpn: ["h3"]],
        streams: [max_streams_bidi: 64]
      )

    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {ip, port} = Quic.local(server)
    {:ok, owner} = ConnectionOwner.start_link(host: ip, port: port, tls: ctx.tls, max_streams: 64)
    on_exit(fn -> if Process.alive?(owner), do: GenServer.stop(owner) end)
    assert :ok = ConnectionOwner.await_ready(owner, 2_000)
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    generation = make_ref()

    refs =
      for n <- 1..32 do
        fields = [
          {":method", "GET"},
          {":scheme", "https"},
          {":authority", "example.test"},
          {":path", "/#{n}"}
        ]

        assert {:ok, ref} = ConnectionOwner.open(owner, fields, "", self(), generation)
        ref
      end

    assert %{requests: 32, allocations: 33, lifecycle: :ready} = ConnectionOwner.status(owner)
    for ref <- refs, do: assert(:ok = ConnectionOwner.cancel(owner, ref))
    assert %{requests: 0} = ConnectionOwner.status(owner)
    endpoint = ConnectionOwner.status(owner).endpoint
    assert :ok = GenServer.stop(owner)
    refute Process.alive?(endpoint)
  end

  test "a paused native download allows a sibling and terminal delivery follows acknowledged bytes",
       ctx do
    {:ok, server} =
      Quic.listen(
        tls: [cert: [ctx.cert], key: ctx.key, alpn: ["h3"]],
        streams: [max_streams_bidi: 64]
      )

    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {_, port} = Quic.local(server)
    {:ok, pool} = Pool.start_link()

    request = %HTTP.Request{
      url: URI.parse("https://127.0.0.1:#{port}/"),
      transport_options: [ssl: ctx.tls, timeout: 5_000]
    }

    assert {:ok, first, generation} = Stream.start(request, self(), pool: pool)
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    incoming = incoming(accepted, 0)
    send_response(incoming, String.duplicate("a", 32_768))
    assert_receive {:http_runtime, ^generation, ^first, {:headers, 200, _}}, 2_000
    assert_receive {:http_runtime, ^generation, ^first, {:data, bytes, delivery}}, 2_000
    assert byte_size(bytes) < 32_768
    refute_receive {:http_runtime, ^generation, ^first, {:data, _, _}}, 20
    assert {:ok, sibling, sibling_generation} = Stream.start(request, self(), pool: pool)
    send_response(incoming(accepted, 4), "sibling")
    assert_receive {:http_runtime, ^sibling_generation, ^sibling, {:headers, 200, _}}, 2_000

    assert_receive {:http_runtime, ^sibling_generation, ^sibling,
                    {:data, "sibling", sibling_delivery}},
                   2_000

    refute_receive {:http_runtime, ^sibling_generation, ^sibling, :done}, 10
    Stream.acknowledge(sibling, sibling_delivery)
    assert_receive {:http_runtime, ^sibling_generation, ^sibling, :done}, 2_000
    Stream.acknowledge(first, delivery)
    assert byte_size(collect(first, generation, bytes)) == 32_768
    GenServer.stop(pool)
  end

  test "explicit user transfer encoding fails before connecting", ctx do
    request = %HTTP.Request{
      method: :post,
      body: self(),
      duplex: :half,
      headers: HTTP.Headers.new([{"transfer-encoding", "chunked"}]),
      url: URI.parse("https://127.0.0.1/"),
      transport_options: [ssl: ctx.tls]
    }

    assert {:ok, stream, generation} = Stream.start(request, self())
    assert_receive {:http_runtime, ^generation, ^stream, {:error, :invalid_http3_headers}}, 1_000
  end

  test "native early final response cancels the producer without acknowledging unadmitted bytes",
       ctx do
    {:ok, server} = Quic.listen(tls: [cert: [ctx.cert], key: ctx.key, alpn: ["h3"]])
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {_, port} = Quic.local(server)
    {:ok, pool} = Pool.start_link()

    request = %HTTP.Request{
      method: :post,
      body: self(),
      duplex: :half,
      url: URI.parse("https://127.0.0.1:#{port}/early"),
      transport_options: [ssl: ctx.tls, timeout: 5_000]
    }

    assert {:ok, stream, generation} = Stream.start(request, self(), pool: pool)
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    request_stream = incoming(accepted, 0)
    assert_receive {:read_chunk, _bridge, :ack}, 2_000
    send_response(request_stream, "early", "413")
    assert_receive {:http_runtime, ^generation, ^stream, {:headers, 413, _}}, 2_000
    assert_receive {:error, :early_response}, 2_000
    assert_receive {:http_runtime, ^generation, ^stream, {:data, "early", ref}}, 2_000
    Stream.acknowledge(stream, ref)
    assert_receive {:http_runtime, ^generation, ^stream, :done}, 2_000
    refute_receive {:http_runtime, ^generation, ^stream, {:error, _}}, 10
    GenServer.stop(pool)
  end

  test "stopping an owner preserves a verified shared endpoint", ctx do
    {:ok, server} = Quic.listen(tls: [cert: [ctx.cert], key: ctx.key, alpn: ["h3"]])
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {_, port} = Quic.local(server)
    {:ok, budget} = ReceiveBudget.normalize([])

    {:ok, endpoint} =
      QuicHttp3.Transport.Quic.client(Keyword.merge(budget, host: "127.0.0.1", tls: ctx.tls))

    on_exit(fn -> QuicHttp3.Transport.Quic.stop_endpoint(endpoint) end)

    {:ok, owner} =
      ConnectionOwner.start_link(host: "127.0.0.1", port: port, tls: ctx.tls, endpoint: endpoint)

    assert :ok = ConnectionOwner.await_ready(owner, 2_000)
    assert :ok = GenServer.stop(owner)
    assert Process.alive?(endpoint.pid)
  end

  defp incoming(handle, id), do: incoming(handle, id, System.monotonic_time(:millisecond) + 2_000)

  defp incoming(handle, id, deadline) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(handle, 128)

    case Enum.find_value(events, fn
           {:stream_open, %{id: ^id} = stream, :bidi} -> stream
           _ -> nil
         end) do
      nil -> incoming(handle, id, deadline)
      stream -> stream
    end
  end

  defp send_response(stream, body, status \\ "200") do
    {:ok, headers} =
      QuicHttp3.Qpack.encode_header_block([
        {":status", status},
        {"content-length", Integer.to_string(byte_size(body))}
      ])

    bytes = QuicHttp3.Frame.encode!(:headers, headers) <> QuicHttp3.Frame.encode!(:data, body)
    send_bytes(stream, bytes)
  end

  defp send_bytes(stream, bytes) do
    size = min(byte_size(bytes), 16_384)
    <<chunk::binary-size(^size), rest::binary>> = bytes
    assert {:ok, _} = Quic.send_stream(stream, chunk, rest == <<>>)
    if rest != <<>>, do: send_bytes(stream, rest)
  end

  defp collect(stream, generation, bytes) do
    receive do
      {:http_runtime, ^generation, ^stream, {:data, chunk, ref}} ->
        Stream.acknowledge(stream, ref)
        collect(stream, generation, bytes <> chunk)

      {:http_runtime, ^generation, ^stream, :done} ->
        bytes

      {:http_runtime, ^generation, ^stream, {:error, reason}} ->
        flunk(inspect(reason))
    after
      2_000 -> flunk("native response did not finish")
    end
  end

  defp await_pending(pool, count, attempts \\ 1_000)
  defp await_pending(_pool, _count, 0), do: flunk("pool waiter was not queued")

  defp await_pending(pool, count, attempts) do
    case Pool.status(pool) do
      %{pending: ^count} = status -> status
      _ -> await_pending(pool, count, attempts - 1)
    end
  end

  defp await_released(pool, attempts \\ 1_000)
  defp await_released(_pool, 0), do: flunk("pool lease was not released")

  defp await_released(pool, attempts) do
    case Pool.status(pool) do
      %{leases: 0} = status -> status
      _ -> await_released(pool, attempts - 1)
    end
  end
end

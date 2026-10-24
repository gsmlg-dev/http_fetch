defmodule HTTP.HTTP3.CleanupIntegrationTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  alias HTTP.HTTP3.{Pool, Stream}
  alias Quic.Cleanup

  # A test-only retained authority exercises H1's C1 callback boundary. Native
  # endpoint/connection/IO/Port effects use the actual default QUIC transport.
  defmodule Retainer do
    use GenServer
    def init(test), do: {:ok, %{test: test, descriptors: []}}

    def handle_call(:begin_cleanup, _from, state) do
      {:ok, handle, lease} = Cleanup.new(owner: self())
      descriptor = %{handle: handle, lease: lease}
      test = state.test

      debug = fn
        count, {:in, {:"$gen_call", _, {_, {:enroll, _, resource}}}}, _ ->
          send(test, {:native_resource, handle, resource})
          count + 1

        count, _, _ ->
          count
      end

      :ok = :sys.install(handle.observer, {debug, 0})
      state = %{state | descriptors: [descriptor | state.descriptors]}
      send(test, {:retained_cleanup, descriptor})
      {:reply, {:ok, descriptor}, state}
    end

    def handle_call({:register_worker, worker, kind, _}, _from, state) do
      send(state.test, {:http_worker, worker, kind})
      {:reply, :ok, state}
    end

    def handle_call({:register, worker, kind}, _from, state) do
      send(state.test, {:http_worker, worker, kind})
      {:reply, :ok, state}
    end

    def handle_cast(_, state), do: {:noreply, state}

    def terminate(_, state) do
      for descriptor <- state.descriptors, do: Cleanup.retire(descriptor.lease, bound(0))
    end

    defp bound(timeout), do: {:abs_ms, System.monotonic_time(:millisecond) + timeout}
  end

  setup do
    directory = Path.expand("../../../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(directory, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(directory, "leaf-key.pem")))

    server =
      start_supervised!(%{
        id: :native_h3_peer,
        start:
          {Quic, :listen,
           [[acceptor: self(), tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]]]]},
        restart: :temporary
      })

    {_, port} = Quic.local(server)
    {:ok, tracker} = GenServer.start(Retainer, self())
    on_exit(fn -> if Process.alive?(tracker), do: GenServer.stop(tracker) end)
    pool = start_supervised!({Pool, []})

    request = %HTTP.Request{
      url: URI.parse("https://127.0.0.1:#{port}/retire"),
      transport_options: [
        http3_reuse: false,
        timeout: 5_000,
        ssl: [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
      ]
    }

    %{server: server, tracker: tracker, pool: pool, request: request}
  end

  for cause <- [:complete, :close, :owner_loss, :watchdog_loss, :tracker_loss] do
    @cause cause
    test "real native graph and HTTP workers independently join after #{@cause}", ctx do
      opening = now() + 3_000

      callback = fn received ->
        assert received == opening
        GenServer.call(ctx.tracker, :begin_cleanup)
      end

      assert {:ok, relay, generation} =
               Stream.start(ctx.request, self(),
                 pool: ctx.pool,
                 opening_deadline_at: opening,
                 request_lifecycle: ctx.tracker,
                 quic_cleanup: callback,
                 idle_timeout: 60_000
               )

      relay_join = Process.monitor(relay)
      assert_receive {:retained_cleanup, %{handle: handle} = descriptor}, 1_000

      joins =
        for _ <- 1..4 do
          assert_receive {:native_resource, ^handle, resource}, 2_000
          type = if is_port(resource), do: :port, else: :process
          {resource, type, :erlang.monitor(type, resource)}
        end

      assert_receive {:http_worker, owner, :http3_owner}
      assert_receive {:http_worker, watchdog, :http3_watchdog}
      owner_join = Process.monitor(owner)
      watchdog_join = Process.monitor(watchdog)
      assert_receive {:quic_accept, server}, 2_000
      assert server == ctx.server
      {:ok, accepted} = Quic.accept(server)
      :ok = Quic.attach(accepted, self())
      request_stream = incoming(accepted, 0, bound(2_000))

      assert {:pending, %{roles: %{endpoint: 1, connection: 1, io: 1, port: 1}}} =
               Cleanup.status(handle)

      case @cause do
        :complete ->
          {:ok, headers} =
            QuicHttp3.Qpack.encode_header_block([{":status", "200"}, {"content-length", "4"}])

          bytes =
            QuicHttp3.Frame.encode!(:headers, headers) <> QuicHttp3.Frame.encode!(:data, "done")

          assert {:ok, _} = Quic.send_stream(request_stream, bytes, true)
          assert collect(relay, generation, "") == "done"

        :close ->
          Stream.close(relay)

        :owner_loss ->
          Process.exit(owner, :kill)

        :watchdog_loss ->
          Process.exit(watchdog, :kill)

        :tracker_loss ->
          Process.exit(ctx.tracker, :kill)
      end

      assert_receive {:DOWN, ^relay_join, :process, ^relay, _}, 2_000
      assert_receive {:DOWN, ^owner_join, :process, ^owner, _}, 2_000
      assert_receive {:DOWN, ^watchdog_join, :process, ^watchdog, _}, 2_000

      assert {:ok, %{cleanup: :confirmed, enrolled: 4, down: 4}} =
               Cleanup.await(handle, bound(2_000))

      for {resource, type, monitor} <- joins do
        assert_receive {:DOWN, ^monitor, ^type, ^resource, _}, 1_000
        if type == :port, do: assert(:erlang.port_info(resource) == :undefined)
      end

      assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(descriptor.lease, bound(0))
      assert %{leases: 0, pending: 0} = Pool.status(ctx.pool)

      for kind <- [:http3_connector, :http3_connector_watchdog] do
        assert_receive {:http_worker, worker, ^kind}
        refute Process.alive?(worker)
      end
    end
  end

  defp incoming(connection, id, {:abs_ms, deadline} = bound) do
    assert now() < deadline
    assert {:ok, events} = Quic.events(connection)

    case Enum.find(events, &match?({:stream_open, %{id: ^id}, _}, &1)) do
      {:stream_open, handle, _} ->
        handle

      _ ->
        receive do
        after
          1 -> incoming(connection, id, bound)
        end
    end
  end

  defp collect(relay, generation, acc) do
    receive do
      {:http_runtime, ^generation, ^relay, {:data, bytes, ref}} ->
        Stream.acknowledge(relay, ref)
        collect(relay, generation, acc <> bytes)

      {:http_runtime, ^generation, ^relay, :done} ->
        acc

      {:http_runtime, ^generation, ^relay, {:error, reason}} ->
        flunk(inspect(reason))

      {:http_runtime, ^generation, ^relay, _} ->
        collect(relay, generation, acc)
    after
      2_000 -> flunk("HTTP/3 native response timed out")
    end
  end

  defp bound(timeout), do: {:abs_ms, now() + timeout}
  defp now, do: System.monotonic_time(:millisecond)
end

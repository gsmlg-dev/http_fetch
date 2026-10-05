defmodule HTTP.HTTP3.LifecycleTest do
  use ExUnit.Case, async: true
  alias HTTP.HTTP3.{BodyBridge, ConnectionOwner, Pool}

  defmodule Transport do
    def connect(_, _, opts) do
      controller = opts[:controller]
      send(Agent.get(controller, & &1.test), {:native_connect, self()})

      if Agent.get(controller, &Map.get(&1, :stall_connect, false)),
        do: receive(do: (:never -> :ok))

      {:ok, %{controller: controller, endpoint: controller}}
    end

    def ready(_, _), do: :ready

    def open_stream(connection, kind, _) do
      id =
        Agent.get_and_update(connection.controller, fn state ->
          id = if kind == :bidi, do: state.id, else: 2
          {id, if(kind == :bidi, do: %{state | id: id + 4}, else: state)}
        end)

      {:ok, %{controller: connection.controller, handle: %{id: id}}}
    end

    def send_stream(stream, bytes, fin, opts) do
      outcome =
        Agent.get_and_update(stream.controller, fn state ->
          [outcome | rest] = state.sends ++ [:ok]
          send(state.test, {:native_send, stream.handle.id, bytes, fin})
          {outcome, %{state | sends: rest}}
        end)

      case outcome do
        :unknown ->
          send(Agent.get(stream.controller, & &1.test), {:native_unknown, opts[:ref]})
          {:unknown, opts[:ref]}

        :blocked ->
          {:blocked, :flow_control}

        :ok ->
          {:ok, make_ref()}
      end
    end

    def operation_status(connection, ref, _) do
      Agent.get(connection.controller, fn state -> Map.get(state.statuses, ref, :unknown) end)
    end

    def events(connection, _, _) do
      {:ok, Agent.get_and_update(connection.controller, &{&1.events, %{&1 | events: []}})}
    end

    def read(stream, _, _) do
      {:ok,
       Agent.get_and_update(stream.controller, fn state ->
         {items, reads} = Map.pop(Map.get(state, :reads, %{}), stream.handle.id, [])
         {items, Map.put(state, :reads, reads)}
       end)}
    end

    def reset_stream(stream, _, opts) do
      outcome =
        Agent.get_and_update(stream.controller, fn state ->
          [outcome | rest] = Map.get(state, :resets, []) ++ [:ok]
          send(state.test, {:native_reset, stream.handle.id, opts[:ref]})
          {outcome, Map.put(state, :resets, rest)}
        end)

      if outcome == :unknown, do: {:unknown, opts[:ref]}, else: :ok
    end

    def stop_stream(_, _, _), do: :ok
    def abort(_, _), do: :ok
  end

  setup do
    test = self()

    {:ok, controller} =
      Agent.start_link(fn -> %{test: test, id: 0, sends: [], statuses: %{}, events: []} end)

    %{controller: controller}
  end

  defp owner(controller, opts \\ []) do
    {:ok, owner} =
      ConnectionOwner.start_link(
        Keyword.merge(
          [
            host: "test",
            port: 443,
            controller: controller,
            session_options: [transport: Transport]
          ],
          opts
        )
      )

    on_exit(fn -> if Process.alive?(owner), do: GenServer.stop(owner) end)
    :ok = ConnectionOwner.await_ready(owner)
    owner
  end

  defp fields,
    do: [{":method", "POST"}, {":scheme", "https"}, {":authority", "test"}, {":path", "/"}]

  test "unknown upload reconciles its original operation without replay or producer ACK", %{
    controller: controller
  } do
    owner = owner(controller)
    assert {:ok, request} = ConnectionOwner.open(owner, fields(), :stream, self(), make_ref())
    Agent.update(controller, &%{&1 | sends: [:unknown]})
    {:ok, bridge} = BodyBridge.start_link(self(), self())
    BodyBridge.credit(bridge, 16_384)
    assert_receive {:read_chunk, ^bridge, :ack}
    source_ref = make_ref()
    send(bridge, {:stream_chunk, self(), "body", source_ref})
    assert_receive {:body_chunk, ^bridge, "body", write_ref}
    ConnectionOwner.send_data(owner, request, "body", false, self(), write_ref)
    assert_receive {:native_unknown, operation}
    refute_receive {:http3_write, ^write_ref, _}, 20
    refute_receive {:stream_chunk_ack, ^source_ref}, 10
    Agent.update(controller, &put_in(&1.statuses[operation], %{status: :admitted, result: :ok}))
    assert_receive {:http3_write, ^write_ref, :done}, 1_000
    assert :ok = BodyBridge.ack(bridge, write_ref)
    assert_receive {:stream_chunk_ack, ^source_ref}
    data = QuicHttp3.Frame.encode!(:data, "body")
    assert_receive {:native_send, 0, ^data, false}
    refute_receive {:native_send, 0, ^data, false}, 20
    GenServer.stop(bridge)
  end

  test "definitely blocked request waits for writable and does not starve sibling opens", %{
    controller: controller
  } do
    owner = owner(controller)
    Agent.update(controller, &%{&1 | sends: [:blocked]})
    test = self()

    spawn(fn ->
      send(test, {:first_open, ConnectionOwner.open(owner, fields(), "", test, make_ref())})
    end)

    assert_receive {:native_send, 0, first_headers, true}
    assert %{continuations: 1} = ConnectionOwner.status(owner)
    assert {:ok, sibling} = ConnectionOwner.open(owner, fields(), "", self(), make_ref())
    assert_receive {:native_send, 4, _, true}
    refute_receive {:native_send, 0, ^first_headers, true}, 20
    refute_receive {:first_open, _}, 10
    Agent.update(controller, &%{&1 | events: [:writable]})
    assert_receive {:first_open, {:ok, first}}, 1_000
    assert_receive {:native_send, 0, ^first_headers, true}
    ConnectionOwner.cancel(owner, first)
    ConnectionOwner.cancel(owner, sibling)
  end

  test "blocked initialization is resumed rather than allocating control twice", %{
    controller: controller
  } do
    Agent.update(controller, &%{&1 | sends: [:blocked], events: [:writable]})
    owner = owner(controller)
    assert %{allocations: 1, lifecycle: :ready} = ConnectionOwner.status(owner)
    assert_receive {:native_send, 2, control, false}
    assert_receive {:native_send, 2, ^control, false}
    refute_receive {:native_send, 2, ^control, false}, 10
  end

  test "external watchdog bounds a synchronous stalled connect", %{controller: controller} do
    Agent.update(controller, &Map.put(&1, :stall_connect, true))

    {:ok, owner} =
      ConnectionOwner.start_link(
        host: "test",
        port: 443,
        controller: controller,
        connect_timeout: 30,
        operation_timeout: 30,
        session_options: [transport: Transport]
      )

    Process.unlink(owner)
    monitor = Process.monitor(owner)
    assert_receive {:native_connect, ^owner}
    assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}, 1_000
  end

  test "rotation counts critical allocation and drains before further admission", %{
    controller: controller
  } do
    owner = owner(controller, rotation_after: 3)
    assert {:ok, first} = ConnectionOwner.open(owner, fields(), "", self(), make_ref())
    assert {:ok, second} = ConnectionOwner.open(owner, fields(), "", self(), make_ref())
    assert %{allocations: 3, lifecycle: :draining} = ConnectionOwner.status(owner)
    assert {:error, :goaway} = ConnectionOwner.open(owner, fields(), "", self(), make_ref())
    monitor = Process.monitor(owner)
    ConnectionOwner.cancel(owner, first)
    ConnectionOwner.cancel(owner, second)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
  end

  test "early final headers wait for send-half reconciliation and abandon only blocked writes", %{
    controller: controller
  } do
    owner = owner(controller)
    generation = make_ref()
    assert {:ok, request} = ConnectionOwner.open(owner, fields(), :stream, self(), generation)
    Agent.update(controller, &%{&1 | sends: [:blocked]})
    write_ref = make_ref()
    ConnectionOwner.send_data(owner, request, "body", false, self(), write_ref)
    data = QuicHttp3.Frame.encode!(:data, "body")
    assert_receive {:native_send, 0, ^data, false}
    {:ok, headers} = QuicHttp3.Qpack.encode_header_block([{":status", "413"}])
    stream = %{controller: controller, handle: %{id: 0}}

    Agent.update(controller, fn state ->
      state
      |> Map.put(:resets, [:unknown])
      |> Map.put(:reads, %{0 => [{:data, QuicHttp3.Frame.encode!(:headers, headers)}]})
      |> Map.put(:events, [{:readable, stream}])
    end)

    assert_receive {:http3_write, ^write_ref, {:error, :upload_closed}}, 1_000
    assert_receive {:native_reset, 0, operation}, 1_000
    refute_receive {:http3, ^generation, ^request, {:headers, 413, _}}, 20
    Agent.update(controller, &put_in(&1.statuses[operation], %{status: :completed, result: :ok}))
    assert_receive {:http3, ^generation, ^request, {:headers, 413, _}}, 1_000
    refute_receive {:native_send, 0, ^data, false}, 10
  end

  test "GOAWAY rejects admitted IDs at the cutoff and drains without replay", %{
    controller: controller
  } do
    owner = owner(controller)
    generation = make_ref()
    assert {:ok, first} = ConnectionOwner.open(owner, fields(), "", self(), generation)
    assert {:ok, second} = ConnectionOwner.open(owner, fields(), "", self(), generation)
    peer = %{controller: controller, handle: %{id: 3}}

    bytes =
      <<0>> <>
        QuicHttp3.Frame.encode!(:settings, <<>>) <>
        QuicHttp3.Frame.encode!(:goaway, QuicHttp3.Varint.encode!(4))

    Agent.update(controller, fn state ->
      state
      |> Map.put(:reads, %{3 => [{:data, bytes}]})
      |> Map.put(:events, [{:stream_open, peer, :uni}, {:readable, peer}])
    end)

    assert_receive {:http3, ^generation, ^second, {:error, :request_rejected}}, 1_000
    refute_receive {:http3, ^generation, ^first, {:error, _}}, 10
    assert %{lifecycle: :draining, requests: 1} = ConnectionOwner.status(owner)
    assert {:error, :goaway} = ConnectionOwner.open(owner, fields(), "", self(), generation)
    ConnectionOwner.cancel(owner, first)
  end

  test "idle budget starts again after the last request activity", %{controller: controller} do
    owner = owner(controller, idle_timeout: 60)
    monitor = Process.monitor(owner)
    assert {:ok, request} = ConnectionOwner.open(owner, fields(), "", self(), make_ref())
    refute_receive {:DOWN, ^monitor, :process, ^owner, _}, 70
    ConnectionOwner.cancel(owner, request)
    refute_receive {:DOWN, ^monitor, :process, ^owner, _}, 20
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 500
  end

  test "subscriber death during unknown opening reconciles then cancels the same stream", %{
    controller: controller
  } do
    owner = owner(controller)
    Agent.update(controller, &%{&1 | sends: [:unknown]})
    subscriber = spawn(fn -> ConnectionOwner.open(owner, fields(), "", self(), make_ref()) end)
    assert_receive {:native_unknown, operation}, 1_000
    monitor = Process.monitor(subscriber)
    Process.exit(subscriber, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^subscriber, :killed}
    Agent.update(controller, &put_in(&1.statuses[operation], %{status: :admitted, result: :ok}))
    assert_receive {:native_reset, 0, _}, 1_000
    assert %{requests: 0, allocations: 2} = ConnectionOwner.status(owner)
    refute_receive {:native_send, 4, _, _}, 10
  end

  test "pool validates connector identity and cleans up after lease and caller death" do
    {:ok, pool} = Pool.start_link(max_connections: 1, max_total_connections: 1)
    {:connect, lease} = Pool.reserve(pool, :one)

    owner =
      spawn(fn ->
        receive do
          :http3_pool_down -> :ok
        end
      end)

    monitor = Process.monitor(owner)
    assert {:error, :invalid_connector} = Pool.register(pool, :other, owner, lease)
    assert :ok = Pool.register(pool, :one, owner, lease)
    assert {:error, :owner_already_registered} = Pool.register(pool, :one, owner, lease)
    Pool.release(pool, lease)
    GenServer.stop(pool)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
  end
end

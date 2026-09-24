defmodule HTTP.HTTP2RuntimeTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{BodyBridge, ConnectionOwner, Frame, HPACK, Pool}

  defp transport(test_pid) do
    %{
      send: fn socket, data ->
        send(test_pid, {:wire, socket, IO.iodata_to_binary(data)})
        :ok
      end,
      close: fn socket ->
        send(test_pid, {:closed, socket})
        :ok
      end
    }
  end

  defp headers(path) do
    [
      {":method", "GET"},
      {":scheme", "http"},
      {":authority", "example.test"},
      {":path", path}
    ]
  end

  defp upload_stream(test_pid) do
    spawn(fn -> upload_stream_loop(test_pid) end)
  end

  defp upload_stream_loop(test_pid) do
    receive do
      {:read_chunk, bridge, :ack} ->
        send(test_pid, {:read, bridge})
        upload_stream_loop(test_pid)

      {:chunk, bridge, chunk} ->
        ref = make_ref()
        send(bridge, {:stream_chunk, self(), chunk, ref})
        send(test_pid, {:chunk_ref, ref})
        upload_stream_loop(test_pid)

      {:eof, bridge} ->
        send(test_pid, :stream_eof_sent)
        send(bridge, {:stream_end, self()})

        receive do
          {:read_chunk, _bridge, :ack} ->
            upload_stream_loop(test_pid)
        after
          500 -> :ok
        end

      {:stream_chunk_ack, ref} ->
        send(test_pid, {:chunk_ack, ref})
        upload_stream_loop(test_pid)
    end
  end

  defp decode_wire!(wire) do
    assert {:ok, frame, <<>>} = Frame.decode(wire)
    frame
  end

  test "one owner writes one preface and allocates three overlapping streams" do
    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport(self()), socket: :socket, max_streams: 3)

    assert_receive {:wire, :socket, preface_and_settings}, 500
    assert binary_part(preface_and_settings, 0, 24) == HTTP.HTTP2.connection_preface()

    assert {:ok, first} = ConnectionOwner.open_stream(owner, headers("/one"), subscriber: self())
    assert {:ok, second} = ConnectionOwner.open_stream(owner, headers("/two"), subscriber: self())

    assert {:ok, third} =
             ConnectionOwner.open_stream(owner, headers("/three"), subscriber: self())

    assert [first.id, second.id, third.id] == [1, 3, 5]

    status = ConnectionOwner.status(owner)
    assert status.lifecycle == :ready
    assert Enum.sort(status.stream_ids) == [1, 3, 5]
    assert status.queue_peak_bytes > 0
    assert status.queue_peak_bytes <= status.max_queue_bytes
  end

  test "legacy priority profile serializes PRIORITY before HEADERS" do
    {:ok, owner} =
      ConnectionOwner.start_link(
        transport: transport(self()),
        socket: :socket,
        profile: :synthetic_test_v1
      )

    assert_receive {:wire, :socket, _}, 500

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, headers("/priority"), subscriber: self())

    assert_receive {:wire, :socket, priority_wire}, 500

    assert %{type: :priority, stream_id: 1, payload: <<0::1, 0::31, 15>>} =
             decode_wire!(priority_wire)

    assert_receive {:wire, :socket, _headers}, 500
  end

  test "accepts the peer ACK for the initial SETTINGS frame" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, preface_and_settings}, 500

    <<_preface::binary-size(24), settings::binary>> = preface_and_settings
    assert {:ok, %{type: :settings, flags: 0, stream_id: 0}, <<>>} = Frame.decode(settings)

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:settings, 0x1, 0, <<>>))
    assert ConnectionOwner.status(owner).lifecycle == :ready
  end

  test "single stream cancellation emits RST and leaves neighbor alive" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500
    assert {:ok, first} = ConnectionOwner.open_stream(owner, headers("/one"), subscriber: self())
    assert {:ok, second} = ConnectionOwner.open_stream(owner, headers("/two"), subscriber: self())
    assert :ok = ConnectionOwner.cancel(owner, first.ref)
    assert_receive {:http2, first_id, {:http2, :cancelled}}, 500
    assert first_id == first.id
    assert ConnectionOwner.status(owner).stream_ids == [first.id, second.id]
  end

  test "GOAWAY drains the owner and rejects new streams" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500
    goaway = Frame.encode(:goaway, 0, 0, <<0::1, 1::31, 0::32>>)
    assert :ok = ConnectionOwner.receive_bytes(owner, goaway)
    assert ConnectionOwner.status(owner).lifecycle == :draining
    assert {:error, :draining} = ConnectionOwner.open_stream(owner, headers("/new"))
  end

  test "GOAWAY closes after the last stream is released" do
    {:ok, owner} =
      ConnectionOwner.start_link(
        transport: transport(self()),
        socket: :socket,
        drain_timeout: 1_000
      )

    assert_receive {:wire, :socket, _}, 500

    assert {:ok, %{ref: ref}} =
             ConnectionOwner.open_stream(owner, headers("/drain"), subscriber: self())

    assert :ok =
             ConnectionOwner.receive_bytes(
               owner,
               Frame.encode(:goaway, 0, 0, <<0::1, 1::31, 0::32>>)
             )

    assert :ok = ConnectionOwner.release_stream(owner, ref)
    refute Process.alive?(owner)
  end

  test "GOAWAY drain deadline closes an unfinished owner" do
    {:ok, owner} =
      ConnectionOwner.start_link(
        transport: transport(self()),
        socket: :socket,
        drain_timeout: 10
      )

    Process.unlink(owner)
    monitor = Process.monitor(owner)
    assert_receive {:wire, :socket, _}, 500

    assert {:ok, _stream} =
             ConnectionOwner.open_stream(owner, headers("/stuck"), subscriber: self())

    assert :ok =
             ConnectionOwner.receive_bytes(
               owner,
               Frame.encode(:goaway, 0, 0, <<0::1, 1::31, 0::32>>)
             )

    assert_receive {:DOWN, ^monitor, :process, ^owner, :drain_timeout}, 500
  end

  test "response HEADERS and CONTINUATION update shared HPACK state atomically" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, headers("/headers"), subscriber: self())

    block = HPACK.encode_headers([{":status", "200"}]) |> IO.iodata_to_binary()
    <<first, rest::binary>> = block
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 0, 1, <<first>>))
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:continuation, 0x4, 1, rest))
    assert_receive {:http2, 1, {:http2, :headers, [{":status", "200"}], _flags}}, 500
  end

  test "inbound DATA consumes receive credit and replenishes both windows" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, headers("/data"), subscriber: self())

    assert_receive {:wire, :socket, _headers}, 500

    block = HPACK.encode_headers([{":status", "200"}]) |> IO.iodata_to_binary()
    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:headers, 0x4, 1, block))
    assert_receive {:http2, 1, {:http2, :headers, _, _}}, 500

    assert :ok = ConnectionOwner.receive_bytes(owner, Frame.encode(:data, 0x1, 1, "ok"))
    assert_receive {:http2, 1, {:http2, :data, "ok", 1}}, 500
    assert_receive {:wire, :socket, window_wire}, 500

    assert %{type: :window_update, stream_id: 0, payload: <<0::1, 2::31>>} =
             decode_wire!(window_wire)

    assert_receive {:wire, :socket, window_wire}, 500

    assert %{type: :window_update, stream_id: 1, payload: <<0::1, 2::31>>} =
             decode_wire!(window_wire)
  end

  test "body bridge credit writes DATA and forwards the bridge acknowledgement" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500

    stream = upload_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, owner)

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, headers("/upload"), body_bridge: bridge)

    assert_receive {:wire, :socket, _headers}, 500
    assert :ok = BodyBridge.credit(bridge, 5)
    assert_receive {:read, ^bridge}, 500
    send(stream, {:chunk, bridge, "hello"})
    assert_receive {:chunk_ref, ref}, 500

    assert_receive {:wire, :socket, data_wire}, 500
    assert %{type: :data, stream_id: 1, flags: 0, payload: "hello"} = decode_wire!(data_wire)
    assert_receive {:chunk_ack, ^ref}, 500
  end

  test "body bridge EOF writes an empty END_STREAM DATA frame" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500

    stream = upload_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, owner)

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, headers("/upload-eof"), body_bridge: bridge)

    assert_receive {:wire, :socket, _headers}, 500
    assert :ok = BodyBridge.credit(bridge, 1)
    assert_receive {:read, ^bridge}, 500
    send(stream, {:eof, bridge})
    assert_receive :stream_eof_sent, 500
    assert_receive {:wire, :socket, data_wire}, 500
    assert %{type: :data, stream_id: 1, flags: 1, payload: <<>>} = decode_wire!(data_wire)
  end

  test "blocked body data resumes after a stream WINDOW_UPDATE" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500

    settings = Frame.encode(:settings, 0, 0, <<4::16, 0::32>>)
    assert :ok = ConnectionOwner.receive_bytes(owner, settings)
    assert_receive {:wire, :socket, settings_ack}, 500
    assert %{type: :settings, flags: 1, stream_id: 0, payload: <<>>} = decode_wire!(settings_ack)

    bridge = self()

    assert {:ok, %{id: 1}} =
             ConnectionOwner.open_stream(owner, headers("/blocked"), body_bridge: bridge)

    assert_receive {:wire, :socket, _headers}, 500
    ack_ref = make_ref()

    assert :ok =
             ConnectionOwner.send_event(owner, {:body_chunk, bridge, "x", ack_ref})

    refute_receive {:body_ack, ^ack_ref}, 50

    window_update = Frame.encode(:window_update, 0, 1, <<0::1, 1::31>>)
    assert :ok = ConnectionOwner.receive_bytes(owner, window_update)
    assert_receive {:wire, :socket, data_wire}, 500
    assert %{type: :data, stream_id: 1, flags: 0, payload: "x"} = decode_wire!(data_wire)
    assert_receive {:body_ack, ^ack_ref}, 500
    assert ConnectionOwner.status(owner).stream_ids == [1]
  end

  test "cancelling an upload stream stops its body bridge" do
    {:ok, owner} = ConnectionOwner.start_link(transport: transport(self()), socket: :socket)
    assert_receive {:wire, :socket, _}, 500

    stream = upload_stream(self())
    {:ok, bridge} = BodyBridge.start_link(stream, owner)

    assert {:ok, %{id: id, ref: ref}} =
             ConnectionOwner.open_stream(owner, headers("/cancel-upload"),
               body_bridge: bridge,
               subscriber: self()
             )

    assert_receive {:wire, :socket, _headers}, 500
    assert :ok = ConnectionOwner.cancel(owner, ref)
    assert_receive {:http2, ^id, {:http2, :cancelled}}, 500
    assert %{stopped?: true} = BodyBridge.status(bridge)
  end

  test "pool reserves capacity atomically for a registered owner" do
    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport(self()), socket: :socket, max_streams: 1)

    assert_receive {:wire, :socket, _}, 500
    {:ok, pool} = Pool.start_link(max_connections: 1, max_streams: 1)
    assert :ok = Pool.register(pool, :profile_key, owner, max_streams: 1)
    assert {:ok, ^owner, token} = Pool.reserve(pool, :profile_key)
    assert %{streams: 1} = Pool.stats(pool)[:profile_key]
    assert :ok = Pool.release(pool, :profile_key, token)
    assert %{streams: 0} = Pool.stats(pool)[:profile_key]
  end

  test "pool allows only one out-of-band connector per key" do
    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport(self()), socket: :socket, max_streams: 1)

    assert_receive {:wire, :socket, _}, 500
    {:ok, pool} = Pool.start_link(max_connections: 2)

    assert :start = Pool.claim_connect(pool, :profile_key)
    assert :wait = Pool.claim_connect(pool, :profile_key)
    assert :ok = Pool.register(pool, :profile_key, owner, connecting?: true)
    assert %{connecting: 0, connections: 1} = Pool.stats(pool)[:profile_key]
  end

  test "failed out-of-band connection wakes queued reservations" do
    {:ok, pool} = Pool.start_link(max_connections: 1)
    assert :start = Pool.claim_connect(pool, :profile_key)

    waiter = Task.async(fn -> Pool.reserve(pool, :profile_key) end)
    Process.sleep(10)
    assert :ok = Pool.fail_connect(pool, :profile_key, :econnrefused)
    assert {:error, {:owner_start_failed, :econnrefused}} = Task.await(waiter)
    assert %{connecting: 0, pending: 0} = Pool.stats(pool)[:profile_key]
  end

  test "draining owners stop new reservations but free a connection slot" do
    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport(self()), socket: :socket, max_streams: 1)

    assert_receive {:wire, :socket, _}, 500
    {:ok, pool} = Pool.start_link(max_connections: 1)
    assert :ok = Pool.register(pool, :profile_key, owner)
    assert :ok = Pool.mark_draining(pool, :profile_key, owner)
    assert :none = Pool.try_reserve(pool, :profile_key)
    assert :start = Pool.claim_connect(pool, :profile_key)
  end

  test "idle owners stop after the configured timeout" do
    {:ok, owner} =
      ConnectionOwner.start_link(transport: transport(self()), socket: :socket, max_streams: 1)

    assert_receive {:wire, :socket, _}, 500
    {:ok, pool} = Pool.start_link(max_connections: 1, idle_timeout: 10)
    assert :ok = Pool.register(pool, :profile_key, owner)
    assert {:ok, ^owner, token} = Pool.reserve(pool, :profile_key)
    assert :ok = Pool.release(pool, :profile_key, token)
    Process.sleep(30)
    refute Process.alive?(owner)
  end
end

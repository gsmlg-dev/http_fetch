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

  test "blocked body data reports backpressure without acknowledging the chunk" do
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

    assert {:error, {:body_backpressure, :flow_control_blocked}} =
             ConnectionOwner.send_event(owner, {:body_chunk, bridge, "x", ack_ref})

    refute_receive {:body_ack, ^ack_ref}, 50
    assert_receive {:body_error, :flow_control_blocked}, 500
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
end

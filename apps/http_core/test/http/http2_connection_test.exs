defmodule HTTP.HTTP2ConnectionTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{Connection, HPACK, Settings, StreamState}

  test "allocates odd stream ids and enforces peer concurrency" do
    peer = Settings.new(values: %{max_concurrent_streams: 1})
    conn = Connection.new(peer_settings: peer)
    assert {:ok, first, conn} = Connection.open_stream(conn)
    assert first.id == 1
    assert {:error, :max_concurrent_streams} = Connection.open_stream(conn)
    conn = Connection.remove_stream(conn, first.id)
    assert {:ok, second, _conn} = Connection.open_stream(conn)
    assert second.id == 3
  end

  test "peer initial window changes apply to all streams and can pause sends" do
    {:ok, stream, conn} = Connection.open_stream(Connection.new())
    {:ok, stream} = StreamState.send_data(stream, 65_535)
    conn = Connection.put_stream(conn, stream)

    assert {:ok, conn, [{:settings_ack, [{:initial_window_size, 0}]}]} =
             Connection.update_peer_settings(conn, [{:initial_window_size, 0}])

    assert {:ok, stream} = Connection.stream(conn, 1)
    assert stream.send_window == -65_535
    assert {:error, :flow_control_blocked} = StreamState.send_data(stream, 1)
  end

  test "numeric SETTINGS update directional state and HPACK capacity" do
    conn = Connection.new()

    assert {:ok, conn, [{:settings, _payload}]} =
             Connection.update_local_settings(conn, [{1, 8192}])

    assert conn.local.values.header_table_size == 8192
    assert conn.decoder.max_dynamic_size == 4096
    {:ok, conn, []} = Connection.acknowledge_settings(conn)
    assert conn.decoder.max_dynamic_size == 8192

    assert {:ok, conn, [{:settings_ack, [{1, 2048}]}]} =
             Connection.update_peer_settings(conn, [{1, 2048}])

    assert conn.peer.values.header_table_size == 2048
    assert conn.encoder.max_dynamic_size == 2048
  end

  test "headers are one atomic batch and cancellation preserves committed HPACK state" do
    {:ok, _stream, conn} = Connection.open_stream(Connection.new())

    assert {:ok, conn, [{:headers, 1, frames}]} =
             Connection.commit_headers(conn, 1, [{":status", "200"}], max_frame_size: 1)

    assert Enum.all?(frames, &(binary_part(&1, 3, 1) in [<<1>>, <<9>>]))
    assert {:ok, _conn, [{:rst_stream, 1, :cancel}]} = Connection.cancel_headers(conn, 1)
  end

  test "trailers close the send half without consuming windows and share the HPACK encoder" do
    peer = %{Settings.new() | values: %{Settings.new().values | max_frame_size: 8}}
    {:ok, _, conn} = Connection.open_stream(Connection.new(peer_settings: peer))
    initial = [{":method", "POST"}, {"x-initial", "shared"}]
    {:ok, conn, [{:headers, 1, frames}]} = Connection.commit_headers(conn, 1, initial)
    {:ok, decoder, ^initial} = HPACK.decode(HPACK.new_decoder(), header_block(frames))
    {:ok, conn, []} = Connection.update_send_window(conn, 1, 1)
    {:ok, stream} = Connection.stream(conn, 1)
    conn = Connection.put_stream(conn, %{stream | send_window: -1})
    conn = %{conn | connection_send_window: 0}
    fields = [{"X-Checksum", "one"}, {"X-Checksum", "two"}]

    assert {:ok, conn, [{:headers, 1, frames}]} = Connection.send_trailers(conn, 1, fields)
    assert length(frames) > 1

    assert Enum.map(frames, &:binary.part(&1, 3, 1)) == [
             <<1>> | List.duplicate(<<9>>, length(frames) - 1)
           ]

    assert :binary.part(hd(frames), 4, 1) == <<1>>
    assert :binary.part(List.last(frames), 4, 1) == <<4>>
    assert Enum.all?(frames, &(byte_size(&1) - 9 <= 8))

    assert {:ok, decoder, [{"x-checksum", "one"}, {"x-checksum", "two"}]} =
             HPACK.decode(decoder, header_block(frames))

    assert {:ok, %{state: :half_closed_local, send_window: -1}} = Connection.stream(conn, 1)
    assert conn.connection_send_window == 0
    assert {:error, :stream_closed} = Connection.send_trailers(conn, 1, fields)
    {:ok, _, conn} = Connection.open_stream(conn)
    {:ok, conn, [{:headers, 3, frames}]} = Connection.commit_headers(conn, 3, initial)
    assert {:ok, decoder, ^initial} = HPACK.decode(decoder, header_block(frames))
    {:ok, _conn, [{:headers, 3, frames}]} = Connection.send_trailers(conn, 3, fields)

    assert {:ok, _decoder, [{"x-checksum", "one"}, {"x-checksum", "two"}]} =
             HPACK.decode(decoder, header_block(frames))
  end

  test "empty trailers end with HEADERS and invalid trailers fail before encoder mutation" do
    conn = Connection.new()
    assert {:error, :unknown_stream} = Connection.send_trailers(conn, 1, [])
    {:ok, _, conn} = Connection.open_stream(conn)
    assert {:error, :headers_not_committed} = Connection.send_trailers(conn, 1, [])
    {:ok, conn, _} = Connection.commit_headers(conn, 1, [{":method", "POST"}])
    assert {:error, :invalid_trailer} = Connection.send_trailers(conn, 1, [{":status", "200"}])

    assert {:error, {:forbidden_trailer, "content-length"}} =
             Connection.send_trailers(conn, 1, [{"content-length", "0"}])

    {:ok, _conn, [{:headers, 1, frames}]} = Connection.send_trailers(conn, 1, [])
    assert [<<0::24, 1, 5, 1::32>>] = frames
  end

  test "trailer peer limit counts RFC header-list overhead before encoding" do
    {:ok, _, conn} = Connection.open_stream(Connection.new())
    {:ok, conn, _} = Connection.commit_headers(conn, 1, [{":method", "POST"}])
    {:ok, conn, _} = Connection.update_peer_settings(conn, [{:max_header_list_size, 33}])
    assert {:error, :trailers_too_large} = Connection.send_trailers(conn, 1, [{"x", "y"}])
    {:ok, conn, _} = Connection.update_peer_settings(conn, [{:max_header_list_size, 34}])
    assert {:ok, _conn, _effects} = Connection.send_trailers(conn, 1, [{"x", "y"}])
  end

  defp header_block(frames),
    do: frames |> Enum.map(&:binary.part(&1, 9, byte_size(&1) - 9)) |> IO.iodata_to_binary()

  test "goaway last stream id only tightens and stops new streams" do
    conn = Connection.new()
    assert {:ok, conn, []} = Connection.goaway(conn, 3)
    assert {:error, :draining} = Connection.open_stream(conn)
    assert {:error, :goaway_last_stream_id_increased} = Connection.goaway(conn, 5)
    assert {:ok, conn, []} = Connection.goaway(conn, 1)
    assert conn.goaway_last_stream_id == 1
  end

  test "connection and stream window increments reject overflow" do
    base = Connection.new()
    conn = %{base | connection_send_window: 2_147_483_647}
    assert {:error, :flow_control_error} = Connection.update_send_window(conn, 0, 1)

    stream_base = StreamState.new(1)
    stream = %{stream_base | send_window: 2_147_483_647}
    assert {:error, :flow_control_error} = StreamState.update_send_window(stream, 1)
  end

  test "DATA effects respect peer max frame size and put END_STREAM on the last frame" do
    peer = %{Settings.new() | values: %{Settings.new().values | max_frame_size: 2}}
    {:ok, _stream, conn} = Connection.open_stream(Connection.new(peer_settings: peer))

    assert {:ok, conn, [{:data, 1, frames}]} = Connection.send_data(conn, 1, "abcde", true)
    assert Enum.map(frames, &(byte_size(&1) - 9)) == [2, 2, 1]
    assert Enum.map(frames, &:binary.part(&1, 4, 1)) == [<<0>>, <<0>>, <<1>>]
    assert {:ok, stream} = Connection.stream(conn, 1)
    assert stream.send_window == 65_530
  end

  test "disabled push is decoded for HPACK synchronization and cancelled" do
    conn = Connection.new()
    block = HPACK.encode_headers([{":method", "GET"}]) |> IO.iodata_to_binary()
    assert {:ok, conn, [{:rst_stream, 2, :cancel}]} = Connection.reject_push(conn, 1, 2, block)
    assert MapSet.member?(conn.promised, 2)
  end

  test "PRIORITY_UPDATE keeps a bounded RFC 9218 field value" do
    {:ok, _, conn} = Connection.open_stream(Connection.new())

    assert {:ok, conn, []} = Connection.priority_update(conn, 0, 1, "u=2, i")
    assert conn.priorities[1] == %{value: "u=2, i", rfc9218: true}
    assert {:error, :invalid_priority_update} = Connection.priority_update(conn, 1, 1, "u=1")
    assert {:error, :invalid_priority_update} = Connection.priority_update(conn, 0, 1, :bad)
    assert {:error, :invalid_priority_update} = Connection.priority_update(conn, 0, 0, "u=1")
    assert {:error, :invalid_priority_update} = Connection.priority_update(conn, 0, 1, "")

    assert {:error, :invalid_priority_update} =
             Connection.priority_update(conn, 0, 1, String.duplicate("x", 257))
  end

  test "Frame registers PRIORITY_UPDATE type 0xF" do
    alias HTTP.HTTP2.Frame
    wire = Frame.encode(:priority_update, 0, 0, <<0::1, 1::31, "u=2"::binary>>)

    assert {:ok, %{type: :priority_update, stream_id: 0, payload: <<0::1, 1::31, "u=2"::binary>>},
            <<>>} =
             Frame.decode(wire)
  end
end

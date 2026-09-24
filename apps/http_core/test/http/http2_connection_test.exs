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

  test "headers are one atomic batch and cancellation preserves committed HPACK state" do
    {:ok, _stream, conn} = Connection.open_stream(Connection.new())

    assert {:ok, conn, [{:headers, 1, frames}]} =
             Connection.commit_headers(conn, 1, [{":status", "200"}], max_frame_size: 1)

    assert Enum.all?(frames, &(binary_part(&1, 3, 1) in [<<1>>, <<9>>]))
    assert {:ok, _conn, [{:rst_stream, 1, :cancel}]} = Connection.cancel_headers(conn, 1)
  end

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

  test "disabled push is decoded for HPACK synchronization and cancelled" do
    conn = Connection.new()
    block = HPACK.encode_headers([{":method", "GET"}]) |> IO.iodata_to_binary()
    assert {:ok, conn, [{:rst_stream, 2, :cancel}]} = Connection.reject_push(conn, 1, 2, block)
    assert MapSet.member?(conn.promised, 2)
  end
end

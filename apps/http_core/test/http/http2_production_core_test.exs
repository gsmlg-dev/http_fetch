defmodule HTTP.HTTP2ProductionCoreTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{Connection, StreamState}

  test "removing a stream clears per-stream state but preserves HPACK" do
    {:ok, _, conn} = Connection.open_stream(Connection.new())
    {:ok, conn, _} = Connection.commit_headers(conn, 1, [{":method", "GET"}])
    {:ok, conn, []} = Connection.handle_priority(conn, 1, 0, 16)
    conn = %{conn | pending_headers: %{1 => :pending}}
    encoder = conn.encoder
    decoder = conn.decoder

    conn = Connection.remove_stream(conn, 1)
    assert conn.streams == %{}
    refute MapSet.member?(conn.committed, 1)
    refute Map.has_key?(conn.pending_headers, 1)
    refute Map.has_key?(conn.priorities, 1)
    assert conn.encoder == encoder
    assert conn.decoder == decoder
  end

  test "zero-byte END_STREAM works when both send windows are exhausted" do
    {:ok, _, conn} = Connection.open_stream(Connection.new(send_window: 0))
    {:ok, stream} = Connection.stream(conn, 1)
    conn = Connection.put_stream(conn, %{stream | send_window: -1})
    {:ok, conn, [{:data, 1, [frame]}]} = Connection.send_data(conn, 1, "", true)
    assert <<0::24, 0, 1, 1::32>> = frame
    assert {:ok, stream} = Connection.stream(conn, 1)
    assert stream.end_stream_sent?
  end

  test "bounded prefix consumes only eligible send credit" do
    {:ok, _, conn} = Connection.open_stream(Connection.new(send_window: 5))

    assert {:ok, conn, 3, "defgh", [{:data, 1, [frame]}]} =
             Connection.send_data_prefix(conn, 1, "abcdefgh", false, 3)

    assert <<3::24, 0, 0, 1::32, "abc">> = frame
    assert conn.connection_send_window == 2
    assert {:ok, stream} = Connection.stream(conn, 1)
    assert stream.send_window == 65_532
  end

  test "receive DATA debits windows until acknowledged" do
    {:ok, _, conn} = Connection.open_stream(Connection.new(receive_window: 5))
    assert {:ok, conn, []} = Connection.receive_data(conn, 1, 4)
    assert conn.connection_receive_window == 1
    assert {:ok, stream} = Connection.stream(conn, 1)
    assert stream.receive_window == 65_531
    assert {:error, :flow_control_error} = Connection.receive_data(conn, 1, 2)
    assert {:error, :invalid_acknowledgement} = Connection.acknowledge_data(conn, 1, 5)

    assert {:ok, conn, [{:window_update, 0, 4}, {:window_update, 1, 4}]} =
             Connection.acknowledge_data(conn, 1, 4)

    assert conn.connection_receive_window == 5
    assert {:ok, stream} = Connection.stream(conn, 1)
    assert stream.receive_window == 65_535
  end

  test "request headers and response informational, final, trailer phases are distinct" do
    {:ok, stream} = StreamState.new(1) |> StreamState.open()
    {:ok, stream} = StreamState.send_headers(stream, true)
    assert stream.request_headers_sent?
    assert stream.response_phase == :awaiting_final

    assert {:ok, stream, :informational} =
             StreamState.receive_response_headers(stream, [{":status", "100"}], false)

    assert stream.response_phase == :awaiting_final

    assert {:ok, stream, :final} =
             StreamState.receive_response_headers(stream, [{":status", "200"}], false)

    assert stream.response_phase == :body

    assert {:ok, stream, :trailers} =
             StreamState.receive_response_headers(stream, [{"x-done", "yes"}], true)

    assert stream.response_phase == :complete
    assert stream.state == :closed
  end

  test "response validation rejects malformed status and invalid phase transitions" do
    {:ok, stream} = StreamState.new(1) |> StreamState.open()

    assert {:error, :invalid_response_headers} =
             StreamState.receive_response_headers(stream, [{":status", "wat"}], false)

    assert {:error, :invalid_response_headers} =
             StreamState.receive_response_headers(
               stream,
               [{":status", "200"}, {":status", "201"}],
               false
             )

    assert {:error, :invalid_response_headers} =
             StreamState.receive_response_headers(stream, [{":status", "100"}], true)

    assert {:error, :invalid_response_headers} =
             StreamState.receive_response_headers(
               stream,
               [{"x-a", "1"}, {":status", "200"}],
               false
             )

    assert {:error, :invalid_response_headers} =
             StreamState.receive_response_headers(
               stream,
               [{":status", "200"}, {"connection", "close"}],
               false
             )

    assert {:ok, stream, :final} =
             StreamState.receive_response_headers(stream, [{":status", "204"}], true)

    assert stream.response_phase == :complete

    assert {:error, :invalid_headers_transition} =
             StreamState.receive_response_headers(stream, [{"x-late", "yes"}], true)
  end

  test "response body bytes validate content length independently of wire credit" do
    {:ok, stream} = StreamState.new(1) |> StreamState.open()

    assert {:ok, stream, :final} =
             StreamState.receive_response_headers(
               stream,
               [{":status", "200"}, {"content-length", "3"}],
               false
             )

    assert {:ok, stream} = StreamState.receive_response_data(stream, 2, false)
    assert {:error, :content_length_mismatch} = StreamState.receive_response_data(stream, 0, true)

    assert {:error, :content_length_mismatch} =
             StreamState.receive_response_data(stream, 2, false)

    assert {:ok, stream} = StreamState.receive_response_data(stream, 1, true)
    assert stream.response_phase == :complete
  end

  test "local header table limit applies to decoder only after SETTINGS acknowledgement" do
    conn = Connection.new()

    assert {:ok, conn, [{:settings, _}]} =
             Connection.update_local_settings(conn, [{:header_table_size, 1024}])

    assert conn.decoder.max_dynamic_size == 4096
    assert {:ok, conn, []} = Connection.acknowledge_settings(conn)
    assert conn.decoder.max_dynamic_size == 1024
  end

  test "server cannot explicitly enable push in peer SETTINGS" do
    conn = Connection.new()

    for entries <- [[{2, 1}], [{:enable_push, 1}]] do
      assert {:error, :protocol_error} = Connection.update_peer_settings(conn, entries)
    end

    assert {:ok, _, [{:settings_ack, [{2, 0}]}]} =
             Connection.update_peer_settings(conn, [{2, 0}])

    assert {:ok, _, [{:settings_ack, []}]} = Connection.update_peer_settings(conn, [])

    assert {:ok, _, [{:settings, _}]} =
             Connection.update_local_settings(conn, [{:enable_push, 1}])
  end

  test "multiple local SETTINGS acknowledgements apply decoder limits in order" do
    conn = Connection.new()
    {:ok, conn, _} = Connection.update_local_settings(conn, [{:header_table_size, 1024}])
    {:ok, conn, _} = Connection.update_local_settings(conn, [{:header_table_size, 2048}])
    assert conn.decoder.max_dynamic_size == 4096
    assert {:ok, conn, []} = Connection.acknowledge_settings(conn)
    assert conn.decoder.max_dynamic_size == 1024
    assert {:ok, conn, []} = Connection.acknowledge_settings(conn)
    assert conn.decoder.max_dynamic_size == 2048
    assert {:error, :unexpected_settings_ack} = Connection.acknowledge_settings(conn)
  end

  test "requested header frame size is clamped to the peer limit" do
    {:ok, _, conn} = Connection.open_stream(Connection.new())
    value = for i <- 0..19_999, into: <<>>, do: <<rem(i * 73, 256)>>
    headers = [{"x-large", value}]

    assert {:ok, _, [{:headers, 1, frames}]} =
             Connection.commit_headers(conn, 1, headers, max_frame_size: 32_768)

    assert length(frames) > 1
    assert Enum.all?(frames, fn frame -> byte_size(frame) - 9 <= 16_384 end)

    assert {:error, :invalid_frame_size} =
             Connection.commit_headers(conn, 1, headers, max_frame_size: 0)
  end

  test "PRIORITY_UPDATE for idle or removed streams never retains historical state" do
    conn = Connection.new()

    conn =
      Enum.reduce(1..1_000, conn, fn id, acc ->
        assert {:ok, next, []} = Connection.priority_update(acc, 0, id * 2, "u=1")
        next
      end)

    assert conn.priorities == %{}
    {:ok, stream, conn} = Connection.open_stream(conn)
    assert {:ok, conn, []} = Connection.priority_update(conn, 0, stream.id, "u=2")
    assert Map.has_key?(conn.priorities, stream.id)
    conn = Connection.remove_stream(conn, stream.id)
    assert {:ok, conn, []} = Connection.priority_update(conn, 0, stream.id, "u=3")
    assert conn.priorities == %{}
  end

  test "local SETTINGS queue has a finite pending ACK bound" do
    conn = Connection.new()

    conn =
      Enum.reduce(1..8, conn, fn _, acc ->
        assert {:ok, next, [{:settings, _}]} = Connection.update_local_settings(acc, [])
        next
      end)

    assert length(conn.local.pending) == 8
    assert {:error, :settings_queue_full} = Connection.update_local_settings(conn, [])
    assert {:ok, conn, []} = Connection.acknowledge_settings(conn)
    assert {:ok, conn, [{:settings, _}]} = Connection.update_local_settings(conn, [])
    assert length(conn.local.pending) == 8
  end
end

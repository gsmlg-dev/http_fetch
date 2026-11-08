defmodule Quic.ReliableResetTest do
  use ExUnit.Case, async: true
  alias Quic.{Codec, Streams, TransportParameters}

  test "draft-11 frame and empty transport parameter round trip" do
    frame = %{
      type: :reset_stream_at,
      stream_id: 4,
      error_code: 42,
      final_size: 100,
      reliable_size: 7
    }

    assert {:ok, <<0x24, _::binary>> = wire} = Codec.encode_frames([frame])
    assert {:ok, [^frame], <<>>} = Codec.decode_frames(wire)
    assert {:ok, raw} = TransportParameters.encode([%{id: 0x1D, value: <<>>}])
    assert {:ok, %{values: %{reset_stream_at: true}}} = TransportParameters.decode(raw)
    assert {:error, _} = TransportParameters.decode(<<0x1D, 1, 0>>)

    assert {:wrong_encryption_level, :reset_stream_at, :handshake} =
             Codec.validate_frame_levels([frame], :handshake)

    assert {:error, :malformed_reset_stream_at} = Codec.decode_frames(<<0x24, 1>>)
  end

  defp frame(offset, bytes, fin \\ false),
    do: %{type: :stream, stream_id: 0, offset: offset, data: bytes, fin: fin}

  test "reset before prefix waits for reordered ranges and emits data before reset once" do
    state = Streams.new(:server, delivery: :manual)
    assert {:ok, state, []} = Streams.receive_reset_at(state, 0, 42, 10, 5)
    assert state.data_received == 10
    assert {:ok, state, []} = Streams.receive(state, frame(3, "defghij"))
    assert {:ok, state, []} = Streams.consume(state, 0, 20)
    assert {:ok, state, []} = Streams.receive(state, frame(0, "abc"))

    assert {:ok, state, [{:data, 0, "abc"}, {:data, 0, "de"}, {:reset, 0, 42, 10}]} =
             Streams.consume(state, 0, 20)

    assert state.streams[0].recv_buffered == 0
    assert state.data_consumed == 10
    assert {:ok, state, []} = Streams.receive_reset_at(state, 0, 42, 10, 5)
    assert {:ok, _, []} = Streams.consume(state, 0, 20)
  end

  test "reliable size decreases, reordered increases are ignored, code/final size cannot change" do
    {:ok, state, []} = Streams.receive_reset_at(Streams.new(:server), 0, 42, 20, 10)
    {:ok, state, []} = Streams.receive_reset_at(state, 0, 42, 20, 5)
    {:ok, state, []} = Streams.receive_reset_at(state, 0, 42, 20, 8)
    assert state.streams[0].recv_reliable == 5
    assert {:error, :stream_state_error} = Streams.receive_reset_at(state, 0, 43, 20, 5)
    assert {:error, :final_size_error} = Streams.receive_reset_at(state, 0, 42, 21, 5)
    assert {:error, :frame_encoding_error} = Streams.receive_reset_at(state, 0, 42, 20, 21)
    assert {:ok, state, [{:reset, 0, 42, 20}]} = Streams.receive_reset(state, 0, 42, 20)
    assert {:ok, _, []} = Streams.receive(state, frame(0, "abc"))
  end

  test "final size charges stream/connection flow control and sparse range/item limits remain enforced" do
    assert {:error, :flow_control} =
             Streams.receive_reset_at(Streams.new(:server, max_data: 10), 0, 42, 11, 5)

    {:ok, state, []} =
      Streams.receive_reset_at(Streams.new(:server, max_recv_ranges: 1), 0, 42, 10, 9)

    {:ok, state, []} = Streams.receive(state, frame(2, "a"))
    assert {:error, :range_limit} = Streams.receive(state, frame(5, "b"))
    assert {:error, :final_size_error} = Streams.receive(state, frame(10, "b"))
  end

  test "local reset retains admitted final size and allows only decreasing reliable size" do
    state = Streams.new(:client)
    {:ok, state, id} = Streams.open(state, :bidi)
    {:ok, state, _} = Streams.send(state, id, "header-and-tail", false)

    assert {:ok, state, %{type: :reset_stream_at, final_size: 15, reliable_size: 6}} =
             Streams.reset_send_at(state, id, 42, 6)

    assert {:error, :stopped} = Streams.send(state, id, "more", false)
    assert {:error, :reliable_size_increase} = Streams.reset_send_at(state, id, 42, 7)
    assert {:ok, _, %{reliable_size: 3}} = Streams.reset_send_at(state, id, 42, 3)
  end

  describe "peer STOP_SENDING on a stream with a declared reliable prefix" do
    defp prefixed(prefix, bytes) do
      {:ok, state, id} = Streams.open(Streams.new(:client), :bidi)
      {:ok, state} = Streams.set_reliable_prefix(state, id, prefix)
      {:ok, state, _} = Streams.send(state, id, bytes, false)
      {state, id}
    end

    test "negotiated reliable reset answers RESET_STREAM_AT with the echoed code" do
      {state, id} = prefixed(6, "header-tail")

      assert {:ok, state,
              %{
                type: :reset_stream_at,
                stream_id: ^id,
                error_code: 9,
                final_size: 11,
                reliable_size: 6
              }} = Streams.peer_stop_sending(state, id, 9, true)

      assert %{send_reset: 9, send_reliable: 6} = state.streams[id]
      assert {:error, :stopped} = Streams.send(state, id, "more", false)
      # A repeated STOP_SENDING is idempotent and never downgrades the reset.
      assert {:ok, ^state, nil} = Streams.peer_stop_sending(state, id, 9, true)
      # A different code after a reset is ignored (RFC 9000 Section 3.5).
      assert {:ok, ^state, nil} = Streams.peer_stop_sending(state, id, 10, true)
      assert {:ok, ^state, nil} = Streams.peer_stop_sending(state, id, 10, false)
    end

    test "STOP_SENDING after a local RESET_STREAM with another code is ignored" do
      {state, id} = prefixed(0, "header-tail")

      assert {:ok, state, %{type: :reset_stream, error_code: 3}} =
               Streams.reset_send(state, id, 3)

      assert {:ok, ^state, nil} = Streams.peer_stop_sending(state, id, 9)
      assert {:ok, ^state, nil} = Streams.peer_stop_sending(state, id, 9, true)
      assert %{send_reset: 3} = state.streams[id]
    end

    test "without negotiation or without a prefix the answer stays RESET_STREAM" do
      {state, id} = prefixed(6, "header-tail")

      assert {:ok, _, %{type: :reset_stream, final_size: 11}} =
               Streams.peer_stop_sending(state, id, 9)

      assert {:ok, _, %{type: :reset_stream, final_size: 11}} =
               Streams.peer_stop_sending(state, id, 9, false)

      {state, id} = prefixed(0, "header-tail")

      assert {:ok, _, %{type: :reset_stream, final_size: 11}} =
               Streams.peer_stop_sending(state, id, 9, true)
    end

    test "a prefix beyond the admitted offset retains only the admitted bytes" do
      {state, id} = prefixed(6, "head")

      assert {:ok, _, %{type: :reset_stream_at, final_size: 4, reliable_size: 4}} =
               Streams.peer_stop_sending(state, id, 9, true)

      {state, id} = prefixed(6, "")

      assert {:ok, _, %{type: :reset_stream, final_size: 0}} =
               Streams.peer_stop_sending(state, id, 9, true)
    end

    test "an earlier application reliable reset is kept or reduced, never enlarged" do
      {state, id} = prefixed(6, "header-tail")
      {:ok, state, _} = Streams.reset_send_at(state, id, 9, 8)

      assert {:ok, state, %{type: :reset_stream_at, reliable_size: 6}} =
               Streams.peer_stop_sending(state, id, 9, true)

      {:ok, state, _} = Streams.reset_send_at(state, id, 9, 3)
      assert {:ok, ^state, nil} = Streams.peer_stop_sending(state, id, 9, true)
    end

    test "prefix declaration is validated and limited to sendable streams" do
      state = Streams.new(:client)
      {:ok, state, id} = Streams.open(state, :bidi)
      assert {:error, :unknown_stream} = Streams.set_reliable_prefix(state, 400, 4)
      assert {:error, :invalid_reliable_prefix} = Streams.set_reliable_prefix(state, id, -1)

      {:ok, state, _} =
        Streams.receive(Streams.new(:server), %{
          type: :stream,
          stream_id: 2,
          offset: 0,
          data: "x",
          fin: false
        })

      assert {:error, :send_on_receive_only_stream} = Streams.set_reliable_prefix(state, 2, 4)
    end
  end
end

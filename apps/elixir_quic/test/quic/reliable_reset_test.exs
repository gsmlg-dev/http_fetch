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
end

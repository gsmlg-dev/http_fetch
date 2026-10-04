defmodule Quic.Phase1ParametersTest do
  use ExUnit.Case, async: true
  alias Quic.{HandshakeScheduler, Recovery, Streams}

  test "authenticated parameters install defaults, zero credit and distinct peer windows" do
    state = %HandshakeScheduler{streams: Streams.new(:client), recovery: Recovery.new()}
    next = HandshakeScheduler.install_peer_parameters(state, %{})
    assert next.streams.peer_max_data == 0
    assert next.streams.peer_max_streams_bidi == 0
    assert next.streams.peer_max_streams_uni == 0
    assert next.max_packet_size == 1350
    assert next.recovery.rtt.max_ack_delay == 25_000
    assert next.recovery.rtt.ack_delay_exponent == 3

    next =
      HandshakeScheduler.install_peer_parameters(state, %{
        initial_max_data: 123,
        initial_max_streams_bidi: 2,
        initial_max_streams_uni: 3,
        initial_max_stream_data_bidi_local: 11,
        initial_max_stream_data_bidi_remote: 22,
        initial_max_stream_data_uni: 33,
        max_udp_payload_size: 1200,
        max_ack_delay: 7,
        ack_delay_exponent: 0,
        max_idle_timeout: 456
      })

    assert next.streams.peer_max_data == 123
    assert next.max_packet_size == 1200
    assert next.recovery.rtt.max_ack_delay == 7000
    assert next.recovery.rtt.ack_delay_exponent == 0
    assert next.peer_idle_timeout == 456
    {:ok, streams, 0} = Streams.open(next.streams, :bidi)
    {:ok, streams, 2} = Streams.open(streams, :uni)

    {:ok, streams, _} =
      Streams.receive(streams, %{type: :stream, stream_id: 1, offset: 0, data: "", fin: false})

    assert streams.streams[0].send_limit == 22
    assert streams.streams[1].send_limit == 11
    assert streams.streams[2].send_limit == 33
  end

  test "consumption queues coalesced credit through the recoverable control path" do
    streams = Streams.new(:client, delivery: :manual, max_data: 4, max_stream_data: 4)

    {:ok, streams, _} =
      Streams.receive(streams, %{type: :stream, stream_id: 1, offset: 0, data: "abcd", fin: false})

    state = %HandshakeScheduler{streams: streams, recovery: Recovery.new()}
    {:ok, state, [{:data, 1, "ab"}]} = HandshakeScheduler.consume_stream(state, 1, 2)
    {:ok, state, [{:data, 1, "cd"}]} = HandshakeScheduler.consume_stream(state, 1, 2)
    frames = state.pending_control.application
    assert Enum.count(frames, &(&1.type == :max_data)) == 1
    assert %{type: :max_data, value: 8} in frames
    assert %{type: :max_stream_data, stream_id: 1, value: 8} in frames
  end
end

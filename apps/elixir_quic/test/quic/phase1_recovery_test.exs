defmodule Quic.Phase1RecoveryTest do
  use ExUnit.Case, async: true

  alias Quic.Recovery

  defp sent(state, space, at) do
    {:ok, state, packet} = Recovery.reserve(state, space, %{kind: :stream}, 100)
    {:ok, state} = Recovery.transition(state, space, packet.number, :queued)
    {:ok, state, [:sent]} = Recovery.local_send(state, space, packet.number, :ok, at)
    {state, packet.number}
  end

  defp sent_with_metadata(state, space, metadata, at) do
    {:ok, state, packet} = Recovery.reserve(state, space, metadata, 100)
    {:ok, state} = Recovery.transition(state, space, packet.number, :queued)
    {:ok, state, [:sent]} = Recovery.local_send(state, space, packet.number, :ok, at)
    {state, packet.number}
  end

  test "application ACK delay uses the negotiated exponent" do
    state = Recovery.new(ack_delay_exponent: 3, max_ack_delay: 1_000)
    {state, first} = sent(state, :application, 0)

    assert {:ok, state, %{rtt_sample: 1_000}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: first, ranges: [{first, first}], delay: 0},
               1_000
             )

    {state, second} = sent(state, :application, 2_000)

    assert {:ok, state, %{rtt_sample: 1_200}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: second, ranges: [{second, second}], delay: 5},
               3_200
             )

    assert state.rtt.latest == 1_200
    assert state.rtt.smoothed == 1_020
  end

  test "Initial and Handshake ACK delays do not reduce the RTT sample" do
    for space <- [:initial, :handshake] do
      state = Recovery.new(ack_delay_exponent: 3, max_ack_delay: 1_000)
      {state, number} = sent(state, space, 0)

      assert {:ok, state, %{rtt_sample: 1_000}} =
               Recovery.receive_ack(
                 state,
                 space,
                 %{largest: number, ranges: [{number, number}], delay: 5},
                 1_000
               )

      assert state.rtt.latest == 1_000
    end
  end

  test "duplicate ACKs do not grow a congestion-avoidance window" do
    state = Recovery.new(mss: 100, initial_cwnd: 200, ssthresh: 100)
    {state, number} = sent(state, :application, 0)

    assert {:ok, state, %{acked: [^number]}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: number, ranges: [{number, number}]},
               10
             )

    cwnd = state.congestion.cwnd

    assert {:ok, state, %{acked: []}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: number, ranges: [{number, number}]},
               20
             )

    assert state.congestion.cwnd == cwnd
  end

  test "late ACK of a lost packet records acknowledgement without releasing flight twice" do
    state = Recovery.new(mss: 100, initial_cwnd: 1_000)
    {state, lost} = sent_with_metadata(state, :application, %{logical: {:stream, 0, 0, 100}}, 0)
    {state, _} = sent(state, :application, 1)
    {state, _} = sent(state, :application, 2)
    {state, largest} = sent(state, :application, 3)

    assert {:ok, state, %{lost: lost_packets}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: largest, ranges: [{largest, largest}]},
               10
             )

    assert {:application, lost} in lost_packets
    assert state.spaces.application.sent[lost].status == :lost
    in_flight = state.congestion.bytes_in_flight

    assert {:ok, state, %{acked: [^lost]}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: lost, ranges: [{lost, lost}]},
               20
             )

    assert state.spaces.application.sent[lost].status == :acked
    assert state.spaces.application.sent[lost].metadata.logical == {:stream, 0, 0, 100}
    assert state.congestion.bytes_in_flight == in_flight
  end

  test "repeated local-send receipts are idempotent" do
    state = Recovery.new()
    {state, number} = sent(state, :application, 0)

    assert {:ok, next, []} = Recovery.local_send(state, :application, number, :ok, 10)
    assert next == state
  end
end

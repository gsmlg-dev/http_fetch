defmodule Quic.RecoveryCongestionPeriodTest do
  use ExUnit.Case, async: true

  alias Quic.Congestion.NewReno
  alias Quic.Recovery

  defp send_packet(state, metadata, bytes, at) do
    {:ok, state, packet} = Recovery.reserve(state, :application, metadata, bytes)
    {:ok, state} = Recovery.transition(state, :application, packet.number, :queued)
    {:ok, state, _} = Recovery.local_send(state, :application, packet.number, :ok, at)
    {state, packet.number}
  end

  defp ack(state, number, at), do: ack(state, number, number, at)

  defp ack(state, first, last, at) do
    {:ok, state, result} =
      Recovery.receive_ack(
        state,
        :application,
        %{largest: last, ranges: [{first, last}], delay: 0},
        at
      )

    {state, result}
  end

  # RFC 9002 section 7.3.2: one reduction per congestion event.
  test "losses of packets sent before recovery began reduce the window only once" do
    state = Recovery.new(mss: 100, initial_cwnd: 100_000, ssthresh: :infinity)

    {state, numbers} =
      Enum.reduce(0..19, {state, []}, fn n, {state, acc} ->
        {state, number} = send_packet(state, %{kind: :stream}, 100, n)
        {state, [number | acc]}
      end)

    [last | _] = numbers
    {state, %{lost: first_lost}} = ack(state, 10, 100)
    assert first_lost != []
    reduced = state.congestion.cwnd
    assert reduced < 100_000
    assert state.congestion.recovery_start == 100

    # A second ACK reveals more losses, but they were sent before recovery started.
    {state, %{lost: more_lost}} = ack(state, 15, 101)
    assert more_lost != []
    assert state.congestion.cwnd == reduced

    # Acknowledged packets sent before recovery do not grow the window either.
    {state, _} = ack(state, last, 102)
    assert state.congestion.cwnd == reduced

    # A packet sent after recovery started and then lost is a new congestion event.
    {state, late} = send_packet(state, %{kind: :stream}, 100, 200)
    {state, later} = send_packet(state, %{kind: :stream}, 100, 201)

    {state, _} =
      Enum.reduce(1..4, {state, later}, fn n, {state, _} ->
        send_packet(state, %{kind: :stream}, 100, 201 + n)
      end)

    {state, %{lost: lost}} = ack(state, late + 5, 300)
    assert {:application, late} in lost
    assert state.congestion.cwnd < reduced
  end

  test "NewReno ignores acknowledgements and losses from before the recovery start" do
    state = NewReno.new(mss: 100, initial_cwnd: 1_000)
    {:ok, state} = NewReno.reserve(state, 600)
    state = NewReno.on_packets_lost(state, 100, 5, 10)
    assert state.cwnd == 500
    assert state.recovery_start == 10

    state = NewReno.on_packets_lost(state, 100, 7, 11)
    assert state.cwnd == 500
    assert state.bytes_in_flight == 400

    state = NewReno.on_packets_acked(state, [{100, 8}])
    assert state.cwnd == 500
    assert state.bytes_in_flight == 300

    state = NewReno.on_packets_acked(state, [{100, 12}])
    assert state.cwnd > 500
  end

  # Lost ACK-only packets have nothing to retransmit, so they must not fill the
  # bounded sent history and stop all sending.
  test "lost ACK-only packets do not exhaust the sent history" do
    state = Recovery.new(max_sent_packets: 8, initial_cwnd: 1_000_000)

    state =
      Enum.reduce(0..40, state, fn _, state ->
        {state, _ack_only} = send_packet(state, %{ack_eliciting: false}, 0, 0)

        {state, [first | _] = numbers} =
          Enum.reduce(1..4, {state, []}, fn _, {state, acc} ->
            {state, number} = send_packet(state, %{kind: :stream}, 100, 0)
            {state, [number | acc]}
          end)

        # Acknowledging four later packets declares the ACK-only packet lost.
        {state, %{lost: [_ | _]}} = ack(state, List.last(numbers), first, 1)
        state
      end)

    assert map_size(state.spaces.application.sent) <= 8
    assert {:ok, _state, _packet} = Recovery.reserve(state, :application, %{kind: :stream}, 100)
  end
end

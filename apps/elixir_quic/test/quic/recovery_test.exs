defmodule Quic.RecoveryTest do
  use ExUnit.Case, async: true

  alias Quic.Recovery

  defp sent(state, space, bytes, at) do
    {:ok, state, packet} = Recovery.reserve(state, space, %{kind: :crypto}, bytes)
    {:ok, state} = Recovery.transition(state, space, packet.number, :queued)
    {:ok, state, _} = Recovery.local_send(state, space, packet.number, :ok, at)
    {state, packet.number}
  end

  test "peer ACK never changes inbound packet number reconstruction or ACK ranges" do
    state = Recovery.new()
    {:ok, state} = Recovery.note_received(state, :initial, 7)
    {state, number} = sent(state, :initial, 10, 0)

    {:ok, state, %{acked: [^number]}} =
      Recovery.receive_ack(state, :initial, %{largest: number, ranges: [{number, number}]}, 10)

    assert state.spaces.initial.largest_received == 7
    assert state.spaces.initial.ack_ranges == [{7, 7}]

    {state, number} = sent(state, :handshake, 10, 0)

    {:ok, state, _} =
      Recovery.receive_ack(state, :handshake, %{largest: number, ranges: [{number, number}]}, 10)

    assert state.spaces.handshake.largest_received == -1
    assert state.spaces.handshake.ack_ranges == []
  end

  test "out of order receive numbers merge ranges and obey a bounded range count" do
    state = Recovery.new(max_ack_ranges: 2)
    {:ok, state} = Recovery.note_received(state, :initial, 4)
    {:ok, state} = Recovery.note_received(state, :initial, 2)
    assert state.spaces.initial.ack_ranges == [{2, 2}, {4, 4}]
    assert {:error, :ack_range_limit} = Recovery.note_received(state, :initial, 0)
    {:ok, state} = Recovery.note_received(state, :initial, 3)
    assert state.spaces.initial.ack_ranges == [{2, 4}]
    {:ok, state} = Recovery.note_received(state, :initial, 2)
    assert state.spaces.initial.ack_ranges == [{2, 4}]
    assert state.spaces.initial.largest_received == 4
    {:ok, state} = Recovery.note_received(state, :initial, 0)
    assert state.spaces.initial.ack_ranges == [{0, 0}, {2, 4}]
  end

  test "rejects an ACK whose largest field is below another acknowledged number" do
    {state, _} = sent(Recovery.new(), :initial, 10, 0)
    {state, _} = sent(state, :initial, 10, 1)

    assert {:error, :invalid_ack_ranges} =
             Recovery.receive_ack(state, :initial, %{largest: 0, ranges: [{0, 1}]}, 10)
  end

  test "packet number spaces are independent and numbers are never reused" do
    state = Recovery.new()
    {:ok, state, initial} = Recovery.reserve(state, :initial, %{}, 10)
    {:ok, state, handshake} = Recovery.reserve(state, :handshake, %{}, 10)
    assert initial.number == 0
    assert handshake.number == 0
    {:ok, state, _} = Recovery.local_send(state, :initial, initial.number, {:error, :closed}, 10)
    {:ok, _state, next} = Recovery.reserve(state, :initial, %{}, 10)
    assert next.number == 1
  end

  test "ACK waits for a delayed local send receipt" do
    state = Recovery.new()
    {:ok, state, packet} = Recovery.reserve(state, :application, %{}, 20)
    {:ok, state} = Recovery.transition(state, :application, packet.number, :queued)

    {:ok, state, result} =
      Recovery.receive_ack(state, :application, %{largest: 0, ranges: [{0, 0}]}, 100)

    assert result.acked == []
    assert MapSet.member?(state.spaces.application.pending_acks, 0)
    {:ok, state, [:acked]} = Recovery.local_send(state, :application, 0, :ok, 110)
    assert state.spaces.application.sent[0].status == :acked
  end

  test "duplicate and never-issued ACKs are handled explicitly" do
    {state, number} = sent(Recovery.new(), :initial, 10, 10)

    {:ok, state, %{acked: [0]}} =
      Recovery.receive_ack(state, :initial, %{largest: number, ranges: [{0, 0}]}, 30)

    {:ok, _state, %{acked: []}} =
      Recovery.receive_ack(state, :initial, %{largest: number, ranges: [{0, 0}]}, 31)

    assert {:error, :ack_never_issued} =
             Recovery.receive_ack(state, :initial, %{largest: 4, ranges: [{4, 4}]}, 32)
  end

  test "PTO probes without declaring unacknowledged flights lost" do
    {state, _} = sent(Recovery.new(), :handshake, 100, 0)
    assert state.deadline == 999_000
    {:ok, early, %{lost: [], probes: []}} = Recovery.on_time(state, 500_000)
    assert early.deadline == state.deadline

    {:ok, next, %{lost: [], probes: [{:handshake, 0}], generation: generation}} =
      Recovery.on_time(early, 999_000)

    assert next.spaces.handshake.sent[0].status == :sent
    assert next.congestion == state.congestion
    assert next.deadline == 1_998_000
    refute Recovery.timer_expired?(next, early.timer_generation, 2_000_000)
    assert Recovery.timer_expired?(next, generation, 2_000_000)
  end

  test "time threshold loss requires a higher acknowledged packet in the same space" do
    {state, _} = sent(Recovery.new(), :handshake, 100, 0)
    {state, _} = sent(state, :handshake, 100, 1)
    {state, _} = sent(state, :initial, 100, 0)

    {:ok, state, _} =
      Recovery.receive_ack(state, :handshake, %{largest: 1, ranges: [{1, 1}]}, 100_000)

    {:ok, state, %{lost: [{:handshake, 0}], probes: []}} = Recovery.on_time(state, 150_000)
    assert state.spaces.initial.sent[0].status == :sent
    assert state.spaces.handshake.sent[0].status == :lost
  end

  test "ACK-only sends do not arm PTO and acknowledging all data cancels its timer" do
    state = Recovery.new()
    {:ok, state, packet} = Recovery.reserve(state, :initial, %{ack_eliciting: false}, 0)
    {:ok, state, _} = Recovery.local_send(state, :initial, packet.number, :ok, 0)
    assert state.deadline == nil
    {state, number} = sent(state, :handshake, 100, 10)
    assert is_integer(state.deadline)

    {:ok, state, _} =
      Recovery.receive_ack(state, :handshake, %{largest: number, ranges: [{number, number}]}, 100)

    assert state.deadline == nil
  end

  test "packet threshold loss is independent from other spaces" do
    state = Recovery.new()
    {state, _} = sent(state, :initial, 100, 0)
    {state, _} = sent(state, :initial, 100, 1)
    {state, _} = sent(state, :initial, 100, 2)
    {state, _} = sent(state, :initial, 100, 3)
    {state, _} = sent(state, :initial, 100, 4)

    {:ok, state, %{lost: lost}} =
      Recovery.receive_ack(state, :initial, %{largest: 4, ranges: [{4, 4}]}, 5)

    assert {:initial, 0} in lost
    assert state.spaces.initial.sent[0].status == :lost
    assert state.spaces.handshake.sent == %{}
  end

  test "recovery reserves congestion credit and releases failed sends" do
    state = Recovery.new(mss: 100, initial_cwnd: 200)
    assert {:ok, state, _first} = Recovery.reserve(state, :initial, %{}, 200)
    assert {:error, :congestion_limited} = Recovery.reserve(state, :initial, %{}, 1)
    {:ok, state, [:failed]} = Recovery.local_send(state, :initial, 0, {:error, :writer_down}, 10)
    assert state.congestion.bytes_in_flight == 0
    assert {:ok, _state, second} = Recovery.reserve(state, :initial, %{}, 200)
    assert second.number == 1
  end

  test "pending ACK consumes congestion credit once receipt arrives" do
    state = Recovery.new(mss: 100, initial_cwnd: 200)
    {:ok, state, _packet} = Recovery.reserve(state, :application, %{}, 200)

    {:ok, state, _} =
      Recovery.receive_ack(state, :application, %{largest: 0, ranges: [{0, 0}]}, 20)

    assert state.congestion.bytes_in_flight == 200
    {:ok, state, [:acked]} = Recovery.local_send(state, :application, 0, :ok, 25)
    assert state.congestion.bytes_in_flight == 0

    {:ok, state, %{acked: []}} =
      Recovery.receive_ack(state, :application, %{largest: 0, ranges: [{0, 0}]}, 30)

    assert state.congestion.bytes_in_flight == 0
  end

  test "packet threshold includes largest acknowledged minus three" do
    state = Recovery.new()
    {state, _} = sent(state, :initial, 10, 0)
    {state, _} = sent(state, :initial, 10, 1)
    {state, _} = sent(state, :initial, 10, 2)
    {state, _} = sent(state, :initial, 10, 3)

    {:ok, state, %{lost: lost}} =
      Recovery.receive_ack(state, :initial, %{largest: 3, ranges: [{3, 3}]}, 5)

    assert {:initial, 0} in lost
    assert state.spaces.initial.sent[0].status == :lost
  end

  test "reclaims acknowledged history at the explicit bound without reusing numbers" do
    state = Recovery.new(max_sent_packets: 2)
    {state, first} = sent(state, :application, 10, 0)

    {:ok, state, _} =
      Recovery.receive_ack(state, :application, %{largest: first, ranges: [{first, first}]}, 10)

    {state, second} = sent(state, :application, 10, 20)

    {:ok, state, _} =
      Recovery.receive_ack(
        state,
        :application,
        %{largest: second, ranges: [{second, second}]},
        30
      )

    assert {:ok, state, third} = Recovery.reserve(state, :application, %{}, 10)
    assert third.number == 2
    assert map_size(state.spaces.application.sent) <= 2
    refute Map.has_key?(state.spaces.application.sent, first)
  end

  test "valid cumulative ACKs survive the default history boundary" do
    state =
      Enum.reduce(0..4097, Recovery.new(), fn n, state ->
        {state, ^n} = sent(state, :application, 10, n * 1000)

        {:ok, state, %{acked: [^n]}} =
          Recovery.receive_ack(
            state,
            :application,
            %{largest: n, ranges: [{n, n}], delay: 0},
            n * 1000 + 1
          )

        state
      end)

    refute Map.has_key?(state.spaces.application.sent, 0)
    assert map_size(state.spaces.application.sent) <= state.max_sent_packets

    assert {:ok, duplicate, %{acked: [], lost: [], rtt_sample: nil}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: 4097, ranges: [{0, 4097}], delay: 0},
               5_000_000
             )

    assert duplicate.spaces == state.spaces
    assert duplicate.congestion == state.congestion
    assert duplicate.rtt == state.rtt

    {state, 4098} = sent(duplicate, :application, 10, 5_000_001)

    assert {:ok, state, %{acked: [4098], lost: [], rtt_sample: 1}} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: 4098, ranges: [{0, 4098}], delay: 0},
               5_000_002
             )

    assert state.congestion.bytes_in_flight == 0

    assert {:error, :ack_never_issued} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: 4099, ranges: [{0, 4099}]},
               5_000_003
             )
  end

  @tag timeout: 1000
  test "huge sparse ACK ranges process only retained packets and preserve RTT order" do
    largest = Integer.pow(2, 62) - 1
    # Model a long-lived space whose earlier terminal history has been pruned.
    state = put_in(Recovery.new().spaces.application.next, largest - 2)
    {state, first} = sent(state, :application, 10, 100)
    {state, middle} = sent(state, :application, 20, 101)
    {state, last} = sent(state, :application, 30, 102)
    ack = %{largest: largest, ranges: [{last, last}, {0, first}], delay: 0}

    assert {:ok, state, %{acked: [^last, ^first], lost: [], rtt_sample: 8}} =
             Recovery.receive_ack(state, :application, ack, 110)

    assert state.spaces.application.sent[middle].status == :sent
    assert state.congestion.bytes_in_flight == 20
    assert map_size(state.spaces.application.sent) == 3

    assert {:ok, duplicate, %{acked: [], lost: [], rtt_sample: nil}} =
             Recovery.receive_ack(state, :application, ack, 111)

    assert duplicate.congestion == state.congestion
  end

  test "wide ACK defers pending receipts and accounts late lost packets only once" do
    state = put_in(Recovery.new(max_sent_packets: 4).spaces.application.next, 5000)
    {state, lost} = sent(state, :application, 10, 0)
    {state, other} = sent(state, :application, 20, 1)
    {:ok, state, pending} = Recovery.reserve(state, :application, %{}, 30)
    {:ok, state} = Recovery.transition(state, :application, pending.number, :queued)
    {state, last} = sent(state, :application, 40, 3)

    {:ok, state, %{lost: [{:application, ^lost}]}} =
      Recovery.receive_ack(state, :application, %{largest: last, ranges: [{last, last}]}, 4)

    assert {:ok, state, %{acked: [^other, ^lost]}} =
             Recovery.receive_ack(state, :application, %{largest: last, ranges: [{0, last}]}, 5)

    assert state.congestion.bytes_in_flight == 30
    assert state.spaces.application.pending_acks == MapSet.new([pending.number])

    assert {:ok, state, [:acked]} =
             Recovery.local_send(state, :application, pending.number, :ok, 6)

    assert state.congestion.bytes_in_flight == 0
    assert state.spaces.application.pending_acks == MapSet.new()
  end

  test "range count and malformed range validation remain bounded" do
    {state, _} = sent(Recovery.new(max_ack_ranges: 1), :application, 10, 0)

    for ranges <- [[{-1, 0}], [{1, 0}], [{0, :invalid}]] do
      assert {:error, :invalid_ack_ranges} =
               Recovery.receive_ack(state, :application, %{largest: 0, ranges: ranges}, 1)
    end

    assert {:error, :ack_range_limit} =
             Recovery.receive_ack(
               state,
               :application,
               %{largest: 0, ranges: [{0, 0}, {0, 0}]},
               1
             )
  end

  test "does not reclaim active or lost packets when history is full" do
    state = Recovery.new(max_sent_packets: 1)
    {state, _number} = sent(state, :application, 10, 0)
    assert {:error, :sent_history_limit} = Recovery.reserve(state, :application, %{}, 10)
  end
end

defmodule Quic.Congestion.NewRenoTest do
  use ExUnit.Case, async: true

  alias Quic.Congestion.NewReno

  test "bounded admission, growth and loss reduction" do
    state = NewReno.new(mss: 100, initial_cwnd: 200)
    assert {:ok, state} = NewReno.reserve(state, 200)
    assert {:error, :congestion_limited} = NewReno.reserve(state, 1)
    state = NewReno.on_ack(state, 100)
    assert state.cwnd > 200
    state = NewReno.on_loss(state, 100)
    assert state.cwnd == 200
    assert state.bytes_in_flight == 0
  end
end

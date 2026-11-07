defmodule Quic.RecoveryPathTest do
  use ExUnit.Case, async: true

  alias Quic.Recovery

  defp sent(state, bytes, at, metadata \\ %{}) do
    {:ok, state, packet} = Recovery.reserve(state, :application, metadata, bytes)
    {:ok, state, [:sent]} = Recovery.local_send(state, :application, packet.number, :ok, at)
    {state, packet.number}
  end

  defp ack(number), do: %{largest: number, ranges: [{number, number}]}

  test "new paths reset congestion and RTT but retain application packet numbers" do
    state = Recovery.new(mss: 100, initial_cwnd: 200)
    {state, 0} = sent(state, 100, 0)
    {:ok, state, _} = Recovery.receive_ack(state, :application, ack(0), 100)
    assert state.congestion.cwnd == 300
    assert state.rtt.smoothed == 100
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    assert Recovery.selected_path(state) == 1
    assert state.rtt.smoothed == nil
    assert state.congestion.cwnd == 200
    assert state.congestion.bytes_in_flight == 0
    {:ok, state, packet} = Recovery.reserve(state, :application, %{}, 100)
    assert packet.number == 1
    assert packet.path_id == 1
    assert packet.metadata.path_id == 1
    assert Recovery.path(state, :default).congestion.cwnd == 300
  end

  test "an old-path ACK on a new address never changes new congestion or RTT" do
    {state, number} = sent(Recovery.new(mss: 100, initial_cwnd: 200), 100, 0)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    initial = Recovery.path(state, 1)

    {:ok, state, %{rtt_sample: nil, acked: [^number]}} =
      Recovery.receive_ack(state, :application, ack(number), 100, 1)

    assert Recovery.path(state, 1) == initial
    assert Recovery.path(state, :default).congestion.bytes_in_flight == 0
    assert Recovery.path(state, :default).congestion.cwnd == 300
    assert Recovery.path(state, :default).rtt.smoothed == nil
  end

  test "same-path old acknowledgments update only the old RTT" do
    {state, number} = sent(Recovery.new(), 100, 0)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)

    {:ok, state, %{rtt_sample: 100}} =
      Recovery.receive_ack(state, :application, ack(number), 100, :default)

    assert Recovery.path(state, :default).rtt.smoothed == 100
    assert state.rtt.smoothed == nil
  end

  test "an unregistered receive address only suppresses RTT sampling" do
    {state, number} = sent(Recovery.new(), 100, 0)

    {:ok, state, %{rtt_sample: nil}} =
      Recovery.receive_ack(state, :application, ack(number), 100, :prospective)

    assert Recovery.path(state, :prospective) == nil
    assert state.rtt.smoothed == nil
    assert state.congestion.bytes_in_flight == 0
  end

  test "ACK-before-receipt completion settles its original path after migration" do
    state = Recovery.new(mss: 100, initial_cwnd: 200)
    {:ok, state, packet} = Recovery.reserve(state, :application, %{}, 100)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)

    {:ok, state, %{acked: []}} =
      Recovery.receive_ack(state, :application, ack(packet.number), 10, 1)

    {:ok, state, [:acked]} = Recovery.local_send(state, :application, packet.number, :ok, 20)
    assert state.congestion.cwnd == 200
    assert state.congestion.bytes_in_flight == 0
    assert Recovery.path(state, :default).congestion.bytes_in_flight == 0
    assert Recovery.path(state, :default).congestion.cwnd == 300
  end

  test "packet-threshold loss of old packets does not halve new congestion" do
    {state, 0} = sent(Recovery.new(mss: 100, initial_cwnd: 1000), 100, 0)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    {state, 1} = sent(state, 100, 1)
    {state, 2} = sent(state, 100, 2)
    {state, 3} = sent(state, 100, 3)

    {:ok, state, %{lost: [{:application, 0}]}} =
      Recovery.receive_ack(state, :application, ack(3), 100, 1)

    assert state.congestion.cwnd == 1100
    assert state.congestion.bytes_in_flight == 200
    assert Recovery.path(state, :default).congestion.cwnd == 500
    assert Recovery.path(state, :default).congestion.bytes_in_flight == 0
  end

  test "failed old-path reservations release only old congestion" do
    state = Recovery.new()
    {:ok, state, packet} = Recovery.reserve(state, :application, %{}, 100)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    {state, _number} = sent(state, 200, 0)

    {:ok, state, [:failed]} =
      Recovery.local_send(state, :application, packet.number, {:error, :closed}, 10)

    assert state.congestion.bytes_in_flight == 200
    assert Recovery.path(state, :default).congestion.bytes_in_flight == 0
  end

  test "retiring a space releases reservations on both paths" do
    state = Recovery.new()
    {:ok, state, _} = Recovery.reserve(state, :handshake, %{}, 100)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    {:ok, state, _} = Recovery.reserve(state, :handshake, %{}, 200)
    state = Recovery.retire_space(state, :handshake)
    assert state.congestion.bytes_in_flight == 0
    assert Recovery.path(state, :default).congestion.bytes_in_flight == 0
    assert state.spaces.handshake.next == 2
  end

  test "reservation rollback releases each pinned path without reusing numbers" do
    state = Recovery.new()
    {:ok, state} = Recovery.add_path(state, 1)
    before = state
    {:ok, state, _} = Recovery.reserve(state, :application, %{}, 100)
    {:ok, state, _} = Recovery.reserve(state, :application, %{path_id: 1}, 200)
    state = Recovery.abort_reservations_since(state, before)
    assert state.congestion.bytes_in_flight == 0
    assert Recovery.path(state, 1).congestion.bytes_in_flight == 0
    assert state.spaces.application.next == 2
  end

  test "two controllers are bounded and outstanding work prevents dropping one" do
    {state, number} = sent(Recovery.new(), 100, 0)
    {:ok, state} = Recovery.add_path(state, 1)
    assert {:error, :path_limit} = Recovery.add_path(state, 2)
    {:ok, state} = Recovery.select_path(state, 1)
    assert {:error, :path_busy} = Recovery.drop_path(state, :default)
    {:ok, state, _} = Recovery.receive_ack(state, :application, ack(number), 100, :default)
    {:ok, state} = Recovery.drop_path(state, :default)
    assert Recovery.path(state, :default) == nil
    assert {:ok, _state} = Recovery.add_path(state, 2)
    assert state.spaces.application.sent[number].path_id == :default
  end

  test "PTO backoff belongs to the probed path" do
    {state, _number} = sent(Recovery.new(), 100, 0)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    {:ok, state, %{probes: [{:application, 0}]}} = Recovery.on_time(state, state.deadline)
    assert Recovery.path(state, :default).rtt.pto_count == 1
    assert state.rtt.pto_count == 0
  end

  test "loss of packets with no congestion bytes cannot reduce a path window" do
    state = Recovery.new(mss: 100, initial_cwnd: 1000)
    {state, 0} = sent(state, 0, 0, %{ack_eliciting: false})
    {state, 1} = sent(state, 0, 1, %{ack_eliciting: false})
    {state, 2} = sent(state, 0, 2, %{ack_eliciting: false})
    {state, 3} = sent(state, 100, 3)

    {:ok, state, %{lost: [{:application, 0}]}} =
      Recovery.receive_ack(state, :application, ack(3), 100)

    assert state.congestion.cwnd == 1100
    assert state.congestion.bytes_in_flight == 0
  end

  test "time loss uses the old path RTT after new-path sampling" do
    {state, 0} = sent(Recovery.new(mss: 100, initial_cwnd: 1000), 100, 0)
    old_duration = Recovery.pto_duration(state)
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    {state, 1} = sent(state, 100, 0)
    {:ok, state, _} = Recovery.receive_ack(state, :application, ack(1), 100_000, 1)
    assert Recovery.pto_duration(state, :default) == old_duration
    {:ok, state, %{lost: [], probes: []}} = Recovery.on_time(state, 150_000)
    assert state.spaces.application.sent[0].status == :sent
    {:ok, state, %{lost: [{:application, 0}]}} = Recovery.on_time(state, 374_625)
    assert state.congestion.cwnd == 1100
    assert Recovery.path(state, :default).congestion.cwnd == 500
  end

  test "completed ACK-only packets do not retain a retired path controller" do
    {state, number} = sent(Recovery.new(), 0, 0, %{ack_eliciting: false})
    {:ok, state} = Recovery.add_path(state, 1)
    {:ok, state} = Recovery.select_path(state, 1)
    assert {:ok, state} = Recovery.drop_path(state, :default)
    assert state.spaces.application.sent[number].status == :discarded
    assert {:ok, state, %{lost: [], probes: []}} = Recovery.on_time(state, 5_000_000)
    assert state.deadline == nil
  end

  test "unknown path operations do not create controllers or packet numbers" do
    state = Recovery.new(path: 42)
    assert Recovery.selected_path(state) == 42
    assert {:error, :unknown_path} = Recovery.select_path(state, :unknown)
    assert {:error, :unknown_path} = Recovery.drop_path(state, :unknown)
    assert {:error, :active_path} = Recovery.drop_path(state, 42)

    assert {:error, :unknown_path} =
             Recovery.reserve(state, :application, %{path_id: :unknown}, 1)

    assert state.spaces.application.next == 0
    assert Recovery.path(state, :unknown) == nil
  end

  test "fresh paths retain negotiated ACK decoding but discard RTT estimates" do
    state = Recovery.new()

    state = %{
      state
      | rtt: %{
          state.rtt
          | max_ack_delay: 1234,
            ack_delay_exponent: 7,
            smoothed: 10,
            variance: 5,
            latest: 10,
            min: 10
        }
    }

    {:ok, state} = Recovery.add_path(state, 1)
    assert Recovery.path(state, 1).rtt.max_ack_delay == 1234
    assert Recovery.path(state, 1).rtt.ack_delay_exponent == 7
    assert Recovery.path(state, 1).rtt.smoothed == nil
    assert Recovery.path(state, 1).rtt.latest == nil
  end

  test "negotiated ACK configuration updates live controllers and future paths" do
    state = Recovery.new()
    state = %{state | rtt: %{state.rtt | smoothed: 10, variance: 5, latest: 10, min: 10}}
    {:ok, state} = Recovery.add_path(state, 1)
    assert {:ok, state} = Recovery.configure_peer_ack(state, 1234, 7)

    for id <- [:default, 1] do
      assert Recovery.path(state, id).rtt.max_ack_delay == 1234
      assert Recovery.path(state, id).rtt.ack_delay_exponent == 7
    end

    assert state.rtt.smoothed == 10
    assert Recovery.path(state, 1).rtt.smoothed == nil
    assert state.path_defaults.rtt.max_ack_delay == 1234
    assert state.path_defaults.rtt.ack_delay_exponent == 7
    assert {:error, :invalid_ack_parameters} = Recovery.configure_peer_ack(state, -1, 7)
    assert {:error, :invalid_ack_parameters} = Recovery.configure_peer_ack(state, 0, 21)
  end
end

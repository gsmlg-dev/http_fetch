defmodule Quic.RecoveryPTOTest do
  use ExUnit.Case, async: true

  alias Quic.Recovery

  defp metadata(path \\ :default) do
    %{
      path_id: path,
      ack_eliciting: true,
      control: [%{type: :stream, id: 1, offset: 0, bytes: :binary.copy(<<0>>, 1319)}]
    }
  end

  defp sent(state, space, bytes, at, path \\ :default) do
    {:ok, state, packet} = Recovery.reserve(state, space, metadata(path), bytes)
    {:ok, state, [:sent]} = Recovery.local_send(state, space, packet.number, :ok, at)
    {state, packet.number}
  end

  defp full_flight(opts \\ []) do
    state = Recovery.new(Keyword.merge([initial_cwnd: 14_242], opts))

    Enum.reduce(1..10, state, fn _, state ->
      {state, _} = sent(state, :application, 1350, 0)
      state
    end)
  end

  defp timeout(state) do
    {:ok, state, %{lost: [], probes: [{:application, number}]}} =
      Recovery.on_time(state, state.deadline)

    {state, number}
  end

  test "a 1350-byte PTO probe preserves the original flight and congestion window" do
    state = full_flight()
    {state, original} = timeout(state)
    assert state.congestion.mss == 1200
    assert state.congestion.cwnd - state.congestion.bytes_in_flight == 742

    assert {:error, :congestion_limited} =
             Recovery.reserve(state, :application, metadata(), 1350)

    assert {:ok, next, probe} =
             Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)

    assert probe.number == 10
    assert probe.path_id == :default
    assert probe.status == :reserved
    assert next.spaces.application.sent[original].status == :sent
    assert next.congestion.cwnd == state.congestion.cwnd
    assert next.congestion.bytes_in_flight == 14_850

    assert {:error, :congestion_limited} =
             Recovery.reserve(next, :application, metadata(), 1)

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(next, :application, original, metadata(), 1350, 1350)
  end

  test "ordinary reservations cannot borrow or consume a PTO grant" do
    {state, original} = full_flight() |> timeout()
    {:ok, state, _ordinary} = Recovery.reserve(state, :application, metadata(), 100)

    assert {:ok, _, _} =
             Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)
  end

  test "early timers and packets not selected for this PTO cannot authorize a probe" do
    state = full_flight()
    {:ok, early, %{probes: []}} = Recovery.on_time(state, state.deadline - 1)

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(early, :application, 0, metadata(), 1350, 1350)

    {state, original} = timeout(state)

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(state, :application, original + 1, metadata(), 1350, 1350)
  end

  test "a grant stays pinned to its original path after active-path selection changes" do
    {state, original} = full_flight() |> timeout()
    {:ok, state} = Recovery.add_path(state, :other)
    {:ok, state} = Recovery.select_path(state, :other)
    other = state.congestion

    assert {:error, :probe_path_mismatch} =
             Recovery.reserve_probe(state, :application, original, metadata(:other), 1350, 1350)

    assert {:ok, next, probe} =
             Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)

    assert probe.path_id == :default
    assert next.congestion == other
    assert Recovery.path(next, :default).congestion.bytes_in_flight == 14_850
  end

  test "invalid sizes and non-ack-eliciting packets preserve the grant and PN" do
    {state, original} = full_flight() |> timeout()

    for {bytes, limit} <- [{0, 1350}, {-1, 1350}, {1351, 1350}, {1350, 0}] do
      assert {:error, :invalid_probe_size} =
               Recovery.reserve_probe(state, :application, original, metadata(), bytes, limit)
    end

    assert {:error, :invalid_probe_packet} =
             Recovery.reserve_probe(
               state,
               :application,
               original,
               %{metadata() | ack_eliciting: false},
               1350,
               1350
             )

    assert {:ok, _, %{number: 10}} =
             Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)
  end

  test "probe reservation retains the finite sent-history limit" do
    {state, original} = full_flight(max_sent_packets: 10) |> timeout()

    assert {:error, :sent_history_limit} =
             Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)
  end

  test "acknowledging the original revokes its pending probe grant" do
    {state, original} = full_flight() |> timeout()

    {:ok, state, _} =
      Recovery.receive_ack(
        state,
        :application,
        %{largest: original, ranges: [{original, original}]},
        1
      )

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)
  end

  test "a later PTO replaces rather than accumulates the previous original grant" do
    {:ok, state} = Recovery.add_path(Recovery.new(), :other)
    {state, _} = sent(state, :initial, 100, 0)
    {state, _} = sent(state, :application, 100, 0, :other)
    {:ok, state, %{probes: [{:initial, 0}]}} = Recovery.on_time(state, state.deadline)
    {:ok, state, %{probes: [{:application, 0}]}} = Recovery.on_time(state, state.deadline)

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(state, :initial, 0, metadata(), 100, 1350)

    assert {:ok, _, _} =
             Recovery.reserve_probe(state, :application, 0, metadata(:other), 100, 1350)
  end

  test "retirement, discarded originals, invalid paths and spaces reject probe grants" do
    {state, original} = full_flight() |> timeout()
    discarded = Recovery.discard_space(state, :application)

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(discarded, :application, original, metadata(), 1350, 1350)

    missing_path = %{state | active_path: :other, paths: %{}}

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(missing_path, :application, original, metadata(), 1350, 1350)

    assert {:error, :invalid_probe_reservation} =
             Recovery.reserve_probe(state, :invalid, original, metadata(), 1350, 1350)

    {initial, number} = sent(Recovery.new(), :initial, 100, 0)

    {:ok, initial, %{probes: [{:initial, ^number}]}} =
      Recovery.on_time(initial, initial.deadline)

    retired = Recovery.retire_space(initial, :initial)

    assert {:error, :retired_space} =
             Recovery.reserve_probe(retired, :initial, number, metadata(), 100, 1350)
  end

  test "failed probe writes release only the probe reservation and do not renew its grant" do
    {state, original} = full_flight() |> timeout()

    {:ok, state, probe} =
      Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)

    {:ok, next, [:failed]} =
      Recovery.local_send(state, :application, probe.number, {:error, :send_failed}, 1)

    assert next.congestion.bytes_in_flight == 13_500
    assert next.congestion.cwnd == 14_242
    assert next.spaces.application.sent[original].status == :sent

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(next, :application, original, metadata(), 1350, 1350)
  end

  test "a retired send path cannot retain its original probe grant" do
    {state, original} = full_flight() |> timeout()
    {:ok, state} = Recovery.add_path(state, :other)
    {:ok, state} = Recovery.select_path(state, :other)
    assert {:error, :path_busy} = Recovery.drop_path(state, :default)
    state = Recovery.discard_space(state, :application)
    {:ok, state} = Recovery.drop_path(state, :default)
    assert Recovery.path(state, :default) == nil

    assert {:error, :probe_not_authorized} =
             Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)
  end

  test "probe and original acknowledgements each release exactly their own reservation" do
    {state, original} = sent(Recovery.new(initial_cwnd: 1350), :application, 1350, 0)
    {state, ^original} = timeout(state)

    {:ok, state, probe} =
      Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)

    {:ok, state, [:sent]} = Recovery.local_send(state, :application, probe.number, :ok, 1)

    {:ok, state, %{lost: []}} =
      Recovery.receive_ack(
        state,
        :application,
        %{largest: probe.number, ranges: [{probe.number, probe.number}]},
        2
      )

    assert state.congestion.bytes_in_flight == 1350
    assert state.spaces.application.sent[original].status == :sent

    {:ok, state, %{lost: []}} =
      Recovery.receive_ack(
        state,
        :application,
        %{largest: original, ranges: [{original, original}]},
        3
      )

    assert state.congestion.bytes_in_flight == 0
  end

  test "ACK of a sent probe releases its own path credit before the original is acknowledged" do
    {state, original} = full_flight() |> timeout()

    {:ok, state, probe} =
      Recovery.reserve_probe(state, :application, original, metadata(), 1350, 1350)

    {:ok, state, [:sent]} = Recovery.local_send(state, :application, probe.number, :ok, 1)

    {:ok, next, result} =
      Recovery.receive_ack(
        state,
        :application,
        %{largest: probe.number, ranges: [{probe.number, probe.number}]},
        2
      )

    assert probe.number in result.acked
    assert original in Enum.map(result.lost, &elem(&1, 1))

    assert next.congestion.bytes_in_flight ==
             Enum.reduce(next.spaces.application.sent, 0, fn {_, packet}, bytes ->
               if packet.status in [:reserved, :queued, :sent],
                 do: bytes + packet.bytes,
                 else: bytes
             end)
  end
end

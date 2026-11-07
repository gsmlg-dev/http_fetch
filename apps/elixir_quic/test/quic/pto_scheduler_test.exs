defmodule Quic.PTOSchedulerTest do
  use ExUnit.Case, async: true

  alias Quic.{HandshakeScheduler, Recovery}

  defmodule ApplicationTLS do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      {:ok, nil,
       for {direction, value} <- [read: read, write: write] do
         %SSL.QUIC.Secret{
           level: :application,
           direction: direction,
           cipher_suite: 0x1301,
           aead: :aes_128_gcm,
           hkdf: :sha256,
           secret: <<value::256>>
         }
       end}
    end

    def info(_), do: %{receive_level: :application}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defmodule InitialTLS do
    def new(_, _), do: {:ok, nil, [{:emit, :initial, "retained handshake"}]}
    def info(_), do: %{receive_level: :initial}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defp scheduler do
    {:ok, state, []} =
      HandshakeScheduler.new(:client,
        adapter: ApplicationTLS,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        max_packet_size: 1350
      )

    HandshakeScheduler.install_peer_parameters(state, %{
      max_datagram_frame_size: 65_535,
      initial_max_data: 1_048_576,
      initial_max_streams_bidi: 16,
      initial_max_stream_data_bidi_remote: 65_536,
      initial_max_stream_data_bidi_local: 65_536
    })
  end

  defp sent_at_capacity(state, effect) do
    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, effect.space, effect.packet_number, :ok, 0)

    put_in(state.recovery.congestion.cwnd, state.recovery.congestion.bytes_in_flight)
  end

  defp expire(state) do
    at = state.recovery.deadline
    {:ok, recovery, %{lost: [], probes: [probe]}} = Recovery.on_time(state.recovery, at)
    {%{state | recovery: recovery}, probe, at}
  end

  test "PTO retransmits retained STREAM at a full window without spending credit on queued data" do
    state = scheduler()
    {:ok, state, 0} = HandshakeScheduler.open_stream(state, :bidi)
    {:ok, state, [original]} = HandshakeScheduler.send_stream(state, 0, "retained bytes", true)
    state = sent_at_capacity(state, original)
    {:ok, state, 4} = HandshakeScheduler.open_stream(state, :bidi)
    {:ok, state, []} = HandshakeScheduler.send_stream(state, 4, "next", false)
    pending = state.pending
    controls = state.pending_control
    flight = state.recovery.congestion.bytes_in_flight
    cwnd = state.recovery.congestion.cwnd
    {state, {:application, number}, at} = expire(state)

    assert {:ok, next, [probe]} = HandshakeScheduler.probe(state, :application, number)
    assert probe.packet_number > original.packet_number
    assert probe.path_id == :default
    packet = next.recovery.spaces.application.sent[probe.packet_number]

    assert packet.metadata.control == [
             %{type: :stream, stream_id: 0, offset: 0, data: "retained bytes", fin: true}
           ]

    assert next.recovery.spaces.application.sent[number].status == :sent
    assert next.recovery.congestion.bytes_in_flight == flight + packet.bytes
    assert next.recovery.congestion.cwnd == cwnd
    assert next.pending == pending
    assert next.pending_control == controls
    assert {:ok, ^next, []} = HandshakeScheduler.schedule(next)
    assert {:error, _} = HandshakeScheduler.probe(next, :application, number)

    {:ok, next, [:sent]} =
      HandshakeScheduler.local_send(next, :application, probe.packet_number, :ok, at)

    assert {:ok, next, %{acked: [_]}} =
             HandshakeScheduler.receive_ack(
               next,
               :application,
               %{
                 largest: probe.packet_number,
                 ranges: [{probe.packet_number, probe.packet_number}]
               },
               at + 1000
             )

    assert {:ok, next, [_ | _]} = HandshakeScheduler.schedule(next)
    assert next.pending_control == %{}
  end

  test "a probe requires an actual PTO grant before bypassing congestion" do
    state = scheduler()
    {:ok, state, 0} = HandshakeScheduler.open_stream(state, :bidi)
    {:ok, state, [original]} = HandshakeScheduler.send_stream(state, 0, "retained", false)
    state = sent_at_capacity(state, original)

    assert {:error, _} = HandshakeScheduler.probe(state, :application, original.packet_number)
    assert state.recovery.congestion.bytes_in_flight == state.recovery.congestion.cwnd
  end

  test "PTO probes do not retransmit an unreliable DATAGRAM or unrelated pending frames" do
    state = scheduler()
    {:ok, state, [original]} = HandshakeScheduler.send_datagram(state, "send once")
    state = sent_at_capacity(state, original)
    {:ok, state, []} = HandshakeScheduler.send_datagram(state, "ordinary queued datagram")
    controls = state.pending_control
    {state, {:application, number}, _} = expire(state)

    assert {:ok, next, [probe]} = HandshakeScheduler.probe(state, :application, number)

    assert next.recovery.spaces.application.sent[probe.packet_number].metadata.control == [
             %{type: :ping}
           ]

    assert next.pending_control == controls
    assert next.queued_bytes == state.queued_bytes
  end

  test "a selected packet whose reliable frames were pruned still produces a PING" do
    state = scheduler()
    {:ok, state, [original]} = HandshakeScheduler.ping(state)
    state = sent_at_capacity(state, original)

    state =
      put_in(state.recovery.spaces.application.sent[original.packet_number].metadata.control, [])

    {state, {:application, number}, _} = expire(state)

    assert {:ok, next, [probe]} = HandshakeScheduler.probe(state, :application, number)

    assert next.recovery.spaces.application.sent[probe.packet_number].metadata.control == [
             %{type: :ping}
           ]
  end

  test "an inactive path PTO sends on its pinned path and preserves selected-path congestion" do
    state = scheduler()
    {:ok, recovery} = Recovery.add_path(state.recovery, 1)
    {:ok, recovery} = Recovery.select_path(recovery, 1)
    {:ok, state} = HandshakeScheduler.bind_path(%{state | recovery: recovery}, 1, :default, true)
    {:ok, state, 0} = HandshakeScheduler.open_stream(state, :bidi)
    {:ok, state, [original]} = HandshakeScheduler.send_stream(state, 0, "old path", false)
    state = sent_at_capacity(state, original)
    {:ok, recovery} = Recovery.select_path(state.recovery, :default)
    state = %{state | recovery: recovery}
    selected = Recovery.path(state.recovery, :default)
    old_flight = Recovery.path(state.recovery, 1).congestion.bytes_in_flight
    {state, {:application, number}, _} = expire(state)

    assert {:ok, next, [probe]} = HandshakeScheduler.probe(state, :application, number)
    assert probe.path_id == 1
    assert Recovery.selected_path(next.recovery) == :default
    assert Recovery.path(next.recovery, :default) == selected
    packet = next.recovery.spaces.application.sent[probe.packet_number]
    assert packet.path_id == 1
    assert Recovery.path(next.recovery, 1).congestion.bytes_in_flight == old_flight + packet.bytes
  end

  test "PTO repacketizes retained CRYPTO with fresh packet numbers at a full window" do
    {:ok, state, [original]} =
      HandshakeScheduler.new(:client,
        adapter: InitialTLS,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>
      )

    state = sent_at_capacity(state, original)
    tls = state.tls
    {state, {:initial, number}, _} = expire(state)

    assert {:ok, next, [probe]} = HandshakeScheduler.probe(state, :initial, number)
    assert probe.packet_number > number
    assert next.tls == tls
    assert next.recovery.spaces.initial.sent[probe.packet_number].metadata.crypto == {0, 18}
    assert next.recovery.spaces.initial.sent[number].status == :sent
  end
end

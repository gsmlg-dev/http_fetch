defmodule Quic.ReliableResetSchedulerTest do
  use ExUnit.Case, async: true
  alias Quic.{HandshakeScheduler, Recovery, Streams}

  defmodule TLS do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      actions =
        for {direction, value} <- [read: read, write: write],
            do: %SSL.QUIC.Secret{
              level: :application,
              direction: direction,
              cipher_suite: 0x1301,
              aead: :aes_128_gcm,
              hkdf: :sha256,
              secret: <<value::256>>
            }

      {:ok, nil, actions}
    end

    def info(_), do: %{receive_level: :application}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defp pair do
    client = <<1, 2, 3, 4>>
    server = <<5, 6, 7, 8>>

    {:ok, sender, []} =
      HandshakeScheduler.new(:client,
        dcid: server,
        scid: client,
        adapter: TLS,
        reset_stream_at: true
      )

    {:ok, receiver, []} =
      HandshakeScheduler.new(:server,
        dcid: client,
        scid: server,
        adapter: TLS,
        reset_stream_at: true
      )

    sender =
      HandshakeScheduler.install_peer_parameters(sender, %{
        reset_stream_at: true,
        initial_max_data: 65_536,
        initial_max_stream_data_bidi_remote: 65_536,
        initial_max_stream_data_uni: 65_536,
        initial_max_streams_bidi: 4,
        initial_max_streams_uni: 4
      })

    {sender, receiver}
  end

  defp sent(state, packets, at) do
    Enum.reduce(packets, state, fn packet, state ->
      {:ok, state, _} =
        HandshakeScheduler.local_send(state, packet.space, packet.packet_number, :ok, at)

      state
    end)
  end

  test "negotiation is required in both directions and unadvertised receive is a protocol error" do
    {sender, receiver} = pair()
    {:ok, sender, id} = HandshakeScheduler.open_stream(sender, :bidi)

    assert {:error, :reliable_reset_not_negotiated} =
             HandshakeScheduler.reset_stream_at(%{sender | peer_reset_stream_at: false}, id, 1, 0)

    {:ok, _, [packet]} = HandshakeScheduler.reset_stream_at(sender, id, 1, 0)

    assert {:error, {:protocol_violation, 0x0A, 0x24}, _} =
             HandshakeScheduler.receive_datagram(
               %{receiver | local_reset_stream_at: false},
               packet.bytes,
               100
             )
  end

  test "lost stream range retransmits only reliable prefix after reset arrives first" do
    {sender, receiver} = pair()
    {:ok, sender, id} = HandshakeScheduler.open_stream(sender, :bidi)
    {:ok, sender, data_packets} = HandshakeScheduler.send_stream(sender, id, "header-tail", false)
    sender = sent(sender, data_packets, 10)
    [data_packet] = data_packets
    {:ok, sender, reset_packets} = HandshakeScheduler.reset_stream_at(sender, id, 42, 6)
    sender = sent(sender, reset_packets, 20)
    [reset_packet] = reset_packets

    {:ok, receiver, reset_events} =
      HandshakeScheduler.receive_datagram(receiver, reset_packet.bytes, 30)

    assert Enum.any?(reset_events, &(&1.type == :reset_stream_at and &1.events == []))
    assert receiver.streams.streams[id].recv_terminal == nil
    original = sender.recovery.spaces.application.sent[data_packet.packet_number]
    assert [%{type: :stream, data: "header", fin: false}] = original.metadata.control
    refute Map.has_key?(original.metadata, :bytes)

    {:ok, sender, retry_packets} =
      HandshakeScheduler.retry_crypto(sender, :application, data_packet.packet_number)

    [retry_packet] = retry_packets
    assert retry_packet.packet_number > reset_packet.packet_number

    {:ok, receiver, events} =
      HandshakeScheduler.receive_datagram(receiver, retry_packet.bytes, 40)

    items = Enum.flat_map(events, &Map.get(&1, :events, []))
    assert items == [{:data, id, "header"}, {:reset, id, 42, 11}]
    assert receiver.streams.streams[id].recv_terminal == :reset
    assert receiver.streams.data_received == 11
    assert receiver.streams.data_consumed == 11
    # A late original packet may contain the tail; it must not deliver another reset or bytes.
    {:ok, _, late} = HandshakeScheduler.receive_datagram(receiver, data_packet.bytes, 50)
    assert Enum.flat_map(late, &Map.get(&1, :events, [])) == []
    assert sender.recovery.spaces.application.next > retry_packet.packet_number
  end

  test "decreasing prefix trims queued and retained work without resetting stream offsets" do
    {sender, _} = pair()
    {:ok, sender, id} = HandshakeScheduler.open_stream(sender, :uni)
    {:ok, sender, [packet]} = HandshakeScheduler.send_stream(sender, id, "header-tail", true)
    {:ok, sender, _} = HandshakeScheduler.reset_stream_at(sender, id, 42, 6)
    refute HandshakeScheduler.pending_send_valid?(sender, packet)
    {:ok, sender, _} = HandshakeScheduler.reset_stream_at(sender, id, 42, 3)
    original = sender.recovery.spaces.application.sent[packet.packet_number]
    assert [%{data: "hea", fin: false}] = original.metadata.control
    assert sender.streams.streams[id].send_offset == 11
    assert sender.streams.data_sent == 11
    assert {:ok, streams, _} = Streams.reset_send(sender.streams, id, 42)
    assert streams.streams[id].send_reliable == 0
  end

  test "reset ACK does not release reliable prefix until its independent ACK" do
    {sender, _} = pair()
    {:ok, sender, id} = HandshakeScheduler.open_stream(sender, :bidi)
    {:ok, sender, [packet]} = HandshakeScheduler.send_stream(sender, id, "header-tail", false)
    sender = sent(sender, [packet], 10)
    {:ok, sender, [reset]} = HandshakeScheduler.reset_stream_at(sender, id, 42, 6)
    sender = sent(sender, [reset], 20)

    ack = %{
      largest: reset.packet_number,
      ranges: [{reset.packet_number, reset.packet_number}],
      delay: 0
    }

    {:ok, sender, _} = HandshakeScheduler.receive_ack(sender, :application, ack, 100)
    assert sender.acked_stream_resets[id] == 6

    assert [%{data: "header"}] =
             sender.recovery.spaces.application.sent[packet.packet_number].metadata.control

    assert {:ok, _, _} =
             Recovery.receive_ack(
               sender.recovery,
               :application,
               %{
                 largest: packet.packet_number,
                 ranges: [{packet.packet_number, packet.packet_number}],
                 delay: 0
               },
               120
             )
  end

  # Delivers `delivered` to the receiver, leaves `lost` unacknowledged in flight,
  # then lets the receiver send STOP_SENDING for the stream.
  defp stop_sending_from_peer(sender, receiver, prefix, delivered, lost) do
    {:ok, sender, id} = HandshakeScheduler.open_stream(sender, :uni, prefix)

    {:ok, sender, delivered_packets} =
      HandshakeScheduler.send_stream(sender, id, delivered, false)

    {:ok, sender, [lost_packet]} = HandshakeScheduler.send_stream(sender, id, lost, false)
    sender = sent(sender, delivered_packets ++ [lost_packet], 10)
    receiver = receive_all(receiver, delivered_packets, 20)
    {:ok, receiver, stops} = HandshakeScheduler.stop_stream(receiver, id, 77)
    sender = receive_all(sender, stops, 30)
    {sender, receiver, id, lost_packet}
  end

  defp receive_all(state, packets, at) do
    Enum.reduce(packets, state, fn packet, state ->
      {:ok, state, _} = HandshakeScheduler.receive_datagram(state, packet.bytes, at)
      state
    end)
  end

  test "peer STOP_SENDING on a prefixed stream is answered with RESET_STREAM_AT" do
    {sender, receiver} = pair()
    {sender, receiver, id, lost} = stop_sending_from_peer(sender, receiver, 6, "head", "er-tail")

    assert %{send_reset: 77, send_reliable: 6} = sender.streams.streams[id]

    # Retained recovery work for the stream is trimmed to the reliable prefix.
    original = sender.recovery.spaces.application.sent[lost.packet_number]
    assert [%{type: :stream, offset: 4, data: "er", fin: false}] = original.metadata.control

    {:ok, sender, reset_packets} = HandshakeScheduler.schedule(sender)
    sender = sent(sender, reset_packets, 40)

    {:ok, receiver, events} =
      HandshakeScheduler.receive_datagram(receiver, hd(reset_packets).bytes, 50)

    assert Enum.any?(events, fn
             %{type: :reset_stream_at, frame: frame} ->
               frame.error_code == 77 and frame.final_size == 11 and frame.reliable_size == 6

             _ ->
               false
           end)

    assert receiver.streams.streams[id].recv_reliable == 6

    # The lost prefix range is still recoverable after the reset.
    {:ok, _sender, [retry]} =
      HandshakeScheduler.retry_crypto(sender, :application, lost.packet_number)

    {:ok, receiver, _} = HandshakeScheduler.receive_datagram(receiver, retry.bytes, 60)
    assert receiver.streams.streams[id].recv_next == 6
  end

  test "without negotiation a prefixed stream keeps the ordinary RESET_STREAM answer" do
    {sender, receiver} = pair()
    sender = %{sender | peer_reset_stream_at: false}
    {sender, _receiver, id, lost} = stop_sending_from_peer(sender, receiver, 6, "head", "er-tail")

    assert %{send_reset: 77, send_reliable: nil} = sender.streams.streams[id]
    original = sender.recovery.spaces.application.sent[lost.packet_number]
    assert Map.get(original.metadata, :control, []) == []

    assert [%{type: :reset_stream, error_code: 77, final_size: 11}] =
             Map.get(sender.pending_control, :application, [])
  end

  test "open_stream validates the declared reliable prefix" do
    {sender, _} = pair()
    assert {:error, :invalid_reliable_prefix} = HandshakeScheduler.open_stream(sender, :uni, -1)
    assert {:error, :invalid_stream_kind} = HandshakeScheduler.open_stream(sender, :other, 4)
    assert {:ok, sender, id} = HandshakeScheduler.open_stream(sender, :bidi, 0)
    assert sender.streams.streams[id].reliable_prefix == 0
  end
end

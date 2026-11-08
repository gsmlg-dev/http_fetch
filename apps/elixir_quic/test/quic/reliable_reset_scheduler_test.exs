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
end

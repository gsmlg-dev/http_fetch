defmodule Quic.DatagramSchedulerTest do
  use ExUnit.Case, async: true
  import Bitwise
  alias Quic.{HandshakeScheduler, Recovery}

  # Recorded TLS actions isolate deterministic transport behavior from TLS entropy.
  defmodule RecordedTLS do
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

  defp scheduler(opts \\ []) do
    {:ok, state, []} =
      HandshakeScheduler.new(
        :client,
        Keyword.merge(
          [
            adapter: RecordedTLS,
            dcid: <<1, 2, 3, 4>>,
            scid: <<5, 6, 7, 8>>,
            max_packet_size: 1200
          ],
          opts
        )
      )

    HandshakeScheduler.install_peer_parameters(state, %{max_datagram_frame_size: 65_535})
  end

  # Independent AES-GCM/header-protection construction, packet number zero.
  defp peer_packet(state, plaintext) do
    keys = state.keys.application.read
    header = <<0x40, state.scid::binary>>
    aad = header <> <<0>>

    {encrypted, tag} =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, keys.iv, plaintext, aad, 16, true)

    payload = encrypted <> tag

    <<mask, pn_mask, _::binary>> =
      :crypto.crypto_one_time(:aes_128_ecb, keys.hp, binary_part(payload, 3, 16), true)

    <<bxor(0x40, band(mask, 0x1F)), state.scid::binary, pn_mask, payload::binary>>
  end

  defp sent_frames(state, packet) do
    keys = state.keys.application.write
    offset = 1 + byte_size(state.dcid)

    <<mask, masks::binary>> =
      :crypto.crypto_one_time(:aes_128_ecb, keys.hp, binary_part(packet, offset + 4, 16), true)

    <<protected, cid::binary-size(^offset - 1), rest::binary>> = packet
    first = bxor(protected, band(mask, 0x1F))
    size = band(first, 3) + 1
    <<protected_pn::binary-size(^size), ciphertext::binary>> = rest
    pn = :crypto.exor(protected_pn, binary_part(masks, 0, size))
    number = :binary.decode_unsigned(pn)
    encrypted_size = byte_size(ciphertext) - 16
    <<encrypted::binary-size(^encrypted_size), tag::binary-size(16)>> = ciphertext

    plaintext =
      :crypto.crypto_one_time_aead(
        :aes_128_gcm,
        keys.key,
        :crypto.exor(keys.iv, <<number::96>>),
        encrypted,
        <<first, cid::binary, pn::binary>>,
        tag,
        false
      )

    {:ok, frames, <<>>} = Quic.Codec.decode_frames(plaintext)
    frames
  end

  test "PTO sends an ack-eliciting probe without retransmitting DATAGRAM payload" do
    state = scheduler()
    {:ok, state, [packet]} = HandshakeScheduler.send_datagram(state, "only once")

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, packet.packet_number, :ok, 0)

    assert state.recovery.congestion.bytes_in_flight > 0
    deadline = state.recovery.deadline
    assert is_integer(deadline)

    {:ok, recovery, %{probes: [{:application, number}], lost: []}} =
      Recovery.on_time(state.recovery, deadline)

    assert number == packet.packet_number

    {:ok, next, [probe]} =
      HandshakeScheduler.retry_crypto(%{state | recovery: recovery}, :application, number)

    assert probe.packet_number > number

    assert next.recovery.spaces.application.sent[probe.packet_number].metadata.control ==
             [%{type: :ping}]
  end

  test "loss discards DATAGRAM content while releasing its history for new work" do
    state = scheduler()
    {:ok, state, [packet]} = HandshakeScheduler.send_datagram(state, "lost")

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, packet.packet_number, :ok, 0)

    # A recorded loss event isolates retry policy from the tested recovery algorithm.
    state = put_in(state.recovery.spaces.application.sent[packet.packet_number].status, :lost)

    {:ok, next, [probe]} =
      HandshakeScheduler.retry_crypto(state, :application, packet.packet_number)

    assert next.recovery.spaces.application.sent[probe.packet_number].metadata.control ==
             [%{type: :ping}]

    assert next.recovery.spaces.application.sent[packet.packet_number].status == :superseded
    assert next.queued_bytes == 0
  end

  test "congestion retains identical empty messages with bounded item admission" do
    state = scheduler(max_queue: 2)
    state = put_in(state.recovery.congestion.cwnd, 0)
    assert {:ok, state, []} = HandshakeScheduler.send_datagram(state, <<>>)
    assert {:ok, state, []} = HandshakeScheduler.send_datagram(state, <<>>)
    assert {:blocked, :send_queue_limit} = HandshakeScheduler.send_datagram(state, <<>>)
    state = put_in(state.recovery.congestion.cwnd, 12_000)
    assert {:ok, next, packets} = HandshakeScheduler.schedule(state)

    frames =
      Enum.flat_map(
        packets,
        &next.recovery.spaces.application.sent[&1.packet_number].metadata.control
      )

    assert Enum.count(frames, &(&1.type == :datagram and &1.data == <<>>)) == 2
    assert next.queued_bytes == 0
  end

  test "packet-size ceiling rejects an unsplittable DATAGRAM before reservation" do
    state = scheduler()
    frame_max = HandshakeScheduler.effective_datagram_frame_size(state)
    payload = :binary.copy("x", frame_max - 3)
    assert {:ok, next, [packet]} = HandshakeScheduler.send_datagram(state, payload)
    assert byte_size(packet.bytes) <= 1200
    assert next.recovery.spaces.application.next == 1
    assert {:error, :datagram_too_large} = HandshakeScheduler.send_datagram(state, payload <> "x")
    assert state.recovery.spaces.application.next == 0
  end

  test "authenticated nonminimal frame bytes enforce the advertised receive ceiling" do
    # 2-byte type + 2-byte length + 3-byte payload = 7, not the canonical 5.
    plaintext = <<0x40, 0x31, 0x40, 3, "abc">>
    state = scheduler(max_datagram_frame_size: 5)

    assert {:error, {:protocol_violation, 0x0A, 0x31}, _} =
             HandshakeScheduler.receive_datagram(state, peer_packet(state, plaintext), 1)

    state = scheduler(max_datagram_frame_size: 7)

    assert {:ok, _, events} =
             HandshakeScheduler.receive_datagram(state, peer_packet(state, plaintext), 1)

    assert Enum.any?(events, &match?(%{type: :datagram, data: "abc"}, &1))
  end

  test "an admitted DATAGRAM still fits after a longer peer CID and packet number" do
    state = scheduler()
    state = put_in(state.recovery.congestion.cwnd, 0)
    limit = HandshakeScheduler.effective_datagram_frame_size(state) - 3

    assert {:ok, state, []} =
             HandshakeScheduler.send_datagram(state, :binary.copy("x", limit))

    state = %{state | dcid: :binary.copy(<<1>>, 20)}
    state = put_in(state.recovery.spaces.application.next, 16_777_216)
    state = put_in(state.recovery.congestion.cwnd, 12_000)
    assert {:ok, next, [packet]} = HandshakeScheduler.schedule(state)
    assert byte_size(packet.bytes) <= 1200
    assert next.queued_bytes == 0
  end

  test "pending ACK ranges do not invalidate an admitted maximum-sized DATAGRAM" do
    state = scheduler()
    state = put_in(state.recovery.congestion.cwnd, 0)
    payload = :binary.copy("x", HandshakeScheduler.effective_datagram_frame_size(state) - 3)
    assert {:ok, state, []} = HandshakeScheduler.send_datagram(state, payload)
    ranges = for number <- 30..0//-2, do: {number, number}

    state =
      HandshakeScheduler.queue_ack(state, :application, %{
        type: :ack,
        largest: 30,
        delay: 0,
        ranges: ranges
      })

    state = put_in(state.recovery.congestion.cwnd, 12_000)
    assert {:ok, next, packets} = HandshakeScheduler.schedule(state)
    assert Enum.all?(packets, &(byte_size(&1.bytes) <= 1200))

    frames =
      Enum.flat_map(
        packets,
        &next.recovery.spaces.application.sent[&1.packet_number].metadata.control
      )

    assert Enum.count(frames, &match?(%{type: :datagram, data: ^payload}, &1)) == 1
    on_wire = Enum.flat_map(packets, &sent_frames(state, &1.bytes))
    assert Enum.any?(on_wire, &match?(%{type: :ack, ranges: ^ranges}, &1))
    assert Enum.count(on_wire, &match?(%{type: :datagram, data: ^payload}, &1)) == 1
    assert next.pending_acks == %{}
  end

  test "authenticated DATAGRAM without advertised receive support is a protocol violation" do
    state = scheduler()

    assert {:error, {:protocol_violation, 0x0A, 0x30}, _} =
             HandshakeScheduler.receive_datagram(state, peer_packet(state, <<0x30, "abc">>), 1)
  end

  test "ACK-only send preserves the admitted DATAGRAM until the send slot is released" do
    state = scheduler(max_queue: 1)
    state = put_in(state.recovery.congestion.cwnd, 0)
    payload = :binary.copy("x", HandshakeScheduler.effective_datagram_frame_size(state) - 3)
    assert {:ok, state, []} = HandshakeScheduler.send_datagram(state, payload)
    ranges = for number <- 30..0//-2, do: {number, number}

    state =
      HandshakeScheduler.queue_ack(state, :application, %{
        type: :ack,
        largest: 30,
        delay: 0,
        ranges: ranges
      })

    state = put_in(state.recovery.congestion.cwnd, 12_000)
    assert {:ok, next, [ack]} = HandshakeScheduler.schedule(state)
    assert Enum.any?(sent_frames(state, ack.bytes), &match?(%{type: :ack, ranges: ^ranges}, &1))
    assert next.queued_bytes == byte_size(payload)
    assert next.queued == 1
    assert {:ok, next, []} = HandshakeScheduler.schedule(next)

    assert {:ok, next, [:sent]} =
             HandshakeScheduler.local_send(next, :application, ack.packet_number, :ok, 1)

    assert {:ok, next, [datagram]} = HandshakeScheduler.schedule(next)

    assert Enum.any?(
             sent_frames(state, datagram.bytes),
             &match?(%{type: :datagram, data: ^payload}, &1)
           )

    assert next.queued_bytes == 0
  end
end

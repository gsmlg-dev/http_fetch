defmodule Quic.HandshakeSchedulerLevelsTest do
  use ExUnit.Case, async: true

  alias Quic.HandshakeScheduler
  alias Quic.Streams
  import Bitwise

  defmodule Recorded do
    defstruct []

    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      {:ok, %__MODULE__{},
       [
         secret(:handshake, :read, <<read::256>>),
         secret(:handshake, :write, <<write::256>>),
         secret(:application, :read, <<read + 2::256>>),
         secret(:application, :write, <<write + 2::256>>)
       ]}
    end

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}

    def secret(level, direction, bytes) do
      %SSL.QUIC.Secret{
        level: level,
        direction: direction,
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: bytes
      }
    end
  end

  defmodule WireRecorded do
    def new(role, opts) do
      {:ok, _, secrets} = Recorded.new(role, opts)
      emissions = if role == :client, do: [{:emit, :handshake, <<7, 8>>}], else: []
      {:ok, %{received: []}, secrets ++ emissions}
    end

    def info(_), do: %{receive_level: :handshake}
    def abort(state, _), do: state

    def feed(state, :handshake, bytes),
      do: {:ok, %{state | received: state.received ++ [bytes]}, []}
  end

  defp new do
    HandshakeScheduler.new(
      :client,
      dcid: <<1, 2, 3, 4>>,
      scid: <<5, 6, 7, 8>>,
      adapter: Recorded,
      min_initial_size: 0
    )
  end

  # Independent RFC 9001 packet oracle using only raw OTP primitives, not
  # Quic.Protection's header/nonce/AEAD implementations.
  defp decrypt_packet(packet, keys, pn_offset) do
    sample = binary_part(packet, pn_offset + 4, 16)
    <<mask, masks::binary>> = :crypto.crypto_one_time(:aes_128_ecb, keys.hp, sample, true)
    <<protected_first, rest::binary>> = packet
    low_bits = if band(protected_first, 0x80) == 0, do: 0x1F, else: 0x0F
    first = bxor(protected_first, band(mask, low_bits))
    pn_len = band(first, 3) + 1

    <<prefix::binary-size(^pn_offset - 1), protected_pn::binary-size(^pn_len),
      ciphertext::binary>> = rest

    pn_bytes = :crypto.exor(protected_pn, binary_part(masks, 0, pn_len))
    pn = :binary.decode_unsigned(pn_bytes)
    aad = <<first, prefix::binary, pn_bytes::binary>>
    cipher_size = byte_size(ciphertext) - 16
    <<encrypted::binary-size(^cipher_size), tag::binary-size(16)>> = ciphertext
    nonce = :crypto.exor(keys.iv, <<pn::96>>)

    plaintext =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, nonce, encrypted, aad, tag, false)

    assert is_binary(plaintext)
    {pn, plaintext}
  end

  defp peer_handshake(keys, plaintext) do
    # Packet number zero; one-byte packet number and bounded one-byte Length.
    header = <<0xE0, 1::32, 4, 5, 6, 7, 8, 4, 1, 2, 3, 4, byte_size(plaintext) + 17>>
    aad = header <> <<0>>

    {encrypted, tag} =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, keys.iv, plaintext, aad, 16, true)

    payload = encrypted <> tag

    <<mask, pn_mask, _::binary>> =
      :crypto.crypto_one_time(:aes_128_ecb, keys.hp, binary_part(payload, 3, 16), true)

    <<first, rest::binary>> = header
    <<bxor(first, band(mask, 0x0F)), rest::binary, pn_mask, payload::binary>>
  end

  test "recorded peer secrets install matching opposite directions at each level" do
    {:ok, client, []} = new()

    {:ok, server, []} =
      HandshakeScheduler.new(:server, dcid: client.scid, scid: client.dcid, adapter: Recorded)

    for level <- [:handshake, :application], {a, b} <- [{:read, :write}, {:write, :read}] do
      assert Map.take(client.keys[level][a], [:key, :iv, :hp]) ==
               Map.take(server.keys[level][b], [:key, :iv, :hp])

      refute client.keys[level][a].key == server.keys[level][a].key
    end
  end

  test "application stream admission uses the protected packet and recovery path" do
    {:ok, state, []} = new()
    {:ok, streams, 0} = Streams.open(state.streams, :bidi)
    state = %{state | streams: streams}

    assert {:ok, next, effects} = HandshakeScheduler.send_stream(state, 0, "hello", true)
    assert [%{type: :send, level: :application, bytes: packet}] = effects
    assert byte_size(packet) > 0
    assert next.streams.streams[0].send_final == 5

    assert [%{type: :stream, stream_id: 0, offset: 0, data: "hello", fin: true}] =
             next.recovery.spaces.application.sent[0].metadata.control
  end

  test "opens local streams through the scheduler's bounded stream state" do
    {:ok, state, []} = new()

    assert {:ok, state, 0} = HandshakeScheduler.open_stream(state, :bidi)
    assert {:ok, state, 2} = HandshakeScheduler.open_stream(state, :uni)
    assert state.streams.streams[0].local_initiated
    assert not state.streams.streams[2].bidi
  end

  test "independently decrypted outbound Handshake replays and retransmits without another TLS feed" do
    {:ok, sender, [first]} =
      HandshakeScheduler.new(:client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: WireRecorded
      )

    {:ok, receiver, []} =
      HandshakeScheduler.new(:server, dcid: sender.scid, scid: sender.dcid, adapter: WireRecorded)

    assert {0, <<6, 0, 2, 7, 8>>} = decrypt_packet(first.bytes, sender.keys.handshake.write, 16)
    {:ok, receiver, _} = HandshakeScheduler.receive_datagram(receiver, first.bytes, 1)
    {:ok, receiver, _} = HandshakeScheduler.receive_datagram(receiver, first.bytes, 2)
    assert receiver.tls.tls.received == [<<7, 8>>]

    {:ok, sender, [:sent]} = HandshakeScheduler.local_send(sender, :handshake, 0, :ok, 0)
    original_tls = sender.tls
    {:ok, sender, [retransmission]} = HandshakeScheduler.retry_crypto(sender, :handshake, 0)
    assert sender.tls == original_tls
    assert retransmission.packet_number == 1
    {:ok, receiver, _} = HandshakeScheduler.receive_datagram(receiver, retransmission.bytes, 3)
    assert receiver.tls.tls.received == [<<7, 8>>]
  end

  test "authenticated Handshake rejects HANDSHAKE_DONE at the wrong encryption level" do
    {:ok, state, []} = new()
    packet = peer_handshake(state.keys.handshake.read, <<0x1E, 0, 0>>)

    assert {:error, {:wrong_encryption_level, :handshake_done, :handshake}, ^state} =
             HandshakeScheduler.receive_datagram(state, packet, 10)
  end

  test "NEW_TOKEN is discarded only by clients at the application level" do
    {:ok, client, []} = new()
    plaintext = <<7, 3, "abc">>
    packet = peer_application(client, plaintext)
    assert {:ok, _next, []} = HandshakeScheduler.receive_datagram(client, packet, 10)

    server = %{client | role: :server}

    assert {:error, :unexpected_new_token, ^server} =
             HandshakeScheduler.receive_datagram(server, packet, 10)

    handshake = peer_handshake(client.keys.handshake.read, plaintext)

    assert {:error, {:wrong_encryption_level, :new_token, :handshake}, ^client} =
             HandshakeScheduler.receive_datagram(client, handshake, 10)
  end

  defp peer_application(state, plaintext) do
    keys = state.keys.application.read
    first = 0x40
    prefix = <<first, state.scid::binary>>
    aad = prefix <> <<0>>

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, keys.iv, plaintext, aad, 16, true)

    packet = aad <> ciphertext <> tag
    sample = binary_part(packet, byte_size(prefix) + 4, 16)
    <<mask, pn_mask, _::binary>> = :crypto.crypto_one_time(:aes_128_ecb, keys.hp, sample, true)
    <<_first, cid::binary>> = prefix
    <<bxor(first, band(mask, 0x1F)), cid::binary, pn_mask, ciphertext::binary, tag::binary>>
  end

  test "authenticated ACK cannot acknowledge a packet from a different number space" do
    {:ok, state, []} = new()
    state = %{state | pending: [%{level: :application, offset: 0, bytes: <<1>>}]}
    {:ok, state, [_]} = HandshakeScheduler.schedule(state)
    {:ok, state, [:sent]} = HandshakeScheduler.local_send(state, :application, 0, :ok, 1)
    # ACK largest=0, delay=0, range-count=0, first-range=0, all one-byte varints.
    packet = peer_handshake(state.keys.handshake.read, <<2, 0, 0, 0, 0>>)

    assert {:error, {:invalid_ack, :ack_never_issued}, ^state} =
             HandshakeScheduler.receive_datagram(state, packet, 10)

    assert state.recovery.spaces.application.sent[0].status == :sent
  end

  test "authenticated malformed ACK does not update the receive range" do
    {:ok, state, []} = new()
    packet = peer_handshake(state.keys.handshake.read, <<2, 4, 0, 0, 5>>)

    assert {:error, {:malformed_frame, :malformed_ack_frame}, ^state} =
             HandshakeScheduler.receive_datagram(state, packet, 10)
  end

  test "authenticated frames are rejected outside their encryption level" do
    {:ok, state, []} = new()
    packet = peer_handshake(state.keys.handshake.read, <<0x18, 0, 0, 1, 9, 1::128>>)

    assert {:error, {:wrong_encryption_level, :new_connection_id, :handshake}, ^state} =
             HandshakeScheduler.receive_datagram(state, packet, 10)
  end

  test "authenticated Handshake padding and transport close decode independently" do
    {:ok, state, []} = new()
    packet = peer_handshake(state.keys.handshake.read, <<0, 0x1C, 0, 0, 0>>)

    assert {:ok, _, [%{type: :connection_close, error_code: 0}]} =
             HandshakeScheduler.receive_datagram(state, packet, 10)
  end

  test "builds Handshake CRYPTO with write keys and independent packet number" do
    assert {:ok, state, []} = new()
    state = %{state | pending: [%{level: :handshake, offset: 7, bytes: <<8, 9>>}]}

    assert {:ok, state, [effect]} = HandshakeScheduler.schedule(state)
    assert effect.level == :handshake
    assert effect.packet_number == 0
    assert state.recovery.spaces.handshake.sent[0].metadata.crypto == {7, 2}

    {pn, plaintext} =
      decrypt_packet(effect.bytes, state.keys.handshake.write, 1 + 4 + 1 + 4 + 1 + 4 + 1)

    assert pn == 0

    assert {:ok, [%{type: :crypto, offset: 7, data: <<8, 9>>}], <<>>} =
             Quic.Codec.decode_frames(plaintext)
  end

  test "encodes an Initial connection close in the Initial payload" do
    assert {:ok, state, []} = new()

    state = %{
      state
      | pending_control: %{
          initial: [%{type: :connection_close, error_code: 0, frame_type: 0, reason: "closed"}]
        }
    }

    assert {:ok, _state, [effect]} = HandshakeScheduler.schedule(state)
    assert effect.level == :initial
    assert {:ok, packet} = Quic.Codec.parse_initial(effect.bytes)
    assert byte_size(packet.payload) > 16
  end

  test "builds Application packets with independent packet number space" do
    assert {:ok, state, []} = new()

    state = %{
      state
      | pending: [
          %{level: :handshake, offset: 0, bytes: <<1>>},
          %{level: :application, offset: 0, bytes: <<2>>}
        ]
    }

    assert {:ok, state, effects} = HandshakeScheduler.schedule(state)

    assert Enum.map(effects, &{&1.level, &1.packet_number}) == [
             {:handshake, 0},
             {:application, 0}
           ]

    app = Enum.find(effects, &(&1.level == :application))
    {pn, plaintext} = decrypt_packet(app.bytes, state.keys.application.write, 1 + 4)
    assert pn == 0

    assert {:ok, [%{type: :crypto, offset: 0, data: <<2>>}], <<>>} =
             Quic.Codec.decode_frames(plaintext)
  end

  test "failed local send retains exact packet and next send does not reuse number" do
    assert {:ok, state, []} = new()
    state = %{state | pending: [%{level: :handshake, offset: 0, bytes: <<1>>}]}
    assert {:ok, state, [first]} = HandshakeScheduler.schedule(state)

    assert {:ok, state, [:failed]} =
             HandshakeScheduler.local_send(state, :handshake, 0, {:error, :closed}, 1)

    assert {:ok, retransmit} = HandshakeScheduler.retransmit(state, :handshake, 0)
    assert retransmit.bytes == first.bytes

    state = %{state | pending: [%{level: :handshake, offset: 1, bytes: <<2>>}]}
    assert {:ok, state, [second]} = HandshakeScheduler.schedule(state)
    assert second.packet_number == 1
    assert state.recovery.spaces.handshake.sent[0].status == :failed
  end

  test "ACK updates the matching Handshake recovery space" do
    assert {:ok, state, []} = new()
    state = %{state | pending: [%{level: :handshake, offset: 0, bytes: <<1>>}]}
    assert {:ok, state, [effect]} = HandshakeScheduler.schedule(state)
    assert {:ok, state, [:sent]} = HandshakeScheduler.local_send(state, :handshake, 0, :ok, 2)

    assert {:ok, state, %{acked: [0]}} =
             HandshakeScheduler.receive_ack(
               state,
               :handshake,
               %{largest: 0, ranges: [{0, 0}]},
               3
             )

    assert state.recovery.spaces.handshake.sent[effect.packet_number].status == :acked
  end
end

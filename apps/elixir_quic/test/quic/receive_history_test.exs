defmodule Quic.ReceiveHistoryTest do
  use ExUnit.Case, async: true
  import Bitwise
  alias Quic.{Codec, HandshakeScheduler, Protection, Recovery}

  defmodule TLS do
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

  test "sparse authenticated receive history remains bounded across connection lifetime" do
    for space <- [:initial, :handshake, :application], limit <- [1, 2, 256] do
      state =
        Enum.reduce(0..1_024, Recovery.new(max_ack_ranges: limit), fn index, state ->
          assert {:ok, next} = Recovery.note_received(state, space, index * 2)
          assert length(next.spaces[space].ack_ranges) <= limit
          assert next.spaces[space].largest_received == index * 2
          next
        end)

      assert List.last(state.spaces[space].ack_ranges) == {2_048, 2_048}
      assert {:ok, ^state} = Recovery.note_received(state, space, 0)
      assert {:ok, ^state} = Recovery.note_received(state, space, 1)
    end
  end

  test "receive range budget requires at least one encodable ACK range" do
    for limit <- [0, -1, 257, :invalid] do
      assert_raise ArgumentError, fn -> Recovery.new(max_ack_ranges: limit) end
    end
  end

  test "recent reordering merges gaps while retired numbers cannot refill history" do
    state =
      Enum.reduce([0, 2, 4, 6], Recovery.new(max_ack_ranges: 2), fn number, state ->
        assert {:ok, next} = Recovery.note_received(state, :application, number)
        next
      end)

    assert state.spaces.application.ack_ranges == [{4, 4}, {6, 6}]
    assert {:ok, ^state} = Recovery.note_received(state, :application, 2)
    assert {:ok, state} = Recovery.note_received(state, :application, 5)
    assert state.spaces.application.ack_ranges == [{4, 6}]
    assert {:ok, state} = Recovery.note_received(state, :application, 3)
    assert state.spaces.application.ack_ranges == [{3, 6}]
    assert state.spaces.application.largest_received == 6
  end

  test "discard resets only its receive epoch and retirement stays terminal" do
    state = Recovery.new(max_ack_ranges: 1)
    {:ok, state} = Recovery.note_received(state, :initial, 10)
    assert {:ok, state} = Recovery.note_received(state, :initial, 12)
    {:ok, state} = Recovery.note_received(state, :application, 8)
    state = Recovery.discard_space(state, :initial)
    assert {:ok, state} = Recovery.note_received(state, :initial, 0)
    assert state.spaces.initial.ack_ranges == [{0, 0}]
    assert state.spaces.application.ack_ranges == [{8, 8}]
    state = Recovery.retire_space(state, :initial)
    assert {:error, :retired_space} = Recovery.note_received(state, :initial, 0)
  end

  test "retained duplicate is acknowledged without repeating DATAGRAM or STREAM effects" do
    state = scheduler()
    frames = [data(0, "a"), %{type: :datagram, data: "once"}]
    bytes = packet(state, 0, frames)
    assert {:ok, state, events} = HandshakeScheduler.receive_datagram(state, bytes, 1)
    assert Enum.any?(events, &(&1.type == :stream))
    assert Enum.any?(events, &(&1.type == :datagram))
    {:ok, state, sends} = HandshakeScheduler.schedule(state)
    assert sends != []
    assert {:ok, next, events} = HandshakeScheduler.receive_datagram(state, bytes, 2)
    refute Enum.any?(events, &(&1.type in [:stream, :datagram]))
    assert next.streams == state.streams
    assert {:ok, _, [_ack]} = HandshakeScheduler.schedule(next)
  end

  test "retired packet cannot repeat effects and missing bytes recover under a fresh number" do
    state = scheduler(max_ack_ranges: 2)
    first = packet(state, 0, [data(0, "a")])
    {:ok, state, _} = HandshakeScheduler.receive_datagram(state, first, 0)

    {:ok, state, _} =
      HandshakeScheduler.receive_datagram(state, packet(state, 2, [data(2, "c")]), 1)

    assert {:ok, state, _} =
             HandshakeScheduler.receive_datagram(state, packet(state, 4, [%{type: :ping}]), 2)

    {:ok, state, _} =
      HandshakeScheduler.receive_datagram(state, packet(state, 6, [%{type: :ping}]), 3)

    streams = state.streams
    assert {:ok, state, events} = HandshakeScheduler.receive_datagram(state, first, 3)
    refute Enum.any?(events, &(&1.type == :stream))
    assert state.streams == streams

    # PN 1 is too old even though unseen; retransmission under fresh PN 8 fills
    # the stream gap, so bounded packet history cannot discard reliable bytes.
    old_missing = packet(state, 1, [data(1, "b")])
    assert {:ok, ^state, _} = HandshakeScheduler.receive_datagram(state, old_missing, 4)

    assert {:ok, next, events} =
             HandshakeScheduler.receive_datagram(state, packet(state, 8, [data(1, "b")]), 5)

    delivered =
      for event <- events, {:data, 1, bytes} <- Map.get(event, :events, []), into: <<>>, do: bytes

    assert delivered == "bc"
    assert next.recovery.spaces.application.largest_received == 8
    assert {:ok, next, sends} = HandshakeScheduler.schedule(next)
    frames = Enum.flat_map(sends, &decode_ack(next, &1))

    assert [%{type: :ack, largest: 8, ranges: [{8, 8}, {6, 6}]}] =
             Enum.filter(frames, &(&1.type == :ack))
  end

  test "old and retained packet numbers never bypass authentication" do
    state = scheduler(max_ack_ranges: 1)

    state =
      Enum.reduce([0, 2], state, fn number, state ->
        {:ok, next, _} =
          HandshakeScheduler.receive_datagram(
            state,
            packet(state, number, [data(number, "a")]),
            0
          )

        next
      end)

    for number <- [0, 2] do
      bytes = packet(state, number, [data(number, "a")])
      size = byte_size(bytes) - 1
      <<prefix::binary-size(^size), last>> = bytes
      damaged = prefix <> <<bxor(last, 1)>>
      assert {:error, _reason, ^state} = HandshakeScheduler.receive_datagram(state, damaged, 1)
    end
  end

  test "ACK-only duplicates do not create an ACK loop or repeat ACK processing" do
    state = scheduler()

    {:ok, state, _} =
      HandshakeScheduler.receive_datagram(state, packet(state, 0, [%{type: :ping}]), 0)

    {:ok, state, [_]} = HandshakeScheduler.schedule(state)

    frames = [%{type: :ack, largest: 0, delay: 0, ranges: [{0, 0}]}]

    bytes = packet(state, 1, frames)
    assert {:ok, state, _} = HandshakeScheduler.receive_datagram(state, bytes, 1)
    expected = %{state | authenticated_packets: state.authenticated_packets + 1}
    assert {:ok, ^expected, []} = HandshakeScheduler.receive_datagram(state, bytes, 2)
    assert {:ok, _, []} = HandshakeScheduler.schedule(state)
  end

  defp decode_ack(state, effect) do
    secret = <<2::256>>
    key = expand(secret, "quic key", 16)
    iv = expand(secret, "quic iv", 12)
    hp = expand(secret, "quic hp", 16)
    offset = 1 + byte_size(state.dcid)

    {:ok, bytes, length} =
      Protection.remove_header_protection(effect.bytes, offset, hp, :aes_128_gcm)

    <<_header::binary-size(^offset), number::binary-size(^length), ciphertext::binary>> = bytes
    number = :binary.decode_unsigned(number)
    aad = binary_part(bytes, 0, offset + length)
    {:ok, plaintext} = Protection.aead_decrypt(key, iv, number, aad, ciphertext)
    {:ok, frames, <<>>} = Codec.decode_frames(plaintext)
    frames
  end

  defp scheduler(opts \\ []) do
    {:ok, state, []} =
      HandshakeScheduler.new(:client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: TLS,
        max_datagram_frame_size: 1200,
        recovery: Recovery.new(opts)
      )

    state
  end

  defp data(offset, bytes),
    do: %{type: :stream, stream_id: 1, offset: offset, data: bytes, fin: false}

  # Independent RFC 8446 HKDF label and RFC 9001 short-packet protection.
  defp expand(secret, label, length) do
    label = "tls13 " <> label
    info = <<length::16, byte_size(label), label::binary, 0, 1>>
    binary_part(:crypto.mac(:hmac, :sha256, secret, info), 0, length)
  end

  defp packet(state, number, frames) do
    secret = <<1::256>>
    key = expand(secret, "quic key", 16)
    iv = expand(secret, "quic iv", 12)
    hp = expand(secret, "quic hp", 16)
    aad = <<0x43, state.scid::binary, number::32>>
    nonce = :crypto.exor(iv, <<0::32, number::64>>)
    {:ok, plaintext} = Codec.encode_frames(frames)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_128_gcm, key, nonce, plaintext, aad, true)

    bytes = aad <> ciphertext <> tag
    offset = 1 + byte_size(state.scid)
    mask = :crypto.crypto_one_time(:aes_128_ecb, hp, binary_part(bytes, offset + 4, 16), true)
    <<first, cid::binary-size(4), pn::binary-size(4), tail::binary>> = bytes
    pn = :crypto.exor(pn, binary_part(mask, 1, 4))
    <<bxor(first, :binary.at(mask, 0) &&& 0x1F), cid::binary, pn::binary, tail::binary>>
  end
end

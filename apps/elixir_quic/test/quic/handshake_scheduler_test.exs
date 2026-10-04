defmodule Quic.HandshakeSchedulerTest do
  use ExUnit.Case, async: true

  alias Quic.{Codec, HandshakeScheduler, Protection}

  defmodule Recorded do
    defstruct [:phase]

    def new(_, _), do: {:ok, %__MODULE__{phase: :initial}, [{:emit, :initial, <<1, 2>>}]}
    def info(%__MODULE__{phase: phase}), do: %{receive_level: phase}
    def abort(state, _), do: state

    def feed(%__MODULE__{phase: :initial} = state, :initial, <<9>>) do
      {:ok, %{state | phase: :handshake}, [{:emit, :initial, <<3>>}]}
    end

    def feed(state, _level, _bytes),
      do: {:error, %{kind: :quic, reason: :unexpected}, state, []}
  end

  defmodule RecordedSecret do
    defstruct [:phase]

    def new(_, _),
      do:
        {:ok, %__MODULE__{phase: :initial},
         [secret(:handshake, :read), secret(:handshake, :write, :b)]}

    def info(%__MODULE__{phase: phase}), do: %{receive_level: phase}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}

    def secret(level, direction, value \\ :a) do
      %SSL.QUIC.Secret{
        level: level,
        direction: direction,
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: :binary.copy(if(value == :b, do: <<2>>, else: <<1>>), 32)
      }
    end
  end

  defmodule DuplicateSecret do
    def new(_, _),
      do:
        {:ok, %{},
         [RecordedSecret.secret(:handshake, :read), RecordedSecret.secret(:handshake, :read)]}

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}
  end

  defmodule ConflictingSecret do
    def new(_, _),
      do:
        {:ok, %{},
         [RecordedSecret.secret(:handshake, :read), RecordedSecret.secret(:handshake, :read, :b)]}

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}
  end

  defmodule UnsupportedSecret do
    def new(_, _),
      do:
        {:ok, %{},
         [
           %SSL.QUIC.Secret{
             level: :handshake,
             direction: :write,
             cipher_suite: 0x1301,
             aead: :aes_256_gcm,
             hkdf: :sha256,
             secret: <<0::256>>
           }
         ]}

    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}
  end

  defmodule InboundRecorded do
    defstruct [:received]

    def new(_, _), do: {:ok, %__MODULE__{received: []}, []}
    def info(_), do: %{receive_level: :initial}
    def abort(state, _), do: state

    def feed(state, :initial, bytes),
      do: {:ok, %{state | received: state.received ++ [bytes]}, []}

    def feed(state, _level, _bytes),
      do: {:error, %{kind: :quic, reason: :unexpected_level}, state, []}
  end

  defmodule LargeFlight do
    defstruct [:phase]

    def new(_, _),
      do: {:ok, %__MODULE__{phase: :initial}, [{:emit, :initial, :binary.copy(<<7>>, 4000)}]}

    def info(%__MODULE__{phase: phase}), do: %{receive_level: phase}
    def abort(state, _), do: state
    def feed(state, _level, _bytes), do: {:ok, state, []}
  end

  defmodule EmitThenInvalidParameters do
    def new(_, _), do: {:ok, :initial, []}
    def info(phase), do: %{receive_level: phase}
    def abort(state, _), do: state

    def feed(_, :initial, _),
      do:
        {:ok, :application,
         [
           {:emit, :handshake, <<7, 8, 9>>},
           {:peer_transport_parameters, <<3, 2, 0x44, 0xAF, 15, 4, 1, 2, 3, 4>>, :authenticated}
         ]}
  end

  defp new(opts \\ []) do
    HandshakeScheduler.new(
      :client,
      [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: Recorded, min_initial_size: 0]
      |> Keyword.merge(opts)
    )
  end

  defp new_with(adapter) do
    HandshakeScheduler.new(
      :client,
      dcid: <<1, 2, 3, 4>>,
      scid: <<5, 6, 7, 8>>,
      adapter: adapter,
      min_initial_size: 0
    )
  end

  test "Retry authenticates the original CID and reuses TLS bytes under fresh packet numbers" do
    {:ok, state, [first]} = new(min_initial_size: 1200)
    {:ok, state, [:sent]} = HandshakeScheduler.local_send(state, :initial, 0, :ok, 0)
    retry_cid = <<9, 10, 11, 12>>
    token = :binary.copy(<<42>>, 200)

    body =
      <<0xF0, 1::32, byte_size(state.scid), state.scid::binary, byte_size(retry_cid),
        retry_cid::binary, token::binary>>

    {:ok, tag} = Protection.retry_tag(state.original_dcid, body)
    retry = body <> tag

    {:ok, next, [%{type: :retry, generated: [resent]}]} =
      HandshakeScheduler.receive_datagram(state, retry, 1)

    assert next.tls == state.tls
    assert next.original_dcid == state.original_dcid
    assert next.retry_scid == retry_cid
    assert next.recovery.spaces.initial.sent[0].status == :discarded
    assert resent.packet_number == first.packet_number + 1
    assert byte_size(resent.bytes) >= 1200
    {:ok, parsed} = Codec.parse_initial(resent.bytes)
    assert parsed.token == token
    assert parsed.dcid == retry_cid
    {:ok, expected} = Protection.initial_secrets(retry_cid, :client)
    assert next.keys.initial == expected

    assert {:error, :unexpected_retry, ^next} =
             HandshakeScheduler.receive_datagram(next, retry, 2)

    <<last, tail::binary>> = tag
    corrupted = body <> <<Bitwise.bxor(last, 1), tail::binary>>

    assert {:error, :invalid_retry_tag, ^state} =
             HandshakeScheduler.receive_datagram(state, corrupted, 1)
  end

  test "fragments a large TLS flight with contiguous offsets and bounded packets" do
    assert {:ok, state, effects} =
             HandshakeScheduler.new(
               :client,
               dcid: <<1, 2, 3, 4>>,
               scid: <<5, 6, 7, 8>>,
               adapter: LargeFlight,
               max_packet_size: 1300,
               min_initial_size: 1200
             )

    sends = Enum.filter(effects, &(&1.type == :send))
    assert length(sends) > 2
    assert Enum.all?(sends, &(byte_size(&1.bytes) <= 1300))
    assert Enum.map(sends, & &1.packet_number) == Enum.to_list(0..(length(sends) - 1))

    ranges =
      sends
      |> Enum.map(fn send ->
        packet = state.recovery.spaces.initial.sent[send.packet_number]
        packet.metadata.crypto
      end)
      |> Enum.sort()

    assert hd(ranges) == {0, elem(Enum.at(ranges, 0), 1)}

    assert ranges
           |> Enum.chunk_every(2, 1, :discard)
           |> Enum.all?(fn [{offset, length}, {next, _}] -> offset + length == next end)

    assert Enum.reduce(ranges, 0, fn {_offset, length}, total -> total + length end) == 4000
  end

  test "rejects invalid authenticated parameters before committing same-batch emissions" do
    {:ok, state, []} = new_with(EmitThenInvalidParameters)
    state = %{state | peer_initial_scid: <<5, 6, 7, 8>>}

    assert {:error, {:transport_parameters, :invalid_max_udp_payload_size}, next, []} =
             HandshakeScheduler.feed(state, :initial, 0, <<1>>)

    assert next.pending == []
  end

  test "installs directional QUIC keys from recorded TLS secrets" do
    result = new_with(RecordedSecret)
    assert {:ok, state, _effects} = result

    assert %{
             read: %{key: read_key},
             write: %{key: write_key, iv: iv, hp: hp, hp_algorithm: :aes_128_gcm}
           } =
             state.keys.handshake

    refute read_key == write_key
    assert byte_size(read_key) == 16
    assert byte_size(write_key) == 16
    assert byte_size(iv) == 12
    assert byte_size(hp) == 16
  end

  test "rejects duplicate and conflicting directional secret installs" do
    assert {:error, {:duplicate_secret, :handshake, :read}, _state} = new_with(DuplicateSecret)

    assert {:error, {:conflicting_secret, :handshake, :read}, _state} =
             new_with(ConflictingSecret)
  end

  test "rejects unsupported secret algorithm combinations" do
    assert {:error, {:unsupported_cipher_suite, 0x1301}, _state} = new_with(UnsupportedSecret)
  end

  test "TLS Initial emission becomes a protected CRYPTO send effect" do
    assert {:ok, state, [effect]} = new()
    assert %{type: :send, level: :initial, packet_number: 0, bytes: packet} = effect
    assert state.recovery.spaces.initial.sent[0].status == :queued

    assert state.tls.levels.initial.sent == [
             %Quic.TLSDriver.Emission{offset: 0, level: :initial, bytes: <<1, 2>>}
           ]

    assert {:ok, parsed} = Codec.parse_initial(packet)
    assert {:ok, keys} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)
    pn_offset = byte_size(packet) - byte_size(parsed.payload) - parsed.packet_number_length

    assert {:ok, unprotected, pn_len} =
             Protection.remove_header_protection(packet, pn_offset, keys.hp, :aes_128_gcm)

    <<aad::binary-size(^pn_offset), pn::binary-size(^pn_len), ciphertext::binary>> = unprotected

    assert {:ok, plaintext} =
             Protection.aead_decrypt(
               keys.key,
               keys.iv,
               :binary.decode_unsigned(pn),
               aad <> pn,
               ciphertext
             )

    assert {:ok, [%{type: :crypto, offset: 0, data: <<1, 2>>}], <<>>} =
             Codec.decode_frames(plaintext)
  end

  test "local send states and exact retransmit are separate from admission" do
    assert {:ok, state, [effect]} = new()
    packet = effect.bytes

    assert {:ok, state, [:failed]} =
             HandshakeScheduler.local_send(state, :initial, 0, {:error, :writer_down}, 10)

    assert {:ok, retransmit} = HandshakeScheduler.retransmit(state, :initial, 0)
    assert retransmit.bytes == packet
    assert retransmit.retransmit

    assert {:ok, state, [next]} = HandshakeScheduler.feed(state, :initial, 0, <<9>>)
    assert next.packet_number == 1
    assert state.recovery.spaces.initial.sent[0].status == :failed
  end

  test "CRYPTO retransmission reserves a fresh packet number without another TLS call" do
    {:ok, state, [first]} = new()

    {:ok, state, [:failed]} =
      HandshakeScheduler.local_send(state, :initial, 0, {:error, :closed}, 10)

    tls_before = state.tls

    assert {:ok, next, [retry]} =
             HandshakeScheduler.retry_crypto(state, :initial, first.packet_number)

    assert retry.packet_number == 1
    refute retry.bytes == first.bytes
    assert next.tls == tls_before

    assert next.recovery.spaces.initial.sent[1].metadata.crypto ==
             state.recovery.spaces.initial.sent[0].metadata.crypto

    assert next.recovery.spaces.initial.sent[0].status == :failed
    assert {:ok, _, [:sent]} = HandshakeScheduler.local_send(next, :initial, 1, :ok, -100)
    assert {:error, :unknown_packet} = HandshakeScheduler.retry_crypto(next, :handshake, 0)
  end

  test "ACK is queued into the next packet and peer accounting remains explicit" do
    assert {:ok, state, [effect]} = new()

    state =
      HandshakeScheduler.queue_ack(state, :initial, %{
        type: :ack,
        largest: 3,
        delay: 0,
        ranges: [{3, 3}]
      })

    assert {:ok, state, [ack_effect]} = HandshakeScheduler.schedule(state)
    assert ack_effect.type == :send
    refute Map.has_key?(state.pending_acks, :initial)

    assert {:ok, state, [:sent]} =
             HandshakeScheduler.local_send(state, :initial, effect.packet_number, :ok, 20)

    assert {:ok, state, result} =
             HandshakeScheduler.receive_ack(state, :initial, %{largest: 0, ranges: [{0, 0}]}, 30)

    assert result.acked == [0]
    assert state.recovery.spaces.initial.sent[0].status == :acked
  end

  test "unsupported handshake level and queue limits are explicit" do
    assert {:ok, state, _} = new()
    state = %{state | pending: [%{level: :handshake, offset: 0, bytes: <<1>>}]}
    assert {:error, {:unsupported_level, :handshake}, ^state} = HandshakeScheduler.schedule(state)

    assert {:error, :send_queue_limit, _limited} = new(max_queue: 0)
  end

  test "authenticated Initial datagram dispatches CRYPTO exactly once" do
    {:ok, sender, [effect]} =
      HandshakeScheduler.new(
        :client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: Recorded,
        min_initial_size: 0
      )

    {:ok, initial_read} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)

    {:ok, receiver, []} =
      HandshakeScheduler.new(
        :client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: InboundRecorded,
        initial_read_keys: initial_read,
        min_initial_size: 0
      )

    assert {:ok, receiver, events} =
             HandshakeScheduler.receive_datagram(receiver, effect.bytes, 10)

    assert [%{type: :crypto, offset: 0, bytes: <<1, 2>>}] = events
    assert receiver.tls.tls.received == [<<1, 2>>]

    assert {:ok, duplicate, [_duplicate_event]} =
             HandshakeScheduler.receive_datagram(receiver, effect.bytes, 11)

    assert duplicate.tls.tls.received == [<<1, 2>>]
    assert duplicate.recovery.spaces.initial.largest_received == 0
    assert sender.recovery.spaces.initial.sent[0].status == :queued
  end

  test "coalesced packets advance offsets in order and retain an accepted prefix on trailing corruption" do
    {:ok, sender, [first]} = new()
    {:ok, _sender, [second]} = HandshakeScheduler.feed(sender, :initial, 0, <<9>>)
    {:ok, keys} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)

    {:ok, receiver, []} =
      HandshakeScheduler.new(:client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: InboundRecorded,
        initial_read_keys: keys,
        min_initial_size: 0
      )

    assert {:ok, next, events} =
             HandshakeScheduler.receive_datagram(receiver, first.bytes <> second.bytes, 10)

    assert next.tls.tls.received == [<<1, 2>>, <<3>>]
    assert [%{type: :crypto, offset: 0}, %{type: :crypto, offset: 2}] = events

    assert {:ok, prefix, events} =
             HandshakeScheduler.receive_datagram(receiver, first.bytes <> <<1>>, 10)

    assert prefix.tls.tls.received == [<<1, 2>>]
    assert [%{type: :crypto}, %{type: :discard, reason: :truncated_header}] = events

    assert {:error, :datagram_size_limit, ^receiver} =
             HandshakeScheduler.receive_datagram(receiver, :binary.copy(<<0>>, 65_528), 10)
  end

  test "bad tags and malformed packets leave scheduler state unchanged" do
    assert {:ok, sender, [effect]} = new()
    {:ok, initial_read} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)

    assert {:ok, receiver, []} =
             HandshakeScheduler.new(
               :client,
               dcid: <<1, 2, 3, 4>>,
               scid: <<5, 6, 7, 8>>,
               adapter: InboundRecorded,
               initial_read_keys: initial_read,
               min_initial_size: 0
             )

    effect_size = byte_size(effect.bytes)
    prefix_size = effect_size - 1
    <<prefix::binary-size(^prefix_size), last>> = effect.bytes
    tampered = prefix <> <<Bitwise.bxor(last, 1)>>
    assert {:error, :bad_tag, ^receiver} = HandshakeScheduler.receive_datagram(receiver, tampered)

    assert {:error, :truncated_header, ^receiver} =
             HandshakeScheduler.receive_datagram(receiver, <<1>>)

    assert sender.recovery.spaces.initial.sent[0].status == :queued
  end

  test "inbound ACK updates Recovery after authenticated decode" do
    assert {:ok, state, [effect]} = new()
    assert {:ok, state, [:sent]} = HandshakeScheduler.local_send(state, :initial, 0, :ok, 1)

    state =
      HandshakeScheduler.queue_ack(state, :initial, %{
        type: :ack,
        largest: 0,
        delay: 0,
        ranges: [{0, 0}]
      })

    assert {:ok, state, [ack_effect]} = HandshakeScheduler.schedule(state)

    {:ok, read_keys} = Protection.initial_secrets(<<1, 2, 3, 4>>, :client)
    receiver = %{state | read_keys: %{initial: read_keys}}

    assert {:ok, receiver, events} =
             HandshakeScheduler.receive_datagram(receiver, ack_effect.bytes, 20)

    assert Enum.any?(events, &(&1.type == :ack))
    assert receiver.recovery.spaces.initial.sent[0].status == :acked
    assert effect.packet_number == 0
  end
end

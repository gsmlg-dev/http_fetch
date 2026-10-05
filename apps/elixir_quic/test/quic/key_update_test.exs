defmodule Quic.KeyUpdateTest do
  use ExUnit.Case, async: true
  import Bitwise
  alias Quic.{Codec, HandshakeScheduler, Protection, Recovery}

  defmodule Recorded do
    def new(_, _) do
      secrets =
        for {direction, value} <- [read: 1, write: 2] do
          %SSL.QUIC.Secret{
            level: :application,
            direction: direction,
            cipher_suite: 0x1301,
            aead: :aes_128_gcm,
            hkdf: :sha256,
            secret: <<value::256>>
          }
        end

      {:ok, 0, secrets}
    end

    def info(_), do: %{receive_level: :application}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defp scheduler(confirmed \\ true) do
    {:ok, state, []} =
      HandshakeScheduler.new(:client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: Recorded,
        min_initial_size: 0
      )

    state = %{state | tls: %{state.tls | facts: %{state.tls.facts | tls_complete: true}}}
    if confirmed, do: HandshakeScheduler.confirm_handshake(state), else: state
  end

  # Independent RFC8446 single-block HKDF-Expand-Label and RFC9001 protection.
  defp expand(secret, label, length) do
    label = "tls13 " <> label
    info = <<length::16, byte_size(label), label::binary, 0, 1>>
    binary_part(:crypto.mac(:hmac, :sha256, secret, info), 0, length)
  end

  defp secret(value, generation) do
    Enum.reduce(1..generation//1, <<value::256>>, fn _, acc -> expand(acc, "quic ku", 32) end)
  end

  defp keys(value, generation) do
    secret = secret(value, generation)

    %{
      key: expand(secret, "quic key", 16),
      iv: expand(secret, "quic iv", 12),
      hp: expand(<<value::256>>, "quic hp", 16)
    }
  end

  defp packet(state, generation, pn, plaintext \\ <<1, 0, 0, 0>>) do
    keys = keys(1, generation)
    aad = <<0x43 ||| rem(generation, 2) <<< 2, state.scid::binary, pn::32>>
    nonce = :crypto.exor(keys.iv, <<0::32, pn::64>>)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, nonce, plaintext, aad, true)

    bytes = aad <> ciphertext <> tag
    offset = 1 + byte_size(state.scid)

    mask =
      :crypto.crypto_one_time(:aes_128_ecb, keys.hp, binary_part(bytes, offset + 4, 16), true)

    <<first, cid::binary-size(4), number::binary-size(4), tail::binary>> = bytes
    number = :crypto.exor(number, binary_part(mask, 1, 4))
    <<bxor(first, :binary.at(mask, 0) &&& 0x1F), cid::binary, number::binary, tail::binary>>
  end

  defp damage(bytes) do
    size = byte_size(bytes) - 1
    <<prefix::binary-size(^size), last>> = bytes
    prefix <> <<bxor(last, 1)>>
  end

  defp decode_ack(state, effect, generation) do
    keys = keys(2, generation)
    offset = 1 + byte_size(state.dcid)

    {:ok, bytes, pn_length} =
      Protection.remove_header_protection(effect.bytes, offset, keys.hp, :aes_128_gcm)

    <<first, _cid::binary-size(4), number::binary-size(^pn_length), ciphertext::binary>> = bytes
    assert (first >>> 2 &&& 1) == rem(generation, 2)
    pn = :binary.decode_unsigned(number)
    aad = binary_part(bytes, 0, offset + pn_length)
    nonce = :crypto.exor(keys.iv, <<0::32, pn::64>>)
    size = byte_size(ciphertext) - 16
    <<ciphertext::binary-size(^size), tag::binary-size(16)>> = ciphertext

    plaintext =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, nonce, ciphertext, aad, tag, false)

    assert is_binary(plaintext)
    {:ok, frames, <<>>} = Codec.decode_frames(plaintext)
    assert Enum.any?(frames, &(&1.type == :ack))
  end

  test "authenticated phase change updates read keys and outgoing ACK with unchanged HP" do
    state = scheduler()
    {:ok, state, _} = HandshakeScheduler.receive_datagram(state, packet(state, 0, 83), 100)
    assert {:ok, next, _} = HandshakeScheduler.receive_datagram(state, packet(state, 1, 84), 200)
    assert next.recovery.spaces.application.largest_received == 84
    assert next.keys.application.read.hp == state.keys.application.read.hp
    assert next.keys.application.write.hp == state.keys.application.write.hp
    {:ok, next, [ack]} = HandshakeScheduler.schedule(next)
    decode_ack(next, ack, 1)
  end

  test "reordered old phase authenticates without rolling back current keys" do
    state = scheduler()
    {:ok, next, _} = HandshakeScheduler.receive_datagram(state, packet(state, 1, 10), 100)
    current_keys = next.keys

    assert {:ok, reordered, _} =
             HandshakeScheduler.receive_datagram(next, packet(state, 0, 9), 101)

    assert reordered.keys == current_keys
    assert reordered.recovery.spaces.application.largest_received == 10

    assert Enum.any?(reordered.recovery.spaces.application.ack_ranges, fn {lo, hi} ->
             lo <= 9 and hi >= 9
           end)
  end

  test "tampered next phase cannot mutate state; the valid packet still transitions" do
    state = scheduler()
    bytes = packet(state, 1, 10)

    assert {:error, :bad_tag, ^state} =
             HandshakeScheduler.receive_datagram(state, damage(bytes), 100)

    assert {:ok, _, _} = HandshakeScheduler.receive_datagram(state, bytes, 101)
  end

  test "authenticated update before confirmation is KEY_UPDATE_ERROR" do
    state = scheduler(false)

    assert {:error, {:key_update_error, :handshake_unconfirmed}, ^state} =
             HandshakeScheduler.receive_datagram(state, packet(state, 1, 10), 100)
  end

  test "phase wraps after ACK is sent and only one previous generation is retained" do
    state = scheduler()
    {:ok, first, _} = HandshakeScheduler.receive_datagram(state, packet(state, 1, 10), 100)

    assert {:error, {:key_update_error, :update_unacknowledged}, ^first} =
             HandshakeScheduler.receive_datagram(first, packet(state, 2, 20), 101)

    {:ok, first, [ack]} = HandshakeScheduler.schedule(first)

    {:ok, first, [:sent]} =
      HandshakeScheduler.local_send(first, :application, ack.packet_number, :ok, 102)

    assert {:ok, second, _} =
             HandshakeScheduler.receive_datagram(first, packet(state, 2, 20), 103)

    {:ok, second, [ack]} = HandshakeScheduler.schedule(second)
    decode_ack(second, ack, 2)

    assert {:ok, reordered, _} =
             HandshakeScheduler.receive_datagram(second, packet(state, 1, 19), 104)

    assert reordered.keys == second.keys

    assert {:error, :bad_tag, ^second} =
             HandshakeScheduler.receive_datagram(second, packet(state, 0, 9), 104)
  end

  test "previous read keys expire after three PTOs" do
    state = scheduler()
    at = 100
    {:ok, next, _} = HandshakeScheduler.receive_datagram(state, packet(state, 1, 10), at)
    expires = at + 3 * Recovery.pto_duration(state.recovery)

    assert {:error, :bad_tag, ^next} =
             HandshakeScheduler.receive_datagram(next, packet(state, 0, 9), expires)

    assert {:ok, _, _} = HandshakeScheduler.receive_datagram(next, packet(state, 1, 11), expires)
  end

  test "a new phase cannot use a PN below authenticated previous-phase packets" do
    state = scheduler()
    {:ok, state, _} = HandshakeScheduler.receive_datagram(state, packet(state, 0, 10), 100)

    assert {:error, {:key_update_error, :packet_number}, ^state} =
             HandshakeScheduler.receive_datagram(state, packet(state, 1, 9), 101)
  end

  defmodule InitialRecorded do
    def new(_, _), do: {:ok, 0, [{:emit, :initial, <<1, 2>>}]}
    def info(_), do: %{receive_level: :initial}
    def feed(state, _, _), do: {:ok, state + 1, []}
    def abort(state, _), do: state
  end

  test "connection discards only failed authentication without changing state or idle deadline" do
    alias Quic.Connection
    alias Quic.IO.GenUDP
    {:ok, peer} = GenUDP.open()
    {:ok, writer} = GenUDP.open()
    opts = [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: InitialRecorded]

    {:ok, conn} =
      Connection.start_link(
        role: :server,
        io: {GenUDP, writer},
        remote: GenUDP.local(peer),
        scheduler: opts,
        handshake_timeout: 5_000
      )

    on_exit(fn ->
      if Process.alive?(conn), do: Connection.close(conn)
      if Process.alive?(writer), do: GenUDP.close(writer)
      if Process.alive?(peer), do: GenUDP.close(peer)
    end)

    {:ok, _, [initial]} = HandshakeScheduler.new(:client, opts)
    before = :sys.get_state(conn)
    generation = Connection.status(conn).generation

    assert :ok =
             Connection.deliver(conn, generation, damage(initial.bytes), GenUDP.monotonic_time())

    assert :sys.get_state(conn) == before
    assert :ok = Connection.deliver(conn, generation, initial.bytes, GenUDP.monotonic_time())
    assert :sys.get_state(conn) != before
    assert Process.alive?(conn)
  end
end

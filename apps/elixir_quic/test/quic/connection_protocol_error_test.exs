defmodule Quic.ConnectionProtocolErrorTest do
  use ExUnit.Case, async: true

  import Bitwise
  alias Quic.{Codec, Connection, Protection}

  # RFC 9000 section 10.2 and 11: an authenticated 1-RTT protocol violation closes
  # the connection with a CONNECTION_CLOSE carrying the section 20.1 code instead
  # of being dropped silently.

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

  defmodule Writer do
    def send(pid, bytes, _remote) do
      Kernel.send(pid, {:sent, bytes})
      {:ok, System.monotonic_time(:microsecond)}
    end

    def monotonic_time, do: System.monotonic_time(:microsecond)
  end

  @scid <<5, 6, 7, 8>>
  @dcid <<1, 2, 3, 4>>

  defp start do
    {:ok, conn} =
      Connection.start_link(
        role: :client,
        io: {Writer, self()},
        remote: {{127, 0, 0, 1}, 1234},
        handshake_timeout: 5_000,
        scheduler: [dcid: @dcid, scid: @scid, adapter: Recorded, min_initial_size: 0]
      )

    {conn, Connection.status(conn).generation}
  end

  defp expand(secret, label, length) do
    label = "tls13 " <> label
    info = <<length::16, byte_size(label), label::binary, 0, 1>>
    binary_part(:crypto.mac(:hmac, :sha256, secret, info), 0, length)
  end

  defp keys(value, generation) do
    secret =
      Enum.reduce(1..generation//1, <<value::256>>, fn _, acc -> expand(acc, "quic ku", 32) end)

    %{
      key: expand(secret, "quic key", 16),
      iv: expand(secret, "quic iv", 12),
      hp: expand(<<value::256>>, "quic hp", 16)
    }
  end

  defp packet(frames, pn, generation \\ 0) do
    plaintext = if is_binary(frames), do: frames, else: encode(frames)
    keys = keys(1, generation)
    aad = <<0x43 ||| rem(generation, 2) <<< 2, @scid::binary, pn::32>>
    nonce = :crypto.exor(keys.iv, <<0::32, pn::64>>)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, nonce, plaintext, aad, true)

    bytes = aad <> ciphertext <> tag
    offset = 1 + byte_size(@scid)

    mask =
      :crypto.crypto_one_time(:aes_128_ecb, keys.hp, binary_part(bytes, offset + 4, 16), true)

    <<first, cid::binary-size(4), number::binary-size(4), tail::binary>> = bytes
    number = :crypto.exor(number, binary_part(mask, 1, 4))
    <<bxor(first, :binary.at(mask, 0) &&& 0x1F), cid::binary, number::binary, tail::binary>>
  end

  defp encode(frames) do
    {:ok, bytes} = Codec.encode_frames(frames)
    bytes
  end

  defp stream(id, offset, data, fin \\ false),
    do: %{type: :stream, stream_id: id, offset: offset, data: data, fin: fin}

  defp deliver(conn, generation, bytes),
    do: Connection.deliver(conn, generation, bytes, System.monotonic_time(:microsecond))

  # The CONNECTION_CLOSE frame of the first 1-RTT packet that carries one.
  defp sent_close_frame do
    keys = keys(2, 0)
    offset = 1 + byte_size(@dcid)

    receive do
      {:sent, <<first, _::binary>> = bytes} when (first &&& 0x80) == 0 ->
        {:ok, bytes, pn_length} =
          Protection.remove_header_protection(bytes, offset, keys.hp, :aes_128_gcm)

        <<_first, _cid::binary-size(4), number::binary-size(^pn_length), ciphertext::binary>> =
          bytes

        pn = :binary.decode_unsigned(number)
        aad = binary_part(bytes, 0, offset + pn_length)
        nonce = :crypto.exor(keys.iv, <<0::32, pn::64>>)
        size = byte_size(ciphertext) - 16
        <<body::binary-size(^size), tag::binary-size(16)>> = ciphertext

        plaintext =
          :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, nonce, body, aad, tag, false)

        {:ok, frames, _} = Codec.decode_frames(plaintext)
        Enum.find(frames, &(&1.type == :connection_close)) || sent_close_frame()
    after
      1_000 -> flunk("no CONNECTION_CLOSE was sent")
    end
  end

  defp assert_closes(packets, code) do
    {conn, generation} = start()

    for {frames, pn} <- Enum.with_index(packets, 10) do
      deliver(conn, generation, packet(frames, pn))
    end

    assert_receive {:quic_closing, ^conn, ^generation, {:transport, ^code, _frame_type}}, 1_000
    assert Connection.status(conn).phase == :closing
    close = sent_close_frame()
    assert close.error_code == code
    close
  end

  test "stream limit violation closes with STREAM_LIMIT_ERROR" do
    assert_closes([[stream(1 + 4 * 1_000_000, 0, "x")]], 0x04)
  end

  test "flow control violation closes with FLOW_CONTROL_ERROR" do
    assert_closes([[stream(1, 1 <<< 40, "x")]], 0x03)
  end

  test "conflicting final size closes with FINAL_SIZE_ERROR" do
    assert_closes([[stream(1, 0, "abc", true)], [stream(1, 0, "abcdef", true)]], 0x06)
  end

  test "sending on a receive-only stream closes with STREAM_STATE_ERROR" do
    # Stream 2 is a client-initiated unidirectional stream, so the peer cannot send on it.
    assert_closes([[stream(2, 0, "x")]], 0x05)
  end

  test "acknowledging an unsent packet closes with PROTOCOL_VIOLATION" do
    assert_closes([[%{type: :ack, largest: 99, ranges: [{99, 99}], delay: 0}]], 0x0A)
  end

  test "a truncated frame closes with FRAME_ENCODING_ERROR" do
    assert_closes([<<0x08>>], 0x07)
  end

  test "an update before handshake confirmation closes with KEY_UPDATE_ERROR" do
    {conn, generation} = start()
    deliver(conn, generation, packet([%{type: :ping}], 10, 1))
    assert_receive {:quic_closing, ^conn, ^generation, {:transport, 0x0E, _}}, 1_000
    assert sent_close_frame().error_code == 0x0E
  end
end

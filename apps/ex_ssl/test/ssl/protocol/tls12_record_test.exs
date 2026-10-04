defmodule SSL.Protocol.TLS12RecordTest do
  use ExUnit.Case, async: true

  alias SSL.Protocol.{RecordFramer, TLS12Record}

  test "OpenSSL GMAC vectors fix TLS 1.2 AAD, nonce and record header for both AES sizes" do
    for {cipher, key, type, tag} <- [
          {:aes_128_gcm, <<0::128>>, :application_data, "dd688b50f78bebb9b44465c09c696f84"},
          {:aes_256_gcm, <<0::256>>, :handshake, "1cb5bb68eefd4cca0c9c3e25a40eaa40"}
        ] do
      assert {:ok, state} = TLS12Record.new(cipher, key, <<0::32>>)
      assert {:ok, wire, %{sequence: 1}} = TLS12Record.encrypt(state, type, <<>>)
      assert binary_part(wire, 5, 8) == <<0::64>>
      assert Base.encode16(binary_part(wire, 13, 16), case: :lower) == tag
      assert {:ok, ^type, <<>>, %{sequence: 1}} = TLS12Record.decrypt(state, wire)
    end
  end

  test "fragmented record input decrypts only after a complete bounded frame" do
    {:ok, state} = TLS12Record.new(:aes_128_gcm, <<1::128>>, <<2::32>>)
    {:ok, wire, next} = TLS12Record.encrypt(state, :application_data, "fragmented")
    assert next.sequence == 1

    {records, remainder} =
      Enum.reduce(:binary.bin_to_list(wire), {[], RecordFramer.new()}, fn byte,
                                                                          {records, framer} ->
        {:ok, produced, framer} = RecordFramer.feed(framer, <<byte>>)
        {records ++ produced, framer}
      end)

    assert records == [wire]
    assert RecordFramer.buffered_size(remainder) == 0

    assert {:ok, :application_data, "fragmented", %{sequence: 1}} =
             TLS12Record.decrypt(state, hd(records))
  end

  test "authentication binds sequence, content type, ciphertext, explicit nonce and tag" do
    {:ok, state} = TLS12Record.new(:aes_128_gcm, <<3::128>>, <<4::32>>)
    {:ok, wire, _next} = TLS12Record.encrypt(state, :alert, <<1, 0>>)

    for index <- [0, 5, 13, byte_size(wire) - 1] do
      modified = flip(wire, index)
      assert {:error, _} = TLS12Record.decrypt(state, modified)
    end

    assert {:error, :authentication_failed} =
             TLS12Record.decrypt(%{state | sequence: 1}, wire)
  end

  test "malformed records, lengths, versions and unsupported content types fail" do
    {:ok, state} = TLS12Record.new(:aes_128_gcm, <<0::128>>, <<0::32>>)
    assert {:error, :malformed_record} = TLS12Record.decrypt(state, <<23, 3>>)

    assert {:error, :invalid_record_version} =
             TLS12Record.decrypt(state, <<23, 3, 1, 0, 24, 0::192>>)

    assert {:error, :record_length_mismatch} =
             TLS12Record.decrypt(state, <<23, 3, 3, 0, 24, 0::64>>)

    assert {:error, :ciphertext_too_short} =
             TLS12Record.decrypt(state, <<23, 3, 3, 0, 23, 0::184>>)

    assert {:error, :record_length_exceeded} =
             TLS12Record.decrypt(state, <<23, 3, 3, 0x4019::16>>)

    assert {:error, :unsupported_content_type} =
             TLS12Record.decrypt(state, <<20, 3, 3, 0, 24, 0::192>>)

    assert {:error, :unsupported_content_type} =
             TLS12Record.encrypt(state, :change_cipher_spec, <<1>>)

    assert {:error, :invalid_plaintext} =
             TLS12Record.encrypt(state, :handshake, :binary.copy(<<0>>, 16_385))
  end

  test "sequence and AES-GCM key-use limits are strict" do
    {:ok, state} = TLS12Record.new(:aes_128_gcm, <<0::128>>, <<0::32>>)

    assert {:ok, wire, %{sequence: 23_726_566}} =
             TLS12Record.encrypt(%{state | sequence: 23_726_565}, :application_data, <<>>)

    assert binary_part(wire, 5, 8) == <<23_726_565::64>>

    assert {:error, :key_usage_exhausted} =
             TLS12Record.encrypt(%{state | sequence: 23_726_566}, :application_data, <<>>)

    assert {:error, :sequence_exhausted} =
             TLS12Record.decrypt(%{state | sequence: 0xFFFFFFFFFFFFFFFF}, wire)

    assert {:error, :invalid_traffic_state} =
             TLS12Record.encrypt(%{state | sequence: -1}, :application_data, <<>>)

    assert {:error, :invalid_traffic_state} = TLS12Record.new(:aes_128_gcm, <<0::120>>, <<0::32>>)
    assert {:error, :invalid_traffic_state} = TLS12Record.new(:aes_128_gcm, <<0::128>>, <<0::40>>)
    refute inspect(state) =~ "key:"
    refute inspect(state) =~ "iv:"
  end

  defp flip(bytes, index) do
    <<before::binary-size(^index), byte, after_bytes::binary>> = bytes
    <<before::binary, Bitwise.bxor(byte, 1), after_bytes::binary>>
  end
end

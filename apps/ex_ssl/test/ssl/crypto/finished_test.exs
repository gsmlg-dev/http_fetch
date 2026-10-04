defmodule SSL.Crypto.FinishedTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.Finished

  @server_handshake_secret Base.decode16!(
                             "B67B7D690CC16C4E75E54213CB2D37B4E9C912BCDED9105D42BEFD59D391AD38"
                           )

  test "calculates and verifies a SHA-256 Finished value from the RFC 8448 traffic secret" do
    transcript_hash = sequence(32)
    expected = hex("B99ED8CC98AC1EF9207CEF835E06391AAD261C9C876C885640F0070D601DD410")

    assert {:ok, ^expected} =
             Finished.client_verify_data(:sha256, @server_handshake_secret, transcript_hash)

    assert :ok =
             Finished.verify_server(:sha256, @server_handshake_secret, transcript_hash, expected)
  end

  test "calculates and verifies an independent OpenSSL SHA-384 vector" do
    traffic_secret = sequence(48)
    transcript_hash = sequence(48)

    expected =
      hex(
        "B719E25532E775A3132F2FB00B480A21DD219B9E8B9C4C559BB9C811E20738E5" <>
          "F64AEB4A0524373C9B5B64045C92DD86"
      )

    assert {:ok, ^expected} =
             Finished.client_verify_data(:sha384, traffic_secret, transcript_hash)

    assert :ok = Finished.verify_server(:sha384, traffic_secret, transcript_hash, expected)
  end

  test "rejects wrong-value and wrong-length Finished data" do
    transcript_hash = sequence(32)

    assert {:ok, expected} =
             Finished.client_verify_data(:sha256, @server_handshake_secret, transcript_hash)

    assert {:error, :invalid_finished} =
             Finished.verify_server(
               :sha256,
               @server_handshake_secret,
               transcript_hash,
               flip_first_bit(expected)
             )

    assert {:error, {:invalid_finished_length, 31, 32}} =
             Finished.verify_server(
               :sha256,
               @server_handshake_secret,
               transcript_hash,
               binary_part(expected, 0, 31)
             )
  end

  test "returns tagged errors for unsupported hashes and malformed terms" do
    assert {:error, :unsupported_hash} = Finished.client_verify_data(:sha512, <<>>, <<>>)

    assert {:error, {:invalid_secret_length, :traffic_secret, 32}} =
             Finished.client_verify_data(:sha256, nil, sequence(32))

    assert {:error, {:invalid_input, :transcript_hash}} =
             Finished.client_verify_data(:sha256, @server_handshake_secret, nil)

    assert {:error, {:invalid_input, :verify_data}} =
             Finished.verify_server(:sha256, @server_handshake_secret, sequence(32), nil)
  end

  defp sequence(size), do: for(byte <- 0..(size - 1), into: <<>>, do: <<byte>>)
  defp hex(value), do: Base.decode16!(value)
  defp flip_first_bit(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>
end

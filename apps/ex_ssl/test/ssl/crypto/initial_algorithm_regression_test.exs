defmodule SSL.Crypto.InitialAlgorithmRegressionTest do
  use ExUnit.Case, async: true
  alias SSL.Crypto.{KeyExchange, Signature}

  test "generates fresh secp384r1 key pairs that agree" do
    if KeyExchange.supported?(:secp384r1) do
      assert {:ok, left} = KeyExchange.generate(:secp384r1)
      assert {:ok, right} = KeyExchange.generate(:secp384r1)
      assert byte_size(left.public_key) == 97
      assert byte_size(right.public_key) == 97
      assert byte_size(left.private_key) == 48
      assert byte_size(right.private_key) == 48
      refute left.public_key == right.public_key
      refute left.private_key == right.private_key

      assert {:ok, left_secret} = KeyExchange.shared_secret(left, right.public_key)
      assert {:ok, right_secret} = KeyExchange.shared_secret(right, left.public_key)
      assert left_secret == right_secret
      assert byte_size(left_secret) == 48
    else
      assert {:error, {:unsupported_capability, :secp384r1}} =
               KeyExchange.generate(:secp384r1)
    end
  end

  test "verifies ECDSA P-384 with the TLS 1.3 P-384 scheme" do
    private_key = :public_key.generate_key({:namedCurve, {1, 3, 132, 0, 34}})
    public_key = {{:ECPoint, elem(private_key, 4)}, elem(private_key, 3)}
    transcript_digest = :crypto.hash(:sha384, "p384 transcript")

    signed_content =
      :binary.copy(<<0x20>>, 64) <>
        "TLS 1.3, server CertificateVerify" <> <<0>> <> transcript_digest

    signature = :public_key.sign(signed_content, :sha384, private_key)

    assert :ok =
             Signature.verify_server(
               0x0503,
               public_key,
               :sha384,
               transcript_digest,
               signature
             )
  end

  test "verifies Ed25519 with the TLS 1.3 scheme" do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    public_key = {{1, 3, 101, 112}, {:ECPoint, public_key}, {:namedCurve, {1, 3, 101, 112}}}
    transcript_digest = :crypto.hash(:sha256, "ed25519 transcript")

    signed_content =
      :binary.copy(<<0x20>>, 64) <>
        "TLS 1.3, server CertificateVerify" <> <<0>> <> transcript_digest

    signature = :crypto.sign(:eddsa, :none, signed_content, [private_key, :ed25519])

    assert :ok =
             Signature.verify_server(
               0x0807,
               public_key,
               :sha256,
               transcript_digest,
               signature
             )
  end
end

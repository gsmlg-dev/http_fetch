defmodule SSL.Crypto.TLS12SignatureTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.Signature

  test "P-256 ECDSA signs exact TLS 1.2 bytes without TLS 1.3 context" do
    private = :public_key.generate_key({:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}})
    public = {{:ECPoint, elem(private, 4)}, elem(private, 3)}
    message = <<1::256, 2::256, 3, 0, 23, 0, 65, 4, 5>>

    assert {:ok, signature} = Signature.sign_message(0x0403, private, message)
    assert :ok = Signature.verify_message(0x0403, public, message, signature)
    assert :public_key.verify(message, :sha256, signature, public)

    assert {:error, :invalid_certificate_verify} =
             Signature.verify_message(0x0403, public, message <> <<0>>, signature)

    assert {:error, :invalid_certificate_verify} =
             Signature.verify_server(
               0x0403,
               public,
               :sha256,
               :crypto.hash(:sha256, message),
               signature
             )
  end

  test "RSA-PSS raw signatures retain scheme and key restrictions" do
    private = :public_key.generate_key({:rsa, 2048, 65_537})
    public = {:RSAPublicKey, elem(private, 2), elem(private, 3)}
    message = "exact client key exchange transcript"

    assert {:ok, signature} = Signature.sign_message(0x0804, private, message)
    assert :ok = Signature.verify_message(0x0804, public, message, signature)

    assert {:error, :invalid_certificate_verify} =
             Signature.verify_message(0x0804, public, message <> "!", signature)

    assert {:error, {:key_type_mismatch, :ecdsa}} =
             Signature.verify_message(0x0403, public, message, signature)

    assert {:error, {:unsupported_signature_scheme, 0x0401}} =
             Signature.sign_message(0x0401, private, message)

    assert {:error, {:invalid_input, :message}} = Signature.sign_message(0x0804, private, nil)
    assert {:error, :empty_signature} = Signature.verify_message(0x0804, public, message, <<>>)
  end
end

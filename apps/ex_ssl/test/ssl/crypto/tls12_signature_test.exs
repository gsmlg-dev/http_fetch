defmodule SSL.Crypto.TLS12SignatureTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.Signature

  test "TLS1.2 ECDSA digest is independent of supported curve; TLS1.3 remains bound" do
    for {oid, scheme} <- [{{1, 3, 132, 0, 34}, 0x0403}, {{1, 2, 840, 10_045, 3, 1, 7}, 0x0503}] do
      private = :public_key.generate_key({:namedCurve, oid})
      public = {{:ECPoint, elem(private, 4)}, elem(private, 3)}
      message = "exact TLS1.2 cross-curve transcript"
      assert {:ok, signature} = Signature.sign_message(scheme, private, message)
      assert :ok = Signature.verify_message(scheme, public, message, signature)

      assert :public_key.verify(
               message,
               if(scheme == 0x0403, do: :sha256, else: :sha384),
               signature,
               public
             )

      assert {:error, _} = Signature.verify_message(scheme, public, message <> "!", signature)

      assert {:error, _} =
               Signature.verify_message(
                 scheme,
                 {{:ECPoint, <<4, 1>>}, {:namedCurve, oid}},
                 message,
                 signature
               )

      digest = :crypto.hash(:sha256, message)
      assert {:error, _} = Signature.sign_client(scheme, private, :sha256, digest)
      assert {:error, _} = Signature.verify_client(scheme, public, :sha256, digest, signature)
    end
  end

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

    assert {:error, {:unsupported_signature_scheme, 0x0201}} =
             Signature.sign_message(0x0201, private, message)

    assert {:error, {:invalid_input, :message}} = Signature.sign_message(0x0804, private, nil)
    assert {:error, :empty_signature} = Signature.verify_message(0x0804, public, message, <<>>)
  end
end

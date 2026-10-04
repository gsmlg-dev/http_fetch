defmodule SSL.Crypto.SignatureTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.Signature

  @ec_public_pem """
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm0xowUhHz7sYVWJg9e5CLgxYRFjS
  o10bzUcjoEZAbgIBJQMyen9BC2HvMAf4SOS78iL3kC6QbpMF9XhnpepEig==
  -----END PUBLIC KEY-----
  """

  @rsa_public_pem """
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsMd+CZz6gXtUYTKhXd5J
  z+Bx07TXGxpQl3dEKHHR/9jU/DT7aa2+1jdWMTYEXJ3M2o5jmKd/G+P0V07I9qY8
  Nf/gimhKc91T7W9S96Zv0TABTs6meS/AEeX8jsSI5CETxBWnnsauGx624X85zCOI
  th5/UMi3yIxtZHowz++nR9QAioN7dKba1Qzlf3K6ykSoIVDimx06B+Bf/Z8SwJu9
  +7gwYz+oBWmAmnjDvnq8ZbxH1WOfgkJ2QsVAJ5QQ1xjc5jMeqNFkQ9KGuYSUrZQm
  pAkkJ9WM0nv2EPbBHTPQZ3DAgwduGm305NNFVX3+yrXJqsqyX/B7zGg7ZXCX48Xk
  8QIDAQAB
  -----END PUBLIC KEY-----
  """

  @ec_signature "3045022009d3de6ab2646d4dbb53a169a7c1082a2159b1bbbbcc86cd09ea3599be6b7030" <>
                  "022100f75080e62c7d5d4e005394fde0f91b7754a5c9749e9431a571c74d8debc7acec"

  @rsa_signatures %{
    0x0804 =>
      "33e6b3a948cf54ae9de5ada9d380f83f9e0c6bf43d32ee454b76c8ef31c94e352d4e3c1975060a17b751dcc9fc1eedcf38417aa6d3972ecaefb127dc7680f0cb2dd2ea57537de1cf2f9e20acc8292b28b5cb987f9ae4e6032181a659b26b2404d345c153933ed8c265989e81a1824490e722124c4dbcf591b96b322d04d06fa07d4348b73aea351c86f5d672384edcff311c3546913d0af954f37e95b6363633260aff8e54e7cff744e92199e7121747e17176784fc3b5adfc56295630c311f064b2de5948ddab298fd055801952945ab38135b5ad655e1519968b27e9def2b8deb9f150d726f50a4da4f9e81abadb7fa3213af68389cf0b2503595958d37d75",
    0x0805 =>
      "41c4fa83ebdd96059b44b404795706f252b6edc109b9e72d54047701004f1438de4bbec024e4913d393732fa5a410b939dfa49d4ec01ea9845a9a719a2a55f4274a2471b0e3f7931242a25790495da97b022059490af413fe113bd94594eb7febd540fda455840739607a03f10e270e86b3726897ae5daab07e734e890b7a7fb5b16634ac340d24700abc15cecac07b384509f3e6b74119f07b0ee37def86a23a0c85b7c08b0475ce6ef8411335c11c6fb344fe62e42492ed873c435f7adf213d78de726fbc36666acb331d61f037b9575ba5baf3b282f14304f2b27f685006ddf8173c79a98e6705adca952c69c349b22ee107223c31e0341317a3e17b20b48",
    0x0806 =>
      "97a239c4c8e9f83c08099a08d327c1be14b48d27d33b3dcabd12b5eb48b4b0921bfa219f71678f8ef8808f0029a5a59930e0832b40c7986e54f63fa68cad1dd116e1abe616714bee4876bef4bfffe5e4e7f595d0dbaed29277c055a66a5bb2ff704f56a26713a2063d321c787f209ce3661cdb2b50678513dfe22636a074d32daec707a5ce11f346c16758e167420497409d0e6988800a3f69fb9e66aebd592076b83dec909c80f9cd1a1b0e2ff6fa13a241b15487b97d30deab873d480897203243c93e8d143cf3d00aeee1c99cb7c4422354e72921543246524e903d2048fe26a14fecadef00c4847257d77ddc162608080954386afaf3971e057fadd5d259"
  }

  test "constructs the exact TLS 1.3 server CertificateVerify content" do
    transcript_hash = sequence(32)

    assert {:ok, content} = Signature.server_signed_content(:sha256, transcript_hash)

    assert content ==
             :binary.copy(" ", 64) <>
               "TLS 1.3, server CertificateVerify" <> <<0>> <> transcript_hash
  end

  test "verifies a fixed OpenSSL P-256 ECDSA signature" do
    assert :ok =
             Signature.verify_server(
               0x0403,
               public_key(@ec_public_pem),
               :sha256,
               sequence(32),
               hex(@ec_signature)
             )
  end

  test "verifies ECDSA SHA-256 with a SHA-384 transcript digest" do
    private_key = :public_key.generate_key({:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}})
    public_key = {{:ECPoint, elem(private_key, 4)}, elem(private_key, 3)}
    transcript_digest = :crypto.hash(:sha384, "independent transcript")

    signed_content =
      :binary.copy(<<0x20>>, 64) <>
        "TLS 1.3, server CertificateVerify" <> <<0>> <> transcript_digest

    signature = :public_key.sign(signed_content, :sha256, private_key)

    assert :ok =
             Signature.verify_server(
               0x0403,
               public_key,
               :sha384,
               transcript_digest,
               signature
             )
  end

  test "verifies RSA-PSS SHA-256 with SHA-384 and RSA-PSS SHA-384 with SHA-256 transcripts" do
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})
    public_key = {:RSAPublicKey, elem(private_key, 2), elem(private_key, 3)}

    for {scheme, transcript_hash, signature_hash, salt_length} <- [
          {0x0804, :sha384, :sha256, 32},
          {0x0805, :sha256, :sha384, 48},
          {0x0806, :sha384, :sha512, 64}
        ] do
      transcript_digest = :crypto.hash(transcript_hash, "independent transcript")

      signed_content =
        :binary.copy(<<0x20>>, 64) <>
          "TLS 1.3, server CertificateVerify" <> <<0>> <> transcript_digest

      options = [
        {:rsa_padding, :rsa_pkcs1_pss_padding},
        {:rsa_pss_saltlen, salt_length},
        {:rsa_mgf1_md, signature_hash}
      ]

      signature = :public_key.sign(signed_content, signature_hash, private_key, options)

      assert :ok =
               Signature.verify_server(
                 scheme,
                 public_key,
                 transcript_hash,
                 transcript_digest,
                 signature
               )
    end
  end

  test "verifies fixed OpenSSL RSA-PSS SHA-256, SHA-384, and SHA-512 signatures" do
    key = public_key(@rsa_public_pem)

    for {scheme, transcript_size} <- [{0x0804, 32}, {0x0805, 48}, {0x0806, 64}] do
      assert :ok =
               Signature.verify_server(
                 scheme,
                 key,
                 transcript_hash_algorithm(transcript_size),
                 sequence(transcript_size),
                 hex(Map.fetch!(@rsa_signatures, scheme))
               )
    end
  end

  test "rejects wrong transcript hashes and tampered signatures" do
    key = public_key(@ec_public_pem)
    signature = hex(@ec_signature)

    assert {:error, :invalid_certificate_verify} =
             Signature.verify_server(0x0403, key, :sha256, :binary.copy(<<0>>, 32), signature)

    assert {:error, :invalid_ecdsa_signature_encoding} =
             Signature.verify_server(
               0x0403,
               key,
               :sha256,
               sequence(32),
               flip_first_bit(signature)
             )
  end

  test "rejects key type and curve mismatches" do
    ec_key = public_key(@ec_public_pem)
    rsa_key = public_key(@rsa_public_pem)
    {{:ECPoint, point}, _params} = ec_key
    wrong_curve = {{:ECPoint, point}, {:namedCurve, {1, 3, 132, 0, 34}}}

    assert {:error, {:key_type_mismatch, :ecdsa}} =
             Signature.verify_server(0x0403, rsa_key, :sha256, sequence(32), hex(@ec_signature))

    assert {:error, {:key_type_mismatch, :rsa}} =
             Signature.verify_server(
               0x0804,
               ec_key,
               :sha256,
               sequence(32),
               hex(Map.fetch!(@rsa_signatures, 0x0804))
             )

    assert {:error, {:unsupported_ec_curve, :secp384r1}} =
             Signature.verify_server(
               0x0403,
               wrong_curve,
               :sha256,
               sequence(32),
               hex(@ec_signature)
             )
  end

  test "rejects unsupported schemes and malformed arbitrary terms" do
    ec_key = public_key(@ec_public_pem)

    assert {:error, {:unsupported_signature_scheme, 0x0808}} =
             Signature.verify_server(0x0808, ec_key, :sha256, sequence(32), <<1>>)

    assert {:error, {:unsupported_signature_scheme, nil}} =
             Signature.verify_server(nil, ec_key, :sha256, sequence(32), <<1>>)

    assert {:error, {:invalid_transcript_hash_length, 32}} =
             Signature.verify_server(0x0403, ec_key, :sha256, <<0>>, <<1>>)

    assert {:error, {:invalid_input, :transcript_hash}} =
             Signature.verify_server(0x0403, ec_key, :sha256, nil, <<1>>)

    assert {:error, {:invalid_input, :signature}} =
             Signature.verify_server(0x0403, ec_key, :sha256, sequence(32), nil)

    assert {:error, :empty_signature} =
             Signature.verify_server(0x0403, ec_key, :sha256, sequence(32), <<>>)

    assert {:error, :invalid_public_key} =
             Signature.verify_server(0x0403, nil, :sha256, sequence(32), <<1>>)

    assert {:error, :unsupported_hash} = Signature.server_signed_content(:sha1, <<0::160>>)

    assert {:error, {:invalid_transcript_hash_length, 32}} =
             Signature.server_signed_content(:sha256, <<0::384>>)
  end

  defp public_key(pem) do
    [entry] = :public_key.pem_decode(pem)
    :public_key.pem_entry_decode(entry)
  end

  defp sequence(size), do: for(byte <- 0..(size - 1), into: <<>>, do: <<byte>>)
  defp transcript_hash_algorithm(32), do: :sha256
  defp transcript_hash_algorithm(48), do: :sha384
  defp transcript_hash_algorithm(64), do: :sha512
  defp hex(value), do: Base.decode16!(value, case: :mixed)
  defp flip_first_bit(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>
end

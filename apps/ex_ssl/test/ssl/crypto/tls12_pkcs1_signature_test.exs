defmodule SSL.Crypto.TLS12PKCS1SignatureTest do
  use ExUnit.Case, async: true
  alias SSL.Crypto.Signature

  # Generated independently with OpenSSL 3.6.5 dgst -sha{256,384,512}
  # -sign rsa.pem -sigopt rsa_padding_mode:pkcs1 over the exact message below.
  @private_pem """
  -----BEGIN PRIVATE KEY-----
  MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQC/oNbH00GA0MYw
  dVzoWt9ryxJyASrp/FjuaSs1wABzOzSucF3FASCocodAl5JZPfHcK1/t/F5tTEGx
  ce9DqZJ/C9NymO22VI6xB2SXgnVbpFNgcaXVhulsbWU421y5rEacXqlNfv2wQTii
  p4suhINPJO/yoIHvVDCyQhy75nxnxMYx8HkmW2TLiSOYJOdh8J0et8e6uq+OiJco
  Z5vt29zAJxPCFDRyaVnEoYTtqAw8Kl2FygZBAncLIrVlLbmusEZ3WofsPy7zCJVx
  sDZl4tABILOUE/far0LVSF1HCiVLvOi68SF+TfemJbPrfzqAH1FKOSZ3c3/WMWuw
  oIhyknfpAgMBAAECgf8iDvQdj+6UdobDFhjtMzmCbxVYLdzyuWcU+Jw1cWqjEGLM
  niwMV6b2SWTAli/srJXQC+WA5tnhkywZ3aYo4HqpGfD67TNStLSnwiiexREWuJ4Z
  BhnzWYcjPk4/TL2uQnBKWoi8vVVZfj4SqrSSD/tGlcoP1XdCkjQVeqqgutZhmsiC
  vbnpnhT2tCg4eAXO7tHIMKyDo5Udru/uSqBvaR+I8xUELQJu7iGlGVXk5ICphRaw
  HeGj6xEVSA3MISmGk6QRUlDzt2S1ibdyhbKZhwXABCqvfeSY1ff5eCLE7VEF9f6V
  qhnHcuWustCPr6ZXYqVjkN4+jJlkh91vBURIiu8CgYEA9E4YoEYiORJSUTrLANdQ
  vfIuJQq4sVTTSmCbGbBQflrx1AIxk/IDgiE2BszV43m2ehAo9mBDUYv0SOPUyVvu
  ftVR6+fwMYmoHnIpZH5cxi8NlsDIvLiSM3mR0Sv4xbtXUfHD6Jc/aoN9Y48rlrLG
  33WC+ctStBE7FRuHKduLD68CgYEAyM0zWWry30+E6UvDbtQEbXAACaAudcIPBc7z
  kdgPQpHPUNIgXy8nloMttm5OhUlb+MuuvNlvNl5G+LiUPjgYDSZ2+iBByzF/0+p9
  kIPLrjzB/47is5nLG62lDCuX7IDFIzBe0SHa7AudE9J51kjtnUx8duILK76a3dDR
  6YoI/+cCgYB1QobPZtpGSmT4WB/X54D5qqQ7Y0oC05QWvwey7M212DD6cZMaT68f
  ZpFn8ik3ZdQQAnGmz81/9ozp73DStS1j8z++2zSOkmP/OQxlD8G33h3HngC7lFuY
  GWHD5DcjsSfYTRKbMP1fQn2Mq8tgKa8K0nxrKQwpIZwaJXxauuWkQQKBgHkEOmM0
  cmUlHnwfngvIGVb/PfaPJBDyQG2GuQJ3jVLYX3JdAQd8esZaDo240ve/K3+4+Xl1
  LXI9xVYWn7kTw2MBgIjkMeLM1TYZR012MKW0llJ3gacuE9t9fk/kYe41+RlpCGvP
  lInXwfX1TlpXn2TCeOyI9KSLffga5rdx6lSXAoGAUgh7wJMzRlUROwDieJgtR4ZI
  hx+PsHH+IxCl3dYaUZ5EE/nFm6LZeg/e84P+sOmbotilV5PD6+EHqB9U5KYQy3Ju
  QAigFewkn+53VGyVtjKIFCGmOHae7pfy1BGdtK1ZnXXcMrjbsTW0enkVPCqwwCuw
  JtnjgCveqMl/ExOapn4=
  -----END PRIVATE KEY-----
  """
  @public_pem """
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv6DWx9NBgNDGMHVc6Frf
  a8sScgEq6fxY7mkrNcAAczs0rnBdxQEgqHKHQJeSWT3x3Ctf7fxebUxBsXHvQ6mS
  fwvTcpjttlSOsQdkl4J1W6RTYHGl1YbpbG1lONtcuaxGnF6pTX79sEE4oqeLLoSD
  TyTv8qCB71QwskIcu+Z8Z8TGMfB5Jltky4kjmCTnYfCdHrfHurqvjoiXKGeb7dvc
  wCcTwhQ0cmlZxKGE7agMPCpdhcoGQQJ3CyK1ZS25rrBGd1qH7D8u8wiVcbA2ZeLQ
  ASCzlBP32q9C1UhdRwolS7zouvEhfk33piWz6386gB9RSjkmd3N/1jFrsKCIcpJ3
  6QIDAQAB
  -----END PUBLIC KEY-----
  """
  @vectors [
    {0x0401, :sha256,
     "055beb313576d48ac3a60c8a44f569b2cdc2693c39b84ee85f834e2f923ecfa903c2f161b07ed91c4aa6faedbca9bc4c43e994019e3b9ed688612cb7ff72cf81619bab935537af229fadc85295ba67db56487133bc3d15987b9c2a2042b84aa6ad4ee2d16605f8f0c34a2e32727e52ccd07c0a523590900c3ad08d7c6a42ba49b5845890cc36ed9c54f0b6f75d66756f1662de630df5f986a4fe1b2192dba37b2a809ad21b3600efcb62c1b39c858ff5298e691bba3319b365893389131266c0f8f86ece05e2297adfdeddcca36ba5cb14e1b23fc23c2e18449d03e7b9be99c3775b6ca805fe518310b08f5ac2ae3f6dce9c5da3d4a8546333febfe848ca64f5"},
    {0x0501, :sha384,
     "5d449abe65af4cec6b3f99ecac7959443897e30be1298996e1160e413d1bc8fa1f4bcf020b0fd7a116b1b4e6a370c2b04457e26d9df33b689ec99489ef284a18f754085cedbb33041eac5c6886fdbc64fe5df18d0cbd5dc8db0de0a7d5c1d057f7fe1dd186d393ffdc1019b4086c1eb786060a77d1878e15db429a70ab49466039186ec1eb36a8cd0e8d9eed1bc686233146c5b788d66c188806e7e665882248acdb634d258cfd9f52f22f33cbe299780456f1632d38c9393c080168f145867368fb705bc668bd5bde378db6f377d769fba1ba2ab3d431679f4af819a66929a997df49e8523c884b7aaa32f6d8b1fee60185868d11bfd1bf938d941b1d28981f"},
    {0x0601, :sha512,
     "9ca63619edb445eb9654b6c430b7096f9f59685cabc5e6bcb532332ce6848aa023abeb4dc2246293daba4e3f29df80d76120c6c3861fd89bd0feaae989f4be1bbedf6c480cf624c0d46561f4fcf42c8352e9fb2509a881f3aad65c5cc0e603f96b66359a61c4e119be9b4c475e4adbc340184a1612e9184b572cca4a65aa0b758246dbc46bb2f29385c39e5e9389d3a0901dc48c4847dd2ddd1a70129fb75d4c29ec401a9c2028236857b05cf3ea0c89b9fde7b9c5a92594f0ca7207347bca95f5c61d942f7c80d8e5fcaba102f23b8a693de4578bab226606279adfaa6eaabb75ce790382f6302eba00e61486403bb7fab29a45b7ae3316c7a8eaac3fac5413"}
  ]
  @message Base.decode16!(
             "0100000b544c5320312e3200ff0065786163742068616e647368616b6520627974657300",
             case: :lower
           )

  test "TLS12 PKCS1 signing and verification match independent fixed vectors" do
    private = decode(@private_pem)
    public = decode(@public_pem)

    for {scheme, _hash, hex} <- @vectors do
      expected = Base.decode16!(hex, case: :lower)
      assert :ok = Signature.verify_message(scheme, public, @message, expected)
      assert {:ok, ^expected} = Signature.sign_message(scheme, private, @message)
    end
  end

  test "PKCS1 raw signatures reject message, scheme, signature and key substitutions" do
    private = decode(@private_pem)
    public = decode(@public_pem)
    ec = :public_key.generate_key({:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}})
    ec_public = {{:ECPoint, elem(ec, 4)}, elem(ec, 3)}
    pss_public = {{1, 2, 840, 113_549, 1, 1, 10}, public, :asn1_NOVALUE}

    for {scheme, _hash, hex} <- @vectors do
      signature = Base.decode16!(hex, case: :lower)
      <<first, tail::binary>> = signature

      assert {:error, :invalid_certificate_verify} =
               Signature.verify_message(scheme, public, @message <> <<0>>, signature)

      assert {:error, :invalid_certificate_verify} =
               Signature.verify_message(
                 scheme,
                 public,
                 @message,
                 <<Bitwise.bxor(first, 1), tail::binary>>
               )

      assert {:error, {:key_type_mismatch, :rsa}} = Signature.sign_message(scheme, ec, @message)

      assert {:error, {:key_type_mismatch, :rsa}} =
               Signature.sign_message(scheme, {private, :asn1_NOVALUE}, @message)

      assert {:error, {:key_type_mismatch, :rsa}} =
               Signature.verify_message(scheme, ec_public, @message, signature)

      assert {:error, {:key_type_mismatch, :rsa}} =
               Signature.verify_message(scheme, pss_public, @message, signature)

      for {other, _, _} <- @vectors, other != scheme do
        assert {:error, :invalid_certificate_verify} =
                 Signature.verify_message(other, public, @message, signature)
      end
    end
  end

  test "PKCS1 never enters TLS13 client or server CertificateVerify" do
    private = decode(@private_pem)
    public = decode(@public_pem)
    digest = :crypto.hash(:sha256, @message)

    for {scheme, _hash, hex} <- @vectors do
      signature = Base.decode16!(hex, case: :lower)
      error = {:error, {:unsupported_signature_scheme, scheme}}
      assert ^error = Signature.sign_client(scheme, private, :sha256, digest)
      assert ^error = Signature.sign_server(scheme, private, :sha256, digest)
      assert ^error = Signature.verify_client(scheme, public, :sha256, digest, signature)
      assert ^error = Signature.verify_server(scheme, public, :sha256, digest, signature)
    end
  end

  defp decode(pem) do
    [entry] = :public_key.pem_decode(pem)
    :public_key.pem_entry_decode(entry)
  end
end

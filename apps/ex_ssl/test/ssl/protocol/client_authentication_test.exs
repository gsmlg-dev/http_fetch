defmodule SSL.Protocol.ClientAuthenticationTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias ExSSL.TestSupport.SignatureFixtures
  alias SSL.ClientIdentity
  alias SSL.Crypto.KeySchedule
  alias SSL.Crypto.Signature
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.Protocol.{ClientAuthentication, HandshakeFramer, Record, ServerFlight, Transcript}
  alias SSL.Protocol.ServerFlight.{Certificate, CertificateRequest, CertificateVerify}

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-clientflight-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    fixtures = ClientAuthFixtures.create(directory)
    signature_fixtures = SignatureFixtures.create(Path.join(directory, "signatures"))

    {:ok, identity} =
      ClientIdentity.load(certfile: fixtures.rsa.certificate, keyfile: fixtures.rsa.key)

    {:ok, large} =
      ClientIdentity.load(certfile: fixtures.large.certificate, keyfile: fixtures.large.key)

    {:ok,
     fixtures: fixtures, signature_fixtures: signature_fixtures, identity: identity, large: large}
  end

  test "unsupported OID filter values preserve valid high-tag DER as opaque bytes" do
    oid = <<6, 3, 85, 29, 37>>
    high_tag_value = <<0x9F, 0x20, 0x01, 0x00>>

    filter =
      <<byte_size(oid), oid::binary, byte_size(high_tag_value)::16, high_tag_value::binary>>

    encoded =
      request_message([
        extension(13, <<2::16, 0x0804::16>>),
        extension(48, <<byte_size(filter)::16, filter::binary>>)
      ])

    assert {:ok, %CertificateRequest{extensions: extensions}, <<>>} = ServerFlight.decode(encoded)
    assert {:oid_filters, [{oid, high_tag_value}]} in extensions
  end

  test "CertificateRequest decodes bounded CA, certificate-signature and OID constraints",
       context do
    name = ca_name(context.fixtures.ca.der)
    authorities = <<byte_size(name) + 2::16, byte_size(name)::16, name::binary>>
    filters = <<8::16, 5, 6, 3, 85, 29, 37, 0::16>>

    encoded =
      request_message([
        extension(13, <<2::16, 0x0804::16>>),
        extension(47, authorities),
        extension(50, <<2::16, 0x0401::16>>),
        extension(48, filters)
      ])

    assert {:ok, %CertificateRequest{extensions: extensions, encoded: ^encoded}, <<>>} =
             ServerFlight.decode(encoded)

    assert {:certificate_authorities, names} =
             List.keyfind(extensions, :certificate_authorities, 0)

    assert names == [name]
    assert {:signature_algorithms_cert, [0x0401]} in extensions
    assert {:oid_filters, [{<<6, 3, 85, 29, 37>>, <<>>}]} in extensions
  end

  test "known malformed CertificateRequest constraints reject at decode", context do
    name = ca_name(context.fixtures.ca.der)
    bad_name = <<3::16, 1::16, 0>>
    good_name = <<byte_size(name) + 2::16, byte_size(name)::16, name::binary>>
    oid = <<6, 3, 85, 29, 37>>
    filter = <<5, oid::binary, 0::16>>

    for {id, bad} <- [
          {47, bad_name},
          {47, <<0::16>>},
          {47, good_name <> <<0>>},
          {47, <<byte_size(name) + 3::16, byte_size(name) + 1::16, name::binary, 0>>},
          {50, <<0::16>>},
          {50, <<2::16, 0x0804::16, 0>>},
          {48, <<1::16, 0>>},
          {48, <<2 * byte_size(filter)::16, filter::binary, filter::binary>>},
          {48, <<8::16, 5, 6, 3, 85, 29, 128, 0::16>>}
        ] do
      encoded = request_message([extension(13, <<2::16, 0x0804::16>>), extension(id, bad)])
      assert {:error, _reason} = ServerFlight.decode(encoded)
    end
  end

  test "certificate signature policy uses the issuer key type and curve", context do
    p384 = context.signature_fixtures[0x0503]
    pss = context.signature_fixtures[0x0809]

    p384_der = signed_leaf(p384, "sha384")
    pss_der = signed_leaf(pss, "sha256")
    extensions = p384_der |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(10)
    # OpenSSL versions differ in whether they add identifier extensions to this leaf.
    extensions = if extensions == :asn1_NOVALUE, do: [], else: extensions
    refute Enum.any?(extensions, &match?({:Extension, {2, 5, 29, 15}, _, _}, &1))

    assert CertificateSignaturePolicy.schemes(p384_der, p384.der) == [0x0503]
    assert CertificateSignaturePolicy.schemes(p384_der, context.fixtures.ca.der) == []
    assert CertificateSignaturePolicy.schemes(pss_der, pss.der) == [0x0809]

    assert CertificateSignaturePolicy.schemes(pss_der, context.signature_fixtures[0x080A].der) ==
             []

    p384_identity = %ClientIdentity{
      chain: [p384_der, p384.der],
      private_key: nil,
      public_key: nil,
      signature_schemes: [0x0503]
    }

    pss_identity = %ClientIdentity{
      chain: [pss_der, pss.der],
      private_key: nil,
      public_key: nil,
      signature_schemes: [0x0809]
    }

    assert {:ok, {^p384_identity, 0x0503}} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0503]},
                 {:signature_algorithms_cert, [0x0503]}
               ]),
               p384_identity
             )

    assert {:ok, nil} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0503]},
                 {:signature_algorithms_cert, [0x0403]}
               ]),
               p384_identity
             )

    assert {:ok, {^pss_identity, 0x0809}} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0809]},
                 {:signature_algorithms_cert, [0x0809]}
               ]),
               pss_identity
             )

    assert {:ok, nil} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0809]},
                 {:signature_algorithms_cert, [0x0804]}
               ]),
               pss_identity
             )
  end

  test "identity selection honors requested signature, CA and cert-signature policy", context do
    name = ca_name(context.fixtures.ca.der)

    request =
      request([
        {:signature_algorithms, [0x0804]},
        {:certificate_authorities, [name]},
        {:signature_algorithms_cert, [0x0401]}
      ])

    assert {:ok, {%ClientIdentity{}, 0x0804}} =
             ClientAuthentication.select(request, context.identity)

    wrong_ca = ca_name(context.fixtures.server.der)

    assert {:ok, nil} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0804]},
                 {:certificate_authorities, [wrong_ca]},
                 {:signature_algorithms_cert, [0x0401]}
               ]),
               context.identity
             )

    assert {:ok, nil} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0804]},
                 {:signature_algorithms_cert, [0x0501]}
               ]),
               context.identity
             )

    assert {:ok, nil} =
             ClientAuthentication.select(
               request([{:signature_algorithms, [0x0403]}]),
               context.identity
             )

    assert {:ok, nil} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0804]},
                 {:oid_filters, [{<<6, 3, 85, 29, 37>>, <<>>}]}
               ]),
               context.identity
             )

    identity = context.identity

    assert {:ok, {^identity, 0x0804}} =
             ClientAuthentication.select(
               request([
                 {:signature_algorithms, [0x0804]},
                 {:signature_algorithms_cert, [0x0401]},
                 {:oid_filters, [{<<6, 3, 85, 29, 19>>, <<0x9F, 0x20, 0x01, 0x00>>}]}
               ]),
               context.identity
             )
  end

  test "leaf without digitalSignature key usage is not selected", context do
    ca_identity = %ClientIdentity{
      chain: [context.fixtures.ca.der],
      private_key: nil,
      public_key: nil,
      signature_schemes: [0x0804]
    }

    assert {:ok, nil} =
             ClientAuthentication.select(
               request([{:signature_algorithms, [0x0804]}]),
               ca_identity
             )
  end

  test "large client Certificate fragments into handshake records and CV signs after it",
       context do
    request = request([{:signature_algorithms, [0x0804]}, {:signature_algorithms_cert, [0x0401]}])
    transcript = Transcript.new(:sha256) |> Transcript.append("preceding server flight")
    {:ok, write} = KeySchedule.traffic_state(:tls_aes_128_gcm_sha256, <<1::256>>)

    assert {:ok, final_transcript, next_write, records} =
             ClientAuthentication.emit(request, context.large, transcript, write)

    assert length(records) >= 3
    assert next_write.sequence == write.sequence + length(records)

    {fragments, _read} =
      Enum.map_reduce(records, write, fn record, read ->
        assert {:ok, :handshake, plaintext, next_read} = Record.decrypt(read, record)
        assert byte_size(plaintext) <= 16_384
        {plaintext, next_read}
      end)

    {:ok, [certificate_bytes, verify_bytes], framer} =
      HandshakeFramer.feed(HandshakeFramer.new(), IO.iodata_to_binary(fragments))

    assert HandshakeFramer.buffered_size(framer) == 0

    assert {:ok, %Certificate{entries: [%{der: der}]}, <<>>} =
             ServerFlight.decode(certificate_bytes)

    assert der == context.fixtures.large.der

    assert {:ok, %CertificateVerify{signature_scheme: 0x0804, signature: signature}, <<>>} =
             ServerFlight.decode(verify_bytes)

    after_certificate = Transcript.append(transcript, certificate_bytes)

    assert :ok =
             Signature.verify_client(
               0x0804,
               context.large.public_key,
               :sha256,
               Transcript.digest(after_certificate),
               signature
             )

    assert {:error, :invalid_certificate_verify} =
             Signature.verify_server(
               0x0804,
               context.large.public_key,
               :sha256,
               Transcript.digest(after_certificate),
               signature
             )

    assert Transcript.digest(final_transcript) ==
             Transcript.digest(Transcript.append(after_certificate, verify_bytes))
  end

  test "credentials remain absent without request or when no compatible identity exists",
       context do
    transcript = Transcript.new(:sha256)
    {:ok, write} = KeySchedule.traffic_state(:tls_aes_128_gcm_sha256, <<1::256>>)

    assert {:ok, ^transcript, ^write, []} =
             ClientAuthentication.emit(nil, context.identity, transcript, write)

    request = request([{:signature_algorithms, [0x0403]}])

    assert {:ok, after_empty, next_write, [record]} =
             ClientAuthentication.emit(request, context.identity, transcript, write)

    assert {:ok, :handshake, <<11, 4::24, 0, 0::24>>, _} = Record.decrypt(write, record)
    assert next_write.sequence == write.sequence + 1
    refute Transcript.digest(after_empty) == Transcript.digest(transcript)
  end

  defp request(extensions),
    do: %CertificateRequest{request_context: <<>>, extensions: extensions, encoded: <<>>}

  defp ca_name(der) do
    der
    |> :public_key.pkix_decode_cert(:otp)
    |> elem(1)
    |> elem(6)
    |> then(&:public_key.der_encode(:Name, &1))
  end

  defp request_message(extensions) do
    encoded = IO.iodata_to_binary(extensions)
    body = <<0, byte_size(encoded)::16, encoded::binary>>
    <<13, byte_size(body)::24, body::binary>>
  end

  defp extension(id, payload), do: <<id::16, byte_size(payload)::16, payload::binary>>

  defp signed_leaf(issuer, digest) do
    directory = Path.dirname(issuer.certificate)
    request = Path.join(directory, "issued-#{digest}.csr")
    certificate = Path.join(directory, "issued-#{digest}.pem")

    SignatureFixtures.openssl!([
      "req",
      "-new",
      "-key",
      issuer.key,
      "-out",
      request,
      "-subj",
      "/CN=issued-#{digest}"
    ])

    SignatureFixtures.openssl!([
      "x509",
      "-req",
      "-in",
      request,
      "-CA",
      issuer.certificate,
      "-CAkey",
      issuer.key,
      "-CAcreateserial",
      "-out",
      certificate,
      "-days",
      "1",
      "-#{digest}"
    ])

    [{:Certificate, der, :not_encrypted}] =
      certificate |> File.read!() |> :public_key.pem_decode()

    der
  end
end

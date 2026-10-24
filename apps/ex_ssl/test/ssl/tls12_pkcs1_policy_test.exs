defmodule SSL.TLS12PKCS1PolicyTest do
  use ExUnit.Case, async: true

  alias SSL.{Capabilities, ClientIdentity, Options}
  alias SSL.ClientHello.{Materializer, Profile, Serializer}
  alias SSL.Protocol.{ClientAuthentication, ClientOffer, ServerFlight}
  alias SSL.Protocol.ServerFlight.CertificateRequest

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
  @certificate_pem """
  -----BEGIN CERTIFICATE-----
  MIIDSDCCAjCgAwIBAgIUGk2QEYQL02UQoCF4S81TAfamPNMwDQYJKoZIhvcNAQEL
  BQAwFjEUMBIGA1UEAwwLUjQyIHRlc3QgQ0EwHhcNMjYxMDIzMDUwMjE4WhcNMjYx
  MDI1MDUwMjE4WjARMQ8wDQYDVQQDDAZjbGllbnQwggEiMA0GCSqGSIb3DQEBAQUA
  A4IBDwAwggEKAoIBAQC/oNbH00GA0MYwdVzoWt9ryxJyASrp/FjuaSs1wABzOzSu
  cF3FASCocodAl5JZPfHcK1/t/F5tTEGxce9DqZJ/C9NymO22VI6xB2SXgnVbpFNg
  caXVhulsbWU421y5rEacXqlNfv2wQTiip4suhINPJO/yoIHvVDCyQhy75nxnxMYx
  8HkmW2TLiSOYJOdh8J0et8e6uq+OiJcoZ5vt29zAJxPCFDRyaVnEoYTtqAw8Kl2F
  ygZBAncLIrVlLbmusEZ3WofsPy7zCJVxsDZl4tABILOUE/far0LVSF1HCiVLvOi6
  8SF+TfemJbPrfzqAH1FKOSZ3c3/WMWuwoIhyknfpAgMBAAGjgZIwgY8wDAYDVR0T
  AQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwGgYD
  VR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMB0GA1UdDgQWBBRxQxpbmpn+qxyRoqH7
  YrJ185hQMjAfBgNVHSMEGDAWgBRxQxpbmpn+qxyRoqH7YrJ185hQMjANBgkqhkiG
  9w0BAQsFAAOCAQEAoIlyuKKq2ty/ig/NWhV7HavnqLGIrKb3PbAPdWLnTlP8RENz
  R39XSP6RhjmSVjx+Tt35BW+F6WCBTqh5Jn3pfnyz8CJsvnw8BT21P4xy8G15OEd4
  9H/fppd+KHnIlcukqpsrpKoDzLu3CvUssRd/vc+O3mKhd/jzBpvYAR1I5TsJFDOK
  jFIzrA9LJUWQVob6eWPJ9JNtKf6hslMOQcDuMqJK+bkAg/IfhD/fDt5yNFs5pp/S
  UnJwp8OsQeBWsIlQXR1gAVMN798xG/WKZlhn13H34YtrVF785LWhw7E83kPcw/eh
  JmMxfU8CKlkEnAZsOVVrovmZo1Jv1/W3hzKF8Q==
  -----END CERTIFICATE-----
  """
  @ca_pem """
  -----BEGIN CERTIFICATE-----
  MIIDHTCCAgWgAwIBAgIUM8AVRKOK5Lqj+orSzwIMjiQmCXowDQYJKoZIhvcNAQEL
  BQAwFjEUMBIGA1UEAwwLUjQyIHRlc3QgQ0EwHhcNMjYxMDIzMDUwMjE4WhcNMjYx
  MDI1MDUwMjE4WjAWMRQwEgYDVQQDDAtSNDIgdGVzdCBDQTCCASIwDQYJKoZIhvcN
  AQEBBQADggEPADCCAQoCggEBAL+g1sfTQYDQxjB1XOha32vLEnIBKun8WO5pKzXA
  AHM7NK5wXcUBIKhyh0CXklk98dwrX+38Xm1MQbFx70Opkn8L03KY7bZUjrEHZJeC
  dVukU2BxpdWG6WxtZTjbXLmsRpxeqU1+/bBBOKKniy6Eg08k7/Kgge9UMLJCHLvm
  fGfExjHweSZbZMuJI5gk52HwnR63x7q6r46Ilyhnm+3b3MAnE8IUNHJpWcShhO2o
  DDwqXYXKBkECdwsitWUtua6wRndah+w/LvMIlXGwNmXi0AEgs5QT99qvQtVIXUcK
  JUu86LrxIX5N96Yls+t/OoAfUUo5Jndzf9Yxa7CgiHKSd+kCAwEAAaNjMGEwHwYD
  VR0jBBgwFoAUcUMaW5qZ/qsckaKh+2KydfOYUDIwDwYDVR0TAQH/BAUwAwEB/zAO
  BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHFDGluamf6rHJGioftisnXzmFAyMA0G
  CSqGSIb3DQEBCwUAA4IBAQCoFFe3mT6m1b3IjGrd40ngOvmMGqXdcGaQfG47Pvou
  AeTFoSI8zoMZevJrUwQc98D+KXlcKlqpcVN3UwUYaJKeCn3YzhOb1r1httwrUjm0
  KWYSpJXBPJc7/1hoSnPMOTKET8YrgoKQIESi50ycNdoti4/PxrrvG9t71XfsVAOB
  VHGdCVWEddLM2aIXRuK0jM2e8oOLVFCv+Ze7qyUD6vw0TAtEc2UKrE/8/22s7Myd
  xoMQPzN+S6f1jxQev1zFKEe8WIcErtPZjAbnvKeS3koOd5n6+xBi3IFOkfnX2moe
  yD0vYAZhcX9OsHyKaCJH9/ktLLrTdiE+FWdxQx3Qnp7q
  -----END CERTIFICATE-----
  """

  @schemes [0x0401, 0x0501, 0x0601]
  @names [:rsa_pkcs1_sha256, :rsa_pkcs1_sha384, :rsa_pkcs1_sha512]

  test "TLS12 RSA capability prerequisites and TLS13 capability separation are explicit" do
    runtime = %{
      public_keys: [:rsa],
      hashs: [:sha256, :sha512],
      macs: [:hmac],
      rsa_opts: [:rsa_pkcs1_padding]
    }

    assert Capabilities.identifiers(:tls12_signature_algorithm, runtime) ==
             [0x0401, :rsa_pkcs1_sha256, 0x0601, :rsa_pkcs1_sha512]

    assert Capabilities.identifiers(:tls12_signature_algorithm, %{runtime | rsa_opts: []}) == []
    assert Capabilities.identifiers(:signature_algorithm, runtime) == []

    for {id, name, hash} <- [
          {0x0401, :rsa_pkcs1_sha256, :sha256},
          {0x0501, :rsa_pkcs1_sha384, :sha384},
          {0x0601, :rsa_pkcs1_sha512, :sha512}
        ] do
      assert %{id: ^id, hash: ^hash, key: :rsa, verify_options: [rsa_padding: :rsa_pkcs1_padding]} =
               Capabilities.signature(name, :tls12)

      assert Capabilities.signature(id) == nil
      refute Capabilities.tls13_signature_scheme?(id)
      refute id in Capabilities.identifiers(:signature_algorithm)
      assert %{id: ^id} = Capabilities.resolve(:certificate_signature_algorithm, name)
    end
  end

  test "ordered TLS12 and mixed public policies materialize exact signature bytes" do
    for versions <- [[:"tlsv1.2"], [:"tlsv1.3", :"tlsv1.2"]] do
      assert {:ok, %{profile: profile}} =
               Options.normalize("localhost",
                 verify: :verify_none,
                 versions: versions,
                 signature_algs: Enum.reverse(@names)
               )

      assert {:signature_algorithms, [0x0601, 0x0501, 0x0401]} in profile.extensions
      assert {:extended_master_secret, <<>>} in profile.extensions
      assert {:renegotiation_info, <<0>>} in profile.extensions

      assert Enum.all?(profile.cipher_suites, fn id ->
               %{cipher: cipher} = Capabilities.resolve(:cipher_suite, id)
               cipher in [:aes_128_gcm, :aes_256_gcm, :chacha20_poly1305]
             end)

      assert {:ok, materialized} =
               Materializer.materialize(profile, Options.capabilities(), %{
                 server_name: "localhost"
               })

      assert {:ok, encoded} = Serializer.encode(materialized.client_hello)

      assert {:ok, %{signature_schemes: [0x0601, 0x0501, 0x0401]}} =
               ClientOffer.from_client_hello(encoded)

      assert :binary.match(encoded, <<13::16, 8::16, 6::16, 0x0601::16, 0x0501::16, 0x0401::16>>) !=
               :nomatch

      explicit = %{
        profile
        | extensions:
            List.keyreplace(
              profile.extensions,
              :signature_algorithms,
              0,
              {:signature_algorithms, Enum.reverse(@names)}
            )
      }

      assert {:ok, %{profile: ^explicit}} =
               Options.normalize("localhost",
                 verify: :verify_none,
                 versions: versions,
                 signature_algs: Enum.reverse(@names),
                 ex_ssl: [profile: explicit]
               )

      assert {:ok, _} =
               Materializer.materialize(explicit, Options.capabilities(), %{
                 server_name: "localhost"
               })

      assert {:error, {:options, {:signature_algs, :profile_conflict}}} =
               Options.normalize("localhost",
                 verify: :verify_none,
                 versions: versions,
                 signature_algs: @names,
                 ex_ssl: [profile: explicit]
               )
    end
  end

  test "TLS13 policies reject PKCS1 handshake algorithms while certificate policy accepts them" do
    for name <- @names do
      assert {:error, {:options, {:signature_algs, :unsupported_or_invalid}}} =
               Options.normalize("localhost",
                 verify: :verify_none,
                 versions: [:"tlsv1.3"],
                 signature_algs: [name]
               )
    end

    assert {:ok, %{profile: profile}} =
             Options.normalize("localhost",
               verify: :verify_none,
               versions: [:"tlsv1.3"],
               signature_algs_cert: @names
             )

    assert {:signature_algorithms_cert, @schemes} in profile.extensions

    invalid = %{
      profile
      | extensions:
          List.keyreplace(
            profile.extensions,
            :signature_algorithms,
            0,
            {:signature_algorithms, @schemes}
          )
    }

    assert {:error, {:unsupported_signature_algorithms, @schemes}} =
             Profile.validate(invalid, Options.capabilities())
  end

  test "TLS12 default gains PKCS1 without changing the TLS13 default" do
    assert {:ok, %{profile: twelve}} =
             Options.normalize("localhost", verify: :verify_none, versions: [:"tlsv1.2"])

    assert {:ok, %{profile: thirteen}} =
             Options.normalize("localhost", verify: :verify_none, versions: [:"tlsv1.3"])

    {:signature_algorithms, schemes12} = List.keyfind(twelve.extensions, :signature_algorithms, 0)

    {:signature_algorithms, schemes13} =
      List.keyfind(thirteen.extensions, :signature_algorithms, 0)

    assert Enum.all?(@schemes, &(&1 in schemes12))
    refute Enum.any?(@schemes, &(&1 in schemes13))
  end

  test "identity loading and selection keep TLS12 eligibility separate from TLS13" do
    identity = identity()
    assert Enum.all?(@schemes, &(&1 in identity.tls12_signature_schemes))
    refute Enum.any?(@schemes, &(&1 in identity.signature_schemes))
    request = request([0x0601, 0x0401, 0x0804])
    assert {:ok, {^identity, 0x0601}} = ClientAuthentication.select(request, identity, :tls12)
    assert {:ok, {^identity, 0x0804}} = ClientAuthentication.select(request, identity)
    assert {:ok, nil} = ClientAuthentication.select(request(@schemes), identity)
    assert {:ok, nil} = ClientAuthentication.select(request([0x0201]), identity, :tls12)

    assert {:error, :invalid_client_authentication} =
             ClientAuthentication.select(request, identity, :unknown)
  end

  test "TLS12 identity selection retains certificate policy, authorities and key usage" do
    identity = identity()
    request = request(@schemes)

    bad_policy = %{
      request
      | extensions: [signature_algorithms: @schemes, signature_algorithms_cert: [0x0501]]
    }

    assert {:ok, nil} = ClientAuthentication.select(bad_policy, identity, :tls12)
    ca = decode_certificate(@ca_pem)
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(ca, :otp)
    name = :public_key.der_encode(:Name, elem(tbs, 6))
    matching = %{request | extensions: request.extensions ++ [certificate_authorities: [name]]}
    assert {:ok, {^identity, 0x0401}} = ClientAuthentication.select(matching, identity, :tls12)
    leaf = decode_certificate(@certificate_pem)
    {:OTPCertificate, leaf_tbs, _, _} = :public_key.pkix_decode_cert(leaf, :otp)
    wrong_name = :public_key.der_encode(:Name, elem(leaf_tbs, 6))
    refute wrong_name == name
    wrong = %{request | extensions: request.extensions ++ [certificate_authorities: [wrong_name]]}
    assert {:ok, {^identity, 0x0401}} = ClientAuthentication.select(wrong, identity, :tls12)

    matching13 = %{
      matching
      | extensions: Keyword.put(matching.extensions, :signature_algorithms, [0x0804])
    }

    wrong13 = %{
      wrong
      | extensions: Keyword.put(wrong.extensions, :signature_algorithms, [0x0804])
    }

    assert {:ok, {^identity, 0x0804}} = ClientAuthentication.select(matching13, identity, :tls13)
    assert {:ok, nil} = ClientAuthentication.select(wrong13, identity, :tls13)
    malformed = %{request | extensions: request.extensions ++ [certificate_authorities: [<<1>>]]}

    assert {:error, :invalid_client_authentication} =
             ClientAuthentication.select(malformed, identity, :tls12)

    no_usage = %{identity | chain: [ca]}
    assert {:ok, nil} = ClientAuthentication.select(request, no_usage, :tls12)
  end

  test "TLS12 ServerKeyExchange binds the offered PKCS1 scheme, key, parameters and randoms" do
    for scheme <- @schemes do
      {state, wire} = signed_exchange(scheme)

      assert {:ok, %{phase: :await_request_or_done}, [], []} =
               SSL.Protocol.TLS12.feed(state, wire)

      error = {:error, {:fatal_alert, :decrypt_error, :invalid_server_key_exchange}}
      assert ^error = SSL.Protocol.TLS12.feed(%{state | server_random: <<1::256>>}, wire)
      assert ^error = SSL.Protocol.TLS12.feed(%{state | client_random: <<1::256>>}, wire)

      assert ^error =
               SSL.Protocol.TLS12.feed(
                 %{state | offer: %{state.offer | signature_schemes: [0x0804]}},
                 wire
               )

      ec = :public_key.generate_key({:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}})
      peer = %{state.peer | public_key: {{:ECPoint, elem(ec, 4)}, elem(ec, 3)}}
      assert ^error = SSL.Protocol.TLS12.feed(%{state | peer: peer}, wire)
      size = byte_size(wire) - 1
      <<prefix::binary-size(^size), last>> = wire
      assert ^error = SSL.Protocol.TLS12.feed(state, <<prefix::binary, Bitwise.bxor(last, 1)>>)
    end
  end

  test "TLS12 client authentication retains rsa_sign certificate type restrictions" do
    for scheme <- @schemes, type <- [1, 64] do
      {state, wire} = signed_exchange(scheme)
      state = %{state | client_identity: identity()}
      assert {:ok, state, [], []} = SSL.Protocol.TLS12.feed(state, wire)
      schemes = Enum.uniq([scheme, 0x0401]) |> Enum.map(&<<&1::16>>) |> IO.iodata_to_binary()
      body = <<1, type, byte_size(schemes)::16, schemes::binary, 0::16>>
      request = <<13, byte_size(body)::24, body::binary>>

      assert {:ok, state, [], []} =
               SSL.Protocol.TLS12.feed_handshakes(state, [request], state.framer)

      assert {:ok, state, _records, []} =
               SSL.Protocol.TLS12.feed_handshakes(state, [<<14, 0::24>>], state.framer)

      messages = Enum.reverse(state.transcript.messages)
      certificates = Enum.filter(messages, &match?(<<11, _::binary>>, &1))
      verifies = Enum.filter(messages, &match?(<<15, _::binary>>, &1))

      if type == 1 do
        assert [<<11, _::binary>>] = certificates
        assert [<<15, _::24, ^scheme::16, _::binary>>] = verifies
      else
        assert [<<11, 3::24, 0::24>>] = certificates
        assert [] = verifies
      end
    end
  end

  test "QUIC and TLS13 wire decoders reject all TLS12-only handshake schemes" do
    ids = Enum.map(SSL.QUIC.capabilities().signatures, & &1.id)
    refute Enum.any?(@schemes, &(&1 in ids))

    options = [
      alpn: ["test"],
      transport_parameters: <<1, 0>>,
      cacerts: [decode_certificate(@ca_pem)],
      reference_identity: {:dns_id, "localhost"}
    ]

    assert {:ok, _} = SSL.QUIC.Config.build(:client, options)

    for scheme <- @schemes do
      assert {:error, :invalid_configuration} =
               SSL.QUIC.Config.build(:client, options ++ [signature_algorithms: [scheme]])

      message = <<15, 5::24, scheme::16, 1::16, 1>>
      assert {:error, {:unsupported_signature_scheme, ^scheme}} = ServerFlight.decode(message)
    end
  end

  defp signed_exchange(scheme) do
    identity = identity()

    assert {:ok, %{profile: profile}} =
             Options.normalize("localhost", verify: :verify_none, versions: [:"tlsv1.2"])

    assert {:ok, materialized} =
             Materializer.materialize(profile, Options.capabilities(), %{server_name: "localhost"})

    assert {:ok, hello} = Serializer.encode(materialized.client_hello)
    assert {:ok, offer} = ClientOffer.from_client_hello(hello)
    assert {:ok, state} = SSL.Protocol.TLS12.new(hello, offer, [], nil, [])
    assert {:ok, suite} = SSL.Crypto.TLS12KeySchedule.suite(0xC02F)
    assert {:ok, pair} = SSL.Crypto.KeyExchange.generate(:secp256r1)
    parameters = <<3, 0x0017::16, byte_size(pair.public_key), pair.public_key::binary>>

    state = %{
      state
      | phase: :await_server_key_exchange,
        suite: suite,
        server_random: <<0::256>>,
        peer: %SSL.PKIX.VerifiedPeer{leaf_der: <<>>, leaf: nil, public_key: identity.public_key}
    }

    assert {:ok, signature} =
             SSL.Crypto.Signature.sign_message(
               scheme,
               identity.private_key,
               state.client_random <> state.server_random <> parameters
             )

    body = <<parameters::binary, scheme::16, byte_size(signature)::16, signature::binary>>
    message = <<12, byte_size(body)::24, body::binary>>
    {state, <<22, 3, 3, byte_size(message)::16, message::binary>>}
  end

  defp identity do
    [{type, key, :not_encrypted}] = :public_key.pem_decode(@private_pem)

    assert {:ok, identity} =
             ClientIdentity.load(
               cert: [decode_certificate(@certificate_pem), decode_certificate(@ca_pem)],
               key: {type, key}
             )

    identity
  end

  defp request(schemes),
    do: %CertificateRequest{
      encoded: <<>>,
      request_context: <<>>,
      extensions: [signature_algorithms: schemes, signature_algorithms_cert: [0x0401]]
    }

  defp decode_certificate(pem) do
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(pem)
    der
  end
end

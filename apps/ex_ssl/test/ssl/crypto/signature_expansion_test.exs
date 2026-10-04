defmodule SSL.Crypto.SignatureExpansionTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer
  alias ExSSL.TestSupport.SignatureFixtures
  alias SSL.Capabilities
  alias SSL.Crypto.Signature
  alias SSL.PKIX

  @moduletag :integration
  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-signature-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)

    fixtures = SignatureFixtures.create(directory)

    {:ok, fixtures: fixtures, directory: directory}
  end

  test "OpenSSL signatures verify with exact TLS contexts and decoded leaf keys", context do
    for {scheme, _name, key_type} <- SignatureFixtures.schemes() do
      fixture = Map.fetch!(context.fixtures, scheme)
      {:ok, verified} = PKIX.verify([fixture.der], [fixture.der], {:dns_id, "exssl.test"})
      digest = :crypto.hash(:sha384, "signature vector transcript")
      {:ok, content} = Signature.server_signed_content(:sha384, digest)
      content_file = Path.join(context.directory, "content-#{scheme}.bin")
      signature_file = Path.join(context.directory, "signature-#{scheme}.bin")
      File.write!(content_file, content)
      openssl_sign!(key_type, fixture.key, content_file, signature_file)
      signature = File.read!(signature_file)

      assert :ok =
               Signature.verify_server(scheme, verified.public_key, :sha384, digest, signature)

      assert {:error, :invalid_certificate_verify} =
               Signature.verify_server(
                 scheme,
                 verified.public_key,
                 :sha384,
                 :crypto.hash(:sha384, "different transcript"),
                 signature
               )
    end
  end

  test "RSA-PSS-PSS rejects rsaEncryption keys and mismatched restrictions", context do
    %{der: der} = Map.fetch!(context.fixtures, 0x0809)
    {:ok, verified} = PKIX.verify([der], [der], {:dns_id, "exssl.test"})
    {oid, rsa_key, parameters} = verified.public_key
    digest = :crypto.hash(:sha256, "transcript")

    assert {:error, {:key_type_mismatch, :rsa_pss}} =
             Signature.verify_server(0x0809, rsa_key, :sha256, digest, <<1>>)

    assert {:error, {:key_type_mismatch, :rsa}} =
             Signature.verify_server(0x0804, verified.public_key, :sha256, digest, <<1>>)

    assert {:error, :invalid_rsa_pss_parameters} =
             Signature.verify_server(0x080A, verified.public_key, :sha256, digest, <<1>>)

    bad_salt = put_elem(parameters, 3, 31)

    bad_mgf =
      put_elem(
        parameters,
        2,
        {:MaskGenAlgorithm, {1, 2, 840, 113_549, 1, 1, 8},
         {:HashAlgorithm, {2, 16, 840, 1, 101, 3, 4, 2, 2}, :NULL}}
      )

    for bad <- [bad_salt, bad_mgf, put_elem(parameters, 4, 2)] do
      assert {:error, :invalid_rsa_pss_parameters} =
               Signature.verify_server(0x0809, {oid, rsa_key, bad}, :sha256, digest, <<1>>)
    end

    {:ok, content} = Signature.server_signed_content(:sha256, digest)
    content_file = Path.join(context.directory, "pss-unrestricted-content.bin")
    signature_file = Path.join(context.directory, "pss-unrestricted-signature.bin")
    File.write!(content_file, content)

    openssl_sign!(
      {:pss, :sha256, 32},
      Map.fetch!(context.fixtures, 0x0809).key,
      content_file,
      signature_file
    )

    assert :ok =
             Signature.verify_server(
               0x0809,
               {oid, rsa_key, :asn1_NOVALUE},
               :sha256,
               digest,
               File.read!(signature_file)
             )
  end

  test "client verification enforces PSS leaf restrictions even with an unrestricted matching key",
       context do
    fixture = Map.fetch!(context.fixtures, 0x0809)
    {:ok, verified} = PKIX.verify([fixture.der], [fixture.der], {:dns_id, "exssl.test"})
    [entry] = fixture.key |> File.read!() |> :public_key.pem_decode()
    {rsa_private, _restricted_params} = :public_key.pem_entry_decode(entry)
    digest = :crypto.hash(:sha256, "client policy transcript")

    assert {:ok, signature} =
             Signature.sign_client(0x080A, {rsa_private, :asn1_NOVALUE}, :sha256, digest)

    assert {:error, :invalid_rsa_pss_parameters} =
             Signature.verify_client(0x080A, verified.public_key, :sha256, digest, signature)

    assert {:ok, allowed_signature} =
             Signature.sign_client(0x0809, {rsa_private, :asn1_NOVALUE}, :sha256, digest)

    assert :ok =
             Signature.verify_client(
               0x0809,
               verified.public_key,
               :sha256,
               digest,
               allowed_signature
             )

    assert {:error, :invalid_certificate_verify} =
             Signature.verify_server(
               0x0809,
               verified.public_key,
               :sha256,
               digest,
               allowed_signature
             )
  end

  test "Ed25519 and P-384 reject wrong key identity, curve, and signature encoding", context do
    p384 = Map.fetch!(context.fixtures, 0x0503)
    ed = Map.fetch!(context.fixtures, 0x0807)
    {:ok, ec_peer} = PKIX.verify([p384.der], [p384.der], {:dns_id, "exssl.test"})
    {:ok, ed_peer} = PKIX.verify([ed.der], [ed.der], {:dns_id, "exssl.test"})
    digest = :crypto.hash(:sha384, "transcript")

    assert {:error, :invalid_ecdsa_signature_encoding} =
             Signature.verify_server(0x0503, ec_peer.public_key, :sha384, digest, <<1, 2, 3>>)

    assert {:error, :invalid_public_key} =
             Signature.verify_server(
               0x0807,
               ec_peer.public_key,
               :sha384,
               digest,
               :binary.copy(<<0>>, 64)
             )

    assert {:error, :invalid_public_key} =
             Signature.verify_server(0x0503, ed_peer.public_key, :sha384, digest, <<1>>)

    p256_private = :public_key.generate_key({:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}})
    p256_public = {{:ECPoint, elem(p256_private, 4)}, elem(p256_private, 3)}
    {:ok, content} = Signature.server_signed_content(:sha384, digest)
    valid_p256_signature = :public_key.sign(content, :sha256, p256_private)

    assert {:error, {:unsupported_ec_curve, {1, 2, 840, 10_045, 3, 1, 7}}} =
             Signature.verify_server(0x0503, p256_public, :sha384, digest, valid_p256_signature)
  end

  test "valid signatures fail with another key of the same algorithm", context do
    digest = :crypto.hash(:sha256, "same algorithm wrong key")
    {:ok, content} = Signature.server_signed_content(:sha256, digest)

    for {scheme, _name, key_type} <- SignatureFixtures.schemes() do
      fixture = Map.fetch!(context.fixtures, scheme)
      content_file = Path.join(context.directory, "wrong-key-content-#{scheme}.bin")
      signature_file = Path.join(context.directory, "wrong-key-signature-#{scheme}.bin")
      File.write!(content_file, content)
      openssl_sign!(key_type, fixture.key, content_file, signature_file)

      wrong_key =
        case key_type do
          :p384 ->
            private = :public_key.generate_key({:namedCurve, {1, 3, 132, 0, 34}})
            {{:ECPoint, elem(private, 4)}, elem(private, 3)}

          :ed25519 ->
            {public, _private} = :crypto.generate_key(:eddsa, :ed25519)
            {{1, 3, 101, 112}, {:ECPoint, public}, {:namedCurve, {1, 3, 101, 112}}}

          {:pss, _, _} ->
            private = :public_key.generate_key({:rsa, 2048, 65_537})
            {:ok, verified} = PKIX.verify([fixture.der], [fixture.der], {:dns_id, "exssl.test"})
            {oid, _public_key, parameters} = verified.public_key
            {oid, {:RSAPublicKey, elem(private, 2), elem(private, 3)}, parameters}
        end

      assert {:error, :invalid_certificate_verify} =
               Signature.verify_server(
                 scheme,
                 wrong_key,
                 :sha256,
                 digest,
                 File.read!(signature_file)
               )
    end
  end

  test "registry removes new schemes when required runtime primitives are absent" do
    runtime = Capabilities.runtime()

    for {scheme, _name, type} <- SignatureFixtures.schemes() do
      kind = if type == :ed25519, do: :eddsa, else: if(type == :p384, do: :ecdsa, else: :rsa)
      unavailable = Map.update!(runtime, :public_keys, &List.delete(&1, kind))
      refute scheme in Capabilities.identifiers(:signature_algorithm, unavailable)
    end
  end

  test "client signed content uses the client context and signing rejects wrong key" do
    digest = :crypto.hash(:sha256, "client transcript")

    assert {:ok, content} = Signature.client_signed_content(:sha256, digest)

    assert content ==
             :binary.copy(" ", 64) <> "TLS 1.3, client CertificateVerify" <> <<0>> <> digest

    assert {:error, {:key_type_mismatch, :eddsa}} =
             Signature.sign_client(0x0807, :not_a_key, :sha256, digest)
  end

  test "client signing uses the matching private key and client context", context do
    digest = :crypto.hash(:sha384, "client signing transcript")
    {:ok, content} = Signature.client_signed_content(:sha384, digest)

    for {scheme, _name, key_type} <- SignatureFixtures.schemes() do
      fixture = Map.fetch!(context.fixtures, scheme)
      {:ok, verified} = PKIX.verify([fixture.der], [fixture.der], {:dns_id, "exssl.test"})
      [entry] = fixture.key |> File.read!() |> :public_key.pem_decode()
      private_key = :public_key.pem_entry_decode(entry)

      assert {:ok, signature} = Signature.sign_client(scheme, private_key, :sha384, digest)

      content_file = Path.join(context.directory, "client-content-#{scheme}.bin")
      signature_file = Path.join(context.directory, "client-signature-#{scheme}.bin")
      public_key_file = Path.join(context.directory, "client-public-#{scheme}.pem")
      File.write!(content_file, content)
      File.write!(signature_file, signature)
      SignatureFixtures.openssl!(["pkey", "-in", fixture.key, "-pubout", "-out", public_key_file])

      openssl_verify!(key_type, public_key_file, content_file, signature_file)

      assert {:error, :invalid_certificate_verify} =
               Signature.verify_server(scheme, verified.public_key, :sha384, digest, signature)

      {verification_key, hash, options} =
        case key_type do
          :p384 ->
            {verified.public_key, :sha384, []}

          :ed25519 ->
            {Tuple.delete_at(verified.public_key, 0), :none, []}

          {:pss, hash, salt} ->
            {elem(verified.public_key, 1), hash,
             [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: salt, rsa_mgf1_md: hash]}
        end

      assert :public_key.verify(content, hash, signature, verification_key, options)
    end
  end

  test "every new scheme completes an authenticated HTTP exchange with a constrained OTP peer",
       context do
    for {scheme, name, _key_type} <- SignatureFixtures.schemes() do
      fixture = Map.fetch!(context.fixtures, scheme)

      {:ok, peer} =
        LocalTLSPeer.start(
          fn socket ->
            assert {:ok, request} = :ssl.recv(socket, 0, 5_000)
            assert String.starts_with?(request, "GET /signature HTTP/1.1\r\n")
            :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
          end,
          ssl_options: [
            certfile: String.to_charlist(fixture.certificate),
            keyfile: String.to_charlist(fixture.key),
            signature_algs: [
              if(name == "ed25519", do: :eddsa_ed25519, else: String.to_atom(name))
            ]
          ]
        )

      options =
        List.keystore(LocalTLSPeer.client_options(), :cacerts, 0, {:cacerts, [fixture.der]})

      try do
        assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
        monitor = Process.monitor(socket.pid)

        try do
          assert :ok = SSL.send(socket, "GET /signature HTTP/1.1\r\nHost: exssl.test\r\n\r\n")
          expected = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
          assert {:ok, ^expected} = SSL.recv(socket, byte_size(expected), 5_000)
        after
          assert :ok = SSL.close(socket)
        end

        assert_receive {:DOWN, ^monitor, :process, _, _}, 2_000
      after
        assert :ok = LocalTLSPeer.stop(peer)
      end
    end
  end

  defp openssl_sign!(:ed25519, key, input, output),
    do:
      SignatureFixtures.openssl!([
        "pkeyutl",
        "-sign",
        "-rawin",
        "-inkey",
        key,
        "-in",
        input,
        "-out",
        output
      ])

  defp openssl_sign!({:pss, hash, salt}, key, input, output),
    do:
      SignatureFixtures.openssl!([
        "dgst",
        "-#{hash}",
        "-sign",
        key,
        "-sigopt",
        "rsa_padding_mode:pss",
        "-sigopt",
        "rsa_pss_saltlen:#{salt}",
        "-sigopt",
        "rsa_mgf1_md:#{hash}",
        "-out",
        output,
        input
      ])

  defp openssl_sign!(:p384, key, input, output),
    do: SignatureFixtures.openssl!(["dgst", "-sha384", "-sign", key, "-out", output, input])

  defp openssl_verify!(:ed25519, key, input, signature),
    do:
      SignatureFixtures.openssl!([
        "pkeyutl",
        "-verify",
        "-rawin",
        "-pubin",
        "-inkey",
        key,
        "-sigfile",
        signature,
        "-in",
        input
      ])

  defp openssl_verify!({:pss, hash, salt}, key, input, signature),
    do:
      SignatureFixtures.openssl!([
        "dgst",
        "-#{hash}",
        "-verify",
        key,
        "-signature",
        signature,
        "-sigopt",
        "rsa_padding_mode:pss",
        "-sigopt",
        "rsa_pss_saltlen:#{salt}",
        "-sigopt",
        "rsa_mgf1_md:#{hash}",
        input
      ])

  defp openssl_verify!(:p384, key, input, signature),
    do:
      SignatureFixtures.openssl!([
        "dgst",
        "-sha384",
        "-verify",
        key,
        "-signature",
        signature,
        input
      ])
end

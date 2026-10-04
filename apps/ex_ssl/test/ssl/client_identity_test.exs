defmodule SSL.ClientIdentityTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer
  alias ExSSL.TestSupport.SignatureFixtures
  alias SSL.ClientIdentity

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-identity-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, directory: directory, fixtures: SignatureFixtures.create(directory)}
  end

  test "no identity returns nil and partial or conflicting configuration fails" do
    assert {:ok, nil} = ClientIdentity.load([])
    assert {:error, {:options, :incomplete_identity}} = ClientIdentity.load(cert: <<1>>)
    assert {:error, {:options, :incomplete_identity}} = ClientIdentity.load(keyfile: "/missing")

    assert {:error, {:options, :conflicting_identity_sources}} =
             ClientIdentity.load(cert: <<1>>, certfile: "/missing", keyfile: "/missing")

    for malformed <- [[{:cert, <<1>>} | :invalid_tail], [:cert], [{:cert, <<1>>}, {:cert, <<2>>}]] do
      assert {:error, {:options, _}} = ClientIdentity.load(malformed)
    end
  end

  test "loads PEM binary and charlist paths with one matching identity", context do
    for {id, _name, _key_type} <- SignatureFixtures.schemes() do
      fixture = Map.fetch!(context.fixtures, id)

      assert {:ok, %ClientIdentity{} = identity} =
               ClientIdentity.load(
                 certfile: fixture.certificate,
                 keyfile: String.to_charlist(fixture.key)
               )

      assert identity.chain == [fixture.der]
      assert id in identity.signature_schemes
      refute inspect(identity) =~ "BEGIN PRIVATE KEY"
      refute inspect(identity) =~ "private_key:"
    end
  end

  test "loads OTP in-memory DER certificate and typed DER private key", context do
    fixture = Map.fetch!(context.fixtures, 0x0503)
    [{type, der, :not_encrypted}] = fixture.key |> File.read!() |> :public_key.pem_decode()

    assert {:ok, %ClientIdentity{chain: [certificate]}} =
             ClientIdentity.load(cert: fixture.der, key: {type, der})

    assert certificate == fixture.der
  end

  test "loads existing RSA and P-256 identities; leaf expiry is left to the peer" do
    fixture = LocalTLSPeer.certificates()

    assert {:ok, %ClientIdentity{signature_schemes: rsa_schemes}} =
             ClientIdentity.load(certfile: fixture.certfile, keyfile: fixture.keyfile)

    assert 0x0804 in rsa_schemes
    refute 0x0809 in rsa_schemes

    assert {:ok, %ClientIdentity{signature_schemes: ec_schemes}} =
             ClientIdentity.load(certfile: fixture.ecdsa_certfile, keyfile: fixture.ecdsa_keyfile)

    assert ec_schemes == [0x0403]

    assert {:ok, %ClientIdentity{}} =
             ClientIdentity.load(certfile: fixture.expired_certfile, keyfile: fixture.keyfile)
  end

  test "a combined certificate and key PEM file supplies one identity", context do
    fixture = Map.fetch!(context.fixtures, 0x0503)
    combined = Path.join(context.directory, "combined.pem")
    File.write!(combined, File.read!(fixture.certificate) <> File.read!(fixture.key))

    assert {:ok, %ClientIdentity{chain: [der]}} = ClientIdentity.load(certfile: combined)
    assert der == fixture.der

    assert {:error, {:options, :invalid_certificate_file}} =
             ClientIdentity.load(
               certfile: combined,
               keyfile: Map.fetch!(context.fixtures, 0x0807).key
             )
  end

  test "preserves RSA-PSS PKCS#8 restrictions and never treats it as RSAE", context do
    fixture = Map.fetch!(context.fixtures, 0x0809)
    [{type, der, :not_encrypted}] = fixture.key |> File.read!() |> :public_key.pem_decode()

    assert {:ok, %ClientIdentity{} = identity} =
             ClientIdentity.load(cert: fixture.der, key: {type, der})

    assert identity.signature_schemes == [0x0809]
    assert {_, {:"RSASSA-PSS-params", _, _, 32, 1}} = identity.private_key
    refute 0x0804 in identity.signature_schemes

    default_parameters = Path.join(context.directory, "default-pss.key")

    SignatureFixtures.openssl!([
      "genpkey",
      "-algorithm",
      "RSA-PSS",
      "-pkeyopt",
      "rsa_keygen_bits:2048",
      "-out",
      default_parameters
    ])

    [entry] = default_parameters |> File.read!() |> :public_key.pem_decode()

    assert {{:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}, {:"RSASSA-PSS-params", _, _, 20, 1}} =
             :public_key.pem_entry_decode(entry)

    assert {:error, {:options, :key_certificate_mismatch}} =
             ClientIdentity.load(cert: fixture.der, keyfile: default_parameters)
  end

  test "rejects a private key that does not match the leaf", context do
    ec = Map.fetch!(context.fixtures, 0x0503)
    ed = Map.fetch!(context.fixtures, 0x0807)

    assert {:error, {:options, :key_certificate_mismatch}} =
             ClientIdentity.load(certfile: ec.certificate, keyfile: ed.key)

    other_p384 = :public_key.generate_key({:namedCurve, {1, 3, 132, 0, 34}})
    der = :public_key.der_encode(:ECPrivateKey, other_p384)

    assert {:error, {:options, :key_certificate_mismatch}} =
             ClientIdentity.load(cert: ec.der, key: {:ECPrivateKey, der})
  end

  test "validates ordered issuer adjacency without trusting the chain", context do
    %{chain_certfile: chainfile, chain_keyfile: keyfile} = LocalTLSPeer.certificates()

    assert {:ok, %ClientIdentity{chain: [_leaf, _issuer]}} =
             ClientIdentity.load(certfile: chainfile, keyfile: keyfile)

    [leaf, issuer] =
      chainfile |> File.read!() |> :public_key.pem_decode() |> Enum.map(&elem(&1, 1))

    assert {:error, {:options, :invalid_chain_order}} =
             ClientIdentity.load(cert: [issuer, leaf], keyfile: keyfile)

    unrelated = Map.fetch!(context.fixtures, 0x0807).der

    assert {:error, {:options, :invalid_chain_order}} =
             ClientIdentity.load(cert: [leaf, unrelated], keyfile: keyfile)
  end

  test "rejects malformed, oversized and multiple PEM keys with redacted errors", context do
    fixture = Map.fetch!(context.fixtures, 0x0503)
    key_pem = File.read!(fixture.key)
    huge = Path.join(context.directory, "huge.pem")
    multi = Path.join(context.directory, "multi.pem")
    File.write!(huge, :binary.copy("x", 1_048_577))
    File.write!(multi, key_pem <> key_pem)

    for options <- [
          [certfile: fixture.certificate, keyfile: huge],
          [certfile: fixture.certificate, keyfile: multi],
          [cert: [fixture.der, fixture.der], keyfile: fixture.key],
          [cert: List.duplicate(fixture.der, 17), keyfile: fixture.key],
          [cert: <<1, 2, 3>>, keyfile: fixture.key],
          [certfile: fixture.certificate, key: %{algorithm: :rsa, sign_fun: fn _ -> <<>> end}]
        ] do
      assert {:error, {:options, reason}} = ClientIdentity.load(options)
      refute inspect(reason) =~ key_pem
      refute inspect(reason) =~ fixture.key
    end
  end

  test "rejects unsupported identity selection and encrypted key forms", context do
    fixture = Map.fetch!(context.fixtures, 0x0503)
    encrypted = Path.join(context.directory, "encrypted.key")

    SignatureFixtures.openssl!([
      "pkcs8",
      "-topk8",
      "-in",
      fixture.key,
      "-out",
      encrypted,
      "-v2",
      "aes-256-cbc",
      "-passout",
      "pass:example"
    ])

    for options <- [
          [certs_keys: [%{certfile: fixture.certificate, keyfile: fixture.key}]],
          [certfile: fixture.certificate, keyfile: encrypted],
          [certfile: fixture.certificate, keyfile: fixture.key, password: "example"]
        ] do
      assert {:error, {:options, _reason}} = ClientIdentity.load(options)
    end
  end
end

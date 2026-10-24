defmodule SSL.EncryptedClientIdentityTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{EncryptedIdentityFixtures, SignatureFixtures}

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-encrypted-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    Map.put(EncryptedIdentityFixtures.create(directory), :directory, directory)
  end

  test "public options decrypt independent AES PBES2 RSA and EC credentials", context do
    for role <- [:rsa, :ec] do
      fixture = Map.fetch!(context.encrypted, role)
      common = [verify: :verify_none, certfile: fixture.certificate]

      assert {:ok, clear} =
               SSL.Options.normalize(~c"exssl.test", common ++ [keyfile: fixture.key])

      assert {:ok, encrypted} =
               SSL.Options.normalize(
                 ~c"exssl.test",
                 common ++ [keyfile: fixture.encrypted_key, password: fixture.password]
               )

      assert encrypted.client_identity.chain == clear.client_identity.chain

      assert encrypted.client_identity.signature_schemes ==
               clear.client_identity.signature_schemes

      assert encrypted.client_identity.tls12_signature_schemes ==
               clear.client_identity.tls12_signature_schemes
    end
  end

  test "password octets and callbacks are transient and preserve all valid iodata forms",
       context do
    fixture = context.encrypted.rsa
    <<first, rest::binary>> = fixture.password

    for value <- [
          fixture.password,
          :binary.bin_to_list(fixture.password),
          [<<first>>, [rest]],
          [first | rest]
        ] do
      for callback? <- [false, true] do
        counter = :atomics.new(1, [])

        password =
          if callback?,
            do: fn ->
              :atomics.add_get(counter, 1, 1)
              value
            end,
            else: value

        options = [
          verify: :verify_none,
          certfile: fixture.certificate,
          keyfile: fixture.encrypted_key,
          password: password
        ]

        assert {:ok, normalized} = SSL.Options.normalize(~c"exssl.test", options)
        assert :atomics.get(counter, 1) == if(callback?, do: 1, else: 0)
        assert normalized.client_identity.chain == [fixture.der]
        refute Map.has_key?(Map.from_struct(normalized), :password)
        refute Map.has_key?(Map.from_struct(normalized.client_identity), :password)
        refute inspect(normalized) =~ fixture.encrypted_key
        refute inspect(normalized.client_identity) =~ "PRIVATE KEY"
        assert :binary.match(:erlang.term_to_binary(normalized), fixture.password) == :nomatch
      end
    end
  end

  test "file-backed plaintext calls once but DER and no identity never call the password",
       context do
    fixture = context.encrypted.ec
    [entry] = fixture.key |> File.read!() |> :public_key.pem_decode()
    {type, der, :not_encrypted} = entry

    for {identity, count} <- [
          {[certfile: fixture.certificate, keyfile: fixture.key], 1},
          {[cert: fixture.der, key: {type, der}], 0},
          {[], 0}
        ] do
      counter = :atomics.new(1, [])

      password = fn ->
        :atomics.add_get(counter, 1, 1)
        fixture.password
      end

      assert {:ok, _} = SSL.ClientIdentity.load(identity ++ [password: password])
      assert :atomics.get(counter, 1) == count
    end
  end

  test "missing, wrong and invalid passwords and callback failures are fixed and redacted",
       context do
    fixture = context.encrypted.rsa
    options = [certfile: fixture.certificate, keyfile: fixture.encrypted_key]

    values = [
      :absent,
      "WRONG_PRIVATE_PASSWORD",
      <<>>,
      %{secret: fixture.password},
      [256],
      [1 | 2],
      <<1::1>>,
      fn _ -> fixture.password end,
      fn -> %{secret: fixture.password} end,
      fn -> raise "PRIVATE_CALLBACK_SECRET" end,
      fn -> throw("PRIVATE_CALLBACK_SECRET") end,
      fn -> exit("PRIVATE_CALLBACK_SECRET") end
    ]

    for value <- values do
      supplied = if value == :absent, do: options, else: options ++ [password: value]
      assert {:error, {:options, reason}} = SSL.ClientIdentity.load(supplied)
      assert reason in [:invalid_password, :unsupported_private_key]
      refute inspect(reason) =~ fixture.password
      refute inspect(reason) =~ fixture.encrypted_key
      refute inspect(reason) =~ "PRIVATE_CALLBACK_SECRET"
    end
  end

  test "password byte node and nested-list bounds reject before flattening", context do
    assert {:ok, nil} = SSL.ClientIdentity.load(password: :binary.copy("x", 1_048_576))

    assert {:error, {:options, :invalid_password}} =
             SSL.ClientIdentity.load(password: :binary.copy("x", 1_048_577))

    at_depth = Enum.reduce(1..64, <<>>, fn _, acc -> [acc] end)
    assert {:ok, nil} = SSL.ClientIdentity.load(password: at_depth)
    assert {:error, {:options, :invalid_password}} = SSL.ClientIdentity.load(password: [at_depth])

    assert {:error, {:options, :invalid_password}} =
             SSL.ClientIdentity.load(password: List.duplicate(<<>>, 2_097_154))

    assert {:error, {:options, :unsupported_identity_option}} =
             SSL.ClientIdentity.load(
               password: context.encrypted.rsa.password,
               password: "duplicate"
             )
  end

  test "PBES2 cipher and PRF variants and restricted key families preserve clear scheme policy",
       context do
    signatures = SignatureFixtures.create(Path.join(context.directory, "signature-variants"))

    for {id, fixture} <- signatures do
      encrypted =
        EncryptedIdentityFixtures.encrypt(
          fixture,
          context.directory,
          "signature-#{id}",
          context.encrypted.rsa.password
        )

      assert_key_parity(encrypted)
    end

    for cipher <- ["aes-128-cbc", "aes-192-cbc", "aes-256-cbc"],
        prf <- [
          "hmacWithSHA1",
          "hmacWithSHA224",
          "hmacWithSHA256",
          "hmacWithSHA384",
          "hmacWithSHA512"
        ] do
      fixture =
        EncryptedIdentityFixtures.encrypt(
          context.fixtures.rsa,
          context.directory,
          "#{cipher}-#{prf}",
          context.encrypted.rsa.password,
          ["-v2", cipher, "-v2prf", prf]
        )

      assert_key_parity(fixture)
    end
  end

  test "legacy AES and 3DES accept binary and nested passwords for RSA and EC", context do
    for role <- [:rsa, :ec], cipher <- ["aes128", "aes192", "aes256", "des3"] do
      fixture =
        EncryptedIdentityFixtures.legacy(
          Map.fetch!(context.fixtures, role),
          context.directory,
          "legacy-#{role}-#{cipher}",
          cipher,
          context.encrypted.rsa.password,
          role
        )

      assert_key_parity(fixture)
      <<head, rest::binary>> = fixture.password

      assert {:ok, _} =
               SSL.ClientIdentity.load(
                 certfile: fixture.certificate,
                 keyfile: fixture.encrypted_key,
                 password: fn -> [head | rest] end
               )
    end
  end

  test "an independent empty-password encrypted key is distinct from a missing password",
       context do
    fixture =
      EncryptedIdentityFixtures.encrypt(
        context.fixtures.rsa,
        context.directory,
        "empty-password",
        <<>>,
        ["-passout", "pass:"]
      )

    assert_key_parity(fixture)

    assert {:error, {:options, :unsupported_private_key}} =
             SSL.ClientIdentity.load(
               certfile: fixture.certificate,
               keyfile: fixture.encrypted_key
             )
  end

  test "combined cardinality byte limits and same-family mismatch retain fixed errors", context do
    fixture = context.encrypted.rsa
    certificate = File.read!(fixture.certificate)
    key = File.read!(fixture.encrypted_key)

    for {name, pem} <- [{"cert-first", certificate <> key}, {"key-first", key <> certificate}] do
      path = Path.join(context.directory, name <> ".pem")
      File.write!(path, pem)
      assert {:ok, identity} = SSL.ClientIdentity.load(certfile: path, password: fixture.password)
      assert identity.chain == [fixture.der]

      assert {:ok, ^identity} =
               SSL.ClientIdentity.load(
                 certfile: path,
                 keyfile: path,
                 password: fixture.password
               )
    end

    for {name, pem} <- [
          {"duplicate", key <> key},
          {"mixed", key <> File.read!(fixture.key)},
          {"malformed", binary_part(key, 0, div(byte_size(key), 2))},
          {"too-large", key <> :binary.copy("\n", 1_048_577 - byte_size(key))}
        ] do
      path = Path.join(context.directory, name <> ".key")
      File.write!(path, pem)

      assert {:error, {:options, :unsupported_private_key}} =
               SSL.ClientIdentity.load(
                 certfile: fixture.certificate,
                 keyfile: path,
                 password: fixture.password
               )
    end

    path = Path.join(context.directory, "at-limit.key")
    File.write!(path, key <> :binary.copy("\n", 1_048_576 - byte_size(key)))

    assert {:ok, _} =
             SSL.ClientIdentity.load(
               certfile: fixture.certificate,
               keyfile: path,
               password: fixture.password
             )

    wrong =
      EncryptedIdentityFixtures.encrypt(
        context.fixtures.server,
        context.directory,
        "mismatching-rsa",
        fixture.password
      )

    assert {:error, {:options, :key_certificate_mismatch}} =
             SSL.ClientIdentity.load(
               certfile: fixture.certificate,
               keyfile: wrong.encrypted_key,
               password: fixture.password
             )
  end

  test "encoded invalid KDF count and length fail through public loader without deriving",
       context do
    fixture = context.encrypted.rsa

    for {name, index, value} <- [
          {"zero", 2, 0},
          {"negative", 2, -1},
          {"excess-count", 2, 1_000_001},
          {"wrong-key-length", 3, 31},
          {"huge-key-length", 3, 1_000_000_000}
        ] do
      path = Path.join(context.directory, "#{name}.key")

      mutant =
        EncryptedIdentityFixtures.rewrite_parameters(fixture, path, fn params ->
          kdf = elem(params, 1)
          put_elem(params, 1, put_elem(kdf, 2, put_elem(elem(kdf, 2), index, value)))
        end)

      assert {:error, {:options, :unsupported_private_key}} =
               SSL.ClientIdentity.load(
                 certfile: fixture.certificate,
                 keyfile: mutant.encrypted_key,
                 password: fixture.password
               )
    end

    explicit =
      EncryptedIdentityFixtures.rewrite_parameters(
        fixture,
        Path.join(context.directory, "explicit-length.key"),
        fn params ->
          kdf = elem(params, 1)
          put_elem(params, 1, put_elem(kdf, 2, put_elem(elem(kdf, 2), 3, 32)))
        end
      )

    assert_key_parity(explicit)
  end

  test "client identity continues to reject auto tickets and log no password", context do
    fixture = context.encrypted.rsa

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, {:options, {:session_tickets, :client_identity_unsupported}}} =
                 SSL.Options.normalize(~c"exssl.test",
                   verify: :verify_none,
                   certfile: fixture.certificate,
                   keyfile: fixture.encrypted_key,
                   password: fixture.password,
                   session_tickets: :auto
                 )

        assert {:error, {:options, :unsupported_private_key}} =
                 SSL.connect(
                   {127, 0, 0, 1},
                   1,
                   [
                     verify: :verify_none,
                     certfile: fixture.certificate,
                     keyfile: fixture.encrypted_key,
                     password: "PRIVATE_WRONG_PASSWORD"
                   ],
                   50
                 )
      end)

    refute log =~ fixture.password
    refute log =~ "PRIVATE_WRONG_PASSWORD"
    refute log =~ fixture.encrypted_key
  end

  test "unknown KDF PRF cipher and invalid IV are rejected through encoded public PEM", context do
    fixture = context.encrypted.rsa

    mutations = [
      {"unknown-kdf",
       fn params ->
         kdf =
           elem(params, 1)
           |> put_elem(1, {1, 2, 3, 4})
           |> put_elem(2, {:asn1_OPENTYPE, <<5, 0>>})

         put_elem(params, 1, kdf)
       end},
      {"unknown-prf",
       fn params ->
         kdf = elem(params, 1)

         pbkdf =
           put_elem(
             elem(kdf, 2),
             4,
             {:"PBKDF2-params_prf", {1, 2, 3, 4}, {:asn1_OPENTYPE, <<5, 0>>}}
           )

         put_elem(params, 1, put_elem(kdf, 2, pbkdf))
       end},
      {"unknown-cipher",
       fn params -> put_elem(params, 2, put_elem(elem(params, 2), 1, {1, 2, 3, 4})) end},
      {"invalid-iv",
       fn params ->
         put_elem(params, 2, put_elem(elem(params, 2), 2, {:asn1_OPENTYPE, <<4, 0>>}))
       end}
    ]

    for {name, mutation} <- mutations do
      mutant =
        EncryptedIdentityFixtures.rewrite_parameters(
          fixture,
          Path.join(context.directory, name <> ".key"),
          mutation
        )

      assert {:error, {:options, :unsupported_private_key}} =
               SSL.ClientIdentity.load(
                 certfile: fixture.certificate,
                 keyfile: mutant.encrypted_key,
                 password: fixture.password
               )
    end
  end

  test "PBES2 3DES is supported while scrypt and PKCS12 envelopes return explicit errors",
       context do
    fixture =
      EncryptedIdentityFixtures.encrypt(
        context.fixtures.rsa,
        context.directory,
        "pbes2-3des",
        context.encrypted.rsa.password,
        ["-v2", "des3"]
      )

    assert_key_parity(fixture)

    for {name, arguments} <- [
          {"scrypt", ["-scrypt", "-scrypt_N", "1024"]},
          {"pkcs12", ["-v1", "PBE-SHA1-3DES"]}
        ] do
      path = Path.join(context.directory, name <> ".key")

      SignatureFixtures.openssl!(
        [
          "pkcs8",
          "-topk8",
          "-in",
          fixture.key,
          "-out",
          path,
          "-passout",
          "file:#{Path.join(context.directory, "rsa.password")}"
        ] ++ arguments
      )

      assert {:error, {:options, :unsupported_private_key}} =
               SSL.ClientIdentity.load(
                 certfile: fixture.certificate,
                 keyfile: path,
                 password: fixture.password
               )
    end
  end

  test "empty PBES2 salt and omitted SHA1 PRF decode and match an independent OpenSSL check",
       context do
    fixture = context.encrypted.rsa

    [{type, _, {cipher, params}}] =
      fixture.encrypted_key |> File.read!() |> :public_key.pem_decode()

    kdf = elem(params, 1)

    pbkdf =
      elem(kdf, 2)
      |> put_elem(1, {:specified, <<>>})
      |> put_elem(4, {:"PBKDF2-params_prf", {1, 2, 840, 113_549, 2, 7}, :NULL})

    params = put_elem(params, 1, put_elem(kdf, 2, pbkdf))
    [clear] = fixture.key |> File.read!() |> :public_key.pem_decode()
    key = :public_key.pem_entry_decode(clear)

    encrypted =
      :public_key.pem_entry_encode(
        type,
        key,
        {{cipher, params}, :binary.bin_to_list(fixture.password)}
      )

    path = Path.join(context.directory, "empty-salt.key")
    File.write!(path, :public_key.pem_encode([encrypted]))
    assert_key_parity(%{fixture | encrypted_key: path})

    SignatureFixtures.openssl!([
      "pkey",
      "-in",
      path,
      "-passin",
      "file:#{Path.join(context.directory, "rsa.password")}",
      "-noout"
    ])

    omitted =
      EncryptedIdentityFixtures.rewrite_parameters(
        %{fixture | encrypted_key: path},
        Path.join(context.directory, "omitted-sha1.key"),
        fn p ->
          k = elem(p, 1)
          put_elem(p, 1, put_elem(k, 2, put_elem(elem(k, 2), 4, :asn1_DEFAULT)))
        end
      )

    assert_key_parity(omitted)
  end

  test "wrong password and callback failure reject before any TCP accept", context do
    fixture = context.encrypted.rsa
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)

    try do
      for password <- ["WRONG_PRIVATE_PASSWORD", fn -> throw("PRIVATE_CALLBACK_SECRET") end] do
        assert {:error, {:options, _}} =
                 SSL.connect(
                   {127, 0, 0, 1},
                   port,
                   [
                     verify: :verify_none,
                     certfile: fixture.certificate,
                     keyfile: fixture.encrypted_key,
                     password: password
                   ],
                   500
                 )

        assert {:error, :timeout} = :gen_tcp.accept(listener, 20)
      end
    after
      :gen_tcp.close(listener)
    end
  end

  defp assert_key_parity(fixture) do
    assert {:ok, clear} =
             SSL.ClientIdentity.load(certfile: fixture.certificate, keyfile: fixture.key)

    assert {:ok, encrypted} =
             SSL.ClientIdentity.load(
               certfile: fixture.certificate,
               keyfile: fixture.encrypted_key,
               password: fixture.password
             )

    assert encrypted.chain == clear.chain
    assert encrypted.signature_schemes == clear.signature_schemes
    assert encrypted.tls12_signature_schemes == clear.tls12_signature_schemes
  end
end

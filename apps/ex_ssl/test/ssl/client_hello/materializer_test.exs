defmodule SSL.ClientHello.MaterializerTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.{AST, GreasePolicy, Materializer, Serializer, WireProfile}
  alias SSL.Crypto.KeyExchange.KeyPair

  @capabilities %{versions: [:tlsv1_3], ciphers: [0x1301], groups: []}

  test "serializes a minimal deterministic ClientHello exactly" do
    profile = %WireProfile{session_id: :empty}

    assert {:ok, materialized} =
             Materializer.materialize(profile, @capabilities, %{},
               test_random: :binary.copy(<<0>>, 32)
             )

    assert {:ok, encoded} = Serializer.encode(materialized.client_hello)

    assert encoded ==
             Base.decode16!(
               "0100002B0303" <>
                 String.duplicate("00", 32) <>
                 "000002130101000000"
             )
  end

  test "materializes every bounded typed extension in declared order" do
    profile = %WireProfile{
      session_id: {:fixed, <<1, 2>>},
      extensions: [
        {:server_name, :from_connection},
        {:supported_groups, [:x25519]},
        {:ec_point_formats, [0]},
        {:signature_algorithms, [:ecdsa_secp256r1_sha256, :rsa_pss_rsae_sha256]},
        {:signature_algorithms_cert, [0x0403]},
        {:alpn, ["h2", "http/1.1"]},
        {:supported_versions, [:tlsv1_3]},
        {:psk_key_exchange_modes, [:psk_dhe_ke]},
        {:key_share, [:x25519]},
        {:padding, {:fixed, 3}},
        {:raw, 0xFE0D, <<1, 2>>},
        {:pre_shared_key, :deferred}
      ]
    }

    capabilities = %{
      versions: [:tlsv1_3],
      ciphers: [0x1301],
      groups: [:x25519],
      signature_algorithms: [:ecdsa_secp256r1_sha256, :rsa_pss_rsae_sha256, 0x0403],
      certificate_signature_algorithms: [0x0403],
      psk_key_exchange_modes: [:psk_dhe_ke],
      raw_extensions: [0xFE0D]
    }

    public_key = :binary.copy(<<0xAA>>, 32)
    key_pair = key_pair(:x25519, public_key, :binary.copy(<<0xBB>>, 32))

    assert {:ok, materialized} =
             Materializer.materialize(
               profile,
               capabilities,
               %{server_name: "example.com", pre_shared_key: <<0, 1, 2>>},
               test_random: :binary.copy(<<0x11>>, 32),
               test_key_share_generator: fn :x25519 -> {:ok, key_pair} end
             )

    assert [^key_pair] = materialized.key_pairs

    assert materialized.client_hello.extensions == [
             {0, <<0, 14, 0, 0, 11, "example.com">>},
             {10, <<0, 2, 0, 29>>},
             {11, <<1, 0>>},
             {13, <<0, 4, 4, 3, 8, 4>>},
             {50, <<0, 2, 4, 3>>},
             {16, <<0, 12, 2, "h2", 8, "http/1.1">>},
             {43, <<2, 3, 4>>},
             {45, <<1, 1>>},
             {51, <<0, 36, 0, 29, 0, 32, public_key::binary>>},
             {21, <<0, 0, 0>>},
             {0xFE0D, <<1, 2>>},
             {41, <<0, 1, 2>>}
           ]

    assert {:ok, encoded} = Serializer.encode(materialized.client_hello)
    assert <<1, body_length::24, _body::binary-size(body_length)>> = encoded
    assert byte_size(encoded) == 4 + body_length
  end

  test "resolves a deterministic GREASE slot consistently across registries" do
    caller = self()

    profile = %WireProfile{
      session_id: :empty,
      cipher_suites: [{:grease, :a}, 0x1301],
      grease: %GreasePolicy{mode: {:deterministic, 0}},
      extensions: [
        {:grease, :a},
        {:supported_groups, [{:grease, :a}, :x25519]},
        {:signature_algorithms, [{:grease, :a}, :ecdsa_secp256r1_sha256]},
        {:signature_algorithms_cert, [{:grease, :a}]},
        {:alpn, [{:grease, :a}, "h2"]},
        {:supported_versions, [{:grease, :a}, :tlsv1_3]},
        {:psk_key_exchange_modes, [{:grease, :a}, :psk_dhe_ke]},
        {:key_share, [{:grease, :a}, :x25519]}
      ]
    }

    capabilities = %{
      versions: [:tlsv1_3],
      ciphers: [0x1301],
      groups: [:x25519],
      signature_algorithms: [:ecdsa_secp256r1_sha256],
      psk_key_exchange_modes: [:psk_dhe_ke]
    }

    generator = fn group ->
      send(caller, {:generated, group})
      {:ok, key_pair(group, :binary.copy(<<0xCC>>, 32), :binary.copy(<<0xDD>>, 32))}
    end

    assert {:ok, materialized} =
             Materializer.materialize(profile, capabilities, %{},
               test_random: :binary.copy(<<0>>, 32),
               test_key_share_generator: generator
             )

    assert materialized.client_hello.cipher_suites == [0x0A0A, 0x1301]

    assert [
             {0x0A0A, <<>>},
             {10, <<0, 4, 0x0A, 0x0A, 0, 29>>},
             {13, <<0, 4, 0x0A, 0x0A, 4, 3>>},
             {50, <<0, 2, 0x0A, 0x0A>>},
             {16, <<0, 6, 2, 0x0A, 0x0A, 2, "h2">>},
             {43, <<4, 0x0A, 0x0A, 3, 4>>},
             {45, <<2, 0x0B, 1>>},
             {51, <<0, 42, 0x0A, 0x0A, 0, 2, 0x0A, 0x0A, 0, 29, 0, 32, _::binary-size(32)>>}
           ] = materialized.client_hello.extensions

    assert_receive {:generated, :x25519}
    refute_receive {:generated, {:grease, :a}}
    assert [%KeyPair{group: :x25519}] = materialized.key_pairs

    assert {:ok, encoded} = Serializer.encode(materialized.client_hello)

    assert Base.encode16(encoded) ==
             "01000099030300000000000000000000000000000000000000000000000000000000000000000000040A0A13010100006C0A0A0000000A000600040A0A001D000D000600040A0A04030032000400020A0A001000080006020A0A026832002B0005040A0A0304002D0003020B010033002C002A0A0A00020A0A001D0020CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
  end

  test "random GREASE selects registered values and reuses a slot" do
    profile = %WireProfile{
      session_id: :empty,
      cipher_suites: [{:grease, :a}, 0x1301],
      grease: %GreasePolicy{mode: :random},
      extensions: [
        {:grease, :a},
        {:signature_algorithms, [{:grease, :a}]},
        {:alpn, [{:grease, :a}]},
        {:psk_key_exchange_modes, [{:grease, :a}]}
      ]
    }

    capabilities =
      Map.merge(@capabilities, %{signature_algorithms: [], psk_key_exchange_modes: []})

    assert {:ok, materialized} =
             Materializer.materialize(profile, capabilities, %{},
               test_random: :binary.copy(<<0>>, 32)
             )

    [grease, 0x1301] = materialized.client_hello.cipher_suites
    assert grease in for(index <- 0..15, do: 0x0A0A + index * 0x1010)

    assert [
             {^grease, <<>>},
             {13, <<0, 2, ^grease::16>>},
             {16, <<0, 3, 2, ^grease::16>>},
             {45, <<1, grease_mode>>}
           ] = materialized.client_hello.extensions

    assert grease_mode in [0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4]
  end

  test "production defaults generate fresh random, session, and key-share state" do
    profile = %WireProfile{
      extensions: [
        {:supported_groups, [:x25519]},
        {:key_share, [:x25519]}
      ]
    }

    capabilities = %{@capabilities | groups: [:x25519]}

    assert {:ok, first} = Materializer.materialize(profile, capabilities, %{})
    assert {:ok, second} = Materializer.materialize(profile, capabilities, %{})
    refute first.client_hello.random == second.client_hello.random
    refute first.client_hello.session_id == second.client_hello.session_id
    refute first.client_hello.extensions == second.client_hello.extensions

    assert [%KeyPair{private_key: first_private}] = first.key_pairs
    assert [%KeyPair{private_key: second_private}] = second.key_pairs
    refute first_private == second_private
    refute inspect(first) =~ "key_pairs"
    refute inspect(first) =~ inspect(first_private)
    refute inspect(first.client_hello) =~ inspect(first_private)
  end

  test "requires and bounds dynamic extension material" do
    server_name_profile = %WireProfile{extensions: [{:server_name, :from_connection}]}
    psk_profile = %WireProfile{extensions: [{:pre_shared_key, :deferred}]}
    opts = [test_random: :binary.copy(<<0>>, 32)]

    assert {:error, {:missing_material, :server_name}} =
             Materializer.materialize(server_name_profile, @capabilities, %{}, opts)

    assert {:error, {:invalid_material, :server_name}} =
             Materializer.materialize(
               server_name_profile,
               @capabilities,
               %{server_name: :invalid},
               opts
             )

    assert {:error, {:extension_payload_length_exceeded, :server_name, 65_536, 65_535}} =
             Materializer.materialize(
               server_name_profile,
               @capabilities,
               %{server_name: :binary.copy("a", 65_531)},
               opts
             )

    assert {:error, {:extension_payload_length_exceeded, :server_name, 65_541, 65_535}} =
             Materializer.materialize(
               server_name_profile,
               @capabilities,
               %{server_name: :binary.copy("a", 65_536)},
               opts
             )

    assert {:error, {:missing_material, :pre_shared_key}} =
             Materializer.materialize(psk_profile, @capabilities, %{}, opts)

    assert {:error, {:invalid_material, :pre_shared_key}} =
             Materializer.materialize(
               psk_profile,
               @capabilities,
               %{pre_shared_key: nil},
               opts
             )

    assert {:error, {:extension_payload_length_exceeded, :pre_shared_key, 65_536, 65_535}} =
             Materializer.materialize(
               psk_profile,
               @capabilities,
               %{pre_shared_key: :binary.copy(<<0>>, 65_536)},
               opts
             )

    assert {:error, {:extensions_length_exceeded, 65_539, 65_535}} =
             Materializer.materialize(
               psk_profile,
               @capabilities,
               %{pre_shared_key: :binary.copy(<<0>>, 65_535)},
               opts
             )
  end

  test "rejects duplicate extension IDs after GREASE resolution" do
    profile = %WireProfile{
      session_id: :empty,
      grease: %GreasePolicy{mode: {:deterministic, 0}},
      extensions: [{:grease, :a}, {:raw, 0x0A0A, <<>>}]
    }

    capabilities = Map.put(@capabilities, :raw_extensions, [0x0A0A])

    assert {:error, {:duplicate_extension, 0x0A0A}} =
             Materializer.materialize(profile, capabilities, %{},
               test_random: :binary.copy(<<0>>, 32)
             )
  end

  test "rejects duplicate identifiers after GREASE resolution" do
    cipher_profile = %WireProfile{
      session_id: :empty,
      cipher_suites: [{:grease, :a}, 0x0A0A],
      grease: %GreasePolicy{mode: {:deterministic, 0}}
    }

    assert {:error, {:duplicate_materialized_identifier, :cipher_suites, 0x0A0A}} =
             Materializer.materialize(
               cipher_profile,
               %{@capabilities | ciphers: [0x0A0A]},
               %{},
               test_random: :binary.copy(<<0>>, 32)
             )

    signature_profile = %WireProfile{
      session_id: :empty,
      grease: %GreasePolicy{mode: {:deterministic, 0}},
      extensions: [{:signature_algorithms, [{:grease, :a}, 0x0A0A]}]
    }

    capabilities = Map.put(@capabilities, :signature_algorithms, [0x0A0A])

    assert {:error, {:duplicate_materialized_identifier, :signature_algorithms, 0x0A0A}} =
             Materializer.materialize(signature_profile, capabilities, %{},
               test_random: :binary.copy(<<0>>, 32)
             )
  end

  test "rejects invalid injected key-share generators" do
    profile = %WireProfile{
      extensions: [{:supported_groups, [:x25519]}, {:key_share, [:x25519]}]
    }

    capabilities = %{@capabilities | groups: [:x25519]}
    opts = [test_random: :binary.copy(<<0>>, 32)]

    assert {:error, {:invalid_test_option, :test_key_share_generator}} =
             Materializer.materialize(
               profile,
               capabilities,
               %{},
               Keyword.put(opts, :test_key_share_generator, :invalid)
             )

    wrong_group = key_pair(:secp256r1, :binary.copy(<<4>>, 65), :binary.copy(<<1>>, 32))

    assert {:error, {:invalid_generated_key_share, :x25519}} =
             Materializer.materialize(
               profile,
               capabilities,
               %{},
               Keyword.put(opts, :test_key_share_generator, fn :x25519 ->
                 {:ok, wrong_group}
               end)
             )

    assert {:error, {:invalid_key_source, :test}} =
             Materializer.materialize(
               profile,
               capabilities,
               %{},
               Keyword.put(opts, :test_key_share_generator, fn :x25519 ->
                 {:error, {:invalid_key_source, :test}}
               end)
             )
  end

  test "rejects invalid deterministic injection and malformed public ASTs" do
    assert {:error, {:invalid_test_option, :test_random}} =
             Materializer.materialize(%WireProfile{}, @capabilities, %{}, test_random: <<0>>)

    assert {:error, {:invalid_test_option, :test_session_id}} =
             Materializer.materialize(%WireProfile{}, @capabilities, %{}, test_session_id: <<0>>)

    assert {:error, {:unknown_materialization_option, :random}} =
             Materializer.materialize(%WireProfile{}, @capabilities, %{}, random: <<0>>)

    ast = %AST{
      legacy_version: 0x0303,
      random: <<0>>,
      session_id: <<>>,
      cipher_suites: [0x1301],
      compression_methods: [0],
      extensions: []
    }

    assert {:error, {:invalid_client_hello, :random}} = Serializer.encode(ast)
    assert {:error, {:invalid_client_hello, :structure}} = Serializer.encode(%{})
  end

  defp key_pair(group, public_key, private_key) do
    %KeyPair{group: group, public_key: public_key, private_key: private_key}
  end
end

defmodule SSL.ClientHello.ProfileTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.ClientHello.{GreasePolicy, Profile, RecordPolicy, WireProfile}

  @capabilities %{
    versions: [:tlsv1_3],
    ciphers: [0x1301, 0x1302],
    groups: [:x25519, :secp256r1],
    signature_algorithms: [:ecdsa_secp256r1_sha256, :rsa_pss_rsae_sha256]
  }

  test "accepts a supported profile without changing wire order" do
    cipher_suites = [0x1302, 0x1301]

    extensions = [
      {:server_name, :from_connection},
      {:supported_groups, [:secp256r1, :x25519]},
      {:signature_algorithms, [:ecdsa_secp256r1_sha256, :rsa_pss_rsae_sha256]},
      {:alpn, ["h2", "http/1.1"]},
      {:supported_versions, [:tlsv1_3]},
      {:key_share, [:x25519]}
    ]

    profile =
      struct(WireProfile,
        name: :structural_golden,
        cipher_suites: cipher_suites,
        extensions: extensions
      )

    assert {:ok, validated} = Profile.validate(profile, @capabilities)
    assert ^profile = validated
    assert ^cipher_suites = validated.cipher_suites
    assert ^extensions = validated.extensions
  end

  test "requires explicit version, cipher, and group capabilities" do
    profile = struct(WireProfile)

    for missing <- [:versions, :ciphers, :groups] do
      capabilities = Map.delete(@capabilities, missing)

      assert {:error, {:invalid_capabilities, ^missing}} =
               Profile.validate(profile, capabilities)
    end
  end

  test "rejects malformed fixed ClientHello policies" do
    invalid_profiles = [
      {struct(WireProfile, legacy_version: 0x0304), :legacy_version},
      {struct(WireProfile, session_id: {:fixed, :not_binary}), :session_id},
      {struct(WireProfile, session_id: {:fixed, :binary.copy(<<0>>, 33)}), :session_id},
      {struct(WireProfile, cipher_suites: :unordered), :cipher_suites},
      {struct(WireProfile, compression_methods: [1]), :compression_methods},
      {struct(WireProfile, extensions: %{}), :extensions},
      {struct(WireProfile, grease: %GreasePolicy{mode: {:deterministic, -1}}), :grease},
      {struct(WireProfile, record: %RecordPolicy{mode: {:split, 128}}), :record}
    ]

    for {profile, field} <- invalid_profiles do
      assert {:error, {:invalid_profile, ^field}} = Profile.validate(profile, @capabilities)
    end
  end

  test "requires an enabled GREASE policy for symbolic slots" do
    profile = struct(WireProfile, cipher_suites: [{:grease, :a}, 0x1301])

    assert {:error, :grease_not_supported} = Profile.validate(profile, @capabilities)

    for mode <- [:random, {:deterministic, 0}] do
      enabled = %{profile | grease: %GreasePolicy{mode: mode}}
      assert {:ok, ^enabled} = Profile.validate(enabled, @capabilities)
    end
  end

  test "rejects malformed extension specifications" do
    profile = struct(WireProfile, extensions: [{:unknown_extension, <<>>}])

    assert {:error, {:invalid_extension, {:unknown_extension, <<>>}}} =
             Profile.validate(profile, @capabilities)
  end

  test "rejects nil and false extensions without crashing" do
    for extension <- [nil, false] do
      profile = struct(WireProfile, extensions: [extension])

      assert {:error, {:invalid_extension, ^extension}} =
               Profile.validate(profile, @capabilities)
    end
  end

  test "rejects malformed extension tuples and wrong arities" do
    invalid_extensions = [
      {},
      {:alpn},
      {:alpn, ["h2"], :extra},
      {:raw, 0xFE0D},
      {:raw, 0xFE0D, <<>>, :extra}
    ]

    for extension <- invalid_extensions do
      profile = struct(WireProfile, extensions: [extension])

      assert {:error, {:invalid_extension, ^extension}} =
               Profile.validate(profile, @capabilities)
    end
  end

  test "rejects non-list extensions" do
    profile = struct(WireProfile, extensions: %{alpn: ["h2"]})

    assert {:error, {:invalid_profile, :extensions}} =
             Profile.validate(profile, @capabilities)
  end

  test "rejects malformed capability structures" do
    invalid_capabilities = [
      {nil, :structure},
      {%{@capabilities | versions: :tlsv1_3}, :versions},
      {%{@capabilities | ciphers: 0x1301}, :ciphers},
      {%{@capabilities | groups: :x25519}, :groups},
      {Map.put(@capabilities, :signature_algorithms, :all), :signature_algorithms},
      {Map.put(@capabilities, :psk_key_exchange_modes, :all), :psk_key_exchange_modes},
      {Map.put(@capabilities, :raw_extensions, [0x1_0000]), :raw_extensions},
      {Map.put(@capabilities, :key_share_sizes, %{x25519: 0}), :key_share_sizes}
    ]

    profile = struct(WireProfile)

    for {capabilities, field} <- invalid_capabilities do
      assert {:error, {:invalid_capabilities, ^field}} =
               Profile.validate(profile, capabilities)
    end
  end

  property "bounded malformed extension inputs return tagged errors" do
    check all(
            extensions <- list_of(malformed_extension(), min_length: 1, max_length: 8),
            max_runs: 100
          ) do
      profile = struct(WireProfile, extensions: extensions)

      assert {:error, {:invalid_extension, _extension}} =
               Profile.validate(profile, @capabilities)
    end
  end

  test "rejects duplicate extension identities" do
    duplicate_typed =
      struct(WireProfile,
        extensions: [
          {:alpn, ["h2"]},
          {:alpn, ["http/1.1"]}
        ]
      )

    assert {:error, {:duplicate_extension, 16}} =
             Profile.validate(duplicate_typed, @capabilities)

    duplicate_raw_identity =
      struct(WireProfile,
        extensions: [
          {:alpn, ["h2"]},
          {:raw, 16, <<0, 3, 2, "h2">>}
        ]
      )

    capabilities = Map.put(@capabilities, :raw_extensions, [16])

    assert {:error, {:duplicate_extension, 16}} =
             Profile.validate(duplicate_raw_identity, capabilities)
  end

  test "requires pre_shared_key to be the final extension" do
    profile =
      struct(WireProfile,
        extensions: [
          {:pre_shared_key, :deferred},
          {:supported_versions, [:tlsv1_3]}
        ]
      )

    assert {:error, :pre_shared_key_must_be_last} =
             Profile.validate(profile, @capabilities)
  end

  test "rejects unsupported advertised versions" do
    profile =
      struct(WireProfile,
        extensions: [{:supported_versions, [:tlsv1_3, :tlsv1_2]}]
      )

    assert {:error, {:unsupported_versions, [:tlsv1_2]}} =
             Profile.validate(profile, @capabilities)
  end

  test "rejects unsupported advertised cipher suites" do
    profile = struct(WireProfile, cipher_suites: [0x1301, 0xC02F, 0x1303])

    assert {:error, {:unsupported_ciphers, [0xC02F, 0x1303]}} =
             Profile.validate(profile, @capabilities)
  end

  test "rejects unsupported groups in supported_groups and key_share" do
    supported_groups =
      struct(WireProfile, extensions: [{:supported_groups, [:x25519, :secp384r1]}])

    key_share = struct(WireProfile, extensions: [{:key_share, [:x25519, :ffdhe2048]}])

    assert {:error, {:unsupported_groups, [:secp384r1]}} =
             Profile.validate(supported_groups, @capabilities)

    assert {:error, {:unsupported_groups, [:ffdhe2048]}} =
             Profile.validate(key_share, @capabilities)
  end

  test "rejects empty, non-binary, oversized, and collectively oversized ALPN names" do
    too_large_list = List.duplicate(:binary.copy("a", 255), 256)

    for protocols <- [[], [""], [:h2], [:binary.copy("a", 256)], too_large_list] do
      profile = struct(WireProfile, extensions: [{:alpn, protocols}])

      assert {:error, :invalid_alpn} = Profile.validate(profile, @capabilities)
    end
  end

  test "allows raw extensions only through an explicit extension ID allowlist" do
    profile = struct(WireProfile, extensions: [{:raw, 0xFE0D, <<1, 2, 3>>}])

    assert {:error, {:raw_extension_not_allowed, 0xFE0D}} =
             Profile.validate(profile, @capabilities)

    capabilities = Map.put(@capabilities, :raw_extensions, [0xFE0D])
    assert {:ok, ^profile} = Profile.validate(profile, capabilities)
  end

  test "does not let raw extensions bypass typed extension validation" do
    for extension_id <- [0, 43, 51] do
      profile = struct(WireProfile, extensions: [{:raw, extension_id, <<>>}])
      capabilities = Map.put(@capabilities, :raw_extensions, [extension_id])

      assert {:error, {:raw_extension_requires_typed_form, ^extension_id}} =
               Profile.validate(profile, capabilities)
    end
  end

  test "rejects extension values that cannot fit their wire representation" do
    oversized_raw = :binary.copy(<<0>>, 65_536)

    invalid_extensions = [
      {:padding, 65_536},
      {:padding, {:fixed, 65_536}},
      {:raw, 0xFE0D, oversized_raw},
      {:ec_point_formats, List.duplicate(0, 256)},
      {:ec_point_formats, [:uncompressed]},
      {:signature_algorithms, [<<1, 2>>]},
      {:signature_algorithms_cert, [-1]},
      {:psk_key_exchange_modes, [256]},
      {:pre_shared_key, :encoded_material}
    ]

    capabilities = Map.put(@capabilities, :raw_extensions, [0xFE0D])

    for extension <- invalid_extensions do
      profile = struct(WireProfile, extensions: [extension])
      assert {:error, {:invalid_extension, ^extension}} = Profile.validate(profile, capabilities)
    end
  end

  test "rejects aggregate vectors that cannot fit their ClientHello fields" do
    oversized_ciphers = Enum.to_list(0..32_767)

    cipher_profile = struct(WireProfile, cipher_suites: oversized_ciphers)
    cipher_capabilities = %{@capabilities | ciphers: oversized_ciphers}

    assert {:error, {:invalid_profile, :cipher_suites}} =
             Profile.validate(cipher_profile, cipher_capabilities)

    key_share_profile =
      struct(WireProfile, extensions: [{:key_share, List.duplicate(:x25519, 20_000)}])

    assert {:error, {:duplicate_key_share, :x25519}} =
             Profile.validate(key_share_profile, @capabilities)

    raw_extensions = [
      {:raw, 0xFE0D, :binary.copy(<<0>>, 40_000)},
      {:raw, 0xFE0E, :binary.copy(<<0>>, 40_000)}
    ]

    raw_profile = struct(WireProfile, extensions: raw_extensions)
    raw_capabilities = Map.put(@capabilities, :raw_extensions, [0xFE0D, 0xFE0E])

    assert {:error, {:extensions_length_exceeded, _actual, 65_535}} =
             Profile.validate(raw_profile, raw_capabilities)
  end

  test "requires at least one cipher suite and accepts the largest encodable vector" do
    empty_profile = struct(WireProfile, cipher_suites: [])

    assert {:error, {:invalid_profile, :cipher_suites}} =
             Profile.validate(empty_profile, @capabilities)

    maximum_ciphers = Enum.to_list(0..32_766)
    maximum_profile = struct(WireProfile, cipher_suites: maximum_ciphers)
    maximum_capabilities = %{@capabilities | ciphers: maximum_ciphers}

    assert {:ok, ^maximum_profile} = Profile.validate(maximum_profile, maximum_capabilities)
  end

  test "requires symbolic signature algorithms to be explicit capabilities" do
    profile = struct(WireProfile, extensions: [{:signature_algorithms, [:bogus]}])

    assert {:error, {:unsupported_signature_algorithms, [:bogus]}} =
             Profile.validate(profile, @capabilities)
  end

  test "requires separate certificate signature capabilities" do
    profile = struct(WireProfile, extensions: [{:signature_algorithms_cert, [0x0403]}])

    assert {:error, {:unsupported_certificate_signature_algorithms, [0x0403]}} =
             Profile.validate(profile, @capabilities)

    capabilities = Map.put(@capabilities, :certificate_signature_algorithms, [0x0403])
    assert {:ok, ^profile} = Profile.validate(profile, capabilities)
  end

  test "requires key shares to be an ordered subset of unique supported groups" do
    invalid_profiles = [
      {profile(extensions: [{:supported_groups, [:x25519, :x25519]}]),
       {:duplicate_supported_group, :x25519}},
      {profile(extensions: [{:key_share, [:x25519]}]), :key_share_requires_supported_groups},
      {profile(extensions: [{:key_share, []}]), :key_share_requires_supported_groups},
      {profile(extensions: [{:supported_groups, [:x25519]}]),
       :supported_groups_requires_key_share},
      {profile(
         extensions: [
           {:supported_groups, [:x25519]},
           {:key_share, [:secp256r1]}
         ]
       ), {:key_share_not_ordered_subset, [:secp256r1]}},
      {profile(
         extensions: [
           {:supported_groups, [:x25519, :secp256r1]},
           {:key_share, [:secp256r1, :x25519]}
         ]
       ), {:key_share_not_ordered_subset, [:secp256r1, :x25519]}}
    ]

    for {profile, reason} <- invalid_profiles do
      assert {:error, ^reason} = Profile.validate(profile, @capabilities)
    end
  end

  test "allows an explicitly empty key_share when supported_groups is present" do
    profile =
      profile(
        extensions: [
          {:supported_groups, [:x25519]},
          {:key_share, []}
        ]
      )

    assert {:ok, ^profile} = Profile.validate(profile, @capabilities)
  end

  defp profile(attrs) do
    struct(WireProfile, Keyword.put_new(attrs, :cipher_suites, [0x1301]))
  end

  defp malformed_extension do
    one_of([
      member_of([nil, false, :not_a_tuple, {}, {:alpn}, {:raw, 0xFE0D}]),
      map(binary(max_length: 8), &{:unknown_extension, &1}),
      map(integer(-1_000..1_000), &{:supported_versions, &1}),
      map(list_of(binary(max_length: 4), max_length: 4), &{:alpn, &1, :extra})
    ])
  end
end

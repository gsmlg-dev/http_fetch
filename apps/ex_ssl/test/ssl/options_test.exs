defmodule SSL.OptionsTest do
  use ExUnit.Case, async: true

  test "TLS12 rejects an effective signature list with no supported cipher authentication" do
    assert {:error, {:options, {:signature_algs, :unsupported_or_invalid}}} =
             SSL.Options.normalize("example.com",
               versions: [:"tlsv1.2"],
               signature_algs: [:ed25519]
             )
  end

  test "consumer binary/passive/raw options retain DNS identity independently of IP routing" do
    opts = [
      :binary,
      active: false,
      packet: :raw,
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      server_name_indication: ~c"mail.example",
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]

    assert {:ok, options} = SSL.Options.normalize({127, 0, 0, 1}, opts)
    assert options.identity == {:dns_id, "mail.example"}
    assert options.context == %{server_name: "mail.example"}
    assert options.hostname_check[:match_fun]
  end

  test "rejects unsupported security and socket options" do
    for option <- [
          active: true,
          packet: :line,
          mode: :list,
          verify: :verify_none,
          customize_hostname_check: [fail_callback: fn _ -> true end]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize(~c"mail.example", [option])
    end
  end

  test "TLS 1.2-only and mixed versions generate bounded ordered ClientHello offers" do
    for {versions, expected} <- [
          {[:"tlsv1.2"], [0x0303]},
          {[:"tlsv1.3", :"tlsv1.2"], [0x0304, 0x0303]},
          {[:"tlsv1.2", :"tlsv1.3"], [0x0303, 0x0304]}
        ] do
      assert {:ok, %{profile: profile}} =
               SSL.Options.normalize("mail.example", versions: versions)

      assert {:supported_versions, ^expected} =
               List.keyfind(profile.extensions, :supported_versions, 0)

      assert {:extended_master_secret, <<>>} in profile.extensions
      assert {:renegotiation_info, <<0>>} in profile.extensions
      assert {:ec_point_formats, [0]} in profile.extensions

      assert Enum.all?(expected, fn version ->
               Enum.any?(profile.cipher_suites, fn id ->
                 SSL.Capabilities.resolve(:cipher_suite, id).version == version
               end)
             end)

      assert 0x0304 in expected == (List.keyfind(profile.extensions, :key_share, 0) != nil)

      assert {:ok, materialized} =
               SSL.ClientHello.Materializer.materialize(profile, SSL.Options.capabilities(), %{
                 server_name: "mail.example"
               })

      assert {:ok, encoded} = SSL.ClientHello.Serializer.encode(materialized.client_hello)
      assert {:ok, offer} = SSL.Protocol.ClientOffer.from_client_hello(encoded)
      assert offer.offered_versions == expected
      assert materialized.key_pairs == [] == (expected == [0x0303])
      assert 23 in offer.extension_ids
      assert 0xFF01 in offer.extension_ids
    end
  end

  test "TLS version and cipher/profile conflicts reject without fallback" do
    for versions <- [[], [:"tlsv1.2", :"tlsv1.2"], [:"tlsv1.3", :"tlsv1.3"], [:"tlsv1.1"]] do
      assert {:error, {:options, _}} = SSL.Options.normalize("mail.example", versions: versions)
    end

    assert {:error, {:options, {:ciphers, :unsupported_or_invalid}}} =
             SSL.Options.normalize("mail.example",
               versions: [:"tlsv1.2"],
               ciphers: ["TLS_AES_128_GCM_SHA256"]
             )

    assert {:error, {:options, {:ciphers, :unsupported_or_invalid}}} =
             SSL.Options.normalize("mail.example",
               versions: [:"tlsv1.3", :"tlsv1.2"],
               ciphers: ["TLS_AES_128_GCM_SHA256"]
             )

    assert {:ok, %{profile: tls13}} = SSL.Options.normalize("mail.example", [])

    assert {:error, {:options, {:versions, :profile_conflict}}} =
             SSL.Options.normalize("mail.example",
               versions: [:"tlsv1.2"],
               ex_ssl: [profile: tls13]
             )

    assert {:ok, %{profile: tls12}} =
             SSL.Options.normalize("mail.example", versions: [:"tlsv1.2"])

    assert {:error, {:options, {:versions, :profile_conflict}}} =
             SSL.Options.normalize("mail.example",
               versions: [:"tlsv1.2"],
               ex_ssl: [
                 profile: %{tls12 | extensions: tls12.extensions ++ [{:key_share, [0x001D]}]}
               ]
             )

    invalid_ems =
      %{
        tls12
        | extensions:
            List.keyreplace(
              tls12.extensions,
              :extended_master_secret,
              0,
              {:extended_master_secret, <<1>>}
            )
      }

    assert {:error, {:options, {:ex_ssl, :unsupported_profile}}} =
             SSL.Options.normalize("mail.example",
               versions: [:"tlsv1.2"],
               ex_ssl: [profile: invalid_ems]
             )
  end

  test "normalizes active-once, depth, and send policy without accepting weaker variants" do
    assert {:ok, %{active: :once, depth: 2, send_timeout: :infinity, send_timeout_close: true}} =
             SSL.Options.normalize("mail.example",
               active: :once,
               depth: 2,
               send_timeout: :infinity,
               send_timeout_close: true
             )

    for option <- [
          active: true,
          depth: -1,
          depth: 1.5,
          send_timeout: -1,
          send_timeout: 1.5,
          send_timeout_close: false
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize("mail.example", [option])
    end

    end_time =
      :erlang.system_info(:end_time)
      |> :erlang.convert_time_unit(:native, :millisecond)

    unrepresentable_timeout = end_time - System.monotonic_time(:millisecond) + 1_000

    assert {:error, {:options, _}} =
             SSL.Options.normalize("mail.example", send_timeout: unrepresentable_timeout)
  end

  test "normalizes a complete setopts request atomically" do
    assert {:ok, [active: :once, send_timeout: :infinity, send_timeout_close: true]} =
             SSL.Options.normalize_setopts(
               active: :once,
               send_timeout: :infinity,
               send_timeout_close: true
             )

    for options <- [
          [active: :once, active: false],
          [packet: :raw],
          [depth: 1],
          [send_timeout_close: false],
          [unknown: :value]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize_setopts(options)
    end
  end

  test "adds ordered ALPN to the default profile" do
    assert {:ok, %{profile: profile, alpn_advertised_protocols: ["h2", "http/1.1"]}} =
             SSL.Options.normalize("mail.example", alpn_advertised_protocols: ["h2", "http/1.1"])

    assert {:alpn, ["h2", "http/1.1"]} = Enum.find(profile.extensions, &match?({:alpn, _}, &1))
  end

  test "requires an exact ALPN match for an explicit profile" do
    profile = default_profile_with_alpn(["h2", "http/1.1"])

    assert {:ok, %{profile: ^profile}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: profile],
               alpn_advertised_protocols: ["h2", "http/1.1"]
             )

    assert {:error, {:options, {:alpn_advertised_protocols, :profile_conflict}}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: profile],
               alpn_advertised_protocols: ["http/1.1", "h2"]
             )
  end

  test "does not inject top-level ALPN into an explicit profile without ALPN" do
    profile = default_profile_with_alpn(nil)

    assert {:error, {:options, {:alpn_advertised_protocols, :profile_conflict}}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: profile],
               alpn_advertised_protocols: ["h2"]
             )
  end

  test "rejects malformed or oversized ALPN lists before connecting" do
    for protocols <- [
          [],
          [""],
          [:h2],
          [String.duplicate("a", 256)],
          List.duplicate("a", 32_768)
        ] do
      assert {:error, {:options, {:alpn_advertised_protocols, :unsupported_or_invalid}}} =
               SSL.Options.normalize("mail.example", alpn_advertised_protocols: protocols)
    end
  end

  test "validates malformed options and timeouts without making a connection" do
    for options <- [
          nil,
          %{},
          [:invalid],
          [{:active, false, :extra}],
          [active: false, active: false]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize(~c"mail.example", options)
    end

    for timeout <- [-1, 1.0, nil, :invalid] do
      assert {:error, :badarg} = SSL.Options.deadline(timeout)
    end

    end_time =
      :erlang.system_info(:end_time)
      |> :erlang.convert_time_unit(:native, :millisecond)

    unrepresentable_timeout = end_time - System.monotonic_time(:millisecond) + 1_000
    assert {:error, :badarg} = SSL.Options.deadline(unrepresentable_timeout)
    assert {:ok, _deadline} = SSL.Options.deadline(4_294_967_296)

    assert {:ok, :infinity} = SSL.Options.deadline(:infinity)
    assert {:ok, deadline} = SSL.Options.deadline(0)
    assert SSL.Options.remaining(deadline) == 0
  end

  test "upgrade requires an explicit reference identity" do
    assert {:error, {:options, _}} = SSL.Options.normalize(:upgrade, [])

    assert {:ok, %{identity: {:dns_id, "mail.example"}}} =
             SSL.Options.normalize(:upgrade, server_name_indication: ~c"mail.example")
  end

  test "IP connection never fabricates SNI" do
    assert {:ok, options} = SSL.Options.normalize({127, 0, 0, 1}, [])
    assert options.identity == {:ip, {127, 0, 0, 1}}
    assert options.context == %{}
    refute Enum.any?(options.profile.extensions, &match?({:server_name, _}, &1))

    for host <- ["::1", ~c"::1", "127.0.0.1"] do
      assert {:ok, textual} = SSL.Options.normalize(host, [])
      assert match?({:ip, _}, textual.identity)
      assert textual.context == %{}
      refute Enum.any?(textual.profile.extensions, &match?({:server_name, _}, &1))
    end
  end

  test "incomplete profiles are rejected before a TCP connection is attempted" do
    assert {:error, {:options, _}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: %SSL.ClientHello.WireProfile{}]
             )
  end

  test "accepts an explicit certificate signature policy only when PKIX can enforce it" do
    assert {:ok, %{profile: profile}} = SSL.Options.normalize("mail.example", [])

    profile = %{
      profile
      | extensions: profile.extensions ++ [{:signature_algorithms_cert, [0x0403]}]
    }

    assert {:ok, %{profile: ^profile}} =
             SSL.Options.normalize("mail.example", ex_ssl: [profile: profile])
  end

  test "ordered public TLS policy lists materialize exact ClientHello choices" do
    suites = :ssl.cipher_suites(:exclusive, :"tlsv1.3")
    aes_256 = Enum.find(suites, &(&1.cipher == :aes_256_gcm))

    assert {:ok, %{profile: profile}} =
             SSL.Options.normalize("mail.example",
               ciphers: [aes_256, "TLS_AES_128_GCM_SHA256"],
               signature_algs: [:rsa_pss_rsae_sha384, :ecdsa_secp256r1_sha256],
               signature_algs_cert: [:rsa_pkcs1_sha256, :rsa_pss_rsae_sha384],
               supported_groups: [:secp384r1, :x25519]
             )

    assert profile.cipher_suites == [0x1302, 0x1301]
    assert {:supported_groups, [0x0018, 0x001D]} in profile.extensions
    assert {:key_share, [0x0018]} in profile.extensions
    assert {:signature_algorithms, [0x0805, 0x0403]} in profile.extensions
    assert {:signature_algorithms_cert, [0x0401, 0x0805]} in profile.extensions

    assert {:ok, materialized} =
             SSL.ClientHello.Materializer.materialize(profile, SSL.Options.capabilities(), %{
               server_name: "mail.example"
             })

    assert {:ok, encoded} =
             SSL.ClientHello.Serializer.encode(materialized.client_hello)

    assert {:ok, offer} = SSL.Protocol.ClientOffer.from_client_hello(encoded)
    assert offer.cipher_suites == [0x1302, 0x1301]
    assert offer.supported_groups == [0x0018, 0x001D]
    assert offer.signature_schemes == [0x0805, 0x0403]
    assert offer.certificate_signature_schemes == [0x0401, 0x0805]
  end

  test "invalid or duplicate public TLS policy values fail instead of using defaults" do
    for option <- [
          ciphers: [],
          ciphers: ["TLS_RSA_WITH_AES_128_GCM_SHA256"],
          ciphers: ["TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"],
          signature_algs: [],
          signature_algs: [0x0804],
          signature_algs: [:rsa_pkcs1_sha256],
          signature_algs_cert: [0x0401],
          signature_algs_cert: [:rsa_pkcs1_sha256, :rsa_pkcs1_sha256],
          supported_groups: [],
          supported_groups: [0x001D],
          supported_groups: [:x25519, :x25519],
          signature_algs: [:rsa_pss_rsae_sha256 | :bad],
          ciphers: [~c"TLS_AES_128_GCM_SHA256" | :bad]
        ] do
      assert {:error, {:options, _}} = SSL.Options.normalize("mail.example", [option])
    end
  end

  test "explicit profiles cannot silently override supplied TLS policy" do
    assert {:ok, %{profile: profile}} = SSL.Options.normalize("mail.example", [])

    assert {:ok, %{profile: ^profile}} =
             SSL.Options.normalize("mail.example",
               ex_ssl: [profile: profile],
               supported_groups: [:x25519, :secp256r1, :secp384r1]
             )

    for option <- [
          ciphers: ["TLS_AES_256_GCM_SHA384"],
          signature_algs: [:rsa_pss_rsae_sha256],
          signature_algs_cert: [:rsa_pkcs1_sha256],
          supported_groups: [:secp384r1]
        ] do
      assert {:error, {:options, {_key, :profile_conflict}}} =
               SSL.Options.normalize("mail.example", [{:ex_ssl, [profile: profile]}, option])
    end
  end

  defp default_profile_with_alpn(protocols) do
    assert {:ok, %{profile: profile}} = SSL.Options.normalize("mail.example", [])

    extensions =
      case protocols do
        nil -> profile.extensions
        protocols -> profile.extensions ++ [{:alpn, protocols}]
      end

    %{profile | extensions: extensions}
  end
end

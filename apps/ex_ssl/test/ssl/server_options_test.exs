defmodule SSL.ServerOptionsTest do
  use ExUnit.Case, async: true

  alias SSL.ServerOptions

  @dir Path.expand("../support/server", __DIR__)
  @cert Path.join(@dir, "cert.pem")
  @key Path.join(@dir, "key.pem")
  @ca Path.join(@dir, "ca.pem")

  defp base, do: [certfile: @cert, keyfile: @key]

  test "defaults" do
    assert {:ok, %{alpn: nil, client_auth: nil, sni: nil, tcp: [], transport_parameters: nil} = o} =
             ServerOptions.build(base())

    assert o.ciphers != [] and Enum.all?(o.ciphers, &(&1 in 0x1301..0x1303))
    assert o.identity.chain != []
    assert Enum.all?(o.signature_algorithms, &(&1 in o.identity.signature_schemes))
  end

  test "bare address families pass to the carrier in order" do
    assert {:ok, %{tcp: [:inet6]}} = ServerOptions.build(base() ++ [:inet6])

    assert {:ok, %{tcp: [:inet, {:backlog, 5}, :local]}} =
             ServerOptions.build([:binary, :inet] ++ base() ++ [{:backlog, 5}, :local])

    assert {:error, {:unsupported_option, :mode}} = ServerOptions.build(base() ++ [:list])
  end

  test "alpn, ciphers and certs_keys" do
    assert {:ok, %{alpn: ["h2", "http/1.1"]}} =
             ServerOptions.build(base() ++ [alpn_preferred_protocols: ["h2", "http/1.1"]])

    assert {:ok, %{ciphers: [0x1302]}} =
             ServerOptions.build(base() ++ [ciphers: [:tls_aes_256_gcm_sha384]])

    assert {:error, {:invalid_option, :ciphers}} =
             ServerOptions.build(base() ++ [ciphers: [0xC02F]])

    assert {:ok, %{identity: %{}}} =
             ServerOptions.build(certs_keys: [%{certfile: @cert, keyfile: @key}])
  end

  test "unsupported options" do
    assert {:error, {:unsupported_option, :versions}} =
             ServerOptions.build(base() ++ [versions: [:"tlsv1.2"]])

    assert {:ok, _} = ServerOptions.build(base() ++ [versions: [:"tlsv1.3"]])

    for {k, v} <- [
          session_tickets: :stateless,
          reuse_sessions: true,
          verify_fun: {fn _, _, s -> {:valid, s} end, nil},
          partial_chain: fn _ -> :unknown_ca end
        ] do
      assert {:error, {:unsupported_option, ^k}} = ServerOptions.build([{k, v} | base()])
    end

    for {k, v} <- [honor_cipher_order: true, log_level: :debug, signature_algs: [], eccs: []] do
      assert {:error, {:unsupported_option, ^k}} = ServerOptions.build([{k, v} | base()])
    end

    assert {:ok, _} =
             ServerOptions.build([session_tickets: :disabled, reuse_sessions: false] ++ base())
  end

  # OTP 28 ssl_config:ssl_options/0 plus the keys split_options/2 also strips.
  @otp_ssl_options ~w(
    alpn_advertised_protocols alpn_preferred_protocols anti_replay beast_mitigation
    cacertfile cacerts cert certs_keys certfile certificate_authorities ciphers
    client_renegotiation cookie crl_cache crl_check customize_hostname_check depth
    dh dhfile early_data eccs erl_dist fail_if_no_peer_cert fallback handshake
    hibernate_after honor_cipher_order honor_ecc_order keep_secrets key keyfile
    key_update_at ktls log_level max_handshake_size middlebox_comp_mode
    max_fragment_length next_protocol_selector next_protocols_advertised stapling
    padding_check partial_chain password protocol psk_groups psk_identity
    receiver_spawn_opts renegotiate_at reuse_session reuse_sessions
    secure_renegotiate sender_spawn_opts server_name_indication session_tickets
    stateless_tickets_seed signature_algs signature_algs_cert sni_fun sni_hosts
    srp_identity supported_groups use_ticket use_srtp user_lookup_fun verify
    verify_fun cert_policy_opts allow_any_ca_purpose versions
    cb_info client_preferred_next_protocols ssl_imp
  )a
  # Keys the server implements; session_tickets/reuse_sessions only when disabled.
  @supported ~w(
    alpn_preferred_protocols cacertfile cacerts cert certs_keys certfile ciphers depth
    fail_if_no_peer_cert key keyfile password reuse_sessions session_tickets
    sni_fun sni_hosts verify versions
  )a

  test "every OTP :ssl-only option is rejected instead of reaching :gen_tcp" do
    for key <- @otp_ssl_options -- @supported do
      assert {:error, {:unsupported_option, ^key}} =
               ServerOptions.build([{key, :x} | base()]),
             "#{key} was not rejected"
    end
  end

  test "the OTP option table matches the installed :ssl when its source is present" do
    path = Path.join(:code.lib_dir(:ssl), "src/ssl_config.erl")

    with {:ok, source} <- File.read(path),
         [_, body] <- Regex.run(~r/^ssl_options\(\) ->\s*\[(.*?)\]\./ms, source) do
      installed = body |> String.split(~r/[\s,]+/, trim: true) |> Enum.map(&String.to_atom/1)
      assert installed -- @otp_ssl_options == []
    end
  end

  test "client authentication" do
    assert {:ok, %{client_auth: %{require: false, depth: 10, trust: [_ | _]}}} =
             ServerOptions.build(base() ++ [verify: :verify_peer, cacertfile: @ca])

    assert {:ok, %{client_auth: %{require: true}}} =
             ServerOptions.build(
               base() ++ [verify: :verify_peer, cacertfile: @ca, fail_if_no_peer_cert: true]
             )

    assert {:error, {:invalid_option, :cacerts}} =
             ServerOptions.build(base() ++ [verify: :verify_peer])

    assert {:error, {:invalid_option, :cacerts}} =
             ServerOptions.build(base() ++ [verify: :verify_peer, cacertfile: "/nonexistent"])
  end

  test "tcp passthrough and sni" do
    assert {:ok, %{tcp: [send_timeout: 1230]}} =
             ServerOptions.build(base() ++ [send_timeout: 1230])

    assert {:error, :server_identity_required} = ServerOptions.build([])

    fun = fn _ -> :undefined end
    assert {:ok, %{sni: {:fun, ^fun}, identity: nil}} = ServerOptions.build(sni_fun: fun)

    assert {:ok, %{sni: {:hosts, %{~c"a.test" => [%SSL.ClientIdentity{}]}}}} =
             ServerOptions.build(sni_hosts: [{~c"a.test", [certfile: @cert, keyfile: @key]}])
  end
end

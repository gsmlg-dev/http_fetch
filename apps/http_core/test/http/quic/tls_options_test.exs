defmodule HTTP.QUIC.TLSOptionsTest do
  use ExUnit.Case, async: true

  alias HTTP.QUIC.TLSOptions
  alias SSL.ClientHello.{RecordPolicy, WireProfile}

  @fixtures Path.expand("../../../../http_fetch/test/support/fixtures", __DIR__)
  @ca Path.join(@fixtures, "localhost-ca.pem")
  @cert Path.join(@fixtures, "localhost.pem")
  @key Path.join(@fixtures, "localhost.key")

  test "normalizes explicit CA trust, DNS identity, SNI, ALPN, and supported algorithms" do
    assert {:ok, options} =
             TLSOptions.normalize("localhost",
               cacertfile: @ca,
               server_name_indication: ~c"localhost",
               alpn: ["ex-quic-phase1"],
               ciphers: [0x1301],
               groups: [0x001D],
               signature_algorithms: [0x0804]
             )

    assert options[:reference_identity] == {:dns_id, "localhost"}
    assert options[:server_name] == "localhost"
    assert options[:alpn] == ["ex-quic-phase1"]
    assert is_list(options[:cacerts]) and options[:cacerts] != []
    assert options[:ciphers] == [0x1301]
    assert options[:groups] == [0x001D]
    assert options[:signature_algorithms] == [0x0804]
    refute Keyword.has_key?(options, :transport_parameters)
  end

  test "uses an IP reference identity without emitting SNI" do
    assert {:ok, options} = TLSOptions.normalize("127.0.0.1", cacertfile: @ca)
    assert options[:reference_identity] == {:ip, {127, 0, 0, 1}}
    refute Keyword.has_key?(options, :server_name)
  end

  test "keeps an explicit identity independent from SNI and accepts IPv6" do
    assert {:ok, options} =
             TLSOptions.normalize("2001:db8::1",
               cacertfile: @ca,
               reference_identity: {:ip, "2001:db8::1"},
               server_name_indication: "unrelated.example"
             )

    assert options[:reference_identity] == {:ip, {8193, 3512, 0, 0, 0, 0, 0, 1}}
    assert options[:server_name] == "unrelated.example"
  end

  test "uses the derived reference identity when SNI is absent" do
    assert {:ok, options} = TLSOptions.normalize("localhost", cacertfile: @ca)
    assert options[:reference_identity] == {:dns_id, "localhost"}
    refute Keyword.has_key?(options, :server_name)
  end

  test "loads and validates client credentials before a QUIC TLS feed" do
    assert {:ok, options} =
             TLSOptions.normalize("localhost", cacertfile: @ca, certfile: @cert, keyfile: @key)

    assert [leaf | _] = options[:cert]
    assert is_binary(leaf)
    assert {type, key} = options[:key]
    assert type in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]
    assert is_binary(key)
  end

  test "maps normalized options to the public QUIC TLS constructor" do
    assert {:ok, options} = TLSOptions.normalize("localhost", cacertfile: @ca)

    # The endpoint owns real transport parameters. This test-only empty value
    # validates the public mapping without adding one in production.
    assert {:ok, _state, _actions} =
             SSL.QUIC.new(:client, options ++ [transport_parameters: <<>>])
  end

  test "rejects insecure, unsupported, duplicate, and malformed inputs with redacted reasons" do
    assert {:error, :verify_none_not_supported} =
             TLSOptions.normalize("localhost", cacertfile: @ca, verify: :verify_none)

    assert {:error, {:unsupported_tls_option, :alpn_advertised_protocols}} =
             TLSOptions.normalize("localhost", cacertfile: @ca, alpn_advertised_protocols: ["h3"])

    assert {:error, :duplicate_tls_option} =
             TLSOptions.normalize("localhost", cacertfile: @ca, cacertfile: @ca)

    assert {:error, :invalid_alpn} =
             TLSOptions.normalize("localhost", cacertfile: @ca, alpn: ["h3"])

    assert {:error, :invalid_alpn} =
             TLSOptions.normalize("localhost", cacertfile: @ca, alpn: [<<"h3", 255>>])

    assert {:error, :invalid_reference_identity} =
             TLSOptions.normalize("localhost",
               cacertfile: @ca,
               reference_identity: {:ip, "not-an-ip"}
             )

    assert {:error, :invalid_reference_identity} =
             TLSOptions.normalize("localhost",
               cacertfile: @ca,
               reference_identity: {:ip, "2001:db8::10000"}
             )

    assert {:error, :invalid_reference_identity} =
             TLSOptions.normalize(<<255>>, cacertfile: @ca)

    assert {:error, :conflicting_ca_sources} =
             TLSOptions.normalize("localhost", cacerts: [], cacertfile: @ca)

    assert {:error, :invalid_ca_trust} =
             TLSOptions.normalize("localhost", cacerts: <<"not a PEM bundle">>)

    assert {:error, :invalid_ca_file} =
             TLSOptions.normalize("localhost", cacertfile: "/missing/ca.pem")

    assert {:error, :invalid_certificate_file} =
             TLSOptions.normalize("localhost",
               cacertfile: @ca,
               certfile: "/missing/cert.pem",
               keyfile: @key
             )

    assert {:error, :incomplete_identity} =
             TLSOptions.normalize("localhost", cacertfile: @ca, certfile: @cert)

    assert {:error, :invalid_identity} =
             TLSOptions.normalize("localhost",
               cacertfile: @ca,
               cert: <<1>>,
               key: {:RSAPrivateKey, <<1>>}
             )

    assert {:error, :invalid_identity} =
             TLSOptions.normalize("localhost", cacertfile: @ca, certfile: @cert, keyfile: @ca)

    assert {:error, {:unsupported_algorithm, :groups}} =
             TLSOptions.normalize("localhost", cacertfile: @ca, groups: [0xFFFF])

    tcp_profile = %WireProfile{session_id: :empty, record: %RecordPolicy{mode: :default}}

    assert {:error, :invalid_profile} =
             TLSOptions.normalize("localhost", cacertfile: @ca, profile: tcp_profile)
  end
end

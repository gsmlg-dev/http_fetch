defmodule HTTP.ManagedTransportExSSLPolicyTest do
  use ExUnit.Case, async: true

  alias HTTP.ManagedTransport.Policy

  test "explicit ExSSL selectors freeze the normalized backend and immutable security identity" do
    assert {:ok, policy} = freeze(:ex_ssl)
    assert policy.transport[:tls_backend] == :ex_ssl
    assert {:ok, same} = freeze("ex_ssl")
    assert same == policy
    assert {:ok, otp} = freeze(:ssl)
    refute policy.identity == otp.identity
    assert {:ok, default} = Policy.freeze(options() ++ [ssl: [cacerts: []]])
    assert default.transport[:tls_backend] == :ssl
  end

  test "inline CA cert key and socket policy are copied without changing explicit settings" do
    ca = borrowed("inline-ca")
    cert = borrowed("inline-cert")
    key = borrowed("inline-key")
    ssl = [cacerts: [ca], cert: cert, key: {:RSAPrivateKey, key}]
    sockets = [buffer: 32_768, sndbuf: 65_536, recbuf: 49_152, nodelay: true]

    assert {:ok, policy} =
             Policy.freeze(options() ++ [tls_backend: :ex_ssl, ssl: ssl, socket_opts: sockets])

    assert Keyword.take(policy.transport[:socket_opts], Keyword.keys(sockets)) == sockets
    assert policy.transport[:socket_opts][:send_timeout_close] == true
    assert [retained_ca] = policy.transport[:ssl][:cacerts]
    assert retained_ca == ca
    assert :binary.referenced_byte_size(retained_ca) == byte_size(retained_ca)
    assert :binary.referenced_byte_size(policy.transport[:ssl][:cert]) == byte_size(cert)
    assert {:RSAPrivateKey, retained_key} = policy.transport[:ssl][:key]
    assert :binary.referenced_byte_size(retained_key) == byte_size(key)
  end

  test "advanced policies and invalid selectors remain excluded" do
    for ssl <- [
          [verify_fun: {fn _, _, _ -> :ok end, nil}],
          [partial_chain: fn _ -> :unknown_ca end],
          [crl_check: true],
          [stapling: :staple],
          [password: "secret"],
          [certs_keys: []]
        ] do
      assert {:error, :invalid_transport_scope_tls_policy} = freeze(:ex_ssl, ssl)
    end

    assert {:error, :invalid_tls_backend} = freeze(:other)
  end

  test "origin SNI and protocol policy stay isolated and immutable" do
    assert {:ok, h1} = freeze(:ex_ssl, alpn_advertised_protocols: ["http/1.1"])
    assert h1.transport[:ssl][:server_name_indication] == ~c"localhost"

    assert {:error, :invalid_transport_scope_tls_policy} =
             freeze(:ex_ssl, server_name_indication: ~c"other")

    assert {:error, :invalid_transport_scope_tls_policy} =
             Policy.freeze(
               options(:http2) ++
                 [tls_backend: :ex_ssl, ssl: [cacerts: [], alpn_advertised_protocols: ["h2"]]]
             )

    assert {:ok, h2} =
             Policy.freeze(options(:http2) ++ [tls_backend: :ex_ssl, ssl: [cacerts: []]])

    refute h1.identity == h2.identity
  end

  defp options(protocol \\ :http1),
    do: [origin: "https://localhost", connect_address: {127, 0, 0, 1}, http_version: protocol]

  defp freeze(backend, ssl \\ []),
    do: Policy.freeze(options() ++ [tls_backend: backend, ssl: [cacerts: []] ++ ssl])

  defp borrowed(value),
    do: binary_part(value <> :binary.copy(<<0>>, 1_048_576), 0, byte_size(value))
end

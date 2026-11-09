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

    assert {:ok, %{sni: {:hosts, %{~c"a.test" => [certfile: _, keyfile: _]}}}} =
             ServerOptions.build(sni_hosts: [{~c"a.test", [certfile: @cert, keyfile: @key]}])
  end
end

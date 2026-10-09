defmodule SSL.ReferenceIdentityInteropTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer, OpenSSLPeer}

  @moduletag :integration
  @dial_address {127, 0, 0, 2}

  setup_all do
    directory =
      Path.join(
        System.tmp_dir!(),
        "exssl-reference-identity-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "direct and upgraded sockets authenticate IPv4 and IPv6 SANs independently of dial IP and SNI",
       %{fixtures: fixtures} do
    for mode <- [:direct, :upgrade],
        reference <- [
          {:ip, "127.0.0.1"},
          {:ip, {127, 0, 0, 1}},
          {:ip, "::1"},
          {:ip, {0, 0, 0, 0, 0, 0, 0, 1}}
        ],
        sni <- [nil, :disable, ~c"routing.exssl.test"] do
      exchange(fixtures, mode, reference, sni)
    end
  end

  test "explicit DNS certificate identity does not require matching or present SNI", %{
    fixtures: fixtures
  } do
    for mode <- [:direct, :upgrade], sni <- [:disable, ~c"routing.exssl.test"] do
      exchange(fixtures, mode, {:dns_id, "exssl.test"}, sni)
    end
  end

  test "a valid dial IP or SNI cannot rescue a mismatching explicit reference", %{
    fixtures: fixtures
  } do
    for mode <- [:direct, :upgrade],
        reference <- [{:ip, "127.0.0.2"}, {:ip, "::2"}, {:dns_id, "wrong.exssl.test"}] do
      {:ok, peer} = peer(fixtures, fn _ -> flunk("unauthenticated application callback") end)
      options = options(fixtures, reference, ~c"exssl.test")

      assert {:error, {:tls_alert, {:certificate_unknown, _}}} =
               connect(mode, {127, 0, 0, 1}, peer.port, options)

      assert {:handshake_error, _} = LocalTLSPeer.stop(peer)
    end
  end

  test "explicit identity still rejects a certificate outside the configured trust", %{
    fixtures: fixtures
  } do
    for mode <- [:direct, :upgrade] do
      {:ok, peer} = peer(fixtures, fn _ -> flunk("untrusted application callback") end)

      options =
        fixtures
        |> options({:ip, "127.0.0.1"}, :disable)
        |> Keyword.put(:cacerts, [fixtures.wrong.der])

      assert {:error, {:tls_alert, {:unknown_ca, _}}} =
               connect(mode, @dial_address, peer.port, options)

      assert {:handshake_error, _} = LocalTLSPeer.stop(peer)
    end
  end

  test "OpenSSL TLS1.2 direct and upgraded sockets verify an independent IP reference", %{
    fixtures: fixtures
  } do
    for mode <- [:direct, :upgrade], reference <- [{:ip, "127.0.0.1"}, {:ip, "::1"}] do
      {:ok, peer} = openssl_peer(fixtures)

      try do
        options =
          fixtures
          |> options(reference, nil)
          |> Keyword.put(:versions, [:"tlsv1.2"])

        assert {:ok, socket} = connect(mode, {127, 0, 0, 1}, peer.port, options)
        assert {:ok, %{"version" => "TLSv1.2"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
        assert :ok = SSL.send(socket, <<4::32, "ping">>)
        assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 5_000)
        assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        assert :ok = SSL.close(socket)
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  test "OpenSSL TLS1.2 rejects wrong references and untrusted certificates on direct and upgraded sockets",
       %{fixtures: fixtures} do
    for mode <- [:direct, :upgrade],
        {reference, trust} <- [
          {{:ip, "127.0.0.2"}, [fixtures.ca.der]},
          {{:ip, "::2"}, [fixtures.ca.der]},
          {{:dns_id, "wrong.exssl.test"}, [fixtures.ca.der]},
          {{:ip, "::1"}, [fixtures.wrong.der]}
        ] do
      {:ok, peer} = openssl_peer(fixtures)

      try do
        options =
          fixtures
          |> options(reference, ~c"exssl.test")
          |> Keyword.put(:versions, [:"tlsv1.2"])
          |> Keyword.put(:cacerts, trust)

        assert {:error, {:tls_alert, {:bad_certificate, _}}} =
                 connect(mode, {127, 0, 0, 1}, peer.port, options)

        assert {:error, %{"kind" => "failure", "error" => "SSLError"}} =
                 OpenSSLPeer.event(peer, "handshake", 5_000)
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  test "OTP reference supports authenticated IP dialing and DNS socket upgrade", %{
    fixtures: fixtures
  } do
    for mode <- [:direct, :upgrade] do
      sni = if mode == :direct, do: :disable, else: ~c"exssl.test"
      {:ok, peer} = peer(fixtures, &respond/1)

      options =
        fixtures
        |> options({:ip, "127.0.0.1"}, sni)
        |> Keyword.delete(:ex_ssl)
        |> Keyword.put(:customize_hostname_check,
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        )

      assert {:ok, socket} = connect(mode, {127, 0, 0, 1}, peer.port, options, :ssl)
      assert :ok = :ssl.send(socket, "ping")
      assert {:ok, "pong"} = :ssl.recv(socket, 4, 5_000)
      assert :ok = :ssl.close(socket)
      assert :ok = LocalTLSPeer.stop(peer)
    end
  end

  defp exchange(fixtures, mode, reference, sni) do
    {:ok, peer} =
      peer(fixtures, fn socket ->
        expected = if sni in [nil, :disable], do: [], else: [sni_hostname: sni]
        assert {:ok, ^expected} = :ssl.connection_information(socket, [:sni_hostname])
        respond(socket)
      end)

    assert {:ok, socket} =
             connect(mode, @dial_address, peer.port, options(fixtures, reference, sni))

    assert {:ok, certificate} = SSL.peercert(socket)
    assert certificate == fixtures.server.der
    assert :ok = SSL.send(socket, "ping")
    assert {:ok, "pong"} = SSL.recv(socket, 4, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  defp respond(socket) do
    assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
    assert :ok = :ssl.send(socket, "pong")
  end

  defp peer(fixtures, handler) do
    LocalTLSPeer.start(handler,
      ssl_options: [
        certfile: String.to_charlist(fixtures.server.certificate),
        keyfile: String.to_charlist(fixtures.server.key)
      ]
    )
  end

  defp options(fixtures, reference, sni) do
    [
      mode: :binary,
      active: false,
      packet: :raw,
      verify: :verify_peer,
      cacerts: [fixtures.ca.der],
      versions: [:"tlsv1.3"],
      ex_ssl: [reference_identity: reference]
    ] ++ if(sni, do: [server_name_indication: sni], else: [])
  end

  defp openssl_peer(fixtures) do
    OpenSSLPeer.start(
      certfile: fixtures.server.certificate,
      keyfile: fixtures.server.key,
      min_version: :tls12,
      max_version: :tls12
    )
  end

  defp connect(mode, address, port, options, backend \\ SSL)

  defp connect(:direct, address, port, options, backend),
    do: backend.connect(address, port, options, 5_000)

  defp connect(:upgrade, address, port, options, backend) do
    assert {:ok, tcp} = :gen_tcp.connect(address, port, [:binary, active: false], 5_000)
    backend.connect(tcp, options, 5_000)
  end
end

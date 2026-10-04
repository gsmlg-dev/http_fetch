defmodule SSL.TLS12InteropTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, OpenSSLPeer}

  @moduletag :integration
  @suites [
    {:rsa, 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"},
    {:rsa, 0xC030, "ECDHE-RSA-AES256-GCM-SHA384"},
    {:ec, 0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"},
    {:ec, 0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"}
  ]

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-tls12-peer-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory), peer_version: python_ssl_version()}
  end

  for {key, suite, cipher} <- @suites do
    test "OpenSSL TLS 1.2 #{cipher} authenticates and exchanges bounded bytes", %{
      fixtures: fixtures,
      peer_version: peer_version
    } do
      server = if unquote(key) == :rsa, do: fixtures.server, else: fixtures.ec_server
      peer = start_peer(fixtures, server, cipher: unquote(cipher), alpn: ["http/1.1"])

      try do
        socket = connect(peer, options(fixtures, [:"tlsv1.2"], [unquote(suite)]))
        assert {:ok, handshake} = OpenSSLPeer.event(peer, "handshake", 5_000)
        assert handshake["version"] == "TLSv1.2"
        assert handshake["cipher"] == unquote(cipher)
        assert handshake["alpn"] == "http/1.1"
        assert handshake["client_der_b64"] == :null
        report_handshake(handshake, peer_version, "verified TLS 1.2 echo")
        assert {:ok, "http/1.1"} = SSL.negotiated_protocol(socket)
        assert_echo(socket, "tls12-#{unquote(suite)}")
        assert {:ok, %{"bytes" => _}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        assert :ok = SSL.close(socket)
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  for identity_key <- [:rsa, :ec, :large] do
    test "OpenSSL TLS 1.2 required mTLS authenticates exact #{identity_key} DER", %{
      fixtures: fixtures,
      peer_version: peer_version
    } do
      identity = fixtures[unquote(identity_key)]
      peer = start_peer(fixtures, fixtures.server, verify: :required)

      try do
        opts =
          options(fixtures, [:"tlsv1.2"], [0xC02F]) ++
            [certfile: identity.certificate, keyfile: identity.key]

        socket = connect(peer, opts)
        assert {:ok, handshake} = OpenSSLPeer.event(peer, "handshake", 5_000)
        assert handshake["version"] == "TLSv1.2"
        assert Base.decode64!(handshake["client_der_b64"]) == identity.der
        report_handshake(handshake, peer_version, "verified TLS 1.2 mTLS echo")
        if unquote(identity_key) == :large, do: assert(byte_size(identity.der) > 16_384)
        assert_echo(socket, "authenticated")
        assert {:ok, %{"bytes" => 13}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        assert :ok = SSL.close(socket)
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  test "OpenSSL TLS 1.2 rejects missing, wrong-CA and expired client identities", %{
    fixtures: fixtures
  } do
    for identity <- [nil, fixtures.wrong, fixtures.expired] do
      peer = start_peer(fixtures, fixtures.server, verify: :required)

      try do
        credentials =
          if identity, do: [certfile: identity.certificate, keyfile: identity.key], else: []

        assert {:error, _} =
                 SSL.connect(
                   {127, 0, 0, 1},
                   peer.port,
                   options(fixtures, [:"tlsv1.2"], [0xC02F]) ++ credentials,
                   5_000
                 )

        assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  test "wrong server hostname fails before application bytes", %{fixtures: fixtures} do
    peer = start_peer(fixtures, fixtures.server)

    try do
      opts =
        List.keystore(
          options(fixtures, [:"tlsv1.2"], [0xC02F]),
          :server_name_indication,
          0,
          {:server_name_indication, ~c"wrong.exssl.test"}
        )

      assert {:error, _} = SSL.connect({127, 0, 0, 1}, peer.port, opts, 5_000)
    after
      OpenSSLPeer.stop(peer)
    end
  end

  test "TLS 1.2 only and mixed offers select TLS 1.2 on a TLS 1.2-only peer", %{
    fixtures: fixtures
  } do
    for versions <- [[:"tlsv1.2"], [:"tlsv1.3", :"tlsv1.2"]] do
      peer = start_peer(fixtures, fixtures.server)

      try do
        ciphers = if versions == [:"tlsv1.2"], do: [0xC02F], else: [0x1301, 0xC02F]
        socket = connect(peer, options(fixtures, versions, ciphers))
        assert {:ok, %{"version" => "TLSv1.2"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
        assert_echo(socket, "version twelve")
        assert {:ok, _} = OpenSSLPeer.event(peer, "exchange", 5_000)
        assert :ok = SSL.close(socket)
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  test "TLS 1.3 only and mixed offers select TLS 1.3 on a capable peer", %{fixtures: fixtures} do
    for versions <- [[:"tlsv1.3"], [:"tlsv1.3", :"tlsv1.2"]] do
      peer = start_peer(fixtures, fixtures.server, min_version: :tls12, max_version: :tls13)

      try do
        ciphers = if versions == [:"tlsv1.3"], do: [0x1301], else: [0x1301, 0xC02F]
        socket = connect(peer, options(fixtures, versions, ciphers))
        assert {:ok, %{"version" => "TLSv1.3"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
        assert_echo(socket, "version thirteen")
        assert {:ok, _} = OpenSSLPeer.event(peer, "exchange", 5_000)
        assert :ok = SSL.close(socket)
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  test "TLS 1.2 active-once delivery retains its public socket term", %{fixtures: fixtures} do
    peer = start_peer(fixtures, fixtures.server)

    try do
      socket = connect(peer, options(fixtures, [:"tlsv1.2"], [0xC02F]))
      assert {:ok, _} = OpenSSLPeer.event(peer, "handshake", 5_000)
      assert :ok = SSL.setopts(socket, active: :once)
      assert :ok = SSL.send(socket, <<0, 0, 0, 4, "once">>)
      assert_receive {:ssl, ^socket, <<0, 0, 0, 4, "once">>}, 5_000
      assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
      assert :ok = SSL.close(socket)
    after
      OpenSSLPeer.stop(peer)
    end
  end

  test "TLS 1.2 sends a large bounded body through multiple records", %{fixtures: fixtures} do
    peer = start_peer(fixtures, fixtures.server, delay_ms: 1)
    payload = :binary.copy("x", 256 * 1024)

    try do
      socket = connect(peer, options(fixtures, [:"tlsv1.2"], [0xC02F]))
      assert {:ok, _} = OpenSSLPeer.event(peer, "handshake", 5_000)
      assert_echo(socket, payload)
      assert {:ok, %{"bytes" => 262_144}} = OpenSSLPeer.event(peer, "exchange", 5_000)
      assert :ok = SSL.close(socket)
    after
      OpenSSLPeer.stop(peer)
    end
  end

  test "TLS12 ownership transfer preserves active-once delivery and cleans up", %{
    fixtures: fixtures
  } do
    peer = start_peer(fixtures, fixtures.server)

    try do
      socket = connect(peer, options(fixtures, [:"tlsv1.2"], [0xC02F]))
      assert {:ok, _} = OpenSSLPeer.event(peer, "handshake", 5_000)
      {:connected, state} = :sys.get_state(socket.pid)
      monitor = Process.monitor(socket.pid)

      owner =
        Task.async(fn ->
          receive do
            {:socket, owned} ->
              assert :ok = SSL.setopts(owned, active: :once)
              assert :ok = SSL.send(owned, <<4::32, "move">>)
              assert_receive {:ssl, ^owned, <<4::32, "move">>}, 5_000
              SSL.close(owned)
          end
        end)

      assert :ok = SSL.controlling_process(socket, owner.pid)
      send(owner.pid, {:socket, socket})
      assert :ok = Task.await(owner, 5_000)
      assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
      assert Port.info(state.tcp) == nil
      refute Process.alive?(state.writer)
    after
      OpenSSLPeer.stop(peer)
    end
  end

  test "TLS12 transport truncation cannot produce orderly closure", %{fixtures: fixtures} do
    peer = start_peer(fixtures, fixtures.server)
    socket = connect(peer, options(fixtures, [:"tlsv1.2"], [0xC02F]))
    assert {:ok, _} = OpenSSLPeer.event(peer, "handshake", 5_000)
    {:connected, state} = :sys.get_state(socket.pid)
    monitor = Process.monitor(socket.pid)
    OpenSSLPeer.stop(peer)
    assert {:error, :econnreset} = SSL.recv(socket, 1, 5_000)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
    assert Port.info(state.tcp) == nil
    refute Process.alive?(state.writer)
  end

  defp start_peer(fixtures, server, options \\ []) do
    {:ok, peer} =
      OpenSSLPeer.start(
        Keyword.merge(
          [
            certfile: server.certificate,
            keyfile: server.key,
            cafile: fixtures.ca.certificate,
            min_version: :tls12,
            max_version: :tls12,
            alpn: ["http/1.1"]
          ],
          options
        )
      )

    peer
  end

  defp options(fixtures, versions, ciphers) do
    [
      mode: :binary,
      active: false,
      packet: :raw,
      verify: :verify_peer,
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      versions: versions,
      ciphers: Enum.map(ciphers, &cipher_option/1),
      alpn_advertised_protocols: ["http/1.1"]
    ]
  end

  defp connect(peer, options) do
    assert {:ok, socket} = SSL.connect({127, 0, 0, 1}, peer.port, options, 5_000)
    socket
  end

  defp assert_echo(socket, payload) do
    assert :ok = SSL.send(socket, <<byte_size(payload)::32, payload::binary>>)
    assert {:ok, <<length::32>>} = SSL.recv(socket, 4, 15_000)
    assert length == byte_size(payload)
    assert {:ok, ^payload} = SSL.recv(socket, length, 15_000)
  end

  defp cipher_option(0x1301),
    do: %{key_exchange: :any, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}

  defp cipher_option(0xC02F),
    do: %{key_exchange: :ecdhe_rsa, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}

  defp cipher_option(0xC030),
    do: %{key_exchange: :ecdhe_rsa, cipher: :aes_256_gcm, mac: :aead, prf: :sha384}

  defp cipher_option(0xC02B),
    do: %{key_exchange: :ecdhe_ecdsa, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}

  defp cipher_option(0xC02C),
    do: %{key_exchange: :ecdhe_ecdsa, cipher: :aes_256_gcm, mac: :aead, prf: :sha384}

  defp python_ssl_version do
    {version, 0} = System.cmd("python3", ["-c", "import ssl; print(ssl.OPENSSL_VERSION)"])
    String.trim(version)
  end

  defp report_handshake(handshake, peer_version, expected) do
    IO.puts(
      "TLS 1.2 interop peer=Python ssl/#{peer_version} protocol=#{handshake["version"]} " <>
        "suite=#{handshake["cipher"]} expected=#{expected}"
    )
  end
end

defmodule SSL.ConnectionInteropTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer
  alias SSL.ClientHello.WireProfile

  @moduletag :integration

  test "public API exchanges repeated application writes with an OTP TLS 1.3 peer" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert {:ok, "first"} = :ssl.recv(socket, 5, 5_000)
        assert :ok = :ssl.send(socket, "one")
        assert {:ok, "second"} = :ssl.recv(socket, 6, 5_000)
        assert :ok = :ssl.send(socket, "two")
      end)

    assert {:ok, socket} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = SSL.send(socket, ["fir", ~c"st"])
    assert {:ok, "one"} = SSL.recv(socket, 0, 5_000)
    assert :ok = SSL.send(socket, "second")
    assert {:ok, "two"} = SSL.recv(socket, 3, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "public API upgrades a fully consumed STARTTLS response" do
    {:ok, peer} =
      LocalTLSPeer.start_starttls(fn socket ->
        assert {:ok, "after-upgrade"} = :ssl.recv(socket, 13, 5_000)
        assert :ok = :ssl.send(socket, "upgraded")
      end)

    {:ok, tcp} =
      :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false, packet: :raw], 5_000)

    assert {:ok, "220 local STARTTLS peer\r\n"} = :gen_tcp.recv(tcp, 0, 5_000)
    assert :ok = :gen_tcp.send(tcp, "STARTTLS\r\n")
    assert {:ok, "220 begin TLS\r\n"} = :gen_tcp.recv(tcp, 0, 5_000)

    assert {:ok, socket} = SSL.connect(tcp, LocalTLSPeer.client_options(), 5_000)
    assert :ok = SSL.send(socket, "after-upgrade")
    assert {:ok, "upgraded"} = SSL.recv(socket, 8, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "public API rejects a verified server with a hostname mismatch" do
    {:ok, peer} = LocalTLSPeer.start(fn _socket -> :unexpected_success end)

    options =
      List.keystore(
        LocalTLSPeer.client_options(),
        :server_name_indication,
        0,
        {:server_name_indication, ~c"wrong.exssl.test"}
      )

    assert {:error, _reason} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
    assert {:handshake_error, _reason} = LocalTLSPeer.stop(peer)
  end

  test "public API rejects a chain from an untrusted root" do
    {:ok, peer} = LocalTLSPeer.start(fn _socket -> :unexpected_success end)

    options =
      List.keystore(
        LocalTLSPeer.client_options(),
        :cacerts,
        0,
        {:cacerts,
         [
           LocalTLSPeer.certificate_from_pem!(
             Path.expand("../fixtures/pkix/wrong_root.pem", __DIR__)
           )
         ]}
      )

    assert {:error, _reason} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
    assert {:handshake_error, _reason} = LocalTLSPeer.stop(peer)
  end

  test "public API rejects an expired server certificate signed by the trusted CA" do
    {:ok, peer} = LocalTLSPeer.start(fn _socket -> :unexpected_success end, certificate: :expired)

    assert {:error, _reason} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:handshake_error, _reason} = LocalTLSPeer.stop(peer)
  end

  test "public API advertises the configured ClientHello order and fresh key shares" do
    {:ok, first} = LocalTLSPeer.observe_client_hello(self())

    assert {:error, _reason} =
             SSL.connect(~c"127.0.0.1", first.port, LocalTLSPeer.client_options(), 1_000)

    assert_receive {:client_hello_observed, first_hello}, 2_000
    assert :ok = Task.await(first.task, 2_000)

    {:ok, second} = LocalTLSPeer.observe_client_hello(self())

    assert {:error, _reason} =
             SSL.connect(~c"127.0.0.1", second.port, LocalTLSPeer.client_options(), 1_000)

    assert_receive {:client_hello_observed, second_hello}, 2_000
    assert :ok = Task.await(second.task, 2_000)

    assert %{
             cipher_suites: [0x1301, 0x1302, 0x1303],
             extensions: [0, 43, 10, 13, 51],
             key_share: key_share
           } =
             parse_client_hello(first_hello)

    assert %{key_share: second_key_share} = parse_client_hello(second_hello)
    refute key_share == second_key_share
  end

  test "public API rejects a TLS 1.2-only peer without downgrade" do
    {:ok, peer} =
      LocalTLSPeer.start(fn _socket -> :unexpected_success end,
        ssl_options: [versions: [:"tlsv1.2"]]
      )

    assert {:error, _reason} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:handshake_error, _reason} = LocalTLSPeer.stop(peer)
  end

  test "public API fragments a large write and receives the complete peer response" do
    payload = :binary.copy(<<0xA5>>, 96_000)

    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert {:ok, ^payload} = :ssl.recv(socket, byte_size(payload), 5_000)
        assert :ok = :ssl.send(socket, payload)
      end)

    assert {:ok, socket} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = SSL.send(socket, payload)
    assert {:ok, ^payload} = SSL.recv(socket, byte_size(payload), 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "public API survives fragmented and coalesced TLS wire traffic through an independent peer" do
    payload = :binary.copy(<<0xA5>>, 96_000)

    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        Enum.each(1..3, fn _ ->
          assert {:ok, ^payload} = :ssl.recv(socket, byte_size(payload), 10_000)
          assert :ok = :ssl.send(socket, payload)
        end)
      end)

    {:ok, proxy} = LocalTLSPeer.start_fragmenting_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      assert {:ok, socket} =
               SSL.connect(~c"127.0.0.1", proxy.port, LocalTLSPeer.client_options(), 10_000)

      for _ <- 1..3 do
        assert :ok = SSL.send(socket, payload)
        assert {:ok, ^payload} = SSL.recv(socket, byte_size(payload), 10_000)
      end

      assert :ok = SSL.close(socket)
      assert_receive {:tls_proxy, ^proxy_ref, :client_to_server, _bytes}, 2_000
      assert_receive {:tls_proxy, ^proxy_ref, :server_to_client, _bytes}, 2_000
    after
      _ = LocalTLSPeer.stop_fragmenting_proxy(proxy)
      assert :ok = LocalTLSPeer.stop(peer)
    end
  end

  test "public API sends a custom WireProfile to an authenticated OTP peer with fresh key shares" do
    profile = %WireProfile{
      name: :interop_custom,
      cipher_suites: [0x1302, 0x1301, 0x1303],
      extensions: [
        {:supported_versions, [0x0304]},
        {:server_name, :from_connection},
        {:padding, {:fixed, 19}},
        {:supported_groups, [0x001D, 0x0017]},
        {:signature_algorithms, [0x0804, 0x0805, 0x0403]},
        {:key_share, [0x001D]}
      ]
    }

    first = authenticated_profile_exchange(profile)
    second = authenticated_profile_exchange(profile)

    assert %{
             cipher_suites: [0x1302, 0x1301, 0x1303],
             extensions: [43, 0, 21, 10, 13, 51],
             extension_values: %{21 => <<0::size(19 * 8)>>},
             key_share: key_share
           } = first

    assert %{key_share: second_key_share} = second
    refute key_share == second_key_share
  end

  test "public API authenticates an ECDSA server certificate" do
    {:ok, peer} =
      LocalTLSPeer.start(
        fn socket ->
          assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
          assert :ok = :ssl.send(socket, "pong")
        end,
        certificate: :ecdsa
      )

    assert {:ok, socket} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = SSL.send(socket, "ping")
    assert {:ok, "pong"} = SSL.recv(socket, 4, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "public API completes an OTP HelloRetryRequest and exchanges application data" do
    {:ok, peer} =
      LocalTLSPeer.start(
        fn socket ->
          assert {:ok, "after-hrr"} = :ssl.recv(socket, 9, 5_000)
          assert :ok = :ssl.send(socket, "accepted")
        end,
        ssl_options: [supported_groups: [:secp256r1]]
      )

    assert {:ok, socket} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = SSL.send(socket, "after-hrr")
    assert {:ok, "accepted"} = SSL.recv(socket, 8, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "public API exchanges application data with a P-384 ECDHE peer" do
    profile = %WireProfile{
      name: :secp384r1,
      extensions: [
        {:supported_versions, [0x0304]},
        {:server_name, :from_connection},
        {:supported_groups, [:secp384r1]},
        {:signature_algorithms, [:ecdsa_secp256r1_sha256, :rsa_pss_rsae_sha256]},
        {:key_share, [:secp384r1]}
      ]
    }

    {:ok, peer} =
      LocalTLSPeer.start(
        fn socket ->
          assert {:ok, "p384"} = :ssl.recv(socket, 4, 5_000)
          assert :ok = :ssl.send(socket, "ok")
        end,
        ssl_options: [supported_groups: [:secp384r1]]
      )

    options = Keyword.put(LocalTLSPeer.client_options(), :ex_ssl, profile: profile)

    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
    assert :ok = SSL.send(socket, "p384")
    assert {:ok, "ok"} = SSL.recv(socket, 2, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "public API handles a peer KeyUpdate before later application data" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert :ok = :ssl.update_keys(socket, :write)
        assert :ok = :ssl.send(socket, "after-key-update")
        assert {:ok, "client-still-writes"} = :ssl.recv(socket, 19, 5_000)
        :ok
      end)

    assert {:ok, socket} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert {:ok, "after-key-update"} = SSL.recv(socket, 16, 5_000)
    assert :ok = SSL.send(socket, "client-still-writes")
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  defp parse_client_hello(
         <<22, _legacy::binary-size(2), record_length::16, record::binary-size(record_length),
           _rest::binary>>
       ) do
    <<1, handshake_length::24, handshake::binary-size(handshake_length)>> = record
    <<_version::16, _random::binary-size(32), session_size, rest::binary>> = handshake

    <<_session::binary-size(^session_size), cipher_size::16, ciphers::binary-size(cipher_size),
      rest::binary>> = rest

    <<compression_size, _compression::binary-size(compression_size), extensions_size::16,
      extensions::binary-size(extensions_size)>> = rest

    %{cipher_suites: for(<<suite::16 <- ciphers>>, do: suite)}
    |> Map.merge(parse_extensions(extensions, []))
  end

  defp parse_extensions(<<>>, extensions),
    do: %{extensions: Enum.reverse(extensions), extension_values: %{}, key_share: nil}

  defp parse_extensions(
         <<type::16, size::16, value::binary-size(size), rest::binary>>,
         extensions
       ) do
    parsed = parse_extensions(rest, [type | extensions])

    parsed = %{parsed | extension_values: Map.put(parsed.extension_values, type, value)}
    if type == 51, do: %{parsed | key_share: value}, else: parsed
  end

  defp authenticated_profile_exchange(profile) do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert {:ok, "profile-ping"} = :ssl.recv(socket, 12, 5_000)
        assert :ok = :ssl.send(socket, "profile-pong")
      end)

    {:ok, proxy} = LocalTLSPeer.start_fragmenting_proxy(peer.port, self())

    try do
      options = Keyword.put(LocalTLSPeer.client_options(), :ex_ssl, profile: profile)

      assert {:ok, socket} = SSL.connect(~c"127.0.0.1", proxy.port, options, 5_000)
      assert :ok = SSL.send(socket, "profile-ping")
      assert {:ok, "profile-pong"} = SSL.recv(socket, 12, 5_000)
      assert :ok = SSL.close(socket)
      receive_client_hello(proxy.ref)
    after
      _ = LocalTLSPeer.stop_fragmenting_proxy(proxy)
      assert :ok = LocalTLSPeer.stop(peer)
    end
  end

  defp receive_client_hello(proxy_ref, bytes \\ <<>>) do
    case complete_client_hello?(bytes) do
      true ->
        parse_client_hello(bytes)

      false ->
        receive do
          {:tls_proxy, ^proxy_ref, :client_to_server, next} ->
            receive_client_hello(proxy_ref, bytes <> next)

          {:tls_proxy, ^proxy_ref, :server_to_client, _next} ->
            receive_client_hello(proxy_ref, bytes)
        after
          2_000 -> flunk("proxy did not observe a complete ClientHello")
        end
    end
  end

  defp complete_client_hello?(<<22, _legacy::binary-size(2), length::16, rest::binary>>),
    do: byte_size(rest) >= length

  defp complete_client_hello?(_bytes), do: false

  test "public API sends an empty Certificate response to an optional CertificateRequest" do
    {:ok, peer} =
      LocalTLSPeer.start(
        fn socket ->
          assert {:ok, "no-client-cert"} = :ssl.recv(socket, 14, 5_000)
          assert :ok = :ssl.send(socket, "continued")
        end,
        ssl_options: [
          verify: :verify_peer,
          fail_if_no_peer_cert: false,
          cacerts: LocalTLSPeer.certificate_authorities()
        ]
      )

    assert {:ok, socket} =
             SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

    assert :ok = SSL.send(socket, "no-client-cert")
    assert {:ok, "continued"} = SSL.recv(socket, 9, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = LocalTLSPeer.stop(peer)
  end

  test "public API interoperates with OpenSSL TLS 1.3" do
    {:ok, peer} = LocalTLSPeer.start_openssl()

    try do
      assert {:ok, socket} =
               SSL.connect(~c"127.0.0.1", peer.port, LocalTLSPeer.client_options(), 5_000)

      assert :ok = SSL.send(socket, "GET / HTTP/1.0\r\nHost: exssl.test\r\n\r\n")
      assert {:ok, response} = SSL.recv(socket, 0, 5_000)
      assert response =~ "HTTP/1.0 200"
      assert :ok = SSL.close(socket)
    after
      assert :ok = LocalTLSPeer.stop_openssl(peer)
    end

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 500)
  end
end

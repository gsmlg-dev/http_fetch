defmodule SSL.ClientAuthInteropTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer}
  @moduletag :integration
  @request "GET /mtls HTTP/1.1\r\nHost: exssl.test\r\nConnection: close\r\n\r\n"
  @response "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nmtls"

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-client-auth-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  for identity <- [:rsa, :ec, :large] do
    test "required mTLS authenticates the exact #{identity} identity and returns HTTP", %{
      fixtures: fixtures
    } do
      identity = fixtures[unquote(identity)]
      if unquote(identity) == :large, do: assert(byte_size(identity.der) > 16_384)
      exchange(fixtures, identity, :required)
    end
  end

  test "mTLS preserves the transcript through a P384 HelloRetryRequest", %{fixtures: fixtures} do
    exchange(fixtures, fixtures.rsa, :required, SSL, supported_groups: [:secp384r1])
  end

  test "OTP reference accepts the same RSA and ECDSA identity files", %{fixtures: fixtures} do
    exchange(fixtures, fixtures.rsa, :required, :ssl)
    exchange(fixtures, fixtures.ec, :required, :ssl)
  end

  test "required authentication fails for an incompatible requested scheme", %{fixtures: fixtures} do
    {:ok, peer} =
      peer(%{fixtures | server: fixtures.ec_server}, fn _ -> :unexpected_success end, :required,
        signature_algs: [:ecdsa_secp256r1_sha256]
      )

    try do
      case SSL.connect(~c"127.0.0.1", peer.port, options(fixtures, fixtures.rsa), 5_000) do
        {:ok, socket} ->
          _ = SSL.send(socket, @request)
          assert {:error, _} = SSL.recv(socket, 0, 5_000)
          assert :ok = SSL.close(socket)

        {:error, _} ->
          :ok
      end
    after
      assert {:handshake_error, _} = LocalTLSPeer.stop(peer)
    end
  end

  test "optional authentication with no identity sends empty Certificate", %{fixtures: fixtures} do
    exchange(fixtures, nil, :optional)
  end

  test "configured credentials are not sent without a CertificateRequest", %{fixtures: fixtures} do
    exchange(fixtures, fixtures.rsa, :unrequested)
  end

  test "missing, wrong-CA, expired and wrong-purpose clients cannot return a successful response",
       %{fixtures: fixtures} do
    for identity <- [nil, fixtures.wrong, fixtures.expired, fixtures.server] do
      {:ok, peer} = peer(fixtures, fn _socket -> :unexpected_success end, :required)

      try do
        case SSL.connect(~c"127.0.0.1", peer.port, options(fixtures, identity), 5_000) do
          {:error, _} ->
            :ok

          {:ok, socket} ->
            # TLS1.3 client Finished output can complete before the server's
            # identity verdict arrives. No successful HTTP response is allowed.
            monitor = Process.monitor(socket.pid)
            _ = SSL.send(socket, @request)
            assert {:error, _} = SSL.recv(socket, 0, 5_000)
            assert :ok = SSL.close(socket)
            assert_receive {:DOWN, ^monitor, :process, _, _}, 1_000
        end
      after
        assert {:handshake_error, _} = LocalTLSPeer.stop(peer)
      end
    end
  end

  defp exchange(fixtures, identity, mode, backend \\ SSL, extra \\ []) do
    expected = if mode == :unrequested or identity == nil, do: nil, else: identity.der

    {:ok, peer} =
      peer(
        fixtures,
        fn socket ->
          if expected == nil do
            assert {:error, :no_peercert} = :ssl.peercert(socket)
          else
            assert {:ok, ^expected} = :ssl.peercert(socket)
          end

          assert {:ok, @request} = :ssl.recv(socket, byte_size(@request), 5_000)
          :ssl.send(socket, @response)
        end,
        mode,
        extra
      )

    proxy =
      if identity && byte_size(identity.der) > 16_384 do
        {:ok, proxy} = LocalTLSPeer.start_fragmenting_proxy(peer.port, self())
        proxy
      end

    port = if proxy, do: proxy.port, else: peer.port

    try do
      assert {:ok, socket} =
               backend.connect(~c"127.0.0.1", port, options(fixtures, identity), 5_000)

      monitor = if backend == SSL, do: Process.monitor(socket.pid)
      assert :ok = backend.send(socket, @request)
      assert {:ok, @response} = backend.recv(socket, byte_size(@response), 5_000)
      assert :ok = backend.close(socket)
      if monitor, do: assert_receive({:DOWN, ^monitor, :process, _, _}, 1_000)
    after
      if proxy, do: LocalTLSPeer.stop_fragmenting_proxy(proxy)
      assert :ok = LocalTLSPeer.stop(peer)
    end

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 1_000)
  end

  defp peer(fixtures, handler, mode, extra \\ []) do
    LocalTLSPeer.start(handler,
      ssl_options:
        Keyword.merge(
          [
            certfile: String.to_charlist(fixtures.server.certificate),
            keyfile: String.to_charlist(fixtures.server.key),
            cacerts: [fixtures.ca.der],
            verify: if(mode == :unrequested, do: :verify_none, else: :verify_peer),
            fail_if_no_peer_cert: mode == :required
          ],
          extra
        )
    )
  end

  defp options(fixtures, identity) do
    [
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      active: false,
      mode: :binary,
      verify: :verify_peer,
      versions: [:"tlsv1.3"]
    ] ++
      if(identity, do: [certfile: identity.certificate, keyfile: identity.key], else: [])
  end
end

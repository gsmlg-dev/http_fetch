defmodule HTTP.ProxyPreparedTLSTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias Elixir.ExSSL.TestSupport.OpenSSLPeer
  alias HTTP.Transport.ExSSL
  alias SSL.ClientHello.WireProfile

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)
  @ca Path.join(@fixtures, "localhost-ca.pem")
  @cert Path.join(@fixtures, "localhost.pem")
  @key Path.join(@fixtures, "localhost.key")

  @tag :tmp_dir
  test "invalid effective TLS configuration has zero proxy and origin accepts", %{
    tmp_dir: directory
  } do
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()
    missing = Path.join(directory, "missing.pem")

    sni_profile = %WireProfile{
      extensions: [
        {:server_name, :from_connection},
        {:supported_versions, [0x0304]},
        {:supported_groups, [:x25519]},
        {:signature_algorithms, [:rsa_pss_rsae_sha256]},
        {:key_share, [:x25519]}
      ]
    }

    for opts <- [
          [ssl: [unsupported_tls_option: true]],
          [ssl: :invalid],
          [ssl: [versions: [:"tlsv1.1"]]],
          [ssl: [alpn_advertised_protocols: [""]]],
          [ssl: [cacertfile: missing]],
          [ssl: [certfile: @cert, keyfile: missing]],
          [ssl: [ex_ssl: [profile: %WireProfile{}]]],
          [
            ssl: [
              verify: :verify_none,
              server_name_indication: :disable,
              versions: [:"tlsv1.3"],
              ex_ssl: [profile: sni_profile, reference_identity: {:ip, {127, 0, 0, 1}}]
            ]
          ],
          [
            ssl: [
              alpn_advertised_protocols: ["h2"],
              versions: [:"tlsv1.3"],
              ex_ssl: [profile: sni_profile]
            ]
          ],
          [socket_opts: [ip: {127, 0, 0, 1}]],
          [socket_opts: [port: 0]],
          [socket_opts: [send_timeout: :invalid]],
          [socket_opts: [:inet6]]
        ] do
      assert {:error, {:options, _}} =
               HTTP.Proxy.connect(ExSSL, "localhost", origin_port, opts, 500, route(proxy_port))

      assert {:error, :timeout} = :gen_tcp.accept(proxy, 20)
      assert {:error, :timeout} = :gen_tcp.accept(origin, 20)
    end
  end

  for host <- ["localhost", "127.0.0.1"],
      {version, alpn} <- [{:"tlsv1.2", "http/1.1"}, {:"tlsv1.3", "h2"}] do
    if version == :"tlsv1.2" do
      @tag :integration
    end

    test "verified #{host} CONNECT retains #{version} and #{alpn} policy and option precedence" do
      {origin, origin_port} = listener()
      {proxy, proxy_port} = listener()
      peer = start_peer(unquote(version), proxy, unquote(host), origin_port, unquote(alpn))

      # socket_opts wins over the invalid lower-precedence ssl send timeout.
      opts = [
        ssl: [cacertfile: @ca, send_timeout: :invalid, alpn_advertised_protocols: [unquote(alpn)]],
        socket_opts: [send_timeout: 5_000]
      ]

      assert {:ok, socket} =
               HTTP.Proxy.connect(
                 ExSSL,
                 unquote(host),
                 origin_port,
                 opts,
                 5_000,
                 route(proxy_port)
               )

      assert {:ok, unquote(alpn)} = ExSSL.negotiated_protocol(socket)
      assert {:ok, [protocol: unquote(version)]} = SSL.connection_information(socket, [:protocol])
      assert :ok = ExSSL.send(socket, <<4::32, "ping">>)
      assert {:ok, <<4::32, "ping">>} = ExSSL.recv(socket, 8, 5_000)
      ExSSL.close(socket)
      assert_receive :replied, 5_000
      send(peer.pid, :close)
      Task.await(peer, 5_000)
      assert {:error, :timeout} = :gen_tcp.accept(origin, 20)
    end
  end

  test "an exhausted preparation deadline never calls raw proxy TCP connect" do
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()
    opts = [ssl: [cacertfile: @ca]]
    assert {:ok, _} = ExSSL.prepare_upgrade("localhost", opts)

    assert {:error, :timeout} =
             HTTP.Proxy.connect(ExSSL, "localhost", origin_port, opts, 0, route(proxy_port))

    assert {:error, :timeout} = :gen_tcp.accept(proxy, 50)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 50)
  end

  @tag :tmp_dir
  test "CONNECT consumes trust frozen before the proxy response", %{tmp_dir: directory} do
    ca = Path.join(directory, "trust.pem")
    File.cp!(@ca, ca)
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(proxy, 5_000)
        recv_head(tcp)
        File.write!(ca, "replacement is not a CA bundle")
        :ok = :gen_tcp.send(tcp, "HTTP/1.1 200 OK\r\n\r\n")

        {:ok, socket} =
          :ssl.handshake(
            tcp,
            [
              certfile: @cert,
              keyfile: @key,
              active: false,
              mode: :binary
            ],
            5_000
          )

        assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
        :ok = :ssl.send(socket, "pong")
        :ssl.close(socket)
      end)

    assert {:ok, socket} =
             HTTP.Proxy.connect(
               ExSSL,
               "localhost",
               origin_port,
               [ssl: [cacertfile: ca]],
               5_000,
               route(proxy_port)
             )

    assert :ok = ExSSL.send(socket, "ping")
    assert {:ok, "pong"} = ExSSL.recv(socket, 4, 5_000)
    ExSSL.close(socket)
    Task.await(peer, 5_000)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 20)
  end

  # OTP 29's TLS12 server omits EMS; bounded ExSSL TLS12 requires it.
  # The combined client offer remains unchanged for both independent peers.
  defp start_peer(:"tlsv1.2", proxy, host, origin_port, alpn) do
    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: @cert,
        keyfile: @key,
        min_version: :tls12,
        max_version: :tls12,
        alpn: [alpn],
        max_connections: 1
      )

    on_exit(fn -> OpenSSLPeer.stop(peer) end)
    parent = self()

    Task.async(fn ->
      tcp = accept_tunnel(proxy, host, origin_port)

      {:ok, upstream} =
        :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 5_000)

      :ok = :inet.setopts(tcp, active: :once)
      :ok = :inet.setopts(upstream, active: :once)
      forward(tcp, upstream)
      send(parent, :replied)
    end)
  end

  defp start_peer(:"tlsv1.3", proxy, host, origin_port, alpn) do
    parent = self()

    Task.async(fn ->
      tcp = accept_tunnel(proxy, host, origin_port)

      {:ok, socket} =
        :ssl.handshake(
          tcp,
          [
            certfile: @cert,
            keyfile: @key,
            active: false,
            mode: :binary,
            versions: [:"tlsv1.3"],
            alpn_preferred_protocols: [alpn]
          ],
          5_000
        )

      assert {:ok, <<4::32, "ping">>} = :ssl.recv(socket, 8, 5_000)
      :ok = :ssl.send(socket, <<4::32, "ping">>)
      send(parent, :replied)
      receive do: (:close -> :ssl.close(socket))
    end)
  end

  defp accept_tunnel(proxy, host, origin_port) do
    {:ok, tcp} = :gen_tcp.accept(proxy, 5_000)
    assert recv_head(tcp) =~ "CONNECT #{host}:#{origin_port} HTTP/1.1\r\n"
    :ok = :gen_tcp.send(tcp, "HTTP/1.1 200 OK\r\n\r\n")
    tcp
  end

  defp forward(client, upstream) do
    receive do
      {:tcp, ^client, data} ->
        :ok = :gen_tcp.send(upstream, data)
        :ok = :inet.setopts(client, active: :once)
        forward(client, upstream)

      {:tcp, ^upstream, data} ->
        :ok = :gen_tcp.send(client, data)
        :ok = :inet.setopts(upstream, active: :once)
        forward(client, upstream)

      {:tcp_closed, _} ->
        :gen_tcp.close(client)
        :gen_tcp.close(upstream)
    after
      5_000 -> flunk("independent TLS peer did not finish its bounded exchange")
    end
  end

  defp route(port),
    do: %{scheme: :http, host: "127.0.0.1", port: port, timeout: 5_000, headers: []}

  defp listener do
    {:ok, socket} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    {:ok, port} = :inet.port(socket)
    on_exit(fn -> :gen_tcp.close(socket) end)
    {socket, port}
  end

  defp recv_head(socket, acc \\ "") do
    assert byte_size(acc) <= 16_384

    case :binary.match(acc, "\r\n\r\n") do
      {_, 4} ->
        acc

      :nomatch ->
        {:ok, bytes} = :gen_tcp.recv(socket, 0, 5_000)
        recv_head(socket, acc <> bytes)
    end
  end
end

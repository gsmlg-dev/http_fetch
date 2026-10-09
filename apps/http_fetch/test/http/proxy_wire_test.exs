defmodule HTTP.ProxyWireTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "unreachable explicit proxy never connects directly to the origin" do
    {origin, origin_port} = listener()
    {closed, proxy_port} = listener()
    :gen_tcp.close(closed)

    result =
      HTTP.fetch("http://localhost:#{origin_port}/probe",
        proxy: {:http, "127.0.0.1", proxy_port, []},
        redirect: :manual,
        timeout: 500
      )
      |> HTTP.Promise.await(2_000)

    assert match?({:error, _}, result)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 100)
  end

  test "HTTP forward proxy receives absolute form and proxy-only authorization" do
    parent = self()
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(proxy, 2_000)
        head = recv_head(socket, :gen_tcp)
        send(parent, {:proxy_head, head})
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        :gen_tcp.close(socket)
      end)

    on_exit(fn -> if Process.alive?(peer), do: Process.exit(peer, :kill) end)

    response =
      HTTP.fetch("http://localhost:#{origin_port}/probe?q=1#fragment",
        proxy:
          {:http, "127.0.0.1", proxy_port,
           [headers: [{"Proxy-Authorization", "Basic proxy-secret"}]]},
        headers: [{"Authorization", "Bearer origin-secret"}],
        timeout: 2_000
      )
      |> HTTP.Promise.await()

    assert %HTTP.Response{status: 200} = response
    assert HTTP.Response.read_all(response) == "ok"
    assert_receive {:proxy_head, head}, 2_000
    assert head =~ "GET http://localhost:#{origin_port}/probe?q=1 HTTP/1.1\r\n"
    assert head =~ "Proxy-Authorization: Basic proxy-secret\r\n"
    assert head =~ "Authorization: Bearer origin-secret\r\n"
    refute head =~ "fragment"
    assert {:error, :timeout} = :gen_tcp.accept(origin, 100)
  end

  for {backend, origin_host} <- [{:ssl, "localhost"}, {:ex_ssl, "localhost"}, {:ssl, "127.0.0.1"}],
      protocol <- [:http1, :http2, :auto] do
    test "HTTPS #{protocol} #{origin_host} tunnels with #{backend} and keeps proxy auth outside TLS" do
      parent = self()
      {origin, origin_port} = listener()
      {proxy, proxy_port} = listener()

      peer =
        spawn_link(fn ->
          {:ok, tcp} = :gen_tcp.accept(proxy, 5_000)
          connect = recv_head(tcp, :gen_tcp)
          send(parent, {:connect, connect})
          :ok = :gen_tcp.send(tcp, ["HTTP/1.1 200 Connection Established\r\n", "\r\n"])
          alpn = unquote(if protocol in [:http2, :auto], do: ["h2"], else: ["http/1.1"])

          {:ok, socket} =
            :ssl.handshake(
              tcp,
              [
                certfile: String.to_charlist(Path.join(@fixtures, "localhost.pem")),
                keyfile: String.to_charlist(Path.join(@fixtures, "localhost.key")),
                active: false,
                mode: :binary,
                alpn_preferred_protocols: alpn
              ],
              5_000
            )

          serve_tls(socket, unquote(if protocol == :auto, do: :http2, else: protocol), parent)
          send(parent, {:peer_done, self()})

          receive do
            :close -> :ssl.close(socket)
          end
        end)

      on_exit(fn -> if Process.alive?(peer), do: Process.exit(peer, :kill) end)

      response =
        HTTP.fetch("https://#{unquote(origin_host)}:#{origin_port}/private",
          http_version: unquote(protocol),
          tls_backend: unquote(backend),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          proxy:
            {:http, "127.0.0.1", proxy_port,
             [headers: [{"Proxy-Authorization", "Basic proxy-secret"}]]},
          headers: [
            {"Proxy-Authorization", "Basic must-not-leak"},
            {"Authorization", "Bearer origin-secret"}
          ],
          timeout: 5_000
        )
        |> HTTP.Promise.await(7_000)

      assert %HTTP.Response{status: 200} = response
      assert HTTP.Response.read_all(response) == "ok"
      assert_receive {:connect, connect}, 2_000
      assert connect =~ "CONNECT #{unquote(origin_host)}:#{origin_port} HTTP/1.1\r\n"
      assert connect =~ "Proxy-Authorization: Basic proxy-secret\r\n"
      refute connect =~ "origin-secret"
      refute connect =~ "must-not-leak"
      assert_tunnel_request(unquote(if protocol == :auto, do: :http2, else: protocol))
      assert {:error, :timeout} = :gen_tcp.accept(origin, 100)
      assert_receive {:peer_done, ^peer}, 2_000
      send(peer, :close)
    end
  end

  for response <- [
        "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\nplaintext",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: " <> String.duplicate("x", 16_384) <> "\r\n\r\n"
      ] do
    test "CONNECT rejects unsafe response #{inspect(binary_part(response, 0, min(50, byte_size(response))))}" do
      {origin, origin_port} = listener()
      {proxy, proxy_port} = listener()
      parent = self()

      peer =
        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(proxy, 2_000)
          recv_head(socket, :gen_tcp)
          :ok = :gen_tcp.send(socket, unquote(response))
          assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
          send(parent, :proxy_closed)
        end)

      on_exit(fn -> if Process.alive?(peer), do: Process.exit(peer, :kill) end)

      assert {:error, _} =
               HTTP.fetch("https://localhost:#{origin_port}/",
                 timeout: 1_000,
                 proxy: {:http, "127.0.0.1", proxy_port, []}
               )
               |> HTTP.Promise.await(2_000)

      assert_receive :proxy_closed, 2_000
      assert {:error, :timeout} = :gen_tcp.accept(origin, 100)
    end
  end

  test "CONNECT tunnel deadline and abort close the proxy peer without origin traffic" do
    for operation <- [:timeout, :abort] do
      {origin, origin_port} = listener()
      {proxy, proxy_port} = listener()
      parent = self()

      peer =
        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(proxy, 2_000)
          recv_head(socket, :gen_tcp)
          send(parent, :connect_received)
          assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
          send(parent, :proxy_closed)
        end)

      on_exit(fn -> if Process.alive?(peer), do: Process.exit(peer, :kill) end)
      {:ok, controller} = HTTP.AbortController.start_link()

      promise =
        HTTP.fetch("https://localhost:#{origin_port}/",
          signal: controller,
          proxy:
            {:http, "127.0.0.1", proxy_port,
             [timeout: if(operation == :timeout, do: 100, else: 1_000)]},
          timeout: 1_000
        )

      assert_receive :connect_received, 2_000
      if operation == :abort, do: HTTP.AbortController.abort(controller)
      assert {:error, _} = HTTP.Promise.await(promise, 2_000)
      assert_receive :proxy_closed, 2_000
      assert {:error, :timeout} = :gen_tcp.accept(origin, 100)
    end
  end

  test "invalid proxy shapes, authentication and unsupported h2c fail before any I/O" do
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()

    for {route, version} <- [
          {"http://localhost:1", :http1},
          {{:http, "127.0.0.1", proxy_port,
            [headers: [{"Proxy-Authorization", "bad\r\nInjected: yes"}]]}, :http1},
          {{:http, "127.0.0.1", proxy_port, [headers: [{"Authorization", "origin-auth"}]]},
           :http1},
          {{:http, "127.0.0.1", proxy_port, []}, :h2c}
        ] do
      assert {:error, _} =
               HTTP.fetch("http://localhost:#{origin_port}/",
                 proxy: route,
                 http_version: version,
                 timeout: 100
               )
               |> HTTP.Promise.await(1_000)
    end

    assert {:error, :timeout} = :gen_tcp.accept(proxy, 100)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 100)
  end

  test "ExSSL IP certificate identity and Unix proxy routes are rejected before I/O" do
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()
    route = {:http, "127.0.0.1", proxy_port, []}

    assert {:error, :ex_ssl_proxy_ip_identity_unsupported} =
             HTTP.fetch("https://127.0.0.1:#{origin_port}/",
               proxy: route,
               tls_backend: :ex_ssl,
               timeout: 500
             )
             |> HTTP.Promise.await()

    assert {:error, :proxy_not_supported_for_unix_socket} =
             HTTP.fetch("http://localhost:#{origin_port}/",
               proxy: route,
               unix_socket: "/tmp/unused-proxy-test.sock",
               timeout: 500
             )
             |> HTTP.Promise.await()

    assert {:error, :timeout} = :gen_tcp.accept(proxy, 100)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 100)
  end

  test "public and socket-client HTTP/3 proxy requests fail before TCP or UDP I/O" do
    {:ok, origin} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(origin) end)
    {:ok, origin_port} = :inet.port(origin)
    {proxy, proxy_port} = listener()
    url = "https://localhost:#{origin_port}/"
    route = {:http, "127.0.0.1", proxy_port, []}

    assert {:error, :proxy_not_supported_for_quic} =
             HTTP.fetch(url, proxy: route, http_version: :http3) |> HTTP.Promise.await()

    request = %HTTP.Request{
      url: URI.parse(url),
      transport_options: [http_version: :http3, proxy: route]
    }

    assert {:error, :proxy_not_supported_for_quic} = HTTP.SocketClient.request(request)
    assert {:error, :timeout} = :gen_tcp.accept(proxy, 100)
    assert {:error, :timeout} = :gen_udp.recv(origin, 0, 100)
  end

  defp serve_tls(socket, :http1, parent) do
    send(parent, {:origin_head, recv_head(socket, :ssl)})
    :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
  end

  defp serve_tls(socket, :http2, parent) do
    assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(socket, 24, 5_000)
    :ok = :ssl.send(socket, HTTP.Test.HTTP2ScriptedPeer.frame(4, 0, 0, <<>>))
    {id, headers} = h2_headers(socket)
    send(parent, {:origin_headers, headers})

    :ok =
      :ssl.send(socket, [
        HTTP.Test.HTTP2ScriptedPeer.frame(1, 4, id, <<0x88>>),
        HTTP.Test.HTTP2ScriptedPeer.frame(0, 1, id, "ok")
      ])
  end

  defp assert_tunnel_request(:http1) do
    assert_receive {:origin_head, head}, 2_000
    assert head =~ "GET /private HTTP/1.1\r\n"
    assert head =~ "Authorization: Bearer origin-secret"
    refute String.downcase(head) =~ "proxy-authorization"
  end

  defp assert_tunnel_request(:http2) do
    assert_receive {:origin_headers, headers}, 2_000
    assert {"authorization", "Bearer origin-secret"} in headers
    refute Enum.any?(headers, fn {name, _} -> name == "proxy-authorization" end)
  end

  defp listener do
    {:ok, socket} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(socket)
    on_exit(fn -> :gen_tcp.close(socket) end)
    {socket, port}
  end

  defp recv_head(socket, transport, acc \\ "") do
    case :binary.match(acc, "\r\n\r\n") do
      {at, 4} ->
        binary_part(acc, 0, at + 4)

      :nomatch ->
        {:ok, bytes} = transport.recv(socket, 0, 5_000)
        recv_head(socket, transport, acc <> bytes)
    end
  end

  defp h2_headers(socket) do
    {:ok, <<length::24, type, _flags, _::1, id::31>>} = :ssl.recv(socket, 9, 5_000)
    payload = if length == 0, do: <<>>, else: elem(:ssl.recv(socket, length, 5_000), 1)

    if type == 1 do
      {:ok, _, headers} = HTTP.HTTP2.HPACK.decode(HTTP.HTTP2.HPACK.new_decoder(), payload)
      {id, headers}
    else
      h2_headers(socket)
    end
  end
end

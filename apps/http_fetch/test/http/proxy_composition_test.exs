defmodule HTTP.ProxyCompositionTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../support/fixtures", __DIR__)

  for {scheme, backend} <- [{:http, nil}, {:https, :ssl}, {:https, :ex_ssl}] do
    test "#{scheme}/#{backend} reuse isolates proxy credentials and endpoints" do
      scheme = unquote(scheme)
      {first_port, first_proxy} = peer(scheme)
      {second_port, second_proxy} = peer(scheme)
      url = "#{scheme}://localhost:8443/private?q=1"

      opts =
        reuse_options()
        |> Keyword.merge(
          tls_backend: unquote(backend),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          headers: [{"Authorization", "Bearer origin-secret"}]
        )

      first = Keyword.put(opts, :proxy, proxy(first_port, "Basic first-secret"))
      second = Keyword.put(opts, :proxy, proxy(first_port, "Basic second-secret"))
      other = Keyword.put(opts, :proxy, proxy(second_port, "Basic first-secret"))

      assert fetch(url, first).body == "ok"
      assert_receive {:accepted, ^first_proxy, first_connection, _}, 2_000
      assert_proxy_auth(scheme, first_proxy, first_connection, "Basic first-secret")
      assert_request(first_proxy, first_connection, 1, scheme, "Basic first-secret")

      assert fetch(url, first).body == "ok"
      assert_request(first_proxy, first_connection, 2, scheme, "Basic first-secret")

      assert fetch(url, second).body == "ok"
      assert_receive {:accepted, ^first_proxy, second_connection, _}, 2_000
      refute second_connection == first_connection
      assert_proxy_auth(scheme, first_proxy, second_connection, "Basic second-secret")
      assert_request(first_proxy, second_connection, 1, scheme, "Basic second-secret")

      assert fetch(url, first).body == "ok"
      assert_request(first_proxy, first_connection, 3, scheme, "Basic first-secret")

      assert fetch(url, other).body == "ok"
      assert_receive {:accepted, ^second_proxy, other_connection, _}, 2_000
      refute other_connection in [first_connection, second_connection]
      assert_proxy_auth(scheme, second_proxy, other_connection, "Basic first-secret")
      assert_request(second_proxy, other_connection, 1, scheme, "Basic first-secret")
    end
  end

  test "HTTP/1 reuse separates pinned destinations while preserving the origin Host" do
    {port, server} = peer(:http, ip: {0, 0, 0, 0})
    url = "http://pinned.example:#{port}/private?q=1"
    opts = Keyword.put(reuse_options(), :redirect, :manual)
    first = Keyword.put(opts, :connect_address, {127, 0, 0, 1})
    second = Keyword.put(opts, :connect_address, {127, 0, 0, 2})

    assert fetch(url, first).body == "ok"
    assert_receive {:accepted, ^server, first_connection, {127, 0, 0, 1}}, 2_000
    assert_pinned_request(server, first_connection, 1, port)
    assert fetch(url, first).body == "ok"
    assert_pinned_request(server, first_connection, 2, port)

    assert fetch(url, second).body == "ok"
    assert_receive {:accepted, ^server, second_connection, {127, 0, 0, 2}}, 2_000
    refute first_connection == second_connection
    assert_pinned_request(server, second_connection, 1, port)
    assert fetch(url, second).body == "ok"
    assert_pinned_request(server, second_connection, 2, port)
    assert fetch(url, first).body == "ok"
    assert_pinned_request(server, first_connection, 3, port)
  end

  test "proxy-mode GET entities compose with header-first response streaming" do
    {port, server} = peer(:http, gated: true)

    promise =
      HTTP.fetch("http://localhost:8443/entity",
        http_version: :http1,
        proxy: proxy(port, "Basic proxy-secret"),
        request_mode: :proxy,
        body: "get-entity",
        stream_response: true,
        decode_body: false,
        redirect: :manual,
        timeout: 4_000
      )

    assert_receive {:accepted, ^server, connection, _}, 2_000
    assert_receive {:request, ^server, ^connection, 1, head, "get-entity"}, 2_000
    assert head =~ "GET http://localhost:8443/entity HTTP/1.1\r\n"
    assert head =~ "Content-Length: 10\r\n"
    assert head =~ "Proxy-Authorization: Basic proxy-secret\r\n"
    assert_receive {:headers_sent, ^connection}, 2_000
    assert %HTTP.Response{status: 200, body: stream} = HTTP.Promise.await(promise, 1_000)
    assert is_pid(stream)
    send(stream, {:read_chunk, self(), :ack})
    send(connection, :release_body)
    assert_receive {:stream_chunk, ^stream, "ok", ack}, 2_000
    send(stream, {:stream_chunk_ack, ack})
    assert_receive {:stream_end, ^stream}, 2_000
  end

  defp reuse_options do
    [
      http_version: :http1,
      http1_reuse: true,
      http1_scope: "composition-#{System.unique_integer([:positive])}",
      timeout: 4_000,
      telemetry: false
    ]
  end

  defp fetch(url, opts), do: HTTP.fetch(url, opts) |> HTTP.Promise.await(5_000)

  defp proxy(port, auth),
    do: {:http, "127.0.0.1", port, [headers: [{"Proxy-Authorization", auth}]]}

  defp assert_proxy_auth(:http, _proxy, _connection, _auth), do: :ok

  defp assert_proxy_auth(:https, proxy, connection, auth) do
    assert_receive {:connect, ^proxy, ^connection, head}, 2_000
    assert head =~ "CONNECT localhost:8443 HTTP/1.1\r\n"
    assert head =~ "Proxy-Authorization: #{auth}\r\n"
    refute head =~ "origin-secret"
  end

  defp assert_request(proxy, connection, count, scheme, auth) do
    assert_receive {:request, ^proxy, ^connection, ^count, head, ""}, 2_000
    target = if scheme == :http, do: "http://localhost:8443/private?q=1", else: "/private?q=1"
    assert head =~ "GET #{target} HTTP/1.1\r\n"
    assert head =~ "Authorization: Bearer origin-secret\r\n"

    if scheme == :http do
      assert head =~ "Proxy-Authorization: #{auth}\r\n"
    else
      refute String.downcase(head) =~ "proxy-authorization"
    end
  end

  defp assert_pinned_request(server, connection, count, port) do
    assert_receive {:request, ^server, ^connection, ^count, head, ""}, 2_000
    assert head =~ "GET /private?q=1 HTTP/1.1\r\n"
    assert head =~ "Host: pinned.example:#{port}\r\n"
  end

  defp peer(scheme, opts \\ []) do
    parent = self()

    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        reuseaddr: true,
        ip: Keyword.get(opts, :ip, {127, 0, 0, 1})
      ])

    {:ok, {_, port}} = :inet.sockname(listener)
    server = spawn_link(fn -> accept_loop(listener, parent, scheme, opts) end)

    on_exit(fn ->
      Process.unlink(server)
      Process.exit(server, :kill)
      :gen_tcp.close(listener)
    end)

    {port, server}
  end

  defp accept_loop(listener, parent, scheme, opts) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        server = self()
        {:ok, {address, _}} = :inet.sockname(socket)

        connection =
          spawn_link(fn ->
            receive do
              :ready -> serve_connection(socket, parent, server, scheme, opts)
            end
          end)

        :ok = :gen_tcp.controlling_process(socket, connection)
        send(parent, {:accepted, server, connection, address})
        send(connection, :ready)
        accept_loop(listener, parent, scheme, opts)

      {:error, :closed} ->
        :ok
    end
  end

  defp serve_connection(socket, parent, server, :https, opts) do
    {head, "", ""} = recv_request(socket, :gen_tcp, "")
    send(parent, {:connect, server, self(), head})
    :ok = :gen_tcp.send(socket, "HTTP/1.1 200 Connection Established\r\n\r\n")

    {:ok, tls} =
      :ssl.handshake(
        socket,
        [
          certfile: String.to_charlist(Path.join(@fixtures, "localhost.pem")),
          keyfile: String.to_charlist(Path.join(@fixtures, "localhost.key")),
          active: false,
          mode: :binary,
          alpn_preferred_protocols: ["http/1.1"]
        ],
        4_000
      )

    serve(tls, :ssl, parent, server, opts, 1, "")
  end

  defp serve_connection(socket, parent, server, :http, opts),
    do: serve(socket, :gen_tcp, parent, server, opts, 1, "")

  defp serve(socket, transport, parent, server, opts, count, buffer) do
    case recv_request(socket, transport, buffer) do
      {head, body, rest} ->
        send(parent, {:request, server, self(), count, head, body})
        :ok = transport.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")

        if Keyword.get(opts, :gated, false) do
          send(parent, {:headers_sent, self()})

          receive do
            :release_body -> :ok
          after
            4_000 -> raise "response body gate was not released"
          end
        end

        :ok = transport.send(socket, "ok")
        serve(socket, transport, parent, server, opts, count + 1, rest)

      :closed ->
        transport.close(socket)
    end
  end

  defp recv_request(socket, transport, buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {at, 4} ->
        <<head::binary-size(at + 4), rest::binary>> = buffer

        length =
          case Regex.run(~r/\r\ncontent-length:\s*(\d+)/i, head) do
            [_, value] -> String.to_integer(value)
            nil -> 0
          end

        {body, rest} = recv_body(socket, transport, rest, length)
        {head, body, rest}

      :nomatch ->
        case transport.recv(socket, 0, 5_000) do
          {:ok, bytes} -> recv_request(socket, transport, buffer <> bytes)
          {:error, :closed} -> :closed
        end
    end
  end

  defp recv_body(_socket, _transport, buffer, length) when byte_size(buffer) >= length do
    <<body::binary-size(length), rest::binary>> = buffer
    {body, rest}
  end

  defp recv_body(socket, transport, buffer, length) do
    {:ok, bytes} = transport.recv(socket, 0, 4_000)
    recv_body(socket, transport, buffer <> bytes, length)
  end
end

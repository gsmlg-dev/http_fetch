defmodule HTTP.ProxyRequestCompletionTest do
  use ExUnit.Case, async: false

  alias HTTP.{Promise, RequestCompletion, Stream}

  @fixtures Path.expand("../support/fixtures", __DIR__)

  test "explicit proxy routes expose a pending public handle before dialing and support repeated/concurrent waits" do
    for proxy <- [
          {:http, "127.0.0.1", 3128, []},
          {:https, "127.0.0.1", 3128, [headers: [{"Proxy-Authorization", "Basic test"}]]}
        ] do
      options =
        HTTP.FetchOptions.new(
          proxy: proxy,
          redirect: :manual,
          request_mode: :proxy,
          http_version: :http1,
          tls_backend: :ssl
        )

      handle = RequestCompletion.new(options)
      assert %RequestCompletion{} = handle
      assert handle.tracker != nil
      assert handle.unsupported == nil
      assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    end
  end

  test "public example from issue 82 exposes valid handle and initial pending state" do
    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        case :gen_tcp.accept(proxy, 2_000) do
          {:ok, socket} ->
            :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            :gen_tcp.close(socket)

          {:error, _} ->
            :ok
        end
      end)

    promise =
      HTTP.fetch("http://origin.example/resource",
        proxy: {:http, "127.0.0.1", proxy_port, []},
        request_mode: :proxy,
        http_version: :http1,
        redirect: :manual,
        decode_body: false,
        stream_response: true,
        tls_backend: :ssl,
        timeout: 2_000
      )

    completion = Promise.completion(promise)
    assert %RequestCompletion{} = completion
    assert completion.unsupported == nil
    # Before stream read finishes, handle confirms pending or ok
    assert %HTTP.Response{status: 200, stream: stream_pid} = Promise.await(promise)
    assert is_pid(stream_pid)
    assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)

    # Read stream to completion
    assert HTTP.Response.read_all(%HTTP.Response{status: 200, stream: stream_pid}) == "ok"
    assert :ok = RequestCompletion.await(completion, 1_000)

    # Repeated and concurrent waits confirm :ok
    assert :ok = RequestCompletion.await(completion, 0)
    waiters = for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(completion, 100) end)
    assert Enum.all?(Task.await_many(waiters), &(&1 == :ok))

    _ = Task.await(peer)
  end

  test "HTTP forward proxy confirms completion and separates proxy auth from origin headers" do
    parent = self()
    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(proxy, 2_000)
        head = recv_head(socket, :gen_tcp)
        send(parent, {:proxy_head, head})
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
        :gen_tcp.close(socket)
      end)

    url = "http://origin.example/resource?q=1"

    promise =
      HTTP.fetch(url,
        proxy:
          {:http, "127.0.0.1", proxy_port,
           [headers: [{"Proxy-Authorization", "Basic proxy-token"}]]},
        headers: [{"Authorization", "Bearer origin-token"}],
        redirect: :manual,
        timeout: 2_000
      )

    completion = Promise.completion(promise)
    assert %HTTP.Response{status: 200, body: "done"} = Promise.await(promise)
    assert :ok = RequestCompletion.await(completion, 1_000)

    assert_receive {:proxy_head, head}, 2_000
    assert head =~ "GET http://origin.example/resource?q=1 HTTP/1.1\r\n"
    assert head =~ "Proxy-Authorization: Basic proxy-token\r\n"
    assert head =~ "Authorization: Bearer origin-token\r\n"

    # Repeated wait
    assert :ok = RequestCompletion.await(completion, 0)
    assert :ok = Task.await(peer)
  end

  test "HTTP forward proxy cancellation closes proxy socket and confirms cleanup" do
    parent = self()
    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(proxy, 2_000)
        head = recv_head(socket, :gen_tcp)
        send(parent, {:proxy_connected, head})

        # Wait until client closes socket
        result = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, {:proxy_socket_closed, result})
        :gen_tcp.close(socket)
      end)

    promise =
      HTTP.fetch("http://origin.example/slow",
        proxy: {:http, "127.0.0.1", proxy_port, []},
        redirect: :manual,
        timeout: 5_000
      )

    completion = Promise.completion(promise)
    assert_receive {:proxy_connected, _head}, 2_000

    assert :ok = RequestCompletion.abort_and_await(completion, 2_000)
    assert_receive {:proxy_socket_closed, {:error, :closed}}, 2_000
    assert {:error, _} = Promise.await(promise)

    assert :ok = RequestCompletion.await(completion, 0)
    assert :ok = Task.await(peer)
  end

  test "streaming upload via HTTP proxy settles request helpers and confirms cleanup on cancellation" do
    parent = self()
    {:ok, source} = Stream.start_link(0)

    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(proxy, 2_000)
        head = recv_head(socket, :gen_tcp)
        send(parent, {:upload_started, head})
        result = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, {:upload_closed, result})
        :gen_tcp.close(socket)
      end)

    promise =
      HTTP.fetch("http://origin.example/upload",
        method: :post,
        body: source,
        duplex: :half,
        proxy: {:http, "127.0.0.1", proxy_port, []},
        redirect: :manual,
        timeout: 5_000
      )

    completion = Promise.completion(promise)
    assert_receive {:upload_started, _head}, 2_000

    assert :ok = RequestCompletion.abort_and_await(completion, 2_000)
    assert_receive {:upload_closed, {:error, :closed}}, 2_000
    refute Process.alive?(source)
    assert {:error, _} = Promise.await(promise)

    assert :ok = RequestCompletion.await(completion, 0)
    assert :ok = Task.await(peer)
  end

  test "pooled HTTP/1 reuse via proxy preserves healthy reused connection" do
    parent = self()
    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(proxy, 2_000)

        for n <- 1..2 do
          head = recv_head(socket, :gen_tcp)
          send(parent, {:request, n, head})
          :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        end

        receive do
          :close -> :gen_tcp.close(socket)
        end
      end)

    url = "http://origin.example/resource"
    scope = "proxy-pool-#{System.unique_integer([:positive])}"

    opts = [
      proxy: {:http, "127.0.0.1", proxy_port, []},
      http1_reuse: true,
      http1_scope: scope,
      redirect: :manual,
      timeout: 2_000
    ]

    first = HTTP.fetch(url, opts)
    assert %HTTP.Response{body: "ok"} = Promise.await(first)
    first_completion = Promise.completion(first)
    assert :ok = RequestCompletion.await(first_completion, 1_000)
    assert_receive {:request, 1, _}

    # Second request reuses the connection
    second = HTTP.fetch(url, opts)
    # Aborting first request completion must not harm the reused connection
    assert :ok = RequestCompletion.abort_and_await(first_completion, 0)

    assert %HTTP.Response{body: "ok"} = Promise.await(second)
    second_completion = Promise.completion(second)
    assert :ok = RequestCompletion.await(second_completion, 1_000)
    assert_receive {:request, 2, _}

    send(peer.pid, :close)
    assert :ok = Task.await(peer)
  end

  test "HTTPS proxy confirms request cleanup and supports cancellation" do
    {port, peer} = https_proxy_peer()
    route = {:https, "localhost", port, []}

    options = [
      proxy: route,
      tls_backend: :ssl,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
      redirect: :manual,
      timeout: 3_000
    ]

    promise = HTTP.fetch("http://origin.invalid:8080/data", options)
    completion = Promise.completion(promise)
    assert %HTTP.Response{status: 200, body: "ok"} = Promise.await(promise)
    assert :ok = RequestCompletion.await(completion, 1_000)
    assert :ok = RequestCompletion.await(completion, 0)

    Process.exit(peer, :kill)
  end

  test "HTTPS proxy pooled reuse preserves reused connection" do
    {port, peer} = https_proxy_peer()
    scope = "https-proxy-pool-#{System.unique_integer([:positive])}"

    options = [
      proxy: {:https, "localhost", port, []},
      tls_backend: :ssl,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
      http1_reuse: true,
      http1_scope: scope,
      redirect: :manual,
      timeout: 3_000
    ]

    first = HTTP.fetch("http://origin.invalid:8080/data", options)
    assert %HTTP.Response{body: "ok"} = Promise.await(first)
    first_completion = Promise.completion(first)
    assert :ok = RequestCompletion.await(first_completion, 1_000)

    second = HTTP.fetch("http://origin.invalid:8080/data", options)
    assert :ok = RequestCompletion.abort_and_await(first_completion, 0)
    assert %HTTP.Response{body: "ok"} = Promise.await(second)
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)

    Process.exit(peer, :kill)
  end

  test "HTTPS origin through HTTP proxy CONNECT tunnel confirms completion and cancellation" do
    parent = self()
    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(proxy, 3_000)
        connect = recv_head(tcp, :gen_tcp)
        send(parent, {:connect_received, connect})
        :ok = :gen_tcp.send(tcp, "HTTP/1.1 200 Connection Established\r\n\r\n")

        # Upgrade to TLS server on the tunnel
        server_ssl_opts = [
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          alpn_preferred_protocols: ["http/1.1"],
          active: false
        ]

        {:ok, ssl} = :ssl.handshake(tcp, server_ssl_opts, 3_000)
        origin_head = recv_head(ssl, :ssl)
        send(parent, {:origin_head, origin_head})
        :ok = :ssl.send(ssl, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ntunnel")
        :ssl.close(ssl)
      end)

    promise =
      HTTP.fetch("https://localhost/secure",
        proxy:
          {:http, "127.0.0.1", proxy_port,
           [headers: [{"Proxy-Authorization", "Basic tunnel-auth"}]]},
        headers: [{"Authorization", "Bearer origin-auth"}],
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
        redirect: :manual,
        timeout: 3_000
      )

    completion = Promise.completion(promise)
    assert %HTTP.Response{status: 200, body: "tunnel"} = Promise.await(promise)
    assert :ok = RequestCompletion.await(completion, 1_000)

    assert_receive {:connect_received, connect}, 2_000
    assert connect =~ "CONNECT localhost:443 HTTP/1.1\r\n"
    assert connect =~ "Proxy-Authorization: Basic tunnel-auth\r\n"
    refute connect =~ "Bearer origin-auth"

    assert_receive {:origin_head, origin_head}, 2_000
    assert origin_head =~ "GET /secure HTTP/1.1\r\n"
    assert origin_head =~ "Authorization: Bearer origin-auth\r\n"
    refute origin_head =~ "Proxy-Authorization"

    assert :ok = Task.await(peer)
  end

  test "HTTPS origin through HTTP proxy tunnel cancellation during CONNECT closes socket" do
    parent = self()
    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(proxy, 3_000)
        connect = recv_head(tcp, :gen_tcp)
        send(parent, {:connect_stalled, connect})
        # Client cancels while waiting for CONNECT response
        result = :gen_tcp.recv(tcp, 0, 2_000)
        send(parent, {:tunnel_closed, result})
        :gen_tcp.close(tcp)
      end)

    promise =
      HTTP.fetch("https://localhost/secure",
        proxy: {:http, "127.0.0.1", proxy_port, []},
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
        redirect: :manual,
        timeout: 5_000
      )

    completion = Promise.completion(promise)
    assert_receive {:connect_stalled, _}, 2_000

    assert :ok = RequestCompletion.abort_and_await(completion, 2_000)
    assert_receive {:tunnel_closed, {:error, :closed}}, 2_000
    assert {:error, _} = Promise.await(promise)
    assert :ok = RequestCompletion.await(completion, 0)
    assert :ok = Task.await(peer)
  end

  test "HTTPS origin through HTTP proxy CONNECT tunnel supports HTTP/2 and confirms stream completion" do
    {proxy, proxy_port} = tcp_listener()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(proxy, 3_000)
        _connect = recv_head(tcp, :gen_tcp)
        :ok = :gen_tcp.send(tcp, "HTTP/1.1 200 Connection Established\r\n\r\n")

        server_ssl_opts = [
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          alpn_preferred_protocols: ["h2"],
          active: false
        ]

        {:ok, ssl} = :ssl.handshake(tcp, server_ssl_opts, 3_000)
        assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(ssl, 24, 5_000)
        :ok = :ssl.send(ssl, HTTP.Test.HTTP2ScriptedPeer.frame(4, 0, 0, <<>>))
        {id, _headers} = h2_headers(ssl)

        :ok =
          :ssl.send(ssl, [
            HTTP.Test.HTTP2ScriptedPeer.frame(1, 4, id, <<0x88>>),
            HTTP.Test.HTTP2ScriptedPeer.frame(0, 1, id, "h2-done")
          ])

        receive do
          :close -> :ssl.close(ssl)
        end
      end)

    scope = "proxy-h2-#{System.unique_integer([:positive])}"

    promise =
      HTTP.fetch("https://localhost/h2",
        http_version: :http2,
        http2_scope: scope,
        proxy: {:http, "127.0.0.1", proxy_port, []},
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
        redirect: :manual,
        timeout: 3_000
      )

    completion = Promise.completion(promise)
    response = Promise.await(promise)
    assert %HTTP.Response{status: 200} = response
    assert HTTP.Response.read_all(response) == "h2-done"
    assert :ok = RequestCompletion.await(completion, 1_000)
    assert :ok = RequestCompletion.await(completion, 0)

    send(peer.pid, :close)
    assert :ok = Task.await(peer)
  end

  defp tcp_listener do
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

  defp https_proxy_peer do
    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        alpn_preferred_protocols: ["http/1.1"]
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)
    parent = self()
    peer = spawn(fn -> accept_https_proxy(listener, parent) end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)

    {port, peer}
  end

  defp accept_https_proxy(listener, parent) do
    case :ssl.transport_accept(listener) do
      {:ok, socket} ->
        child =
          spawn_link(fn ->
            receive do
              :ready ->
                case :ssl.handshake(socket, 3_000) do
                  {:ok, socket} -> serve_https_proxy(socket, parent, "")
                  {:error, _} -> :ssl.close(socket)
                end
            end
          end)

        :ok = :ssl.controlling_process(socket, child)
        send(child, :ready)
        accept_https_proxy(listener, parent)

      {:error, :closed} ->
        :ok
    end
  end

  defp serve_https_proxy(socket, parent, bytes) do
    case :binary.match(bytes, "\r\n\r\n") do
      {at, 4} ->
        <<head::binary-size(at + 4), rest::binary>> = bytes
        send(parent, {:proxy_request, head})
        :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        serve_https_proxy(socket, parent, rest)

      :nomatch ->
        case :ssl.recv(socket, 0, :infinity) do
          {:ok, chunk} -> serve_https_proxy(socket, parent, bytes <> chunk)
          {:error, :closed} -> :ssl.close(socket)
        end
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

defmodule HTTP.HTTP1ReuseTest do
  use ExUnit.Case, async: true

  for {scheme, backend} <- [{:http, nil}, {:https, :ssl}, {:https, :ex_ssl}] do
    test "#{scheme}/#{backend} reuses one fully consumed connection" do
      {url, peer, opts} = peer(unquote(scheme))
      opts = Keyword.merge(opts, http1_reuse: true, tls_backend: unquote(backend))
      assert fetch(url, opts).body == "ok"
      assert fetch(url, opts).body == "ok"
      assert_receive {:accepted, ^peer}, 2_000
      refute_receive {:accepted, ^peer}, 50
      assert_receive {:requests, ^peer, 2}, 2_000
    end
  end

  test "default policy uses separate connections" do
    {url, peer, opts} = peer(:http)
    assert fetch(url, opts).body == "ok"
    assert fetch(url, opts).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
  end

  test "a server close response is not retained" do
    {url, peer, opts} = peer(:http, "Connection: close\r\n")
    assert fetch(url, Keyword.put(opts, :http1_reuse, true)).body == "ok"
    assert fetch(url, Keyword.put(opts, :http1_reuse, true)).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
  end

  test "HTTP1.0 without keep-alive is not retained" do
    {url, peer, opts} = peer(:http, "", "HTTP/1.0")
    assert fetch(url, Keyword.put(opts, :http1_reuse, true)).body == "ok"
    assert fetch(url, Keyword.put(opts, :http1_reuse, true)).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
  end

  test "idle expiry closes a retained peer" do
    {url, peer, opts} = peer(:http)

    assert fetch(url, Keyword.merge(opts, http1_reuse: true, http1_idle_timeout: 100)).body ==
             "ok"

    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:closed, ^peer}, 2_000
  end

  test "TLS policies and caller scopes do not share idle connections" do
    {url, peer, opts} = peer(:https)
    first = Keyword.merge(opts, http1_reuse: true, http1_scope: "route-a")
    second = Keyword.merge(opts, http1_reuse: true, http1_scope: "route-b")
    assert fetch(url, first).body == "ok"
    assert fetch(url, second).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
    assert fetch(url, Keyword.put(first, :ssl, verify: :verify_none)).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
  end

  test "stale idle connections are discarded before a new request" do
    {url, peer, opts} = peer(:http)
    opts = Keyword.put(opts, :http1_reuse, true)
    assert fetch(url, opts).body == "ok"
    assert_receive {:peer_socket, ^peer, socket}, 2_000
    :gen_tcp.close(socket)
    assert fetch(url, opts).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
  end

  test "acknowledged chunked responses can reuse the connection" do
    {url, peer, opts} = peer(:http, :chunked)
    opts = Keyword.put(opts, :http1_reuse, true)
    response = fetch(url, opts)
    assert is_pid(response.body)
    assert HTTP.Response.read_all(response) == "ok"
    assert HTTP.Response.read_all(fetch(url, opts)) == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    refute_receive {:accepted, ^peer}, 50
  end

  test "abort with an unread chunked body closes instead of retaining the socket" do
    {url, peer, opts} = peer(:http, :chunked)
    controller = HTTP.AbortController.new()
    opts = Keyword.merge(opts, http1_reuse: true, signal: controller)
    response = fetch(url, opts)
    assert is_pid(response.body)
    HTTP.AbortController.abort(controller)
    assert_receive {:closed, ^peer}, 2_000
    assert HTTP.Response.read_all(fetch(url, Keyword.delete(opts, :signal))) == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
  end

  test "a connection closed after uncertain POST response is never replayed" do
    {url, peer, opts} = peer(:http, :truncated)

    assert {:error, :closed} =
             fetch(url, Keyword.merge(opts, http1_reuse: true, method: :post, body: "abc"))

    assert_receive {:accepted, ^peer}, 2_000
    refute_receive {:accepted, ^peer}, 50
  end

  test "per-route idle limit closes excess simultaneous connections" do
    {url, peer, opts} = peer(:http, :gated)
    opts = Keyword.merge(opts, http1_reuse: true, http1_pool_size: 1)
    tasks = for _ <- 1..2, do: Task.async(fn -> fetch(url, opts) end)
    assert_receive {:waiting, ^peer, first}, 2_000
    assert_receive {:waiting, ^peer, second}, 2_000
    send(first, :release)
    send(second, :release)
    for task <- tasks, do: assert(Task.await(task).body == "ok")
    assert_receive {:closed, ^peer}, 2_000
    assert fetch(url, opts).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
    refute_receive {:accepted, ^peer}, 50
  end

  test "pool policy validates options instead of silently ignoring them" do
    assert_raise ArgumentError, fn -> HTTP.FetchOptions.new(http1_reuse: :yes) end
    assert_raise ArgumentError, fn -> HTTP.FetchOptions.new(http1_pool_size: 0) end
    assert_raise ArgumentError, fn -> HTTP.FetchOptions.new(http1_idle_timeout: 0) end
  end

  defp fetch(url, opts) do
    HTTP.fetch(url, Keyword.merge([http_version: :http1, timeout: 3_000, telemetry: false], opts))
    |> HTTP.Promise.await(4_000)
  end

  defp peer(scheme, extra \\ "", version \\ "HTTP/1.1") do
    parent = self()
    transport = if scheme == :http, do: :gen_tcp, else: :ssl
    fixture = Path.expand("../support/fixtures", __DIR__)

    tls_opts =
      if scheme == :http,
        do: [],
        else: [
          certfile: String.to_charlist(Path.join(fixture, "localhost.pem")),
          keyfile: String.to_charlist(Path.join(fixture, "localhost.key")),
          versions: [:"tlsv1.3"]
        ]

    {:ok, listener} =
      transport.listen(
        0,
        [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}] ++ tls_opts
      )

    {:ok, {_, port}} =
      if scheme == :http, do: :inet.sockname(listener), else: :ssl.sockname(listener)

    peer = spawn_link(fn -> accept_loop(listener, transport, parent, self(), extra, version) end)

    on_exit(fn ->
      Process.unlink(peer)
      Process.exit(peer, :kill)
      transport.close(listener)
    end)

    opts =
      if scheme == :http,
        do: [],
        else: [ssl: [cacertfile: Path.join(fixture, "localhost-ca.pem")]]

    {"#{scheme}://localhost:#{port}/", peer, opts}
  end

  defp accept_loop(listener, transport, parent, peer, extra, version) do
    result =
      if transport == :gen_tcp,
        do: :gen_tcp.accept(listener),
        else: :ssl.transport_accept(listener)

    case result do
      {:ok, socket} ->
        socket =
          if transport == :gen_tcp, do: socket, else: elem(:ssl.handshake(socket, 2_000), 1)

        send(parent, {:accepted, peer})
        send(parent, {:peer_socket, peer, socket})
        spawn_link(fn -> serve(socket, transport, parent, peer, extra, version, 0) end)
        accept_loop(listener, transport, parent, peer, extra, version)

      {:error, :closed} ->
        :ok
    end
  end

  defp serve(socket, transport, parent, peer, extra, version, count) do
    case transport.recv(socket, 0, 3_000) do
      {:ok, _head} ->
        if extra == :gated and count == 0 do
          send(parent, {:waiting, peer, self()})

          receive do
            :release -> :ok
          after
            3_000 -> raise "response gate was not released"
          end
        end

        :ok = transport.send(socket, response_wire(extra, version))
        send(parent, {:requests, peer, count + 1})
        if extra == :truncated, do: transport.close(socket)
        serve(socket, transport, parent, peer, extra, version, count + 1)

      {:error, _} ->
        send(parent, {:closed, peer})
        transport.close(socket)
    end
  end

  defp response_wire(:gated, version), do: response_wire("", version)

  defp response_wire(:chunked, version),
    do: "#{version} 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"

  defp response_wire(:truncated, version), do: "#{version} 200 OK\r\nContent-Length: 4\r\n\r\nok"

  defp response_wire(extra, version),
    do: "#{version} 200 OK\r\nContent-Length: 2\r\n#{extra}\r\nok"
end

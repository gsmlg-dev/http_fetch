defmodule HTTP.HTTP1ReuseTest do
  use ExUnit.Case, async: false

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

  test "queued activation cannot revive an expired ownership handoff" do
    {url, peer, opts} = peer(:http)
    assert fetch(url, Keyword.put(opts, :http1_reuse, true)).body == "ok"
    entry = idle_entry!(url)
    {:ok, socket} = :gen_tcp.connect(~c"localhost", URI.parse(url).port, [:binary, active: false])
    pool = Process.whereis(HTTP.HTTP1.Pool)
    {:ok, token} = GenServer.call(pool, {:prepare, entry.key, HTTP.Transport.TCP, socket})
    :ok = :gen_tcp.controlling_process(socket, pool)
    pending = :sys.get_state(pool).entries[token]
    suspend_pool!()
    task = Task.async(fn -> GenServer.call(pool, {:activate, token}) end)
    await!(fn -> queued_message?(pool, &match?({:"$gen_call", _, {:activate, ^token}}, &1)) end)
    await!(fn -> Process.read_timer(pending.timer) == false end)
    :sys.resume(pool)
    assert Task.await(task) == :expired
    assert_receive {:closed, ^peer}, 2_000
  end

  test "a queued checkout cannot lease a socket after its idle deadline" do
    {url, peer, opts} = peer(:http)
    opts = Keyword.merge(opts, http1_reuse: true, http1_idle_timeout: 300)
    assert fetch(url, opts).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    entry = idle_entry!(url)
    pool = suspend_pool!()
    promise = start_fetch(url, opts)
    await!(fn -> queued_checkout?(pool) end)
    await!(fn -> Process.read_timer(entry.timer) == false end)
    :sys.resume(pool)
    assert HTTP.Promise.await(promise, 4_000).body == "ok"
    assert_receive {:closed, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
  end

  for cancellation <- [:deadline, :abort, :caller_death] do
    test "#{cancellation} during queued checkout sends no POST bytes" do
      {url, peer, opts} = peer(:http)
      opts = Keyword.put(opts, :http1_reuse, true)
      assert fetch(url, opts).body == "ok"
      assert_receive {:requests, ^peer, 1}, 2_000
      idle_entry!(url)
      pool = suspend_pool!()
      controller = HTTP.AbortController.new()

      promise =
        start_fetch(
          url,
          Keyword.merge(opts,
            method: :post,
            body: "must-not-be-sent",
            signal: controller,
            timeout: if(unquote(cancellation) == :deadline, do: 200, else: 3_000)
          )
        )

      await!(fn -> queued_checkout?(pool) end)
      owner = Agent.get(controller, & &1.request_id)
      monitor = Process.monitor(owner)

      case unquote(cancellation) do
        :deadline ->
          await!(fn -> queued_message?(owner, &(&1 == :deadline)) end)

        :abort ->
          HTTP.AbortController.abort(controller)
          await!(fn -> queued_message?(owner, &(&1 == :abort)) end)

        :caller_death ->
          Process.exit(promise.task.pid, :kill)
          await!(fn -> queued_message?(owner, &match?({:DOWN, _, :process, _, _}, &1)) end)
      end

      :sys.resume(pool)

      case unquote(cancellation) do
        :deadline -> assert HTTP.Promise.await(promise, 4_000) == {:error, :request_timeout}
        :abort -> assert HTTP.Promise.await(promise, 4_000) == {:error, :aborted}
        :caller_death -> Process.demonitor(promise.task.ref, [:flush])
      end

      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 2_000
      assert_receive {:closed, ^peer}, 2_000
      refute_receive {:requests, ^peer, 2}, 0
      refute_receive {:wire, ^peer, "POST " <> _}, 0
    end
  end

  test "idle socket data queued behind checkout discards the socket before reuse" do
    {url, peer, opts} = peer(:http)
    opts = Keyword.put(opts, :http1_reuse, true)
    assert fetch(url, opts).body == "ok"
    assert_receive {:peer_socket, ^peer, peer_socket}, 2_000
    entry = idle_entry!(url)
    pool = suspend_pool!()
    promise = start_fetch(url, opts)
    await!(fn -> queued_checkout?(pool) end)
    :ok = :gen_tcp.send(peer_socket, "unsolicited")

    await!(fn ->
      queued_message?(pool, &match?({:tcp, socket, _} when socket == entry.socket, &1))
    end)

    :sys.resume(pool)
    assert HTTP.Promise.await(promise, 4_000).body == "ok"
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:accepted, ^peer}, 2_000
    assert_receive {:closed, ^peer}, 2_000
  end

  test "reuse refreshes send timeout from the current request budget" do
    {url, _peer, opts} = peer(:http)
    opts = Keyword.put(opts, :http1_reuse, true)
    assert fetch(url, Keyword.put(opts, :timeout, 10_000)).body == "ok"
    assert fetch(url, Keyword.put(opts, :timeout, 1_000)).body == "ok"
    socket = idle_entry!(url).socket
    assert {:ok, [send_timeout: timeout]} = :inet.getopts(socket, [:send_timeout])
    assert timeout > 0 and timeout <= 1_000
  end

  test "buffered OTP TLS prime retains bounded teardown for a blocked reused upload" do
    {url, peer, opts} = peer(:https, :tls_upload)

    opts =
      Keyword.merge(opts,
        http1_reuse: true,
        timeout: 6_000,
        socket_opts: [sndbuf: 1_024, high_watermark: 1_024, low_watermark: 512]
      )

    assert fetch(url, opts).body == "ok"
    assert {:cancellable_ssl, _ssl, tcp} = idle_entry!(url).socket

    {:ok, upload} =
      HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> :binary.copy("x", 65_536) end))

    controller = HTTP.AbortController.new()

    promise =
      start_fetch(
        url,
        Keyword.merge(opts, method: :post, body: upload, duplex: :half, signal: controller)
      )

    assert_receive {:upload_waiting, ^peer, handler}, 2_000
    owner = Agent.get(controller, & &1.request_id)
    owner_monitor = Process.monitor(owner)
    writer = blocked_tls_writer!(owner)

    await!(fn ->
      case :inet.getstat(tcp, [:send_pend]) do
        {:ok, [send_pend: pending]} -> pending > 0
        _ -> false
      end
    end)

    writer_monitor = Process.monitor(writer)
    send(handler, :reject_upload)
    assert %HTTP.Response{status: 413} = HTTP.Promise.await(promise, 2_000)
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, :killed}, 1_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000
    refute Process.alive?(upload)
    send(handler, :peer_done)
    assert_receive {:accepted, ^peer}, 2_000
    refute_receive {:accepted, ^peer}, 0
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

  defp start_fetch(url, opts) do
    HTTP.fetch(url, Keyword.merge([http_version: :http1, timeout: 3_000, telemetry: false], opts))
  end

  defp idle_entry!(url) do
    port = URI.parse(url).port

    await!(fn ->
      HTTP.HTTP1.Pool
      |> :sys.get_state()
      |> Map.fetch!(:entries)
      |> Enum.find_value(fn {_, entry} ->
        if entry.key.port == port and entry.status == :idle, do: entry
      end)
    end)
  end

  defp suspend_pool! do
    pool = Process.whereis(HTTP.HTTP1.Pool)
    :ok = :sys.suspend(pool)
    on_exit(fn -> if Process.alive?(pool), do: :sys.resume(pool) end)
    pool
  end

  defp queued_checkout?(pool),
    do: queued_message?(pool, &match?({:"$gen_call", _, {:checkout, _}}, &1))

  defp queued_message?(pid, predicate) do
    case Process.info(pid, :messages) do
      {:messages, messages} -> Enum.any?(messages, predicate)
      nil -> false
    end
  end

  defp await!(condition, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 2_000
    result = condition.()

    cond do
      result ->
        result

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("condition did not become true")

      true ->
        receive do
        after
          1 -> await!(condition, deadline)
        end
    end
  end

  defp blocked_tls_writer!(owner) do
    await!(fn ->
      {:links, links} = Process.info(owner, :links)

      Enum.find(Enum.filter(links, &is_pid/1), &blocked_tls_writer?/1)
    end)
  end

  defp blocked_tls_writer?(pid) do
    case Process.info(pid, :current_stacktrace) do
      {:current_stacktrace, stack} ->
        Enum.any?(stack, fn {module, function, _, _} -> module == :ssl and function == :send end) and
          Enum.any?(stack, fn {module, _, _, _} -> module == HTTP.HTTP1.Upload end)

      _ ->
        false
    end
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
        [:binary, active: false, reuseaddr: true, recbuf: 1_024, ip: {127, 0, 0, 1}] ++ tls_opts
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

  defp serve(socket, :ssl, parent, peer, :tls_upload, _version, 1) do
    recv_tls_headers(socket, "")
    send(parent, {:upload_waiting, peer, self()})

    receive do
      :reject_upload ->
        :ok = :ssl.send(socket, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
    after
      4_000 -> raise "TLS upload gate was not released"
    end

    receive do
      :peer_done -> :ssl.close(socket)
    after
      4_000 -> :ssl.close(socket)
    end
  end

  defp serve(socket, transport, parent, peer, extra, version, count) do
    case transport.recv(socket, 0, 3_000) do
      {:ok, head} ->
        send(parent, {:wire, peer, head})

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

  defp recv_tls_headers(socket, bytes) do
    if String.contains?(bytes, "\r\n\r\n") do
      :ok
    else
      {:ok, chunk} = :ssl.recv(socket, 0, 2_000)
      recv_tls_headers(socket, bytes <> chunk)
    end
  end

  defp response_wire(:tls_upload, version), do: response_wire("", version)

  defp response_wire(:gated, version), do: response_wire("", version)

  defp response_wire(:chunked, version),
    do: "#{version} 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"

  defp response_wire(:truncated, version), do: "#{version} 200 OK\r\nContent-Length: 4\r\n\r\nok"

  defp response_wire(extra, version),
    do: "#{version} 200 OK\r\nContent-Length: 2\r\n#{extra}\r\nok"
end

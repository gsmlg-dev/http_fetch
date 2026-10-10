defmodule HTTP.PooledRequestCompletionTest do
  use ExUnit.Case, async: false

  alias HTTP.{Promise, RequestCompletion}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer
  @fixtures Path.expand("../../../http_web_socket/test/support/fixtures", __DIR__)

  test "pooled HTTP1 and HTTP2 expose a pending public handle before dialing" do
    for opts <- [[http1_reuse: true], [http_version: :http2], [http_version: :h2c]] do
      options = HTTP.FetchOptions.new(Keyword.merge([redirect: :manual], opts))
      handle = RequestCompletion.new(options)
      assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
      send(handle.tracker, :launch_failed)
      assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(handle, 1_000)
    end
  end

  test "HTTP1 completion returns an idle connection and cannot cancel its next lease" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)

        for n <- 1..2 do
          {:ok, _head} = :gen_tcp.recv(socket, 0, 2_000)
          send(parent, {:h1_request, n})
          :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        end

        receive do
          :close -> :gen_tcp.close(socket)
        end

        :gen_tcp.close(listener)
      end)

    on_exit(fn -> :gen_tcp.close(listener) end)
    url = "http://127.0.0.1:#{port}/"
    opts = [http1_reuse: true, redirect: :manual, timeout: 2_000]
    first = HTTP.fetch(url, opts)
    assert %HTTP.Response{body: "ok"} = Promise.await(first)
    assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
    assert_receive {:h1_request, 1}
    second = HTTP.fetch(url, opts)
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(first), 0)
    assert %HTTP.Response{body: "ok"} = Promise.await(second)
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    assert_receive {:h1_request, 2}
    send(peer.pid, :close)
    assert :ok = Task.await(peer)
  end

  test "HTTP2 cancellation settles one stream while a live sibling and pooled socket survive" do
    parent = self()

    {url, peer} =
      Peer.start(parent, fn socket ->
        {first_id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, first_id, <<0x88>>))
        {second_id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, second_id, <<0x88>>))
        await_reset(socket, first_id)
        send(parent, :reset_observed)

        receive do
          :finish_sibling -> :ok
        end

        :ok = :gen_tcp.send(socket, Peer.frame(0, 1, second_id, "survived"))
        {third_id, true} = Peer.request(socket)
        :ok = Peer.response(socket, third_id, "reused")
      end)

    first = h2_fetch(url)
    assert %HTTP.Response{status: 200} = Promise.await(first)
    second = h2_fetch(url)
    sibling = Promise.await(second)
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(first), 1_000)
    assert_receive :reset_observed
    assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(second), 0)
    send(peer, :finish_sibling)
    assert HTTP.Response.read_all(sibling) == "survived"
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    third = h2_fetch(url)
    assert HTTP.Response.read_all(Promise.await(third)) == "reused"
    assert :ok = RequestCompletion.await(Promise.completion(third), 1_000)
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "HTTP1 cancellation during checkout stays pending until the leased socket closes" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        {:ok, _head} = :gen_tcp.recv(socket, 0, 2_000)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, :checkout_peer_closed)
        :gen_tcp.close(listener)
      end)

    on_exit(fn -> :gen_tcp.close(listener) end)
    url = "http://127.0.0.1:#{port}/"
    opts = [http1_reuse: true, redirect: :manual, timeout: 2_000]
    first = HTTP.fetch(url, opts)
    Promise.await(first)
    assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
    pool = Process.whereis(HTTP.HTTP1.Pool)
    :sys.suspend(pool)
    second = HTTP.fetch(url, Keyword.merge(opts, method: :post, body: "must-not-send"))

    try do
      wait_until(fn ->
        {:messages, messages} = Process.info(pool, :messages)
        Enum.any?(messages, &match?({:"$gen_call", _, {:checkout, _}}, &1))
      end)

      assert {:error, :cleanup_pending} =
               RequestCompletion.abort_and_await(Promise.completion(second), 20)
    after
      :sys.resume(pool)
    end

    assert {:error, :aborted} = Promise.await(second)
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    assert_receive :checkout_peer_closed
    assert :ok = Task.await(peer)
  end

  test "HTTP2 stream termination stays pending behind suspended shared-owner cleanup" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
        await_reset(socket, id)
      end)

    promise = h2_fetch(url)
    response = Promise.await(promise)
    stream = response.stream
    monitor = Process.monitor(stream)
    send(stream, {:read_chunk, self(), :ack})
    owner = h2_owner(url)
    :sys.suspend(owner)

    try do
      handle = Promise.completion(promise)
      assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 20)
      assert_receive {:stream_error, ^stream, :aborted}
      assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}
      waiters = for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(handle, 20) end)
      assert Enum.all?(waiters, &(Task.await(&1) == {:error, :cleanup_pending}))
    after
      :sys.resume(owner)
    end

    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 0)
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "HTTP2 early response waits for a suspended upload source to terminate" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, false} = Peer.request(socket)

        receive do
          :respond -> :ok
        end

        :ok = Peer.response(socket, id, "early")
      end)

    {:ok, source} = HTTP.Stream.start_link(0)
    promise = h2_fetch(url, method: :post, body: source, duplex: :half)
    owner = wait_until(fn -> h2_owner(url) end)
    wait_until(fn -> map_size(:sys.get_state(owner).streams) == 1 end)
    :erlang.suspend_process(source)

    try do
      send(peer, :respond)
      response = Promise.await(promise)
      assert HTTP.Response.read_all(response) == "early"
      assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(promise), 20)
    after
      :erlang.resume_process(source)
    end

    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    refute Process.alive?(source)
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "HTTP2 shared-owner death returns persistent unconfirmed cleanup" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))
      end)

    promise = h2_fetch(url)
    Promise.await(promise)
    Process.exit(h2_owner(url), :kill)

    assert {:error, :cleanup_unconfirmed} =
             RequestCompletion.await(Promise.completion(promise), 1_000)

    assert {:error, :cleanup_unconfirmed} =
             RequestCompletion.await(Promise.completion(promise), 0)

    send(peer, :close)
  end

  for terminal <- [:abort, :deadline] do
    test "HTTP2 #{terminal} settles a pool wait without touching the occupied sibling" do
      parent = self()
      pool = Process.whereis(:http_fetch_http2_pool)
      previous_limit = :sys.get_state(pool).max_connections
      :sys.replace_state(pool, &%{&1 | max_connections: 1})
      on_exit(fn -> :sys.replace_state(pool, &%{&1 | max_connections: previous_limit}) end)

      {url, peer} =
        Peer.start(
          parent,
          fn socket ->
            {id, true} = Peer.request(socket)
            :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))

            receive do
              :finish_sibling -> :ok
            end

            :ok = :gen_tcp.send(socket, Peer.frame(0, 1, id, "sibling"))
          end,
          settings: <<3::16, 1::32>>
        )

      first = h2_fetch(url)
      sibling = Promise.await(first)
      controller = HTTP.AbortController.new()
      promise = h2_fetch(url, signal: controller)
      wait_until(fn -> pool_stats(url).pending == 1 end)

      case unquote(terminal) do
        :abort ->
          assert :ok = RequestCompletion.abort_and_await(Promise.completion(promise), 1_000)
          assert {:error, :aborted} = Promise.await(promise)

        :deadline ->
          send(Agent.get(controller, & &1.request_id), :deadline)
          assert {:error, :request_timeout} = Promise.await(promise)
          assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
      end

      assert pool_stats(url).pending == 0
      assert pool_stats(url).streams == 1
      assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(first), 0)
      send(peer, :finish_sibling)
      assert HTTP.Response.read_all(sibling) == "sibling"
      assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
      assert pool_stats(url).streams == 0
      assert_receive {:peer_complete, ^peer}
      send(peer, :close)
    end
  end

  test "HTTP2 completion waits for pool release after request EOF" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {id, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, id, <<0x88>>))

        receive do
          :finish -> :ok
        end

        :ok = :gen_tcp.send(socket, Peer.frame(0, 1, id, "done"))
      end)

    promise = h2_fetch(url)
    response = Promise.await(promise)
    pool = Process.whereis(:http_fetch_http2_pool)
    :sys.suspend(pool)

    try do
      send(peer, :finish)
      assert HTTP.Response.read_all(response) == "done"
      assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(promise), 20)
    after
      :sys.resume(pool)
    end

    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert pool_stats(url).streams == 0
    assert_receive {:peer_complete, ^peer}
    send(peer, :close)
  end

  test "pooled cancellation remains sticky before owner registration" do
    for opts <- [[http1_reuse: true], [http_version: :h2c]] do
      controller = HTTP.AbortController.new()
      HTTP.AbortController.abort(controller)

      promise =
        HTTP.fetch(
          "http://127.0.0.1:1/",
          Keyword.merge([redirect: :manual, signal: controller], opts)
        )

      assert {:error, :aborted} = Promise.await(promise)
      assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    end
  end

  test "HTTP2 TLS dialing cancellation confirms cleanup before negotiation" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        {:ok, _hello} = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, :tls_dial_started)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
        :gen_tcp.close(listener)
      end)

    on_exit(fn -> :gen_tcp.close(listener) end)

    promise =
      HTTP.fetch("https://127.0.0.1:#{port}/",
        http_version: :http2,
        redirect: :manual,
        timeout: 2_000,
        ssl: [verify: :verify_none]
      )

    assert_receive :tls_dial_started, 1_000
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(promise), 1_000)
    assert {:error, _} = Promise.await(promise)
    assert :ok = Task.await(peer)
  end

  for version <- [:http1, :http2] do
    test "verified OTP TLS #{version} cleanup preserves its pooled connection for reuse" do
      assert_tls_reuse(unquote(version))
    end
  end

  for mode <- [:disabled_reuse, :non_reusable_key] do
    test "HTTP2 exclusive cleanup retains connection evidence for #{mode}" do
      parent = self()

      {url, peer} =
        Peer.start(parent, fn socket ->
          {id, true} = Peer.request(socket)
          :ok = Peer.response(socket, id, "exclusive")
          await_tcp_close(socket)
          send(parent, :exclusive_socket_closed)
        end)

      opts = exclusive_options(unquote(mode))
      promise = h2_fetch(url, opts)
      assert HTTP.Response.read_all(Promise.await(promise)) == "exclusive"
      assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
      assert_receive :exclusive_socket_closed
      assert_receive {:peer_complete, ^peer}
      send(peer, :close)
    end
  end

  test "HTTP2 failed pool registration settles its provisional owner and TLS socket" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        send(parent, :registration_tcp_accepted)

        receive do
          :negotiate -> :ok
        end

        {:ok, socket} =
          :ssl.handshake(
            tcp,
            [
              certfile: Path.join(@fixtures, "localhost.pem"),
              keyfile: Path.join(@fixtures, "localhost.key"),
              alpn_preferred_protocols: ["h2"]
            ],
            2_000
          )

        assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(socket, 24, 2_000)
        await_tls_close_without_request(socket)
        :gen_tcp.close(listener)
      end)

    promise =
      HTTP.fetch("https://localhost:#{port}/",
        http_version: :http2,
        redirect: :manual,
        timeout: 2_000,
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
      )

    assert_receive :registration_tcp_accepted
    pool = Process.whereis(:http_fetch_http2_pool)
    previous_limit = :sys.get_state(pool).max_connections
    :sys.replace_state(pool, &%{&1 | max_connections: 0})

    try do
      send(peer.pid, :negotiate)
      assert {:error, :connection_capacity} = Promise.await(promise)
      assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
      assert :ok = Task.await(peer)
    after
      :sys.replace_state(pool, &%{&1 | max_connections: previous_limit})
    end
  end

  defp assert_tls_reuse(version) do
    alpn = if version == :http2, do: [alpn_preferred_protocols: ["h2"]], else: []

    {:ok, listener} =
      :ssl.listen(
        0,
        [
          :binary,
          active: false,
          reuseaddr: true,
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key")
        ] ++ alpn
      )

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 2_000)
        {:ok, socket} = :ssl.handshake(tcp, 2_000)

        if version == :http2 do
          assert {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :ssl.recv(socket, 24, 2_000)
          :ok = :ssl.send(socket, Peer.frame(4, 0, 0, ""))
        end

        for _ <- 1..2 do
          if version == :http1 do
            assert {:ok, _head} = :ssl.recv(socket, 0, 2_000)
            :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
          else
            id = tls_request_id(socket)

            :ok =
              :ssl.send(socket, [Peer.frame(1, 4, id, <<0x88>>), Peer.frame(0, 1, id, "ok")])
          end
        end

        receive do
          :close -> :ssl.close(socket)
        end

        :ssl.close(listener)
      end)

    on_exit(fn -> :ssl.close(listener) end)

    opts = [
      http_version: version,
      http1_reuse: version == :http1,
      redirect: :manual,
      timeout: 2_000,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
    ]

    for _ <- 1..2 do
      promise = HTTP.fetch("https://localhost:#{port}/", opts)
      assert HTTP.Response.read_all(Promise.await(promise)) == "ok"
      assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    end

    send(peer.pid, :close)
    assert :ok = Task.await(peer)
  end

  defp h2_fetch(url, opts \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          http_version: :h2c,
          redirect: :manual,
          stream_response: true,
          timeout: 3_000,
          telemetry: false
        ],
        opts
      )
    )
  end

  defp exclusive_options(:disabled_reuse), do: [http2_reuse: false]
  defp exclusive_options(:non_reusable_key), do: [ssl: [verify_fun: fn _, _, _ -> :valid end]]

  defp await_reset(socket, id) do
    case Peer.recv(socket) do
      {3, _, ^id, <<8::32>>} -> :ok
      _ -> await_reset(socket, id)
    end
  end

  defp h2_owner(url) do
    port = URI.parse(url).port

    :http_fetch_http2_pool
    |> :sys.get_state()
    |> Map.fetch!(:entries)
    |> Enum.find_value(fn {key, entry} ->
      if key.port == port, do: entry.connections |> Map.keys() |> List.first()
    end)
  end

  defp pool_stats(url) do
    port = URI.parse(url).port

    HTTP.HTTP2.Pool.stats(Process.whereis(:http_fetch_http2_pool))
    |> Enum.find_value(fn {key, stats} -> if key.port == port, do: stats end)
  end

  defp tls_request_id(socket) do
    {:ok, <<length::24, type, _flags, _::1, id::31>>} = :ssl.recv(socket, 9, 2_000)
    if length > 0, do: assert(match?({:ok, _}, :ssl.recv(socket, length, 2_000)))
    if type == 1, do: id, else: tls_request_id(socket)
  end

  defp await_tcp_close(socket) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, _control_bytes} -> await_tcp_close(socket)
      {:error, :closed} -> :ok
    end
  end

  defp await_tls_close_without_request(socket) do
    case :ssl.recv(socket, 9, 2_000) do
      {:ok, <<length::24, type, _flags, _::1, _id::31>>} ->
        refute type == 1
        if length > 0, do: assert(match?({:ok, _}, :ssl.recv(socket, length, 2_000)))
        await_tls_close_without_request(socket)

      {:error, :closed} ->
        :ok
    end
  end

  defp wait_until(fun, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 1_000

    case fun.() do
      value when value not in [false, nil] ->
        value

      _ ->
        assert System.monotonic_time(:millisecond) < deadline

        receive do
        after
          1 -> wait_until(fun, deadline)
        end
    end
  end
end

defmodule HTTP.PreferIPv6WireTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.{Promise, RequestCompletion}
  @fixtures Path.expand("../support/fixtures", __DIR__)
  @wait 4_000

  for backend <- [:tcp, nil, :ex_ssl] do
    test "#{backend} public preference preserves authority and confirmed request cleanup" do
      backend = unquote(backend)
      parent = self()

      url =
        peer(backend, fn transport, socket ->
          head = read_head(transport, socket)
          send(parent, {:ipv4_request, head})
          :ok = transport.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
          assert {:error, :closed} = transport.recv(socket, 0, @wait)
        end)

      promise = fetch(url, backend)
      assert %HTTP.Response{status: 200} = response = Promise.await(promise, @wait)
      assert HTTP.Response.read_all(response) == "ok"
      assert_receive {:ipv4_request, head}, @wait
      assert head =~ "Host: localhost:#{URI.parse(url).port}\r\n"
      assert :ok = RequestCompletion.await(Promise.completion(promise), @wait)
    end
  end

  for backend <- [:tcp, nil, :ex_ssl], interruption <- [:cancel, :deadline] do
    test "#{backend} #{interruption} closes the connection after IPv4 fallback" do
      backend = unquote(backend)
      parent = self()

      url =
        peer(backend, fn transport, socket ->
          _head = read_head(transport, socket)
          send(parent, {:waiting_response, self()})
          assert {:error, :closed} = transport.recv(socket, 0, @wait)
          send(parent, {:fallback_peer_closed, self()})
        end)

      controller = HTTP.AbortController.new()
      timeout = if unquote(interruption) == :deadline, do: 400, else: @wait
      promise = fetch(url, backend, timeout: timeout, signal: controller)
      assert_receive {:waiting_response, peer}, @wait

      if unquote(interruption) == :cancel, do: HTTP.AbortController.abort(controller)
      expected = if unquote(interruption) == :cancel, do: :aborted, else: :request_timeout
      assert {:error, ^expected} = Promise.await(promise, @wait)
      assert_receive {:fallback_peer_closed, ^peer}, @wait
      assert :ok = RequestCompletion.await(Promise.completion(promise), @wait)
    end
  end

  for backend <- [nil, :ex_ssl] do
    test "#{backend} retains structured TLS rejection evidence after IPv4 fallback" do
      parent = self()

      {:ok, listener} =
        :ssl.listen(0,
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          active: false,
          ip: {127, 0, 0, 1}
        )

      {:ok, {_, port}} = :ssl.sockname(listener)

      server =
        spawn_link(fn ->
          {:ok, socket} = :ssl.transport_accept(listener, @wait)
          assert {:error, _} = :ssl.handshake(socket, @wait)
          send(parent, :rejected_tls_peer)
          :ssl.close(socket)
        end)

      on_exit(fn ->
        if Process.alive?(server), do: Process.exit(server, :kill)
        :ssl.close(listener)
      end)

      promise =
        fetch("https://localhost:#{port}/health", unquote(backend),
          ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")],
          error_mode: :structured
        )

      assert {:error, %HTTP.RequestError{phase: :tls_setup, request_started: false} = error} =
               Promise.await(promise, @wait)

      assert HTTP.RequestError.pre_send?(error)
      assert_receive :rejected_tls_peer, @wait
      assert :ok = RequestCompletion.await(Promise.completion(promise), @wait)
    end
  end

  test "a response on IPv6 never triggers an HTTP replay on IPv4" do
    parent = self()

    {ipv6, ipv4, port} = dual_listeners([])

    server =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(ipv6, @wait)
        _head = read_head(:gen_tcp, socket)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n")
        :gen_tcp.close(socket)
        send(parent, :ipv6_response_sent)
      end)

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :kill)
      :gen_tcp.close(ipv6)
      :gen_tcp.close(ipv4)
    end)

    promise = fetch("http://localhost:#{port}/health", :tcp)
    assert %HTTP.Response{status: 503} = Promise.await(promise, @wait)
    assert_receive :ipv6_response_sent, @wait
    assert :ok = RequestCompletion.await(Promise.completion(promise), @wait)
    assert {:error, :timeout} = :gen_tcp.accept(ipv4, 0)
  end

  test "cancellation during a blocked IPv6 attempt cannot launch IPv4 fallback" do
    {ipv6, ipv4, port} = dual_listeners(backlog: 0)
    {:ok, queued} = :gen_tcp.connect(~c"::1", port, [:binary, :inet6, active: false], @wait)

    :erlang.trace_pattern({:gen_tcp, :connect, 4}, [{[:_, port, :_, :_], [], []}], [])
    :erlang.trace(:all, true, [:call, {:tracer, self()}])

    on_exit(fn ->
      :erlang.trace(:all, false, [:call])
      :erlang.trace_pattern({:gen_tcp, :connect, 4}, false, [])
      :gen_tcp.close(queued)
      :gen_tcp.close(ipv6)
      :gen_tcp.close(ipv4)
    end)

    controller = HTTP.AbortController.new()

    promise =
      fetch("http://localhost:#{port}/health", :tcp, signal: controller, connect_timeout: 500)

    assert_receive {:trace, worker, :call, {:gen_tcp, :connect, [_host, ^port, opts, _timeout]}},
                   @wait

    assert :inet6 in opts
    monitor = Process.monitor(worker)
    HTTP.AbortController.abort(controller)
    assert {:error, :aborted} = Promise.await(promise, @wait)
    assert_receive {:DOWN, ^monitor, :process, ^worker, _}, @wait
    assert :ok = RequestCompletion.await(Promise.completion(promise), @wait)
    delivered = :erlang.trace_delivered(worker)
    assert_receive {:trace_delivered, ^worker, ^delivered}, @wait
    refute_receive {:trace, ^worker, :call, {:gen_tcp, :connect, _}}, 0
    assert {:error, :timeout} = :gen_tcp.accept(ipv4, 0)
  end

  defp dual_listeners(options, attempts \\ 8)

  defp dual_listeners(options, attempts) when attempts > 0 do
    # A v6-only ephemeral port can still be occupied in the IPv4 namespace.
    # Reserve both before traffic, releasing partial allocations on conflict.
    {:ok, ipv4} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(ipv4)

    case :gen_tcp.listen(
           port,
           [:binary, :inet6, active: false, ip: {0, 0, 0, 0, 0, 0, 0, 1}, ipv6_v6only: true] ++
             options
         ) do
      {:ok, ipv6} ->
        on_exit(fn ->
          :gen_tcp.close(ipv6)
          :gen_tcp.close(ipv4)
        end)

        {ipv6, ipv4, port}

      {:error, :eaddrinuse} ->
        :gen_tcp.close(ipv4)
        dual_listeners(options, attempts - 1)

      {:error, reason} ->
        :gen_tcp.close(ipv4)
        flunk("dual loopback listener setup failed: #{inspect(reason)}")
    end
  end

  defp dual_listeners(_options, 0), do: flunk("no shared IPv4/IPv6 loopback port available")

  defp fetch(url, backend, options \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          prefer_ipv6: true,
          tls_backend: if(backend == :tcp, do: nil, else: backend),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          http_version: :http1,
          redirect: :manual,
          telemetry: false,
          timeout: @wait
        ],
        options
      )
    )
  end

  defp peer(backend, handler) do
    transport = if backend == :tcp, do: :gen_tcp, else: :ssl

    opts =
      [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true] ++
        if backend == :tcp do
          []
        else
          [
            certfile: Path.join(@fixtures, "localhost.pem"),
            keyfile: Path.join(@fixtures, "localhost.key")
          ]
        end

    {:ok, listener} = transport.listen(0, opts)

    {:ok, {_, port}} =
      if transport == :gen_tcp, do: :inet.sockname(listener), else: :ssl.sockname(listener)

    server =
      spawn_link(fn ->
        socket =
          if backend == :tcp do
            {:ok, socket} = :gen_tcp.accept(listener, @wait)
            socket
          else
            {:ok, socket} = :ssl.transport_accept(listener, @wait)
            {:ok, socket} = :ssl.handshake(socket, @wait)
            socket
          end

        handler.(transport, socket)
        transport.close(socket)
        transport.close(listener)
      end)

    on_exit(fn ->
      if Process.alive?(server), do: Process.exit(server, :kill)
      transport.close(listener)
    end)

    scheme = if backend == :tcp, do: "http", else: "https"
    "#{scheme}://localhost:#{port}/health"
  end

  defp read_head(transport, socket, data \\ "") do
    case :binary.match(data, "\r\n\r\n") do
      {_index, 4} ->
        data

      :nomatch ->
        {:ok, more} = transport.recv(socket, 0, @wait)
        read_head(transport, socket, data <> more)
    end
  end
end

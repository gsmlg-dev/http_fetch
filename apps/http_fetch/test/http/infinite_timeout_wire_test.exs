defmodule HTTP.InfiniteTimeoutWireTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../../../http_web_socket/test/support/fixtures", __DIR__)
  @wait 2_000

  for backend <- [:tcp, :ssl, :ex_ssl], connect_timeout <- [1_000, :infinity] do
    test "#{backend} infinite request retains a separate #{connect_timeout} connection timeout" do
      {url, peer} = peer(unquote(backend))

      promise =
        HTTP.fetch(
          url,
          options(unquote(backend), timeout: :infinity, connect_timeout: unquote(connect_timeout))
        )

      assert_receive {:headers, ^peer, _head, ""}, @wait
      # The connection budget ends at establishment, not at the first response.
      task_ref = promise.task.ref
      refute_receive {^task_ref, _result}, 1_100
      send(peer, {:send, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"})
      assert %HTTP.Response{status: 200, body: "ok"} = HTTP.Promise.await(promise, @wait)
      send(peer, :closed)
      assert_receive {:closed, ^peer}, @wait
    end
  end

  for backend <- [:tcp, :ssl, :ex_ssl] do
    test "#{backend} infinite request supports acknowledged raw streaming downloads" do
      {url, peer} = peer(unquote(backend))

      promise =
        HTTP.fetch(
          url,
          options(unquote(backend),
            timeout: :infinity,
            decode_body: false,
            stream_response: true
          )
        )

      assert_receive {:headers, ^peer, _, _}, @wait

      send(
        peer,
        {:send, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"}
      )

      assert %HTTP.Response{status: 200, stream: stream} =
               HTTP.Promise.await(promise, @wait)

      send(stream, {:read_chunk, self(), :ack})
      send(peer, {:send, "3\r\n" <> <<0, 255, 128>> <> "\r\n"})
      assert_receive {:stream_chunk, ^stream, <<0, 255, 128>>, ack}, @wait
      send(stream, {:stream_chunk_ack, ack})
      send(peer, {:send, "3\r\n" <> <<254, 1, 0>> <> "\r\n0\r\n\r\n"})
      assert_receive {:stream_chunk, ^stream, <<254, 1, 0>>, ack}, @wait
      send(stream, {:stream_chunk_ack, ack})
      assert_receive {:stream_end, ^stream}, @wait
      send(peer, :closed)
      assert_receive {:closed, ^peer}, @wait
    end

    test "#{backend} infinite request sends a raw streaming upload to completion" do
      {url, peer} = peer(unquote(backend))
      {:ok, source} = HTTP.Stream.start_link(0)

      promise =
        HTTP.fetch(
          url,
          options(unquote(backend),
            method: :post,
            body: source,
            duplex: :half,
            timeout: :infinity,
            connect_timeout: :infinity
          )
        )

      assert_receive {:headers, ^peer, head, rest}, @wait
      assert head =~ "Transfer-Encoding: chunked"
      assert :ok = HTTP.Stream.chunk(source, <<0, 255, 128>>)
      assert :ok = HTTP.Stream.finish(source)
      send(peer, {:upload, rest})
      assert_receive {:uploaded, ^peer, "3\r\n" <> <<0, 255, 128>> <> "\r\n0\r\n\r\n"}, @wait
      assert %HTTP.Response{status: 200, body: "ok"} = HTTP.Promise.await(promise, @wait)
      send(peer, :closed)
      assert_receive {:closed, ^peer}, @wait
    end

    for outcome <- [:abort, :owner_down, :caller_down] do
      test "#{backend} infinite upload #{outcome} releases the source and socket" do
        {url, peer} = peer(unquote(backend))
        {:ok, source} = HTTP.Stream.start_link(0)
        source_monitor = Process.monitor(source)
        controller = HTTP.AbortController.new()

        promise =
          HTTP.fetch(
            url,
            options(unquote(backend),
              method: :post,
              body: source,
              duplex: :half,
              signal: controller,
              timeout: :infinity,
              connect_timeout: :infinity
            )
          )

        assert_receive {:headers, ^peer, _, _}, @wait
        owner = Agent.get(controller, & &1.request_id)
        owner_monitor = Process.monitor(owner)

        case unquote(outcome) do
          :abort ->
            HTTP.AbortController.abort(controller)
            assert {:error, :aborted} = HTTP.Promise.await(promise, @wait)

          :owner_down ->
            Process.exit(owner, :kill)
            assert {:error, {:request_process_down, :killed}} = HTTP.Promise.await(promise, @wait)

          :caller_down ->
            Process.exit(promise.task.pid, :kill)
            Process.demonitor(promise.task.ref, [:flush])
        end

        assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, @wait
        assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _}, @wait
        send(peer, :closed)
        assert_receive {:closed, ^peer}, @wait
      end
    end

    test "#{backend} infinite response reader death releases the owner and socket" do
      {url, peer} = peer(unquote(backend))
      controller = HTTP.AbortController.new()
      promise = HTTP.fetch(url, options(unquote(backend), timeout: :infinity, signal: controller))
      assert_receive {:headers, ^peer, _, _}, @wait
      owner = Agent.get(controller, & &1.request_id)
      owner_monitor = Process.monitor(owner)
      send(peer, {:send, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"})
      assert %HTTP.Response{stream: stream} = HTTP.Promise.await(promise, @wait)
      stream_monitor = Process.monitor(stream)
      parent = self()

      reader =
        spawn(fn ->
          send(stream, {:read_chunk, self(), :ack})

          receive do
            {:stream_chunk, ^stream, "raw", _ack} ->
              send(parent, {:reader_has_chunk, self()})

              receive do
                :stop -> :ok
              end
          end
        end)

      on_exit(fn -> Process.exit(reader, :kill) end)
      send(peer, {:send, "3\r\nraw\r\n"})
      assert_receive {:reader_has_chunk, ^reader}, @wait
      Process.exit(reader, :kill)
      assert_receive {:DOWN, ^stream_monitor, :process, ^stream, _}, @wait
      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _}, @wait
      send(peer, :closed)
      assert_receive {:closed, ^peer}, @wait
    end

    test "#{backend} finite request deadline still caps an infinite connection timeout" do
      {url, peer} = peer(unquote(backend))

      promise =
        HTTP.fetch(url, options(unquote(backend), timeout: 300, connect_timeout: :infinity))

      assert_receive {:headers, ^peer, _, _}, @wait
      assert {:error, :request_timeout} = HTTP.Promise.await(promise, @wait)
      send(peer, :closed)
      assert_receive {:closed, ^peer}, @wait
    end

    test "#{backend} infinite response stream can still be aborted" do
      {url, peer} = peer(unquote(backend))
      controller = HTTP.AbortController.new()

      promise =
        HTTP.fetch(
          url,
          options(unquote(backend), timeout: :infinity, signal: controller)
        )

      assert_receive {:headers, ^peer, _, _}, @wait
      owner = Agent.get(controller, & &1.request_id)
      monitor = Process.monitor(owner)
      send(peer, {:send, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"})
      assert %HTTP.Response{stream: stream} = HTTP.Promise.await(promise, @wait)
      send(stream, {:read_chunk, self(), :ack})
      HTTP.AbortController.abort(controller)
      assert_receive {:stream_error, ^stream, :aborted}, @wait
      assert_receive {:DOWN, ^monitor, :process, ^owner, _}, @wait
      send(peer, :closed)
      assert_receive {:closed, ^peer}, @wait
    end
  end

  for backend <- [:ssl, :ex_ssl],
      {timeout, connect_timeout, result} <- [
        {:infinity, 100, :connect_timeout},
        {100, :infinity, :request_timeout},
        {:infinity, :infinity, :aborted}
      ] do
    test "#{backend} stalled handshake honors #{timeout} request and #{connect_timeout} connect timeout" do
      parent = self()
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, port} = :inet.port(listener)

      peer =
        spawn_link(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, @wait)
          {:ok, <<22, _::binary>>} = :gen_tcp.recv(socket, 0, @wait)
          send(parent, {:client_hello, self()})
          assert {:error, :closed} = :gen_tcp.recv(socket, 0, @wait)
          send(parent, {:closed, self()})
        end)

      on_exit(fn ->
        Process.exit(peer, :kill)
        :gen_tcp.close(listener)
      end)

      controller = HTTP.AbortController.new()

      promise =
        HTTP.fetch(
          "https://localhost:#{port}/",
          options(unquote(backend),
            timeout: unquote(timeout),
            connect_timeout: unquote(connect_timeout),
            signal: controller
          )
        )

      assert_receive {:client_hello, ^peer}, @wait
      if unquote(result) == :aborted, do: HTTP.AbortController.abort(controller)
      assert {:error, reason} = HTTP.Promise.await(promise, @wait)
      # The request timer and the dialer's capped timer can expire together.
      expected =
        case {unquote(timeout), unquote(result)} do
          {_, :aborted} -> [:aborted]
          {:infinity, _} -> [:timeout, :connect_timeout]
          _ -> [:timeout, :request_timeout, :connect_timeout]
        end

      assert reason in expected
      assert_receive {:closed, ^peer}, @wait
    end
  end

  test "infinite request preserves an immediate connection refusal" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)
    :gen_tcp.close(listener)

    assert {:error, :econnrefused} =
             HTTP.fetch("http://127.0.0.1:#{port}/", timeout: :infinity)
             |> HTTP.Promise.await(@wait)
  end

  for backend <- [:ssl, :ex_ssl] do
    test "#{backend} automatic TLS selection supports infinite HTTP1 fallback" do
      {url, peer} = peer(unquote(backend))
      opts = Keyword.put(options(unquote(backend), timeout: :infinity), :http_version, :auto)
      promise = HTTP.fetch(url, opts)
      assert_receive {:headers, ^peer, _, _}, @wait
      send(peer, {:send, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"})
      assert %HTTP.Response{http_version: :http1, body: "ok"} = HTTP.Promise.await(promise, @wait)
      send(peer, :closed)
      assert_receive {:closed, ^peer}, @wait
    end
  end

  defp options(backend, opts) do
    base = [http_version: :http1, redirect: :manual]

    if backend == :tcp,
      do: base ++ opts,
      else:
        base ++
          [tls_backend: backend, ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]] ++
          opts
  end

  defp peer(backend) do
    transport = if backend == :tcp, do: :gen_tcp, else: :ssl
    opts = [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}]

    opts =
      if transport == :ssl,
        do:
          opts ++
            [
              certfile: Path.join(@fixtures, "localhost.pem"),
              keyfile: Path.join(@fixtures, "localhost.key")
            ],
        else: opts

    {:ok, listener} = apply(transport, :listen, [0, opts])
    {:ok, {_, port}} = apply(if(transport == :ssl, do: :ssl, else: :inet), :sockname, [listener])
    parent = self()

    peer =
      spawn_link(fn ->
        socket =
          if transport == :ssl do
            {:ok, tcp} = :ssl.transport_accept(listener, @wait)
            {:ok, tls} = :ssl.handshake(tcp, @wait)
            tls
          else
            {:ok, tcp} = :gen_tcp.accept(listener, @wait)
            tcp
          end

        bytes = recv_until(transport, socket, "", "\r\n\r\n")
        [head, rest] = :binary.split(bytes, "\r\n\r\n")
        send(parent, {:headers, self(), head, rest})
        serve(transport, socket, parent)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      apply(transport, :close, [listener])
    end)

    {"#{if backend == :tcp, do: "http", else: "https"}://localhost:#{port}/", peer}
  end

  defp serve(transport, socket, parent) do
    receive do
      {:send, bytes} ->
        :ok = apply(transport, :send, [socket, bytes])
        serve(transport, socket, parent)

      {:upload, rest} ->
        bytes = recv_until(transport, socket, rest, "0\r\n\r\n")
        send(parent, {:uploaded, self(), bytes})
        :ok = apply(transport, :send, [socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"])
        serve(transport, socket, parent)

      :closed ->
        assert {:error, :closed} = apply(transport, :recv, [socket, 0, @wait])
        send(parent, {:closed, self()})
    after
      @wait -> flunk("peer never received its next test gate")
    end
  end

  defp recv_until(transport, socket, bytes, marker) do
    if :binary.match(bytes, marker) == :nomatch do
      {:ok, more} = apply(transport, :recv, [socket, 0, @wait])
      recv_until(transport, socket, bytes <> more, marker)
    else
      bytes
    end
  end
end

defmodule HTTP.HTTP1WriteIdleWireTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @wait 8_000
  @chunk :binary.copy(<<0, 255, 128, 1>>, 4_096)

  for backend <- [:tcp, :ssl, :ex_ssl] do
    test "#{backend} a nonreading peer expires streamed writes and closes the source" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      {:ok, source} = HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> @chunk end))
      monitor = Process.monitor(source)
      promise = fetch(url, backend, body: source, duplex: "half", write_idle_timeout: 300)
      assert_request(peer)
      assert {:error, :write_idle_timeout} = Promise.await(promise, @wait)
      assert_receive {:DOWN, ^monitor, :process, ^source, :normal}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} buffered bodies use the same bounded write deadline" do
      backend = unquote(backend)
      {peer, url} = peer(backend)

      promise =
        fetch(url, backend, body: :binary.copy(@chunk, 512), write_idle_timeout: 300)

      assert_request(peer)
      assert {:error, :write_idle_timeout} = Promise.await(promise, @wait)
      finish(peer, promise, backend)
    end

    test "#{backend} a shorter configured native send timeout retains its original reason" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      {:ok, source} = HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> @chunk end))
      monitor = Process.monitor(source)

      promise =
        fetch(url, backend,
          body: source,
          duplex: "half",
          write_idle_timeout: 1_000,
          socket_opts: [sndbuf: 4_096, send_timeout: 200]
        )

      assert_request(peer)
      assert {:error, :timeout} = Promise.await(promise, @wait)
      assert_receive {:DOWN, ^monitor, :process, ^source, :normal}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} waiting for the next source chunk does not consume write idle time" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      {:ok, source} = HTTP.Stream.start_link(6)
      monitor = Process.monitor(source)

      promise =
        fetch(url, backend,
          body: source,
          duplex: "half",
          headers: [{"content-length", "6"}],
          write_idle_timeout: 100
        )

      assert_request(peer)
      assert :ok = HTTP.Stream.chunk(source, <<0, 255, 128>>)
      send(peer.pid, {:read_exact, 3})
      assert_receive {:body, <<0, 255, 128>>}, @wait
      tick(300)
      assert Process.alive?(source)
      assert :ok = HTTP.Stream.chunk(source, <<254, 1, 0>>)
      assert :ok = HTTP.Stream.finish(source)
      send(peer.pid, {:read_exact, 3})
      assert_receive {:body, <<254, 1, 0>>}, @wait
      send(peer.pid, :respond)
      assert %Response{body: "ok"} = Promise.await(promise, @wait)
      assert_receive {:DOWN, ^monitor, :process, ^source, :normal}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} response header progress does not extend a blocked write deadline" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      {:ok, source} = HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> @chunk end))
      monitor = Process.monitor(source)
      promise = fetch(url, backend, body: source, duplex: "half", write_idle_timeout: 600)
      assert_request(peer)
      await_blocked_writer(source)
      send_bytes(peer, "HTTP/1.1 200 OK\r\nX-Progress: ")

      for _ <- 1..3 do
        tick(100)
        send_bytes(peer, "x")
      end

      assert {:error, :write_idle_timeout} = Promise.await(promise, @wait)
      assert_receive {:DOWN, ^monitor, :process, ^source, :normal}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} peer closure during a source wait preserves the native error" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      {:ok, source} = HTTP.Stream.start_link(0)
      monitor = Process.monitor(source)
      promise = fetch(url, backend, body: source, duplex: "half", write_idle_timeout: 2_000)
      assert_request(peer)
      send(peer.pid, :close)
      assert {:error, :closed} = Promise.await(promise, @wait)
      assert_receive {:DOWN, ^monitor, :process, ^source, :normal}, @wait
      assert :ok = Task.await(peer, @wait)
      assert_completion(promise, backend)
    end

    test "#{backend} cancellation interrupts an observed in-flight blocked upload" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      {:ok, source} = HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> @chunk end))
      source_monitor = Process.monitor(source)
      controller = HTTP.AbortController.new()

      promise =
        fetch(url, backend,
          body: source,
          duplex: "half",
          write_idle_timeout: 4_000,
          signal: controller
        )

      assert_request(peer)
      writer = await_blocked_writer(source)
      writer_monitor = Process.monitor(writer)
      HTTP.AbortController.abort(controller)
      assert {:error, :aborted} = Promise.await(promise, @wait)
      assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, @wait
      assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} the overall deadline interrupts an observed in-flight blocked upload" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      {:ok, source} = HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> @chunk end))
      source_monitor = Process.monitor(source)

      promise =
        fetch(url, backend,
          body: source,
          duplex: "half",
          write_idle_timeout: 4_000,
          timeout: 1_500
        )

      assert_request(peer)
      writer = await_blocked_writer(source)
      writer_monitor = Process.monitor(writer)
      assert {:error, :request_timeout} = Promise.await(promise, @wait)
      assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, @wait
      assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} ordinary reuse refreshes a previous request's short send limit" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      scope = "idle-reuse-#{System.unique_integer([:positive])}"

      first =
        fetch(url, backend,
          body: "",
          http1_reuse: true,
          http1_scope: scope,
          read_idle_timeout: 100,
          write_idle_timeout: 80
        )

      assert_request(peer)
      send(peer.pid, :keepalive)
      assert %Response{body: "ok"} = Promise.await(first, @wait)
      assert_completion(first, backend)
      send(peer.pid, :next_request)
      {:ok, source} = HTTP.Stream.from_enumerable(List.duplicate(@chunk, 64))

      second =
        fetch(url, backend,
          body: source,
          duplex: "half",
          headers: [{"content-length", Integer.to_string(byte_size(@chunk) * 64)}],
          http1_reuse: true,
          http1_scope: scope
        )

      assert_request(peer)
      await_blocked_writer(source)
      # The same peer socket is paused longer than the previous send/read limits.
      # Restoring the next request's policy must allow its bounded upload to finish.
      tick(350)
      send(peer.pid, {:read_exact, byte_size(@chunk) * 64})
      assert_receive {:body, body}, @wait
      assert body == :binary.copy(@chunk, 64)
      send(peer.pid, :respond)
      assert %Response{body: "ok"} = Promise.await(second, @wait)
      finish(peer, second, backend)
    end
  end

  defp fetch(url, backend, options) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          http_version: :http1,
          redirect: :manual,
          method: :post,
          tls_backend: if(backend == :ex_ssl, do: :ex_ssl, else: :ssl),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          socket_opts: [sndbuf: 4_096],
          decode_body: false,
          timeout: @wait,
          telemetry: false
        ],
        options
      )
    )
  end

  defp peer(backend) do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        reuseaddr: true,
        recbuf: 65_536,
        ip: {127, 0, 0, 1}
      ])

    {:ok, {_, port}} = :inet.sockname(listener)
    test = self()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, @wait)
        {transport, socket} = handshake(backend, tcp)
        request(transport, socket, test)
      end)

    on_exit(fn ->
      if Process.alive?(task.pid), do: Process.exit(task.pid, :kill)
      :gen_tcp.close(listener)
    end)

    scheme = if backend == :tcp, do: "http", else: "https"
    {task, "#{scheme}://localhost:#{port}/write-idle"}
  end

  defp handshake(:tcp, socket), do: {:gen_tcp, socket}

  defp handshake(_backend, socket) do
    {:ok, tls} =
      :ssl.handshake(
        socket,
        [
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          versions: [:"tlsv1.3"],
          active: false
        ],
        @wait
      )

    {:ssl, tls}
  end

  defp request(transport, socket, test) do
    assert recv_headers(transport, socket, "") =~ "POST /write-idle HTTP/1.1\r\n"
    send(test, {:request_received, self()})
    serve(transport, socket, test)
  end

  defp recv_headers(transport, socket, bytes) do
    if String.ends_with?(bytes, "\r\n\r\n") do
      bytes
    else
      assert {:ok, more} = transport.recv(socket, 1, @wait)
      recv_headers(transport, socket, bytes <> more)
    end
  end

  defp serve(transport, socket, test) do
    receive do
      {:read_exact, size} ->
        assert {:ok, bytes} = transport.recv(socket, size, @wait)
        send(test, {:body, bytes})
        serve(transport, socket, test)

      :respond ->
        :ok =
          transport.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
          )

        serve(transport, socket, test)

      :keepalive ->
        :ok = transport.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        serve(transport, socket, test)

      :next_request ->
        request(transport, socket, test)

      {:send, ref, bytes} ->
        :ok = transport.send(socket, bytes)
        send(test, {:sent, ref})
        serve(transport, socket, test)

      :close ->
        transport.close(socket)
        :ok

      :await_close ->
        drain_closed(transport, socket)
        transport.close(socket)
        send(test, {:peer_closed, self()})
        :ok
    after
      @wait -> flunk("write-idle peer was not released")
    end
  end

  defp drain_closed(transport, socket) do
    case transport.recv(socket, 0, @wait) do
      {:ok, _bytes} -> drain_closed(transport, socket)
      {:error, reason} -> assert reason in [:closed, :econnreset]
    end
  end

  defp assert_request(%Task{pid: peer}) do
    assert_receive {:request_received, ^peer}, @wait
  end

  defp await_blocked_writer(source) do
    await_blocked_writer(source, System.monotonic_time(:millisecond) + 1_000)
  end

  defp await_blocked_writer(source, deadline) do
    monitors = Process.info(source, :monitors)

    writer =
      case monitors do
        {:monitors, monitors} ->
          Enum.find_value(monitors, &blocked_writer/1)

        _ ->
          nil
      end

    cond do
      writer ->
        writer

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("no in-flight bounded send observed")

      true ->
        tick(5)
        await_blocked_writer(source, deadline)
    end
  end

  defp blocked_writer({:process, pid}) when is_pid(pid) do
    case Process.info(pid, [:status, :current_stacktrace]) do
      info when is_list(info) ->
        if info[:status] == :waiting and Enum.any?(info[:current_stacktrace], &write_frame?/1),
          do: pid

      _ ->
        nil
    end
  end

  defp blocked_writer(_monitor), do: nil

  defp write_frame?({module, function, _, _}),
    do:
      module == HTTP.HTTP1.IdleTimeout or
        (module == HTTP.HTTP1.Upload and function == :write_chunk)

  defp tick(milliseconds) do
    ref = make_ref()
    Process.send_after(self(), {:stimulus, ref}, milliseconds)
    assert_receive {:stimulus, ^ref}, @wait
  end

  defp send_bytes(peer, bytes) do
    ref = make_ref()
    send(peer.pid, {:send, ref, bytes})
    assert_receive {:sent, ^ref}, @wait
  end

  defp finish(%Task{pid: peer} = task, promise, backend) do
    send(peer, :await_close)
    assert_receive {:peer_closed, ^peer}, @wait
    assert :ok = Task.await(task, @wait)
    assert_completion(promise, backend)
  end

  defp assert_completion(promise, backend) do
    expected =
      if backend == :ex_ssl, do: {:error, {:unsupported_completion, :tls_backend}}, else: :ok

    assert RequestCompletion.await(Promise.completion(promise), @wait) == expected
  end
end

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
      # The original 1 MiB body can fit OTP TLS/native buffers without blocking.
      # Keep the workload finite while proving that the peer pause stalls a send.
      pressure_chunks = 256
      produced = :atomics.new(1, [])

      chunks =
        Stream.map(1..pressure_chunks, fn _ ->
          :atomics.add_get(produced, 1, 1)
          @chunk
        end)

      {:ok, source} = HTTP.Stream.from_enumerable(chunks)
      source_monitor = Process.monitor(source)

      second =
        fetch(url, backend,
          body: source,
          duplex: "half",
          headers: [{"content-length", Integer.to_string(byte_size(@chunk) * pressure_chunks)}],
          http1_reuse: true,
          http1_scope: scope
        )

      assert_request(peer)

      {blocked, stalled_since} = await_stalled_reuse_writer(source, produced)

      # Observe sustained upload write wait beyond 80 ms, then keep the peer
      # paused for 350 ms total, beyond both previous send/read limits.
      elapsed = System.monotonic_time(:millisecond) - stalled_since
      tick(max(350 - elapsed, 0))

      assert Process.alive?(source)
      assert Process.alive?(blocked)
      assert {:monitors, monitors} = Process.info(source, :monitors)
      assert {:process, blocked} in monitors
      assert :atomics.get(produced, 1) < pressure_chunks

      send(peer.pid, {:read_exact, byte_size(@chunk) * pressure_chunks})
      assert_receive {:body, body}, @wait
      assert body == :binary.copy(@chunk, pressure_chunks)
      send(peer.pid, :respond)
      assert %Response{body: "ok"} = Promise.await(second, @wait)
      assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, @wait
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

  defp await_stalled_reuse_writer(source, produced) do
    deadline = System.monotonic_time(:millisecond) + 1_000
    await_stalled_reuse_writer(source, produced, deadline, nil)
  end

  defp await_stalled_reuse_writer(source, produced, deadline, candidate) do
    if System.monotonic_time(:millisecond) >= deadline,
      do: flunk("no sustained in-flight send observed")

    writer = await_blocked_writer(source, deadline)
    count = :atomics.get(produced, 1)
    now = System.monotonic_time(:millisecond)

    since =
      case candidate do
        {^writer, ^count, since} -> since
        _ -> now
      end

    if now - since >= 90 do
      {writer, since}
    else
      tick(5)
      await_stalled_reuse_writer(source, produced, deadline, {writer, count, since})
    end
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

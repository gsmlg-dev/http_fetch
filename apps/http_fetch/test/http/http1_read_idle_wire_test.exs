defmodule HTTP.HTTP1ReadIdleWireTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @wait 4_000
  @idle 600
  @head "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n"

  for backend <- [:tcp, :ssl, :ex_ssl] do
    test "#{backend} fragmented headers and raw body progress outlast the read idle budget" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      promise = fetch(url, backend, stream_response: true)
      assert_request(peer)
      started = System.monotonic_time(:millisecond)

      for bytes <- [
            "HTTP/1.",
            "1 200 OK\r\n",
            "Content-Length: 6\r\n",
            "Content-Encoding: gzip\r\nConnection: close\r\n",
            "\r\n"
          ] do
        tick(200)
        send_bytes(peer, bytes)
      end

      assert %Response{status: 200, stream: stream} = Promise.await(promise, @wait)
      assert System.monotonic_time(:millisecond) - started > @idle

      for bytes <- [<<0, 255, 128>>, <<254, 1, 0>>] do
        send(stream, {:read_chunk, self(), :ack})
        tick(200)
        send_bytes(peer, bytes)
        assert_receive {:stream_chunk, ^stream, ^bytes, ack}, @wait
        send(stream, {:stream_chunk_ack, ack})
      end

      assert_receive {:stream_end, ^stream}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} a partial response header stalls with the typed read idle error" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      promise = fetch(url, backend)
      assert_request(peer)
      send_bytes(peer, "HTTP/1.1 200 OK\r\nContent-Length:")
      assert {:error, :read_idle_timeout} = Promise.await(promise, @wait)
      finish(peer, promise, backend)
    end

    test "#{backend} a body stall fails the stream after an acknowledged raw chunk" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      promise = fetch(url, backend, stream_response: true)
      assert_request(peer)
      send_bytes(peer, @head)
      assert %Response{stream: stream} = Promise.await(promise, @wait)
      send(stream, {:read_chunk, self(), :ack})
      send_bytes(peer, <<0, 255, 128>>)
      assert_receive {:stream_chunk, ^stream, <<0, 255, 128>>, ack}, @wait
      send(stream, {:stream_chunk_ack, ack})
      send(stream, {:read_chunk, self(), :ack})
      assert_receive {:stream_error, ^stream, :read_idle_timeout}, @wait
      refute_receive {:stream_end, ^stream}, 0
      finish(peer, promise, backend)
    end

    test "#{backend} consumer acknowledgement backpressure does not consume read idle time" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      promise = fetch(url, backend, stream_response: true)
      assert_request(peer)
      send_bytes(peer, @head)
      assert %Response{stream: stream} = Promise.await(promise, @wait)
      send(stream, {:read_chunk, self(), :ack})
      send_bytes(peer, <<0, 255, 128>>)
      assert_receive {:stream_chunk, ^stream, <<0, 255, 128>>, first_ack}, @wait

      refute_receive {:stream_error, ^stream, _}, @idle + 300
      send(stream, {:stream_chunk_ack, first_ack})
      send(stream, {:read_chunk, self(), :ack})
      send_bytes(peer, <<254, 1, 0>>)
      assert_receive {:stream_chunk, ^stream, <<254, 1, 0>>, last_ack}, @wait
      send(stream, {:stream_chunk_ack, last_ack})
      assert_receive {:stream_end, ^stream}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} peer-observed upload progress does not reset a pending response read" do
      backend = unquote(backend)
      {peer, url} = peer(backend, true)
      {:ok, source} = HTTP.Stream.start_link(0)
      source_monitor = Process.monitor(source)

      promise =
        fetch(url, backend,
          method: :post,
          body: source,
          duplex: :half,
          read_idle_timeout: 1_200
        )

      assert_request(peer)
      peer_pid = peer.pid

      for _ <- 1..3 do
        tick(300)
        assert :ok = HTTP.Stream.chunk(source, "abc")
        assert_receive {:upload_progress, ^peer_pid, "abc"}, @wait
      end

      # A wrongly shared/reset clock would allow another full 1,200 ms here.
      assert {:error, :read_idle_timeout} = Promise.await(promise, 700)
      assert_receive {:DOWN, ^source_monitor, :process, ^source, _}, @wait
      finish(peer, promise, backend)
    end

    test "#{backend} cancellation ends a pending read without becoming an idle timeout" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      controller = HTTP.AbortController.new()
      promise = fetch(url, backend, signal: controller, read_idle_timeout: 2_000)
      assert_request(peer)
      HTTP.AbortController.abort(controller)
      assert {:error, :aborted} = Promise.await(promise, @wait)
      finish(peer, promise, backend)
    end

    test "#{backend} the shorter overall deadline remains independent of read idle" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      promise = fetch(url, backend, timeout: 400, read_idle_timeout: 2_000)
      assert_request(peer)
      assert {:error, :request_timeout} = Promise.await(promise, @wait)
      finish(peer, promise, backend)
    end

    test "#{backend} the connection budget stops applying after establishment" do
      backend = unquote(backend)
      {peer, url} = peer(backend)
      promise = fetch(url, backend, connect_timeout: 750, read_idle_timeout: 2_000)
      assert_request(peer)
      tick(1_000)
      send_bytes(peer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
      assert %Response{body: "ok"} = Promise.await(promise, @wait)
      finish(peer, promise, backend)
    end
  end

  defp fetch(url, backend, options) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          http_version: :http1,
          redirect: :manual,
          tls_backend: if(backend == :ex_ssl, do: :ex_ssl, else: :ssl),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          decode_body: false,
          read_idle_timeout: @idle,
          timeout: @wait,
          telemetry: false
        ],
        options
      )
    )
  end

  defp fetch(url, backend), do: fetch(url, backend, [])

  defp peer(backend, upload? \\ false) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    test = self()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, @wait)
        {transport, socket} = handshake(backend, tcp)
        method = if upload?, do: "POST", else: "GET"
        assert recv_headers(transport, socket, "") =~ method <> " /read-idle HTTP/1.1\r\n"
        send(test, {:request_received, self()})

        if upload?,
          do: drain_upload(transport, socket, test, ""),
          else: serve(transport, socket, test)
      end)

    on_exit(fn ->
      if Process.alive?(task.pid), do: Process.exit(task.pid, :kill)
      :gen_tcp.close(listener)
    end)

    scheme = if backend == :tcp, do: "http", else: "https"
    {task, "#{scheme}://localhost:#{port}/read-idle"}
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
      {:send, ref, bytes} ->
        :ok = transport.send(socket, bytes)
        send(test, {:sent, ref})
        serve(transport, socket, test)

      :await_close ->
        assert {:error, reason} = transport.recv(socket, 0, @wait)
        assert reason in [:closed, :econnreset]
        transport.close(socket)
        send(test, {:peer_closed, self()})
        :ok
    after
      @wait -> flunk("read-idle peer was not released")
    end
  end

  defp drain_upload(transport, socket, test, bytes) do
    case bytes do
      <<"3\r\n", body::binary-size(3), "\r\n", rest::binary>> ->
        send(test, {:upload_progress, self(), body})
        drain_upload(transport, socket, test, rest)

      _ ->
        case transport.recv(socket, 0, @wait) do
          {:ok, more} ->
            drain_upload(transport, socket, test, bytes <> more)

          {:error, reason} ->
            assert reason in [:closed, :econnreset]
            assert bytes == ""
            transport.close(socket)
            send(test, {:peer_closed, self()})
            :ok
        end
    end
  end

  defp assert_request(%Task{pid: peer}) do
    assert_receive {:request_received, ^peer}, @wait
  end

  defp send_bytes(%Task{pid: peer}, bytes) do
    ref = make_ref()
    send(peer, {:send, ref, bytes})
    assert_receive {:sent, ^ref}, @wait
  end

  defp tick(milliseconds) do
    ref = make_ref()
    Process.send_after(self(), {:stimulus, ref}, milliseconds)
    assert_receive {:stimulus, ^ref}, @wait
  end

  defp finish(%Task{pid: peer} = task, promise, backend) do
    send(peer, :await_close)
    assert_receive {:peer_closed, ^peer}, @wait
    assert :ok = Task.await(task, @wait)

    expected =
      if backend == :ex_ssl, do: {:error, {:unsupported_completion, :tls_backend}}, else: :ok

    assert RequestCompletion.await(Promise.completion(promise), @wait) == expected
  end
end

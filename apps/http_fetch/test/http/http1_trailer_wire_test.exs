defmodule HTTP.HTTP1TrailerWireTest do
  use ExUnit.Case, async: true

  test "public response trailers preserve order after acknowledged body delivery" do
    {url, _peer} =
      peer(fn socket ->
        recv_headers(socket)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n4\r\ndata\r\n0\r\nX-Checksum: first\r\nX-Checksum: second\r\n\r\n"
          )

        :gen_tcp.recv(socket, 0, 2_000)
      end)

    response = HTTP.fetch(url, http_version: :http1, redirect: :manual) |> HTTP.Promise.await()
    assert response.trailers.headers == []
    stream = response.stream
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "data", ref}, 1_000
    refute_receive {:stream_trailers, ^stream, _}, 0
    refute_receive {:stream_end, ^stream}, 0
    send(stream, {:stream_chunk_ack, ref})
    assert_receive {:stream_trailers, ^stream, headers}, 1_000
    assert headers.headers == [{"X-Checksum", "first"}, {"X-Checksum", "second"}]
    assert_receive {:stream_end, ^stream}, 1_000
  end

  test "public chunked upload completion serializes declared duplicate trailers" do
    test_pid = self()

    {url, _peer} =
      peer(fn socket ->
        {headers, rest} = recv_headers(socket)
        body = recv_until(socket, rest, "0\r\nX-Checksum: first\r\nx-checksum: second\r\n\r\n")
        send(test_pid, {:uploaded_trailers, headers, body})
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
      end)

    {:ok, stream} = HTTP.Stream.start_link(0)

    promise =
      HTTP.fetch(url,
        method: :post,
        body: stream,
        duplex: :half,
        headers: [{"Trailer", "X-Checksum"}]
      )

    assert :ok = HTTP.Stream.chunk(stream, "data")
    assert :ok = HTTP.Stream.finish(stream, [{"X-Checksum", "first"}, {"x-checksum", "second"}])
    assert %HTTP.Response{status: 200} = HTTP.Promise.await(promise)
    assert_receive {:uploaded_trailers, headers, body}, 1_000
    assert headers =~ "Trailer: X-Checksum\r\n"
    assert headers =~ "Transfer-Encoding: chunked\r\n"
    assert body == "4\r\ndata\r\n0\r\nX-Checksum: first\r\nx-checksum: second\r\n\r\n"
  end

  test "undeclared upload trailers fail without sending a terminal chunk" do
    test_pid = self()

    {url, _peer} =
      peer(fn socket ->
        {_headers, rest} = recv_headers(socket)
        send(test_pid, {:undeclared_upload_bytes, recv_closed(socket, rest)})
      end)

    {:ok, stream} = HTTP.Stream.start_link(0)
    promise = HTTP.fetch(url, method: :post, body: stream, duplex: :half)
    assert :ok = HTTP.Stream.chunk(stream, "data")
    assert :ok = HTTP.Stream.finish(stream, [{"X-Checksum", "one"}])
    assert {:error, :undeclared_trailer} = HTTP.Promise.await(promise)
    assert_receive {:undeclared_upload_bytes, "4\r\ndata\r\n"}, 1_000
  end

  test "fixed-length upload trailers fail without extra framing bytes" do
    test_pid = self()

    {url, _peer} =
      peer(fn socket ->
        {_headers, rest} = recv_headers(socket)
        send(test_pid, {:fixed_upload_bytes, recv_closed(socket, rest)})
      end)

    {:ok, stream} = HTTP.Stream.start_link(4)

    promise =
      HTTP.fetch(url,
        method: :post,
        body: stream,
        duplex: :half,
        headers: [{"Content-Length", "4"}]
      )

    assert :ok = HTTP.Stream.chunk(stream, "data")
    assert :ok = HTTP.Stream.finish(stream, [{"X-Checksum", "one"}])
    assert {:error, :request_trailers_require_chunked} = HTTP.Promise.await(promise)
    assert_receive {:fixed_upload_bytes, "data"}, 1_000
  end

  test "cancellation before upload completion omits trailers and releases the source" do
    test_pid = self()

    {url, _peer} =
      peer(fn socket ->
        {_headers, rest} = recv_headers(socket)
        send(test_pid, {:cancelled_upload_bytes, recv_closed(socket, rest)})
      end)

    {:ok, stream} = HTTP.Stream.start_link(0)
    monitor = Process.monitor(stream)
    {:ok, controller} = HTTP.AbortController.start_link()

    promise =
      HTTP.fetch(url,
        method: :post,
        body: stream,
        duplex: :half,
        signal: controller,
        headers: [{"Trailer", "X-Checksum"}]
      )

    assert :ok = HTTP.Stream.chunk(stream, "data")
    :ok = HTTP.AbortController.abort(controller)
    assert {:error, :aborted} = HTTP.Promise.await(promise)
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
    assert :ok = HTTP.Stream.finish(stream, [{"X-Checksum", "late"}])
    assert_receive {:cancelled_upload_bytes, "4\r\ndata\r\n"}, 1_000
  end

  test "cancellation of the last response body ACK never exposes trailers or stream end" do
    {url, _peer} =
      peer(fn socket ->
        recv_headers(socket)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\nX-Checksum: hidden\r\n\r\n"
          )

        :gen_tcp.recv(socket, 0, 2_000)
      end)

    {:ok, controller} = HTTP.AbortController.start_link()
    response = HTTP.fetch(url, signal: controller) |> HTTP.Promise.await()
    stream = response.stream
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "data", _ref}, 1_000
    :ok = HTTP.AbortController.abort(controller)
    assert_receive {:stream_error, ^stream, :aborted}, 1_000
    refute_receive {:stream_trailers, ^stream, _}, 0
    refute_receive {:stream_end, ^stream}, 0
  end

  for {fields, expected} <- [
        {"Content-Length: 0\r\n", {:forbidden_trailer, "content-length"}},
        {"Malformed\r\n", :invalid_trailer},
        {String.duplicate("X: one\r\n", 129), :trailers_too_large},
        {"X: " <> String.duplicate("a", 65_530) <> "\r\n", :trailers_too_large}
      ] do
    test "public fragmented response rejects invalid trailer #{inspect(expected)} #{byte_size(fields)}" do
      {url, peer} =
        peer(fn socket ->
          recv_headers(socket)
          :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")

          receive do
            :send_trailers ->
              :ok = :gen_tcp.send(socket, "0\r\n" <> unquote(fields) <> "\r\n")
          end

          :gen_tcp.recv(socket, 0, 2_000)
        end)

      response = HTTP.fetch(url) |> HTTP.Promise.await()
      stream = response.stream
      send(stream, {:read_chunk, self(), :ack})
      send(peer, :send_trailers)
      assert_receive {:stream_error, ^stream, unquote(expected)}, 1_000
      refute_receive {:stream_trailers, ^stream, _}, 0
      refute_receive {:stream_end, ^stream}, 0
    end
  end

  defp peer(handler) do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        packet: :raw,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listener)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        handler.(socket)
        :gen_tcp.close(socket)
        :gen_tcp.close(listener)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listener)
    end)

    {"http://127.0.0.1:#{port}/trailers", pid}
  end

  defp recv_headers(socket) do
    data = recv_until(socket, "", "\r\n\r\n")
    [headers, rest] = :binary.split(data, "\r\n\r\n")
    {headers <> "\r\n", rest}
  end

  defp recv_until(socket, data, marker) do
    if :binary.match(data, marker) != :nomatch do
      data
    else
      {:ok, more} = :gen_tcp.recv(socket, 0, 2_000)
      recv_until(socket, data <> more, marker)
    end
  end

  defp recv_closed(socket, data) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, more} -> recv_closed(socket, data <> more)
      {:error, reason} when reason in [:closed, :econnreset] -> data
    end
  end
end

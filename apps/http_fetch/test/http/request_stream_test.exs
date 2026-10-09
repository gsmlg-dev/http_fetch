defmodule HTTP.RequestStreamTest do
  use ExUnit.Case, async: true

  for chunks <- [["abc", "", "def"], []] do
    test "uploads exactly the declared HTTP/1 length for #{inspect(chunks)}" do
      chunks = unquote(chunks)
      bytes = Enum.join(chunks)
      test_pid = self()

      url =
        start_raw_http_server!(fn listener ->
          {:ok, socket} = :gen_tcp.accept(listener)
          request = recv_request(socket)
          send(test_pid, {:fixed_request, request})
          :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
          assert {:error, :closed} = :gen_tcp.recv(socket, 0, 5_000)
          send(test_pid, :no_extra_upload_bytes)
        end)

      {:ok, stream} = HTTP.Stream.from_enumerable(chunks)

      response =
        HTTP.fetch(url,
          method: :put,
          headers: [{"content-length", to_string(byte_size(bytes))}],
          body: stream,
          duplex: "half"
        )
        |> HTTP.Promise.await()

      assert HTTP.Response.read_all(response) == "ok"
      assert_receive {:fixed_request, %{body: ^bytes, headers: headers}}, 5_000
      assert headers["content-length"] == to_string(byte_size(bytes))
      refute Map.has_key?(headers, "transfer-encoding")
      assert_receive :no_extra_upload_bytes, 5_000
    end
  end

  for chunks <- [["abc"], ["abc", "def"], ["abcdef"]] do
    test "rejects HTTP/1 length mismatch for #{inspect(chunks)} before extra bytes are sent" do
      test_pid = self()

      url =
        start_raw_http_server!(fn listener ->
          {:ok, socket} = :gen_tcp.accept(listener)
          {headers, body} = recv_header_block(socket, "")
          assert "Content-Length: 4" in String.split(headers, "\r\n")
          refute headers =~ "Transfer-Encoding"
          send(test_pid, {:partial_upload, recv_closed_body(socket, body)})
        end)

      {:ok, stream} = HTTP.Stream.from_enumerable(unquote(chunks))

      assert {:error, :content_length_mismatch} =
               HTTP.fetch(url,
                 method: :put,
                 headers: [{"content-length", "4"}],
                 body: stream,
                 duplex: :half
               )
               |> HTTP.Promise.await()

      expected = if unquote(chunks) == ["abcdef"], do: "", else: "abc"
      assert_receive {:partial_upload, ^expected}, 5_000
    end
  end

  test "fixed-length uploads retain lazy producer backpressure" do
    test_pid = self()

    chunks =
      Stream.map(["abc", "def"], fn chunk ->
        send(test_pid, {:produced, chunk})
        chunk
      end)

    {:ok, stream} = HTTP.Stream.from_enumerable(chunks)
    assert_receive {:produced, "abc"}
    refute_receive {:produced, "def"}

    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        assert %{body: "abcdef"} = recv_request(socket)
        :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        :gen_tcp.close(socket)
      end)

    assert %HTTP.Response{status: 200} =
             HTTP.fetch(url,
               method: :put,
               headers: [{"content-length", "6"}],
               body: stream,
               duplex: "half"
             )
             |> HTTP.Promise.await()

    assert_receive {:produced, "def"}
  end

  test "abort stops a fixed-length upload and its source" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {_headers, body} = recv_header_block(socket, "")
        send(test_pid, {:aborted_body, recv_closed_body(socket, body)})
      end)

    {:ok, stream} = HTTP.Stream.start_link(6)
    monitor = Process.monitor(stream)
    {:ok, controller} = HTTP.AbortController.start_link()

    promise =
      HTTP.fetch(url,
        method: :put,
        headers: [{"content-length", "6"}],
        body: stream,
        duplex: "half",
        signal: controller
      )

    assert :ok = HTTP.Stream.chunk(stream, "abc")
    HTTP.AbortController.abort(controller)
    assert {:error, :aborted} = HTTP.Promise.await(promise)
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 5_000
    assert_receive {:aborted_body, "abc"}, 5_000
  end

  test "uploads a duplex half stream as an HTTP/1.1 chunked request body" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listen_socket ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        request = recv_request(socket)
        send(test_pid, {:request, request})

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])

        :gen_tcp.close(socket)
      end)

    {:ok, stream} = HTTP.Stream.from_enumerable(["hello", "", " ", "stream"])

    response =
      url
      |> HTTP.fetch(method: :post, body: stream, duplex: "half", content_type: "text/plain")
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "ok"

    assert_receive {:request,
                    %{
                      request_line: "POST /test HTTP/1.1",
                      headers: headers,
                      body: "hello stream"
                    }}

    assert headers["content-type"] == "text/plain"
    assert headers["transfer-encoding"] == "chunked"
    refute Map.has_key?(headers, "content-length")
  end

  test "an early final response cancels an open upload before its EOF" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        {_headers, body} = recv_header_block(socket, "")
        assert body == ""
        :ok = :gen_tcp.send(socket, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
        send(test_pid, :early_peer_closed)
      end)

    {:ok, upload} = HTTP.Stream.start_link(0)
    monitor = Process.monitor(upload)

    assert %HTTP.Response{status: 413} =
             HTTP.fetch(url,
               method: :post,
               body: upload,
               duplex: "half",
               http_version: :http1,
               redirect: :manual,
               timeout: 150
             )
             |> HTTP.Promise.await(2_000)

    assert_receive {:DOWN, ^monitor, :process, ^upload, :normal}, 1_000
    assert_receive :early_peer_closed, 1_000
  end

  test "an early streamed response drains after the upload source has terminated" do
    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        recv_header_block(socket, "")

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 413 Payload Too Large\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nstop\r\n0\r\n\r\n"
          )

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
      end)

    {:ok, upload} = HTTP.Stream.start_link(0)

    response =
      HTTP.fetch(url, method: :post, body: upload, duplex: :half, timeout: 1_000)
      |> HTTP.Promise.await()

    assert response.status == 413
    assert is_pid(response.stream)
    refute Process.alive?(upload)
    assert HTTP.Response.read_all(response) == "stop"
  end

  test "downstream abort cancels an early response with an unacknowledged body chunk" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        recv_header_block(socket, "")

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 413 Payload Too Large\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nstop\r\n"
          )

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
        send(test_pid, :cancelled_response_peer_closed)
      end)

    {:ok, upload} = HTTP.Stream.start_link(0)
    {:ok, controller} = HTTP.AbortController.start_link()

    response =
      HTTP.fetch(url,
        method: :post,
        body: upload,
        duplex: :half,
        signal: controller,
        timeout: 2_000
      )
      |> HTTP.Promise.await()

    stream = response.stream
    monitor = Process.monitor(stream)
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^stream, "stop", _ack}, 1_000
    assert :ok = HTTP.AbortController.abort(controller)
    assert :ok = HTTP.AbortController.abort(controller)
    assert_receive {:stream_error, ^stream, :aborted}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
    assert_receive :cancelled_response_peer_closed, 1_000
    refute Process.alive?(upload)
  end

  test "the original request deadline stops a stalled upload" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        recv_header_block(socket, "")
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
        send(test_pid, :deadline_peer_closed)
      end)

    {:ok, upload} = HTTP.Stream.start_link(0)
    monitor = Process.monitor(upload)

    assert {:error, :request_timeout} =
             HTTP.fetch(url, method: :post, body: upload, duplex: :half, timeout: 100)
             |> HTTP.Promise.await()

    assert_receive {:DOWN, ^monitor, :process, ^upload, :normal}, 1_000
    assert_receive :deadline_peer_closed, 1_000
  end

  test "socket owner death stops the upload source and closes the peer" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        recv_header_block(socket, "")
        send(test_pid, :owner_request_received)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
        send(test_pid, :owner_peer_closed)
      end)

    {:ok, upload} = HTTP.Stream.start_link(0)
    monitor = Process.monitor(upload)
    {:ok, controller} = HTTP.AbortController.start_link()
    promise = HTTP.fetch(url, method: :post, body: upload, duplex: :half, signal: controller)
    assert_receive :owner_request_received, 1_000
    owner = Agent.get(controller, & &1.request_id)
    Process.exit(owner, :kill)
    assert {:error, {:request_process_down, :killed}} = HTTP.Promise.await(promise)
    assert_receive {:DOWN, ^monitor, :process, ^upload, :normal}, 1_000
    assert_receive :owner_peer_closed, 1_000
  end

  test "owner death on the first header byte stops the upload source" do
    test_pid = self()
    {:ok, controller} = HTTP.AbortController.start_link()

    url =
      start_raw_http_server!(fn listener ->
        Process.flag(:priority, :high)
        {:ok, socket} = :gen_tcp.accept(listener)
        assert {:ok, "P"} = :gen_tcp.recv(socket, 1, 1_000)
        owner = Agent.get(controller, & &1.request_id)
        Process.exit(owner, :kill)
        send(test_pid, :owner_killed_on_header)
        drain_until_closed(socket)
        send(test_pid, :owner_header_peer_closed)
      end)

    {:ok, upload} = HTTP.Stream.start_link(0)
    source_monitor = Process.monitor(upload)

    promise =
      HTTP.fetch(url,
        method: :post,
        headers: [{"x-large-header", :binary.copy("x", 65_536)}],
        socket_opts: [sndbuf: 1_024],
        body: upload,
        duplex: :half,
        signal: controller
      )

    assert_receive :owner_killed_on_header, 1_000
    assert {:error, {:request_process_down, :killed}} = HTTP.Promise.await(promise)
    assert_receive {:DOWN, ^source_monitor, :process, ^upload, :normal}, 1_000
    assert_receive :owner_header_peer_closed, 1_000
  end

  test "early redirects never replay a streaming body" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listener ->
        {:ok, socket} = :gen_tcp.accept(listener)
        recv_header_block(socket, "")

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n"
          )

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
        assert {:error, :timeout} = :gen_tcp.accept(listener, 100)
        send(test_pid, :stream_not_replayed)
      end)

    {:ok, upload} = HTTP.Stream.start_link(0)

    response =
      HTTP.fetch(url, method: :post, body: upload, duplex: :half, timeout: 1_000)
      |> HTTP.Promise.await()

    assert response.status == 307
    refute Process.alive?(upload)
    assert_receive :stream_not_replayed, 1_000
  end

  test "an early final response tears down a filled TCP send queue" do
    test_pid = self()

    url =
      start_raw_http_server!(
        fn listener ->
          {:ok, socket} = :gen_tcp.accept(listener)
          recv_header_block(socket, "")
          send(test_pid, {:slow_upload_peer, self()})

          receive do
            :reject_upload ->
              :ok =
                :gen_tcp.send(
                  socket,
                  "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"
                )
          end

          receive do
            :peer_done -> :gen_tcp.close(socket)
          end
        end,
        recbuf: 1_024
      )

    {:ok, upload} =
      HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> :binary.copy("x", 65_536) end))

    {:ok, controller} = HTTP.AbortController.start_link()

    promise =
      HTTP.fetch(url,
        method: :post,
        body: upload,
        duplex: :half,
        signal: controller,
        timeout: 4_000,
        socket_opts: [sndbuf: 1_024, high_watermark: 1_024, low_watermark: 512]
      )

    assert_receive {:slow_upload_peer, peer}, 1_000
    owner = Agent.get(controller, & &1.request_id)
    owner_monitor = Process.monitor(owner)
    writer = blocked_upload_writer!(owner, System.monotonic_time(:millisecond) + 2_000)
    writer_monitor = Process.monitor(writer)
    send(peer, :reject_upload)
    assert %HTTP.Response{status: 413} = HTTP.Promise.await(promise, 2_000)
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, :killed}, 1_000
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000
    refute Process.alive?(upload)
    send(peer, :peer_done)
  end

  defp blocked_upload_writer!(owner, deadline) do
    {:links, links} = Process.info(owner, :links)

    writer =
      Enum.find(Enum.filter(links, &is_pid/1), fn pid ->
        case Process.info(pid, :current_stacktrace) do
          {:current_stacktrace, stack} ->
            Enum.any?(stack, fn {module, function, _, _} ->
              module == :prim_inet and function == :send
            end) and Enum.any?(stack, fn {module, _, _, _} -> module == HTTP.HTTP1.Upload end)

          _ ->
            false
        end
      end)

    cond do
      writer ->
        writer

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("upload writer never blocked in TCP send")

      true ->
        receive do
        after
          1 -> blocked_upload_writer!(owner, deadline)
        end
    end
  end

  defp drain_until_closed(socket) do
    case :gen_tcp.recv(socket, 0, 1_000) do
      {:ok, _header_bytes} -> drain_until_closed(socket)
      {:error, :closed} -> :ok
      other -> flunk("expected header socket closure, got #{inspect(other)}")
    end
  end

  defp start_raw_http_server!(handler, socket_opts \\ []) when is_function(handler, 1) do
    {:ok, listen_socket} =
      :gen_tcp.listen(
        0,
        [
          :binary,
          packet: :raw,
          active: false,
          ip: {127, 0, 0, 1},
          reuseaddr: true
        ] ++ socket_opts
      )

    {:ok, port} = :inet.port(listen_socket)

    pid =
      spawn_link(fn ->
        handler.(listen_socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp recv_request(socket) do
    {head, rest} = recv_header_block(socket, <<>>)
    [request_line | header_lines] = String.split(head, "\r\n")

    headers =
      header_lines
      |> Enum.flat_map(fn line ->
        case String.split(line, ":", parts: 2) do
          [name, value] -> [{String.downcase(name), String.trim(value)}]
          _ -> []
        end
      end)
      |> Map.new()

    body =
      case Map.get(headers, "transfer-encoding") do
        "chunked" -> recv_chunked_body(socket, rest)
        _other -> recv_content_length_body(socket, rest, headers)
      end

    %{request_line: request_line, headers: headers, body: body}
  end

  defp recv_header_block(socket, acc) do
    case :binary.match(acc, "\r\n\r\n") do
      {index, 4} ->
        head = binary_part(acc, 0, index)
        rest = binary_part(acc, index + 4, byte_size(acc) - index - 4)
        {head, rest}

      :nomatch ->
        {:ok, data} = :gen_tcp.recv(socket, 0, 5_000)
        recv_header_block(socket, acc <> data)
    end
  end

  defp recv_chunked_body(socket, data) do
    data = recv_until(socket, data, "0\r\n\r\n")
    parse_chunked_body(data, [])
  end

  defp recv_until(socket, data, marker) do
    if String.contains?(data, marker) do
      data
    else
      {:ok, more} = :gen_tcp.recv(socket, 0, 5_000)
      recv_until(socket, data <> more, marker)
    end
  end

  defp parse_chunked_body(data, acc) do
    {line, rest} = take_line(data)
    size = String.to_integer(line, 16)

    if size == 0 do
      acc |> Enum.reverse() |> IO.iodata_to_binary()
    else
      <<chunk::binary-size(size), "\r\n", rest::binary>> = rest
      parse_chunked_body(rest, [chunk | acc])
    end
  end

  defp take_line(data) do
    {index, 2} = :binary.match(data, "\r\n")
    line = binary_part(data, 0, index)
    rest = binary_part(data, index + 2, byte_size(data) - index - 2)
    {line, rest}
  end

  defp recv_content_length_body(socket, data, headers) do
    content_length =
      headers
      |> Map.get("content-length", "0")
      |> String.to_integer()

    recv_body(socket, data, content_length)
  end

  defp recv_body(_socket, data, content_length) when byte_size(data) >= content_length do
    binary_part(data, 0, content_length)
  end

  defp recv_body(socket, data, content_length) do
    {:ok, more} = :gen_tcp.recv(socket, content_length - byte_size(data), 5_000)
    recv_body(socket, data <> more, content_length)
  end

  defp recv_closed_body(socket, body) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, bytes} -> recv_closed_body(socket, body <> bytes)
      {:error, :closed} -> body
    end
  end
end

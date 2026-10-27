defmodule HTTP.MultipartStreamWireTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :tmp_dir

  alias HTTP.{FormData, Promise, RequestCompletion}
  @wait 4_000
  @chunk_size 32_768

  test "uploads exact multipart bytes and length over fixed-length HTTP/1", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "audio.bin")
    bytes = :binary.copy(<<0, 255, 13, 10, 128>>, 220_001)
    File.write!(path, bytes)

    form =
      form(path)
      |> FormData.append_field("last", "after")

    {:multipart, expected, _boundary} = FormData.to_body(form)
    expected = IO.iodata_to_binary(expected)
    {:ok, envelope} = FormData.to_stream(form, chunk_size: @chunk_size)
    parent = self()

    url =
      peer(fn socket ->
        {head, rest} = read_head(socket)
        body = read_bytes(socket, rest, envelope.content_length)
        send(parent, {:multipart_request, head, body})
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, @wait)
      end)

    {:ok, stream} = HTTP.Stream.from_enumerable(envelope.body, telemetry: false)
    monitor = Process.monitor(stream)
    promise = fetch(url, envelope, stream)
    assert %HTTP.Response{status: 200} = response = Promise.await(promise, @wait)
    assert HTTP.Response.read_all(response) == "ok"
    assert_receive {:multipart_request, head, ^expected}, @wait
    assert head =~ "Content-Length: #{byte_size(expected)}\r\n"
    assert head =~ "Content-Type: #{envelope.content_type}\r\n"
    refute head =~ "Transfer-Encoding"
    assert_receive {:DOWN, ^monitor, :process, ^stream, _}, @wait
    assert :ok = RequestCompletion.await(Promise.completion(promise), @wait)
  end

  for interruption <- [:cancel, :owner_exit] do
    test "#{interruption} closes an active file, producer and socket", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "cancel.bin")
      File.write!(path, :binary.copy(<<0, 255>>, 2_000_000))
      {:ok, envelope} = FormData.to_stream(form(path), chunk_size: @chunk_size)
      parent = self()

      url =
        peer(fn socket ->
          {_head, rest} = read_head(socket)
          first = read_bytes(socket, rest, file_header_length() + @chunk_size)
          send(parent, {:multipart_prefix, byte_size(first)})
          send(parent, {:multipart_closed, drain(socket, byte_size(first))})
        end)

      {stream, producer} = gated_stream(envelope)
      trace_open(producer)
      source_monitor = Process.monitor(stream)
      producer_monitor = Process.monitor(producer)
      controller = HTTP.AbortController.new()
      promise = fetch(url, envelope, stream, signal: controller)
      assert_receive {:trace, ^producer, :return_from, {File, :open!, 2}, file}, @wait
      assert is_pid(file)
      file_monitor = Process.monitor(file)
      assert_receive {:multipart_source_blocked, ^producer}, @wait
      assert_receive {:multipart_prefix, prefix_length}, @wait
      assert prefix_length == file_header_length() + @chunk_size

      case unquote(interruption) do
        :cancel ->
          :ok = HTTP.AbortController.abort(controller)
          assert {:error, :aborted} = Promise.await(promise, @wait)

        :owner_exit ->
          Task.shutdown(promise.task, :brutal_kill)
      end

      assert_receive {:DOWN, ^source_monitor, :process, ^stream, _}, @wait
      assert_receive {:DOWN, ^producer_monitor, :process, ^producer, _}, @wait
      assert_receive {:DOWN, ^file_monitor, :process, ^file, _}, @wait
      assert {:error, :terminated} = :file.read(file, 1)
      assert_receive {:multipart_closed, sent_bytes}, @wait
      assert sent_bytes == prefix_length
      assert sent_bytes < envelope.content_length
    end
  end

  test "connection failure terminates the producer before opening its file", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "unopened.bin")
    File.write!(path, "must remain unopened")
    {:ok, envelope} = FormData.to_stream(form(path))
    {stream, producer} = gated_stream(envelope)
    trace_open(producer)
    source_monitor = Process.monitor(stream)
    producer_monitor = Process.monitor(producer)
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)
    :ok = :gen_tcp.close(listener)
    promise = fetch("http://127.0.0.1:#{port}/upload", envelope, stream)
    assert {:error, :econnrefused} = Promise.await(promise, @wait)
    assert_receive {:DOWN, ^source_monitor, :process, ^stream, _}, @wait
    assert_receive {:DOWN, ^producer_monitor, :process, ^producer, _}, @wait
    delivered = :erlang.trace_delivered(producer)
    assert_receive {:trace_delivered, ^producer, ^delivered}, @wait
    refute_receive {:trace, ^producer, :return_from, {File, :open!, 2}, _}, 0
  end

  for mutation <- [:truncate, :append] do
    test "fixed-length upload rejects a file changed by #{mutation}", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "changed.bin")
      File.write!(path, "original")
      {:ok, envelope} = FormData.to_stream(form(path), chunk_size: 4)

      case unquote(mutation) do
        :truncate -> File.write!(path, "x")
        :append -> File.write!(path, :binary.copy("changed", 100))
      end

      parent = self()

      url =
        peer(fn socket ->
          {_head, rest} = read_head(socket)
          send(parent, {:mismatched_bytes, drain(socket, byte_size(rest))})
        end)

      {:ok, stream} = HTTP.Stream.from_enumerable(envelope.body, telemetry: false)
      promise = fetch(url, envelope, stream)
      assert {:error, :content_length_mismatch} = Promise.await(promise, @wait)
      assert_receive {:mismatched_bytes, bytes}, @wait
      assert bytes <= envelope.content_length
    end
  end

  defp form(path) do
    FormData.new()
    |> FormData.append_file("file", "audio.bin", File.stream!(path))
    |> Map.put(:boundary, "wire-boundary")
  end

  defp file_header_length do
    byte_size(
      "--wire-boundary\r\n" <>
        "Content-Disposition: form-data; name=\"file\"; filename=\"audio.bin\"\r\n" <>
        "Content-Type: application/octet-stream\r\n\r\n"
    )
  end

  defp fetch(url, envelope, stream, options \\ []) do
    HTTP.fetch(
      url,
      [
        method: :post,
        body: stream,
        duplex: :half,
        content_type: envelope.content_type,
        headers: [{"Content-Length", Integer.to_string(envelope.content_length)}],
        http_version: :http1,
        redirect: :manual,
        timeout: @wait,
        telemetry: false
      ] ++ options
    )
  end

  defp gated_stream(envelope) do
    parent = self()

    source =
      envelope.body
      |> Stream.with_index()
      |> Stream.map(fn {chunk, index} ->
        if index == 0, do: send(parent, {:multipart_producer, self()})

        if index == 2 do
          send(parent, {:multipart_source_blocked, self()})

          receive do
            :release_multipart_source -> :ok
          after
            @wait -> raise "multipart source gate was not released"
          end
        end

        chunk
      end)

    {:ok, stream} = HTTP.Stream.from_enumerable(source, telemetry: false)
    assert_receive {:multipart_producer, producer}, @wait
    {stream, producer}
  end

  defp trace_open(producer) do
    :erlang.trace_pattern({File, :open!, 2}, [{:_, [], [{:return_trace}]}], [])
    :erlang.trace(producer, true, [:call, {:tracer, self()}])
    on_exit(fn -> :erlang.trace_pattern({File, :open!, 2}, false, []) end)
  end

  defp peer(handler) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    {:ok, port} = :inet.port(listener)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @wait)
        :ok = :gen_tcp.close(listener)
        handler.(socket)
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listener)
    end)

    "http://127.0.0.1:#{port}/upload"
  end

  defp read_head(socket, data \\ "") do
    case :binary.match(data, "\r\n\r\n") do
      {index, 4} ->
        {binary_part(data, 0, index + 2),
         binary_part(data, index + 4, byte_size(data) - index - 4)}

      :nomatch ->
        {:ok, more} = :gen_tcp.recv(socket, 0, @wait)
        read_head(socket, data <> more)
    end
  end

  defp read_bytes(_socket, data, length) when byte_size(data) >= length, do: data

  defp read_bytes(socket, data, length) do
    {:ok, more} = :gen_tcp.recv(socket, length - byte_size(data), @wait)
    read_bytes(socket, data <> more, length)
  end

  defp drain(socket, bytes) do
    case :gen_tcp.recv(socket, 0, @wait) do
      {:ok, data} -> drain(socket, bytes + byte_size(data))
      {:error, :closed} -> bytes
      other -> flunk("expected multipart socket closure, got #{inspect(other)}")
    end
  end
end

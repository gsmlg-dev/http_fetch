defmodule HTTP.HTTP1StrictFramingWireTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion, RequestError, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @head "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
  @malformed [
    {:conflict,
     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n0\r\n\r\n",
     :conflicting_response_framing},
    {:leading_space, @head <> " 1\r\na\r\n0\r\n\r\n", :invalid_chunk_size},
    {:trailing_space, @head <> "1 \r\na\r\n0\r\n\r\n", :invalid_chunk_size},
    {:quoted_extension, @head <> "1;name=\"unterminated\r\na\r\n0\r\n\r\n", :invalid_chunk_size},
    {:status, "HTTP/1.1 600 Invalid\r\nContent-Length: 0\r\n\r\n", :invalid_status_line}
  ]

  for scheme <- [:http, :https],
      mode <- [:raw, :structured],
      {name, bytes, reason} <- @malformed do
    test "#{scheme} #{mode} immediately malformed #{name} closes without replay or reuse" do
      {url, peer, options} = peer(unquote(scheme), unquote(bytes), false)
      promise = post(url, options, unquote(mode))
      completion = Promise.completion(promise)

      case Promise.await(promise, 5_000) do
        {:error, error} ->
          assert_error(error, unquote(reason), unquote(mode))

        %Response{body: stream} when is_pid(stream) ->
          assert_stream_error(stream, unquote(reason))
      end

      assert :ok = RequestCompletion.await(completion, 5_000)
      assert_receive {:parser_closed_peer, ^peer}, 5_000
      assert_no_pool_entry(url)
      assert_fresh_get(url, peer, options)
    end
  end

  for scheme <- [:http, :https],
      mode <- [:raw, :structured],
      reader <- [:early, :late],
      {name, bytes, reason} <- [
        {:quoted_extension, "1;name=\"unterminated\r\n", :invalid_chunk_size},
        {:oversized_line, String.duplicate("0", 8_193) <> "\r\n", :line_too_long}
      ] do
    test "#{scheme} #{mode} #{reader} reader receives gated #{name} error after headers" do
      {url, peer, options} = peer(unquote(scheme), unquote(bytes), true)
      promise = post(url, options, unquote(mode))
      completion = Promise.completion(promise)
      assert %Response{status: 200, body: stream} = Promise.await(promise, 5_000)
      assert is_pid(stream)
      if unquote(reader) == :early, do: send(stream, {:read_chunk, self(), :ack})
      send(peer, :malformed)
      assert_receive {:parser_closed_peer, ^peer}, 5_000
      if unquote(reader) == :late, do: send(stream, {:read_chunk, self(), :ack})
      assert_receive {:stream_error, ^stream, unquote(reason)}, 5_000
      refute_receive {:stream_end, ^stream}, 0
      assert :ok = RequestCompletion.await(completion, 5_000)
      assert_no_pool_entry(url)
      assert_fresh_get(url, peer, options)
    end
  end

  defp post(url, options, mode) do
    HTTP.fetch(
      url,
      options ++
        [
          method: :post,
          body: "once",
          error_mode: mode,
          timeout: 5_000,
          redirect: :manual,
          http1_reuse: true,
          telemetry: false
        ]
    )
  end

  defp assert_error(error, reason, :raw) do
    assert error == reason
    refute RequestError.pre_send?(error)
  end

  defp assert_error(error, reason, :structured) do
    assert %RequestError{reason: ^reason, phase: :unknown, request_started: :unknown} = error
    refute RequestError.pre_send?(error)
  end

  defp assert_stream_error(stream, reason) do
    send(stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_error, ^stream, ^reason}, 5_000
    refute_receive {:stream_end, ^stream}, 0
    refute RequestError.pre_send?(reason)
  end

  defp assert_no_pool_entry(url) do
    port = URI.parse(url).port
    entries = :sys.get_state(HTTP.HTTP1.Pool).entries
    refute Enum.any?(entries, fn {_, entry} -> entry.key.port == port end)
  end

  defp assert_fresh_get(url, peer, options) do
    promise =
      HTTP.fetch(
        url,
        options ++
          [method: :get, http1_reuse: true, redirect: :manual, telemetry: false, timeout: 5_000]
      )

    assert %Response{status: 200, body: "ok"} = Promise.await(promise, 5_000)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 5_000)
    assert_receive {:fresh_get_completed, ^peer}, 5_000
  end

  defp peer(scheme, bytes, gated?) do
    parent = self()
    transport = if scheme == :http, do: :gen_tcp, else: :ssl

    tls =
      if scheme == :http,
        do: [],
        else: [
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          versions: [:"tlsv1.3"]
        ]

    {:ok, listener} = transport.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}] ++ tls)

    {:ok, {_, port}} =
      if scheme == :http, do: :inet.sockname(listener), else: :ssl.sockname(listener)

    peer =
      spawn_link(fn ->
        socket = accept(listener, transport)
        assert_request(socket, transport, "POST", "once")

        if gated? do
          :ok = transport.send(socket, @head)
          assert_receive :malformed, 5_000
        end

        :ok = transport.send(socket, bytes)
        assert {:error, :closed} = transport.recv(socket, 0, 5_000)
        transport.close(socket)
        send(parent, {:parser_closed_peer, self()})

        next = accept(listener, transport)
        assert_request(next, transport, "GET", "")

        :ok =
          transport.send(
            next,
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
          )

        transport.close(next)
        send(parent, {:fresh_get_completed, self()})
      end)

    on_exit(fn ->
      if Process.alive?(peer), do: Process.exit(peer, :kill)
      transport.close(listener)
    end)

    options =
      if scheme == :http,
        do: [],
        else: [
          tls_backend: :ssl,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem"), versions: [:"tlsv1.3"]]
        ]

    {"#{scheme}://localhost:#{port}/mutation", peer, options}
  end

  defp accept(listener, :gen_tcp) do
    {:ok, socket} = :gen_tcp.accept(listener, 5_000)
    socket
  end

  defp accept(listener, :ssl) do
    {:ok, socket} = :ssl.transport_accept(listener, 5_000)
    {:ok, socket} = :ssl.handshake(socket, 5_000)
    socket
  end

  defp assert_request(socket, transport, method, body) do
    :ok = set_packet(socket, transport, :line)
    assert {:ok, line} = transport.recv(socket, 0, 5_000)
    assert line == method <> " /mutation HTTP/1.1\r\n"
    headers(socket, transport)
    :ok = set_packet(socket, transport, :raw)
    if body != "", do: assert({:ok, ^body} = transport.recv(socket, byte_size(body), 5_000))
  end

  defp set_packet(socket, :gen_tcp, packet), do: :inet.setopts(socket, packet: packet)
  defp set_packet(socket, :ssl, packet), do: :ssl.setopts(socket, packet: packet)

  defp headers(socket, transport) do
    case transport.recv(socket, 0, 5_000) do
      {:ok, "\r\n"} -> :ok
      {:ok, _line} -> headers(socket, transport)
    end
  end
end

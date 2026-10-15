defmodule HTTP.HTTP1VersionWireTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion, RequestError, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  for backend <- [:ssl, :ex_ssl],
      mode <- [:raw, :structured],
      version <- ["HTTP/2.0", "HTTP/0.9"] do
    test "#{backend} #{mode} rejects #{version} before response acceptance and closes without replay" do
      bytes = unquote(version) <> " 200 OK\r\nContent-Length: 2\r\n\r\nok"
      {url, peer, options} = peer(bytes, unquote(backend))
      promise = post(url, options, unquote(mode))

      assert {:error, error} = Promise.await(promise, 5_000)
      assert_error(error, :invalid_status_line, unquote(mode))
      assert_completion(promise, unquote(backend))
      assert_receive {:parser_closed_peer, ^peer}, 5_000
      assert_no_pool_entry(url)
      assert_fresh_get(url, peer, options, unquote(backend))
    end
  end

  for backend <- [:ssl, :ex_ssl], version <- ["HTTP/1.0", "HTTP/1.1", "HTTP/1.9"] do
    test "#{backend} accepts compatible #{version} responses" do
      connection = if unquote(version) == "HTTP/1.1", do: "Connection: close\r\n", else: ""
      bytes = unquote(version) <> " 200 OK\r\nContent-Length: 2\r\n" <> connection <> "\r\nok"
      {url, peer, options} = peer(bytes, unquote(backend))
      promise = post(url, options, :raw)

      assert %Response{status: 200, body: "ok"} = Promise.await(promise, 5_000)
      assert_completion(promise, unquote(backend))
      assert_receive {:parser_closed_peer, ^peer}, 5_000
      assert_no_pool_entry(url)
      assert_fresh_get(url, peer, options, unquote(backend))
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

  defp assert_no_pool_entry(url) do
    port = URI.parse(url).port
    entries = :sys.get_state(HTTP.HTTP1.Pool).entries
    refute Enum.any?(entries, fn {_, entry} -> entry.key.port == port end)
  end

  defp assert_completion(promise, backend) do
    result = RequestCompletion.await(Promise.completion(promise), 5_000)

    case backend do
      :ssl -> assert result == :ok
      :ex_ssl -> assert result == {:error, {:unsupported_completion, :tls_backend}}
    end
  end

  defp assert_fresh_get(url, peer, options, backend) do
    promise =
      HTTP.fetch(
        url,
        options ++
          [method: :get, http1_reuse: true, redirect: :manual, telemetry: false, timeout: 5_000]
      )

    assert %Response{status: 200, body: "ok"} = Promise.await(promise, 5_000)
    assert_completion(promise, backend)
    assert_receive {:fresh_get_completed, ^peer}, 5_000
  end

  defp peer(bytes, backend) do
    parent = self()
    transport = :ssl

    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        ip: {127, 0, 0, 1},
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        versions: [:"tlsv1.3"]
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      spawn_link(fn ->
        socket = accept(listener, transport)
        assert_request(socket, transport, "POST", "once")

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

    options = [
      tls_backend: backend,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem"), versions: [:"tlsv1.3"]]
    ]

    {"https://localhost:#{port}/mutation", peer, options}
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

  defp set_packet(socket, :ssl, packet), do: :ssl.setopts(socket, packet: packet)

  defp headers(socket, transport) do
    case transport.recv(socket, 0, 5_000) do
      {:ok, "\r\n"} -> :ok
      {:ok, _line} -> headers(socket, transport)
    end
  end
end

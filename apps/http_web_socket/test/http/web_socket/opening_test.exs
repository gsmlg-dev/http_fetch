defmodule HTTP.WebSocket.OpeningTest do
  use ExUnit.Case, async: false
  import Bitwise
  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Open, Close, Error}

  @timeout 5_000
  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @fixtures Path.expand("../../../../http_fetch/test/support/fixtures", __DIR__)

  test "close interrupts a held HTTP/1 Upgrade and closes the worker-owned socket" do
    parent = self()
    {url, peer} = stalled_peer(:upgrade, parent)
    ws = WebSocket.new(url, [], timeout: 30_000, opening_timeout: 30_000)
    monitor = Process.monitor(ws.pid)
    assert_receive {:held, ^peer}, @timeout
    assert WebSocket.ready_state(ws) == WebSocket.connecting()
    assert :ok = WebSocket.close(ws)
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
    assert_receive {:socket_closed, ^peer}, 1_000
    refute_receive {WebSocket, ^ws, %Open{}}, 0
  end

  for backend <- [:ssl, :ex_ssl] do
    test "close interrupts stalled HTTP/1 TLS dialing with #{backend}" do
      parent = self()
      {url, peer} = stalled_peer(:tls, parent)

      ws =
        WebSocket.new(url, [],
          tls_backend: unquote(backend),
          timeout: 30_000,
          connect_timeout: :infinity
        )

      monitor = Process.monitor(ws.pid)
      assert_receive {:held, ^peer}, @timeout
      assert :ok = WebSocket.close(ws)
      assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
      assert_receive {:socket_closed, ^peer}, 1_000
    end

    test "auto capability fallback uses one separate HTTP/1 connection and preserves the healthy H2 owner with #{backend}" do
      parent = self()
      {listener, port} = tls_listener()

      peer =
        spawn_link(fn ->
          first = tls_accept(listener)
          assert {:ok, "h2"} = :ssl.negotiated_protocol(first)
          assert {:ok, @preface} = :ssl.recv(first, byte_size(@preface), @timeout)
          assert {4, 0, 0, _} = ssl_frame(first)
          :ok = :ssl.send(first, [frame(4, 0, 0, <<3::16, 10::32>>), frame(4, 1, 0, "")])
          second = tls_accept(listener)
          assert {:ok, "http/1.1"} = :ssl.negotiated_protocol(second)
          request = upgrade_request(second, "")
          key = header(request, "sec-websocket-key")

          accept =
            Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

          :ok =
            :ssl.send(
              second,
              "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept}\r\n\r\n"
            )

          receive do: (:prove_no_connect -> :ok)
          :ok = :ssl.send(first, frame(6, 0, 0, "fallback"))
          no_headers_until_ping(first)
          send(parent, {:no_connect, self()})
          assert {8, <<1000::16>>} = ssl_websocket_frame(second)
          :ok = :ssl.send(second, <<0x88, 2, 1000::16>>)
          receive do: (:stop -> :ok)
          :ssl.close(first)
          :ssl.close(second)
        end)

      cleanup_tls(listener, peer)

      ws =
        WebSocket.new("wss://localhost:#{port}/chat", [],
          http_version: :auto,
          tls_backend: unquote(backend),
          ssl: trusted(),
          timeout: @timeout
        )

      assert %WebSocket{} = ws
      on_exit(fn -> if Process.alive?(ws.pid), do: Process.exit(ws.pid, :kill) end)
      assert_receive {WebSocket, ^ws, %Open{}}, @timeout
      assert WebSocket.http_version(ws) == :http1
      assert %{fallback?: true} = WebSocket.status(ws)
      send(peer, :prove_no_connect)
      assert_receive {:no_connect, ^peer}, @timeout
      assert :ok = WebSocket.close(ws, 1000)
      assert_receive {WebSocket, ^ws, %Close{code: 1000, was_clean: true}}, @timeout
      assert {:error, :timeout} = :ssl.transport_accept(listener, 0)
    end

    test "auto never falls back after an H2 authentication rejection with #{backend}" do
      parent = self()
      {listener, port} = tls_listener()

      peer =
        spawn_link(fn ->
          socket = tls_accept(listener)
          assert {:ok, "h2"} = :ssl.negotiated_protocol(socket)
          assert {:ok, @preface} = :ssl.recv(socket, byte_size(@preface), @timeout)
          assert {4, 0, 0, _} = ssl_frame(socket)
          :ok = :ssl.send(socket, [frame(4, 0, 0, <<8::16, 1::32>>), frame(4, 1, 0, "")])
          {1, 4, id, _headers} = ssl_next(socket, 1)
          # Independent literal :status=401, without indexed package encoding.
          :ok = :ssl.send(socket, frame(1, 5, id, <<0, 7, ":status", 3, "401">>))
          assert {3, 0, ^id, <<8::32>>} = ssl_next(socket, 3)
          send(parent, {:rejection_wire, self()})
          receive do: (:stop -> :ssl.close(socket))
        end)

      cleanup_tls(listener, peer)

      ws =
        WebSocket.new("wss://localhost:#{port}/chat", [],
          http_version: :auto,
          tls_backend: unquote(backend),
          ssl: trusted(),
          timeout: @timeout
        )

      assert %WebSocket{} = ws
      assert_receive {WebSocket, ^ws, %Error{reason: {:unexpected_status, 401}}}, @timeout
      assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, @timeout
      assert_receive {:rejection_wire, ^peer}, @timeout
      refute_receive {WebSocket, ^ws, %Open{}}, 0
      assert {:error, :timeout} = :ssl.transport_accept(listener, 0)
    end

    test "auto never falls back after certificate reference-identity failure with #{backend}" do
      {listener, port} = tls_listener()

      peer =
        spawn_link(fn ->
          assert {:ok, tcp} = :ssl.transport_accept(listener, @timeout)

          case :ssl.handshake(tcp, @timeout) do
            {:ok, socket} ->
              assert {:error, reason} = :ssl.recv(socket, 0, @timeout)
              refute reason == :timeout
              :ssl.close(socket)

            {:error, reason} ->
              refute reason == :timeout
          end
        end)

      cleanup_tls(listener, peer)

      ws =
        WebSocket.new("wss://localhost:#{port}/chat", [],
          http_version: :auto,
          tls_backend: unquote(backend),
          ssl: Keyword.put(trusted(), :server_name_indication, ~c"wrong.test"),
          timeout: @timeout
        )

      assert %WebSocket{} = ws
      assert_receive {WebSocket, ^ws, %Error{reason: reason}}, @timeout
      refute reason in [:http1_negotiated, :extended_connect_not_supported, :opening_timeout]
      assert_receive {WebSocket, ^ws, %Close{was_clean: false}}, @timeout
      assert {:error, :timeout} = :ssl.transport_accept(listener, 0)
    end
  end

  defp stalled_peer(mode, parent) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @timeout)
        assert {:ok, _request_or_hello} = :gen_tcp.recv(socket, 0, @timeout)
        send(parent, {:held, self()})
        receive_closed(socket)
        send(parent, {:socket_closed, self()})
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    scheme = if mode == :tls, do: "wss", else: "ws"
    {"#{scheme}://127.0.0.1:#{port}/chat", peer}
  end

  defp receive_closed(socket) do
    case :gen_tcp.recv(socket, 0, @timeout) do
      {:ok, _data} -> receive_closed(socket)
      {:error, :closed} -> :ok
      other -> flunk("expected close: #{inspect(other)}")
    end
  end

  defp trusted,
    do: [
      verify: :verify_peer,
      cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
      server_name_indication: ~c"localhost"
    ]

  defp tls_listener do
    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        reuseaddr: true,
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        alpn_preferred_protocols: ["h2", "http/1.1"]
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)
    {listener, port}
  end

  defp cleanup_tls(listener, peer) do
    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)
  end

  defp tls_accept(listener) do
    assert {:ok, tcp} = :ssl.transport_accept(listener, @timeout)
    assert {:ok, socket} = :ssl.handshake(tcp, @timeout)
    socket
  end

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp ssl_frame(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :ssl.recv(socket, 9, @timeout)
    payload = if size == 0, do: "", else: ssl_recv(socket, size)
    {type, flags, id, payload}
  end

  defp ssl_recv(socket, size) do
    assert {:ok, data} = :ssl.recv(socket, size, @timeout)
    data
  end

  defp ssl_next(socket, type) do
    case ssl_frame(socket) do
      {^type, _, _, _} = observed ->
        observed

      {4, 0, 0, _} ->
        :ok = :ssl.send(socket, frame(4, 1, 0, ""))
        ssl_next(socket, type)

      _frame ->
        ssl_next(socket, type)
    end
  end

  defp no_headers_until_ping(socket) do
    case ssl_frame(socket) do
      {6, 1, 0, "fallback"} -> :ok
      {1, _, _, _} -> flunk("capability refusal wrote CONNECT")
      _ -> no_headers_until_ping(socket)
    end
  end

  defp upgrade_request(socket, buffer) do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      assert {:ok, data} = :ssl.recv(socket, 0, @timeout)
      upgrade_request(socket, buffer <> data)
    else
      buffer
    end
  end

  defp header(request, name) do
    request
    |> String.split("\r\n")
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [key, value] -> if String.downcase(key) == name, do: String.trim(value)
        _ -> nil
      end
    end)
  end

  defp ssl_websocket_frame(socket) do
    <<first, 1::1, size::7>> = ssl_recv(socket, 2)
    <<key::binary-size(4), payload::binary-size(size)>> = ssl_recv(socket, size + 4)

    bytes =
      for {byte, index} <- Enum.with_index(:binary.bin_to_list(payload)),
          do: bxor(byte, :binary.at(key, rem(index, 4)))

    {first &&& 15, :erlang.list_to_binary(bytes)}
  end
end

defmodule HTTP.WebSocket.TransportControlsTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}

  @timeout 5_000
  @peer_limit "x-codex-websocket-max-unfragmented-message-bytes"
  @fixtures Path.expand("../../../../http_fetch/test/support/fixtures", __DIR__)

  for {family, address} <- [inet: {127, 0, 0, 1}, inet6: {0, 0, 0, 0, 0, 0, 0, 1}] do
    test "pins #{family} without resolving or replacing the URL Host" do
      parent = self()

      {port, peer} =
        peer(
          fn socket ->
            request = request(socket)
            send(parent, {:host, self(), header(request, "host")})
            :ok = :gen_tcp.send(socket, upgrade(request))
            close_exchange(socket)
          end,
          [unquote(family), ip: unquote(Macro.escape(address))]
        )

      ws =
        WebSocket.new("ws://unresolvable.invalid:#{port}/chat", [],
          connect_address: unquote(Macro.escape(address))
        )

      assert_receive {WebSocket, ^ws, %Open{}}, @timeout
      assert_receive {:host, ^peer, host}, @timeout
      assert host == "unresolvable.invalid:#{port}"
      assert :ok = WebSocket.close(ws)
      assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
      assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(ws), @timeout)
    end
  end

  test "a failed pinned dial never retries the URL address" do
    {port, _peer} =
      peer(fn socket ->
        request = request(socket)
        :ok = :gen_tcp.send(socket, upgrade(request))
        close_exchange(socket)
      end)

    ws =
      WebSocket.new("ws://127.0.0.1:#{port}/chat", [], connect_address: {127, 0, 0, 2})

    assert_receive {WebSocket, ^ws, %Error{reason: :econnrefused}}, @timeout
    assert_receive {WebSocket, ^ws, %Close{was_clean: false}}, @timeout
    assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(ws), @timeout)
    refute_receive {WebSocket, ^ws, %Open{}}, 0
  end

  test "TLS pins the address while verifying the URL hostname and sending its SNI" do
    parent = self()

    {:ok, listener} =
      :ssl.listen(0,
        binary: true,
        active: false,
        ip: {127, 0, 0, 2},
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        alpn_preferred_protocols: ["http/1.1"]
      )

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, @timeout)
        {:ok, socket} = :ssl.handshake(tcp, @timeout)
        {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
        request = request(socket, :ssl)
        send(parent, {:identity, info[:sni_hostname], header(request, "host")})
        :ok = :ssl.send(socket, upgrade(request))
        close_exchange(socket, :ssl)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)

    ws =
      WebSocket.new("wss://localhost:#{port}/chat", [],
        connect_address: {127, 0, 0, 2},
        ssl: [verify: :verify_peer, cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
      )

    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert_receive {:identity, ~c"localhost", host}, @timeout
    assert host == "localhost:#{port}"
    assert :ok = WebSocket.close(ws)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
    assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(ws), @timeout)
  end

  test "open exposes selected metadata and preserves coalesced fragments with ACK delivery" do
    {port, _peer} =
      peer(fn socket ->
        request = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            upgrade(request, [{@peer_limit, "3"}, {"set-cookie", "secret"}]),
            <<0x01, 3, "abc", 0x80, 3, "def">>
          ])

        close_exchange(socket)
      end)

    ws =
      WebSocket.new("ws://127.0.0.1:#{port}/chat", [],
        delivery: :ack,
        max_message_size: 6,
        max_frame_bytes: 3,
        max_read_bytes: 16
      )

    assert_receive {WebSocket, ^ws, %Open{} = event}, @timeout
    assert %{handshake: %{status: 101, headers: headers, truncated?: false}} = event
    assert HTTP.Headers.get(headers, @peer_limit) == "3"
    assert HTTP.Headers.get(headers, "set-cookie") == nil
    assert length(headers.headers) == 1
    assert_receive {WebSocket, ^ws, %Message{data: "abcdef"}, ref}, @timeout
    assert :ok = WebSocket.acknowledge(ws, ref)
    assert :ok = WebSocket.close(ws)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
    assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(ws), @timeout)
  end

  test "failed upgrades retain Retry-After but omit oversized or duplicate selected values" do
    {port, _peer} =
      peer(fn socket ->
        _ = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 10\r\n",
            @peer_limit,
            ": ",
            :binary.copy("x", 1025),
            "\r\nSet-Cookie: secret\r\n\r\n"
          ])

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, @timeout)
      end)

    ws = WebSocket.new("ws://127.0.0.1:#{port}/chat")
    assert_receive {WebSocket, ^ws, %Error{reason: {:unexpected_status, 429}} = event}, @timeout
    assert %{handshake: %{status: 429, headers: headers, truncated?: true}} = event
    assert headers.headers == [{"retry-after", "10"}]
    assert_receive {WebSocket, ^ws, %Close{was_clean: false}}, @timeout
    assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(ws), @timeout)

    {port, _peer} =
      peer(fn socket ->
        request = request(socket)

        :ok =
          :gen_tcp.send(socket, upgrade(request, [{"Retry-After", "1"}, {"retry-after", "2"}]))

        close_exchange(socket)
      end)

    ws = WebSocket.new("ws://127.0.0.1:#{port}/chat")
    assert_receive {WebSocket, ^ws, %Open{} = event}, @timeout
    assert %{handshake: %{headers: %{headers: []}, truncated?: true}} = event
    assert :ok = WebSocket.close(ws)
    assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(ws), @timeout)
  end

  for {name, chunks, limits, reason} <- [
        {:frame, [<<0x81, 9>>], [max_frame_bytes: 4, max_read_bytes: 64], :frame_too_big},
        {:read, [<<0x81, 10, "1234">>, "567890"], [max_frame_bytes: 64, max_read_bytes: 8],
         :read_buffer_too_big},
        {:coalesced_read, [<<0x81, 10, "1234567890">>], [max_frame_bytes: 64, max_read_bytes: 8],
         :read_buffer_too_big}
      ] do
    test "#{name} limit terminates distinctly and completes cleanup" do
      {port, peer} =
        peer(fn socket ->
          request = request(socket)

          case unquote(name) do
            :coalesced_read ->
              :ok = :gen_tcp.send(socket, [upgrade(request) | unquote(chunks)])

            :read ->
              :ok = :gen_tcp.send(socket, [upgrade(request), <<0x81, 0, 0x81, 10, "1234">>])
              receive do: (:continue -> :ok)
              :ok = :gen_tcp.send(socket, "567890")

            :frame ->
              :ok = :gen_tcp.send(socket, [upgrade(request) | unquote(chunks)])
          end

          assert <<1009::16, unquote(Atom.to_string(reason))::binary>> = close_frame(socket)
        end)

      ws =
        WebSocket.new(
          "ws://127.0.0.1:#{port}/chat",
          [],
          [delivery: :ack, max_queue_events: 1, max_message_size: 64, close_timeout: 1_000] ++
            unquote(limits)
        )

      assert_receive {WebSocket, ^ws, %Open{}}, @timeout

      if unquote(name) == :read do
        # Acknowledgement drains the queued partial frame before the next read.
        assert_receive {WebSocket, ^ws, %Message{data: ""}, ref}, @timeout
        assert :ok = WebSocket.acknowledge(ws, ref)
        send(peer, :continue)
      end

      assert_receive {WebSocket, ^ws, %Error{reason: unquote(reason)}}, @timeout
      assert_receive {WebSocket, ^ws, %Close{code: 1009, was_clean: false}}, @timeout
      assert :ok = HTTP.ClientCompletion.await(WebSocket.completion(ws), @timeout)
      refute_receive {WebSocket, ^ws, %Message{}}, 0
    end
  end

  defp peer(script, options \\ [ip: {127, 0, 0, 1}]) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true] ++ options)
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @timeout)
        script.(socket)
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {port, peer}
  end

  defp request(socket, transport \\ :gen_tcp, buffer \\ "") do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      assert {:ok, data} = transport.recv(socket, 0, @timeout)
      request(socket, transport, buffer <> data)
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

  defp upgrade(request, headers \\ []) do
    accept =
      Base.encode64(
        :crypto.hash(
          :sha,
          header(request, "sec-websocket-key") <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        )
      )

    [
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
      accept,
      "\r\n",
      Enum.map(headers, fn {name, value} -> [name, ": ", value, "\r\n"] end),
      "\r\n"
    ]
  end

  defp close_exchange(socket, transport \\ :gen_tcp) do
    payload = close_frame(socket, transport)
    :ok = transport.send(socket, <<0x88, byte_size(payload), payload::binary>>)
  end

  defp close_frame(socket, transport \\ :gen_tcp) do
    assert {:ok, <<0x88, 1::1, size::7>>} = transport.recv(socket, 2, @timeout)
    assert {:ok, masked} = transport.recv(socket, size + 4, @timeout)
    <<key::binary-size(4), payload::binary>> = masked
    mask = binary_part(:binary.copy(key, div(size + 3, 4)), 0, size)
    :crypto.exor(payload, mask)
  end
end

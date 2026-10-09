defmodule HTTP.WebSocket.ProxyBoundaryTest do
  use ExUnit.Case, async: true
  import Bitwise
  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Open, Message, Error, Close}

  @timeout 5_000

  test "coalesced handshake and frames retain finite ACK credit and acknowledged binary writes" do
    parent = self()

    {url, peer} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, [head(key), <<0x82, 1, 255, 0x81, 1, "b", 0x89, 1, "p">>])
        assert {2, <<0, 255>>} = frame(socket)
        assert {10, "p"} = frame(socket)
        send(parent, {:bidirectional, self()})
        assert {8, <<1000::16>>} = frame(socket)
        :ok = :gen_tcp.send(socket, <<0x88, 2, 1000::16>>)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, @timeout)
      end)

    ws =
      WebSocket.new(url, [],
        delivery: :ack,
        binary_type: :array_buffer,
        max_message_size: 2,
        max_queue_bytes: 9,
        max_queue_events: 1
      )

    assert_receive {WebSocket, ^ws, %Open{}}, @timeout

    assert_receive {WebSocket, ^ws, %Message{data: %WebSocket.ArrayBuffer{data: <<255>>}}, first},
                   @timeout

    refute_receive {WebSocket, ^ws, %Message{}}, 0
    assert %{queued_events: 1, queued_bytes: 8} = WebSocket.status(ws)
    assert {:ok, sent} = WebSocket.send_ack(ws, WebSocket.array_buffer(<<0, 255>>))
    assert_receive {WebSocket, ^ws, {:send_result, ^sent, :ok}}, @timeout
    assert :ok = WebSocket.acknowledge(ws, first)
    assert_receive {WebSocket, ^ws, %Message{data: "b"}, second}, @timeout
    assert :ok = WebSocket.acknowledge(ws, second)
    assert_receive {:bidirectional, ^peer}, @timeout
    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{code: 1000, was_clean: true}}, @timeout
  end

  test "invalid handshake and redirects never open or replay" do
    for response <- [
          "HTTP/1.1 302 Found\r\nLocation: /other\r\n\r\n",
          "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n"
        ] do
      {url, _} =
        peer(fn socket, _key ->
          :ok = :gen_tcp.send(socket, response)
          assert {:error, :closed} = :gen_tcp.recv(socket, 0, @timeout)
        end)

      ws = WebSocket.new(url)
      assert_receive {WebSocket, ^ws, %Error{}}, @timeout
      assert_receive {WebSocket, ^ws, %Close{was_clean: false}}, @timeout
      refute_receive {WebSocket, ^ws, %Open{}}, 0
      assert {:error, :closed} = WebSocket.send_ack(ws, "late")
    end
  end

  test "slow peer retains bounded pending writes, stays cancellable and settles discarded sends" do
    parent = self()

    {url, peer} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, head(key))
        receive do: (:drain -> :ok)
        drain(socket)
        send(parent, {:peer_closed, self()})
      end)

    ws =
      WebSocket.new(url, [],
        max_send_queue: 8 * 1024 * 1024,
        max_send_frames: 2,
        write_timeout: 5_000,
        close_timeout: 100,
        socket_opts: [sndbuf: 1_024, high_watermark: 1_024, low_watermark: 512]
      )

    assert_receive {WebSocket, ^ws, %Open{}}, @timeout

    assert {:ok, _warmup} =
             WebSocket.send_ack(ws, WebSocket.array_buffer(:binary.copy(<<0>>, 4 * 1024 * 1024)))

    assert {:ok, first} =
             WebSocket.send_ack(ws, WebSocket.array_buffer(:binary.copy(<<1>>, 4 * 1024 * 1024)))

    assert {:ok, second} =
             WebSocket.send_ack(ws, WebSocket.array_buffer(:binary.copy(<<2>>, 4 * 1024 * 1024)))

    assert {:error, :send_queue_full} = WebSocket.send_ack(ws, "overflow")
    assert %{pending_send_frames: 2, buffered_amount: bytes} = WebSocket.status(ws)
    assert bytes <= 8 * 1024 * 1024
    monitor = Process.monitor(ws.pid)
    assert :ok = WebSocket.close(ws)
    assert_receive {WebSocket, ^ws, {:send_result, ^second, {:error, :closed}}}, 1_000
    assert_receive {WebSocket, ^ws, {:send_result, ^first, {:error, :closed}}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
    send(peer, :drain)
    assert_receive {:peer_closed, ^peer}, @timeout
  end

  test "write deadline terminates a blocked send and confirms cleanup" do
    {url, peer} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, head(key))
        receive do: (:drain -> drain(socket))
      end)

    ws =
      WebSocket.new(url, [],
        write_timeout: 100,
        socket_opts: [sndbuf: 1_024, high_watermark: 1_024, low_watermark: 512]
      )

    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    monitor = Process.monitor(ws.pid)

    assert {:ok, _warmup} =
             WebSocket.send_ack(ws, WebSocket.array_buffer(:binary.copy(<<0>>, 8 * 1024 * 1024)))

    assert {:ok, ref} =
             WebSocket.send_ack(ws, WebSocket.array_buffer(:binary.copy(<<0>>, 8 * 1024 * 1024)))

    assert_receive {WebSocket, ^ws, {:send_result, ^ref, {:error, :send_timeout}}}, 2_000
    assert_receive {WebSocket, ^ws, %Error{reason: :send_timeout}}, 2_000
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 2_000
    send(peer, :drain)
  end

  test "owner loss closes a blocked connection" do
    parent = self()

    {url, peer} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, head(key))
        receive do: (:drain -> drain(socket))
        send(parent, {:owner_peer_closed, self()})
      end)

    owner =
      spawn(fn ->
        ws =
          WebSocket.new(url, [],
            socket_opts: [sndbuf: 1_024, high_watermark: 1_024, low_watermark: 512]
          )

        receive do
          {WebSocket, ^ws, %Open{}} ->
            {:ok, _} =
              WebSocket.send_ack(ws, WebSocket.array_buffer(:binary.copy(<<0>>, 8 * 1024 * 1024)))

            send(parent, {:owned, ws})
        end

        receive do: (:stop -> :ok)
      end)

    assert_receive {:owned, ws}, @timeout
    monitor = Process.monitor(ws.pid)
    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 1_000
    send(peer, :drain)
    assert_receive {:owner_peer_closed, ^peer}, @timeout
  end

  for backend <- [:ssl, :ex_ssl] do
    test "verified WSS slow-peer cancellation is bounded with #{backend}" do
      fixtures = Path.expand("../../support/fixtures", __DIR__)

      {:ok, listener} =
        :ssl.listen(0, [
          :binary,
          active: false,
          reuseaddr: true,
          certfile: Path.join(fixtures, "localhost.pem"),
          keyfile: Path.join(fixtures, "localhost.key"),
          recbuf: 1_024
        ])

      {:ok, {_, port}} = :ssl.sockname(listener)
      parent = self()

      peer =
        spawn_link(fn ->
          {:ok, tcp} = :ssl.transport_accept(listener, @timeout)
          {:ok, socket} = :ssl.handshake(tcp, @timeout)
          {:ok, request} = :ssl.recv(socket, 0, @timeout)
          :ok = :ssl.send(socket, head(request_key(request)))
          receive do: (:drain -> ssl_drain(socket))
          send(parent, {:wss_closed, self()})
        end)

      on_exit(fn ->
        Process.exit(peer, :kill)
        :ssl.close(listener)
      end)

      ws =
        WebSocket.new("wss://localhost:#{port}/proxy", [],
          tls_backend: unquote(backend),
          write_timeout: 2_000,
          close_timeout: 100,
          ssl: [cacertfile: Path.join(fixtures, "localhost-ca.pem")],
          socket_opts: [sndbuf: 1_024]
        )

      assert_receive {WebSocket, ^ws, %Open{}}, @timeout

      assert {:ok, _} =
               WebSocket.send_ack(
                 ws,
                 WebSocket.array_buffer(:binary.copy(<<0>>, 8 * 1024 * 1024))
               )

      assert {:ok, _} =
               WebSocket.send_ack(
                 ws,
                 WebSocket.array_buffer(:binary.copy(<<1>>, 8 * 1024 * 1024))
               )

      monitor = Process.monitor(ws.pid)
      assert :ok = WebSocket.close(ws)
      assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
      send(peer, :drain)
      assert_receive {:wss_closed, ^peer}, @timeout
    end
  end

  defp ssl_drain(socket) do
    case :ssl.recv(socket, 0, @timeout) do
      {:ok, _} -> ssl_drain(socket)
      {:error, :timeout} -> flunk("WSS socket was not closed")
      {:error, _} -> :ok
    end
  end

  defp peer(fun) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, recbuf: 1_024])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @timeout)
        request = request(socket, "")

        key = request_key(request)

        fun.(socket, key)
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {"ws://127.0.0.1:#{port}/proxy", peer}
  end

  defp request(socket, buffer) do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      {:ok, data} = :gen_tcp.recv(socket, 0, @timeout)
      request(socket, buffer <> data)
    else
      buffer
    end
  end

  defp request_key(request) do
    request
    |> String.split("\r\n")
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] -> if String.downcase(name) == "sec-websocket-key", do: String.trim(value)
        _ -> nil
      end
    end)
  end

  defp head(key) do
    accept = Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept}\r\n\r\n"
  end

  defp frame(socket) do
    {:ok, <<first, 1::1, size::7>>} = :gen_tcp.recv(socket, 2, @timeout)

    {:ok, <<mask::binary-size(4), payload::binary-size(size)>>} =
      :gen_tcp.recv(socket, 4 + size, @timeout)

    bytes =
      for {byte, index} <- Enum.with_index(:binary.bin_to_list(payload)),
          do: bxor(byte, :binary.at(mask, rem(index, 4)))

    {first &&& 15, :erlang.list_to_binary(bytes)}
  end

  defp drain(socket) do
    case :gen_tcp.recv(socket, 0, @timeout) do
      {:ok, _} -> drain(socket)
      {:error, reason} when reason in [:closed, :econnreset] -> :ok
      other -> flunk("expected closed, got #{inspect(other)}")
    end
  end
end

defmodule HTTP.WebSocket.ClosedRearmTest do
  use ExUnit.Case, async: false

  import Bitwise

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}

  @fixtures Path.expand("../../support/fixtures", __DIR__)

  for backend <- [:ssl, :ex_ssl], terminal <- [:close, :eof, :truncated, :invalid] do
    test "#{backend} processes queued #{terminal} frames before peer EOF finalizes closure" do
      backend = unquote(backend)
      terminal = unquote(terminal)
      parent = self()
      {peer, port} = close_peer(parent, terminal)

      socket =
        WebSocket.new("wss://127.0.0.1:#{port}/socket", [],
          tls_backend: backend,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
        )

      on_exit(fn -> Process.exit(socket.pid, :kill) end)
      assert_receive {WebSocket, ^socket, %Open{}}, 5_000
      %{generation: generation, socket: tls} = :sys.get_state(socket.pid)
      consumer = socket.pid
      tls_pid = tls_pid(tls)
      tls_monitor = Process.monitor(tls_pid)
      on_exit(fn -> Process.exit(tls_pid, :kill) end)
      :ok = :sys.suspend(tls_pid)
      :erlang.trace(tls_pid, true, [:send])
      writer_supervisor = Process.whereis(:http_runtime_task_supervisor)
      :erlang.trace(writer_supervisor, true, [:send, :set_on_spawn])
      :erlang.trace(socket.pid, true, [:send])
      close_task = Task.async(fn -> WebSocket.close(socket, 1000, "done") end)
      on_exit(fn -> Process.exit(close_task.pid, :kill) end)

      # The synchronous active-once call selects its reply ahead of TLS data.
      # Park the consumer at that real call, while its writer remains runnable.
      assert_receive {:trace, ^consumer, :send, {:"$gen_call", _, _}, ^tls_pid}, 5_000
      true = :erlang.suspend_process(socket.pid)

      try do
        :ok = :sys.resume(tls_pid)
        assert_receive {:peer_received_close, ^peer}, 5_000
        assert_receive {:trace, writer, :send, {:http1_write, writer, :ok}, ^consumer}, 5_000

        # These precede peer data and exercise identity guards after closed rearm.
        send(consumer, {:http1_read_closed, make_ref(), tls})
        send(consumer, {:http1_read_closed, generation, make_ref()})

        # Release the peer only after the real write acknowledgment is queued.
        send(peer, :reply_close)
        wait_for_tls_data(backend, tls_pid, tls_monitor, consumer)
        {:messages, pending} = Process.info(socket.pid, :messages)
        write_index = Enum.find_index(pending, &match?({:http1_write, _, :ok}, &1))
        data_index = Enum.find_index(pending, &match?({:ssl, _, _}, &1))
        assert is_integer(write_index) and is_integer(data_index)
        assert write_index < data_index
      after
        :erlang.trace(writer_supervisor, false, [:send, :set_on_spawn])
        :erlang.trace(socket.pid, false, [:send])
        if Process.alive?(tls_pid), do: :erlang.trace(tls_pid, false, [:send])
        true = :erlang.resume_process(socket.pid)
      end

      assert :ok = Task.await(close_task, 5_000)
      assert_receive {WebSocket, ^socket, %Message{data: "tail"}}, 5_000
      expected_code = %{close: 1000, eof: 1006, truncated: 1006, invalid: 1002}[terminal]
      expected_clean = unquote(terminal == :close)

      assert_receive {WebSocket, ^socket,
                      %Close{code: ^expected_code, was_clean: ^expected_clean}},
                     5_000

      assert_terminal_error(terminal, socket)
      refute_receive {WebSocket, ^socket, %Close{}}, 0
    end
  end

  test "stale or unsolicited deferred EOF cannot close a live socket" do
    {:ok, _peer, port} = HTTPWebSocket.TestServer.start_link()
    socket = WebSocket.new("ws://127.0.0.1:#{port}/socket")
    on_exit(fn -> Process.exit(socket.pid, :kill) end)
    assert_receive {WebSocket, ^socket, %Open{}}, 5_000
    %{generation: generation, socket: tcp} = :sys.get_state(socket.pid)

    send(socket.pid, {:http1_read_closed, make_ref(), tcp})
    send(socket.pid, {:http1_read_closed, generation, make_ref()})
    send(socket.pid, {:http1_read_closed, generation, tcp})

    assert :ok = WebSocket.send(socket, "still-open")
    assert_receive {WebSocket, ^socket, %Message{data: "echo:still-open"}}, 5_000
    refute_receive {WebSocket, ^socket, %Close{}}, 0
    assert :ok = WebSocket.close(socket, 1000, "done")
    assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 5_000
  end

  defp close_peer(parent, terminal) do
    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        active: false,
        ip: {127, 0, 0, 1},
        versions: [:"tlsv1.3"],
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key")
      )

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
        {:ok, tls} = :ssl.handshake(tcp, 5_000)
        request = receive_upgrade(tls)
        [_, key] = Regex.run(~r/Sec-WebSocket-Key: ([^\r]+)\r\n/, request)
        accept = :crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

        :ok =
          :ssl.send(tls, [
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
            Base.encode64(accept),
            "\r\n\r\n"
          ])

        assert {:ok, <<0x88, 0x86, mask::binary-size(4), payload::binary-size(6)>>} =
                 :ssl.recv(tls, 12, 5_000)

        decoded =
          for {byte, index} <- Enum.with_index(:binary.bin_to_list(payload)), into: <<>> do
            <<bxor(byte, :binary.at(mask, rem(index, 4)))>>
          end

        assert decoded == <<1000::16, "done">>
        send(parent, {:peer_received_close, self()})
        receive do: (:reply_close -> :ok)
        :ok = :ssl.send(tls, [<<0x81, 4, "tail">>, terminal_frame(terminal)])
        :ok = :ssl.close(tls)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)

    {peer, port}
  end

  defp terminal_frame(:close), do: <<0x88, 2, 1000::16>>
  defp terminal_frame(:eof), do: <<>>
  defp terminal_frame(:truncated), do: <<0x88, 2, 3>>
  defp terminal_frame(:invalid), do: <<0x88, 2, 1005::16>>

  defp assert_terminal_error(:invalid, socket) do
    assert_receive {WebSocket, ^socket, %Error{reason: :invalid_close_code}}, 5_000
  end

  defp assert_terminal_error(_terminal, socket) do
    refute_receive {WebSocket, ^socket, %Error{}}, 0
  end

  defp tls_pid(%SSL.Socket{pid: pid}), do: pid
  defp tls_pid({:cancellable_ssl, socket, _tcp}), do: tls_pid(socket)
  defp tls_pid({:sslsocket, _, [pid | _]}), do: pid
  defp tls_pid({:sslsocket, _, pid, _, _, _, _, _}), do: pid

  defp wait_for_tls_data(:ex_ssl, pid, monitor, _consumer) do
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5_000
  end

  defp wait_for_tls_data(:ssl, pid, _monitor, consumer) do
    # OTP can retain its TLS process until the next active-once request.
    assert_receive {:trace, ^pid, :send, {:ssl, _, _}, ^consumer}, 5_000
  end

  defp receive_upgrade(socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :ssl.recv(socket, 0, 5_000)
      receive_upgrade(socket, buffer <> data)
    end
  end
end

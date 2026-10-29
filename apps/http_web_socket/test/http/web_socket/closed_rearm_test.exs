defmodule HTTP.WebSocket.ClosedRearmTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  import Bitwise

  alias HTTP.Runtime.Delivery
  alias HTTP.Transport.TCP
  alias HTTP.WebSocket
  alias HTTP.WebSocket.{Connection, Frame, Options}
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}

  @fixtures Path.expand("../../support/fixtures", __DIR__)

  for backend <- [:inet, :socket], blocked? <- [false, true], valid? <- [false, true] do
    test "TCP #{backend} handles a #{if valid?, do: "valid", else: "malformed"} #{if blocked?, do: "backpressured", else: "buffered"} peer Close after deferred EOF" do
      set_tcp_backend(unquote(backend))
      {tcp, port} = closed_tcp()

      {:ok, options} =
        Options.new("ws://127.0.0.1:#{port}/socket", [],
          delivery: :ack,
          max_queue_events: 1,
          close_timeout: 1_000,
          write_timeout: 1_000
        )

      target = %WebSocket{}
      delivery = Delivery.new(options)

      {delivery, ack} =
        if unquote(blocked?) do
          message = %Message{target: target, data: "tail"}
          {:ok, delivery, [{^message, ref}]} = Delivery.push(delivery, message, 11, self())
          {delivery, ref}
        else
          {delivery, nil}
        end

      frame = if unquote(valid?), do: <<0x88, 2, 1000::16>>, else: <<0x88, 2, 1005::16>>
      generation = make_ref()

      state = %Connection{
        options: options,
        owner: self(),
        target: target,
        uri: options.uri,
        transport: TCP,
        socket: tcp,
        http_version: :http1,
        ready_state: WebSocket.open(),
        generation: generation,
        read_close_pending?: true,
        parser: Frame.new_parser(),
        delivery: delivery,
        raw_queue: :queue.from_list([{frame, nil}]),
        raw_bytes: byte_size(frame)
      }

      assert {:noreply, state} =
               Connection.handle_info({:http1_read_closed, generation, tcp}, state)

      state =
        if ack do
          assert state.raw_bytes == byte_size(frame)
          assert is_nil(state.write)
          assert {:reply, :ok, state} = Connection.handle_call({:acknowledge, ack}, nil, state)
          state
        else
          state
        end

      %{worker: worker, monitor: monitor, timer: timer} = state.write

      on_exit(fn ->
        Process.exit(worker, :kill)
        Process.cancel_timer(timer)
        if state.close_timer, do: Process.cancel_timer(elem(state.close_timer, 0))
      end)

      assert_receive {:http1_write, ^worker, {:error, :closed}} = result, 1_000
      # The send can finish before submit/2 installs its monitor.
      assert_receive {:DOWN, ^monitor, :process, ^worker, reason}, 1_000
      assert reason in [:normal, :noproc]
      assert {:stop, :normal, finished} = Connection.handle_info(result, state)
      assert finished.transport == nil
      assert finished.socket == nil
      assert finished.write == nil

      if unquote(valid?) do
        assert_receive {WebSocket, ^target, %Close{code: 1000, was_clean: true}}
        refute_receive {WebSocket, ^target, %Error{}}, 0
      else
        assert_receive {WebSocket, ^target, %Error{reason: :invalid_close_code}}
        assert_receive {WebSocket, ^target, %Close{code: 1006, was_clean: false}}
      end
    end
  end

  test "deferred EOF waits for delivery ACK without scheduling another read" do
    {tcp, port} = closed_tcp()

    {:ok, options} = Options.new("ws://127.0.0.1:#{port}/socket", [], delivery: :ack)
    target = %WebSocket{}
    message = %Message{target: target, data: "tail"}
    {:ok, delivery, [{^message, ref}]} = Delivery.push(Delivery.new(options), message, 11, self())
    generation = make_ref()

    state = %Connection{
      options: options,
      owner: self(),
      target: target,
      transport: TCP,
      socket: tcp,
      http_version: :http1,
      ready_state: WebSocket.open(),
      generation: generation,
      read_close_pending?: true,
      parser: Frame.new_parser(),
      delivery: delivery
    }

    assert {:noreply, state} =
             Connection.handle_info({:http1_read_closed, generation, tcp}, state)

    refute_receive {:http1_read_closed, _, _}, 0
    assert {:stop, :normal, :ok, _} = Connection.handle_call({:acknowledge, ref}, nil, state)
    assert_receive {WebSocket, ^target, %Close{code: 1006, was_clean: false}}
  end

  for backend <- [nil, :ex_ssl], terminal <- [:close, :eof, :truncated, :invalid] do
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

  for backend <- [:inet, :socket], terminal <- [:close, :eof, :truncated, :invalid] do
    @tag tcp_backend: backend
    test "TCP #{backend} processes queued #{terminal} frames after the native socket closes" do
      set_tcp_backend(unquote(backend))
      terminal = unquote(terminal)
      {peer, port} = close_peer(self(), terminal, :gen_tcp)
      socket = WebSocket.new("ws://127.0.0.1:#{port}/socket")
      on_exit(fn -> Process.exit(socket.pid, :kill) end)
      assert_receive {WebSocket, ^socket, %Open{}}, 5_000
      %{generation: generation, socket: tcp} = :sys.get_state(socket.pid)
      consumer = socket.pid
      {native, native_type} = tcp_actor(tcp)

      native_monitor =
        if native_type == :port, do: :inet.monitor(tcp), else: Process.monitor(native)

      writer_supervisor = Process.whereis(:http_runtime_task_supervisor)
      :erlang.trace(consumer, true, [:send])
      :erlang.trace(writer_supervisor, true, [:send, :set_on_spawn])
      :erlang.trace(native, true, [:send])
      token = make_ref()
      :ok = park_after_close(consumer, self(), token)
      close_task = Task.async(fn -> WebSocket.close(socket, 1000, "done") end)
      on_exit(fn -> Process.exit(close_task.pid, :kill) end)

      try do
        # The reply barrier follows retained writer admission and precedes the
        # next mailbox receive, so ACK and final data remain queued together.
        assert_receive {:close_parked, ^token, writer}, 5_000
        assert_receive {:peer_received_close, ^peer}, 5_000

        assert_receive {:trace, ^writer, :send, {:http1_write, ^writer, :ok}, ^consumer},
                       5_000

        send(consumer, {:http1_read_closed, make_ref(), tcp})
        send(consumer, {:http1_read_closed, generation, make_ref()})
        send(peer, :reply_close)
        assert_receive {:trace, ^native, :send, {:tcp, ^tcp, _}, ^consumer}, 5_000

        # Model the next read credit with final data queued and the owner paused.
        # Native socket death proves this is EOF, not an invalid live option.
        assert :ok = :inet.setopts(tcp, active: :once)
        assert_receive {:DOWN, ^native_monitor, ^native_type, ^native, _}, 5_000
        assert_tcp_exited(native)
        assert {:error, :einval} = :inet.setopts(tcp, active: :once)
        {:messages, pending} = Process.info(consumer, :messages)
        write_index = Enum.find_index(pending, &match?({:http1_write, _, :ok}, &1))
        data_index = Enum.find_index(pending, &match?({:tcp, ^tcp, _}, &1))
        assert is_integer(write_index) and is_integer(data_index)
        assert write_index < data_index
      after
        send(consumer, {:release_close, token})
        :erlang.trace(consumer, false, [:send])
        :erlang.trace(writer_supervisor, false, [:send, :set_on_spawn])
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

  for backend <- [:inet, :socket] do
    test "invalid options on live TCP #{backend} retain errors without closing the connection" do
      set_tcp_backend(unquote(backend))
      {:ok, _peer, port} = HTTPWebSocket.TestServer.start_link()
      socket = WebSocket.new("ws://127.0.0.1:#{port}/socket")
      on_exit(fn -> Process.exit(socket.pid, :kill) end)
      assert_receive {WebSocket, ^socket, %Open{}}, 5_000
      %{socket: tcp} = :sys.get_state(socket.pid)

      assert {:error, :einval} = TCP.setopts(tcp, active: :invalid)
      {native, native_type} = tcp_actor(tcp)

      assert if(native_type == :port,
               do: is_list(:erlang.port_info(native)),
               else: Process.alive?(native)
             )

      assert :ok = TCP.setopts(tcp, active: :once)
      assert :ok = WebSocket.send(socket, "still-open")
      assert_receive {WebSocket, ^socket, %Message{data: "echo:still-open"}}, 5_000
      refute_receive {WebSocket, ^socket, %Error{}}, 0
      refute_receive {WebSocket, ^socket, %Close{}}, 0
      assert :ok = WebSocket.close(socket, 1000, "done")
      assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 5_000
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

  defp park_after_close(consumer, parent, token) do
    callback = fn
      :armed, {:out, :ok, _, %{ready_state: 2, write: %{worker: worker}}}, _ ->
        send(parent, {:close_parked, token, worker})

        receive do
          {:release_close, ^token} -> :done
        after
          5_000 -> :done
        end

      :armed, _, _ ->
        :armed
    end

    :sys.install(consumer, {callback, :armed})
  end

  defp close_peer(parent, terminal, transport \\ :ssl) do
    {:ok, listener} = listen_peer(transport)

    {:ok, {_, port}} =
      if transport == :ssl, do: :ssl.sockname(listener), else: :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = accept_peer(transport, listener)
        request = receive_upgrade(transport, socket)
        [_, key] = Regex.run(~r/Sec-WebSocket-Key: ([^\r]+)\r\n/, request)
        accept = :crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

        :ok =
          transport.send(socket, [
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
            Base.encode64(accept),
            "\r\n\r\n"
          ])

        assert {:ok, <<0x88, 0x86, mask::binary-size(4), payload::binary-size(6)>>} =
                 transport.recv(socket, 12, 5_000)

        decoded =
          for {byte, index} <- Enum.with_index(:binary.bin_to_list(payload)), into: <<>> do
            <<bxor(byte, :binary.at(mask, rem(index, 4)))>>
          end

        assert decoded == <<1000::16, "done">>
        send(parent, {:peer_received_close, self()})
        receive do: (:reply_close -> :ok)
        :ok = transport.send(socket, [<<0x81, 4, "tail">>, terminal_frame(terminal)])
        :ok = transport.close(socket)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      transport.close(listener)
    end)

    {peer, port}
  end

  defp listen_peer(:ssl) do
    :ssl.listen(0,
      mode: :binary,
      active: false,
      ip: {127, 0, 0, 1},
      versions: [:"tlsv1.3"],
      certfile: Path.join(@fixtures, "localhost.pem"),
      keyfile: Path.join(@fixtures, "localhost.key")
    )
  end

  defp listen_peer(:gen_tcp),
    do: :gen_tcp.listen(0, [{:inet_backend, :inet}, :binary, active: false, ip: {127, 0, 0, 1}])

  defp accept_peer(:ssl, listener) do
    with {:ok, tcp} <- :ssl.transport_accept(listener, 5_000), do: :ssl.handshake(tcp, 5_000)
  end

  defp accept_peer(:gen_tcp, listener), do: :gen_tcp.accept(listener, 5_000)

  defp set_tcp_backend(backend) do
    key = {:kernel, :inet_backend}
    previous = :persistent_term.get(key, :undefined)
    :persistent_term.put(key, backend)

    on_exit(fn ->
      if previous == :undefined,
        do: :persistent_term.erase(key),
        else: :persistent_term.put(key, previous)
    end)
  end

  defp closed_tcp do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false])
    {:ok, {_, port}} = :inet.sockname(listener)
    {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    {:ok, peer} = :gen_tcp.accept(listener)
    :ok = :gen_tcp.close(peer)
    :ok = :gen_tcp.close(tcp)
    :ok = :gen_tcp.close(listener)
    {tcp, port}
  end

  defp tcp_actor(socket) when is_port(socket), do: {socket, :port}
  defp tcp_actor({:"$inet", :gen_tcp_socket, {pid, _socket}}), do: {pid, :process}

  defp assert_tcp_exited(socket) when is_port(socket),
    do: assert(:undefined == :erlang.port_info(socket))

  defp assert_tcp_exited(pid), do: refute(Process.alive?(pid))

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

  defp wait_for_tls_data(backend, pid, monitor, _consumer) when backend in [nil, :ex_ssl] do
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5_000
  end

  defp receive_upgrade(transport, socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = transport.recv(socket, 0, 5_000)
      receive_upgrade(transport, socket, buffer <> data)
    end
  end
end

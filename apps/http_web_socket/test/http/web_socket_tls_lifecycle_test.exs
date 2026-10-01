defmodule HTTP.WebSocketTLSLifecycleTest do
  use ExUnit.Case, async: false

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.Close
  alias HTTP.WebSocket.Event.Message
  alias HTTP.WebSocket.Event.Open

  @fixtures Path.expand("../support/fixtures", __DIR__)

  for backend <- [:ssl, :ex_ssl], terminal <- [:eof, :close] do
    test "delivers validated Upgrade bytes when #{backend} closes before ownership transfer with #{terminal}" do
      parent = self()

      {peer, port} = upgrade_peer(parent, false, unquote(terminal))

      peer_monitor = Process.monitor(peer)

      socket =
        WebSocket.new("wss://localhost:#{port}/socket", [],
          tls_backend: unquote(backend),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
        )

      on_exit(fn ->
        if Process.alive?(socket.pid), do: Process.exit(socket.pid, :kill)
      end)

      socket_monitor = Process.monitor(socket.pid)
      assert_receive {:upgrade_requested, ^peer}, 5_000
      %{worker: worker} = :sys.get_state(socket.pid)
      worker_monitor = Process.monitor(worker)
      :erlang.trace(worker, true, [:send])
      :ok = :sys.suspend(socket.pid)

      try do
        send(peer, :send_upgrade)

        assert_receive {:trace, ^worker, :send,
                        {:http1_ready, _generation, ^worker, _transport, tls}, pid},
                       5_000

        assert pid == socket.pid

        if unquote(backend) == :ex_ssl do
          tls_monitor = Process.monitor(tls_pid(tls))
          assert_receive {:DOWN, ^tls_monitor, :process, _, reason}, 5_000
          assert reason in [:normal, :noproc]
        else
          assert_receive {:DOWN, ^peer_monitor, :process, ^peer, reason}, 5_000
          assert reason in [:normal, :noproc]
        end
      after
        :erlang.trace(worker, false, [:send])
        :sys.resume(socket.pid)
      end

      assert %Open{} = next_event(socket)
      assert %Message{data: "bye"} = next_event(socket)
      expected_code = if unquote(terminal) == :close, do: 1000, else: 1006
      assert %Close{code: ^expected_code, was_clean: clean?} = next_event(socket)
      assert clean? == (unquote(terminal) == :close)
      assert_receive {:DOWN, ^socket_monitor, :process, _, :normal}, 5_000
      assert_receive {:DOWN, ^worker_monitor, :process, ^worker, :normal}, 5_000
    end
  end

  for completion <- [:success, :cancel, :timeout] do
    test "preserves transferred TLS bytes and pending-opening #{completion}" do
      {peer, port} = upgrade_peer(self(), true)

      socket =
        WebSocket.new("wss://localhost:#{port}/socket", [],
          tls_backend: :ex_ssl,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
        )

      on_exit(fn ->
        if Process.alive?(socket.pid), do: Process.exit(socket.pid, :kill)
      end)

      socket_monitor = Process.monitor(socket.pid)
      assert_receive {:upgrade_requested, ^peer}, 5_000
      %{worker: worker} = :sys.get_state(socket.pid)
      worker_monitor = Process.monitor(worker)
      :erlang.trace(worker, true, [:send])
      :ok = :sys.suspend(socket.pid)
      send(peer, :send_upgrade)

      assert_receive {:trace, ^worker, :send,
                      {:http1_ready, _generation, ^worker, transport, tls}, pid},
                     5_000

      assert pid == socket.pid
      tls_pid = tls_pid(tls)
      :ok = :sys.suspend(tls_pid)
      send(worker, :transfer)

      assert_receive {:trace, ^worker, :send, {:"$gen_call", _, _}, ^tls_pid}, 5_000
      true = :erlang.suspend_process(worker)

      try do
        :ok = :sys.resume(tls_pid)
        {:connected, %{owner: owner}} = :sys.get_state(tls_pid)
        assert owner == socket.pid
        :ok = transport.setopts(tls, active: :once)
        tls_monitor = Process.monitor(tls_pid)
        send(peer, :send_tail)
        assert_receive {:DOWN, ^tls_monitor, :process, ^tls_pid, :normal}, 5_000
        :ok = :sys.resume(socket.pid)
        assert %{worker: ^worker, raw_bytes: 6, remote_end?: true} = :sys.get_state(socket.pid)
        refute_receive {WebSocket, ^socket, _}, 0

        if unquote(completion) != :success do
          send(socket.pid, {:ssl_error, tls, :econnreset})
          pending = :sys.get_state(socket.pid)
          assert pending.ready_state == WebSocket.connecting()

          case unquote(completion) do
            :cancel ->
              assert :ok = WebSocket.close(socket)

            :timeout ->
              {_timer, token} = pending.opening_timer
              send(socket.pid, {:opening_timeout, token})
          end
        end

        if unquote(completion) == :success do
          :erlang.trace(worker, false, [:send])
          true = :erlang.resume_process(worker)
        end

        case unquote(completion) do
          :success ->
            assert %Open{} = next_event(socket)
            assert %Message{data: "bye"} = next_event(socket)
            assert %Message{data: "tail"} = next_event(socket)

          :timeout ->
            assert %HTTP.WebSocket.Event.Error{reason: :timeout} = next_event(socket)

          :cancel ->
            :ok
        end

        assert %Close{code: 1006, was_clean: false} = next_event(socket)
        assert_receive {:DOWN, ^socket_monitor, :process, _, :normal}, 5_000
        assert_receive {:DOWN, ^worker_monitor, :process, ^worker, worker_reason}, 5_000
        assert worker_reason == if(unquote(completion) == :success, do: :normal, else: :killed)
        refute_receive {WebSocket, ^socket, _}, 0
      after
        Process.exit(worker, :kill)
        Process.exit(socket.pid, :kill)
        Process.exit(tls_pid, :kill)
      end
    end
  end

  test "delivers upgrade-buffered frames after the TLS peer has closed" do
    parent = self()
    existing_connections = tls_connections()

    {:ok, server, port} =
      HTTPWebSocket.TestServer.start_link(
        tls: true,
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        # A complete text frame and close frame share the upgrade's TLS record.
        upgrade_frames: <<0x81, 3, "bye", 0x88, 2, 1000::16>>,
        close_after_upgrade: true
      )

    handler = {__MODULE__, make_ref()}

    :ok =
      :telemetry.attach(
        handler,
        [:http_web_socket, :connect, :stop],
        &__MODULE__.pause_after_upgrade/4,
        {port, parent}
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    socket =
      WebSocket.new("wss://127.0.0.1:#{port}/socket", [],
        tls_backend: :ex_ssl,
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
      )

    assert_receive {:upgrade_received, consumer}, 5_000
    [tls_pid] = tls_connections() -- existing_connections
    monitor = Process.monitor(tls_pid)

    try do
      send(server, :close_tls)
      assert_receive {:DOWN, ^monitor, :process, ^tls_pid, _}, 5_000
    after
      send(consumer, :continue_upgrade)
    end

    assert_receive {WebSocket, ^socket, %Open{}}, 5_000
    assert_receive {WebSocket, ^socket, %Message{data: "bye"}}, 5_000
    assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 5_000
  end

  def pause_after_upgrade(_event, _measurements, %{port: port}, {port, parent}) do
    send(parent, {:upgrade_received, self()})

    receive do
      :continue_upgrade -> :ok
    after
      5_000 -> :ok
    end
  end

  def pause_after_upgrade(_event, _measurements, _metadata, _config), do: :ok

  defp tls_connections do
    for {_, pid, _, _} <- DynamicSupervisor.which_children(SSL.ConnectionSupervisor), do: pid
  end

  defp next_event(socket) do
    assert_receive {WebSocket, ^socket, event}, 5_000
    event
  end

  defp upgrade_peer(parent, split?, terminal \\ :eof) do
    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        ip: {127, 0, 0, 1},
        versions: [:"tlsv1.3"],
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key")
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
        {:ok, tls} = :ssl.handshake(tcp, 5_000)
        request = upgrade_request(tls)
        send(parent, {:upgrade_requested, self()})
        receive do: (:send_upgrade -> :ok)

        key = upgrade_key(request)

        accept =
          :crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11") |> Base.encode64()

        :ok =
          :ssl.send(tls, [
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
            accept,
            "\r\n\r\n",
            <<0x81, 3, "bye">>,
            if(terminal == :close, do: <<0x88, 2, 1000::16>>, else: <<>>)
          ])

        if split? do
          receive do: (:send_tail -> :ok)
          :ok = :ssl.send(tls, <<0x81, 4, "tail">>)
        end

        :ssl.close(tls)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)

    {peer, port}
  end

  defp upgrade_key(request) do
    request
    |> String.split("\r\n")
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] ->
          if String.downcase(name) == "sec-websocket-key", do: String.trim(value)

        _ ->
          nil
      end
    end)
  end

  defp tls_pid(%SSL.Socket{pid: pid}), do: pid
  defp tls_pid({:sslsocket, _, [pid | _]}), do: pid
  defp tls_pid({:sslsocket, _, pid, _, _, _, _, _}), do: pid

  defp upgrade_request(socket, buffer \\ "") do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, data} = :ssl.recv(socket, 0, 5_000)
      upgrade_request(socket, buffer <> data)
    end
  end
end

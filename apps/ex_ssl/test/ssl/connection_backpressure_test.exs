defmodule SSL.ConnectionBackpressureTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer

  @moduletag :integration
  @payload_size 16 * 1_048_576

  test "real TCP backpressure recovers without replay across a requested KeyUpdate" do
    parent = self()
    peer_ready_ref = make_ref()
    payload = :binary.copy("k", @payload_size)

    {:ok, peer} =
      Peer.start(fn socket ->
        send(parent, {:backpressure_peer_ready, peer_ready_ref})

        receive do
          :request_update -> :ok
        end

        send(parent, :backpressure_key_update_started)
        update_result = :ssl.update_keys(socket, :read_write)
        send(parent, {:backpressure_key_update, update_result})
        result = :ssl.recv(socket, byte_size(payload), 30_000)
        send(parent, {:backpressure_payload, result})
        assert :ok = :ssl.send(socket, "recovered")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      assert_receive {:backpressure_proxy, ^proxy_ref, :ready}, 1_000
      assert_receive {:backpressure_peer_ready, ^peer_ready_ref}, 5_000
      assert :ok = Peer.pause_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000

      sender = Task.async(fn -> SSL.send(socket, payload) end)
      assert_receive {:backpressure_proxy, ^proxy_ref, :held, held}, 5_000
      assert held > 0
      assert_writer_is_socket_blocked(socket, sender)

      send(peer.task.pid, :request_update)
      assert_receive :backpressure_key_update_started, 5_000
      wait_for_pending_input(socket.pid)
      assert :ok = Peer.resume_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^proxy_ref, :resumed}, 1_000

      assert :ok = Task.await(sender, 30_000)
      assert_receive {:backpressure_key_update, :ok}, 5_000
      assert_receive {:backpressure_payload, {:ok, ^payload}}, 30_000
      assert {:ok, "recovered"} = SSL.recv(socket, 9, 5_000)
      assert :ok = SSL.close(socket)
      assert :ok = Peer.stop(peer)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  test "close cancels an infinite-timeout write blocked by real TCP backpressure" do
    parent = self()
    peer_ready_ref = make_ref()
    payload = :binary.copy("c", @payload_size)

    {:ok, peer} =
      Peer.start(fn socket ->
        send(parent, {:backpressure_peer_ready, peer_ready_ref})

        case :ssl.recv(socket, byte_size(payload), 30_000) do
          {:ok, _bytes} -> :unexpected_complete_payload
          {:error, _reason} -> :closed
        end
      end)

    {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())
    proxy_ref = proxy.ref

    try do
      socket = connect(proxy.port, send_timeout: :infinity)
      assert_receive {:backpressure_proxy, ^proxy_ref, :ready}, 1_000
      assert_receive {:backpressure_peer_ready, ^peer_ready_ref}, 5_000
      assert :ok = Peer.pause_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000

      {:connected, state} = :sys.get_state(socket.pid)
      connection_monitor = Process.monitor(socket.pid)
      writer_monitor = Process.monitor(state.writer)
      sender = Task.async(fn -> SSL.send(socket, payload) end)
      assert_receive {:backpressure_proxy, ^proxy_ref, :held, _held}, 5_000
      assert_writer_is_socket_blocked(socket, sender)

      started = System.monotonic_time(:millisecond)
      assert :ok = SSL.close(socket)
      assert System.monotonic_time(:millisecond) - started < 1_000
      assert {:error, :closed} = Task.await(sender, 1_000)
      assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
      assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
      _ = Peer.stop_backpressure_proxy(proxy)
      _ = :ssl.close(peer.listener)
      _ = Task.shutdown(peer.task, :brutal_kill)
      refute Process.alive?(peer.task.pid)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  for mode <- [:passive, :once], finish <- [:deadline, :close, :terminate] do
    test "#{mode} response drainage with real queued output has bounded #{finish} cleanup" do
      assert_backlog_cleanup(unquote(mode), unquote(finish))
    end
  end

  defp assert_backlog_cleanup(mode, finish) do
    parent = self()
    response = "upload rejected before body drain"
    backlog = :binary.copy("q", @payload_size)

    {:ok, peer} =
      Peer.start(fn socket ->
        send(parent, :backlog_peer_ready)

        receive do
          :reject_upload -> :ok
        end

        assert :ok = :ssl.send(socket, response)
        send(parent, :backlog_peer_closed)
        assert :ok = :ssl.close(socket)

        receive do
          :cleanup -> :ok
        end
      end)

    {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self(), hold_upstream_close: true)
    proxy_ref = proxy.ref
    socket = connect(proxy.port, send_timeout: :infinity)
    {:connected, initial} = :sys.get_state(socket.pid)
    watchdog = start_cleanup_watchdog(socket.pid)

    try do
      assert_receive {:backpressure_proxy, ^proxy_ref, :ready}, 1_000
      assert_receive :backlog_peer_ready, 5_000
      connection_monitor = Process.monitor(socket.pid)
      writer_monitor = Process.monitor(initial.writer)
      assert :ok = Peer.pause_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000

      # This test-only raw filler creates a real inet send backlog. The proxy
      # never forwards it; authenticated TLS response traffic still flows in
      # the server-to-client direction.
      filler = Task.async(fn -> :gen_tcp.send(initial.tcp, backlog) end)
      assert_receive {:backpressure_proxy, ^proxy_ref, :held, held}, 5_000
      assert held > 0
      assert_send_pend(initial.tcp)

      assert true = :erlang.suspend_process(initial.writer)
      send(peer.task.pid, :reject_upload)
      assert_receive :backlog_peer_closed, 5_000

      settled = wait_for_peer_close_output(socket.pid)
      assert settled.size == byte_size(response)
      assert settled.output.kind == :close_notify
      assert is_reference(settled.output.timer)
      queued_bytes = send_pend(initial.tcp)
      assert queued_bytes > 0
      assert Process.alive?(proxy.controller)

      started = System.monotonic_time(:millisecond)

      case mode do
        :passive ->
          assert {:ok, ^response} = SSL.recv(socket, byte_size(response), 1_000)

        :once ->
          assert :ok = SSL.setopts(socket, active: :once)
          assert_receive {:ssl, ^socket, ^response}, 1_000
      end

      assert Process.alive?(socket.pid)
      {:connected, draining} = :sys.get_state(socket.pid, 750)
      assert draining.closed
      assert draining.size == 0
      assert is_port(draining.tcp)
      assert draining.output.kind == :close_notify

      case finish do
        :deadline -> :ok
        :close -> assert :ok = SSL.close(socket)
        :terminate -> assert :ok = :sys.terminate(socket.pid, :shutdown, 750)
      end

      reason = if finish == :terminate, do: :shutdown, else: :normal
      assert_receive {:DOWN, ^connection_monitor, :process, _, ^reason}, 750
      assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 750
      elapsed = System.monotonic_time(:millisecond) - started
      assert elapsed < 750, "cleanup took #{elapsed} ms with #{queued_bytes} queued bytes"
      assert Port.info(initial.tcp) == nil
      assert Process.read_timer(settled.output.timer) == false
      assert {:error, :closed} = SSL.recv(socket, 0, 1_000)

      if mode == :once and finish == :deadline do
        assert_receive {:ssl_closed, ^socket}, 1_000
        refute_receive {:ssl, ^socket, _}, 0
        refute_receive {:ssl_closed, ^socket}, 0
      end

      assert :ok = Task.await(filler, 1_000)
      assert :ok = SSL.close(socket)
      _ = Peer.stop_backpressure_proxy(proxy)
      send(peer.task.pid, :cleanup)
      assert :ok = Peer.stop(peer)
    after
      send(watchdog, :done)
      resume_connection(socket.pid)
      resume_if_suspended(initial.writer)
      if Process.alive?(socket.pid), do: Process.exit(socket.pid, :kill)
      if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
      stop_peer_on_failure(peer)
    end
  end

  defp assert_writer_is_socket_blocked(socket, sender) do
    wait_for_output(socket.pid)
    deadline = System.monotonic_time(:millisecond) + 5_000
    wait_for_stable_output(socket, sender, deadline)
  end

  defp wait_for_stable_output(socket, sender, deadline) do
    {:connected, first} = :sys.get_state(socket.pid)
    token = first.output.token
    writer = first.writer
    Process.send_after(self(), {:backpressure_watchdog, token}, 50)

    assert_receive {:backpressure_watchdog, ^token}, 1_000
    assert Task.yield(sender, 0) == nil
    {:connected, second} = :sys.get_state(socket.pid)

    if second.output.token == token do
      assert Process.alive?(writer)

      assert Process.info(writer, :current_function) !=
               {:current_function, {SSL.ConnectionWriter, :loop, 2}}
    else
      assert System.monotonic_time(:millisecond) < deadline
      wait_for_stable_output(socket, sender, deadline)
    end
  end

  defp wait_for_output(pid, attempts \\ 5_000)
  defp wait_for_output(_pid, 0), do: flunk("connection writer never became pending")

  defp wait_for_output(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{output: %{kind: :application}}} ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_output(pid, attempts - 1)
    end
  end

  defp wait_for_pending_input(pid, attempts \\ 1_000)
  defp wait_for_pending_input(_pid, 0), do: flunk("KeyUpdate was not queued behind output")

  defp wait_for_pending_input(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{input_size: size}} when size > 0 ->
        :ok

      _ ->
        Process.sleep(1)
        wait_for_pending_input(pid, attempts - 1)
    end
  end

  defp assert_send_pend(tcp) do
    deadline = System.monotonic_time(:millisecond) + 5_000
    wait_for_send_pend(tcp, deadline)
  end

  defp wait_for_send_pend(tcp, deadline) do
    if send_pend(tcp) > 0 do
      :ok
    else
      if System.monotonic_time(:millisecond) < deadline do
        Process.sleep(1)
        wait_for_send_pend(tcp, deadline)
      else
        flunk("real inet socket output never became pending")
      end
    end
  end

  defp send_pend(tcp) do
    case :inet.getstat(tcp, [:send_pend]) do
      {:ok, stats} -> Keyword.fetch!(stats, :send_pend)
      {:error, _reason} -> 0
    end
  end

  defp wait_for_peer_close_output(pid, attempts \\ 5_000)

  defp wait_for_peer_close_output(_pid, 0),
    do: flunk("peer close_notify did not start shutdown output")

  defp wait_for_peer_close_output(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{closed: true, output: %{kind: :close_notify}} = state} ->
        state

      _ ->
        Process.sleep(1)
        wait_for_peer_close_output(pid, attempts - 1)
    end
  end

  defp resume_if_suspended(writer) do
    if Process.alive?(writer), do: :erlang.resume_process(writer)
  rescue
    ArgumentError -> :ok
  end

  defp resume_connection(pid) do
    if Process.alive?(pid), do: :sys.resume(pid, 50)
  catch
    :exit, _reason -> :ok
  end

  defp start_cleanup_watchdog(connection) do
    spawn(fn ->
      receive do
        :done -> :ok
      after
        2_000 ->
          if Process.alive?(connection), do: Process.exit(connection, :kill)
      end
    end)
  end

  defp connect(port, extra_options) do
    options = [:binary | Keyword.merge(tl(Peer.client_options()), extra_options)]
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", port, options, 5_000)
    socket
  end

  defp stop_peer_on_failure(peer) do
    if Process.alive?(peer.task.pid) do
      _ = :ssl.close(peer.listener)
      _ = Task.shutdown(peer.task, 1_000)
    end
  end
end

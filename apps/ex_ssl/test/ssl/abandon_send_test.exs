defmodule SSL.AbandonSendTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer

  @moduletag :integration
  @payload :binary.copy("x", 16 * 1_048_576)

  for abandon? <- [false, true] do
    test "explicit abandon=#{abandon?} preserves the default sender-death boundary" do
      parent = self()

      {:ok, peer} =
        Peer.start(fn socket ->
          send(parent, :peer_ready)

          receive do
            :respond ->
              assert :ok = :ssl.send(socket, "retained-response")
          end

          receive do
            :finish -> :ok
          end
        end)

      {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())

      on_exit(fn ->
        if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
        if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
        :ssl.close(peer.listener)
      end)

      options = [:binary | Keyword.merge(tl(Peer.client_options()), send_timeout: 5_000)]
      {:ok, socket} = SSL.connect(~c"127.0.0.1", proxy.port, options, 5_000)
      connection_monitor = Process.monitor(socket.pid)
      assert_receive :peer_ready, 5_000
      :ok = Peer.pause_client_to_server(proxy, self())
      proxy_ref = proxy.ref
      assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000

      {sender, sender_monitor} =
        spawn_monitor(fn -> send(parent, {:send_result, SSL.send(socket, @payload)}) end)

      state = pending_record(socket.pid, System.monotonic_time(:millisecond) + 2_000)
      assert state.output.size <= 16_406

      if unquote(abandon?) do
        assert :ok = SSL.abandon_send(socket)
        assert_receive {:send_result, {:error, :write_abandoned}}, 1_000
        assert_receive {:DOWN, ^sender_monitor, :process, ^sender, :normal}, 1_000
        {:connected, abandoned} = :sys.get_state(socket.pid)
        assert abandoned.write_abandoned?
        assert abandoned.write == nil
        assert abandoned.output == state.output
        assert Process.read_timer(state.write.timer) == false
        assert is_integer(Process.read_timer(state.output.timer))
        assert {:error, :closed} = SSL.send(socket, "must-never-write")
        outsider = Task.async(fn -> SSL.abandon_send(socket) end)
        assert {:error, :not_owner} = Task.await(outsider)
        send(peer.task.pid, :respond)
        assert {:ok, "retained-response"} = SSL.recv(socket, 0, 1_000)
        # No pending-record completion was needed to authenticate these bytes.
        {:connected, read_state} = :sys.get_state(socket.pid)
        assert read_state.output == state.output
        assert :ok = SSL.close(socket)
      else
        Process.exit(sender, :kill)
        assert_receive {:DOWN, ^sender_monitor, :process, ^sender, :killed}, 1_000
      end

      assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
      assert :erlang.port_info(state.tcp) == :undefined
      expected = if unquote(abandon?), do: :closed, else: :econnreset
      assert {:error, ^expected} = SSL.recv(socket, 0, 1_000)
    end
  end

  test "duplex admission is owner-only, idempotent and requires finite future sends" do
    {socket, _peer} = held_peer()
    outsider = Task.async(fn -> SSL.enable_duplex_reads(socket) end)
    assert {:error, :not_owner} = Task.await(outsider)
    assert :ok = SSL.setopts(socket, send_timeout: :infinity)
    assert {:error, :infinite_send_timeout} = SSL.enable_duplex_reads(socket)
    assert :ok = SSL.setopts(socket, send_timeout: 2_000)
    assert :ok = SSL.enable_duplex_reads(socket)
    assert :ok = SSL.enable_duplex_reads(socket)
    assert :ok = SSL.setopts(socket, send_timeout: :infinity)
    assert {:error, :infinite_send_timeout} = SSL.send(socket, "forbidden")
    assert :ok = SSL.abandon_send(socket)
    assert :ok = SSL.abandon_send(socket)
    assert {:error, :closed} = SSL.enable_duplex_reads(socket)
    assert {:error, :closed} = SSL.send(socket, "still-forbidden")
  end

  for request <- [:write, :read_write] do
    test "duplex receives KeyUpdate #{request} while an immutable application job is held" do
      {socket, peer} = held_peer()
      assert :ok = SSL.enable_duplex_reads(socket)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert :erlang.suspend_process(initial.writer)
      sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 65_536)) end)
      pending = held_output(socket.pid, System.monotonic_time(:millisecond) + 1_000)
      send(peer.task.pid, {:update, unquote(request)})

      if unquote(request) == :write do
        assert {:ok, "after-update"} = SSL.recv(socket, 0, 1_000)
        {:connected, received} = :sys.get_state(socket.pid)
        assert received.output == pending.output
        assert received.machine.read_state.generation == initial.machine.read_state.generation + 1
        assert received.machine.write_state == pending.machine.write_state
        assert :ok = SSL.abandon_send(socket)
        assert {:error, :write_abandoned} = Task.await(sender, 1_000)
        assert :ok = SSL.close(socket)
      else
        # The requested reciprocal update must not overtake or rebuild the
        # protected application job; the existing busy writer fails closed.
        assert {:error, :busy} = Task.await(sender, 1_000)
        assert {:error, :econnreset} = SSL.recv(socket, 0, 1_000)
      end
    end
  end

  test "abandon rejects retaining an output with no finite timer" do
    {socket, _peer} = held_peer()
    assert :ok = SSL.setopts(socket, send_timeout: :infinity)
    {:connected, initial} = :sys.get_state(socket.pid)
    assert :erlang.suspend_process(initial.writer)
    sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 65_536)) end)
    pending = held_output(socket.pid, System.monotonic_time(:millisecond) + 1_000)
    assert pending.output.timer == nil
    assert :ok = SSL.setopts(socket, send_timeout: 2_000)
    assert {:error, :infinite_send_timeout} = SSL.enable_duplex_reads(socket)
    assert {:error, :infinite_send_timeout} = SSL.abandon_send(socket)
    {:connected, unchanged} = :sys.get_state(socket.pid)
    assert unchanged.output == pending.output
    refute unchanged.write_abandoned?
    assert :ok = SSL.close(socket)
    assert {:error, :closed} = Task.await(sender, 1_000)
  end

  defp held_peer do
    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          {:update, mode} ->
            assert :ok = :ssl.update_keys(socket, mode)
            if mode == :write, do: assert(:ok == :ssl.send(socket, "after-update"))

          :finish ->
            :ok
        end

        receive do
          :finish -> :ok
        end
      end)

    options = [:binary | Keyword.merge(tl(Peer.client_options()), send_timeout: 2_000)]
    {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)

    on_exit(fn ->
      if Process.alive?(socket.pid), do: SSL.close(socket)
      if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end)

    {socket, peer}
  end

  defp held_output(pid, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case :sys.get_state(pid) do
      {:connected, %{output: %{kind: :application}} = state} ->
        state

      _ ->
        receive do
        after
          1 -> held_output(pid, deadline)
        end
    end
  end

  defp pending_record(pid, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case :sys.get_state(pid) do
      {:connected, %{output: %{kind: :application} = output} = state} ->
        case :inet.getstat(state.tcp, [:send_pend]) do
          {:ok, [{:send_pend, count}]} when count > 0 ->
            token = output.token

            receive do
            after
              20 -> :ok
            end

            case :sys.get_state(pid) do
              {:connected, %{output: %{token: ^token}}} -> state
              _ -> pending_record(pid, deadline)
            end

          _ ->
            receive do
            after
              1 -> pending_record(pid, deadline)
            end
        end

      _ ->
        receive do
        after
          1 -> pending_record(pid, deadline)
        end
    end
  end
end

defmodule SSL.DuplexProtocolBoundsTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.Crypto.TrafficState

  @moduletag :integration

  test "automatic KeyUpdate and application ciphertext remain one immutable bounded job" do
    {socket, _peer, _proxy} = fixture()
    {:connected, initial} = :sys.get_state(socket.pid)
    limit = TrafficState.encryption_limit(initial.machine.write_state.cipher_suite)

    :sys.replace_state(socket.pid, fn {:connected, state} ->
      write = %{state.machine.write_state | sequence: limit - 1}
      {:connected, %{state | machine: %{state.machine | write_state: write}}}
    end)

    {sender, pending} = hold_write(socket)
    assert pending.machine.write_state.generation == initial.machine.write_state.generation + 1
    assert pending.machine.write_state.sequence == 1
    assert pending.output.size <= 16_433
    assert pending.output.size > 16_406
    assert :ok = SSL.abandon_send(socket)
    assert {:error, :write_abandoned} = Task.await(sender, 1_000)
    {:connected, abandoned} = :sys.get_state(socket.pid)
    assert abandoned.output == pending.output
    assert abandoned.machine.write_state == pending.machine.write_state
    assert is_integer(Process.read_timer(abandoned.output.timer))
    assert :ok = SSL.close(socket)
  end

  for fault <- [:malformed, :eof] do
    test "#{fault} while duplex output is held fails closed and settles the sender" do
      {socket, _peer, proxy} = fixture()
      {sender, pending} = hold_write(socket)
      monitor = Process.monitor(socket.pid)
      send(proxy.task.pid, {unquote(fault), self()})
      assert_receive :fault_injected, 1_000
      assert {:error, _reason} = Task.await(sender, 1_000)
      assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1_000
      assert {:error, :econnreset} = SSL.recv(socket, 0, 0)
      assert :erlang.port_info(pending.tcp) == :undefined
    end
  end

  test "authenticated close_notify drains buffered data while output is held" do
    {socket, peer, _proxy} = fixture()
    {sender, pending} = hold_write(socket)
    send(peer.task.pid, :finish)
    assert {:error, :closed} = Task.await(sender, 1_000)
    assert {:ok, "final"} = SSL.recv(socket, 5, 1_000)
    assert {:ok, "-data"} = SSL.recv(socket, 0, 1_000)
    assert {:error, :closed} = SSL.recv(socket, 0, 1_000)
    assert :erlang.port_info(pending.tcp) == :undefined
  end

  defp fixture do
    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :finish ->
            assert :ok = :ssl.send(socket, "final-data")
            :ssl.close(socket)
        end
      end)

    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, downstream} = :gen_tcp.accept(listener, 5_000)

        {:ok, upstream} =
          :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

        :ok = :inet.setopts(downstream, active: :once)
        :ok = :inet.setopts(upstream, active: :once)

        try do
          forward(downstream, upstream)
        after
          :gen_tcp.close(downstream)
          :gen_tcp.close(upstream)
        end
      end)

    options = [:binary | Keyword.merge(tl(Peer.client_options()), send_timeout: 2_000)]
    {:ok, socket} = SSL.connect(~c"127.0.0.1", port, options, 5_000)
    :ok = SSL.enable_duplex_reads(socket)

    on_exit(fn ->
      if Process.alive?(socket.pid), do: SSL.close(socket)
      if Process.alive?(task.pid), do: Task.shutdown(task, :brutal_kill)
      :gen_tcp.close(listener)
      if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end)

    {socket, peer, %{task: task}}
  end

  defp forward(downstream, upstream) do
    receive do
      {:tcp, ^downstream, bytes} ->
        :ok = :gen_tcp.send(upstream, bytes)
        :ok = :inet.setopts(downstream, active: :once)
        forward(downstream, upstream)

      {:tcp, ^upstream, bytes} ->
        :ok = :gen_tcp.send(downstream, bytes)
        :ok = :inet.setopts(upstream, active: :once)
        forward(downstream, upstream)

      {:malformed, caller} ->
        :ok = :gen_tcp.send(downstream, <<23, 3, 3, 65_535::16>>)
        send(caller, :fault_injected)
        forward(downstream, upstream)

      {:eof, caller} ->
        :gen_tcp.close(downstream)
        send(caller, :fault_injected)

      {:tcp_closed, _} ->
        :ok
    after
      5_000 -> flunk("duplex proxy timed out")
    end
  end

  defp hold_write(socket) do
    {:connected, initial} = :sys.get_state(socket.pid)
    assert :erlang.suspend_process(initial.writer)
    sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 65_536)) end)
    {sender, held_output(socket.pid, System.monotonic_time(:millisecond) + 1_000)}
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
end

defmodule SSL.SocketTest do
  use ExUnit.Case, async: true

  alias SSL.{ConnectionWriter, Socket}

  test "the owner constructor and boundary retain the exact handle and terminal state" do
    pid = self()
    ref = make_ref()
    status = :atomics.new(1, [])
    socket = Socket.new(pid, ref, status)

    assert socket.pid == pid
    assert socket.ref == ref
    assert socket.status == status
    assert {:ok, ^socket} = Socket.fetch(socket)
    assert :ok = Socket.mark_terminal(socket, true)
    assert {:ok, ^socket} = Socket.fetch(socket)
    assert :closed = Socket.terminal_error(socket)
  end

  test "a handle remains recognizable after its connection process exits" do
    {pid, monitor} = spawn_monitor(fn -> :ok end)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    socket = Socket.new(pid, make_ref(), :atomics.new(1, []))

    assert {:ok, ^socket} = Socket.fetch(socket)
    assert :ok = SSL.close(socket)
  end

  test "the boundary rejects malformed fields, incomplete structs and other transports" do
    for candidate <- malformed_sockets() ++ [nil, self(), make_ref(), {:"$socket", make_ref()}] do
      assert {:error, :badarg} = Socket.fetch(candidate)
    end
  end

  test "the constructor requires the declared handle field types" do
    socket = Socket.new(self(), make_ref(), :atomics.new(1, []))

    for {pid, ref} <- [{:invalid, socket.ref}, {socket.pid, :invalid}] do
      assert_raise FunctionClauseError, fn ->
        Socket.new(pid, ref, socket.status)
      end
    end

    for status <- invalid_statuses() do
      assert_raise ArgumentError, fn ->
        Socket.new(socket.pid, socket.ref, status)
      end
    end
  end

  test "private carrier writes settle malformed handles with badarg and retain ordering" do
    {writer, monitor} = ConnectionWriter.start(self())
    on_exit(fn -> if Process.alive?(writer), do: Process.exit(writer, :kill) end)

    jobs =
      for deadline <- [:infinity, System.monotonic_time(:millisecond) + 1_000],
          socket <- malformed_sockets() do
        token = make_ref()
        send(writer, {:carrier_send, token, socket, "invalid carrier", false, deadline})
        token
      end

    for token <- jobs do
      assert_receive {:writer_result, ^writer, completed, {:error, :badarg}}, 1_000
      assert completed == token
    end

    assert Process.alive?(writer)
    Process.exit(writer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^writer, :killed}, 1_000
  end

  defp malformed_sockets do
    socket = Socket.new(self(), make_ref(), :atomics.new(1, []))

    [%{socket | pid: :invalid}, %{socket | ref: :invalid}, %{__struct__: Socket}] ++
      Enum.map(invalid_statuses(), &%{socket | status: &1})
  end

  defp invalid_statuses do
    monitor = Process.monitor(self())
    true = Process.demonitor(monitor)
    [:invalid, make_ref(), monitor]
  end
end

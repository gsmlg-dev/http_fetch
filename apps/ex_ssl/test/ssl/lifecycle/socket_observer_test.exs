defmodule SSL.Lifecycle.SocketObserverTest do
  use ExUnit.Case, async: false
  alias SSL.Lifecycle.{Observer, Reader, Receipt}
  @moduletag :integration

  test "original creator enrolls actual socket before connect and observes both DOWNs" do
    {receipt, lease, owner, owner_mon, socket, socket_mon, _token, native, parent} = attempt()
    assert :use = invoke(owner, {:enroll, socket}, native)

    assert {:ok, %{roles: 17, allocations: 0, losses: 0}} =
             Observer.snapshot(receipt, budget(native))

    assert :ok = Observer.cancel(receipt, lease, budget(native))
    assert_receive {:DOWN, ^socket_mon, :socket, ^socket, :closed}, left(parent)
    assert_receive {:DOWN, ^owner_mon, :process, ^owner, _}, left(parent)

    assert {:ok, %{roles: 17, observed_down: 17, cleanup: :confirmed}} =
             Reader.await(receipt, budget(parent))
  end

  test "wrong creator and live or closed foreign sockets leave the original permit pending" do
    {receipt, lease, owner, _owner_mon, socket, _socket_mon, token, native, parent} = attempt()

    assert {:error, :unauthorized_creator} =
             Observer.enroll_socket(receipt, token, socket, budget(native))

    {:ok, foreign} = :socket.open(:inet, :stream, :tcp)
    on_exit(fn -> :socket.close(foreign) end)
    assert {:error, :foreign_or_duplicate_resource} = invoke(owner, {:enroll, foreign}, native)
    :ok = :socket.close(foreign)
    assert {:error, :foreign_or_duplicate_resource} = invoke(owner, {:enroll, foreign}, native)

    assert {:ok, %{roles: 1, allocations: 16, losses: 0}} =
             Observer.snapshot(receipt, budget(native))

    assert :use = invoke(owner, {:enroll, socket}, native)
    assert :ok = Observer.cancel(receipt, lease, budget(native))

    assert {:ok, %{roles: 17, observed_down: 17, cleanup: :confirmed}} =
             Reader.await(receipt, budget(parent))
  end

  test "socket receiver rejects malformed deadlines without consuming the permit" do
    {receipt, lease, owner, _owner_mon, socket, _socket_mon, _token, native, parent} = attempt()
    assert {:error, :invalid_deadline} = invoke(owner, {:raw_socket, socket, :outer}, native)
    assert {:error, :invalid_deadline} = invoke(owner, {:raw_socket, socket, :inner}, native)

    assert {:ok, %{roles: 1, allocations: 16, losses: 0}} =
             Observer.snapshot(receipt, budget(native))

    assert :use = invoke(owner, {:enroll, socket}, native)
    assert :ok = Observer.cancel(receipt, lease, budget(native))

    assert {:ok, %{roles: 17, observed_down: 17, cleanup: :confirmed}} =
             Reader.await(receipt, budget(parent))
  end

  test "fully enrolled Socket graph rejects Port handoff and connected publication" do
    {receipt, lease, owner, _owner_mon, socket, _socket_mon, _token, native, parent} = attempt()
    assert :use = invoke(owner, {:enroll, socket}, native)
    {:ok, setup_token} = Observer.reserve_root(receipt, lease, :setup, budget(native))
    setup = start_role(receipt, :setup, setup_token, native, parent)
    {:ok, connection_token} = invoke(setup, {:perform, {:reserve, :connection}}, native)
    connection = start_role(receipt, :connection, connection_token, native, parent)
    {:ok, writer_token} = invoke(connection, {:perform, {:reserve, :writer}}, native)
    writer = start_role(receipt, :writer, writer_token, native, parent)
    assert {:ok, %{roles: 31, allocations: 0}} = Observer.snapshot(receipt, budget(native))
    assert {:ok, nonce} = invoke(writer, {:perform, :writer_ready}, native)
    assert :ok = invoke(connection, {:perform, {:connection_ready, nonce}}, native)

    assert {:error, :handoff_resources_pending} =
             invoke(owner, {:perform, {:prepare, socket, connection}}, native)

    assert {:error, :socket_transport_not_implemented} =
             invoke(setup, {:perform, :connected}, native)

    assert {:ok, %{setup: :pending, roles: 31}} = Observer.snapshot(receipt, budget(native))
    assert Process.alive?(Receipt.observer(receipt))
    assert :ok = Observer.cancel(receipt, lease, budget(native))

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed}} =
             Reader.await(receipt, budget(parent))
  end

  test "own socket closed before first enrollment remains unknown despite collector DOWN" do
    {receipt, lease, owner, owner_mon, socket, socket_mon, _token, native, parent} = attempt()
    assert :ok = invoke(owner, {:native_close, socket}, native)
    assert_receive {:DOWN, ^socket_mon, :socket, ^socket, :closed}, left(parent)
    assert Process.alive?(owner)
    assert {:error, :foreign_or_duplicate_resource} = invoke(owner, {:enroll, socket}, native)

    assert {:ok, %{roles: 1, allocations: 16, losses: 0}} =
             Observer.snapshot(receipt, budget(native))

    assert :ok = Observer.cancel(receipt, lease, budget(native))
    assert_receive {:DOWN, ^owner_mon, :process, ^owner, _}, left(parent)
    assert {:unconfirmed, :observer_unsealed} = Reader.await(receipt, budget(parent))
    assert :unsealed = Receipt.read(receipt)
  end

  defp attempt do
    native = System.monotonic_time(:millisecond) + 1_000
    parent_deadline = native + 2_000
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    :ok = Observer.bind(receipt, lease, budget(native))
    {:ok, permit} = Observer.reserve_root(receipt, lease, :allocator, budget(native))
    parent = self()

    {owner, monitor} =
      spawn_monitor(fn ->
        timer = :erlang.start_timer(left(parent_deadline), self(), :expiry)
        :use = Observer.enroll_self(receipt, :allocator, permit, budget(native))
        {:ok, tcp} = Observer.reserve_child(receipt, :tcp, budget(native))

        if left(native) > 0 do
          {:ok, socket} = :socket.open(:inet, :stream, :tcp)

          try do
            send(parent, {:opened, self(), socket, tcp})
            actor(receipt, tcp, native, timer)
          after
            :socket.close(socket)
          end
        end
      end)

    on_exit(fn ->
      Process.exit(owner, :kill)

      if Process.alive?(Receipt.observer(receipt)),
        do: Process.exit(Receipt.observer(receipt), :kill)
    end)

    assert_receive {:opened, ^owner, socket, tcp}, left(native)
    socket_monitor = :socket.monitor(socket)
    {receipt, lease, owner, monitor, socket, socket_monitor, tcp, native, parent_deadline}
  end

  defp start_role(receipt, role, token, native, deadline) do
    parent = self()

    {pid, _monitor} =
      spawn_monitor(fn ->
        timer = :erlang.start_timer(left(deadline), self(), :expiry)
        :use = Observer.enroll_self(receipt, role, token, budget(native))
        send(parent, {:role_ready, self()})
        actor(receipt, nil, native, timer)
      end)

    on_exit(fn -> Process.exit(pid, :kill) end)
    assert_receive {:role_ready, ^pid}, left(native)
    pid
  end

  defp actor(receipt, token, native, timer) do
    receive do
      {parent, tag, {:enroll, socket}} ->
        send(parent, {tag, Observer.enroll_socket(receipt, token, socket, budget(native))})
        actor(receipt, token, native, timer)

      {parent, tag, {:raw_socket, socket, kind}} ->
        frame =
          case kind do
            :outer -> {{:enroll_socket, token, socket}, {:abs_ms, :later}}
            :inner -> {{:enroll_socket, token, socket, :later}, budget(native)}
          end

        send(parent, {tag, GenServer.call(Receipt.observer(receipt), frame, left(native))})
        actor(receipt, token, native, timer)

      {parent, tag, {:perform, operation}} ->
        send(parent, {tag, perform(receipt, operation, budget(native))})
        actor(receipt, token, native, timer)

      {parent, tag, {:native_close, socket}} ->
        send(parent, {tag, :socket.close(socket)})
        actor(receipt, token, native, timer)

      {:timeout, ^timer, :expiry} ->
        :ok
    end
  end

  defp perform(receipt, {:reserve, role}, deadline),
    do: Observer.reserve_child(receipt, role, deadline)

  defp perform(receipt, :writer_ready, deadline), do: Observer.writer_ready(receipt, deadline)

  defp perform(receipt, {:connection_ready, nonce}, deadline),
    do: Observer.connection_ready(receipt, nonce, deadline)

  defp perform(receipt, {:prepare, socket, connection}, deadline),
    do: Observer.prepare_handoff(receipt, socket, connection, deadline)

  defp perform(receipt, :connected, deadline),
    do: Observer.publish_setup(receipt, :connected, deadline)

  defp invoke(owner, operation, deadline) do
    tag = make_ref()
    send(owner, {self(), tag, operation})
    assert_receive {^tag, result}, left(deadline)
    result
  end

  defp left(deadline), do: max(0, deadline - System.monotonic_time(:millisecond))
  defp budget(deadline), do: {:abs_ms, deadline}
end

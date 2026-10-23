defmodule SSL.Lifecycle.NativeSocketAllocatorTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  alias SSL.Lifecycle.{Allocator, Observer, Reader, Receipt}
  @ip {127, 0, 0, 1}

  test "actual Socket allocation retains its identity and keeps Port handoff gated" do
    {listener, port} = listener()
    {context, lease, observer} = attempt(port, self())
    allocation = start(context, listener)
    allocator = allocation.allocator

    assert {:error, :socket_transport_not_implemented} =
             Allocator.handoff(
               allocator,
               context.nonce,
               {self(), make_ref(), make_ref()},
               deadline()
             )

    assert {:ok, allocator} == :socket.getopt(allocation.socket, :otp, :controlling_process)

    assert {:ok, %{setup: :pending, roles: 17, allocations: 0, losses: 0}} =
             Observer.snapshot(context.receipt, deadline())

    assert :ok = Observer.cancel(context.receipt, lease, deadline())
    assert_closed(allocation, context.receipt)
    refute Process.alive?(observer)
  end

  test "recipient loss closes the allocated Socket and seals its original monitor" do
    {listener, port} = listener()
    parent = self()
    {recipient, recipient_monitor} = spawn_monitor(fn -> recipient(parent) end)
    on_exit(fn -> Process.exit(recipient, :kill) end)
    {context, _lease, _observer} = attempt(port, recipient)
    allocation = start(context, listener)
    send(recipient, :stop)
    assert_receive {:DOWN, ^recipient_monitor, :process, ^recipient, :normal}, 1_000
    assert_closed(allocation, context.receipt)
  end

  test "owner loss closes the actual allocated Socket without linking the allocator" do
    {listener, port} = listener()
    parent = self()

    {owner, owner_monitor} =
      spawn_monitor(fn ->
        {context, _lease, observer} = attempt(port, parent)
        {:ok, allocator} = Allocator.start_socket(context)
        send(parent, {:owner_attempt, self(), context, observer, allocator})

        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> Process.exit(owner, :kill) end)
    assert_receive {:owner_attempt, ^owner, context, _observer, allocator}, 1_000
    allocation = observe(context, allocator, listener)
    refute allocator in elem(Process.info(owner, :links), 1)
    send(owner, :stop)
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000
    assert_closed(allocation, context.receipt)
  end

  test "real refusal at a closed local listener seals failed connect with both DOWNs" do
    {listener, port} = listener()
    {context, _lease, observer} = attempt(port, self())
    assert :ok = :gen_tcp.close(listener)
    assert {:ok, allocator} = Allocator.start_socket(context)
    monitor = Process.monitor(allocator)
    cleanup(context, allocator)
    assert_receive {:DOWN, ^monitor, :process, ^allocator, _reason}, 1_000
    refute_receive {:lifecycle_allocated, ^allocator, _, _, _}, 0

    assert {:ok,
            %{
              setup: :failed,
              setup_failure: :connect,
              roles: 17,
              observed_down: 17,
              cleanup: :confirmed
            }} =
             Reader.await(context.receipt, deadline(2_000))

    assert {:sealed, %{setup: :failed, setup_failure: :connect, observed_down: 17}} =
             Receipt.read(context.receipt)

    refute Process.alive?(observer)
  end

  defp attempt(port, recipient) do
    budget = deadline(5_000)
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :allocator, budget)

    context = %{
      receipt: receipt,
      permit: permit,
      ip: @ip,
      port: port,
      deadline: budget,
      recipient: recipient,
      nonce: make_ref()
    }

    {context, lease, Receipt.observer(receipt)}
  end

  defp start(context, listener) do
    assert {:ok, allocator} = Allocator.start_socket(context)
    observe(context, allocator, listener)
  end

  defp observe(context, allocator, listener) do
    cleanup(context, allocator)
    monitor = Process.monitor(allocator)
    nonce = context.nonce
    observer = Receipt.observer(context.receipt)
    assert_receive {:lifecycle_allocated, ^allocator, ^nonce, ^observer, socket}, 1_000
    socket_monitor = :socket.monitor(socket)
    assert {:ok, allocator} == :socket.getopt(socket, :otp, :controlling_process)
    assert {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    assert :ok = :socket.send(socket, "probe", 1_000)
    assert {:ok, "probe"} = :gen_tcp.recv(peer, 5, 1_000)

    %{
      allocator: allocator,
      monitor: monitor,
      socket: socket,
      socket_monitor: socket_monitor,
      peer: peer
    }
  end

  defp assert_closed(allocation, receipt) do
    %{
      allocator: allocator,
      monitor: monitor,
      socket: socket,
      socket_monitor: socket_monitor,
      peer: peer
    } = allocation

    assert_receive {:DOWN, ^monitor, :process, ^allocator, _reason}, 1_000
    assert_receive {:DOWN, ^socket_monitor, :socket, ^socket, :closed}, 1_000
    assert {:error, reason} = :gen_tcp.recv(peer, 0, 1_000)
    assert reason in [:closed, :econnreset]

    assert {:ok, %{roles: 17, observed_down: 17, cleanup: :confirmed}} =
             Reader.await(receipt, deadline(2_000))
  end

  defp cleanup(context, allocator) do
    observer = Receipt.observer(context.receipt)

    on_exit(fn ->
      Process.exit(allocator, :kill)
      if Process.alive?(observer), do: Process.exit(observer, :kill)
    end)
  end

  defp recipient(parent) do
    receive do
      {:lifecycle_allocated, _, _, _, _} = event ->
        send(parent, event)
        recipient(parent)

      :stop ->
        :ok
    end
  end

  defp listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        {:inet_backend, :inet},
        :inet,
        :binary,
        active: false,
        packet: :raw,
        ip: @ip
      ])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {@ip, port}} = :inet.sockname(listener)
    {listener, port}
  end

  defp deadline(milliseconds \\ 1_000),
    do: {:abs_ms, System.monotonic_time(:millisecond) + milliseconds}
end

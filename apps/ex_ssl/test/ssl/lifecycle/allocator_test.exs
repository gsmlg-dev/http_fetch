defmodule SSL.Lifecycle.AllocatorTest do
  use ExUnit.Case, async: true
  alias SSL.Lifecycle.{Allocator, Observer, Reader, Receipt}
  @ip {127, 0, 0, 1}

  test "actual unlinked allocator owns enrolled TCP and caller survives cancellation" do
    {context, lease, observer, listener} = attempt()
    {allocator, monitor} = start(context)
    nonce = context.nonce
    assert_receive {:lifecycle_allocated, ^allocator, ^nonce, ^observer, tcp}, 1_000
    tcp_monitor = :erlang.monitor(:port, tcp)
    assert {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    assert Port.info(tcp, :connected) == {:connected, allocator}
    refute allocator in elem(Process.info(self(), :links), 1)
    assert {:ok, %{roles: 17, allocations: 0}} = Observer.snapshot(context.receipt, deadline())
    assert :ok = Observer.cancel(context.receipt, lease, deadline())
    assert_receive {:DOWN, ^monitor, :process, ^allocator, _}, 1_000
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 17, observed_down: 17, cleanup: :confirmed}} =
             Reader.await(context.receipt, deadline())

    refute Process.alive?(observer)
  end

  test "cancel before enrollment accounts a late process without dialing" do
    {context, lease, _observer, listener} = attempt()
    assert :ok = Observer.cancel(context.receipt, lease, deadline())
    {allocator, monitor} = start(context)
    assert_receive {:DOWN, ^monitor, :process, ^allocator, _}, 1_000
    refute_receive {:lifecycle_allocated, ^allocator, _, _, _}, 0
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)

    assert {:ok, %{roles: 1, observed_down: 1, cleanup: :confirmed}} =
             Reader.await(context.receipt, deadline())
  end

  test "inert startup returns while Observer is suspended and original deadline bounds enrollment" do
    {context, lease, observer, listener} = attempt()
    assert :ok = :sys.suspend(observer)
    context = %{context | deadline: deadline(200)}

    try do
      {allocator, monitor} = start(context)
      assert_receive {:DOWN, ^monitor, :process, ^allocator, :normal}, 1_000
      assert System.monotonic_time(:millisecond) >= elem(context.deadline, 1)
      refute_receive {:lifecycle_allocated, ^allocator, _, _, _}, 0
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    after
      :sys.resume(observer)
    end

    assert :ok = Observer.cancel(context.receipt, lease, deadline())
    assert {:unconfirmed, :observer_unsealed} = Reader.await(context.receipt, deadline(2_000))
    assert :unsealed = Receipt.read(context.receipt)
  end

  test "native refusal leaves unknown TCP allocation after actual allocator stops" do
    {context, _lease, _observer, listener} = attempt()
    :ok = :gen_tcp.close(listener)
    {allocator, monitor} = start(context)
    assert_receive {:DOWN, ^monitor, :process, ^allocator, _}, 1_000
    refute_receive {:lifecycle_allocated, ^allocator, _, _, _}, 0
    assert {:ok, %{roles: 1, allocations: 16}} = Observer.snapshot(context.receipt, deadline())
    assert {:unconfirmed, :observer_unsealed} = Reader.await(context.receipt, deadline(2_000))
    assert :unsealed = Receipt.read(context.receipt)
  end

  defp attempt do
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    observer = Receipt.observer(receipt)
    on_exit(fn -> if Process.alive?(observer), do: Process.exit(observer, :kill) end)
    budget = deadline(5_000)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :allocator, budget)

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

    context = %{
      receipt: receipt,
      permit: permit,
      ip: @ip,
      port: port,
      deadline: budget,
      recipient: self(),
      nonce: make_ref()
    }

    {context, lease, observer, listener}
  end

  defp start(context) do
    assert {:ok, allocator} = Allocator.start(context)
    monitor = Process.monitor(allocator)
    on_exit(fn -> Process.exit(allocator, :kill) end)
    {allocator, monitor}
  end

  defp deadline(milliseconds \\ 1_000),
    do: {:abs_ms, System.monotonic_time(:millisecond) + milliseconds}
end

defmodule SSL.Lifecycle.NativeTCPTest do
  use ExUnit.Case, async: true
  alias SSL.Lifecycle.{NativeTCP, Observer, Reader, Receipt}
  @ip {127, 0, 0, 1}

  test "original creator receives only an enrolled Port and cancellation observes both resources" do
    {receipt, lease, allocator, allocator_monitor} = attempt()
    {listener, port} = listener()
    assert {:ok, tcp} = dial(allocator, @ip, port, deadline())
    assert is_port(tcp)
    tcp_monitor = :erlang.monitor(:port, tcp)
    assert {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    assert Port.info(tcp, :connected) == {:connected, allocator}

    assert {:ok, [active: false, packet: packet, mode: :binary]} =
             :inet.getopts(tcp, [:active, :packet, :mode])

    assert packet in [0, :raw]
    assert {:ok, %{roles: 17, allocations: 0, losses: 0}} = Observer.snapshot(receipt, deadline())
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000
    assert_receive {:DOWN, ^allocator_monitor, :process, ^allocator, _}, 1_000

    assert {:ok, %{roles: 17, observed_down: 17, cleanup: :confirmed}} =
             Reader.await(receipt, deadline())

    refute Process.alive?(Receipt.observer(receipt))
  end

  test "unenrolled owner cannot allocate or dial" do
    {receipt, lease, _, _} = attempt()
    {listener, port} = listener()
    assert {:error, :unauthorized_creator} = NativeTCP.connect(receipt, @ip, port, deadline())
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    assert {:ok, %{roles: 1, allocations: 0}} = Observer.snapshot(receipt, deadline())
    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{roles: 1, observed_down: 1, cleanup: :confirmed}} =
             Reader.await(receipt, deadline())
  end

  test "invalid targets and expired budgets cannot reserve or dial" do
    {receipt, lease, allocator, _} = attempt()
    {listener, port} = listener()

    for ip <- ["localhost", {256, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}] do
      assert {:error, :invalid_arguments} = dial(allocator, ip, port, deadline())
    end

    assert {:error, :invalid_arguments} = dial(allocator, @ip, 0, deadline())
    assert {:error, :invalid_arguments} = dial(allocator, @ip, port, :infinity)
    assert {:error, :deadline_exceeded} = dial(allocator, @ip, port, deadline(-1))
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    assert {:ok, %{roles: 1, allocations: 0, losses: 0}} = Observer.snapshot(receipt, deadline())
    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{roles: 1, observed_down: 1, cleanup: :confirmed}} =
             Reader.await(receipt, deadline())
  end

  test "native refusal never retires the unknown TCP reservation" do
    {receipt, _lease, allocator, allocator_monitor} = attempt()
    {listener, port} = listener()
    :ok = :gen_tcp.close(listener)
    assert {:error, :econnrefused} = dial(allocator, @ip, port, deadline())

    assert {:ok, %{roles: 1, allocations: 16, observed_down: 0, losses: 0}} =
             Observer.snapshot(receipt, deadline())

    Process.exit(allocator, :kill)
    assert_receive {:DOWN, ^allocator_monitor, :process, ^allocator, _}, 1_000
    assert {:unconfirmed, :observer_unsealed} = Reader.await(receipt, deadline(2_000))
    assert :unsealed = Receipt.read(receipt)
    refute Process.alive?(Receipt.observer(receipt))
  end

  defp attempt do
    budget = deadline()
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :allocator, budget)
    parent = self()

    {allocator, monitor} =
      spawn_monitor(fn ->
        :use = Observer.enroll_self(receipt, :allocator, permit, budget)
        send(parent, {:allocator_ready, self()})
        actor(receipt)
      end)

    observer = Receipt.observer(receipt)

    on_exit(fn ->
      Process.exit(allocator, :kill)
      if Process.alive?(observer), do: Process.exit(observer, :kill)
    end)

    assert_receive {:allocator_ready, ^allocator}, 1_000
    {receipt, lease, allocator, monitor}
  end

  defp actor(receipt) do
    receive do
      {:connect, parent, tag, ip, port, budget} ->
        send(parent, {tag, NativeTCP.connect(receipt, ip, port, budget)})
        actor(receipt)
    end
  end

  defp dial(allocator, ip, port, budget) do
    tag = make_ref()
    send(allocator, {:connect, self(), tag, ip, port, budget})
    assert_receive {^tag, result}, 1_000
    result
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

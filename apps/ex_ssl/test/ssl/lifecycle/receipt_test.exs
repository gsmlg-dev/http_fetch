defmodule SSL.Lifecycle.ReceiptTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.{Receipt, ResourceLedger}

  test "publication requires closed admission and actual matching resource DOWN" do
    receipt = Receipt.new()
    {pid, monitor} = idle_process()
    token = make_ref()
    {:ok, ledger} = ResourceLedger.reserve(ResourceLedger.new(), :connection, :observer, token)

    {:ok, ledger, :use} =
      ResourceLedger.enroll(ledger, :connection, token, {monitor, :process, pid})

    assert Receipt.seal(receipt, ledger, connected()) == {:error, :resources_pending}
    ledger = ResourceLedger.close_admission(ledger)
    assert Receipt.seal(receipt, ledger, connected()) == {:error, :resources_pending}
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed} = down
    ledger = ResourceLedger.down(ledger, down)
    assert :ok = Receipt.seal(receipt, ledger, connected())

    assert {:sealed,
            %{
              roles: 4,
              observed_down: 4,
              losses: 0,
              cleanup: :confirmed,
              setup: :connected,
              logical: :closed,
              epoch: 0
            }} = Receipt.read(receipt)
  end

  test "only the creating observer publishes and a second seal cannot rewrite words" do
    receipt = Receipt.new()
    parent = self()

    {pid, monitor} =
      spawn_monitor(fn ->
        send(parent, {:foreign, Receipt.seal(receipt, closed(), connected())})
      end)

    assert_receive {:foreign, {:error, :not_observer}}
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}
    assert Receipt.read(receipt) == :unsealed
    assert :ok = Receipt.seal(receipt, closed(), connected())
    before = words(receipt)

    assert {:error, :already_sealing_or_sealed} =
             Receipt.seal(receipt, closed(), %{setup: :failed, failure: :tls, epoch: 99})

    assert words(receipt) == before
  end

  test "terminal metadata is finite and failed validation does not claim publication" do
    receipt = Receipt.new()

    for metadata <- [
          %{setup: :pending, failure: :none, epoch: 0},
          %{setup: :failed, failure: :none, epoch: 0},
          %{setup: :connected, failure: :tls, epoch: 0},
          %{setup: :cancelled, failure: :connect, epoch: 0},
          %{setup: :failed, failure: {:peer_error, "private data"}, epoch: 0},
          %{setup: :failed, failure: :tls, epoch: -1},
          %{setup: :failed, failure: :tls, epoch: 0.0},
          %{setup: :failed, failure: :tls, epoch: 0x8000000000000000},
          Map.put(connected(), :payload, "private data"),
          %{}
        ] do
      assert Receipt.seal(receipt, closed(), metadata) == {:error, :invalid_metadata}
      assert words(receipt) == List.duplicate(0, 8)
    end

    assert :ok =
             Receipt.seal(receipt, closed(), %{setup: :cancelled, failure: :timeout, epoch: 7})

    assert {:sealed, %{setup_failure: :timeout, epoch: 7}} = Receipt.read(receipt)
  end

  @tag :integration
  test "creator loss remains unconfirmed after late port identity and exact DOWN" do
    receipt = Receipt.new()
    {pid, monitor} = idle_process()
    allocator_token = make_ref()
    tcp_token = make_ref()

    {:ok, ledger} =
      ResourceLedger.reserve(ResourceLedger.new(), :allocator, :observer, allocator_token)

    {:ok, ledger, :use} =
      ResourceLedger.enroll(ledger, :allocator, allocator_token, {monitor, :process, pid})

    {:ok, ledger} = ResourceLedger.reserve(ledger, :tcp, {:allocator, monitor}, tcp_token)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed} = down
    ledger = ledger |> ResourceLedger.down(down) |> ResourceLedger.close_admission()
    assert Receipt.seal(receipt, ledger, connected()) == {:error, :resources_pending}
    {:ok, tcp} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    port_monitor = :erlang.monitor(:port, tcp)

    {:ok, ledger, :stop} =
      ResourceLedger.enroll(ledger, :tcp, tcp_token, {port_monitor, :port, tcp})

    :ok = :gen_tcp.close(tcp)
    assert_receive {:DOWN, ^port_monitor, :port, ^tcp, _} = port_down
    ledger = ResourceLedger.down(ledger, port_down)
    assert :ok = Receipt.seal(receipt, ledger, %{setup: :failed, failure: :connect, epoch: 0})

    assert {:sealed, %{cleanup: :unconfirmed, roles: 17, observed_down: 17, losses: 16}} =
             Receipt.read(receipt)
  end

  @tag :integration
  test "STARTTLS scope preserves adoption semantics in terminal data" do
    receipt = Receipt.new()
    {:ok, tcp} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    monitor = :erlang.monitor(:port, tcp)

    {:ok, ledger, :use} =
      ResourceLedger.adopt_tcp(ResourceLedger.new(:upgrade), {monitor, :port, tcp})

    :ok = :gen_tcp.close(tcp)
    assert_receive {:DOWN, ^monitor, :port, ^tcp, _} = down
    ledger = ledger |> ResourceLedger.down(down) |> ResourceLedger.close_admission()
    assert :ok = Receipt.seal(receipt, ledger, connected())
    assert {:sealed, %{scope: :upgrade, roles: 16, observed_down: 16}} = Receipt.read(receipt)
  end

  test "partial publication is unsealed and corrupt sealed words never decode as success" do
    receipt = Receipt.new()
    # Intentional same-module storage fault injection, not a production API.
    :atomics.put(receipt.cell, 1, 1)
    :atomics.put(receipt.cell, 2, 2)
    assert Receipt.read(receipt) == :unsealed
    assert {:error, :already_sealing_or_sealed} = Receipt.seal(receipt, closed(), connected())
    :atomics.put(receipt.cell, 1, 2)
    assert Receipt.read(receipt) == {:error, :invalid_evidence}
    assert Receipt.read(%{receipt | cell: make_ref()}) == {:error, :invalid_evidence}
  end

  test "retained evidence is fixed size and excludes process identities and arbitrary payload" do
    receipt = Receipt.new()
    before = :atomics.info(receipt.cell)
    assert before.size == 8
    assert before.memory <= 512

    assert :ok =
             Receipt.seal(receipt, closed(), %{
               setup: :connected,
               failure: :none,
               epoch: 0x7FFFFFFFFFFFFFFF
             })

    assert :atomics.info(receipt.cell) == before
    assert {:sealed, terminal} = Receipt.read(receipt)
    assert Enum.all?(Map.values(terminal), &(is_atom(&1) or is_integer(&1)))
    refute inspect(receipt) =~ inspect(receipt.cell)
    refute inspect(receipt) =~ inspect(self())
  end

  defp idle_process do
    {pid, monitor} = spawn_monitor(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    {pid, monitor}
  end

  defp closed, do: ResourceLedger.new() |> ResourceLedger.close_admission()
  defp connected, do: %{setup: :connected, failure: :none, epoch: 0}
  defp words(receipt), do: Enum.map(1..8, &:atomics.get(receipt.cell, &1))
end

defmodule SSL.Lifecycle.AuxiliaryReceiptTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.{AuxiliaryLedger, Reader, Receipt, ResourceLedger}

  test "ordinary new handles and no-effect combined seals retain the exact v1 map" do
    expected = %{
      version: 1,
      scope: :dial,
      setup: :connected,
      setup_failure: :none,
      logical: :closed,
      cleanup: :confirmed,
      roles: 0,
      observed_down: 0,
      losses: 0,
      epoch: 0
    }

    ordinary = Receipt.new()
    combined = Receipt.new()
    assert :ok = Receipt.seal(ordinary, primary(), metadata())
    empty = AuxiliaryLedger.new() |> AuxiliaryLedger.close_admission()
    assert :ok = Receipt.seal(combined, primary(), empty, metadata())
    assert Receipt.read(ordinary) == {:sealed, expected}
    assert Receipt.read(combined) == {:sealed, expected}
    assert :atomics.info(ordinary.cell).size == 8
    assert :atomics.info(ordinary.auxiliary_cell).size == 4
    assert Enum.map(1..4, &:atomics.get(ordinary.auxiliary_cell, &1)) == [0, 0, 0, 0]
  end

  test "genuine legacy eight-word handles remain readable and cannot publish v2" do
    legacy = %Receipt{cell: :atomics.new(8, signed: false), observer: self()}
    assert :ok = Receipt.seal(legacy, primary(), metadata())
    assert {:sealed, %{version: 1, cleanup: :confirmed}} = Receipt.read(legacy)
    assert Receipt.read(Map.delete(legacy, :auxiliary_cell)) == Receipt.read(legacy)

    unsealed = %Receipt{cell: :atomics.new(8, signed: false), observer: self()}

    assert {:error, :auxiliary_capacity_missing} =
             Receipt.seal(unsealed, primary(), auxiliary(), metadata())

    assert Receipt.read(unsealed) == :unsealed
  end

  test "primary role masks 31 and 30 remain exact in ordinary and extended maps" do
    for mask <- [31, 30] do
      ledger = full_primary(mask)
      ordinary = Receipt.new()
      extended = Receipt.new()
      assert :ok = Receipt.seal(ordinary, ledger, metadata())
      assert :ok = Receipt.seal(extended, ledger, auxiliary(), metadata())
      assert {:sealed, first} = Receipt.read(ordinary)
      assert {:sealed, second} = Receipt.read(extended)
      assert first.roles == mask
      assert first.observed_down == mask
      assert second.roles == mask
      assert second.observed_down == mask
      assert second |> Map.delete(:auxiliary) |> Map.put(:version, 1) == first
    end
  end

  test "v2 has a distinct old-reader fail-closed discriminator and no private payload" do
    receipt = Receipt.new()
    assert :ok = Receipt.seal(receipt, primary(), auxiliary(), metadata())
    assert :atomics.get(receipt.cell, 1) == 3
    assert legacy_read(receipt) == {:error, :invalid_evidence}
    assert {:sealed, terminal} = Receipt.read(receipt)

    assert terminal == %{
             version: 2,
             scope: :dial,
             setup: :connected,
             setup_failure: :none,
             logical: :closed,
             cleanup: :confirmed,
             roles: 0,
             observed_down: 0,
             losses: 0,
             epoch: 0,
             auxiliary: %{roles: 1, observed_down: 1, losses: 0}
           }

    assert :atomics.info(receipt.cell).size == 8
    assert :atomics.info(receipt.auxiliary_cell).size == 4

    assert :atomics.info(receipt.cell).memory + :atomics.info(receipt.auxiliary_cell).memory <=
             1024

    refute inspect(receipt) =~ inspect(receipt.auxiliary_cell)
    refute inspect(terminal) =~ "private-url-path-der-cache-ref"
    refute inspect(terminal) =~ inspect(self())
  end

  test "the combined seal waits for both primary and auxiliary proof" do
    receipt = Receipt.new()
    token = make_ref()
    {:ok, primary} = ResourceLedger.reserve(ResourceLedger.new(), :connection, :observer, token)

    assert {:error, :resources_pending} =
             Receipt.seal(receipt, primary, auxiliary(), metadata())

    assert {:error, :auxiliary_pending} =
             Receipt.seal(receipt, primary(), AuxiliaryLedger.new(), metadata())

    assert Receipt.read(receipt) == :unsealed
    assert :ok = Receipt.seal(receipt, primary(), auxiliary(), metadata())
  end

  test "auxiliary loss never inherits clean primary confirmation" do
    receipt = Receipt.new()
    assert :ok = Receipt.seal(receipt, primary(), auxiliary(:lost), metadata())

    assert {:sealed,
            %{
              version: 2,
              cleanup: :unconfirmed,
              losses: 0,
              auxiliary: %{roles: 1, observed_down: 1, losses: 1}
            }} = Receipt.read(receipt)
  end

  test "file native work remains unsealable despite exact server DOWN and close return" do
    receipt = Receipt.new()
    {ledger, generation, operation, _cleanup, actor} = file_grant()
    {:ok, ledger} = AuxiliaryLedger.handle_closed(ledger, generation)
    ledger = ledger |> AuxiliaryLedger.down(down(actor)) |> AuxiliaryLedger.close_admission()
    assert {:error, :auxiliary_pending} = Receipt.seal(receipt, primary(), ledger, metadata())
    assert :atomics.get(receipt.cell, 1) == 0

    assert {:error, :unknown_operation} =
             AuxiliaryLedger.complete_operation(ledger, generation, {operation, :open, :opened})

    assert Receipt.read(receipt) == :unsealed
  end

  test "post-native ENOENT and pre-entry skip publish file v2 only after actor DOWN" do
    for result <- [:enoent, :skipped] do
      receipt = Receipt.new()
      {ledger, generation, operation, _cleanup, actor} = file_grant()

      {:ok, ledger} =
        AuxiliaryLedger.complete_operation(ledger, generation, {operation, :open, result})

      ledger = AuxiliaryLedger.close_admission(ledger)
      assert {:error, :auxiliary_pending} = Receipt.seal(receipt, primary(), ledger, metadata())
      ledger = AuxiliaryLedger.down(ledger, down(actor))
      assert :ok = Receipt.seal(receipt, primary(), ledger, metadata())

      assert {:sealed,
              %{
                version: 2,
                cleanup: :confirmed,
                auxiliary: %{roles: 2, observed_down: 2, losses: 0}
              }} = Receipt.read(receipt)
    end
  end

  test "independent executor drain after Connection death preserves clean primary projection" do
    receipt = Receipt.new()
    {ledger, generation, operation, cleanup, actor} = file_grant()
    ledger = AuxiliaryLedger.creator_down(ledger, down(ledger.current.requester))

    {:ok, ledger} =
      AuxiliaryLedger.drain_completed(
        ledger,
        generation,
        {operation, :open, :opened},
        {cleanup, :closed}
      )

    ledger = AuxiliaryLedger.down(ledger, down(actor))
    assert :ok = Receipt.seal(receipt, primary(), ledger, metadata())

    assert {:sealed,
            %{
              version: 2,
              roles: 0,
              losses: 0,
              cleanup: :confirmed,
              auxiliary: %{roles: 2, observed_down: 2, losses: 0}
            }} = Receipt.read(receipt)
  end

  test "invalid metadata and foreign publishers cannot claim extended publication" do
    receipt = Receipt.new()

    for bad <- [
          %{},
          %{setup: :connected, failure: :tls, epoch: 0},
          Map.put(metadata(), :private, "private-url-path-der-cache-ref")
        ] do
      assert {:error, :invalid_metadata} = Receipt.seal(receipt, primary(), auxiliary(), bad)
      assert :atomics.get(receipt.cell, 1) == 0
      assert Enum.map(1..4, &:atomics.get(receipt.auxiliary_cell, &1)) == [0, 0, 0, 0]
    end

    parent = self()

    {pid, monitor} =
      spawn_monitor(fn ->
        send(parent, {:foreign, Receipt.seal(receipt, primary(), auxiliary(), metadata())})
      end)

    assert_receive {:foreign, {:error, :not_observer}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    assert Receipt.read(receipt) == :unsealed
  end

  test "v2 publication is immutable and unfinished or corrupt payload is rejected" do
    receipt = Receipt.new()
    assert :ok = Receipt.seal(receipt, primary(), auxiliary(), metadata())
    before = words(receipt)

    assert {:error, :already_sealing_or_sealed} =
             Receipt.seal(receipt, primary(), auxiliary(:lost), metadata())

    assert words(receipt) == before

    for payload <- [
          [4, 4, 0, 1],
          [1, 0, 0, 1],
          [1, 1, 8, 1],
          [1, 1, 4, 1],
          [1, 1, 2, 1],
          [0, 0, 1, 1],
          [1, 1, 0, 0],
          [1, 1, 0, 2]
        ] do
      put_auxiliary(receipt, payload)
      assert Receipt.read(receipt) == {:error, :invalid_evidence}
    end

    put_auxiliary(receipt, [1, 1, 0, 1])
    :atomics.put(receipt.cell, 1, 1)
    assert Receipt.read(receipt) == :unsealed
    :atomics.put(receipt.cell, 1, 3)
    assert {:sealed, %{cleanup: :confirmed}} = Receipt.read(receipt)
    assert Receipt.read(%{receipt | auxiliary_cell: nil}) == {:error, :invalid_evidence}
  end

  test "v2 still waits for observer absence and retains unconfirmed auxiliary loss" do
    for mode <- [:clean, :lost] do
      parent = self()

      {pid, monitor} =
        spawn_monitor(fn ->
          receipt = Receipt.new()
          :ok = Receipt.seal(receipt, primary(), auxiliary(mode), metadata())
          send(parent, {:sealed, self(), receipt})
          receive do: (:exit -> :ok)
        end)

      on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
      assert_receive {:sealed, ^pid, receipt}, 1_000
      assert Reader.status(receipt) == {:pending, %{receipt: :sealed, observer: :alive}}
      assert {:pending, %{receipt: :sealed}} = Reader.await(receipt, deadline())
      send(pid, :exit)
      assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000

      if mode == :clean do
        assert {:ok, %{version: 2, cleanup: :confirmed}} = Reader.await(receipt, deadline())
      else
        assert Reader.await(receipt, deadline()) == {:unconfirmed, :resource_evidence_lost}
      end
    end
  end

  test "observer death after all extension writes but before seal is unconfirmed" do
    parent = self()

    {pid, monitor} =
      spawn_monitor(fn ->
        receipt = Receipt.new()
        :atomics.put(receipt.cell, 1, 1)

        Enum.each(Enum.with_index([2, 1, 0, 0, 0, 0, 1], 2), fn {word, index} ->
          :atomics.put(receipt.cell, index, word)
        end)

        put_auxiliary(receipt, [1, 1, 0, 1])
        send(parent, {:partial, self(), receipt})
      end)

    assert_receive {:partial, ^pid, receipt}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    assert Reader.await(receipt, deadline()) == {:unconfirmed, :observer_unsealed}
  end

  # Pinned v1 read/1 dispatch (publication 0/1/2 only), without the new branch.
  # Existing v1 decoder tests continue running unchanged alongside this test.
  defp legacy_read(receipt) do
    case :atomics.get(receipt.cell, 1) do
      state when state in [0, 1] -> :unsealed
      2 -> Receipt.read(receipt)
      _ -> {:error, :invalid_evidence}
    end
  end

  defp auxiliary(mode \\ :clean) do
    token = make_ref()
    creator = {make_ref(), :process, self()}
    identity = {make_ref(), :socket, "private-url-path-der-cache-ref"}

    {:ok, ledger, generation} =
      AuxiliaryLedger.reserve(AuxiliaryLedger.new(), :http_socket, creator, token)

    ledger =
      if mode == :lost, do: AuxiliaryLedger.creator_down(ledger, down(creator)), else: ledger

    {:ok, ledger, action} = AuxiliaryLedger.enroll(ledger, generation, token, identity)
    if mode == :lost, do: assert(action == :stop), else: assert(action == :use)
    ledger |> AuxiliaryLedger.down(down(identity)) |> AuxiliaryLedger.close_admission()
  end

  defp file_grant do
    permit = make_ref()
    requester = {make_ref(), :process, self()}
    actor = {make_ref(), :process, self()}

    {:ok, ledger, generation} =
      AuxiliaryLedger.reserve(AuxiliaryLedger.new(), :file_executor, requester, permit)

    {:ok, ledger, :use} = AuxiliaryLedger.enroll(ledger, generation, permit, actor)
    operation = make_ref()
    cleanup = make_ref()
    {:ok, ledger} = AuxiliaryLedger.grant_open(ledger, generation, operation, cleanup)
    {ledger, generation, operation, cleanup, actor}
  end

  defp put_auxiliary(receipt, values) do
    Enum.each(Enum.with_index(values, 1), fn {value, index} ->
      :atomics.put(receipt.auxiliary_cell, index, value)
    end)
  end

  defp words(receipt) do
    {Enum.map(1..8, &:atomics.get(receipt.cell, &1)),
     Enum.map(1..4, &:atomics.get(receipt.auxiliary_cell, &1))}
  end

  defp primary, do: ResourceLedger.new() |> ResourceLedger.close_admission()

  defp full_primary(mask) do
    roles =
      if mask == 31,
        do: [:allocator, :setup, :connection, :writer, :tcp],
        else: [:setup, :connection, :writer, :tcp]

    Enum.reduce(roles, ResourceLedger.new(), fn role, ledger ->
      token = make_ref()

      identity =
        if role == :tcp,
          do: {make_ref(), :socket, :primary},
          else: {make_ref(), :process, self()}

      {:ok, ledger} = ResourceLedger.reserve(ledger, role, :observer, token)
      {:ok, ledger, :use} = ResourceLedger.enroll(ledger, role, token, identity)
      ResourceLedger.down(ledger, down(identity))
    end)
    |> ResourceLedger.close_admission()
  end

  defp metadata, do: %{setup: :connected, failure: :none, epoch: 0}
  defp deadline, do: {:abs_ms, System.monotonic_time(:millisecond)}
  defp down({ref, kind, object}), do: {:DOWN, ref, kind, object, :closed}
end

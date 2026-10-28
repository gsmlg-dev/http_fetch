defmodule SSL.Lifecycle.LayerLedgerTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.{Receipt, ResourceLedger}

  test "a layer can reserve only its setup, connection and writer" do
    ledger = ResourceLedger.new(:layer)

    for role <- [:allocator, :tcp] do
      assert {:error, :role_outside_scope} =
               ResourceLedger.reserve(ledger, role, :observer, make_ref())
    end

    assert {:error, :adoption_not_permitted} =
             ResourceLedger.adopt_tcp(ledger, {make_ref(), :port, :not_a_port})

    {ledger, identities} =
      Enum.reduce([:setup, :connection, :writer], {ledger, []}, fn role, {ledger, identities} ->
        token = make_ref()
        identity = {make_ref(), :process, self()}
        assert {:ok, ledger} = ResourceLedger.reserve(ledger, role, :observer, token)
        assert {:ok, ledger, :use} = ResourceLedger.enroll(ledger, role, token, identity)
        {ledger, [identity | identities]}
      end)

    assert %{scope: :layer, roles: 14, observed_down: 0, allocations: 0} =
             ResourceLedger.snapshot(ledger)

    assert %{tcp_sockets: 0, data_resources: 1} = ResourceLedger.resource_counts(ledger)
    ledger = ResourceLedger.close_admission(ledger)
    assert {:pending, %{roles: 14, observed_down: 0}} = ResourceLedger.proof(ledger)

    ledger =
      Enum.reduce(identities, ledger, fn {ref, :process, pid}, ledger ->
        ResourceLedger.down(ledger, {:DOWN, ref, :process, pid, :normal})
      end)

    assert {:ok, %{scope: :layer, roles: 14, observed_down: 14, cleanup: :confirmed}} =
             ResourceLedger.proof(ledger)
  end

  test "layer receipts preserve their scope and reject impossible physical resource bits" do
    receipt = Receipt.new()
    ledger = ResourceLedger.new(:layer) |> ResourceLedger.close_admission()

    assert :ok =
             Receipt.seal(receipt, ledger, %{setup: :cancelled, failure: :cancelled, epoch: 0})

    assert {:sealed, %{scope: :layer, roles: 0, cleanup: :confirmed}} = Receipt.read(receipt)

    for roles <- [1, 16, 17, 31] do
      :atomics.put(receipt.cell, 4, roles)
      :atomics.put(receipt.cell, 5, roles)
      assert {:error, :invalid_evidence} = Receipt.read(receipt)
    end
  end
end

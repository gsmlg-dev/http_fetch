defmodule SSL.Lifecycle.ResourceLedgerTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.ResourceLedger, as: Ledger

  test "empty observations cannot settle while creation remains admitted" do
    ledger = Ledger.new()
    assert {:pending, %{roles: 0}} = Ledger.proof(ledger)

    assert {:ok, %{cleanup: :confirmed, roles: 0}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()
  end

  test "allocation fence remains open after cancellation until enrollment and matching DOWN" do
    token = make_ref()
    monitor = make_ref()
    assert {:ok, ledger} = Ledger.reserve(Ledger.new(), :writer, :observer, token)
    ledger = Ledger.close_admission(ledger)
    assert {:pending, %{allocations: 8}} = Ledger.proof(ledger)
    assert {:error, :admission_closed} = Ledger.reserve(ledger, :setup, :observer, make_ref())

    assert {:ok, ledger, :stop} =
             Ledger.enroll(ledger, :writer, token, {monitor, :process, self()})

    assert {:pending, %{roles: 8, observed_down: 0}} = Ledger.proof(ledger)
    ledger = Ledger.down(ledger, {:DOWN, monitor, :process, self(), :killed})
    assert {:ok, %{cleanup: :confirmed, roles: 8, observed_down: 8}} = Ledger.proof(ledger)
  end

  test "all monitor identity components must match; duplicate DOWN cannot advance proof" do
    {ledger, monitor} = observed(:connection)
    ledger = Ledger.close_admission(ledger)

    for event <- [
          {:DOWN, make_ref(), :process, self(), :normal},
          {:DOWN, monitor, :port, self(), :normal},
          {:DOWN, monitor, :process, :wrong_object, :normal}
        ] do
      assert Ledger.down(ledger, event) == ledger
    end

    down = {:DOWN, monitor, :process, self(), :normal}
    final = Ledger.down(ledger, down)
    assert Ledger.down(final, down) == final
    assert {:ok, %{cleanup: :confirmed}} = Ledger.proof(final)
  end

  test "allocator DOWN with unreported TCP allocation is unconfirmed, never empty-set success" do
    {ledger, allocator} = observed(:allocator)
    assert {:ok, ledger} = Ledger.reserve(ledger, :tcp, {:allocator, allocator}, make_ref())
    ledger = Ledger.down(ledger, {:DOWN, allocator, :process, self(), :killed})
    assert {:pending, %{losses: 16, allocations: 16}} = Ledger.proof(ledger)
    assert {:error, :role_used} = Ledger.reserve(ledger, :tcp, :observer, make_ref())

    assert {:pending, %{roles: 1, observed_down: 1, losses: 16, allocations: 16}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()
  end

  test "loss retains late children and does not bypass independently observed resources" do
    {ledger, connection} = observed(:connection)
    {ledger, writer} = observed(:writer, ledger)
    token = make_ref()
    setup = make_ref()
    assert {:ok, ledger} = Ledger.reserve(ledger, :setup, {:connection, connection}, token)
    ledger = Ledger.down(ledger, {:DOWN, connection, :process, self(), :killed})
    assert {:pending, %{losses: 2, observed_down: 4}} = Ledger.proof(ledger)
    # Even before aggregate cancellation closes admission, a lost creator cannot
    # authorize use of its delayed child. Its original token is still recognized.
    assert {:ok, ledger, :stop} = Ledger.enroll(ledger, :setup, token, {setup, :process, self()})
    ledger = Ledger.close_admission(ledger)
    ledger = Ledger.down(ledger, {:DOWN, writer, :process, self(), :killed})
    assert {:pending, %{losses: 2, observed_down: 12}} = Ledger.proof(ledger)
    ledger = Ledger.down(ledger, {:DOWN, setup, :process, self(), :killed})
    assert {:ok, %{cleanup: :unconfirmed, roles: 14, observed_down: 14}} = Ledger.proof(ledger)
  end

  test "only enrolled live creators can allocate and roles cannot be recycled" do
    ledger = Ledger.new()

    assert {:error, :creator_not_observed} =
             Ledger.reserve(ledger, :tcp, {:allocator, make_ref()}, make_ref())

    assert {:error, :invalid_role} = Ledger.reserve(ledger, :arbitrary, :observer, make_ref())
    {ledger, allocator} = observed(:allocator, ledger)
    assert {:error, :role_used} = Ledger.reserve(ledger, :allocator, :observer, make_ref())
    ledger = Ledger.down(ledger, {:DOWN, allocator, :process, self(), :normal})

    assert {:error, :creator_not_observed} =
             Ledger.reserve(ledger, :tcp, {:allocator, allocator}, make_ref())

    assert {:error, :role_used} = Ledger.reserve(ledger, :allocator, :observer, make_ref())
  end

  test "stale enrollment tokens and duplicate monitor references do not consume permits" do
    {ledger, monitor} = observed(:setup)
    token = make_ref()
    assert {:ok, ledger} = Ledger.reserve(ledger, :connection, {:setup, monitor}, token)

    assert {:error, :unknown_permit} =
             Ledger.enroll(ledger, :connection, make_ref(), {make_ref(), :process, self()})

    assert {:error, :monitor_used} =
             Ledger.enroll(ledger, :connection, token, {monitor, :process, self()})

    assert {:error, :invalid_monitor_identity} =
             Ledger.enroll(ledger, :connection, token, {make_ref(), :port, self()})

    assert %{allocations: 4} = Ledger.snapshot(ledger)

    assert {:ok, _, :use} =
             Ledger.enroll(ledger, :connection, token, {make_ref(), :process, self()})
  end

  test "STARTTLS proof is explicitly adoption-scoped and only accepts ports" do
    {:ok, tcp} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(tcp) end)
    monitor = make_ref()
    identity = {monitor, :port, tcp}
    assert {:error, :adoption_not_permitted} = Ledger.adopt_tcp(Ledger.new(), identity)

    assert {:error, :invalid_monitor_identity} =
             Ledger.adopt_tcp(Ledger.new(:upgrade), {monitor, :process, self()})

    assert {:ok, ledger, :use} = Ledger.adopt_tcp(Ledger.new(:upgrade), identity)
    assert {:error, :role_used} = Ledger.adopt_tcp(ledger, identity)

    ledger =
      ledger |> Ledger.close_admission() |> Ledger.down({:DOWN, monitor, :port, tcp, :normal})

    assert {:ok, %{scope: :upgrade, cleanup: :confirmed, observed_down: 16}} =
             Ledger.proof(ledger)

    assert Port.info(tcp) != nil
  end

  test "bounded snapshots/proofs omit resource identities and arbitrary DOWN reasons" do
    {ledger, monitor} = observed(:connection)
    secret = :binary.copy("not-retained", 1000)

    ledger =
      ledger
      |> Ledger.close_admission()
      |> Ledger.down({:DOWN, monitor, :process, self(), secret})

    assert {:ok, proof} = Ledger.proof(ledger)
    assert Enum.sort(Map.keys(proof)) == [:cleanup, :losses, :observed_down, :roles, :scope]
    refute inspect(ledger) =~ inspect(monitor)
    refute :erlang.term_to_binary(ledger) =~ secret
    refute :erlang.term_to_binary(proof) =~ :erlang.term_to_binary(self())
  end

  test "termination ordering never seals before every observed role is down" do
    for roles <- [
          [:allocator, :connection, :writer],
          [:writer, :allocator, :connection],
          [:connection, :writer, :allocator]
        ] do
      {ledger, monitors} =
        Enum.reduce(roles, {Ledger.new(), []}, fn role, {ledger, refs} ->
          {ledger, monitor} = observed(role, ledger)
          {ledger, [{role, monitor} | refs]}
        end)

      ledger = Ledger.close_admission(ledger)
      {prefix, [{_role, last}]} = Enum.split(monitors, 2)

      ledger =
        Enum.reduce(prefix, ledger, fn {_role, monitor}, acc ->
          Ledger.down(acc, {:DOWN, monitor, :process, self(), :normal})
        end)

      assert {:pending, _} = Ledger.proof(ledger)
      ledger = Ledger.down(ledger, {:DOWN, last, :process, self(), :normal})
      assert {:ok, %{cleanup: :confirmed, roles: 13, observed_down: 13}} = Ledger.proof(ledger)
    end
  end

  defp observed(role, ledger \\ Ledger.new()) do
    token = make_ref()
    monitor = make_ref()
    {:ok, ledger} = Ledger.reserve(ledger, role, :observer, token)
    {:ok, ledger, :use} = Ledger.enroll(ledger, role, token, {monitor, :process, self()})
    {ledger, monitor}
  end
end

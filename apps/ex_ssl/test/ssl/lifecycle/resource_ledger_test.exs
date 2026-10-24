defmodule SSL.Lifecycle.ResourceLedgerTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.ResourceLedger, as: Ledger

  test "numeric projection counts live identities rather than historical roles" do
    {ledger, connection} = observed(:connection)
    {ledger, writer} = observed(:writer, ledger)
    # Pure ledger events deliberately enroll the same PID under distinct monitors.
    # The actual process identity contributes once even though both roles exist.
    assert Ledger.resource_counts(ledger) == %{
             processes: 1,
             tcp_sockets: 0,
             observers: 0,
             data_resources: 1
           }

    ledger = Ledger.down(ledger, {:DOWN, connection, :process, self(), :normal})
    assert Ledger.resource_counts(ledger).processes == 1
    ledger = Ledger.down(ledger, {:DOWN, writer, :process, self(), :normal})

    assert Ledger.resource_counts(ledger) == %{
             processes: 0,
             tcp_sockets: 0,
             observers: 0,
             data_resources: 0
           }

    assert Ledger.snapshot(ledger).roles == 12
  end

  test "numeric projection is unknown for unresolved creation and sticky loss" do
    {ledger, allocator} = observed(:allocator)
    token = make_ref()
    assert {:ok, ledger} = Ledger.reserve(ledger, :tcp, {:allocator, allocator}, token)
    assert Ledger.resource_counts(ledger) == nil
    ledger = Ledger.down(ledger, {:DOWN, allocator, :process, self(), :killed})
    assert Ledger.resource_counts(ledger) == nil
    assert Ledger.snapshot(ledger).losses == 16
  end

  test "distinct processes and TCP survive only their own exact monitor DOWN" do
    actor = spawn(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> send(actor, :stop) end)
    refs = for _ <- 1..3, do: make_ref()
    [connection, writer, tcp] = refs

    identities = [
      {:connection, {connection, :process, self()}},
      {:writer, {writer, :process, actor}},
      {:tcp, {tcp, :socket, :fake_socket}}
    ]

    ledger =
      Enum.reduce(identities, Ledger.new(), fn {role, identity}, ledger ->
        token = make_ref()
        assert {:ok, ledger} = Ledger.reserve(ledger, role, :observer, token)
        assert {:ok, ledger, :use} = Ledger.enroll(ledger, role, token, identity)
        ledger
      end)

    assert Ledger.resource_counts(ledger) == %{
             processes: 2,
             tcp_sockets: 1,
             observers: 0,
             data_resources: 3
           }

    ledger = Ledger.down(ledger, {:DOWN, connection, :process, self(), :normal})
    ledger = Ledger.down(ledger, {:DOWN, writer, :process, actor, :normal})

    assert Ledger.resource_counts(ledger) == %{
             processes: 0,
             tcp_sockets: 1,
             observers: 0,
             data_resources: 1
           }

    assert Ledger.down(ledger, {:DOWN, make_ref(), :socket, :fake_socket, :closed}) == ledger
    ledger = Ledger.down(ledger, {:DOWN, tcp, :socket, :fake_socket, :closed})
    assert Ledger.resource_counts(ledger).data_resources == 0
  end

  test "enrollment view retains consumed creator generation through child DOWN" do
    # Pure event data only; these references are not runtime monitor evidence.
    {ledger, parent_ref} = observed(:setup)
    creator = {:setup, parent_ref}
    token = make_ref()
    child_ref = make_ref()
    identity = {child_ref, :process, self()}
    assert {:ok, ledger} = Ledger.reserve(ledger, :connection, creator, token)
    assert {:ok, ledger, :use} = Ledger.enroll(ledger, :connection, token, identity)

    assert {:ok, %{identity: ^identity, creator: ^creator, state: :live}} =
             Ledger.enrollment_view(ledger, :connection)

    assert :error = Ledger.enrollment_view(ledger, :writer)
    unrelated = Ledger.down(ledger, {:DOWN, make_ref(), :process, self(), :normal})

    assert {:ok, %{identity: ^identity, creator: ^creator, state: :live}} =
             Ledger.enrollment_view(unrelated, :connection)

    down = Ledger.down(ledger, {:DOWN, child_ref, :process, self(), :normal})

    assert {:ok, %{identity: ^identity, creator: ^creator, state: :down}} =
             Ledger.enrollment_view(down, :connection)
  end

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

  @tag :integration
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

  test "pre-native rejection consumes one permit without fabricating resource DOWN or recycling its role" do
    {ledger, allocator} = observed(:allocator)
    token = make_ref()
    creator = {:allocator, allocator}
    assert {:ok, ledger} = Ledger.reserve(ledger, :tcp, creator, token)
    assert {:ok, ledger} = Ledger.reject_before_native(ledger, :tcp, token, creator)
    assert %{roles: 1, observed_down: 0, allocations: 0, losses: 0} = Ledger.snapshot(ledger)
    assert {:error, :role_used} = Ledger.reserve(ledger, :tcp, creator, make_ref())
    assert {:error, :unknown_permit} = Ledger.reject_before_native(ledger, :tcp, token, creator)

    assert {:error, :unknown_permit} =
             Ledger.enroll(ledger, :tcp, token, {make_ref(), :port, :not_allocated})

    ledger = Ledger.close_admission(ledger)
    assert {:pending, %{roles: 1, observed_down: 0, allocations: 0}} = Ledger.proof(ledger)
    ledger = Ledger.down(ledger, {:DOWN, allocator, :process, self(), :normal})
    assert {:ok, %{cleanup: :confirmed, roles: 1, observed_down: 1}} = Ledger.proof(ledger)
  end

  test "pre-native rejection requires the exact permit, role and creator monitor generation" do
    {ledger, allocator} = observed(:allocator)
    token = make_ref()
    creator = {:allocator, allocator}
    assert {:ok, ledger} = Ledger.reserve(ledger, :tcp, creator, token)
    original = Ledger.snapshot(ledger)

    assert {:error, :unknown_permit} =
             Ledger.reject_before_native(ledger, :tcp, make_ref(), creator)

    assert {:error, :unknown_permit} =
             Ledger.reject_before_native(ledger, :writer, token, creator)

    assert {:error, :unknown_permit} =
             Ledger.reject_before_native(Ledger.new(), :tcp, token, creator)

    assert {:error, :unauthorized_creator} =
             Ledger.reject_before_native(ledger, :tcp, token, {:allocator, make_ref()})

    assert {:error, :unauthorized_creator} =
             Ledger.reject_before_native(ledger, :tcp, token, {:setup, allocator})

    assert {:error, :unauthorized_creator} =
             Ledger.reject_before_native(ledger, :tcp, token, :observer)

    assert Ledger.snapshot(ledger) == original
    assert {:ok, _} = Ledger.reject_before_native(ledger, :tcp, token, creator)
  end

  test "settlement after a closed fence performs accounting without admitting a birth" do
    {ledger, setup} = observed(:setup)
    creator = {:setup, setup}
    token = make_ref()
    assert {:ok, ledger} = Ledger.reserve(ledger, :connection, creator, token)
    ledger = Ledger.close_admission(ledger)
    assert {:ok, ledger} = Ledger.reject_before_native(ledger, :connection, token, creator)

    assert %{admission: :closed, allocations: 0, roles: 2, observed_down: 0} =
             Ledger.snapshot(ledger)

    assert {:error, :admission_closed} =
             Ledger.reserve(ledger, :writer, creator, make_ref())

    assert {:error, :unknown_permit} =
             Ledger.enroll(ledger, :connection, token, {make_ref(), :process, self()})

    assert {:pending, %{roles: 2, observed_down: 0}} = Ledger.proof(ledger)
    ledger = Ledger.down(ledger, {:DOWN, setup, :process, self(), :normal})
    assert {:ok, %{cleanup: :confirmed, roles: 2, observed_down: 2}} = Ledger.proof(ledger)
  end

  test "all five rejected roles remain single use without fabricated enrolled roles" do
    for role <- [:allocator, :setup, :connection, :writer, :tcp] do
      token = make_ref()
      assert {:ok, ledger} = Ledger.reserve(Ledger.new(), role, :observer, token)
      assert {:ok, ledger} = Ledger.reject_before_native(ledger, role, token, :observer)
      assert %{roles: 0, observed_down: 0, allocations: 0, losses: 0} = Ledger.snapshot(ledger)
      assert {:error, :role_used} = Ledger.reserve(ledger, role, :observer, make_ref())

      assert {:ok, %{roles: 0, observed_down: 0, cleanup: :confirmed}} =
               ledger |> Ledger.close_admission() |> Ledger.proof()
    end
  end

  test "creator loss cannot be settled by a later rejection and its late child still stops" do
    {ledger, setup} = observed(:setup)
    creator = {:setup, setup}
    token = make_ref()
    assert {:ok, ledger} = Ledger.reserve(ledger, :connection, creator, token)
    ledger = Ledger.down(ledger, {:DOWN, setup, :process, self(), :normal})
    ledger = Ledger.close_admission(ledger)

    assert {:error, :creator_not_observed} =
             Ledger.reject_before_native(ledger, :connection, token, creator)

    assert {:pending, %{allocations: 4, losses: 4, roles: 2, observed_down: 2}} =
             Ledger.proof(ledger)

    child = make_ref()

    assert {:ok, ledger, :stop} =
             Ledger.enroll(ledger, :connection, token, {child, :process, self()})

    ledger = Ledger.down(ledger, {:DOWN, child, :process, self(), :normal})

    assert {:ok, %{cleanup: :unconfirmed, losses: 4, roles: 6, observed_down: 6}} =
             Ledger.proof(ledger)
  end

  test "settling another constructor cannot erase an unknown lost permit" do
    {ledger, setup} = observed(:setup)
    {ledger, allocator} = observed(:allocator, ledger)
    connection_token = make_ref()
    tcp_token = make_ref()
    assert {:ok, ledger} = Ledger.reserve(ledger, :connection, {:setup, setup}, connection_token)
    assert {:ok, ledger} = Ledger.reserve(ledger, :tcp, {:allocator, allocator}, tcp_token)
    ledger = Ledger.down(ledger, {:DOWN, setup, :process, self(), :normal})
    ledger = Ledger.close_admission(ledger)

    assert {:ok, ledger} =
             Ledger.reject_before_native(ledger, :tcp, tcp_token, {:allocator, allocator})

    assert {:pending, %{allocations: 4, losses: 4, roles: 3, observed_down: 2}} =
             Ledger.proof(ledger)

    child = make_ref()

    assert {:ok, ledger, :stop} =
             Ledger.enroll(ledger, :connection, connection_token, {child, :process, self()})

    ledger = Ledger.down(ledger, {:DOWN, child, :process, self(), :normal})
    ledger = Ledger.down(ledger, {:DOWN, allocator, :process, self(), :normal})

    assert {:ok, %{cleanup: :unconfirmed, losses: 4, roles: 7, observed_down: 7}} =
             Ledger.proof(ledger)
  end

  test "TCP rollover retains bounded exact history and fences later identities" do
    {ledger, allocator} = observed(:allocator)
    creator = {:allocator, allocator}
    token = make_ref()
    old = {make_ref(), :socket, :first}
    assert {:ok, ledger} = Ledger.reserve(ledger, :tcp, creator, token)
    assert {:ok, ledger, :use} = Ledger.enroll(ledger, :tcp, token, old)

    assert {:error, :rollover_not_permitted} =
             Ledger.rollover_tcp(ledger, old, creator, make_ref())

    ledger = Ledger.down(ledger, {:DOWN, elem(old, 0), :socket, :first, :closed})
    next_token = make_ref()
    assert {:ok, pending} = Ledger.rollover_tcp(ledger, old, creator, next_token)
    assert %{roles: 17, observed_down: 0, allocations: 16} = Ledger.snapshot(pending)
    assert map_size(pending.resources) == 2

    assert {:error, :rollover_not_permitted} =
             Ledger.rollover_tcp(pending, old, creator, make_ref())

    assert {:error, :rollover_not_permitted} =
             Ledger.rollover_tcp(Ledger.close_admission(ledger), old, creator, make_ref())

    replacement = {make_ref(), :socket, :second}
    assert {:ok, next, :use} = Ledger.enroll(pending, :tcp, next_token, replacement)
    late = Ledger.down(next, {:DOWN, elem(old, 0), :socket, :first, :closed})
    assert Ledger.snapshot(late) == Ledger.snapshot(next)
    assert map_size(late.resources) == 2
    assert {:ok, %{identity: ^replacement, state: :live}} = Ledger.enrollment_view(late, :tcp)
    assert {:error, :unknown_permit} = Ledger.enroll(next, :tcp, token, old)

    lost = Ledger.down(pending, {:DOWN, allocator, :process, self(), :killed})
    assert %{losses: 16, allocations: 16, observed_down: 1} = Ledger.snapshot(lost)
    assert {:pending, _} = lost |> Ledger.close_admission() |> Ledger.proof()
    assert {:error, :rollover_not_permitted} = Ledger.rollover_tcp(lost, old, creator, make_ref())
    assert {:ok, lost, :stop} = Ledger.enroll(lost, :tcp, next_token, replacement)
    lost = Ledger.down(lost, {:DOWN, elem(replacement, 0), :socket, :second, :closed})

    assert {:ok, %{cleanup: :unconfirmed, losses: 16, roles: 17, observed_down: 17}} =
             lost |> Ledger.close_admission() |> Ledger.proof()
  end

  defp observed(role, ledger \\ Ledger.new()) do
    token = make_ref()
    monitor = make_ref()
    {:ok, ledger} = Ledger.reserve(ledger, role, :observer, token)
    {:ok, ledger, :use} = Ledger.enroll(ledger, role, token, {monitor, :process, self()})
    {ledger, monitor}
  end
end

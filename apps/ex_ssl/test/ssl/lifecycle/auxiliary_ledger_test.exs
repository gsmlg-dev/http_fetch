defmodule SSL.Lifecycle.AuxiliaryLedgerTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.AuxiliaryLedger, as: Ledger

  # Synthetic exact identities exercise only the pure reducer. The later
  # Observer adapter must establish and authenticate actual runtime monitors.
  test "no effects retain an empty closed proof" do
    ledger = Ledger.new()
    refute Ledger.admitted?(ledger)
    assert {:pending, %{roles: 0, observed_down: 0, losses: 0}} = Ledger.proof(ledger)

    assert {:ok, %{roles: 0, observed_down: 0, losses: 0, cleanup: :confirmed}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()
  end

  test "reserve precedes birth, exact DOWN precedes serial reuse" do
    {ledger, generation, token, creator} = reserved(:http_socket)
    identity = {make_ref(), :socket, :opaque_socket}
    assert Ledger.admitted?(ledger)
    assert %{allocations: 1, roles: 0} = Ledger.snapshot(ledger)
    assert {:error, :auxiliary_busy} = Ledger.reserve(ledger, :file_executor, creator, make_ref())
    assert {:ok, ledger, :use} = Ledger.enroll(ledger, generation, token, identity)
    assert {:error, :unknown_permit} = Ledger.enroll(ledger, generation, token, identity)

    for mismatch <- [
          {:DOWN, make_ref(), :socket, :opaque_socket, :closed},
          {:DOWN, elem(identity, 0), :process, self(), :closed},
          {:DOWN, elem(identity, 0), :socket, :another_socket, :closed}
        ] do
      assert Ledger.down(ledger, mismatch) == ledger
    end

    assert {:error, :auxiliary_busy} = Ledger.reserve(ledger, :http_socket, creator, make_ref())
    ledger = Ledger.down(ledger, down(identity))
    assert %{roles: 1, observed_down: 1} = Ledger.snapshot(ledger)
    assert {:ok, pending, 2} = Ledger.reserve(ledger, :http_socket, creator, make_ref())
    assert {:pending, _} = pending |> Ledger.close_admission() |> Ledger.proof()
    assert {:error, :unknown_permit} = Ledger.enroll(pending, generation, token, identity)
  end

  test "wrong generation, token, creator and identity kind cannot discharge a permit" do
    {ledger, generation, token, creator} = reserved(:http_socket)
    assert {:error, :unknown_permit} = Ledger.enroll(ledger, generation + 1, token, socket())
    assert {:error, :unknown_permit} = Ledger.enroll(ledger, generation, make_ref(), socket())

    assert {:error, :invalid_monitor_identity} =
             Ledger.enroll(ledger, generation, token, {make_ref(), :process, self()})

    assert {:error, :rejection_not_permitted} =
             Ledger.reject_before_native(
               ledger,
               generation,
               token,
               {make_ref(), :process, self()}
             )

    assert {:ok, ledger} = Ledger.reject_before_native(ledger, generation, token, creator)

    assert {:ok, %{roles: 0, observed_down: 0, cleanup: :confirmed}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()

    assert {:error, :rejection_not_permitted} =
             Ledger.reject_before_native(ledger, generation, token, creator)
  end

  test "pre-native rejection after a previous completed generation preserves its DOWN" do
    {ledger, _identity} = retired_socket()
    creator = creator()
    token = make_ref()
    assert {:ok, ledger, generation} = Ledger.reserve(ledger, :http_socket, creator, token)
    assert {:ok, ledger} = Ledger.reject_before_native(ledger, generation, token, creator)

    assert {:ok, %{roles: 1, observed_down: 1, cleanup: :confirmed}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()
  end

  test "cancellation bars use and future allocation but admits exact late birth for stop" do
    {ledger, generation, token, creator} = reserved(:http_socket)
    ledger = Ledger.close_admission(ledger)
    assert {:pending, %{allocations: 1}} = Ledger.proof(ledger)

    assert {:error, :admission_closed} =
             Ledger.reserve(ledger, :file_executor, creator, make_ref())

    identity = socket()
    assert {:ok, ledger, :stop} = Ledger.enroll(ledger, generation, token, identity)
    assert {:pending, _} = Ledger.proof(ledger)
    ledger = Ledger.down(ledger, down(identity))
    assert {:ok, %{roles: 1, observed_down: 1, cleanup: :confirmed}} = Ledger.proof(ledger)
  end

  test "creator death cannot erase an unknown birth or its sticky loss" do
    {ledger, generation, token, creator} = reserved(:http_socket)
    assert Ledger.creator_down(ledger, {:DOWN, make_ref(), :process, self(), :killed}) == ledger
    ledger = Ledger.creator_down(ledger, down(creator))
    assert {:pending, %{allocations: 1, losses: 1}} = Ledger.proof(ledger)

    assert {:error, :rejection_not_permitted} =
             Ledger.reject_before_native(ledger, generation, token, creator)

    identity = socket()
    assert {:ok, ledger, :stop} = Ledger.enroll(ledger, generation, token, identity)
    ledger = Ledger.down(ledger, down(identity))

    assert {:ok, %{roles: 1, observed_down: 1, losses: 1, cleanup: :unconfirmed}} =
             Ledger.proof(ledger)
  end

  test "inert preobserved actor has no open grant and exact DOWN can settle" do
    {ledger, generation, _permit, actor} = file_actor()
    assert ledger.current.creator == :observer
    assert ledger.current.operation == nil
    assert %{resource_state: :none, native_operation: :idle} = Ledger.snapshot(ledger)

    assert {:error, :operation_not_permitted} =
             Ledger.begin_operation(ledger, generation, make_ref(), :read)

    assert {:pending, _} = ledger |> Ledger.close_admission() |> Ledger.proof()

    assert {:ok, %{roles: 2, observed_down: 2, cleanup: :confirmed}} =
             ledger |> Ledger.down(down(actor)) |> Ledger.close_admission() |> Ledger.proof()
  end

  test "open cannot be granted before actor enrollment or after cancellation" do
    {ledger, generation, _permit, _requester} = reserved(:file_executor)

    assert {:error, :operation_not_permitted} =
             Ledger.grant_open(ledger, generation, make_ref(), make_ref())

    {ledger, generation, _, _} = file_actor()

    assert {:error, :operation_not_permitted} =
             Ledger.grant_open(Ledger.close_admission(ledger), generation, make_ref(), make_ref())
  end

  test "file server DOWN and handle close do not fabricate native completion" do
    {ledger, generation, operation, _cleanup, actor} = granted_file()
    assert {:ok, ledger} = Ledger.handle_closed(ledger, generation)
    ledger = ledger |> Ledger.down(down(actor)) |> Ledger.close_admission()
    assert {:pending, %{native_operation: :pending, losses: 4}} = Ledger.proof(ledger)

    assert {:error, :unknown_operation} =
             Ledger.complete_operation(ledger, generation, {operation, :open, :opened})

    assert {:error, :unknown_operation} =
             Ledger.complete_operation(ledger, generation, {make_ref(), :open, :enoent})
  end

  test "an entered file open without a returned identity remains an unresolved birth" do
    {ledger, generation, _permit, _requester} = reserved(:file_executor)

    assert {:error, :unknown_operation} =
             Ledger.complete_operation(ledger, generation, {make_ref(), :open, :enoent})

    assert {:error, :unknown_file_generation} = Ledger.handle_closed(ledger, generation)
    assert {:pending, %{allocations: 2}} = ledger |> Ledger.close_admission() |> Ledger.proof()
  end

  test "genuine post-native ENOENT needs no handle but still requires exact actor DOWN" do
    {ledger, generation, operation, _cleanup, actor} = granted_file()

    assert {:ok, ledger} =
             Ledger.complete_operation(ledger, generation, {operation, :open, :enoent})

    assert %{resource_state: :none, native_operation: :idle} = Ledger.snapshot(ledger)
    assert {:pending, _} = ledger |> Ledger.close_admission() |> Ledger.proof()

    assert {:ok, %{cleanup: :confirmed}} =
             ledger |> Ledger.down(down(actor)) |> Ledger.close_admission() |> Ledger.proof()
  end

  test "generic open errors are unknown and cannot be recast as ENOENT" do
    {ledger, generation, operation, _cleanup, actor} = granted_file()

    assert {:ok, ledger} =
             Ledger.complete_operation(ledger, generation, {operation, :open, :unknown})

    assert {:error, :unknown_operation} =
             Ledger.complete_operation(ledger, generation, {operation, :open, :enoent})

    assert {:pending, %{resource_state: :unknown, losses: 4}} =
             ledger |> Ledger.down(down(actor)) |> Ledger.close_admission() |> Ledger.proof()
  end

  test "irrevocable pre-entry skip consumes grant without claiming post-native rejection" do
    {ledger, generation, operation, _cleanup, actor} = granted_file()

    assert {:ok, ledger} =
             Ledger.complete_operation(ledger, generation, {operation, :open, :skipped})

    assert {:error, :operation_not_permitted} =
             Ledger.grant_open(ledger, generation, make_ref(), make_ref())

    assert {:ok, %{cleanup: :confirmed}} = ledger |> Ledger.down(down(actor)) |> Ledger.proof()
  end

  test "file open, serial read, close and DOWN are independent fenced events" do
    {ledger, generation, operation, cleanup, actor} = granted_file()
    read = make_ref()

    assert {:error, :operation_not_permitted} =
             Ledger.begin_operation(ledger, generation, read, :read)

    assert {:ok, ledger} =
             Ledger.complete_operation(ledger, generation, {operation, :open, :opened})

    assert {:ok, ledger} = Ledger.begin_operation(ledger, generation, read, :read)

    assert {:error, :operation_not_permitted} =
             Ledger.begin_operation(ledger, generation, cleanup, :close)

    assert {:ok, ledger} =
             Ledger.complete_operation(ledger, generation, {read, :read, :read_completed})

    ledger = Ledger.close_admission(ledger)

    assert {:error, :admission_closed} =
             Ledger.begin_operation(ledger, generation, make_ref(), :read)

    assert {:ok, ledger} = Ledger.begin_operation(ledger, generation, cleanup, :close)

    assert {:ok, ledger} =
             Ledger.complete_operation(ledger, generation, {cleanup, :close, :closed})

    assert {:pending, _} = Ledger.proof(ledger)
    assert {:ok, %{cleanup: :confirmed}} = ledger |> Ledger.down(down(actor)) |> Ledger.proof()
  end

  test "creator loss retains unfinished native work after file-server DOWN" do
    {ledger, generation, operation, cleanup, actor} = granted_file()
    ledger = Ledger.creator_down(ledger, down(ledger.current.requester))
    assert %{losses: 0, native_operation: :pending} = Ledger.snapshot(ledger)
    ledger = Ledger.down(ledger, down(actor))
    assert {:ok, ledger} = Ledger.handle_closed(ledger, generation)
    assert {:pending, %{losses: 4, native_operation: :pending}} = Ledger.proof(ledger)

    assert {:error, :invalid_drain_summary} =
             Ledger.drain_completed(
               ledger,
               generation,
               {operation, :open, :opened},
               {cleanup, :closed}
             )
  end

  test "Connection death during open permits late close-only drain without native loss" do
    {ledger, generation, operation, cleanup, actor} = granted_file()
    ledger = Ledger.creator_down(ledger, down(ledger.current.requester))

    assert {:error, :operation_not_permitted} =
             Ledger.grant_open(ledger, generation, make_ref(), make_ref())

    assert {:ok, ledger} =
             Ledger.drain_completed(
               ledger,
               generation,
               {operation, :open, :opened},
               {cleanup, :closed}
             )

    assert %{resource_state: :closed, losses: 0} = Ledger.snapshot(ledger)
    assert {:ok, %{cleanup: :confirmed}} = ledger |> Ledger.down(down(actor)) |> Ledger.proof()
  end

  test "missing result ACK or drain cannot erase the outstanding grant" do
    {ledger, _generation, _operation, _cleanup, actor} = granted_file()

    assert {:pending, %{native_operation: :pending}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()

    assert {:pending, %{native_operation: :pending, losses: 4}} =
             ledger |> Ledger.down(down(actor)) |> Ledger.close_admission() |> Ledger.proof()
  end

  test "fixed drain reconciles missing open ACK and is idempotent but contradictions fail" do
    {ledger, generation, operation, cleanup, actor} = granted_file()
    completion = {operation, :open, :opened}

    assert {:ok, ledger} =
             Ledger.drain_completed(ledger, generation, completion, {cleanup, :closed})

    assert {:ok, ^ledger} =
             Ledger.drain_completed(ledger, generation, completion, {cleanup, :closed})

    assert {:error, :invalid_drain_summary} =
             Ledger.drain_completed(ledger, generation, completion, {cleanup, :close_unknown})

    ledger = Ledger.down(ledger, down(actor))

    assert {:ok, ^ledger} =
             Ledger.drain_completed(ledger, generation, completion, {cleanup, :closed})

    assert {:ok, %{cleanup: :confirmed}} = Ledger.proof(ledger)
  end

  test "read result ACK loss drains one read then one contingent close" do
    {ledger, generation, operation, cleanup, actor} = granted_file()
    {:ok, ledger} = Ledger.complete_operation(ledger, generation, {operation, :open, :opened})
    read = make_ref()
    {:ok, ledger} = Ledger.begin_operation(ledger, generation, read, :read)
    ledger = Ledger.creator_down(ledger, down(ledger.current.requester))

    assert {:ok, ledger} =
             Ledger.drain_completed(
               ledger,
               generation,
               {read, :read, :read_completed},
               {cleanup, :closed}
             )

    assert {:ok, %{cleanup: :confirmed}} = ledger |> Ledger.down(down(actor)) |> Ledger.proof()
  end

  test "drain after already committed result is bounded duplicate reconciliation" do
    {ledger, generation, operation, cleanup, actor} = granted_file()
    result = {operation, :open, :opened}
    {:ok, ledger} = Ledger.complete_operation(ledger, generation, result)
    assert {:ok, ^ledger} = Ledger.complete_operation(ledger, generation, result)
    assert {:ok, ledger} = Ledger.drain_completed(ledger, generation, result, {cleanup, :closed})
    assert {:ok, %{cleanup: :confirmed}} = ledger |> Ledger.down(down(actor)) |> Ledger.proof()
  end

  test "invalid drain is atomic and wrong operation generation or cleanup never releases fence" do
    {ledger, generation, operation, cleanup, _actor} = granted_file()

    for {gen, result, close} <- [
          {generation + 1, {operation, :open, :opened}, {cleanup, :closed}},
          {generation, {make_ref(), :open, :opened}, {cleanup, :closed}},
          {generation, {operation, :open, :opened}, {make_ref(), :closed}},
          {generation, {operation, :open, :opened}, :none},
          {generation, {operation, :open, :enoent}, {cleanup, :closed}}
        ] do
      assert {:error, :invalid_drain_summary} = Ledger.drain_completed(ledger, gen, result, close)
      assert ledger.current.operation == {operation, :open}
      assert ledger.current.resource == :none
    end
  end

  test "DOWN after recorded final proof needs no final executor ACK" do
    {ledger, generation, operation, cleanup, actor} = granted_file()

    {:ok, ledger} =
      Ledger.drain_completed(ledger, generation, {operation, :open, :opened}, {cleanup, :closed})

    assert {:ok, %{losses: 0, cleanup: :confirmed}} =
             ledger |> Ledger.down(down(actor)) |> Ledger.proof()
  end

  test "executor death during read close or idle with handle leaves sticky native loss" do
    for stage <- [:idle, :read, :close] do
      {ledger, generation, operation, cleanup, actor} = granted_file()
      {:ok, ledger} = Ledger.complete_operation(ledger, generation, {operation, :open, :opened})

      ledger =
        case stage do
          :idle ->
            ledger

          :read ->
            {:ok, next} = Ledger.begin_operation(ledger, generation, make_ref(), :read)
            next

          :close ->
            {:ok, next} = Ledger.begin_operation(ledger, generation, cleanup, :close)
            next
        end

      ledger = ledger |> Ledger.down(down(actor)) |> Ledger.close_admission()
      assert {:pending, %{losses: 4}} = Ledger.proof(ledger)

      assert {:error, :unknown_operation} =
               Ledger.complete_operation(ledger, generation, {cleanup, :close, :closed})
    end
  end

  test "close return alone and close error remain insufficient and close is never retried" do
    {ledger, generation, operation, cleanup, actor} = granted_file()
    {:ok, ledger} = Ledger.complete_operation(ledger, generation, {operation, :open, :opened})
    {:ok, ledger} = Ledger.handle_closed(ledger, generation)
    assert %{resource_state: :open, handle_close: :pending} = Ledger.snapshot(ledger)

    assert {:error, :operation_not_permitted} =
             Ledger.begin_operation(ledger, generation, make_ref(), :close)

    {:ok, ledger} = Ledger.begin_operation(ledger, generation, cleanup, :close)

    {:ok, ledger} =
      Ledger.complete_operation(ledger, generation, {cleanup, :close, :close_unknown})

    assert {:error, :operation_not_permitted} =
             Ledger.begin_operation(ledger, generation, cleanup, :close)

    assert {:pending, %{resource_state: :unknown}} =
             ledger |> Ledger.down(down(actor)) |> Ledger.close_admission() |> Ledger.proof()
  end

  test "late old-generation DOWN or completion cannot discharge the replacement" do
    {ledger, old} = retired_socket()
    permit = make_ref()
    {:ok, ledger, 2} = Ledger.reserve(ledger, :file_executor, creator(), permit)
    actor = creator()
    {:ok, ledger, :use} = Ledger.enroll(ledger, 2, permit, actor)
    operation = make_ref()
    {:ok, ledger} = Ledger.grant_open(ledger, 2, operation, make_ref())
    assert Ledger.down(ledger, down(old)) == ledger

    assert {:error, :unknown_operation} =
             Ledger.complete_operation(ledger, 1, {operation, :open, :enoent})

    assert {:pending, %{roles: 3, observed_down: 1, native_operation: :pending}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()
  end

  test "network attempt and file index limits have exact N-1 N N+1 boundaries" do
    for {kind, limit} <- [http_socket: 32, file_executor: 256] do
      ledger =
        Enum.reduce(1..limit, Ledger.new(), fn generation, ledger ->
          token = make_ref()
          creator = creator()
          assert {:ok, next, ^generation} = Ledger.reserve(ledger, kind, creator, token)

          assert {:ok, next} =
                   Ledger.reject_before_native(
                     next,
                     generation,
                     token,
                     if(kind == :file_executor, do: :observer, else: creator)
                   )

          assert {:pending, _} = Ledger.proof(next)
          next
        end)

      assert {:error, :auxiliary_limit} = Ledger.reserve(ledger, kind, creator(), make_ref())

      assert {:ok, %{roles: 0, observed_down: 0, cleanup: :confirmed}} =
               ledger |> Ledger.close_admission() |> Ledger.proof()
    end
  end

  test "completed generations retain bounded state and public projection excludes identities" do
    {first, _identity} = retired_socket()

    ledger =
      Enum.reduce(2..32, first, fn generation, ledger ->
        token = make_ref()
        identity = socket()
        assert {:ok, ledger, ^generation} = Ledger.reserve(ledger, :http_socket, creator(), token)
        assert {:ok, ledger, :use} = Ledger.enroll(ledger, generation, token, identity)
        Ledger.down(ledger, down(identity))
      end)

    assert :erlang.external_size(ledger) <= :erlang.external_size(first) + 16

    assert Ledger.snapshot(ledger) == %{
             admission: :open,
             roles: 1,
             observed_down: 1,
             allocations: 0,
             native_operation: :idle,
             handle_close: :not_required,
             resource_state: :none,
             losses: 0
           }

    refute inspect(ledger) =~ inspect(ledger.current.identity)
    refute inspect(ledger) =~ inspect(ledger.current.token)
  end

  test "a prior committed result cannot clear a newer outstanding read" do
    {ledger, generation, operation, cleanup, _actor} = granted_file()
    result = {operation, :open, :opened}
    {:ok, ledger} = Ledger.complete_operation(ledger, generation, result)
    read = make_ref()
    {:ok, ledger} = Ledger.begin_operation(ledger, generation, read, :read)
    assert {:ok, ^ledger} = Ledger.complete_operation(ledger, generation, result)

    assert {:error, :invalid_drain_summary} =
             Ledger.drain_completed(ledger, generation, result, {cleanup, :closed})

    assert ledger.current.operation == {read, :read}
  end

  test "missing close evidence remains pending even when open result was committed" do
    {ledger, generation, operation, _cleanup, actor} = granted_file()
    {:ok, ledger} = Ledger.complete_operation(ledger, generation, {operation, :open, :opened})

    assert {:pending, %{native_operation: :idle, handle_close: :pending}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()

    assert {:pending, %{losses: 4, resource_state: :open}} =
             ledger |> Ledger.down(down(actor)) |> Ledger.close_admission() |> Ledger.proof()
  end

  test "many missing files retain one last result and stale generation cannot release next" do
    ledger =
      Enum.reduce(1..256, Ledger.new(), fn generation, ledger ->
        permit = make_ref()
        actor = creator()
        operation = make_ref()
        {:ok, ledger, ^generation} = Ledger.reserve(ledger, :file_executor, creator(), permit)
        {:ok, ledger, :use} = Ledger.enroll(ledger, generation, permit, actor)
        {:ok, ledger} = Ledger.grant_open(ledger, generation, operation, make_ref())

        assert {:error, :unknown_operation} =
                 Ledger.complete_operation(ledger, generation - 1, {operation, :open, :enoent})

        {:ok, ledger} = Ledger.complete_operation(ledger, generation, {operation, :open, :enoent})
        Ledger.down(ledger, down(actor))
      end)

    assert map_size(ledger.current) == 12
    assert map_size(ledger.counts) == 2
    assert {_, :open, :enoent} = ledger.current.last_result

    assert {:error, :auxiliary_limit} =
             Ledger.reserve(ledger, :file_executor, creator(), make_ref())

    assert {:ok, %{roles: 2, observed_down: 2, cleanup: :confirmed}} =
             ledger |> Ledger.close_admission() |> Ledger.proof()

    refute inspect(Ledger.snapshot(ledger)) =~ inspect(ledger.current.identity)
  end

  defp file_actor do
    {ledger, generation, permit, _requester} = reserved(:file_executor)
    actor = creator()
    {:ok, ledger, :use} = Ledger.enroll(ledger, generation, permit, actor)
    {ledger, generation, permit, actor}
  end

  defp granted_file do
    {ledger, generation, _permit, actor} = file_actor()
    operation = make_ref()
    cleanup = make_ref()
    {:ok, ledger} = Ledger.grant_open(ledger, generation, operation, cleanup)
    {ledger, generation, operation, cleanup, actor}
  end

  defp reserved(kind) do
    token = make_ref()
    creator = creator()
    {:ok, ledger, generation} = Ledger.reserve(Ledger.new(), kind, creator, token)
    {ledger, generation, token, creator}
  end

  defp retired_socket do
    {ledger, generation, token, _creator} = reserved(:http_socket)
    identity = socket()
    {:ok, ledger, :use} = Ledger.enroll(ledger, generation, token, identity)
    {Ledger.down(ledger, down(identity)), identity}
  end

  defp creator, do: {make_ref(), :process, self()}
  defp socket, do: {make_ref(), :socket, :opaque_socket}
  defp down({ref, kind, object}), do: {:DOWN, ref, kind, object, :closed}
end

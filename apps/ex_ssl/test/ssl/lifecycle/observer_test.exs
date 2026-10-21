defmodule SSL.Lifecycle.ObserverTest do
  use ExUnit.Case, async: false

  alias SSL.Lifecycle.{Observer, ObserverSupervisor, Reader, Receipt}

  test "empty cancellation seals once and a late reader needs no live observer" do
    {receipt, lease} = reservation()
    assert {:ok, %{bound?: false, roles: 0}} = Observer.snapshot(receipt, deadline())
    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{cleanup: :confirmed, setup: :cancelled, roles: 0}} =
             Reader.await(receipt, deadline())

    refute Process.alive?(Receipt.observer(receipt))
    assert {:terminal, %{observed_down: 0}} = Reader.status(receipt)
  end

  test "unbound expiry is clipped by the finite setup deadline" do
    {:ok, receipt, _lease} = Observer.start(self(), deadline(30))
    assert {:ok, %{setup_failure: :timeout}} = Reader.await(receipt, deadline())
  end

  test "binding is single-use and finite setup deadline still expires" do
    {:ok, receipt, lease} = Observer.start(self(), deadline(80))
    assert :ok = Observer.bind(receipt, lease, deadline())
    assert {:error, :already_bound} = Observer.bind(receipt, lease, deadline())
    assert {:ok, %{bound?: true, setup: :pending}} = Observer.snapshot(receipt, deadline())
    assert {:ok, %{setup_failure: :timeout}} = Reader.await(receipt, deadline())
  end

  test "infinite bound setup and huge finite deadlines have safe timers" do
    for setup_deadline <- [:infinity, deadline(0xFFFFFFFF + 10_000)] do
      {:ok, receipt, lease} = Observer.start(self(), setup_deadline)
      assert :ok = Observer.bind(receipt, lease, deadline())
      assert {:pending, _} = Reader.await(receipt, deadline(10))
      assert :ok = Observer.cancel(receipt, lease, deadline())
      assert {:ok, _} = Reader.await(receipt, deadline())
    end
  end

  test "controller and bound application owner independently trigger retirement" do
    for role <- [:controller, :owner] do
      controller = actor(fn -> wait() end)
      {:ok, receipt, lease} = Observer.start(controller, :infinity)
      parent = self()

      owner =
        actor(fn ->
          send(parent, {:bound, Observer.bind(receipt, lease, deadline())})
          wait()
        end)

      assert_receive {:bound, :ok}
      Process.exit(if(role == :controller, do: controller, else: owner), :kill)
      assert {:ok, %{setup_failure: :owner_down}} = Reader.await(receipt, deadline())
    end
  end

  test "native port absence is observed independently after its allocator dies" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    parent = self()

    allocator =
      actor(fn ->
        :use = Observer.enroll_self(receipt, :allocator, token, deadline())
        {:ok, tcp_token} = Observer.reserve_child(receipt, :tcp, deadline())
        {:ok, tcp} = :gen_tcp.listen(0, [:binary, active: false])
        :use = Observer.enroll_port(receipt, tcp_token, tcp, deadline())
        send(parent, {:native, tcp})
        wait()
      end)

    assert_receive {:native, tcp}
    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{roles: 17, observed_down: 17, cleanup: :confirmed}} =
             Reader.await(receipt, deadline())

    refute Process.alive?(allocator)
    assert Port.info(tcp) == nil
  end

  test "foreign native port is untouched and its unresolved permit is never cleaned by inference" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    {:ok, foreign} = :gen_tcp.listen(0, [:binary, active: false])
    on_exit(fn -> :gen_tcp.close(foreign) end)
    parent = self()

    actor(fn ->
      :use = Observer.enroll_self(receipt, :allocator, token, deadline())
      {:ok, tcp_token} = Observer.reserve_child(receipt, :tcp, deadline())
      send(parent, {:foreign, Observer.enroll_port(receipt, tcp_token, foreign, deadline())})
      wait()
    end)

    assert_receive {:foreign, {:error, :foreign_or_duplicate_resource}}
    assert Port.info(foreign, :connected) == {:connected, self()}
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:unconfirmed, :observer_unsealed} = Reader.await(receipt, deadline(1_500))
    assert Port.info(foreign) != nil
  end

  test "new allocations require binding, current lease and fixed creator graph" do
    {receipt, lease} = reservation()

    assert {:error, :unauthorized_creator} =
             Observer.reserve_root(receipt, lease, :allocator, deadline())

    assert :ok = Observer.bind(receipt, lease, deadline())

    assert {:error, :unauthorized_creator} =
             Observer.reserve_root(receipt, lease, :writer, deadline())

    assert {:error, :unauthorized_creator} = Observer.reserve_child(receipt, :tcp, deadline())

    assert {:error, :stale_lease} =
             Observer.cancel(receipt, {make_ref(), 0, make_ref()}, deadline())

    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:ok, _} = Reader.await(receipt, deadline())
  end

  test "controller or application owner cannot consume a disposable process permit" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, deadline())

    assert {:error, :foreign_or_duplicate_resource} =
             Observer.enroll_self(receipt, :setup, token, deadline())

    parent = self()

    actor(fn ->
      send(parent, {:enrolled, Observer.enroll_self(receipt, :setup, token, deadline())})
      wait()
    end)

    assert_receive {:enrolled, :use}
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:ok, %{roles: 2, observed_down: 2}} = Reader.await(receipt, deadline())
  end

  test "unrelated DOWN cannot advance live resources or trigger teardown" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    parent = self()

    allocator =
      actor(fn ->
        send(parent, {:enrolled, Observer.enroll_self(receipt, :allocator, token, deadline())})
        wait()
      end)

    assert_receive {:enrolled, :use}
    send(Receipt.observer(receipt), {:DOWN, make_ref(), :process, allocator, :normal})

    assert {:ok, %{roles: 1, observed_down: 0, phase: :open}} =
             Observer.snapshot(receipt, deadline())

    assert Process.alive?(allocator)
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:ok, %{roles: 1, observed_down: 1}} = Reader.await(receipt, deadline())
  end

  test "late delegated child after creator death stops and preserves sticky evidence loss" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    parent = self()

    setup =
      actor(fn ->
        :use = Observer.enroll_self(receipt, :setup, token, deadline())
        {:ok, child_token} = Observer.reserve_child(receipt, :connection, deadline())
        send(parent, {:child_token, child_token})
        wait()
      end)

    assert_receive {:child_token, child_token}
    Process.exit(setup, :kill)

    assert %{admission: :closed, observed_down: 2, losses: 4} =
             closed_snapshot(receipt, deadline())

    child =
      actor(fn ->
        Observer.enroll_self(receipt, :connection, child_token, deadline())
        flunk("late child used")
      end)

    assert {:unconfirmed, :resource_evidence_lost} = Reader.await(receipt, deadline())
    assert {:terminal, %{roles: 6, observed_down: 6, losses: 4}} = Reader.status(receipt)
    refute Process.alive?(child)
  end

  test "normal helper completion forbids future allocation and still waits for actual DOWN" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    parent = self()

    actor(fn ->
      :use = Observer.enroll_self(receipt, :allocator, token, deadline())
      :ok = Observer.helper_done(receipt, deadline())
      send(parent, {:future, Observer.reserve_child(receipt, :tcp, deadline())})
    end)

    assert_receive {:future, {:error, :unauthorized_creator}}
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:ok, %{roles: 1, observed_down: 1}} = Reader.await(receipt, deadline())
  end

  test "receiver checks expired calls after unknown timeout instead of binding late" do
    {receipt, lease} = reservation()
    observer = Receipt.observer(receipt)
    :ok = :sys.suspend(observer)

    try do
      assert {:error, :acceptance_unconfirmed} = Observer.bind(receipt, lease, deadline(20))
    after
      :ok = :sys.resume(observer)
    end

    assert {:ok, %{bound?: false}} = Observer.snapshot(receipt, deadline())
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:ok, _} = Reader.await(receipt, deadline())
  end

  test "killed observer never restarts and cannot produce cleanup success" do
    {receipt, _lease} = reservation()
    observer = Receipt.observer(receipt)
    monitor = Process.monitor(observer)
    Process.exit(observer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^observer, :killed}
    assert {:unconfirmed, :observer_unsealed} = Reader.await(receipt, deadline())

    refute Enum.any?(DynamicSupervisor.which_children(ObserverSupervisor), fn {_, pid, _, _} ->
             pid == observer
           end)

    assert :temporary == Observer.child_spec({self(), :infinity, :dial}).restart
  end

  test "malformed and nonfinite control budgets are rejected without effects" do
    {receipt, lease} = reservation()
    assert {:error, :invalid_deadline} = Observer.cancel(receipt, lease, :infinity)
    assert {:error, :deadline_exceeded} = Observer.bind(receipt, lease, deadline(-1))
    assert {:error, :invalid_controller} = Observer.start(:invalid, :infinity)
    assert {:error, :invalid_deadline} = Observer.start(self(), :invalid)
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:ok, _} = Reader.await(receipt, deadline())
  end

  test "duplicate process objects cannot consume a second role permit" do
    {receipt, lease} = bound()
    {:ok, setup_token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    parent = self()

    actor(fn ->
      :use = Observer.enroll_self(receipt, :setup, setup_token, deadline())
      {:ok, token} = Observer.reserve_child(receipt, :connection, deadline())
      send(parent, {:connection_token, token})
      wait()
    end)

    assert_receive {:connection_token, token}

    actor(fn ->
      :use = Observer.enroll_self(receipt, :connection, token, deadline())
      {:ok, writer_token} = Observer.reserve_child(receipt, :writer, deadline())
      duplicate = Observer.enroll_self(receipt, :writer, writer_token, deadline())
      replay = Observer.enroll_self(receipt, :connection, token, deadline())
      send(parent, {:writer_token, writer_token, duplicate, replay})
      wait()
    end)

    assert_receive {:writer_token, writer_token, {:error, :foreign_or_duplicate_resource},
                    {:error, :unknown_permit}}

    actor(fn ->
      send(parent, {:writer, Observer.enroll_self(receipt, :writer, writer_token, deadline())})
      wait()
    end)

    assert_receive {:writer, :use}
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert {:ok, %{roles: 14, observed_down: 14}} = Reader.await(receipt, deadline())
  end

  test "only enrolled setup can publish a finite failed setup outcome" do
    {receipt, lease} = bound()

    assert {:error, :setup_not_permitted} =
             Observer.publish_setup(receipt, {:failed, :tls}, deadline())

    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    parent = self()

    actor(fn ->
      :use = Observer.enroll_self(receipt, :setup, token, deadline())
      send(parent, :publishing)
      Observer.publish_setup(receipt, {:failed, :tls}, deadline())
    end)

    assert_receive :publishing

    assert {:ok, %{setup: :failed, setup_failure: :tls, roles: 2, observed_down: 2}} =
             Reader.await(receipt, deadline())
  end

  test "repeated cancellation cannot extend unknown-allocation retention" do
    {receipt, lease} = bound()
    {:ok, _unknown} = Observer.reserve_root(receipt, lease, :setup, deadline())
    started = System.monotonic_time(:millisecond)
    assert :ok = Observer.cancel(receipt, lease, deadline())

    for _ <- 1..4 do
      receive do
      after
        150 -> :ok
      end

      assert :ok = Observer.cancel(receipt, lease, deadline())
    end

    assert {:unconfirmed, :observer_unsealed} = Reader.await(receipt, deadline(1_000))
    assert System.monotonic_time(:millisecond) - started < 1_400
  end

  test "setup cannot report completion while its outcome is unresolved" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    parent = self()

    actor(fn ->
      :use = Observer.enroll_self(receipt, :setup, token, deadline())
      send(parent, {:setup_done, Observer.helper_done(receipt, deadline())})
    end)

    assert_receive {:setup_done, {:error, :setup_outcome_pending}}

    assert {:ok, %{setup: :failed, setup_failure: :internal, observed_down: 2}} =
             Reader.await(receipt, deadline())
  end

  test "finite reservation admission remains bounded when supervisor is suspended" do
    baseline = DynamicSupervisor.count_children(ObserverSupervisor).active
    before_monitors = Process.info(self(), :monitors)
    :ok = :sys.suspend(ObserverSupervisor)
    started = System.monotonic_time(:millisecond)

    try do
      assert {:error, :acceptance_unconfirmed} = Observer.start(self(), deadline(40))
      assert System.monotonic_time(:millisecond) - started < 300
    after
      :ok = :sys.resume(ObserverSupervisor)
    end

    assert Process.info(self(), :monitors) == before_monitors
    empty_reservations(baseline, deadline())
    assert Process.info(self(), :messages) == {:messages, []}
  end

  test "bootstrap worker stays bounded when its caller dies after spawn" do
    baseline = DynamicSupervisor.count_children(ObserverSupervisor).active
    controller = self()
    :ok = :sys.suspend(ObserverSupervisor)

    try do
      for _ <- 1..3 do
        caller =
          actor(fn ->
            receive do
              :launch -> Observer.start(controller, deadline(80))
            end
          end)

        :erlang.trace(caller, true, [:procs, {:tracer, self()}])
        send(caller, :launch)
        assert_receive {:trace, ^caller, :spawn, worker, _}, 500
        monitor = Process.monitor(worker)
        Process.exit(caller, :kill)
        assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 500
      end
    after
      :ok = :sys.resume(ObserverSupervisor)
    end

    empty_reservations(baseline, deadline())
  end

  test "a pre-native rejection lets its allocator finish without inventing a TCP resource" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    parent = self()

    actor(fn ->
      :use = Observer.enroll_self(receipt, :allocator, token, deadline())
      {:ok, tcp_token} = Observer.reserve_child(receipt, :tcp, deadline())
      assert {:error, :allocations_pending} = Observer.helper_done(receipt, deadline())
      :ok = Observer.reject_before_native(receipt, :tcp, tcp_token, deadline())
      :ok = Observer.helper_done(receipt, deadline())
      send(parent, {:rejected_before_native, Observer.reserve_child(receipt, :tcp, deadline())})
      wait()
    end)

    assert_receive {:rejected_before_native, {:error, :unauthorized_creator}}

    assert {:ok, %{roles: 1, allocations: 0, losses: 0, observed_down: 0}} =
             Observer.snapshot(receipt, deadline())

    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{cleanup: :confirmed, roles: 1, observed_down: 1}} =
             Reader.await(receipt, deadline())
  end

  test "constructor rejection authenticates caller, attempt, role, token and finite budget" do
    {receipt, lease} = bound()
    {other, other_lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    parent = self()

    allocator =
      actor(fn ->
        :use = Observer.enroll_self(receipt, :allocator, token, deadline())
        {:ok, tcp_token} = Observer.reserve_child(receipt, :tcp, deadline())
        send(parent, {:constructor_token, tcp_token})

        receive do
          :reject ->
            :ok = Observer.reject_before_native(receipt, :tcp, tcp_token, deadline())

            assert {:error, :unknown_permit} =
                     Observer.reject_before_native(receipt, :tcp, tcp_token, deadline())

            assert {:error, :role_used} = Observer.reserve_child(receipt, :tcp, deadline())
            :ok = Observer.helper_done(receipt, deadline())
            send(parent, :constructor_settled)
            wait()
        end
      end)

    assert_receive {:constructor_token, tcp_token}

    assert {:error, :unauthorized_creator} =
             Observer.reject_before_native(receipt, :tcp, tcp_token, deadline())

    assert {:error, :unknown_permit} =
             Observer.reject_before_native(receipt, :tcp, make_ref(), deadline())

    assert {:error, :unknown_permit} =
             Observer.reject_before_native(receipt, :writer, tcp_token, deadline())

    assert {:error, :unknown_permit} =
             Observer.reject_before_native(other, :tcp, tcp_token, deadline())

    assert {:error, :deadline_exceeded} =
             Observer.reject_before_native(receipt, :tcp, tcp_token, deadline(-1))

    assert {:error, :invalid_deadline} =
             Observer.reject_before_native(receipt, :tcp, tcp_token, :infinity)

    assert {:ok, %{allocations: 16, roles: 1, losses: 0}} = Observer.snapshot(receipt, deadline())
    send(allocator, :reject)
    assert_receive :constructor_settled
    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{cleanup: :confirmed, roles: 1, observed_down: 1}} =
             Reader.await(receipt, deadline())

    assert :ok = Observer.cancel(other, other_lease, deadline())
    assert {:ok, %{roles: 0}} = Reader.await(other, deadline())
  end

  test "root constructor rejection leaves roles empty, forbids reuse and does not invent setup failure" do
    {receipt, lease} = bound()

    for role <- [:allocator, :setup] do
      {:ok, token} = Observer.reserve_root(receipt, lease, role, deadline())
      parent = self()

      actor(fn ->
        send(
          parent,
          {:foreign_constructor, Observer.reject_before_native(receipt, role, token, deadline())}
        )
      end)

      assert_receive {:foreign_constructor, {:error, :unauthorized_creator}}
      :ok = Observer.reject_before_native(receipt, role, token, deadline())

      assert {:error, :unknown_permit} =
               Observer.reject_before_native(receipt, role, token, deadline())

      assert {:error, :role_used} = Observer.reserve_root(receipt, lease, role, deadline())
      parent = self()

      actor(fn ->
        send(
          parent,
          {:late_rejected_birth, Observer.enroll_self(receipt, role, token, deadline())}
        )
      end)

      assert_receive {:late_rejected_birth, {:error, :unknown_permit}}
    end

    assert {:ok, %{roles: 0, allocations: 0, observed_down: 0, setup: :pending}} =
             Observer.snapshot(receipt, deadline())

    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{cleanup: :confirmed, setup: :cancelled, setup_failure: :cancelled, roles: 0}} =
             Reader.await(receipt, deadline())
  end

  test "a genuine root rejection can account after cancellation without opening admission" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert {:ok, %{admission: :closed, allocations: 2, setup: :cancelled}} =
             Observer.snapshot(receipt, deadline())

    assert {:error, :admission_closed} =
             Observer.reserve_root(receipt, lease, :allocator, deadline())

    assert :ok = Observer.reject_before_native(receipt, :setup, token, deadline())

    assert {:ok, %{cleanup: :confirmed, roles: 0, observed_down: 0, setup: :cancelled}} =
             Reader.await(receipt, deadline())
  end

  test "creator DOWN is not a constructor rejection and the lost permit remains sticky" do
    {receipt, lease} = bound()
    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    parent = self()

    setup =
      actor(fn ->
        :use = Observer.enroll_self(receipt, :setup, token, deadline())
        {:ok, child_token} = Observer.reserve_child(receipt, :connection, deadline())
        send(parent, {:unresolved_constructor, child_token})
        wait()
      end)

    assert_receive {:unresolved_constructor, child_token}
    Process.exit(setup, :kill)
    assert %{losses: 4, allocations: 4, observed_down: 2} = closed_snapshot(receipt, deadline())

    assert {:error, :unauthorized_creator} =
             Observer.reject_before_native(receipt, :connection, child_token, deadline())

    assert {:ok, %{losses: 4, allocations: 4}} = Observer.snapshot(receipt, deadline())
    actor(fn -> Observer.enroll_self(receipt, :connection, child_token, deadline()) end)
    assert {:unconfirmed, :resource_evidence_lost} = Reader.await(receipt, deadline())
    assert {:terminal, %{losses: 4, roles: 6, observed_down: 6}} = Reader.status(receipt)
  end

  test "an actual setup helper can publish failure after allocator pre-native completion" do
    {receipt, lease} = bound()
    {:ok, allocator_token} = Observer.reserve_root(receipt, lease, :allocator, deadline())
    {:ok, setup_token} = Observer.reserve_root(receipt, lease, :setup, deadline())
    parent = self()

    setup =
      actor(fn ->
        :use = Observer.enroll_self(receipt, :setup, setup_token, deadline())
        send(parent, :setup_enrolled)

        receive do
          :fail_setup -> Observer.publish_setup(receipt, {:failed, :options}, deadline())
        end
      end)

    assert_receive :setup_enrolled

    actor(fn ->
      :use = Observer.enroll_self(receipt, :allocator, allocator_token, deadline())
      {:ok, tcp_token} = Observer.reserve_child(receipt, :tcp, deadline())
      :ok = Observer.reject_before_native(receipt, :tcp, tcp_token, deadline())
      :ok = Observer.helper_done(receipt, deadline())
      send(parent, :allocator_completed_without_native_entry)
    end)

    assert_receive :allocator_completed_without_native_entry
    send(setup, :fail_setup)

    assert {:ok,
            %{
              cleanup: :confirmed,
              setup: :failed,
              setup_failure: :options,
              roles: 3,
              observed_down: 3
            }} =
             Reader.await(receipt, deadline())
  end

  defp empty_reservations(count, {:abs_ms, expiry} = budget) do
    assert System.monotonic_time(:millisecond) < expiry

    if DynamicSupervisor.count_children(ObserverSupervisor).active != count do
      receive do
      after
        1 -> empty_reservations(count, budget)
      end
    end
  end

  defp closed_snapshot(receipt, {:abs_ms, expiry} = budget) do
    assert System.monotonic_time(:millisecond) < expiry
    assert {:ok, snapshot} = Observer.snapshot(receipt, budget)

    if snapshot.observed_down == 2 and snapshot.admission == :closed do
      snapshot
    else
      receive do
      after
        1 -> closed_snapshot(receipt, budget)
      end
    end
  end

  defp reservation do
    {:ok, receipt, lease} = Observer.start(self(), :infinity)

    on_exit(fn ->
      observer = Receipt.observer(receipt)
      if Process.alive?(observer), do: Process.exit(observer, :kill)
    end)

    {receipt, lease}
  end

  defp bound do
    {receipt, lease} = reservation()
    :ok = Observer.bind(receipt, lease, deadline())
    {receipt, lease}
  end

  defp actor(function) do
    pid = spawn(function)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    pid
  end

  defp wait do
    receive do
      :stop -> :ok
    end
  end

  defp deadline(offset \\ 1_000), do: {:abs_ms, System.monotonic_time(:millisecond) + offset}
end

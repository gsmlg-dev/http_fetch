defmodule Quic.CleanupTest do
  use ExUnit.Case, async: true
  alias Quic.Cleanup

  test "constructor retains a native-effect-free durable exclusive receipt" do
    assert {:ok, handle, lease} = Cleanup.new(owner: self())

    assert {:pending, %{version: 1, scope: :exclusive_endpoint, enrolled: 0}} =
             Cleanup.status(handle)

    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.retire(lease, bound())
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.status(handle)
  end

  test "invalid owner is rejected before creating a scope" do
    assert {:error, :invalid_owner} = Cleanup.new(owner: :invalid)
  end

  test "an outstanding pre-effect birth stays pending until its producer disproves it" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound())
    assert {:pending, %{enrolled: 0, unresolved_births: 1}} = Cleanup.retire(lease, bound(0))
    assert :ok = Cleanup.no_birth(birth)

    assert {:ok, %{cleanup: :confirmed, enrolled: 0, unresolved_births: 0}} =
             Cleanup.await(handle, bound())
  end

  test "a late constructed actor is enrolled and joined without granting activation" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound())
    parent = self()

    child =
      spawn(fn ->
        receive do
          :construct -> send(parent, {:enrollment, self(), Cleanup.enroll(birth, self())})
        end
      end)

    monitor = Process.monitor(child)
    assert {:pending, %{unresolved_births: 1}} = Cleanup.retire(lease, bound(0))
    send(child, :construct)
    assert_receive {:enrollment, ^child, {:error, :retiring}}
    assert_receive {:DOWN, ^monitor, :process, ^child, :normal}
    assert {:ok, %{cleanup: :confirmed, enrolled: 1, down: 1}} = Cleanup.await(handle, bound())
  end

  test "late birth reconciliation preserves the original expired effect deadline" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound(50))
    parent = self()

    child =
      spawn(fn ->
        receive do
          :construct -> send(parent, {:late, self(), Cleanup.enroll(birth, self())})
        end
      end)

    # Expire the permit independently of cleanup's observation bound.
    receive do
    after
      60 -> :ok
    end

    send(child, :construct)
    assert_receive {:late, ^child, {:error, :retiring}}
    assert {:ok, %{cleanup: :confirmed, enrolled: 1}} = Cleanup.await(handle, bound())
  end

  test "producer loss with an unresolved birth cannot be converted into no birth" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    parent = self()

    producer =
      spawn(fn ->
        {:ok, _birth} = Cleanup.reserve(lease, :endpoint, bound())
        send(parent, :reserved)
      end)

    monitor = Process.monitor(producer)
    assert_receive :reserved
    assert_receive {:DOWN, ^monitor, :process, ^producer, :normal}

    assert {:error, {:cleanup_unconfirmed, :birth_unresolved}, %{unresolved_births: 1}} =
             Cleanup.await(handle, bound())
  end

  test "only the original producer can disprove a reserved birth" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound())
    parent = self()
    spawn(fn -> send(parent, {:wrong_producer, Cleanup.no_birth(birth)}) end)
    assert_receive {:wrong_producer, {:error, :invalid_birth}}
    assert {:pending, %{unresolved_births: 1}} = Cleanup.status(handle)
    assert :ok = Cleanup.no_birth(birth)
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
  end

  test "stale lease authority cannot retire a different generation" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    stale = %{lease | secret: make_ref()}
    assert {:error, :invalid_lease} = Cleanup.reserve(stale, :endpoint, bound())
    assert {:pending, %{admission: :open}} = Cleanup.retire(stale, bound(0))
    assert {:pending, %{admission: :open}} = Cleanup.status(handle)
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
  end

  test "operation producer and generation are checked and unresolved outcome survives retirement" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    ref = make_ref()

    assert {:error, :invalid_target_generation} =
             Cleanup.operation(lease, :stale, ref, :send, bound())

    assert {:ok, operation} = Cleanup.operation(lease, make_ref(), ref, :send, bound())

    assert {:error, :operation_ref_reused} =
             Cleanup.operation(lease, make_ref(), ref, :send, bound())

    parent = self()
    spawn(fn -> send(parent, {:wrong_result, Cleanup.resolved(operation)}) end)
    assert_receive {:wrong_result, {:error, :invalid_operation_producer}}

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate, unresolved_operations: 1}} =
             Cleanup.retire(lease, bound())

    assert {:ok, %{native_outcome: :indeterminate}} = Cleanup.status(handle)
  end

  test "known operation return compacts independently of the native cleanup graph" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    assert {:ok, operation} = Cleanup.operation(lease, make_ref(), make_ref(), :connect, bound())
    assert :ok = Cleanup.resolved(operation)

    assert {:pending, %{unresolved_operations: 0, native_outcome: :resolved}} =
             Cleanup.status(handle)

    assert {:ok, %{cleanup: :confirmed, native_outcome: :resolved}} =
             Cleanup.retire(lease, bound())
  end

  test "expired operation intent grants no admission" do
    {:ok, handle, lease} = Cleanup.new(owner: self())

    assert {:error, :deadline_expired} =
             Cleanup.operation(lease, make_ref(), make_ref(), :send, bound(-1))

    assert {:pending, %{unresolved_operations: 0}} = Cleanup.status(handle)
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
  end

  test "terminal receipt has concurrent repeatable reads after its observer has exited" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    assert {:ok, receipt} = Cleanup.retire(lease, bound())
    parent = self()

    Enum.each(1..24, fn id ->
      spawn(fn -> send(parent, {:receipt, id, Cleanup.await(handle, bound(0))}) end)
    end)

    Enum.each(1..24, fn _ -> assert_receive {:receipt, _, {:ok, ^receipt}} end)
    assert {:ok, ^receipt} = Cleanup.retire(lease, bound(0))
  end

  test "lost observer and an incomplete payload remain unconfirmed" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    # Unit fault injection into this module's own opaque receipt. Consumers
    # never obtain or inspect provider state to establish cleanup.
    monitor = Process.monitor(handle.observer)
    :atomics.put(handle.receipt, 3, 1)
    :atomics.put(handle.receipt, 4, 1)
    Process.exit(handle.observer, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, :killed}
    assert {:error, {:cleanup_unconfirmed, :observer_lost}, _} = Cleanup.await(handle, bound(0))
    assert {:error, {:cleanup_unconfirmed, :observer_lost}, _} = Cleanup.retire(lease, bound(0))
  end

  test "polling and repeated retirement cannot renew the fixed observer cap" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound())
    parent = self()

    actor =
      spawn(fn ->
        :ok = Cleanup.enroll(birth, self())
        send(parent, :enrolled)

        receive do
          {:quic_cleanup_retire, _} ->
            send(parent, :retirement_seen)
            receive do: (:release -> :ok)
        end
      end)

    monitor = Process.monitor(actor)
    assert_receive :enrolled
    started = System.monotonic_time(:millisecond)
    assert {:pending, _} = Cleanup.retire(lease, bound(0))
    assert_receive :retirement_seen
    assert {:pending, _} = Cleanup.await(handle, bound(1_000))
    assert {:pending, _} = Cleanup.retire(lease, bound(1_000))

    assert {:error, {:cleanup_unconfirmed, :observation_cap}, _} =
             Cleanup.await(handle, bound(4_000))

    assert System.monotonic_time(:millisecond) - started < 6_000
    assert_receive {:DOWN, ^monitor, :process, ^actor, :killed}
  end

  test "retire fences admission immediately while its observer and queued calls are paused" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound())
    parent = self()

    actor =
      spawn(fn ->
        :ok = Cleanup.enroll(birth, self())
        send(parent, :fence_actor_ready)
        receive do: (:reserve -> :ok)
        send(parent, {:queued_reserve, Cleanup.reserve(lease, :io, bound())})
        receive do: ({:quic_cleanup_retire, _} -> :ok)
      end)

    assert_receive :fence_actor_ready
    assert :erlang.suspend_process(handle.observer)

    on_exit(fn ->
      if Process.alive?(handle.observer), do: :erlang.resume_process(handle.observer)
      if Process.alive?(actor), do: Process.exit(actor, :kill)
    end)

    send(actor, :reserve)

    spawn(fn ->
      send(
        parent,
        {:queued_operation, Cleanup.operation(lease, make_ref(), make_ref(), :send, bound())}
      )
    end)

    assert queued_calls?(handle.observer, 2, bound())
    stale = %{lease | secret: make_ref()}
    assert {:pending, %{admission: :open}} = Cleanup.retire(stale, bound(0))
    assert {:pending, %{admission: :closed}} = Cleanup.retire(lease, bound(0))
    assert {:pending, %{admission: :closed}} = Cleanup.status(handle)
    assert :erlang.resume_process(handle.observer)
    assert_receive {:queued_reserve, {:error, :retiring}}
    assert_receive {:queued_operation, {:error, :retiring}}
    assert {:ok, %{cleanup: :confirmed, enrolled: 1, down: 1}} = Cleanup.await(handle, bound())
  end

  test "a paused observer cannot restart the cap from when it processes retirement" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound())
    parent = self()

    actor =
      spawn(fn ->
        :ok = Cleanup.enroll(birth, self())
        send(parent, :cap_actor_ready)
        receive do: ({:quic_cleanup_retire, _} -> receive do: (:release -> :ok))
      end)

    assert_receive :cap_actor_ready
    monitor = Process.monitor(actor)
    assert :erlang.suspend_process(handle.observer)

    on_exit(fn ->
      if Process.alive?(handle.observer), do: :erlang.resume_process(handle.observer)
      if Process.alive?(actor), do: Process.exit(actor, :kill)
    end)

    assert {:pending, _} = Cleanup.retire(lease, bound(0))

    receive do
    after
      5_050 -> :ok
    end

    assert {:pending, _} = Cleanup.retire(lease, bound(0))
    assert :erlang.resume_process(handle.observer)

    assert {:error, {:cleanup_unconfirmed, :observation_cap}, _} =
             Cleanup.await(handle, bound(1_000))

    assert_receive {:DOWN, ^monitor, :process, ^actor, :killed}
  end

  # Internal scheduling seam: no native resource evidence is inferred here.
  defp queued_calls?(observer, count, {:abs_ms, deadline} = bound) do
    case Process.info(observer, :message_queue_len) do
      {:message_queue_len, queued} when queued >= count ->
        true

      _ ->
        if System.monotonic_time(:millisecond) < deadline do
          receive do
          after
            1 -> queued_calls?(observer, count, bound)
          end
        else
          false
        end
    end
  end

  defp bound(timeout \\ 2_000), do: {:abs_ms, System.monotonic_time(:millisecond) + timeout}
end

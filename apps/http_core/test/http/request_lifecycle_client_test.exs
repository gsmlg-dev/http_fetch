defmodule HTTP.RequestLifecycleClientTest do
  use ExUnit.Case, async: true

  alias HTTP.ClientCompletion
  alias HTTP.RequestLifecycle

  setup_all do
    unless Process.whereis(:http_runtime_task_supervisor) do
      start_supervised!({Task.Supervisor, name: :http_runtime_task_supervisor})
    end

    :ok
  end

  test "late cancellation after confirmed worker completion preserves cleanup proof" do
    receipt = ClientCompletion.new()
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)

    {:ok, worker} =
      RequestLifecycle.start_worker(receipt.tracker, :dial, deadline(), fn ->
        receive do
          :finish -> :ok
        end
      end)

    monitor = Process.monitor(worker)
    send(worker, :finish)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}
    wait_worker_absent(receipt.tracker, worker, deadline())
    RequestLifecycle.cancel_worker(receipt.tracker, worker)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "late cancellation never repairs unexplained worker death" do
    receipt = ClientCompletion.new()
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)

    {:ok, worker} =
      RequestLifecycle.start_worker(receipt.tracker, :dial, deadline(), fn ->
        receive do
          :finish -> :ok
        end
      end)

    Process.exit(worker, :kill)
    wait_worker_absent(receipt.tracker, worker, deadline())
    RequestLifecycle.cancel_worker(receipt.tracker, worker)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
  end

  defp wait_worker_absent(tracker, worker, deadline) do
    state = :sys.get_state(tracker)

    if Enum.any?(state.resources, fn {_, {pid, _}} -> pid == worker end) do
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        1 -> wait_worker_absent(tracker, worker, deadline)
      end
    end
  end

  test "precreation permits share one bounded polling timer" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    assert {:ok, _} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
    assert {:ok, _} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
    :ok = :sys.suspend(receipt.tracker)

    try do
      receive do
      after
        30 -> :ok
      end

      {:messages, messages} = Process.info(receipt.tracker, :messages)

      polls =
        Enum.filter(messages, fn
          :poll_children -> true
          {:poll_children, _} -> true
          _ -> false
        end)

      assert [_] = polls
    after
      :sys.resume(receipt.tracker)
      Process.exit(receipt.tracker, :kill)
    end
  end

  test "two permits bound precreation and unknown birth cannot free capacity" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    deadline = deadline()
    assert {:ok, first} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline)
    assert {:ok, second} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline)
    refute first == second

    assert {:error, :cleanup_capacity} =
             RequestLifecycle.reserve_attempt(receipt.tracker, deadline)

    RequestLifecycle.complete(receipt.tracker)
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    Process.exit(receipt.tracker, :kill)
  end

  test "confirmed children fold only after tracker absence, unconfirmed children stay sticky" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
    child = ClientCompletion.new()
    :ok = RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())
    Process.exit(child.tracker, :kill)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(child, 1_000)
    {:ok, _second} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())

    assert {:error, :cleanup_capacity} =
             RequestLifecycle.reserve_attempt(receipt.tracker, deadline())

    Process.exit(receipt.tracker, :kill)
  end

  test "lost admission ACK does not authorize a worker" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    :ok = :sys.suspend(receipt.tracker)

    assert {:error, :request_timeout} =
             RequestLifecycle.reserve_attempt(receipt.tracker, deadline(5))

    :ok = :sys.resume(receipt.tracker)
    Process.exit(receipt.tracker, :kill)
  end

  test "child cleanup is joined after parent owner retirement and settled history folds" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
    child = ClientCompletion.new()
    :ok = RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())
    :ok = RequestLifecycle.enter(child.tracker, :owner)
    parent = self()

    {:ok, worker} =
      RequestLifecycle.start_worker(child.tracker, :dial, deadline(), fn ->
        send(parent, :effect_started)

        receive do
          :finish -> :ok
        end
      end)

    assert_receive :effect_started
    RequestLifecycle.retire_owner(child.tracker)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    send(worker, :finish)
    assert :ok = ClientCompletion.await(child, 1_000)
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "terminal child uncertainty is sticky after client sealing" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
    child = ClientCompletion.new()
    :ok = RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())
    Process.exit(child.tracker, :kill)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(child, 1_000)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
  end

  test "creator death with an unpublished permit cannot be confirmed" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    parent = self()

    creator =
      spawn(fn ->
        result = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
        send(parent, {:reserved, result})
      end)

    monitor = Process.monitor(creator)
    assert_receive {:reserved, {:ok, _permit}}
    assert_receive {:DOWN, ^monitor, :process, ^creator, _}
    RequestLifecycle.retire_owner(receipt.tracker)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
  end

  test "worker admission timeout leaves its effect inert even after tracker resumes" do
    receipt = ClientCompletion.new()
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    :ok = :sys.suspend(receipt.tracker)
    parent = self()

    assert {:error, :request_timeout} =
             RequestLifecycle.start_worker(receipt.tracker, :dial, deadline(10), fn ->
               send(parent, :forbidden_effect)
             end)

    :ok = :sys.resume(receipt.tracker)
    refute_receive :forbidden_effect, 30
    RequestLifecycle.retire_owner(receipt.tracker)
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "repeated confirmed folds retain neither child history nor extra timer chains" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)

    for _ <- 1..100 do
      {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
      child = ClientCompletion.new()
      :ok = RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())
      assert map_size(:sys.get_state(receipt.tracker).children) == 1
      RequestLifecycle.retire_owner(child.tracker)
      assert :ok = ClientCompletion.await(child, 1_000)
    end

    {:ok, _permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
    state = :sys.get_state(receipt.tracker)
    assert map_size(state.children) == 1
    assert MapSet.size(state.completed) == 0
    assert map_size(state.resources) == 1
    :ok = :sys.suspend(receipt.tracker)

    try do
      receive do
      after
        30 -> :ok
      end

      {:messages, messages} = Process.info(receipt.tracker, :messages)
      assert [_] = Enum.filter(messages, &match?({:poll_children, _}, &1))
    after
      :sys.resume(receipt.tracker)
      Process.exit(receipt.tracker, :kill)
    end
  end

  test "expired retained-child ACK retains the known child without authorizing effects" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
    child = ClientCompletion.new()
    :ok = :sys.suspend(receipt.tracker)

    assert {:error, :request_timeout} =
             RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline(5))

    :ok = :sys.resume(receipt.tracker)
    assert %{child: child_pid} = :sys.get_state(receipt.tracker).children[permit]
    assert child_pid == child.tracker
    RequestLifecycle.retire_owner(receipt.tracker)
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    RequestLifecycle.retire_owner(child.tracker)
    assert :ok = ClientCompletion.await(receipt, 1_000)
  end

  test "creator death after published child retains its incomplete authority" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    parent = self()

    creator =
      spawn(fn ->
        {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
        child = ClientCompletion.new()
        :ok = RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())
        send(parent, {:published, child})

        receive do
          :die -> :ok
        end
      end)

    assert_receive {:published, child}
    send(creator, :die)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(child, 1_000)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
  end

  test "creator death while worker registration is queued cannot launch a late effect" do
    receipt = ClientCompletion.new()
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    :ok = :sys.suspend(receipt.tracker)
    parent = self()

    creator =
      spawn(fn ->
        RequestLifecycle.start_worker(receipt.tracker, :dial, deadline(100), fn ->
          send(parent, :late_effect)
        end)
      end)

    wait_registration(receipt.tracker, creator, deadline())
    Process.exit(creator, :kill)
    :ok = :sys.resume(receipt.tracker)
    RequestLifecycle.retire_owner(receipt.tracker)
    assert :ok = ClientCompletion.await(receipt, 1_000)
    refute_receive :late_effect, 30
  end

  test "creator death with queued child publication retains the late receipt" do
    receipt = ClientCompletion.new(:client)
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    parent = self()

    {creator, monitor} =
      spawn_monitor(fn ->
        {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
        child = ClientCompletion.new()
        send(parent, {:ready_to_publish, permit, child})

        receive do
          :publish -> RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())
        end
      end)

    assert_receive {:ready_to_publish, permit, child}
    :ok = :sys.suspend(receipt.tracker)
    send(creator, :publish)
    wait_publication(receipt.tracker, creator, deadline())
    Process.exit(creator, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^creator, :killed}
    :ok = :sys.resume(receipt.tracker)
    assert %{child: child_pid} = :sys.get_state(receipt.tracker).children[permit]
    assert child_pid == child.tracker
    RequestLifecycle.retire_owner(receipt.tracker)
    assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
  end

  defp wait_publication(tracker, creator, deadline) do
    {:messages, messages} = Process.info(tracker, :messages)

    if not Enum.any?(
         messages,
         &match?({:"$gen_call", {^creator, _}, {:retain_attempt, _, _, _, _}}, &1)
       ) do
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        1 -> wait_publication(tracker, creator, deadline)
      end
    end
  end

  for mismatch <- [:unknown_permit, :foreign_creator] do
    test "#{mismatch} child publication preserves uncertainty" do
      receipt = ClientCompletion.new(:client)
      :ok = RequestLifecycle.enter(receipt.tracker, :owner)
      {:ok, permit} = RequestLifecycle.reserve_attempt(receipt.tracker, deadline())
      child = ClientCompletion.new()

      result =
        if unquote(mismatch) == :unknown_permit do
          RequestLifecycle.retain_attempt(receipt.tracker, make_ref(), child, deadline())
        else
          parent = self()

          {pid, monitor} =
            spawn_monitor(fn ->
              send(
                parent,
                {:publication,
                 RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())}
              )
            end)

          assert_receive {:publication, result}
          assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}
          result
        end

      assert {:error, :cleanup_unconfirmed} = result
      assert map_size(:sys.get_state(receipt.tracker).children) == 1
      assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
      assert :ok = RequestLifecycle.retain_attempt(receipt.tracker, permit, child, deadline())
      RequestLifecycle.retire_owner(child.tracker)
      assert :ok = ClientCompletion.await(child, 1_000)
      RequestLifecycle.retire_owner(receipt.tracker)
      assert {:error, :cleanup_unconfirmed} = ClientCompletion.await(receipt, 1_000)
    end
  end

  defp wait_registration(tracker, creator, deadline) do
    {:messages, messages} = Process.info(tracker, :messages)

    if not Enum.any?(
         messages,
         &match?({:"$gen_call", {^creator, _}, {:register_worker, _, _, _}}, &1)
       ) do
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        1 -> wait_registration(tracker, creator, deadline)
      end
    end
  end

  test "asynchronous return orders known worker retention before creator retirement" do
    receipt = ClientCompletion.new()
    :ok = RequestLifecycle.enter(receipt.tracker, :owner)
    :ok = :sys.suspend(receipt.tracker)
    parent = self()

    assert {:ok, worker} =
             RequestLifecycle.start_worker(
               receipt.tracker,
               :dial,
               deadline(),
               fn ->
                 send(parent, :admitted_effect)

                 receive do
                   :finish -> :ok
                 end
               end,
               fn reason -> send(parent, {:unexpected_rejection, reason}) end
             )

    :erlang.suspend_process(worker)
    RequestLifecycle.retire_owner(receipt.tracker)
    {:messages, messages} = Process.info(receipt.tracker, :messages)
    creator = self()

    assert [
             {:"$gen_cast", {:admit_worker, ^worker, :dial, _, ^creator, _}},
             {:"$gen_cast", {:retire_owner, ^creator}}
           ] = messages

    :ok = :sys.resume(receipt.tracker)
    assert %{sealed?: true, resources: resources} = :sys.get_state(receipt.tracker)
    assert [{^worker, :dial}] = Map.values(resources)
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    refute_receive :admitted_effect, 0
    :erlang.resume_process(worker)
    assert_receive :admitted_effect
    assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
    send(worker, :finish)
    assert :ok = ClientCompletion.await(receipt, 1_000)
    refute_receive {:unexpected_rejection, _}, 0
  end

  for boundary <- [:creator_death, :deadline] do
    test "queued worker launch rechecks #{boundary} before effects" do
      receipt = ClientCompletion.new()
      :ok = RequestLifecycle.enter(receipt.tracker, :owner)
      :ok = :sys.suspend(receipt.tracker)
      parent = self()
      opening_deadline = deadline(300)

      {creator, creator_monitor} =
        spawn_monitor(fn ->
          result =
            RequestLifecycle.start_worker(receipt.tracker, :dial, opening_deadline, fn ->
              send(parent, :forbidden_queued_effect)
            end)

          send(parent, {:started, result})

          receive do
            :finish -> :ok
          end
        end)

      wait_registration(receipt.tracker, creator, deadline())
      {:messages, messages} = Process.info(receipt.tracker, :messages)

      {_, _, {:register_worker, worker, :dial, ^opening_deadline}} =
        Enum.find(
          messages,
          &match?({:"$gen_call", {^creator, _}, {:register_worker, _, _, _}}, &1)
        )

      worker_monitor = Process.monitor(worker)
      :erlang.suspend_process(worker)
      :ok = :sys.resume(receipt.tracker)
      assert_receive {:started, {:ok, ^worker}}
      {:messages, worker_messages} = Process.info(worker, :messages)
      assert Enum.any?(worker_messages, &match?({:launch, _}, &1))

      if unquote(boundary) == :creator_death do
        Process.exit(creator, :kill)
        assert_receive {:DOWN, ^creator_monitor, :process, ^creator, :killed}
      else
        receive do
        after
          max(opening_deadline - System.monotonic_time(:millisecond), 0) + 1 -> :ok
        end
      end

      :erlang.resume_process(worker)
      assert_receive {:DOWN, ^worker_monitor, :process, ^worker, :normal}
      send(creator, :finish)
      RequestLifecycle.retire_owner(receipt.tracker)
      assert :ok = ClientCompletion.await(receipt, 1_000)
      refute_receive :forbidden_queued_effect, 0
    end
  end

  defp deadline(ms \\ 1_000), do: System.monotonic_time(:millisecond) + ms
end

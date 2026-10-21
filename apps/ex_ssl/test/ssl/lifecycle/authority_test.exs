defmodule SSL.Lifecycle.AuthorityTest do
  use ExUnit.Case, async: true
  alias SSL.Lifecycle.Authority

  test "attempt binding is single use and cancellation works before allocation" do
    state = fresh()
    lease = Authority.lease(state)
    assert {:error, :invalid_owner} = Authority.bind(state, lease, nil)
    assert {:ok, bound} = Authority.bind(state, lease, self())
    assert {:error, :already_bound} = Authority.bind(bound, lease, self())
    assert {:ok, cancelled} = Authority.cancel(state, lease, 100, 200)
    assert {:ok, ^cancelled} = Authority.cancel(cancelled, lease, 100, 200)
    assert {:error, :cancelled} = Authority.bind(cancelled, lease, self())
  end

  test "foreign attempt, wrong capability and wrong epoch cannot cancel or offer" do
    state = bound()
    {attempt, epoch, capability} = Authority.lease(state)

    for lease <- [
          {make_ref(), epoch, capability},
          {attempt, epoch + 1, capability},
          {attempt, epoch * 1.0, capability},
          {attempt, epoch, make_ref()}
        ] do
      assert {:error, :stale_lease} = Authority.cancel(state, lease, 100, 200)
      assert {:error, :stale_lease} = offer(state, lease)
    end
  end

  test "offers do not revoke the old controller and only the latest nonce accepts" do
    state = bound()
    old = Authority.lease(state)
    assert {:ok, state, stale} = offer(state, old)
    assert {:ok, state, latest} = offer(state, old)
    assert {:error, :stale_transfer} = Authority.accept(state, stale, context(stale))
    {attempt, epoch, nonce} = latest

    assert {:error, :stale_transfer} =
             Authority.accept(state, {attempt, epoch * 1.0, nonce}, context(latest))

    assert {:ok, _, _} = Authority.accept(state, latest, context(latest))
    assert {:ok, cancelled} = Authority.cancel(state, old, 100, 200)
    assert {:error, :cancelled} = Authority.accept(cancelled, latest, context(latest))
  end

  test "acceptance is recipient-bound and requires exact owner acknowledgment" do
    state = bound()
    recipient = another_pid()
    owner = another_pid()
    assert {:ok, state, ticket} = offer(state, Authority.lease(state), recipient, owner)
    ctx = context(ticket, caller: recipient, owner_ack: {elem(ticket, 2), owner})

    assert {:error, :not_recipient} = Authority.accept(state, ticket, %{ctx | caller: self()})

    for ack <- [{make_ref(), owner}, {elem(ticket, 2), self()}, nil] do
      assert {:error, :owner_not_acknowledged} =
               Authority.accept(state, ticket, %{ctx | owner_ack: ack})
    end

    assert {:ok, next, replacement} = Authority.accept(state, ticket, ctx)
    assert next.controller == recipient
    assert next.owner == owner
    assert replacement == Authority.lease(next)
  end

  test "commit revokes old lease and old controller DOWN while retaining new authority" do
    state = bound()
    old = Authority.lease(state)
    old_monitor = state.controller_monitor
    assert {:ok, offered, ticket} = offer(state, old)
    ctx = context(ticket)
    assert {:ok, accepted, replacement} = Authority.accept(offered, ticket, ctx)
    assert {:error, :stale_lease} = Authority.cancel(accepted, old, 100, 200)
    assert {:error, :stale_lease} = offer(accepted, old)
    assert accepted.epoch == state.epoch + 1
    assert accepted.capability != state.capability

    assert Authority.controller_down(accepted, {:DOWN, old_monitor, :process, self(), :normal}) ==
             accepted

    assert {:ok, cancelled} = Authority.cancel(accepted, replacement, 100, 200)
    assert cancelled.phase == :cancelled
  end

  test "lost acceptance reply is recovered idempotently even after offer expiry" do
    state = bound()
    assert {:ok, state, ticket} = offer(state, Authority.lease(state))
    assert {:ok, accepted, replacement} = Authority.accept(state, ticket, context(ticket))
    retry = context(ticket, now: 300, deadline: 400, owner_ack: nil)
    assert {:ok, ^accepted, ^replacement} = Authority.accept(accepted, ticket, retry)

    assert {:error, :not_recipient} =
             Authority.accept(accepted, ticket, %{retry | caller: another_pid()})

    assert {:ok, cancelled} = Authority.cancel(accepted, replacement, 300, 400)
    assert {:ok, ^cancelled, ^replacement} = Authority.accept(cancelled, ticket, retry)
    assert cancelled.phase == :cancelled
    assert {:error, :cancelled} = offer(cancelled, replacement)
  end

  test "a newer offer supersedes recovery of an older committed nonce" do
    state = bound()
    assert {:ok, state, ticket} = offer(state, Authority.lease(state))
    assert {:ok, accepted, replacement} = Authority.accept(state, ticket, context(ticket))
    assert {:ok, next, latest} = offer(accepted, replacement)
    assert {:error, :stale_transfer} = Authority.accept(next, ticket, context(ticket))
    assert {:ok, _, _} = Authority.accept(next, latest, context(latest))
  end

  test "operation deadlines and pending offer expiry reject before committing" do
    state = bound()
    lease = Authority.lease(state)
    assert {:error, :deadline_exceeded} = Authority.cancel(state, lease, 200, 200)

    assert {:error, :deadline_exceeded} =
             Authority.offer(state, lease, target(), make_ref(), 200, 200)

    assert {:ok, state, ticket} = offer(state, lease)
    assert {:error, :offer_expired} = Authority.accept(state, ticket, context(ticket, now: 200))

    assert {:error, :deadline_exceeded} =
             Authority.accept(state, ticket, context(ticket, now: 200, deadline: 200))

    assert %{epoch: 0, phase: :open, transfer: :expired} = Authority.snapshot(state, 200)
    assert {:ok, _} = Authority.cancel(state, lease, 200, 300)
  end

  test "controller death compares exact ref/type/object and never retains reasons" do
    state = bound()
    ref = state.controller_monitor

    for event <- [
          {:DOWN, make_ref(), :process, self(), :normal},
          {:DOWN, ref, :port, self(), :normal},
          {:DOWN, ref, :process, another_pid(), :normal}
        ] do
      assert Authority.controller_down(state, event) == state
    end

    reason = :binary.copy("discard-controller-reason", 1000)
    closed = Authority.controller_down(state, {:DOWN, ref, :process, self(), reason})
    assert closed.phase == :cancelled
    refute :erlang.term_to_binary(closed) =~ reason
  end

  test "invalid targets, nonce reuse and non-fresh monitor/capability reject" do
    state = bound()
    lease = Authority.lease(state)
    assert {:error, :invalid_target} = Authority.offer(state, lease, %{}, make_ref(), 100, 200)
    assert {:ok, state, ticket} = offer(state, lease)

    assert {:error, :invalid_nonce} =
             Authority.offer(state, lease, target(), elem(ticket, 2), 100, 200)

    assert {:error, :invalid_controller_monitor} =
             Authority.accept(state, ticket, context(ticket, monitor: state.controller_monitor))

    assert {:error, :invalid_capability} =
             Authority.accept(state, ticket, context(ticket, capability: state.capability))
  end

  test "snapshot and inspect omit identities and capabilities with constant state size" do
    state = bound()

    state =
      Enum.reduce(1..100, state, fn _, state ->
        assert {:ok, offered, ticket} = offer(state, Authority.lease(state))
        assert {:ok, accepted, _} = Authority.accept(offered, ticket, context(ticket))
        accepted
      end)

    assert Authority.snapshot(state, 100) ==
             %{
               epoch: 100,
               phase: :open,
               bound?: true,
               transfer: :accepted,
               transfer_nonce: elem(state.offer.ticket, 2)
             }

    refute inspect(state) =~ inspect(state.capability)
    refute inspect(state) =~ inspect(state.controller)
    assert map_size(Map.from_struct(state)) == 9
    assert map_size(state.offer) == 5
  end

  test "status correlates the latest nonce at each transfer outcome" do
    state = bound()
    assert %{transfer: :none, transfer_nonce: :none} = Authority.snapshot(state, 100)
    lease = Authority.lease(state)
    assert {:ok, state, first} = offer(state, lease)
    assert %{epoch: 0, transfer: :pending, transfer_nonce: nonce} = Authority.snapshot(state, 100)
    assert nonce == elem(first, 2)
    assert {:ok, replaced, latest} = offer(state, lease)
    latest_nonce = elem(latest, 2)
    assert %{epoch: 0, transfer_nonce: ^latest_nonce} = Authority.snapshot(replaced, 100)

    assert %{transfer: :expired, transfer_nonce: ^latest_nonce} =
             Authority.snapshot(replaced, 200)

    assert {:ok, cancelled} = Authority.cancel(replaced, lease, 100, 200)

    assert %{transfer: :cancelled, transfer_nonce: ^latest_nonce} =
             Authority.snapshot(cancelled, 100)

    assert {:ok, accepted, _} = Authority.accept(replaced, latest, context(latest))

    assert %{epoch: 1, transfer: :accepted, transfer_nonce: ^latest_nonce} =
             Authority.snapshot(accepted, 300)
  end

  test "distinct controller generations ignore all stale DOWN events" do
    state = bound()
    first_ref = state.controller_monitor
    second = another_pid()
    third = another_pid()
    assert {:ok, state, ticket} = offer(state, Authority.lease(state), second, second)
    ctx = context(ticket, caller: second, owner_ack: {elem(ticket, 2), second})
    assert {:ok, state, lease} = Authority.accept(state, ticket, ctx)
    assert {:ok, state, ticket} = offer(state, lease, third, third)
    next_ctx = context(ticket, caller: third, owner_ack: {elem(ticket, 2), third})
    assert {:ok, state, _} = Authority.accept(state, ticket, next_ctx)

    for {ref, controller} <- [{first_ref, self()}, {ctx.monitor, second}] do
      assert Authority.controller_down(state, {:DOWN, ref, :process, controller, :killed}) ==
               state
    end

    assert Authority.controller_down(state, {:DOWN, next_ctx.monitor, :process, third, :killed}).phase ==
             :cancelled
  end

  defp fresh, do: Authority.new(make_ref(), self(), make_ref(), make_ref())

  defp bound do
    state = fresh()
    {:ok, state} = Authority.bind(state, Authority.lease(state), self())
    state
  end

  defp target, do: %{controller: self(), owner: self()}

  defp offer(state, lease, recipient \\ self(), owner \\ self()),
    do:
      Authority.offer(state, lease, %{controller: recipient, owner: owner}, make_ref(), 100, 200)

  defp context(ticket, overrides \\ []) do
    Map.merge(
      %{
        caller: self(),
        owner_ack: {elem(ticket, 2), self()},
        monitor: make_ref(),
        capability: make_ref(),
        now: 100,
        deadline: 400
      },
      Map.new(overrides)
    )
  end

  defp another_pid do
    pid = spawn(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> Process.exit(pid, :kill) end)
    pid
  end
end

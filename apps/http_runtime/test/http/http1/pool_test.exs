defmodule HTTP.HTTP1.PoolTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP1.Pool

  defmodule Transport do
    def setopts({observer, ref, mode}, opts) do
      send(observer, {:setopts, ref, opts})

      if mode == :block_activation and opts == [active: :once] do
        send(observer, {:activation_waiting, self(), ref})
        receive do: ({:continue_activation, ^ref} -> :ok)
      else
        :ok
      end
    end

    def recv({observer, ref, mode}, 0, 0) do
      if mode == :block_recv do
        send(observer, {:recv_waiting, self(), ref})
        receive do: ({:continue_recv, ^ref} -> {:error, :timeout})
      else
        {:error, :timeout}
      end
    end

    def controlling_process({observer, ref, _}, owner) do
      send(observer, {:transferred, ref, owner})
      :ok
    end

    def close({observer, ref, _}) do
      send(observer, {:closed, ref})
      :ok
    end

    def normalize_message({:socket_event, ref}, {_, ref, _}), do: :closed
    def normalize_message(_, _), do: :unknown
  end

  test "repeated checkin and checkout reuse one logical tick without entry timers" do
    {:ok, initial} = Pool.init([])
    socket = {self(), make_ref(), :normal}
    key = %{http1_policy: {2, 30_000}}

    state =
      Enum.reduce(1..500, initial, fn _, state ->
        {:reply, {:ok, token}, pending} = prepare(state, key, socket)
        if state.expiry_timer, do: assert(pending.expiry_timer == state.expiry_timer)
        refute Map.has_key?(pending.entries[token], :timer)
        {:reply, :ok, idle} = Pool.handle_call({:activate, token}, {self(), nil}, pending)
        {:reply, {:ok, ^socket}, empty} = Pool.handle_call({:checkout, key}, {self(), nil}, idle)
        assert empty.entries == %{}
        assert empty.expiry_timer == pending.expiry_timer
        empty
      end)

    assert is_reference(state.expiry_timer)
    :erlang.cancel_timer(state.expiry_timer)
    refute_receive {:closed, _}
  end

  test "stale expiry messages cannot close an unexpired idle entry or create extra ticks" do
    {:ok, initial} = Pool.init([])
    socket = {self(), make_ref(), :normal}
    key = %{http1_policy: {2, 30_000}}
    {:reply, {:ok, token}, pending} = prepare(initial, key, socket)
    {:reply, :ok, idle} = Pool.handle_call({:activate, token}, {self(), nil}, pending)

    assert {:noreply, ^idle} = Pool.handle_info({:timeout, make_ref(), :expire}, idle)
    assert {:noreply, ^idle} = Pool.handle_info({:expire, token}, idle)
    assert {:noreply, ^idle} = Pool.handle_info({:expire, make_ref()}, idle)

    expired = put_in(idle.entries[token].expires_at, System.monotonic_time(:millisecond) - 1)
    :erlang.cancel_timer(idle.expiry_timer)
    assert {:noreply, empty} = Pool.handle_info({:timeout, idle.expiry_timer, :expire}, expired)
    assert empty.entries == %{}
    assert empty.expiry_timer == nil
    assert_receive {:closed, _}
    assert {:noreply, ^empty} = Pool.handle_info({:timeout, idle.expiry_timer, :expire}, empty)
    refute_receive {:closed, _}
  end

  test "checkout rejects an expired entry without waiting for maintenance" do
    {:ok, initial} = Pool.init([])
    socket = {self(), make_ref(), :normal}
    key = %{http1_policy: {2, 0}}
    {:reply, {:ok, token}, pending} = prepare(initial, key, socket)
    {:reply, :ok, idle} = Pool.handle_call({:activate, token}, {self(), nil}, pending)

    assert {:reply, :none, empty} = Pool.handle_call({:checkout, key}, {self(), nil}, idle)
    assert empty.entries == %{}
    assert_receive {:closed, _}
    refute_receive {:transferred, _, _}
    :erlang.cancel_timer(empty.expiry_timer)
  end

  test "activation only consumes a pending entry owned by its caller" do
    {:ok, initial} = Pool.init([])
    socket = {self(), make_ref(), :normal}
    key = %{http1_policy: {2, 30_000}}
    {:reply, {:ok, token}, pending} = prepare(initial, key, socket)
    stranger = spawn(fn -> :ok end)

    assert {:reply, :expired, ^pending} =
             Pool.handle_call({:activate, token}, {stranger, nil}, pending)

    {:reply, :ok, idle} = Pool.handle_call({:activate, token}, {self(), nil}, pending)
    assert {:reply, :expired, ^idle} = Pool.handle_call({:activate, token}, {self(), nil}, idle)
    refute_receive {:closed, _}
    :erlang.cancel_timer(idle.expiry_timer)
    Pool.terminate(:normal, idle)
  end

  test "pending ownership transfer expires even if its tick has not been handled" do
    {:ok, initial} = Pool.init([])
    socket = {self(), make_ref(), :normal}
    key = %{http1_policy: {2, 30_000}}
    {:reply, {:ok, token}, pending} = prepare(initial, key, socket)
    expired = put_in(pending.entries[token].expires_at, System.monotonic_time(:millisecond) - 1)

    assert {:reply, :expired, empty} =
             Pool.handle_call({:activate, token}, {self(), nil}, expired)

    assert empty.entries == %{}
    assert_receive {:closed, _}
    refute_receive {:setopts, _, [active: :once]}
    :erlang.cancel_timer(empty.expiry_timer)
  end

  test "activation delayed by transport cannot extend the pending transfer deadline" do
    pool = start_supervised!({Pool, name: nil})
    ref = make_ref()
    parent = self()
    key = %{http1_policy: {2, 30_000}}

    owner =
      spawn(fn ->
        {:ok, token} =
          GenServer.call(pool, {:prepare, key, Transport, {parent, ref, :block_activation}})

        send(parent, {:activation_result, GenServer.call(pool, {:activate, token})})
      end)

    monitor = Process.monitor(owner)
    assert_receive {:activation_waiting, ^pool, ^ref}
    # A timer witnesses elapsed deadline time while the actor holds setopts.
    # This checks logical activation behavior, not native reclamation.
    witness = :erlang.start_timer(1_001, self(), :pending_deadline)
    assert_receive {:timeout, ^witness, :pending_deadline}, 2_000
    send(pool, {:continue_activation, ref})
    assert_receive {:activation_result, :expired}
    assert_receive {:closed, ^ref}
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    assert :none = GenServer.call(pool, {:checkout, key})
  end

  test "a handoff accepted by its deadline remains valid after a delayed reply" do
    ref = make_ref()
    key = %{http1_policy: {2, 30_000}}
    parent = self()

    tracker =
      spawn(fn ->
        receive do
          {:"$gen_call", from, {:handoff, resources, deadline} = request} ->
            {:reply, :ok, _} = HTTP.RequestLifecycle.handle_call(request, from, %{resources: %{}})
            send(parent, {:handoff_accepted, self(), resources, deadline})

            receive do
              :reply -> GenServer.reply(from, :ok)
            end
        end
      end)

    task =
      Task.async(fn ->
        {:ok, initial} = Pool.init([])

        {:reply, {:ok, token}, pending} =
          Pool.handle_call(
            {:prepare, key, Transport, {parent, ref, :normal}},
            {parent, nil},
            initial
          )

        result = Pool.handle_call({:activate, token, tracker}, {parent, nil}, pending)
        :erlang.cancel_timer(pending.expiry_timer)
        result
      end)

    assert_receive {:handoff_accepted, ^tracker, [_socket], deadline}

    witness =
      :erlang.start_timer(
        max(deadline - System.monotonic_time(:millisecond), 0) + 1,
        self(),
        :handoff_deadline
      )

    assert_receive {:timeout, ^witness, :handoff_deadline}, 2_000
    send(tracker, :reply)
    assert {:reply, :ok, state} = Task.await(task)
    assert [{_token, %{status: :idle}}] = Map.to_list(state.entries)
    refute_receive {:closed, ^ref}, 0
  end

  test "socket event queued during checkout prevents reuse" do
    pool = start_supervised!({Pool, name: nil})
    ref = make_ref()
    socket = {self(), ref, :block_recv}
    key = %{http1_policy: {2, 30_000}}
    {:ok, token} = GenServer.call(pool, {:prepare, key, Transport, socket})
    assert :ok = GenServer.call(pool, {:activate, token})
    parent = self()

    caller =
      spawn(fn -> send(parent, {:checkout_result, GenServer.call(pool, {:checkout, key})}) end)

    monitor = Process.monitor(caller)

    assert_receive {:recv_waiting, ^pool, ^ref}
    send(pool, {:socket_event, ref})
    send(pool, {:continue_recv, ref})
    assert_receive {:closed, ^ref}
    assert_receive {:checkout_result, :none}
    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}
    refute_receive {:transferred, ^ref, _}
  end

  test "checkout delayed by transport cannot lease an entry after its idle deadline" do
    pool = start_supervised!({Pool, name: nil})
    ref = make_ref()
    key = %{http1_policy: {2, 100}}
    {:ok, token} = GenServer.call(pool, {:prepare, key, Transport, {self(), ref, :block_recv}})
    assert :ok = GenServer.call(pool, {:activate, token})
    parent = self()

    caller =
      spawn(fn -> send(parent, {:checkout_result, GenServer.call(pool, {:checkout, key})}) end)

    monitor = Process.monitor(caller)

    assert_receive {:recv_waiting, ^pool, ^ref}
    witness = :erlang.start_timer(101, self(), :idle_deadline)
    assert_receive {:timeout, ^witness, :idle_deadline}, 1_000
    send(pool, {:continue_recv, ref})
    assert_receive {:checkout_result, :none}
    assert_receive {:closed, ^ref}
    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}
    refute_receive {:transferred, ^ref, _}
  end

  test "pending caller death and pool retirement discard entries before later activation" do
    pool = start_supervised!({Pool, name: nil})
    key = %{http1_policy: {2, 30_000}}
    ref = make_ref()
    parent = self()

    owner =
      spawn(fn ->
        send(
          parent,
          {:prepared, GenServer.call(pool, {:prepare, key, Transport, {parent, ref, :normal}})}
        )

        receive do: (:finish -> :ok)
      end)

    monitor = Process.monitor(owner)
    assert_receive {:prepared, {:ok, token}}
    send(owner, :finish)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}
    assert_receive {:closed, ^ref}
    assert :expired = GenServer.call(pool, {:activate, token})

    next_ref = make_ref()

    assert {:ok, next} =
             GenServer.call(pool, {:prepare, key, Transport, {self(), next_ref, :normal}})

    GenServer.cast(pool, :close_idle)
    assert :expired = GenServer.call(pool, {:activate, next})
    assert_receive {:closed, ^next_ref}
    assert :full = GenServer.call(pool, {:prepare, key, Transport, {self(), make_ref(), :normal}})
    assert :none = GenServer.call(pool, {:checkout, key})
  end

  defp prepare(state, key, socket),
    do: Pool.handle_call({:prepare, key, Transport, socket}, {self(), nil}, state)
end

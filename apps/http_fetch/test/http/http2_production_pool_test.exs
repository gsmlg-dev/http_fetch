defmodule HTTP.HTTP2ProductionPoolTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{ConnectionOwner, ConnectionSupervisor, Pool}

  defmodule IdleOwner do
    use GenServer
    def start_link, do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, nil}
    def handle_info(_, state), do: {:noreply, state}
  end

  test "expired reservations are rejected before queueing" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1})
    deadline = System.monotonic_time(:millisecond) - 1
    assert {:error, :deadline_exceeded} = Pool.reserve(pool, :key, deadline_at: deadline)
    assert Pool.stats(pool) == %{}
  end

  test "queued deadline expires and releases its key" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1})
    deadline = System.monotonic_time(:millisecond) + 100
    task = Task.async(fn -> Pool.reserve(pool, :key, deadline_at: deadline) end)
    assert {:error, :deadline_exceeded} = Task.await(task, 2_000)
    assert Pool.stats(pool) == %{}
  end

  test "owner death reconciles reservations and releases the key" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1})

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    assert :ok = Pool.register(pool, :key, owner)
    assert {:ok, ^owner, token} = Pool.reserve(pool, :key)
    assert %{streams: 1} = Pool.stats(pool)[:key]
    ref = Process.monitor(owner)
    send(owner, :stop)
    assert_receive {:DOWN, ^ref, :process, ^owner, _}
    assert :ok = Pool.release(pool, :key, token)
    assert Pool.stats(pool) == %{}
  end

  test "peer SETTINGS capacity gates and reopens admissions" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1, max_streams: 3})

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    assert :ok = Pool.register(pool, :key, owner)
    assert :ok = Pool.update_capacity(pool, :key, owner, 0)
    assert :none = Pool.try_reserve(pool, :key)
    assert :ok = Pool.update_capacity(pool, :key, owner, 1)
    assert {:ok, ^owner, token} = Pool.try_reserve(pool, :key)
    assert :none = Pool.try_reserve(pool, :key)
    assert :ok = Pool.release(pool, :key, token)
  end

  test "owner attachment reports a pool and async capacity updates wake waiters" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1, max_streams: 2})
    parent = self()

    owner =
      spawn(fn ->
        receive do
          {:http2_pool, pool_pid, key} -> send(parent, {:attached, pool_pid, key})
        end

        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    assert :ok = Pool.register(pool, :key, owner, max_streams: 0)
    assert_receive {:attached, ^pool, :key}
    assert :none = Pool.try_reserve(pool, :key)
    GenServer.cast(pool, {:owner_capacity, :key, owner, 1})
    assert {:ok, ^owner, token} = Pool.try_reserve(pool, :key)
    GenServer.cast(pool, {:owner_draining, :key, owner})
    assert :none = Pool.try_reserve(pool, :key)
    assert :ok = Pool.release(pool, :key, token)
  end

  test "global connection and key bounds cover connector claims" do
    {:ok, pool} =
      start_supervised({Pool, max_connections: 2, max_total_connections: 1, max_keys: 1})

    assert :start = Pool.claim_connect(pool, :first)
    assert :wait = Pool.claim_connect(pool, :second)
    assert :wait = Pool.claim_connect(pool, :first)
    assert %{connecting: 1} = Pool.stats(pool)[:first]
    assert :ok = Pool.fail_connect(pool, :first, :failed)
    assert Pool.stats(pool) == %{}
    assert :start = Pool.claim_connect(pool, :second)
  end

  test "draining replacement still obeys the global connection bound" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1, max_total_connections: 1})

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    assert :ok = Pool.register(pool, :key, owner)
    assert :ok = Pool.mark_draining(pool, :key, owner)
    assert :wait = Pool.claim_connect(pool, :key)
  end

  test "caller death releases an active reservation" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1, max_streams: 1})

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> send(owner, :stop) end)
    assert :ok = Pool.register(pool, :key, owner, max_streams: 1)
    parent = self()

    caller =
      spawn(fn ->
        send(parent, {:reserved, Pool.reserve(pool, :key)})

        receive do
          :stop -> :ok
        end
      end)

    assert_receive {:reserved, {:ok, ^owner, _token}}
    assert :none = Pool.try_reserve(pool, :key)
    ref = Process.monitor(caller)
    send(caller, :stop)
    assert_receive {:DOWN, ^ref, :process, ^caller, _}
    assert {:ok, ^owner, token} = await_reservation(pool, :key, owner, 100)
    assert :ok = Pool.release(pool, :key, token)
  end

  test "connector death releases its claim" do
    {:ok, pool} = start_supervised({Pool, max_connections: 1})
    parent = self()

    connector =
      spawn(fn ->
        send(parent, {:claim, Pool.claim_connect(pool, :key)})

        receive do
          :stop -> :ok
        end
      end)

    assert_receive {:claim, :start}
    ref = Process.monitor(connector)
    send(connector, :stop)
    assert_receive {:DOWN, ^ref, :process, ^connector, _}
    assert :start = Pool.claim_connect(pool, :key)
  end

  test "temporary connection owner survives request caller death" do
    {:ok, supervisor} = start_supervised(ConnectionSupervisor)
    parent = self()

    transport = %{
      send: fn _, data ->
        send(parent, {:wire, data})
        :ok
      end
    }

    caller =
      spawn(fn ->
        result =
          ConnectionSupervisor.start_connection(
            [transport: transport, activate?: false],
            supervisor
          )

        send(parent, {:started, self(), result})

        receive do
          :stop -> :ok
        end
      end)

    ref = Process.monitor(caller)
    assert_receive {:started, ^caller, {:ok, owner}}, 5_000
    # start_link acknowledges init before handle_continue writes the preface.
    assert %{lifecycle: :ready} = ConnectionOwner.status(owner)
    assert_receive {:wire, _}
    send(caller, :stop)
    assert_receive {:DOWN, ^ref, :process, ^caller, _}
    assert Process.alive?(owner)
    assert [{_, ^owner, :worker, _}] = DynamicSupervisor.which_children(supervisor)
  end

  test "factory owner with no surviving waiter expires instead of occupying capacity" do
    parent = self()

    factory = fn _key, _opts ->
      send(parent, {:factory_waiting, self()})

      receive do
        :continue -> :ok
      end

      {:ok, owner} = IdleOwner.start_link()
      send(parent, {:factory_owner, owner})
      {:ok, owner}
    end

    {:ok, pool} = start_supervised({Pool, owner_factory: factory, idle_timeout: 20})
    caller = spawn(fn -> Pool.reserve(pool, :orphan) end)
    assert_receive {:factory_waiting, connector}
    ref = Process.monitor(caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^ref, :process, ^caller, :killed}
    send(connector, :continue)
    assert_receive {:factory_owner, owner}
    owner_ref = Process.monitor(owner)
    assert_receive {:DOWN, ^owner_ref, :process, ^owner, _}, 1_000
    assert Pool.stats(pool) == %{}
  end

  defp await_reservation(_pool, _key, _owner, 0), do: flunk("reservation was not released")

  defp await_reservation(pool, key, owner, attempts) do
    case Pool.try_reserve(pool, key) do
      {:ok, ^owner, _token} = result -> result
      :none -> await_reservation(pool, key, owner, attempts - 1)
    end
  end
end

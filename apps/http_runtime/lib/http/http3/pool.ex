defmodule HTTP.HTTP3.Pool do
  @moduledoc "Bounded FIFO HTTP/3 leases with monitored connector and owner lifetimes."
  use GenServer

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  def reserve(pool, key, opts \\ []),
    do: GenServer.call(pool, {:reserve, key, opts}, Keyword.get(opts, :timeout, 5_000) + 1_000)

  def register(pool, key, owner, token \\ nil, capacity \\ nil),
    do: GenServer.call(pool, {:register, key, owner, token, capacity})

  def release(pool, token), do: GenServer.call(pool, {:release, token})
  def drain(pool, owner), do: GenServer.cast(pool, {:drain, owner})
  def status(pool), do: GenServer.call(pool, :status)

  @impl true
  def init(opts) do
    {:ok,
     %{
       owners: %{},
       leases: %{},
       waiters: [],
       monitors: %{},
       max_streams: Keyword.get(opts, :max_streams, 32),
       stream_limit: Keyword.get(opts, :max_streams),
       max_pending: Keyword.get(opts, :max_pending, 128),
       max_connections: Keyword.get(opts, :max_connections, 2),
       max_total_connections: Keyword.get(opts, :max_total_connections, 20),
       max_keys: Keyword.get(opts, :max_keys, 100)
     }}
  end

  @impl true
  def handle_call(:status, _from, state),
    do:
      {:reply,
       %{
         owners: map_size(state.owners),
         leases: map_size(state.leases),
         pending: length(state.waiters),
         draining: Enum.count(state.owners, fn {_, value} -> value.draining end)
       }, state}

  def handle_call({:register, key, owner, token, capacity}, _from, state) do
    capacity = capacity || state.max_streams

    cond do
      not is_pid(owner) or not Process.alive?(owner) ->
        {:reply, {:error, :invalid_owner}, state}

      not valid_owner_capacity?(capacity) ->
        {:reply, {:error, :invalid_owner_capacity}, state}

      Map.has_key?(state.owners, owner) ->
        {:reply, {:error, :owner_already_registered}, state}

      token != nil and not valid_connector?(state, key, token) ->
        {:reply, {:error, :invalid_connector}, state}

      token == nil and not can_connect?(state, key) ->
        {:reply, {:error, :pool_capacity}, state}

      true ->
        monitor = Process.monitor(owner)
        capacity = if state.stream_limit, do: min(capacity, state.stream_limit), else: capacity

        next = %{
          state
          | owners:
              Map.put(state.owners, owner, %{key: key, draining: false, capacity: capacity}),
            monitors: Map.put(state.monitors, monitor, {:owner, owner})
        }

        next = if token, do: put_in(next.leases[token].owner, owner), else: next
        send(owner, {:http3_pool, self(), key})
        {:reply, :ok, dispatch(next)}
    end
  end

  def handle_call({:reserve, key, opts}, from, state) do
    case available(state, key) do
      owner when is_pid(owner) ->
        {token, next} = lease(state, key, owner, elem(from, 0))
        {:reply, {:ok, owner, token}, next}

      nil ->
        cond do
          can_connect?(state, key) ->
            {token, next} = lease(state, key, nil, elem(from, 0))
            {:reply, {:connect, token}, next}

          length(state.waiters) >= state.max_pending ->
            {:reply, {:error, :pool_queue_full}, state}

          true ->
            token = make_ref()
            monitor = Process.monitor(elem(from, 0))

            timer =
              Process.send_after(self(), {:expire, token}, Keyword.get(opts, :timeout, 5_000))

            waiter = %{key: key, token: token, from: from, monitor: monitor, timer: timer}

            {:noreply,
             %{
               state
               | waiters: state.waiters ++ [waiter],
                 monitors: Map.put(state.monitors, monitor, {:waiter, token})
             }}
        end
    end
  end

  def handle_call({:release, token}, _from, state),
    do: {:reply, :ok, dispatch(forget_lease(state, token))}

  @impl true
  def handle_cast({:drain, owner}, state) do
    next =
      if Map.has_key?(state.owners, owner),
        do: put_in(state.owners[owner].draining, true),
        else: state

    {:noreply, dispatch(next)}
  end

  @impl true
  def handle_info({:expire, token}, state) do
    {expired, remaining} = Enum.split_with(state.waiters, &(&1.token == token))
    for waiter <- expired, do: GenServer.reply(waiter.from, {:error, :pool_timeout})
    {:noreply, Enum.reduce(expired, %{state | waiters: remaining}, &forget_waiter(&2, &1))}
  end

  def handle_info({:DOWN, monitor, :process, _pid, reason}, state) do
    case state.monitors[monitor] do
      {:owner, owner} ->
        tokens = for {token, lease} <- state.leases, lease.owner == owner, do: token

        next =
          Enum.reduce(
            tokens,
            %{
              state
              | owners: Map.delete(state.owners, owner),
                monitors: Map.delete(state.monitors, monitor)
            },
            &forget_lease(&2, &1)
          )

        {:noreply, dispatch(next)}

      {:lease, token} ->
        {:noreply, dispatch(forget_lease(state, token))}

      {:waiter, token} ->
        {removed, kept} = Enum.split_with(state.waiters, &(&1.token == token))
        {:noreply, Enum.reduce(removed, %{state | waiters: kept}, &forget_waiter(&2, &1))}

      nil ->
        _ = reason
        {:noreply, state}
    end
  end

  @impl true
  def terminate(_reason, state) do
    for {owner, _} <- state.owners, do: send(owner, :http3_pool_down)
    for waiter <- state.waiters, do: GenServer.reply(waiter.from, {:error, :pool_down})
    :ok
  end

  defp valid_owner_capacity?(capacity), do: is_integer(capacity) and capacity in 1..128

  defp valid_connector?(state, key, token) do
    case state.leases[token] do
      %{key: ^key, owner: nil} -> true
      _ -> false
    end
  end

  defp lease(state, key, owner, caller) do
    token = make_ref()
    monitor = Process.monitor(caller)

    {token,
     %{
       state
       | leases: Map.put(state.leases, token, %{key: key, owner: owner, monitor: monitor}),
         monitors: Map.put(state.monitors, monitor, {:lease, token})
     }}
  end

  defp forget_lease(state, token) do
    case Map.pop(state.leases, token) do
      {nil, _} ->
        state

      {lease, remaining} ->
        Process.demonitor(lease.monitor, [:flush])
        %{state | leases: remaining, monitors: Map.delete(state.monitors, lease.monitor)}
    end
  end

  defp forget_waiter(state, waiter) do
    _ = Process.cancel_timer(waiter.timer)
    Process.demonitor(waiter.monitor, [:flush])
    %{state | monitors: Map.delete(state.monitors, waiter.monitor)}
  end

  defp available(state, key) do
    Enum.find_value(state.owners, fn {owner, info} ->
      count = Enum.count(state.leases, fn {_, lease} -> lease.owner == owner end)
      if info.key == key and not info.draining and count < info.capacity, do: owner
    end)
  end

  defp can_connect?(state, key) do
    connections =
      Enum.count(state.owners, fn {_, info} -> info.key == key and not info.draining end)

    connecting =
      Enum.count(state.leases, fn {_, lease} -> lease.key == key and lease.owner == nil end)

    total_connecting = Enum.count(state.leases, fn {_, lease} -> lease.owner == nil end)

    keys =
      Enum.uniq(
        Enum.map(state.owners, fn {_, info} -> info.key end) ++
          Enum.map(state.leases, fn {_, lease} -> lease.key end)
      )

    connections + connecting < state.max_connections and
      map_size(state.owners) + total_connecting < state.max_total_connections and
      (key in keys or length(keys) < state.max_keys)
  end

  defp dispatch(state) do
    Enum.reduce(state.waiters, %{state | waiters: []}, fn waiter, next ->
      case available(next, waiter.key) do
        owner when is_pid(owner) ->
          next = forget_waiter(next, waiter)
          {token, next} = lease(next, waiter.key, owner, elem(waiter.from, 0))
          GenServer.reply(waiter.from, {:ok, owner, token})
          next

        nil ->
          if can_connect?(next, waiter.key) do
            next = forget_waiter(next, waiter)
            {token, next} = lease(next, waiter.key, nil, elem(waiter.from, 0))
            GenServer.reply(waiter.from, {:connect, token})
            next
          else
            %{next | waiters: next.waiters ++ [waiter]}
          end
      end
    end)
  end
end

defmodule HTTP.HTTP2.Pool do
  @moduledoc "Bounded profile-aware HTTP/2 connection pool."
  use GenServer

  @type key :: term()
  @type reservation :: reference()

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
  end

  @doc "Atomically reserves one stream slot for `key`."
  @spec reserve(pid(), key(), keyword()) ::
          {:ok, pid(), reservation()} | {:queued, reservation()} | {:error, term()}
  def reserve(pool, key, opts \\ []), do: GenServer.call(pool, {:reserve, key, opts})

  @doc "Reserves an available stream without queueing or starting a connection."
  @spec try_reserve(pid(), key()) :: {:ok, pid(), reservation()} | :none
  def try_reserve(pool, key), do: GenServer.call(pool, {:try_reserve, key})

  @spec release(pid(), key(), reservation()) :: :ok
  def release(pool, key, reservation), do: GenServer.call(pool, {:release, key, reservation})

  @spec cancel(pid(), reservation()) :: :ok | {:error, :unknown_reservation}
  def cancel(pool, reservation), do: GenServer.call(pool, {:cancel, reservation})

  @spec register(pid(), key(), pid(), keyword()) :: :ok
  def register(pool, key, owner, opts \\ []),
    do: GenServer.call(pool, {:register, key, owner, opts})

  @spec stats(pid()) :: map()
  def stats(pool), do: GenServer.call(pool, :stats)

  @impl true
  def init(opts) do
    {:ok,
     %{
       entries: %{},
       reservations: %{},
       max_connections: Keyword.get(opts, :max_connections, 2),
       max_streams: Keyword.get(opts, :max_streams, 100),
       max_pending: Keyword.get(opts, :max_pending, 100),
       owner_factory: Keyword.get(opts, :owner_factory),
       monitors: %{}
     }}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    entries =
      Map.new(state.entries, fn {key, entry} ->
        {key,
         %{
           connections: map_size(entry.connections),
           pending: length(entry.pending),
           connecting: entry.connecting,
           streams: entry.streams
         }}
      end)

    {:reply, entries, state}
  end

  def handle_call({:register, key, owner, opts}, _from, state) when is_pid(owner) do
    max_streams = Keyword.get(opts, :max_streams, state.max_streams)
    entry = Map.get(state.entries, key, new_entry())
    mon = Process.monitor(owner)
    connection = %{pid: owner, streams: 0, max_streams: max_streams, monitor: mon}
    entry = %{entry | connections: Map.put(entry.connections, owner, connection)}

    state = %{
      state
      | entries: Map.put(state.entries, key, entry),
        monitors: Map.put(state.monitors, mon, {key, owner})
    }

    {:reply, :ok, dispatch_waiters(state, key)}
  end

  def handle_call({:reserve, key, opts}, from, state) do
    token = make_ref()

    case available_owner(Map.get(state.entries, key)) do
      {:ok, owner} ->
        state = increment_owner(state, key, owner, token)
        {:reply, {:ok, owner, token}, state}

      :none ->
        entry = Map.get(state.entries, key, new_entry())

        cond do
          length(entry.pending) >= state.max_pending ->
            {:reply, {:error, :pending_capacity}, state}

          map_size(entry.connections) + entry.connecting < state.max_connections and
              is_function(state.owner_factory, 2) ->
            # The factory runs in a separate process; its result is fed back as
            # an ordinary message and never blocks this pool mailbox.
            pool = self()

            spawn(fn ->
              send(pool, {:start_owner, key, opts, state.owner_factory.(key, opts)})
            end)

            entry = %{
              entry
              | pending: entry.pending ++ [{token, from, opts}],
                connecting: entry.connecting + 1
            }

            {:noreply, put_entry(state, key, entry)}

          true ->
            entry = %{entry | pending: entry.pending ++ [{token, from, opts}]}
            {:noreply, put_entry(state, key, entry)}
        end
    end
  end

  def handle_call({:try_reserve, key}, _from, state) do
    case available_owner(Map.get(state.entries, key)) do
      {:ok, owner} ->
        token = make_ref()
        {:reply, {:ok, owner, token}, increment_owner(state, key, owner, token)}

      :none ->
        {:reply, :none, state}
    end
  end

  def handle_call({:release, key, token}, _from, state) do
    case Map.pop(state.reservations, token) do
      {nil, _} ->
        {:reply, :ok, state}

      {%{key: ^key, owner: owner}, reservations} ->
        state = %{state | reservations: reservations} |> decrement_owner(key, owner)
        {:reply, :ok, dispatch_waiters(state, key)}

      {reservation, reservations} ->
        {:reply, :ok, %{state | reservations: Map.put(reservations, token, reservation)}}
    end
  end

  def handle_call({:cancel, token}, _from, state) do
    case Map.pop(state.reservations, token) do
      {nil, reservations} ->
        {state, found?} = remove_pending(state, token)

        if found?,
          do: {:reply, :ok, state},
          else: {:reply, {:error, :unknown_reservation}, %{state | reservations: reservations}}

      {%{key: key, owner: owner}, reservations} ->
        state = %{state | reservations: reservations} |> decrement_owner(key, owner)
        {:reply, :ok, dispatch_waiters(state, key)}
    end
  end

  @impl true
  def handle_info({:start_owner, key, _opts, {:ok, owner}}, state) when is_pid(owner) do
    state = decrement_connecting(state, key)
    {:noreply, state |> register_internal(key, owner) |> dispatch_waiters(key)}
  end

  def handle_info({:start_owner, key, _opts, owner}, state) when is_pid(owner) do
    state = decrement_connecting(state, key)
    {:noreply, state |> register_internal(key, owner) |> dispatch_waiters(key)}
  end

  def handle_info({:start_owner, key, _opts, {:error, reason}}, state) do
    state = decrement_connecting(state, key)

    case Map.get(state.entries, key) do
      %{pending: [{_token, from, _opts} | rest]} = entry ->
        GenServer.reply(from, {:error, {:owner_start_failed, reason}})
        state = put_entry(state, key, %{entry | pending: rest})
        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, monitor, :process, owner, _reason}, state) do
    case Map.pop(state.monitors, monitor) do
      {nil, _} ->
        {:noreply, state}

      {{key, ^owner}, monitors} ->
        entry = Map.get(state.entries, key, new_entry())
        entry = %{entry | connections: Map.delete(entry.connections, owner)}
        state = %{state | monitors: monitors, entries: Map.put(state.entries, key, entry)}
        {:noreply, dispatch_waiters(state, key)}
    end
  end

  defp new_entry, do: %{connections: %{}, pending: [], connecting: 0, streams: 0}
  defp put_entry(state, key, entry), do: %{state | entries: Map.put(state.entries, key, entry)}

  defp available_owner(nil), do: :none

  defp available_owner(entry) do
    case Enum.find(entry.connections, fn {_pid, c} -> c.streams < c.max_streams end) do
      {owner, _} -> {:ok, owner}
      nil -> :none
    end
  end

  defp increment_owner(state, key, owner, token) do
    entry = Map.fetch!(state.entries, key)
    connection = %{entry.connections[owner] | streams: entry.connections[owner].streams + 1}

    entry = %{
      entry
      | connections: Map.put(entry.connections, owner, connection),
        streams: entry.streams + 1
    }

    %{
      state
      | entries: Map.put(state.entries, key, entry),
        reservations: Map.put(state.reservations, token, %{key: key, owner: owner})
    }
  end

  defp decrement_owner(state, key, owner) do
    case get_in(state.entries, [key, :connections, owner]) do
      nil ->
        state

      connection ->
        entry = Map.fetch!(state.entries, key)
        connection = %{connection | streams: max(connection.streams - 1, 0)}

        put_entry(state, key, %{
          entry
          | connections: Map.put(entry.connections, owner, connection),
            streams: max(entry.streams - 1, 0)
        })
    end
  end

  defp register_internal(state, key, owner) do
    entry = Map.get(state.entries, key, new_entry())
    monitor = Process.monitor(owner)
    connection = %{pid: owner, streams: 0, max_streams: state.max_streams, monitor: monitor}

    state
    |> put_entry(key, %{entry | connections: Map.put(entry.connections, owner, connection)})
    |> then(&%{&1 | monitors: Map.put(&1.monitors, monitor, {key, owner})})
  end

  defp decrement_connecting(state, key) do
    case Map.get(state.entries, key) do
      nil -> state
      entry -> put_entry(state, key, %{entry | connecting: max(entry.connecting - 1, 0)})
    end
  end

  defp dispatch_waiters(state, key) do
    entry = Map.get(state.entries, key)
    do_dispatch(state, key, entry)
  end

  defp do_dispatch(state, _key, nil), do: state
  defp do_dispatch(state, _key, %{pending: []}), do: state

  defp do_dispatch(state, key, entry) do
    case available_owner(entry) do
      :none ->
        state

      {:ok, owner} ->
        [{token, from, _opts} | rest] = entry.pending
        state = put_entry(state, key, %{entry | pending: rest})
        state = increment_owner(state, key, owner, token)
        GenServer.reply(from, {:ok, owner, token})
        do_dispatch(state, key, Map.fetch!(state.entries, key))
    end
  end

  defp remove_pending(state, token) do
    Enum.reduce(state.entries, {state, false}, fn {key, entry}, {state, found} ->
      {pending, removed} =
        Enum.split_with(entry.pending, fn {candidate, _, _} -> candidate != token end)

      {put_entry(state, key, %{entry | pending: pending}), found or removed}
    end)
  end
end

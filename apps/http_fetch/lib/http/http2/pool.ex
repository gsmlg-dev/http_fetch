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
  def reserve(pool, key, opts \\ []) do
    timeout =
      case Keyword.get(opts, :deadline_at) do
        deadline when is_integer(deadline) -> max(deadline - now_ms() + 1_000, 1_000)
        _ -> 5_000
      end

    GenServer.call(pool, {:reserve, key, opts}, timeout)
  end

  @doc "Reserves an available stream without queueing or starting a connection."
  @spec try_reserve(pid(), key()) :: {:ok, pid(), reservation()} | :none
  def try_reserve(pool, key), do: GenServer.call(pool, {:try_reserve, key})

  @doc "Claims the per-key connection slot for an out-of-band connector."
  @spec claim_connect(pid(), key()) :: :start | :wait
  def claim_connect(pool, key), do: GenServer.call(pool, {:claim_connect, key})

  @doc "Fails an out-of-band connection attempt and wakes queued reservations."
  @spec fail_connect(pid(), key(), term()) :: :ok
  def fail_connect(pool, key, reason),
    do: GenServer.call(pool, {:fail_connect, key, reason})

  @doc "Stops new reservations on an owner that received GOAWAY."
  @spec mark_draining(pid(), key(), pid()) :: :ok
  def mark_draining(pool, key, owner),
    do: GenServer.call(pool, {:mark_draining, key, owner})

  @spec release(pid(), key(), reservation()) :: :ok
  def release(pool, key, reservation), do: GenServer.call(pool, {:release, key, reservation})

  @spec cancel(pid(), reservation()) :: :ok | {:error, :unknown_reservation}
  def cancel(pool, reservation), do: GenServer.call(pool, {:cancel, reservation})

  @spec register(pid(), key(), pid(), keyword()) :: :ok
  def register(pool, key, owner, opts \\ []),
    do: GenServer.call(pool, {:register, key, owner, opts})

  @doc "Updates one owner's effective peer stream limit."
  def update_capacity(pool, key, owner, limit),
    do: GenServer.call(pool, {:update_capacity, key, owner, limit})

  @spec stats(pid()) :: map()
  def stats(pool), do: GenServer.call(pool, :stats)

  @impl true
  def init(opts) do
    {:ok,
     %{
       entries: %{},
       reservations: %{},
       max_connections: Keyword.get(opts, :max_connections, 2),
       max_total_connections: Keyword.get(opts, :max_total_connections, 20),
       max_keys: Keyword.get(opts, :max_keys, 100),
       max_streams: Keyword.get(opts, :max_streams, 100),
       max_pending: Keyword.get(opts, :max_pending, 100),
       idle_timeout: Keyword.get(opts, :idle_timeout, 30_000),
       owner_factory: Keyword.get(opts, :owner_factory),
       monitors: %{},
       callers: %{},
       connectors: %{},
       deadlines: %{}
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
    cond do
      not Process.alive?(owner) ->
        {:reply, {:error, :owner_closed}, state}

      get_in(state.entries, [key, :connections, owner]) != nil ->
        {:reply, :ok, state}

      not registration_capacity?(state, key, Keyword.get(opts, :connecting?, false)) ->
        {:reply, {:error, :connection_capacity}, state}

      true ->
        state =
          register_internal(state, key, owner, Keyword.get(opts, :max_streams, state.max_streams))

        state =
          if Keyword.get(opts, :connecting?, false), do: finish_connect(state, key), else: state

        {:reply, :ok, state |> dispatch_waiters(key) |> emit_pool(:connection, :registered)}
    end
  end

  def handle_call({:update_capacity, key, owner, limit}, _from, state)
      when (is_integer(limit) and limit >= 0) or limit == :infinity do
    case get_in(state.entries, [key, :connections, owner]) do
      nil ->
        {:reply, {:error, :unknown_owner}, state}

      connection ->
        entry = Map.fetch!(state.entries, key)

        effective =
          if(limit == :infinity, do: state.max_streams, else: min(limit, state.max_streams))

        entry = %{
          entry
          | connections: Map.put(entry.connections, owner, %{connection | max_streams: effective})
        }

        {:reply, :ok, state |> put_entry(key, entry) |> dispatch_waiters(key)}
    end
  end

  def handle_call({:update_capacity, _, _, _}, _, state),
    do: {:reply, {:error, :invalid_capacity}, state}

  def handle_call({:reserve, key, opts}, from, state) do
    token = Keyword.get(opts, :token, make_ref())
    deadline = Keyword.get(opts, :deadline_at)

    cond do
      not is_reference(token) or Map.has_key?(state.callers, token) ->
        {:reply, {:error, :invalid_reservation}, state}

      is_integer(deadline) and deadline <= now_ms() ->
        {:reply, {:error, :deadline_exceeded}, state}

      not key_capacity?(state, key) ->
        {:reply, {:error, :key_capacity}, state}

      true ->
        reserve_available(state, key, opts, from, token, deadline)
    end
  end

  def handle_call({:try_reserve, key}, from, state) do
    case available_owner(Map.get(state.entries, key)) do
      {:ok, owner} ->
        token = make_ref()

        {:reply, {:ok, owner, token},
         state
         |> monitor_caller(token, from)
         |> increment_owner(key, owner, token)
         |> emit_pool(:reservation, :granted)}

      :none ->
        {:reply, :none, state}
    end
  end

  def handle_call({:claim_connect, key}, from, state) do
    entry = Map.get(state.entries, key, new_entry())

    cond do
      entry.connecting > 0 ->
        {:reply, :wait, state}

      can_connect?(state, key) ->
        pid = elem(from, 0)
        monitor = Process.monitor(pid)
        state = put_entry(state, key, %{entry | connecting: 1})

        state = %{
          state
          | connectors: Map.put(state.connectors, key, {pid, monitor}),
            monitors: Map.put(state.monitors, monitor, {:connector, key, pid})
        }

        {:reply, :start, emit_pool(state, :connection, :connecting)}

      true ->
        {:reply, :wait, state}
    end
  end

  def handle_call({:fail_connect, key, reason}, _from, state) do
    entry = Map.get(state.entries, key, new_entry())

    Enum.each(entry.pending, fn {_token, from, _opts} ->
      GenServer.reply(from, {:error, {:owner_start_failed, reason}})
    end)

    state =
      Enum.reduce(entry.pending, state, fn {token, _, _}, acc -> forget_caller(acc, token) end)

    entry = %{entry | pending: [], connecting: max(entry.connecting - 1, 0)}

    {:reply, :ok,
     state
     |> put_entry(key, entry)
     |> forget_connector(key)
     |> prune_key(key)
     |> emit_pool(:connection, :connect_failed)}
  end

  def handle_call({:mark_draining, key, owner}, _from, state) do
    case get_in(state.entries, [key, :connections, owner]) do
      nil ->
        {:reply, :ok, state}

      connection ->
        entry = Map.fetch!(state.entries, key)

        _ =
          if is_reference(connection.idle_timer),
            do: Process.cancel_timer(connection.idle_timer),
            else: :ok

        connection = %{connection | draining: true, idle_timer: nil, idle_token: nil}
        entry = %{entry | connections: Map.put(entry.connections, owner, connection)}
        {:reply, :ok, state |> put_entry(key, entry) |> emit_pool(:connection, :draining)}
    end
  end

  def handle_call({:release, key, token}, _from, state) do
    case Map.pop(state.reservations, token) do
      {nil, _} ->
        {:reply, :ok, state}

      {%{key: ^key, owner: owner}, reservations} ->
        state =
          %{state | reservations: reservations}
          |> forget_caller(token)
          |> decrement_owner(key, owner)

        {:reply, :ok,
         state |> dispatch_waiters(key) |> prune_key(key) |> emit_pool(:reservation, :released)}

      {reservation, reservations} ->
        {:reply, :ok, %{state | reservations: Map.put(reservations, token, reservation)}}
    end
  end

  def handle_call({:cancel, token}, _from, state) do
    case Map.pop(state.reservations, token) do
      {nil, reservations} ->
        {state, found?} = remove_pending(state, token)

        if found?,
          do: {:reply, :ok, state |> forget_caller(token) |> emit_pool(:reservation, :cancelled)},
          else: {:reply, {:error, :unknown_reservation}, %{state | reservations: reservations}}

      {%{key: key, owner: owner}, reservations} ->
        state =
          %{state | reservations: reservations}
          |> forget_caller(token)
          |> decrement_owner(key, owner)

        {:reply, :ok,
         state |> dispatch_waiters(key) |> prune_key(key) |> emit_pool(:reservation, :cancelled)}
    end
  end

  @impl true
  def handle_cast({:owner_capacity, key, owner, limit}, state),
    do: {:noreply, set_capacity(state, key, owner, limit)}

  def handle_cast({:owner_draining, key, owner}, state),
    do: {:noreply, set_draining(state, key, owner)}

  @impl true
  def handle_info({:start_owner, key, _opts, {:ok, owner}}, state) when is_pid(owner) do
    state = finish_connect(state, key)
    {:noreply, state |> register_internal(key, owner) |> dispatch_waiters(key)}
  end

  def handle_info({:start_owner, key, _opts, owner}, state) when is_pid(owner) do
    state = finish_connect(state, key)
    {:noreply, state |> register_internal(key, owner) |> dispatch_waiters(key)}
  end

  def handle_info({:start_owner, key, _opts, {:error, reason}}, state) do
    state = finish_connect(state, key)

    case Map.get(state.entries, key) do
      %{pending: pending} = entry ->
        Enum.each(pending, fn {_token, from, _opts} ->
          GenServer.reply(from, {:error, {:owner_start_failed, reason}})
        end)

        state =
          Enum.reduce(pending, state, fn {token, _, _}, acc -> forget_caller(acc, token) end)

        {:noreply, state |> put_entry(key, %{entry | pending: []}) |> prune_key(key)}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, monitor, :process, pid, _reason}, state) do
    case Map.pop(state.monitors, monitor) do
      {nil, _} ->
        {:noreply, state}

      {{:owner, key, ^pid}, monitors} ->
        entry = Map.get(state.entries, key, new_entry())
        connection = Map.get(entry.connections, pid)

        entry = %{
          entry
          | connections: Map.delete(entry.connections, pid),
            streams: max(entry.streams - if(connection, do: connection.streams, else: 0), 0)
        }

        state = %{state | monitors: monitors, entries: Map.put(state.entries, key, entry)}
        state = drop_owner_reservations(state, key, pid)

        {:noreply,
         state |> dispatch_waiters(key) |> prune_key(key) |> emit_pool(:connection, :owner_down)}

      {{:caller, token, ^pid}, monitors} ->
        state = %{state | monitors: monitors, callers: Map.delete(state.callers, token)}
        {:noreply, state |> cancel_token(token) |> emit_pool(:reservation, :caller_down)}

      {{:connector, key, ^pid}, monitors} ->
        state = %{state | monitors: monitors, connectors: Map.delete(state.connectors, key)}
        entry = Map.get(state.entries, key, new_entry())

        Enum.each(entry.pending, fn {_token, from, _opts} ->
          GenServer.reply(from, {:error, :connector_down})
        end)

        state =
          Enum.reduce(entry.pending, state, fn {token, _, _}, acc -> forget_caller(acc, token) end)

        entry = %{entry | pending: [], connecting: max(entry.connecting - 1, 0)}

        {:noreply,
         state
         |> put_entry(key, entry)
         |> prune_key(key)
         |> emit_pool(:connection, :connector_down)}
    end
  end

  def handle_info({:idle_expire, key, owner, token}, state) do
    case get_in(state.entries, [key, :connections, owner]) do
      %{streams: 0, draining: false, idle_token: ^token} ->
        spawn(fn -> GenServer.stop(owner, :normal) end)
        {:noreply, state}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:reservation_deadline, token}, state) do
    case Map.get(state.callers, token) do
      nil ->
        {:noreply, state}

      _ ->
        case find_pending(state, token) do
          nil ->
            {:noreply, cancel_deadline(state, token)}

          from ->
            GenServer.reply(from, {:error, :deadline_exceeded})

            {:noreply,
             state |> cancel_token(token) |> emit_pool(:reservation, :deadline_exceeded)}
        end
    end
  end

  defp reserve_available(state, key, opts, from, token, deadline) do
    case available_owner(Map.get(state.entries, key)) do
      {:ok, owner} ->
        state = state |> monitor_caller(token, from) |> increment_owner(key, owner, token)
        {:reply, {:ok, owner, token}, emit_pool(state, :reservation, :granted)}

      :none ->
        entry = Map.get(state.entries, key, new_entry())
        queued_opts = Keyword.put(opts, :queued_at_us, System.monotonic_time(:microsecond))

        cond do
          length(entry.pending) >= state.max_pending ->
            {:reply, {:error, :pending_capacity}, state}

          can_connect?(state, key) and
              is_function(state.owner_factory, 2) ->
            # The factory runs in a separate process; its result is fed back as
            # an ordinary message and never blocks this pool mailbox.
            pool = self()

            {connector, monitor} =
              spawn_monitor(fn ->
                send(pool, {:start_owner, key, opts, state.owner_factory.(key, opts)})
              end)

            entry = %{
              entry
              | pending: entry.pending ++ [{token, from, queued_opts}],
                connecting: entry.connecting + 1
            }

            state = state |> put_entry(key, entry) |> monitor_caller(token, from)

            state = %{
              state
              | connectors: Map.put(state.connectors, key, {connector, monitor}),
                monitors: Map.put(state.monitors, monitor, {:connector, key, connector})
            }

            {:noreply, state |> start_deadline(token, deadline) |> emit_pool(:queued, :waiting)}

          true ->
            entry = %{entry | pending: entry.pending ++ [{token, from, queued_opts}]}
            state = state |> put_entry(key, entry) |> monitor_caller(token, from)
            {:noreply, state |> start_deadline(token, deadline) |> emit_pool(:queued, :waiting)}
        end
    end
  end

  defp new_entry, do: %{connections: %{}, pending: [], connecting: 0, streams: 0}
  defp put_entry(state, key, entry), do: %{state | entries: Map.put(state.entries, key, entry)}

  defp available_owner(nil), do: :none

  defp available_owner(entry) do
    case Enum.find(entry.connections, fn {_pid, c} ->
           not c.draining and c.streams < c.max_streams
         end) do
      {owner, _} -> {:ok, owner}
      nil -> :none
    end
  end

  defp increment_owner(state, key, owner, token) do
    entry = Map.fetch!(state.entries, key)
    connection = entry.connections[owner]

    _ =
      if is_reference(connection.idle_timer),
        do: Process.cancel_timer(connection.idle_timer),
        else: :ok

    connection = %{
      connection
      | streams: connection.streams + 1,
        idle_timer: nil,
        idle_token: nil
    }

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
        streams = max(connection.streams - 1, 0)

        {idle_timer, idle_token} =
          if streams == 0 and not connection.draining and state.idle_timeout > 0 do
            token = make_ref()

            timer =
              Process.send_after(self(), {:idle_expire, key, owner, token}, state.idle_timeout)

            {timer, token}
          else
            {nil, nil}
          end

        connection = %{
          connection
          | streams: streams,
            idle_timer: idle_timer,
            idle_token: idle_token
        }

        put_entry(state, key, %{
          entry
          | connections: Map.put(entry.connections, owner, connection),
            streams: max(entry.streams - 1, 0)
        })
    end
  end

  defp register_internal(state, key, owner, max_streams \\ nil) do
    entry = Map.get(state.entries, key, new_entry())
    monitor = Process.monitor(owner)
    send(owner, {:http2_pool, self(), key})

    {idle_timer, idle_token} =
      if state.idle_timeout > 0 do
        token = make_ref()
        timer = Process.send_after(self(), {:idle_expire, key, owner, token}, state.idle_timeout)
        {timer, token}
      else
        {nil, nil}
      end

    connection = %{
      pid: owner,
      streams: 0,
      max_streams: max_streams || state.max_streams,
      monitor: monitor,
      draining: false,
      idle_timer: idle_timer,
      idle_token: idle_token
    }

    state
    |> put_entry(key, %{entry | connections: Map.put(entry.connections, owner, connection)})
    |> then(&%{&1 | monitors: Map.put(&1.monitors, monitor, {:owner, key, owner})})
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
        [{token, from, opts} | rest] = entry.pending
        state = state |> put_entry(key, %{entry | pending: rest}) |> cancel_deadline(token)

        state =
          cond do
            not Process.alive?(elem(from, 0)) ->
              state
              |> forget_caller(token)
              |> emit_pool(:reservation, :caller_down, queue_wait_us(opts))

            is_integer(Keyword.get(opts, :deadline_at)) and
                Keyword.fetch!(opts, :deadline_at) <= now_ms() ->
              GenServer.reply(from, {:error, :deadline_exceeded})

              state
              |> forget_caller(token)
              |> emit_pool(:reservation, :deadline_exceeded, queue_wait_us(opts))

            true ->
              GenServer.reply(from, {:ok, owner, token})

              state
              |> increment_owner(key, owner, token)
              |> emit_pool(:reservation, :granted, queue_wait_us(opts))
          end

        do_dispatch(state, key, Map.fetch!(state.entries, key))
    end
  end

  defp remove_pending(state, token) do
    Enum.reduce(state.entries, {state, false}, fn {key, entry}, {state, found} ->
      {pending, removed} =
        Enum.split_with(entry.pending, fn {candidate, _, _} -> candidate != token end)

      {put_entry(state, key, %{entry | pending: pending}) |> prune_key(key),
       found or removed != []}
    end)
  end

  defp find_pending(state, token) do
    Enum.find_value(state.entries, fn {_key, entry} ->
      case Enum.find(entry.pending, fn {candidate, _, _} -> candidate == token end) do
        {_, from, _} -> from
        nil -> nil
      end
    end)
  end

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp set_capacity(state, key, owner, limit)
       when (is_integer(limit) and limit >= 0) or limit == :infinity do
    case get_in(state.entries, [key, :connections, owner]) do
      nil ->
        state

      connection ->
        entry = Map.fetch!(state.entries, key)

        effective =
          if(limit == :infinity, do: state.max_streams, else: min(limit, state.max_streams))

        entry = %{
          entry
          | connections: Map.put(entry.connections, owner, %{connection | max_streams: effective})
        }

        state |> put_entry(key, entry) |> dispatch_waiters(key)
    end
  end

  defp set_capacity(state, _, _, _), do: state

  defp set_draining(state, key, owner) do
    case get_in(state.entries, [key, :connections, owner]) do
      nil ->
        state

      connection ->
        entry = Map.fetch!(state.entries, key)

        _ =
          if is_reference(connection.idle_timer), do: Process.cancel_timer(connection.idle_timer)

        connection = %{connection | draining: true, idle_timer: nil, idle_token: nil}

        put_entry(state, key, %{
          entry
          | connections: Map.put(entry.connections, owner, connection)
        })
    end
  end

  defp key_capacity?(state, key),
    do: Map.has_key?(state.entries, key) or map_size(state.entries) < state.max_keys

  defp total_connections(state) do
    Enum.reduce(state.entries, 0, fn {_key, entry}, count ->
      count + map_size(entry.connections) + entry.connecting
    end)
  end

  defp can_connect?(state, key) do
    entry = Map.get(state.entries, key, new_entry())

    key_capacity?(state, key) and
      active_connections(entry) + entry.connecting < state.max_connections and
      total_connections(state) < state.max_total_connections
  end

  defp registration_capacity?(state, key, connecting?) do
    entry = Map.get(state.entries, key, new_entry())
    adjustment = if(connecting? and entry.connecting > 0, do: 1, else: 0)

    key_capacity?(state, key) and
      active_connections(entry) + entry.connecting + 1 - adjustment <= state.max_connections and
      total_connections(state) + 1 - adjustment <= state.max_total_connections
  end

  defp active_connections(entry),
    do: Enum.count(entry.connections, fn {_owner, connection} -> not connection.draining end)

  defp monitor_caller(state, token, from) do
    pid = elem(from, 0)
    monitor = Process.monitor(pid)

    %{
      state
      | callers: Map.put(state.callers, token, {pid, monitor}),
        monitors: Map.put(state.monitors, monitor, {:caller, token, pid})
    }
  end

  defp forget_caller(state, token) do
    state = cancel_deadline(state, token)

    case Map.pop(state.callers, token) do
      {nil, _} ->
        state

      {{_pid, monitor}, callers} ->
        Process.demonitor(monitor, [:flush])
        %{state | callers: callers, monitors: Map.delete(state.monitors, monitor)}
    end
  end

  defp forget_connector(state, key) do
    case Map.pop(state.connectors, key) do
      {nil, _} ->
        state

      {{_pid, monitor}, connectors} ->
        Process.demonitor(monitor, [:flush])
        %{state | connectors: connectors, monitors: Map.delete(state.monitors, monitor)}
    end
  end

  defp finish_connect(state, key),
    do: state |> forget_connector(key) |> decrement_connecting(key)

  defp start_deadline(state, _token, nil), do: state

  defp start_deadline(state, token, deadline) when is_integer(deadline) do
    timer =
      Process.send_after(self(), {:reservation_deadline, token}, max(deadline - now_ms(), 0))

    %{state | deadlines: Map.put(state.deadlines, token, timer)}
  end

  defp cancel_deadline(state, token) do
    case Map.pop(state.deadlines, token) do
      {nil, _} ->
        state

      {timer, deadlines} ->
        _ = Process.cancel_timer(timer)
        %{state | deadlines: deadlines}
    end
  end

  defp cancel_token(state, token) do
    case Map.pop(state.reservations, token) do
      {nil, _} ->
        {state, _} = remove_pending(state, token)
        forget_caller(state, token)

      {%{key: key, owner: owner}, reservations} ->
        %{state | reservations: reservations}
        |> forget_caller(token)
        |> decrement_owner(key, owner)
        |> dispatch_waiters(key)
        |> prune_key(key)
    end
  end

  defp drop_owner_reservations(state, key, owner) do
    Enum.reduce(state.reservations, state, fn
      {token, %{key: ^key, owner: ^owner}}, acc ->
        %{acc | reservations: Map.delete(acc.reservations, token)} |> forget_caller(token)

      _, acc ->
        acc
    end)
  end

  defp prune_key(state, key) do
    case Map.get(state.entries, key) do
      %{connections: connections, pending: [], connecting: 0, streams: 0}
      when map_size(connections) == 0 ->
        %{state | entries: Map.delete(state.entries, key)}

      _ ->
        state
    end
  end

  defp queue_wait_us(opts) do
    case Keyword.get(opts, :queued_at_us) do
      started when is_integer(started) -> max(System.monotonic_time(:microsecond) - started, 0)
      _ -> 0
    end
  end

  defp emit_pool(state, event, outcome, queue_wait_us \\ 0) do
    {connections, connecting, draining, waiters} =
      Enum.reduce(state.entries, {0, 0, 0, 0}, fn {_key, entry},
                                                  {connections, connecting, draining, waiters} ->
        {
          connections + map_size(entry.connections),
          connecting + entry.connecting,
          draining + Enum.count(entry.connections, fn {_pid, c} -> c.draining end),
          waiters + length(entry.pending)
        }
      end)

    HTTP.Telemetry.http2_pool(event, outcome, %{
      reservations: map_size(state.reservations),
      waiters: waiters,
      connecting: connecting,
      connections: connections,
      draining: draining,
      queue_wait_us: queue_wait_us
    })

    state
  end
end

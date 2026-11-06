defmodule Abyss.TableOwner do
  @moduledoc false
  # Owns the shared named ETS tables used across all Abyss server instances:
  #
  # - `:abyss_listener_info` - listener socket/endpoint cache (see
  #   `Abyss.Listener`)
  # - `:abyss_telemetry_metrics` - metrics counters (see `Abyss.Telemetry`)
  #
  # The tables are public; this process only ties their lifetime to the
  # `:abyss` application. All lazy `ensure_*` calls route table creation
  # through `ensure_table/2` so that no matter which process first needs a
  # table, it is created by (and owned by) this process rather than by a
  # transient server, listener, or handler process.

  use GenServer

  @spec start_link(term()) :: GenServer.on_start()
  def start_link(arg) do
    GenServer.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @doc false
  # Ensure a named ETS table exists. When this process is running the table
  # is created here so it survives the caller's death; otherwise (the :abyss
  # application not started) it is created in the calling process as a
  # fallback.
  @spec ensure_table(atom(), list()) :: :ok
  def ensure_table(name, opts) do
    case :ets.whereis(name) do
      :undefined ->
        case Process.whereis(__MODULE__) do
          nil -> create_table(name, opts)
          pid when pid == self() -> create_table(name, opts)
          _pid -> GenServer.call(__MODULE__, {:ensure_table, name, opts})
        end

      _ref ->
        :ok
    end
  end

  @doc false
  def track_scope(scope) when is_pid(scope) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      pid when pid == self() -> :ok
      _ -> GenServer.call(__MODULE__, {:track_scope, scope})
    end
  end

  def track_scope(_scope), do: :ok

  @doc false
  def monitor_listener(listener) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      _ -> GenServer.call(__MODULE__, {:monitor_listener, listener})
    end
  end

  @doc false
  def admission(operation) do
    case Process.whereis(__MODULE__) do
      pid when pid == self() ->
        _ = send(self(), {:admission, operation})
        :ok

      nil ->
        Abyss.UDPAdmission.transition(operation)

      _pid ->
        GenServer.call(__MODULE__, {:admission, operation})
    end
  end

  @doc false
  def monitor_runtime(runtime, owner, server, writer, admission),
    do: GenServer.call(__MODULE__, {:monitor_runtime, runtime, owner, server, writer, admission})

  @impl GenServer
  def init(_arg) do
    Abyss.Listener.ensure_info_table_exists()
    Abyss.Telemetry.init_metrics()

    {:ok,
     %{
       scopes: %{},
       listeners: %{},
       reservations: %{},
       protected: %{},
       runtimes: %{},
       components: %{}
     }}
  end

  @impl GenServer
  def handle_call({:ensure_table, name, opts}, _from, state) do
    {:reply, create_table(name, opts), state}
  end

  def handle_call({:admission, operation}, _from, state) do
    {reply, state} = apply_admission(operation, state)
    {:reply, reply, state}
  end

  def handle_call({:monitor_runtime, runtime, owner, server, writer, admission}, _from, state) do
    pids = [runtime, writer, admission]
    entry = %{owner: owner, server: server, pids: MapSet.new(pids)}

    components =
      Enum.reduce(pids, state.components, fn pid, components ->
        Map.put(components, pid, %{
          monitor: Process.monitor(pid),
          runtime: runtime,
          writer: pid == writer
        })
      end)

    state = %{state | runtimes: Map.put(state.runtimes, runtime, entry), components: components}
    {:reply, :ok, state}
  end

  def handle_call({:track_scope, scope}, _from, state) do
    scopes = Map.put_new_lazy(state.scopes, scope, fn -> Process.monitor(scope) end)
    {:reply, :ok, %{state | scopes: scopes}}
  end

  def handle_call({:monitor_listener, listener}, _from, state) do
    listeners = Map.put_new_lazy(state.listeners, listener, fn -> Process.monitor(listener) end)
    {:reply, :ok, %{state | listeners: listeners}}
  end

  @impl GenServer
  def handle_info({:admission, operation}, state) do
    {_, state} = apply_admission(operation, state)
    {:noreply, state}
  end

  def handle_info({:DOWN, monitor, :process, pid, reason}, state) do
    case state.protected[pid] do
      %{monitor: ^monitor} = protected ->
        {:noreply, protected_down(pid, protected, state)}

      _ ->
        component_down(monitor, pid, reason, state)
    end
  end

  defp component_down(monitor, pid, reason, state) do
    case state.components[pid] do
      %{monitor: ^monitor, runtime: runtime, writer: writer?} ->
        if writer?, do: :persistent_term.erase({Abyss.Dispatcher.Writer, pid})
        entry = state.runtimes[runtime]
        pids = MapSet.delete(entry.pids, pid)
        if runtime == pid, do: Enum.each(pids, &Process.exit(&1, :kill))
        runtimes = update_runtime(state.runtimes, runtime, entry, pids)
        {:noreply, %{state | components: Map.delete(state.components, pid), runtimes: runtimes}}

      _ ->
        scope_down(monitor, pid, reason, state)
    end
  end

  defp update_runtime(runtimes, runtime, entry, pids) do
    if MapSet.size(pids) == 0,
      do: Map.delete(runtimes, runtime),
      else: Map.put(runtimes, runtime, %{entry | pids: pids})
  end

  defp scope_down(monitor, scope, _reason, state) do
    case Map.fetch(state.scopes, scope) do
      {:ok, ^monitor} ->
        Abyss.Listener.clear_desired(scope)
        Abyss.Telemetry.clear_scope(scope)
        {:noreply, %{state | scopes: Map.delete(state.scopes, scope)}}

      _ ->
        cleanup_listener(monitor, scope, state)
    end
  end

  defp cleanup_listener(monitor, listener, state) do
    case Map.fetch(state.listeners, listener) do
      {:ok, ^monitor} ->
        Abyss.Listener.cleanup_owner(listener)
        {:noreply, %{state | listeners: Map.delete(state.listeners, listener)}}

      _ ->
        {:noreply, state}
    end
  end

  # A root owns the input; descendants are registered before receiving its payload.
  # Forced retirement retains the ETS count and bytes until every protected DOWN.
  defp apply_admission({:reserve_runtime, server, owner, limit, bytes, byte_limit, root}, state) do
    case Abyss.UDPAdmission.transition({:reserve, server, owner, limit, bytes, byte_limit}) do
      {:ok, token} = reply ->
        reservation = %{root: root, pids: MapSet.new(), pending: false}
        state = %{state | reservations: Map.put(state.reservations, token, reservation)}
        {reply, protect(token, root, state)}

      error ->
        {error, state}
    end
  end

  defp apply_admission({:protect, token, pid}, state) do
    case state.reservations[token] do
      %{pending: false} -> {:ok, protect(token, pid, state)}
      _ -> {{:error, :stale_owner}, state}
    end
  end

  defp apply_admission({:spawn_protected, token, fun}, state) do
    case state.reservations[token] do
      %{root: root, pending: false} ->
        pid =
          spawn(fn ->
            Process.link(root)

            receive do
              :run -> fun.()
            end
          end)

        state = protect(token, pid, state)
        {{:ok, pid}, state}

      _ ->
        {{:error, :stale_owner}, state}
    end
  end

  defp apply_admission({:complete, token}, state) do
    case state.reservations[token] do
      %{pending: true} -> {:ok, state}
      _ -> {:ok, refund(token, state)}
    end
  end

  defp apply_admission({:release, token}, state), do: {:ok, retire(token, state)}

  defp apply_admission({:release_owner, owner}, state),
    do: retire_scope(:owner, owner, state)

  defp apply_admission({:release_server, server}, state),
    do: retire_scope(:server, server, state)

  defp apply_admission(operation, state),
    do: {Abyss.UDPAdmission.transition(operation), state}

  defp protect(token, pid, state) do
    protected =
      Map.get_lazy(state.protected, pid, fn ->
        %{monitor: Process.monitor(pid), tokens: MapSet.new()}
      end)

    reservation = state.reservations[token]

    %{
      state
      | protected:
          Map.put(state.protected, pid, %{protected | tokens: MapSet.put(protected.tokens, token)}),
        reservations:
          Map.put(state.reservations, token, %{
            reservation
            | pids: MapSet.put(reservation.pids, pid)
          })
    }
  end

  defp retire_scope(kind, scope, state) do
    Enum.each(state.runtimes, fn {_runtime, entry} ->
      if Map.fetch!(entry, kind) == scope,
        do: Enum.each(entry.pids, &Process.exit(&1, :kill))
    end)

    state =
      Enum.reduce(Abyss.UDPAdmission.slots(kind, scope), state, fn
        {token, _, _, pid, _}, state ->
          if is_pid(pid), do: Process.exit(pid, :kill)
          retire(token, state)
      end)

    _ = if kind == :server, do: Abyss.UDPAdmission.transition({:cleanup_server, scope})
    {:ok, state}
  end

  defp retire(token, state) do
    case state.reservations[token] do
      nil ->
        refund(token, state)

      reservation ->
        Enum.each(reservation.pids, &Process.exit(&1, :kill))

        state = %{
          state
          | reservations: Map.put(state.reservations, token, %{reservation | pending: true})
        }

        maybe_refund(token, state)
    end
  end

  defp protected_down(pid, protected, state) do
    state = %{state | protected: Map.delete(state.protected, pid)}

    Enum.reduce(protected.tokens, state, fn token, state ->
      reservation = state.reservations[token]
      reservation = %{reservation | pids: MapSet.delete(reservation.pids, pid)}
      state = %{state | reservations: Map.put(state.reservations, token, reservation)}

      if reservation.root == pid,
        do: retire(token, state),
        else: maybe_refund(token, state)
    end)
  end

  defp maybe_refund(token, state) do
    reservation = state.reservations[token]

    if reservation.pending and MapSet.size(reservation.pids) == 0,
      do: refund(token, state),
      else: state
  end

  defp refund(token, state) do
    {reservation, reservations} = Map.pop(state.reservations, token)
    state = %{state | reservations: reservations}

    state =
      if reservation,
        do: Enum.reduce(reservation.pids, state, &detach(&1, token, &2)),
        else: state

    :ok = Abyss.UDPAdmission.transition({:release, token})
    state
  end

  defp detach(pid, token, state) do
    protected = state.protected[pid]
    tokens = MapSet.delete(protected.tokens, token)

    if MapSet.size(tokens) == 0 do
      Process.demonitor(protected.monitor, [:flush])
      %{state | protected: Map.delete(state.protected, pid)}
    else
      %{state | protected: Map.put(state.protected, pid, %{protected | tokens: tokens})}
    end
  end

  defp create_table(name, opts) do
    _ = :ets.new(name, opts)
    :ok
  rescue
    # Concurrent creation race - the table already exists
    ArgumentError -> :ok
  end
end

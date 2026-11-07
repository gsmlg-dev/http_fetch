defmodule HTTP.Test.Registry do
  @moduledoc false
  use GenServer

  def start_link(_opts), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  def configure(owner, name, mode, count, callback),
    do: GenServer.call(__MODULE__, {:configure, owner, name, mode, count, callback})

  def allow(name, owner, allowed), do: GenServer.call(__MODULE__, {:allow, name, owner, allowed})
  def resolve(name, callers), do: GenServer.call(__MODULE__, {:resolve, name, callers})
  def token(owner), do: GenServer.call(__MODULE__, {:token, owner})
  def retain(token), do: GenServer.call(__MODULE__, {:retain, token})

  def claim(token, name, worker, guardian),
    do: GenServer.call(__MODULE__, {:claim, token, name, worker, guardian})

  def track(token, resource, kind),
    do: GenServer.call(__MODULE__, {:track, token, resource, kind})

  def resources(token), do: GenServer.call(__MODULE__, {:resources, token})

  def guardian_completed(token, guardian),
    do: GenServer.call(__MODULE__, {:guardian_completed, token, guardian})

  def finished(token, worker), do: GenServer.call(__MODULE__, {:finished, token, worker})

  def failed(token, worker, failure),
    do: GenServer.call(__MODULE__, {:failed, token, worker, failure})

  def canceled(token, worker), do: GenServer.call(__MODULE__, {:canceled, token, worker})

  def worker_down(token, worker, reason),
    do: GenServer.call(__MODULE__, {:worker_down, token, worker, reason})

  def freeze(token), do: GenServer.call(__MODULE__, {:freeze, token})

  def finish_verification(token, cleanup),
    do: GenServer.call(__MODULE__, {:finish_verification, token, cleanup})

  def delete(token), do: GenServer.call(__MODULE__, {:delete, token})

  @impl true
  def init(nil), do: {:ok, %{owners: %{}, records: %{}, monitors: %{}}}

  @impl true
  def handle_call({:configure, owner, name, mode, count, callback}, _, state) do
    {token, state} = ensure_owner(state, owner)
    record = state.records[token]
    fixture = record.fixtures[name]

    cond do
      record.frozen ->
        {:reply, {:error, :owner_frozen}, state}

      fixture && fixture.mode != mode ->
        {:reply, {:error, :conflicting_fixture_mode}, state}

      mode == :stub ->
        fixture = %{mode: :stub, callback: callback}
        {:reply, :ok, put_in(state.records[token].fixtures[name], fixture)}

      true ->
        expectation = %{remaining: count, callback: callback}

        fixture = %{
          mode: :expect,
          queue: if(fixture, do: fixture.queue, else: []) ++ [expectation]
        }

        {:reply, :ok, put_in(state.records[token].fixtures[name], fixture)}
    end
  end

  def handle_call({:allow, name, owner, allowed}, _, state) do
    with token when not is_nil(token) <- state.owners[owner],
         %{frozen: false} = record <- state.records[token],
         true <- Map.has_key?(record.fixtures, name) do
      allowances =
        Map.update(record.allowances, name, MapSet.new([allowed]), &MapSet.put(&1, allowed))

      {:reply, :ok, put_in(state.records[token].allowances, allowances)}
    else
      _ -> {:reply, {:error, :no_fixture}, state}
    end
  end

  def handle_call({:resolve, name, callers}, _, state) do
    own =
      Enum.find_value(callers, fn pid ->
        token = state.owners[pid]

        if token &&
             (state.records[token].frozen || Map.has_key?(state.records[token].fixtures, name)),
           do: token
      end)

    allowed =
      for {token, record} <- state.records,
          not record.frozen,
          Enum.any?(callers, &MapSet.member?(Map.get(record.allowances, name, MapSet.new()), &1)),
          do: token

    candidates = if own, do: [own], else: Enum.uniq(allowed)

    case candidates do
      [token] ->
        if state.records[token].frozen,
          do: {:reply, {:error, :owner_frozen}, state},
          else: {:reply, {:ok, token}, state}

      [] ->
        {:reply, {:error, :no_fixture_or_allowance}, state}

      _ ->
        {:reply, {:error, :ambiguous_owner}, state}
    end
  end

  def handle_call({:token, owner}, _, state) do
    {token, state} = ensure_owner(state, owner)
    {:reply, token, state}
  end

  def handle_call({:retain, token}, _, state) do
    case state.records[token] do
      nil -> {:reply, {:error, :missing_verification_record}, state}
      _ -> {:reply, :ok, put_in(state.records[token].retain, true)}
    end
  end

  def handle_call({:claim, token, name, worker, guardian}, _, state) do
    case state.records[token] do
      %{frozen: false} = record ->
        case take_fixture(record.fixtures[name]) do
          {:ok, callback, fixture} ->
            monitor = Process.monitor(worker)
            guardian_monitor = Process.monitor(guardian)
            call = %{active: true, canceled: false, monitor: monitor}

            record = %{
              record
              | fixtures: Map.put(record.fixtures, name, fixture),
                calls: Map.put(record.calls, worker, call),
                guardians: MapSet.put(record.guardians, guardian),
                guardian_monitors: Map.put(record.guardian_monitors, guardian, guardian_monitor),
                resources: Map.put(record.resources, worker, :worker)
            }

            state = put_in(state.records[token], record)
            state = put_in(state.monitors[monitor], {:worker, token, worker})
            state = put_in(state.monitors[guardian_monitor], {:guardian, token, guardian})
            {:reply, {:ok, callback}, state}

          {:error, reason} ->
            state = add_failure(state, token, {:expectation, name, reason})
            {:reply, {:error, reason}, state}
        end

      _ ->
        {:reply, {:error, :owner_frozen}, state}
    end
  end

  def handle_call({:register, producer, :producer}, {stream, _}, state) do
    token =
      Enum.find_value(state.records, fn {token, record} ->
        if record.resources[stream] == :stream, do: token
      end)

    if token do
      {:reply, :ok, put_in(state.records[token].resources[producer], :producer)}
    else
      {:reply, {:error, :unowned_stream}, state}
    end
  end

  def handle_call({:track, token, resource, kind}, _, state) do
    if state.records[token] do
      {:reply, :ok, put_in(state.records[token].resources[resource], kind)}
    else
      {:reply, {:error, :missing_verification_record}, state}
    end
  end

  def handle_call({:resources, token}, _, state) do
    resources = if state.records[token], do: state.records[token].resources, else: %{}
    {:reply, resources, state}
  end

  def handle_call({:guardian_completed, token, guardian}, _, state) do
    if state.records[token] do
      {:reply, :ok,
       update_in(state.records[token].completed_guardians, &MapSet.put(&1, guardian))}
    else
      {:reply, {:error, :missing_verification_record}, state}
    end
  end

  def handle_call({:finished, token, worker}, _, state) do
    {:reply, :ok, update_call(state, token, worker, &%{&1 | active: false})}
  end

  def handle_call({:failed, token, worker, failure}, _, state) do
    state =
      state
      |> add_failure(token, failure)
      |> update_call(token, worker, &%{&1 | active: false})

    {:reply, :ok, state}
  end

  def handle_call({:canceled, token, worker}, _, state),
    do: {:reply, :ok, update_call(state, token, worker, &%{&1 | canceled: true})}

  def handle_call({:worker_down, token, worker, reason}, _, state),
    do: {:reply, :ok, record_down(state, token, worker, reason)}

  def handle_call({:freeze, token}, _, state) do
    case state.records[token] do
      nil ->
        {:reply, {:error, :missing_verification_record}, state}

      %{terminal: terminal} when terminal != nil ->
        {:reply, {:terminal, terminal}, state}

      record ->
        {:reply, {:ok, MapSet.to_list(record.guardians)},
         put_in(state.records[token].frozen, true)}
    end
  end

  def handle_call({:finish_verification, token, cleanup}, _, state) do
    case state.records[token] do
      nil ->
        {:reply, {:error, :missing_verification_record}, state}

      record ->
        unmet =
          for {name, %{mode: :expect, queue: queue}} <- record.fixtures,
              remaining = Enum.sum(Enum.map(queue, & &1.remaining)),
              remaining > 0,
              do: {:unmet_expectation, name, remaining}

        guardian_failures =
          for guardian <- record.guardians,
              not MapSet.member?(record.completed_guardians, guardian),
              do: {:guardian_exit, Map.get(record.guardian_exits, guardian, :cleanup_unconfirmed)}

        failures =
          Enum.reverse(record.failures) ++
            unmet ++
            guardian_failures ++
            if(cleanup == :ok, do: [], else: [cleanup])

        result = if failures == [], do: :ok, else: {:error, failures}

        record = %{
          record
          | terminal: result,
            fixtures: %{},
            allowances: %{},
            guardians: MapSet.new(),
            resources: %{}
        }

        {:reply, result, put_in(state.records[token], record)}
    end
  end

  def handle_call({:delete, token}, _, state), do: {:reply, :ok, remove_record(state, token)}

  @impl true
  def handle_info({:DOWN, monitor, :process, _pid, reason}, state) do
    case Map.pop(state.monitors, monitor) do
      {nil, _} ->
        {:noreply, state}

      {{:worker, token, worker}, monitors} ->
        {:noreply, record_down(%{state | monitors: monitors}, token, worker, reason)}

      {{:guardian, token, guardian}, monitors} ->
        state = %{state | monitors: monitors}

        if state.records[token] do
          {:noreply, put_in(state.records[token].guardian_exits[guardian], reason)}
        else
          {:noreply, state}
        end

      {{:owner, token}, monitors} ->
        {:noreply, owner_down(%{state | monitors: monitors}, token)}
    end
  end

  defp owner_down(state, token) do
    case state.records[token] do
      nil ->
        state

      record ->
        Enum.each(record.guardians, &send(&1, :abort))

        if not record.retain do
          {:ok, _cleanup} = Task.start(fn -> HTTP.Test.finalize(token, true) end)
          :ok
        end

        put_in(state.records[token].frozen, true)
    end
  end

  defp ensure_owner(state, owner) do
    case state.owners[owner] do
      nil ->
        token = make_ref()
        monitor = Process.monitor(owner)

        record = %{
          owner: owner,
          monitor: monitor,
          fixtures: %{},
          allowances: %{},
          calls: %{},
          guardians: MapSet.new(),
          guardian_monitors: %{},
          guardian_exits: %{},
          completed_guardians: MapSet.new(),
          resources: %{},
          failures: [],
          retain: false,
          frozen: false,
          terminal: nil
        }

        state = put_in(state.owners[owner], token)
        state = put_in(state.records[token], record)
        {token, put_in(state.monitors[monitor], {:owner, token})}

      token ->
        {token, state}
    end
  end

  defp take_fixture(%{mode: :stub, callback: callback} = fixture), do: {:ok, callback, fixture}

  defp take_fixture(%{mode: :expect, queue: queue} = fixture) do
    case Enum.drop_while(queue, &(&1.remaining == 0)) do
      [item | rest] ->
        {:ok, item.callback, %{fixture | queue: [%{item | remaining: item.remaining - 1} | rest]}}

      [] ->
        {:error, :unexpected_call}
    end
  end

  defp take_fixture(nil), do: {:error, :no_fixture}

  defp update_call(state, token, worker, fun) do
    if state.records[token] && state.records[token].calls[worker],
      do: update_in(state.records[token].calls[worker], fun),
      else: state
  end

  defp add_failure(state, token, failure) do
    if state.records[token],
      do: update_in(state.records[token].failures, &[failure | &1]),
      else: state
  end

  defp record_down(state, token, worker, reason) do
    case get_in(state, [:records, token, :calls, worker]) do
      %{active: true, canceled: false} ->
        state
        |> add_failure(token, {:callback_exit, reason, []})
        |> update_call(token, worker, &%{&1 | active: false})

      _ ->
        state
    end
  end

  defp remove_record(state, token) do
    case state.records[token] do
      nil ->
        state

      record ->
        refs = [
          record.monitor
          | Map.values(record.guardian_monitors) ++
              Enum.map(record.calls, fn {_, call} -> call.monitor end)
        ]

        Enum.each(refs, &Process.demonitor(&1, [:flush]))

        %{
          state
          | owners: Map.delete(state.owners, record.owner),
            records: Map.delete(state.records, token),
            monitors: Map.drop(state.monitors, refs)
        }
    end
  end
end

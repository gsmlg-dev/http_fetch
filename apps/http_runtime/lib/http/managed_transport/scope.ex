defmodule HTTP.ManagedTransport.Scope do
  @moduledoc false
  use GenServer

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    policy = opts[:policy]
    {:ok, h1} = HTTP.HTTP1.Pool.start_link(name: nil)
    {:ok, h2_supervisor} = HTTP.HTTP2.ConnectionSupervisor.start_link([])

    {:ok, h2} =
      HTTP.HTTP2.Pool.start_link(
        max_connections: policy.limits.max_connections,
        max_total_connections: policy.limits.max_connections,
        max_keys: 1,
        max_streams: policy.limits.max_requests,
        max_pending: 0,
        idle_timeout: policy.limits.idle_timeout
      )

    children = Map.new([h1, h2, h2_supervisor], &{Process.monitor(&1), &1})
    ingress = :ets.new(:managed_ingress, [:public, write_concurrency: true])
    :ets.insert(ingress, for(id <- 1..policy.limits.max_requests, do: {id, nil, nil, :free, nil}))
    configuration = :ets.new(:managed_configuration, [:protected, read_concurrency: true])
    gate = :atomics.new(1, [])
    :atomics.put(gate, 1, 1)
    :ets.insert(configuration, {:policy, policy, injection(policy, h1, h2, h2_supervisor)})
    Process.send_after(self(), :reconcile, 5)

    {:ok,
     %{
       policy: policy,
       latch: opts[:latch],
       creator: Process.monitor(opts[:creator]),
       lifecycle: :open,
       requests: %{},
       resources: %{},
       slots: %{},
       children: children,
       h1: h1,
       h2: h2,
       h2_supervisor: h2_supervisor,
       uncertain?: false,
       ingress: ingress,
       configuration: configuration,
       gate: gate,
       request_leases: %{}
     }}
  end

  @impl true
  def handle_call(:handle, _, state) do
    {:reply,
     %{
       coordinator: self(),
       ingress: state.ingress,
       configuration: state.configuration,
       gate: state.gate,
       max_requests: state.policy.limits.max_requests
     }, state}
  end

  def handle_call(:snapshot, _, state) do
    state = reconcile(state)

    {:reply,
     {:ok,
      %{
        active_requests: map_size(state.requests),
        pending: 0,
        preparing_requests: occupied(state) - map_size(state.requests),
        connections: map_size(state.slots),
        resources: map_size(state.resources),
        limits: state.policy.limits,
        identity: Base.encode16(state.policy.identity, case: :lower),
        lifecycle: state.lifecycle
      }}, state}
  end

  def handle_call({:connect_start, tracker}, _, state) do
    cond do
      state.uncertain? or state.lifecycle in [:aborting, :stopping] ->
        {:reply, {:error, :transport_scope_retired}, state}

      tracker not in Map.values(state.requests) ->
        {:reply, {:error, :transport_scope_retired}, state}

      map_size(state.slots) >= state.policy.limits.max_connections ->
        {:reply, {:error, {:transport_scope_capacity, :connections}}, state}

      true ->
        token = make_ref()
        slot = %{tracker: tracker, socket: nil, dials: MapSet.new(), done?: false}
        {:reply, {:ok, token}, %{state | slots: Map.put(state.slots, token, slot)}}
    end
  end

  def handle_call({:track, resource, kind, token}, _, state) do
    if Enum.any?(state.resources, fn {_, {existing, _, _}} -> existing == resource end) do
      {:reply, :ok, state}
    else
      monitor = if is_port(resource), do: Port.monitor(resource), else: Process.monitor(resource)
      state = %{state | resources: Map.put(state.resources, monitor, {resource, kind, token})}

      slots = update_slot(state.slots, token, &retain_slot_resource(&1, resource, kind))

      if state.lifecycle in [:aborting, :stopping], do: close_resource(resource, kind)
      {:reply, :ok, %{state | slots: slots}}
    end
  end

  def handle_call({:retire, mode}, _, state) do
    send(self(), :settle)
    {:reply, :ok, retire(state, mode)}
  end

  @impl true
  def handle_cast(:unconfirmed, state) do
    send(self(), :settle)
    {:noreply, retire(%{state | uncertain?: true}, :graceful)}
  end

  def handle_cast({:connect_done, token}, state) do
    slots = update_slot(state.slots, token, &%{&1 | done?: true})
    {:noreply, prune_slots(%{state | slots: slots})}
  end

  @impl true
  def handle_info({:DOWN, ref, _, resource, reason}, state) do
    cond do
      ref == state.creator ->
        send(self(), :settle)
        {:noreply, retire(state, :abort)}

      Map.has_key?(state.requests, ref) ->
        {id, token} = state.request_leases[ref]
        release_ingress(state, id, token)

        slots =
          Map.new(state.slots, fn {token, slot} ->
            {token, if(slot.tracker == resource, do: %{slot | done?: true}, else: slot)}
          end)

        settle(
          %{
            state
            | requests: Map.delete(state.requests, ref),
              slots: slots,
              request_leases: Map.delete(state.request_leases, ref)
          }
          |> prune_slots()
        )

      Map.has_key?(state.resources, ref) ->
        {_, kind, token} = state.resources[ref]

        slots = update_slot(state.slots, token, &release_slot_resource(&1, resource, kind))

        settle(
          %{state | resources: Map.delete(state.resources, ref), slots: slots}
          |> prune_slots()
        )

      Map.has_key?(state.children, ref) ->
        state = %{state | children: Map.delete(state.children, ref)}

        if state.lifecycle == :stopping do
          settle(state)
        else
          send(self(), :settle)
          {:noreply, retire(%{state | uncertain?: state.uncertain? or reason != :normal}, :abort)}
        end

      true ->
        {:noreply, state}
    end
  end

  def handle_info(:settle, state), do: settle(state)

  def handle_info(:reconcile, state) do
    Process.send_after(self(), :reconcile, 5)
    settle(reconcile(state))
  end

  def handle_info({:EXIT, _, _}, state), do: {:noreply, state}

  defp retire(%{lifecycle: :stopping} = state, _mode), do: state

  defp retire(state, mode) do
    :atomics.put(state.gate, 1, 2)
    GenServer.cast(state.h1, :close_idle)
    GenServer.cast(state.h2, :close_idle)

    if mode == :abort or state.lifecycle == :aborting do
      if state.lifecycle != :aborting do
        for {id, token, _, :active, tracker} <- :ets.tab2list(state.ingress),
            do: cancel_ingress(state, id, token, tracker, :active)

        Enum.each(state.resources, fn {_, {resource, kind, _}} ->
          close_resource(resource, kind)
        end)
      end

      %{state | lifecycle: :aborting}
    else
      %{state | lifecycle: :draining}
    end
  end

  defp settle(state) do
    state = reconcile(state)

    state =
      if state.lifecycle in [:draining, :aborting] and occupied(state) == 0 do
        Enum.each(Map.values(state.children), &Process.exit(&1, :shutdown))

        Enum.each(state.resources, fn {_, {resource, kind, _}} ->
          close_resource(resource, kind)
        end)

        %{state | lifecycle: :stopping}
      else
        state
      end

    if state.lifecycle == :stopping and map_size(state.resources) == 0 and
         map_size(state.children) == 0 and map_size(state.slots) == 0 do
      :atomics.put(state.latch, 1, if(state.uncertain?, do: 3, else: 2))
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end

  defp prune_slots(state) do
    retained_tokens =
      state.resources
      |> Map.values()
      |> MapSet.new(fn {_resource, _kind, token} -> token end)

    slots =
      Map.reject(state.slots, fn {token, slot} ->
        slot.done? and slot.socket == nil and MapSet.size(slot.dials) == 0 and
          not MapSet.member?(retained_tokens, token)
      end)

    %{state | slots: slots}
  end

  defp injection(policy, h1, h2, supervisor) do
    key = %{
      managed: Base.encode16(policy.identity, case: :lower),
      generation: self(),
      http1_policy: {min(policy.limits.max_connections, 16), policy.limits.idle_timeout}
    }

    [
      managed_coordinator: self(),
      managed_pool_key: key,
      http1_pool: h1,
      http2_pool: h2,
      http2_connection_supervisor: supervisor
    ]
  end

  defp occupied(state),
    do:
      :ets.select_count(state.ingress, [
        {{:_, :_, :_, :"$1", :_}, [{:"/=", :"$1", :free}], [true]}
      ])

  defp reconcile(state), do: Enum.reduce(:ets.tab2list(state.ingress), state, &reconcile_slot/2)

  defp reconcile_slot({id, token, owner, :preparing, nil}, state) do
    if state.lifecycle != :open or not Process.alive?(owner),
      do: release_ingress(state, id, token, :preparing, nil)

    state
  end

  defp reconcile_slot({id, token, _owner, :reserved, tracker}, state) do
    if state.lifecycle != :open or not Process.alive?(tracker),
      do: cancel_ingress(state, id, token, tracker, :reserved)

    state
  end

  defp reconcile_slot({id, token, owner, :awaiting, tracker}, state) do
    if state.lifecycle == :open and Process.alive?(tracker) do
      monitor = Process.monitor(tracker)

      replaced =
        :ets.select_replace(
          state.ingress,
          [
            {{id, token, owner, :awaiting, tracker}, [],
             [{:const, {id, token, owner, :active, tracker}}]}
          ]
        )

      if replaced == 1 do
        %{
          state
          | requests: Map.put(state.requests, monitor, tracker),
            request_leases: Map.put(state.request_leases, monitor, {id, token})
        }
      else
        Process.demonitor(monitor, [:flush])
        state
      end
    else
      cancel_ingress(state, id, token, tracker, :awaiting)
      state
    end
  end

  defp reconcile_slot({id, token, _, :canceled, tracker}, state) do
    cancel_ingress(state, id, token, tracker, :canceled)
    state
  end

  defp reconcile_slot({id, token, _, :canceling, tracker}, state) do
    if tracker not in Map.values(state.requests) and not Process.alive?(tracker),
      do: release_ingress(state, id, token, :canceling, tracker)

    state
  end

  defp reconcile_slot(_, state), do: state

  defp cancel_ingress(state, id, token, tracker, phase) do
    if tracker in Map.values(state.requests) or (is_pid(tracker) and Process.alive?(tracker)) do
      replaced =
        :ets.select_replace(
          state.ingress,
          [{{id, token, :"$1", phase, tracker}, [], [{{id, token, :"$1", :canceling, tracker}}]}]
        )

      if replaced == 1, do: HTTP.RequestLifecycle.abort(tracker)
    else
      release_ingress(state, id, token, phase, tracker)
    end
  end

  defp update_slot(slots, token, fun) do
    if Map.has_key?(slots, token), do: Map.update!(slots, token, fun), else: slots
  end

  defp retain_slot_resource(slot, resource, :socket), do: %{slot | socket: resource}

  defp retain_slot_resource(slot, resource, :dial),
    do: %{slot | dials: MapSet.put(slot.dials, resource)}

  defp retain_slot_resource(slot, _, _), do: slot
  defp release_slot_resource(slot, _, :socket), do: %{slot | socket: nil}

  defp release_slot_resource(slot, resource, :dial),
    do: %{slot | dials: MapSet.delete(slot.dials, resource)}

  defp release_slot_resource(slot, _, _), do: slot

  defp release_ingress(state, id, token) do
    :ets.select_replace(state.ingress, [
      {{id, token, :_, :_, :_}, [], [{:const, {id, nil, nil, :free, nil}}]}
    ])

    :ok
  end

  defp release_ingress(state, id, token, phase, tracker) do
    :ets.select_replace(
      state.ingress,
      [{{id, token, :_, phase, tracker}, [], [{:const, {id, nil, nil, :free, nil}}]}]
    )

    :ok
  end

  defp close_resource(port, :socket) do
    _ = :inet.setopts(port, linger: {true, 0})
    :gen_tcp.close(port)
  end

  defp close_resource(pid, :connection), do: Process.exit(pid, :shutdown)
  defp close_resource(pid, kind) when kind in [:owner, :dial, :upload], do: send(pid, :abort)
  defp close_resource(pid, :body_bridge), do: GenServer.cast(pid, :stop)
  defp close_resource(pid, :stream), do: send(pid, {:request_lifecycle_stop, :aborted})
  defp close_resource(_, _), do: :ok
end

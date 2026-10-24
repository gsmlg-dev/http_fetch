defmodule Quic.Cleanup.Observer do
  @moduledoc false
  use GenServer

  @birth_limit 132
  @operation_limit 256

  @impl true
  def init({owner, scope, secret, receipt}) do
    {:ok,
     %{
       owner: owner,
       owner_monitor: Process.monitor(owner),
       scope: scope,
       secret: secret,
       receipt: receipt,
       endpoint_reserved: false,
       births: %{},
       resources: %{},
       monitors: %{},
       operations: %{},
       retiring: false,
       loss: nil
     }}
  end

  @impl true
  def handle_call({secret, request}, {caller, _}, %{secret: secret} = state) do
    state = if Quic.Cleanup.fenced?(state.receipt), do: retire(state), else: state
    {reply, next} = request(request, caller, state)
    {:reply, reply, publish(next), {:continue, :settle}}
  end

  def handle_call(_, _from, state), do: {:reply, {:error, :invalid_lease}, state}

  defp request({:reserve, role, deadline}, caller, state) do
    cond do
      state.retiring ->
        reject(state, :retiring)

      now() >= deadline ->
        reject(state, :deadline_expired)

      map_size(state.births) >= @birth_limit ->
        reject(state, :birth_capacity)

      not may_create?(state, caller, role) ->
        reject(state, :invalid_producer)

      role == :endpoint and state.endpoint_reserved ->
        reject(state, :endpoint_already_reserved)

      true ->
        ref = make_ref()
        monitor = Process.monitor(caller)
        birth = %{role: role, producer: caller, monitor: monitor, deadline: deadline}

        next = %{
          state
          | births: Map.put(state.births, ref, birth),
            endpoint_reserved: state.endpoint_reserved or role == :endpoint
        }

        {{:permit, ref}, next}
    end
  end

  defp request({:enroll, ref, resource}, caller, state) do
    case state.births[ref] do
      %{role: role} = birth ->
        if valid_identity?(role, caller, resource, birth) and
             not Map.has_key?(state.resources, resource) do
          Process.demonitor(birth.monitor, [:flush])
          type = if role == :port, do: :port, else: :process
          monitor = :erlang.monitor(type, resource)
          entry = %{role: role, monitor: monitor, producer: caller}

          next = %{
            state
            | births: Map.delete(state.births, ref),
              resources: Map.put(state.resources, resource, entry),
              monitors: Map.put(state.monitors, monitor, resource)
          }

          :atomics.add(state.receipt, 3, 1)
          increment_role(state.receipt, role)

          if state.retiring or now() >= birth.deadline do
            retire_resource(resource, entry)
            {{:error, :retiring}, retire(next)}
          else
            {:ok, next}
          end
        else
          reject(state, :invalid_identity)
        end

      nil ->
        reject(state, :invalid_birth)
    end
  end

  defp request({:no_birth, ref}, caller, state) do
    case state.births[ref] do
      %{producer: ^caller, monitor: monitor} ->
        Process.demonitor(monitor, [:flush])
        {:ok, %{state | births: Map.delete(state.births, ref)}}

      _ ->
        reject(state, :invalid_birth)
    end
  end

  defp request(:authorize, caller, state) do
    if not state.retiring and Map.has_key?(state.resources, caller),
      do: {:ok, state},
      else: reject(state, :retiring)
  end

  defp request({:operation, target, ref, kind, deadline}, caller, state) do
    cond do
      state.retiring ->
        reject(state, :retiring)

      now() >= deadline ->
        reject(state, :deadline_expired)

      Map.has_key?(state.operations, ref) ->
        reject(state, :operation_ref_reused)

      map_size(state.operations) >= @operation_limit ->
        reject(state, :operation_capacity)

      not is_reference(target) ->
        reject(state, :invalid_target_generation)

      kind not in [
        :connect,
        :attach,
        :open,
        :send,
        :read,
        :close,
        :abort,
        :open_stream,
        :send_stream,
        :events,
        :reset_stream,
        :stop_stream,
        :send_datagram,
        :read_datagrams
      ] ->
        reject(state, :invalid_operation_kind)

      true ->
        operation = %{
          producer: caller,
          monitor: Process.monitor(caller),
          target: target,
          kind: kind,
          deadline: deadline
        }

        {{:permit, ref}, %{state | operations: Map.put(state.operations, ref, operation)}}
    end
  end

  defp request({:operation_result, ref, outcome}, caller, state) do
    case state.operations[ref] do
      %{producer: ^caller, monitor: monitor} ->
        Process.demonitor(monitor, [:flush])
        if outcome == :indeterminate, do: :atomics.put(state.receipt, 7, 1)
        {:ok, %{state | operations: Map.delete(state.operations, ref)}}

      _ ->
        reject(state, :invalid_operation_producer)
    end
  end

  @impl true
  def handle_continue(:settle, state), do: settle(state)

  @impl true
  def handle_info({:retire, secret}, %{secret: secret} = state),
    do: state |> retire() |> publish() |> settle()

  def handle_info({:DOWN, monitor, _type, _resource, _reason}, state) do
    next =
      cond do
        monitor == state.owner_monitor ->
          retire(state)

        Map.has_key?(state.monitors, monitor) ->
          resource_down(state, monitor)

        Enum.any?(state.births, fn {_, birth} -> birth.monitor == monitor end) ->
          retire(%{state | loss: state.loss || 1})

        true ->
          operation_down(state, monitor)
      end

    next |> publish() |> settle()
  end

  def handle_info(:observation_cap, state), do: observation_cap(state)

  def handle_info(_, state), do: {:noreply, state}

  defp may_create?(_state, _caller, :endpoint), do: true

  defp may_create?(state, caller, role) when role in [:io, :connection],
    do: match?(%{role: :endpoint}, state.resources[caller])

  defp may_create?(state, caller, :port), do: match?(%{role: :io}, state.resources[caller])

  defp valid_identity?(:port, caller, resource, %{producer: caller}), do: is_port(resource)

  defp valid_identity?(role, caller, caller, _) when role in [:endpoint, :io, :connection],
    do: is_pid(caller) and node(caller) == node()

  defp valid_identity?(_, _, _, _), do: false

  defp retire(%{retiring: true} = state), do: state

  defp retire(state) do
    Quic.Cleanup.fence(state.receipt)

    Process.send_after(
      self(),
      :observation_cap,
      max(0, Quic.Cleanup.cap_remaining(state.receipt))
    )

    Enum.each(state.resources, fn {resource, entry} -> retire_resource(resource, entry) end)
    %{state | retiring: true}
  end

  defp retire_resource(resource, %{role: role}) when role != :port,
    do: send(resource, {:quic_cleanup_retire, self()})

  defp retire_resource(_, _), do: :ok

  defp resource_down(state, monitor) do
    resource = state.monitors[monitor]
    :atomics.add(state.receipt, 4, 1)
    role = state.resources[resource].role

    next = %{
      state
      | resources: Map.delete(state.resources, resource),
        monitors: Map.delete(state.monitors, monitor)
    }

    if role == :endpoint, do: retire(next), else: next
  end

  defp operation_down(state, monitor) do
    operations =
      Enum.reject(state.operations, fn {_, operation} -> operation.monitor == monitor end)

    if length(operations) < map_size(state.operations), do: :atomics.put(state.receipt, 7, 1)
    %{state | operations: Map.new(operations)}
  end

  defp settle(%{retiring: true} = state) do
    if Quic.Cleanup.cap_remaining(state.receipt) <= 0,
      do: observation_cap(state),
      else: settle_graph(state)
  end

  defp settle(state), do: {:noreply, state}

  defp observation_cap(state) do
    Enum.each(state.resources, fn {resource, entry} ->
      if entry.role != :port, do: Process.exit(resource, :kill)
    end)

    terminal(state, state.loss || 2)
  end

  defp settle_graph(%{resources: resources, births: births} = state)
       when map_size(resources) == 0 and map_size(births) == 0 do
    terminal(state, state.loss)
  end

  defp settle_graph(%{resources: resources, loss: loss} = state)
       when map_size(resources) == 0 and not is_nil(loss),
       do: terminal(state, loss)

  defp settle_graph(state), do: {:noreply, state}

  defp terminal(state, loss) do
    # Missing operation results do not become "not sent" when the graph retires.
    if map_size(state.operations) > 0, do: :atomics.put(state.receipt, 7, 1)
    :atomics.put(state.receipt, 9, loss || 0)
    :atomics.put(state.receipt, 1, if(loss, do: 2, else: 1))
    {:stop, :normal, state}
  end

  defp publish(state) do
    :atomics.put(state.receipt, 2, if(state.retiring, do: 1, else: 0))
    :atomics.put(state.receipt, 5, map_size(state.births))
    :atomics.put(state.receipt, 6, map_size(state.operations))
    state
  end

  defp increment_role(receipt, :endpoint), do: :atomics.add(receipt, 10, 1)
  defp increment_role(receipt, :io), do: :atomics.add(receipt, 11, 1)
  defp increment_role(receipt, :port), do: :atomics.add(receipt, 12, 1)
  defp increment_role(receipt, :connection), do: :atomics.add(receipt, 13, 1)
  defp reject(state, reason), do: {{:error, reason}, state}
  defp now, do: System.monotonic_time(:millisecond)
end

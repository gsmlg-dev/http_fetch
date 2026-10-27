defmodule SSL.PolicyIO.Guard do
  @moduledoc false
  use GenServer
  alias SSL.PolicyIO.FileExecutor

  alias SSL.Lifecycle.AuxiliaryLedger
  alias SSL.PolicyIO

  # This same state/transition adapter runs in the existing lifecycle Observer.
  # It performs no callback, file, socket or ASN.1 operation.
  def new(connection, identity, deadline) do
    %{
      connection: connection,
      requester: identity,
      deadline: deadline,
      capability: make_ref(),
      ledger: AuxiliaryLedger.new(),
      actor: nil,
      socket: nil,
      http_closing: nil,
      retirement: nil,
      finished: false
    }
  end

  def context(state) do
    %PolicyIO.Context{
      observer: self(),
      capability: state.capability,
      deadline: state.deadline
    }
  end

  def operation(state, capability, operation, caller) do
    if capability == state.capability and caller == state.connection do
      authorized(state, operation)
    else
      {{:error, :unauthorized_policy}, state}
    end
  end

  def actor_operation(
        %{actor: %{pid: caller, capability: capability}} = state,
        capability,
        operation,
        caller
      ) do
    if operation in [:open, {:begin, :read}] and
         (state.retirement != nil or PolicyIO.remaining(state.deadline) == 0),
       do: {{:error, :admission_closed}, state},
       else: actor_authorized(state, operation)
  end

  def actor_operation(state, _, _, _), do: {{:error, :unauthorized_policy}, state}

  def down(state, {:DOWN, _, :process, _, _} = event) do
    ledger = state.ledger |> AuxiliaryLedger.creator_down(event) |> AuxiliaryLedger.down(event)
    %{state | ledger: ledger}
  end

  def down(state, {:DOWN, _, :socket, _, _} = event),
    do: %{state | ledger: AuxiliaryLedger.down(state.ledger, event)}

  def down(state, _), do: state

  def retire(%{retirement: nil} = state, grace) do
    if state.actor, do: send(state.actor.pid, {:policy_stop, self(), state.actor.capability})
    %{state | ledger: AuxiliaryLedger.close_admission(state.ledger), retirement: grace}
  end

  def retire(state, _grace), do: state

  def kill(state) do
    if state.actor && Process.alive?(state.actor.pid), do: Process.exit(state.actor.pid, :kill)
    :ok
  end

  def proof(state), do: AuxiliaryLedger.proof(state.ledger)

  def closing_connection?(%{connection: connection, http_closing: generation}, connection)
      when is_integer(generation),
      do: true

  def closing_connection?(_state, _connection), do: false

  def settled?(state),
    do:
      match?(
        {:ok, %{cleanup: :confirmed}},
        AuxiliaryLedger.proof(AuxiliaryLedger.close_admission(state.ledger))
      )

  def counts(state) do
    snapshot = AuxiliaryLedger.snapshot(state.ledger)

    if snapshot.losses == 0 and snapshot.allocations == 0 and
         snapshot.native_operation == :idle and snapshot.resource_state not in [:open, :unknown] do
      current = state.ledger.current
      live = current != nil and current.state == :live

      %{
        processes: if(live and current.kind == :file_executor, do: 1, else: 0),
        sockets: if(live and current.kind == :http_socket, do: 1, else: 0)
      }
    else
      nil
    end
  end

  defp authorized(state, {:http_begin_close, generation}) do
    case state.ledger.current do
      %{kind: :http_socket, generation: ^generation, state: :live}
      when state.retirement == nil and state.http_closing == nil ->
        if PolicyIO.remaining(state.deadline) > 0,
          do: {:ok, %{state | http_closing: generation}},
          else: {{:error, :admission_closed}, state}

      _ ->
        {{:error, :invalid_http_close}, state}
    end
  end

  defp authorized(%{http_closing: generation} = state, {:http_close_finished, generation})
       when is_integer(generation),
       do: {:ok, %{state | http_closing: nil}}

  defp authorized(state, {:http_close_finished, _}),
    do: {{:error, :invalid_http_close}, state}

  defp authorized(state, :finish) do
    if settled?(state) do
      {:ok, %{state | ledger: AuxiliaryLedger.close_admission(state.ledger), finished: true}}
    else
      {{:error, :resources_pending}, state}
    end
  end

  defp authorized(state, {:settled, generation}) do
    if state.ledger.generation == generation,
      do: {if(settled?(state), do: :ok, else: :pending), state},
      else: {{:error, :unknown_generation}, state}
  end

  defp authorized(state, :http) do
    token = make_ref()

    with true <- state.retirement == nil and PolicyIO.remaining(state.deadline) > 0,
         {:ok, ledger, generation} <-
           AuxiliaryLedger.reserve(state.ledger, :http_socket, state.requester, token) do
      {{:ok, generation, token}, %{state | ledger: ledger}}
    else
      false -> {{:error, :admission_closed}, state}
      error -> {error, state}
    end
  end

  defp authorized(state, {:http_enroll, generation, token, socket}) do
    case :socket.info(socket) do
      %{owner: owner, type: :stream, protocol: :tcp} when owner == state.connection ->
        monitor = :socket.monitor(socket)

        ledger =
          if PolicyIO.remaining(state.deadline) == 0,
            do: AuxiliaryLedger.close_admission(state.ledger),
            else: state.ledger

        case AuxiliaryLedger.enroll(ledger, generation, token, {monitor, :socket, socket}) do
          {:ok, ledger, action} ->
            {action, %{state | ledger: ledger, socket: {monitor, socket}}}

          error ->
            :socket.cancel_monitor(monitor)
            {error, state}
        end

      _ ->
        {{:error, :unauthorized_policy}, state}
    end
  catch
    _, _ -> {{:error, :policy_io_unconfirmed}, state}
  end

  defp authorized(state, :file) do
    token = make_ref()

    with true <- state.retirement == nil and PolicyIO.remaining(state.deadline) > 0,
         {:ok, ledger, generation} <-
           AuxiliaryLedger.reserve(state.ledger, :file_executor, state.requester, token) do
      capability = make_ref()
      observer = self()
      connection = state.connection
      deadline = state.deadline

      {pid, monitor} =
        spawn_monitor(fn ->
          FileExecutor.init(observer, connection, capability, generation, deadline)
        end)

      {:ok, ledger, :use} =
        AuxiliaryLedger.enroll(ledger, generation, token, {monitor, :process, pid})

      actor = %{pid: pid, monitor: monitor, capability: capability, generation: generation}
      send(pid, {:policy_activate, observer, capability})
      {{:ok, pid, capability, generation}, %{state | ledger: ledger, actor: actor}}
    else
      false -> {{:error, :admission_closed}, state}
      {:error, _} = error -> {error, state}
    end
  end

  defp authorized(state, _), do: {{:error, :invalid_policy_operation}, state}

  defp actor_authorized(state, :open) do
    operation = make_ref()
    cleanup = make_ref()

    case AuxiliaryLedger.grant_open(state.ledger, state.actor.generation, operation, cleanup) do
      {:ok, ledger} -> {{:ok, operation, cleanup}, %{state | ledger: ledger}}
      error -> {error, state}
    end
  end

  defp actor_authorized(state, {:begin, kind}) when kind in [:read, :close] do
    token = if kind == :close, do: elem(state.ledger.current.cleanup, 0), else: make_ref()

    case AuxiliaryLedger.begin_operation(state.ledger, state.actor.generation, token, kind) do
      {:ok, ledger} -> {{:ok, token}, %{state | ledger: ledger}}
      error -> {error, state}
    end
  end

  defp actor_authorized(state, {:complete, completion}) do
    case AuxiliaryLedger.complete_operation(state.ledger, state.actor.generation, completion) do
      {:ok, ledger} -> {:ok, %{state | ledger: ledger}}
      error -> {error, state}
    end
  end

  defp actor_authorized(state, {:drain, completion, close}) do
    case AuxiliaryLedger.drain_completed(state.ledger, state.actor.generation, completion, close) do
      {:ok, ledger} -> {:ok, %{state | ledger: ledger}}
      error -> {error, state}
    end
  end

  defp actor_authorized(state, _), do: {{:error, :invalid_policy_operation}, state}

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted) |> Map.put(:log, [])

  @impl true
  def init({connection, owner, deadline}) do
    Process.flag(:sensitive, true)
    identity = {Process.monitor(connection), :process, connection}
    owner_monitor = Process.monitor(owner)

    timer =
      if deadline == :infinity,
        do: nil,
        else: Process.send_after(self(), :deadline, PolicyIO.remaining(deadline))

    {:ok,
     %{
       policy: new(connection, identity, deadline),
       owner: owner,
       owner_monitor: owner_monitor,
       timer: timer
     }}
  end

  @impl true
  def handle_call({:context, _}, {caller, _}, %{policy: %{connection: caller}} = state),
    do: {:reply, {:ok, context(state.policy)}, state}

  def handle_call(
        {{:policy, capability, :retire}, _},
        {caller, _},
        %{policy: %{capability: capability, connection: caller}} = state
      ) do
    _ = if state.timer, do: Process.cancel_timer(state.timer)
    policy = retire(state.policy, PolicyIO.now() + 1_000)

    case finish_retirement(%{state | policy: policy, timer: nil}) do
      {:stop, reason, next} -> {:stop, reason, :ok, next}
      {:noreply, next} -> {:reply, :ok, next}
    end
  end

  def handle_call({{:policy, capability, operation}, _}, {caller, _}, state) do
    {reply, policy} = operation(state.policy, capability, operation, caller)
    next = %{state | policy: policy}
    if policy.retirement != nil, do: stop_connection(policy)

    if policy.finished do
      _ = if state.timer, do: Process.cancel_timer(state.timer)
      {:stop, :normal, reply, next}
    else
      {:reply, reply, next}
    end
  end

  def handle_call({{:policy_actor, capability, operation}, _}, {caller, _}, state) do
    {reply, policy} = actor_operation(state.policy, capability, operation, caller)
    {:reply, reply, %{state | policy: policy}}
  end

  def handle_call(_, _, state), do: {:reply, {:error, :unauthorized_policy}, state}

  @impl true
  def handle_info({:DOWN, _, _, _, _} = event, state) do
    policy = down(state.policy, event)
    owner_down = match?({:DOWN, ref, :process, _, _} when ref == state.owner_monitor, event)

    requester_down =
      match?({:DOWN, ref, :process, pid, _} when {ref, :process, pid} == policy.requester, event)

    policy =
      if owner_down or requester_down, do: retire(policy, PolicyIO.now() + 1_000), else: policy

    if owner_down, do: stop_connection(policy)

    finish_retirement(%{state | policy: policy})
  end

  def handle_info(:deadline, state) do
    policy = retire(state.policy, PolicyIO.now() + 1_000)
    stop_connection(policy)
    Process.send_after(self(), :grace, 1_000)
    finish_retirement(%{state | policy: policy})
  end

  def handle_info(:grace, state) do
    Process.exit(state.policy.connection, :kill)
    kill(state.policy)
    {:stop, :normal, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  defp stop_connection(policy) do
    unless closing_connection?(policy, policy.connection),
      do: Process.exit(policy.connection, :kill)
  end

  defp finish_retirement(%{policy: %{retirement: grace}} = state) when is_integer(grace) do
    if settled?(state.policy) do
      {:stop, :normal, state}
    else
      Process.send_after(self(), :grace, max(0, grace - PolicyIO.now()))
      {:noreply, state}
    end
  end

  defp finish_retirement(state), do: {:noreply, state}
end

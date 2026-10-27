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
      http_close: nil,
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

  def finish_http_close(state, capability, generation, nonce, {caller, _} = from) do
    if capability == state.capability and caller == state.connection do
      case state.http_close do
        %{generation: ^generation, nonce: ^nonce, finished: false} = closing ->
          if state.retirement == nil or PolicyIO.now() < state.retirement do
            next = %{state | http_close: %{closing | finished: true, from: from}}
            {:deferred, release_http_close(next)}
          else
            {{:error, :http_close_not_permitted}, state}
          end

        _ ->
          {{:error, :http_close_not_permitted}, state}
      end
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
    release_http_close(%{state | ledger: ledger})
  end

  def down(state, {:DOWN, _, :socket, _, _} = event),
    do: release_http_close(%{state | ledger: AuxiliaryLedger.down(state.ledger, event)})

  def down(state, _), do: state

  def retire(%{retirement: nil} = state, grace) do
    if state.actor, do: send(state.actor.pid, {:policy_stop, self(), state.actor.capability})
    %{state | ledger: AuxiliaryLedger.close_admission(state.ledger), retirement: grace}
  end

  def retire(state, _grace), do: state

  def kill(state) do
    if protects_connection?(state, state.connection), do: Process.exit(state.connection, :kill)
    if state.actor && Process.alive?(state.actor.pid), do: Process.exit(state.actor.pid, :kill)
    :ok
  end

  # A close acknowledgement never substitutes for the original native DOWN.
  # The closer is protected only from our retirement kill, through fixed grace.
  def protects_connection?(%{http_close: closing, connection: pid}, pid),
    do: closing != nil

  def protects_connection?(_state, _pid), do: false

  def http_close_expired?(%{http_close: %{deadline: deadline}}, instant),
    do: instant >= deadline

  def http_close_expired?(_state, _instant), do: false

  def http_close_timer?(%{http_close: %{timer: timer, nonce: nonce}}, timer, nonce),
    do: true

  def http_close_timer?(_state, _timer, _nonce), do: false

  def proof(state), do: AuxiliaryLedger.proof(state.ledger)

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

  defp authorized(state, :finish) do
    if state.http_close == nil and settled?(state) do
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

  defp authorized(state, {:http_close_begin, generation, socket, deadline}) do
    instant = PolicyIO.now()

    with true <- is_integer(deadline) and instant < deadline,
         true <- state.retirement == nil and PolicyIO.remaining(state.deadline) > 0,
         nil <- state.http_close,
         %{
           generation: ^generation,
           kind: :http_socket,
           state: :live,
           identity: {_, :socket, ^socket} = identity
         } <- state.ledger.current,
         %{owner: owner} when owner == state.connection <- :socket.info(socket) do
      bound = min(deadline, instant + 1_000)
      bound = if state.deadline == :infinity, do: bound, else: min(bound, state.deadline)
      nonce = make_ref()
      timer = :erlang.start_timer(bound, self(), {:policy_http_close, nonce}, abs: true)

      closing = %{
        generation: generation,
        identity: identity,
        nonce: nonce,
        deadline: bound,
        timer: timer,
        from: nil,
        finished: false
      }

      {{:ok, nonce, bound}, %{state | http_close: closing}}
    else
      _ -> {{:error, :http_close_not_permitted}, state}
    end
  end

  defp authorized(state, :http) do
    token = make_ref()

    with true <-
           state.retirement == nil and state.http_close == nil and
             PolicyIO.remaining(state.deadline) > 0,
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

    with true <-
           state.retirement == nil and state.http_close == nil and
             PolicyIO.remaining(state.deadline) > 0,
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

  defp release_http_close(%{http_close: %{finished: true, identity: identity} = closing} = state) do
    case state.ledger.current do
      %{identity: ^identity, state: :down} ->
        _ = Process.cancel_timer(closing.timer)
        reply = if state.retirement == nil, do: :ok, else: {:error, :admission_closed}
        GenServer.reply(closing.from, reply)
        %{state | http_close: nil}

      _ ->
        state
    end
  end

  defp release_http_close(state), do: state

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

  def handle_call(
        {{:policy, capability, {:http_close_finish, generation, nonce}}, _},
        from,
        state
      ) do
    state = expire_http_close(state)
    {reply, policy} = finish_http_close(state.policy, capability, generation, nonce, from)
    next = %{state | policy: policy}

    case {reply, finish_retirement(next)} do
      {:deferred, transition} -> transition
      {result, {:noreply, next}} -> {:reply, result, next}
      {result, {:stop, reason, next}} -> {:stop, reason, result, next}
    end
  end

  def handle_call({{:policy, capability, operation}, _}, {caller, _}, state) do
    state = expire_http_close(state)
    {reply, policy} = operation(state.policy, capability, operation, caller)
    next = %{state | policy: policy}

    if policy.finished do
      _ = if state.timer, do: Process.cancel_timer(state.timer)
      {:stop, :normal, reply, next}
    else
      case finish_retirement(next) do
        {:stop, reason, next} -> {:stop, reason, reply, next}
        {:noreply, next} -> {:reply, reply, next}
      end
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

    finish_retirement(%{state | policy: policy})
  end

  def handle_info(:deadline, state) do
    policy = retire(state.policy, PolicyIO.now() + 1_000)
    Process.send_after(self(), :grace, 1_000)
    finish_retirement(%{state | policy: policy})
  end

  def handle_info({:timeout, timer, {:policy_http_close, nonce}}, state) do
    if http_close_timer?(state.policy, timer, nonce),
      do: finish_retirement(expire_http_close(state)),
      else: {:noreply, state}
  end

  def handle_info(:grace, state) do
    kill(state.policy)
    {:stop, :normal, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  defp finish_retirement(%{policy: %{retirement: grace}} = state) when is_integer(grace) do
    unless protects_connection?(state.policy, state.policy.connection),
      do: Process.exit(state.policy.connection, :kill)

    if settled?(state.policy) and
         (state.policy.http_close == nil or not Process.alive?(state.policy.connection)) do
      {:stop, :normal, state}
    else
      Process.send_after(self(), :grace, max(0, grace - PolicyIO.now()))
      {:noreply, state}
    end
  end

  defp finish_retirement(state), do: {:noreply, state}

  defp expire_http_close(state) do
    if http_close_expired?(state.policy, PolicyIO.now()) do
      %{state | policy: retire(state.policy, PolicyIO.now() + 1_000)}
    else
      state
    end
  end
end

defmodule SSL.Lifecycle.Observer do
  @moduledoc false
  use GenServer, restart: :temporary

  alias SSL.Lifecycle.{Authority, Handoff, ObserverSupervisor, Receipt, ResourceLedger}

  # Private cooperative provider protocol, not the public lifecycle API. Possession
  # of a permit delegates self-enrollment; it does not attest spawn ancestry.
  # No native allocation/close or synchronous child/supervisor calls occur here.
  @reservation_ms 30_000
  @grace_ms 1_000
  @call_ms 1_000
  @children %{allocator: [:tcp], setup: [:connection], connection: [:writer]}
  @process_roles [:allocator, :setup, :connection, :writer]
  @failures [:options, :connect, :tls, :timeout, :internal]

  @spec start(pid(), :infinity | {:abs_ms, integer()}, ResourceLedger.scope()) ::
          {:ok, Receipt.t(), Authority.lease()} | {:error, atom()}
  def start(controller, deadline, scope \\ :dial) do
    entered = now()

    with :ok <- validate(controller, deadline, scope) do
      expiry = min_deadline(entered + @call_ms, deadline)

      with {:ok, pid} <- SSL.Lifecycle.Bootstrap.start(controller, deadline, scope, expiry) do
        request(pid, :reservation, {:abs_ms, expiry})
      end
    end
  end

  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @spec bind(Receipt.t(), Authority.lease(), {:abs_ms, integer()}) :: :ok | {:error, atom()}
  def bind(receipt, lease, deadline), do: call(receipt, {:bind, lease}, deadline)

  @spec cancel(Receipt.t(), Authority.lease(), {:abs_ms, integer()}) :: :ok | {:error, atom()}
  def cancel(receipt, lease, deadline), do: call(receipt, {:cancel, lease}, deadline)

  @spec snapshot(Receipt.t(), {:abs_ms, integer()}) :: {:ok, map()} | {:error, atom()}
  def snapshot(receipt, deadline), do: call(receipt, :snapshot, deadline)

  # Record metadata before the existing failure path; this is not cleanup or Setup ACK.
  @spec record_tls_failure(Receipt.t(), {:abs_ms, integer()}) :: :ok | {:error, atom()}
  def record_tls_failure(receipt, {:abs_ms, publication}) when is_integer(publication) do
    entered = now()
    request_deadline = min(publication - 250, entered + 250)

    if entered < request_deadline,
      do:
        call(receipt, {:record_tls_failure, {:abs_ms, publication}}, {:abs_ms, request_deadline}),
      else: {:error, :deadline_exceeded}
  end

  def record_tls_failure(_, _), do: {:error, :invalid_deadline}

  @spec record_connect_failure(
          Receipt.t(),
          :econnrefused | :enetunreach | :ehostunreach,
          {:abs_ms, integer()}
        ) :: :ok | {:error, atom()}
  def record_connect_failure(receipt, reason, {:abs_ms, existing})
      when is_integer(existing) and reason in [:econnrefused, :enetunreach, :ehostunreach] do
    entered = now()
    requested = min(existing, entered + 250)

    if entered < requested,
      do:
        call(
          receipt,
          {:record_connect_failure, reason, {:abs_ms, existing}},
          {:abs_ms, requested}
        ),
      else: {:error, :deadline_exceeded}
  end

  def record_connect_failure(_, _, _), do: {:error, :invalid_connect_failure}

  @spec record_socket_connect_failure(
          Receipt.t(),
          :socket.socket(),
          :econnrefused | :enetunreach | :ehostunreach,
          {:abs_ms, integer()}
        ) :: :ok | {:error, atom()}
  def record_socket_connect_failure(receipt, socket, reason, {:abs_ms, existing})
      when is_integer(existing) and reason in [:econnrefused, :enetunreach, :ehostunreach] do
    entered = now()
    requested = min(existing, entered + 250)

    if entered < requested,
      do:
        call(
          receipt,
          {:record_socket_connect_failure, socket, reason, {:abs_ms, existing}},
          {:abs_ms, requested}
        ),
      else: {:error, :deadline_exceeded}
  end

  def record_socket_connect_failure(_, _, _, _), do: {:error, :invalid_connect_failure}

  @spec reserve_root(Receipt.t(), Authority.lease(), :allocator | :setup, {:abs_ms, integer()}) ::
          {:ok, reference()} | {:error, atom()}
  def reserve_root(receipt, lease, role, deadline),
    do: call(receipt, {:reserve_root, lease, role}, deadline)

  @spec reserve_child(Receipt.t(), ResourceLedger.role(), {:abs_ms, integer()}) ::
          {:ok, reference()} | {:error, atom()}
  def reserve_child(receipt, role, deadline), do: call(receipt, {:reserve_child, role}, deadline)

  @spec enroll_self(Receipt.t(), ResourceLedger.role(), reference(), {:abs_ms, integer()}) ::
          :use | :stop | {:error, atom()}
  def enroll_self(receipt, role, token, deadline),
    do: call(receipt, {:enroll, role, token, self()}, deadline)

  @spec enroll_port(Receipt.t(), reference(), port(), {:abs_ms, integer()}) ::
          :use | :stop | {:error, atom()}
  def enroll_port(receipt, token, port, deadline),
    do: call(receipt, {:enroll, :tcp, token, port}, deadline)

  @spec enroll_socket(Receipt.t(), reference(), :socket.socket(), {:abs_ms, integer()}) ::
          :use | :stop | {:error, atom()}
  def enroll_socket(receipt, token, socket, deadline),
    do: call(receipt, {:enroll_socket, token, socket}, deadline)

  # Only a trusted constructor that has permanently rejected BEFORE native entry
  # may call this. Ordinary native errors, timeouts and DOWN are not this proof.
  @spec reject_before_native(
          Receipt.t(),
          ResourceLedger.role(),
          reference(),
          {:abs_ms, integer()}
        ) ::
          :ok | {:error, atom()}
  def reject_before_native(receipt, role, token, deadline),
    do: call(receipt, {:reject_before_native, role, token}, deadline)

  # Private cooperative ownership protocol; no TLS readiness or native birth proof.
  @spec writer_ready(Receipt.t(), {:abs_ms, integer()}) :: {:ok, reference()} | {:error, atom()}
  def writer_ready(receipt, deadline), do: call(receipt, :writer_ready, deadline)

  @spec connection_ready(Receipt.t(), reference(), {:abs_ms, integer()}) :: :ok | {:error, atom()}
  def connection_ready(receipt, nonce, deadline),
    do: call(receipt, {:connection_ready, nonce}, deadline)

  @spec prepare_handoff(Receipt.t(), port(), pid(), {:abs_ms, integer()}) ::
          {:ok, reference()} | {:error, atom()}
  def prepare_handoff(receipt, port, connection, deadline),
    do: call(receipt, {:prepare_handoff, port, connection}, deadline)

  @spec prepare_handoff_bounded(Receipt.t(), port(), pid(), {:abs_ms, integer()}) ::
          {:ok, reference(), {:abs_ms, integer()}} | {:error, atom()}
  def prepare_handoff_bounded(receipt, port, connection, deadline),
    do: call(receipt, {:prepare_handoff_bounded, port, connection}, deadline)

  @spec commit_handoff(Receipt.t(), port(), pid(), reference(), {:abs_ms, integer()}) ::
          :ok | {:error, atom()}
  def commit_handoff(receipt, port, allocator, nonce, deadline),
    do: call(receipt, {:commit_handoff, port, allocator, nonce}, deadline)

  @spec commit_handoff(Receipt.t(), reference(), {:abs_ms, integer()}) :: :ok | {:error, atom()}
  def commit_handoff(receipt, nonce, deadline),
    do: call(receipt, {:commit_handoff, nonce}, deadline)

  @spec helper_done(Receipt.t(), {:abs_ms, integer()}) :: :ok | {:error, atom()}
  def helper_done(receipt, deadline), do: call(receipt, :helper_done, deadline)

  @spec publish_setup(Receipt.t(), :connected | {:failed, atom()}, {:abs_ms, integer()}) ::
          :ok | {:error, atom()}
  def publish_setup(receipt, result, deadline),
    do: call(receipt, {:publish_setup, result}, deadline)

  @impl true
  def init({controller, deadline, scope}) do
    monitor = Process.monitor(controller)
    authority = Authority.new(make_ref(), controller, monitor, make_ref())
    expires = min_deadline(now() + @reservation_ms, deadline)
    timer = schedule_deadline(expires)

    {:ok,
     %{
       receipt: Receipt.new(),
       authority: authority,
       controller: controller,
       controller_monitor: monitor,
       owner: nil,
       owner_monitor: nil,
       ledger: ResourceLedger.new(scope),
       permits: %{},
       resources: %{},
       handoff: Handoff.new(self()),
       handoff_timer: nil,
       setup: :not_started,
       failure: :none,
       deadline: deadline,
       scope: scope,
       expires: expires,
       timer: timer,
       grace: nil,
       grace_timer: nil
     }}
  end

  @impl true
  def handle_call({{:enroll_socket, token, socket}, {:abs_ms, deadline}}, from, state)
      when is_integer(deadline) do
    state = expire(state)

    if now() < deadline do
      {reply, next} = operate({:enroll_socket, token, socket, deadline}, elem(from, 0), state)
      settle(reply, next)
    else
      settle({:error, :deadline_exceeded}, state)
    end
  end

  def handle_call({{:enroll_socket, _, _}, _}, _from, state),
    do: settle({:error, :invalid_deadline}, expire(state))

  def handle_call({{:enroll_socket, _, _, _}, _}, _from, state),
    do: settle({:error, :invalid_deadline}, expire(state))

  def handle_call(
        {{:record_socket_connect_failure, socket, reason, {:abs_ms, existing}},
         {:abs_ms, deadline}},
        from,
        state
      )
      when is_integer(deadline) do
    state = expire(state)

    if now() < deadline do
      operation = {:record_socket_connect_failure, socket, reason, existing, deadline}
      {reply, next} = operate(operation, elem(from, 0), state)
      settle(reply, next)
    else
      settle({:error, :deadline_exceeded}, state)
    end
  end

  def handle_call({{:record_socket_connect_failure, _, _, _}, _}, _from, state),
    do: settle({:error, :invalid_connect_failure}, expire(state))

  def handle_call({{:record_socket_connect_failure, _, _, _, _}, _}, _from, state),
    do: settle({:error, :invalid_connect_failure}, expire(state))

  def handle_call({operation, {:abs_ms, deadline}}, from, state) do
    state = expire(state)

    if now() < deadline do
      operation =
        case operation do
          {:cancel, lease} ->
            {:cancel, lease, deadline}

          :writer_ready ->
            {:writer_ready, {:abs_ms, deadline}}

          {:connection_ready, nonce} ->
            {:connection_ready, nonce, {:abs_ms, deadline}}

          {:prepare_handoff, port, connection} ->
            {:prepare_handoff, port, connection, {:abs_ms, deadline}}

          {:prepare_handoff_bounded, port, connection} ->
            {:prepare_handoff_bounded, port, connection, {:abs_ms, deadline}}

          {:commit_handoff, port, allocator, nonce} ->
            {:commit_handoff, port, allocator, nonce, {:abs_ms, deadline}}

          {:commit_handoff, nonce} ->
            {:commit_handoff, nonce, {:abs_ms, deadline}}

          {:record_tls_failure, {:abs_ms, publication}} ->
            {:record_tls_failure, publication, deadline}

          {:record_connect_failure, reason, {:abs_ms, existing}} ->
            {:record_connect_failure, reason, existing, deadline}

          other ->
            other
        end

      {reply, next} = operate(operation, elem(from, 0), state)
      settle(reply, next)
    else
      settle({:error, :deadline_exceeded}, state)
    end
  end

  @impl true
  def handle_info({:DOWN, ref, type, object, _reason} = event, state) do
    state = expire(state)
    next = record_down(state, {ref, type, object}, event)
    settle_info(next)
  end

  def handle_info({:timeout, ref, :deadline}, %{timer: ref} = state) do
    next = expire(state)

    if next.grace == nil do
      {:noreply, %{next | timer: schedule_deadline(next.expires)}}
    else
      settle_info(next)
    end
  end

  def handle_info({:timeout, ref, :handoff}, %{handoff_timer: ref} = state)
      when is_reference(ref) do
    next = expire(state)

    if next.grace == nil and Handoff.pending?(next.handoff) do
      {:noreply, %{next | handoff_timer: schedule_handoff(Handoff.deadline(next.handoff))}}
    else
      settle_info(next)
    end
  end

  def handle_info({:timeout, ref, :grace}, %{grace_timer: ref} = state), do: settle_info(state)
  def handle_info(_message, state), do: {:noreply, state}

  defp operate(:reservation, _caller, state),
    do: {{:ok, state.receipt, Authority.lease(state.authority)}, state}

  defp operate(:snapshot, _caller, state) do
    authority =
      Map.take(Authority.snapshot(state.authority, now()), [:epoch, :phase, :bound?, :transfer])

    snapshot = Map.merge(ResourceLedger.snapshot(state.ledger), authority)
    {{:ok, Map.merge(snapshot, %{setup: state.setup, setup_failure: state.failure})}, state}
  end

  defp operate({:bind, lease}, caller, state) do
    case Authority.bind(state.authority, lease, caller) do
      {:ok, authority} ->
        _ = Process.cancel_timer(state.timer)
        expires = min_deadline(:infinity, state.deadline)
        timer = schedule_deadline(expires)

        {:ok,
         %{
           state
           | authority: authority,
             owner: caller,
             owner_monitor: Process.monitor(caller),
             setup: :pending,
             expires: expires,
             timer: timer
         }}

      {:error, reason} ->
        {{:error, reason}, state}
    end
  end

  defp operate({:cancel, lease, deadline}, _caller, state) do
    case Authority.cancel(state.authority, lease, now(), deadline) do
      {:ok, authority} -> {:ok, retire(%{state | authority: authority}, :cancelled)}
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:reserve_root, lease, role}, caller, state) do
    if caller == state.owner and lease === Authority.lease(state.authority) and
         role in [:allocator, :setup],
       do: reserve(state, role, :observer, caller),
       else: {{:error, :unauthorized_creator}, state}
  end

  defp operate({:reserve_child, role}, caller, state) do
    case creator(state, caller) do
      {parent, %{identity: {ref, :process, ^caller}, done: false}} ->
        if role in Map.get(@children, parent, []),
          do: reserve(state, role, {parent, ref}, caller),
          else: {{:error, :invalid_role_edge}, state}

      _ ->
        {{:error, :unauthorized_creator}, state}
    end
  end

  defp operate({:enroll, role, token, object}, caller, state) do
    with {:ok, permit} <- permit(state, role, token),
         :ok <- enrollment(state, role, permit, caller, object) do
      type = if role == :tcp, do: :port, else: :process
      ref = :erlang.monitor(type, object)

      case ResourceLedger.enroll(state.ledger, role, token, {ref, type, object}) do
        {:ok, ledger, action} ->
          resource = %{
            identity: {ref, type, object},
            live: true,
            done: false,
            creator: permit.parent,
            creator_pid: permit.creator,
            creator_monitor: permit.creator_monitor
          }

          next = %{
            state
            | ledger: ledger,
              permits: Map.delete(state.permits, role),
              resources: Map.put(state.resources, role, resource)
          }

          if action == :stop, do: stop_process(resource)
          {action, next}

        {:error, reason} ->
          Process.demonitor(ref, [:flush])
          {{:error, reason}, state}
      end
    else
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:enroll_socket, token, socket, deadline}, caller, state)
       when is_integer(deadline) do
    with {:ok, permit} <- permit(state, :tcp, token),
         :ok <- socket_creator(state, permit, caller),
         :ok <- socket_candidate(state, socket, caller),
         {:ok, ref} <- monitor_socket(socket) do
      # Once the real monitor exists, retain accounting even if authorization expired.
      next = socket_authorization(state, socket, caller, deadline)
      enroll_socket_identity(next, permit, token, socket, ref, deadline)
    else
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:enroll_socket, _, _, _}, _caller, state),
    do: {{:error, :invalid_deadline}, state}

  defp operate({:reject_before_native, role, token}, caller, state) do
    with {:ok, permit} <- permit(state, role, token),
         :ok <- constructor_creator(state, permit, caller),
         {:ok, ledger} <-
           ResourceLedger.reject_before_native(state.ledger, role, token, permit.parent) do
      {:ok, %{state | ledger: ledger, permits: Map.delete(state.permits, role)}}
    else
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:writer_ready, {:abs_ms, deadline}}, caller, state) do
    nonce = make_ref()

    with {:ok, context} <-
           handoff_context(state, caller, :writer, [:setup, :connection, :writer], deadline),
         {:ok, handoff} <- Handoff.writer_ready(state.handoff, %{context | now: now()}, nonce) do
      {{:ok, nonce}, update_handoff(state, handoff)}
    else
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:connection_ready, nonce, {:abs_ms, deadline}}, caller, state) do
    with {:ok, context} <-
           handoff_context(state, caller, :connection, [:setup, :connection, :writer], deadline),
         {:ok, handoff} <- Handoff.connection_ready(state.handoff, %{context | now: now()}, nonce) do
      {:ok, update_handoff(state, handoff)}
    else
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:prepare_handoff, port, connection, {:abs_ms, deadline}}, caller, state) do
    nonce = make_ref()

    with {:ok, context} <-
           handoff_context(state, caller, :allocator, @process_roles ++ [:tcp], deadline),
         true <-
           elem(context.identities.tcp, 2) == port and
             elem(context.identities.connection, 2) == connection,
         :ok <- handoff_owner(context, :allocator),
         {:ok, handoff} <- Handoff.prepare(state.handoff, %{context | now: now()}, nonce) do
      {{:ok, nonce}, update_handoff(state, handoff)}
    else
      false -> {{:error, :foreign_handoff_resource}, state}
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:prepare_handoff_bounded, port, connection, {:abs_ms, deadline}}, caller, state) do
    case operate({:prepare_handoff, port, connection, {:abs_ms, deadline}}, caller, state) do
      {{:ok, grant}, next} ->
        {{:ok, grant, {:abs_ms, min(deadline, Handoff.deadline(next.handoff))}}, next}

      {{:error, _reason}, _next} = error ->
        error
    end
  end

  defp operate({:commit_handoff, port, allocator, nonce, {:abs_ms, deadline}}, caller, state) do
    with {:ok, context} <-
           handoff_context(state, caller, :connection, @process_roles ++ [:tcp], deadline),
         true <-
           elem(context.identities.tcp, 2) == port and
             elem(context.identities.allocator, 2) == allocator,
         :ok <- handoff_owner(context, :connection),
         {:ok, handoff} <- Handoff.commit(state.handoff, %{context | now: now()}, nonce) do
      {:ok, update_handoff(state, handoff)}
    else
      false -> {{:error, :foreign_handoff_resource}, state}
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate({:commit_handoff, nonce, {:abs_ms, deadline}}, caller, state) do
    with {:ok, context} <-
           handoff_context(state, caller, :connection, @process_roles ++ [:tcp], deadline),
         :ok <- handoff_owner(context, :connection),
         {:ok, handoff} <- Handoff.commit(state.handoff, %{context | now: now()}, nonce) do
      {:ok, update_handoff(state, handoff)}
    else
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp operate(:helper_done, caller, state) do
    case creator(state, caller) do
      {:setup, _resource} when state.setup == :pending ->
        {{:error, :setup_outcome_pending}, state}

      {role, resource} when role in [:allocator, :setup] ->
        cond do
          Handoff.pending?(state.handoff) ->
            {{:error, :handoff_pending}, state}

          Enum.any?(state.permits, fn {_, permit} -> permit.creator == caller end) ->
            {{:error, :allocations_pending}, state}

          true ->
            {:ok, %{state | resources: Map.put(state.resources, role, %{resource | done: true})}}
        end

      _ ->
        {{:error, :unauthorized_creator}, state}
    end
  end

  defp operate({:record_tls_failure, publication, requested}, caller, state)
       when is_integer(publication) and is_integer(requested) do
    with true <- failure_window?(publication, requested),
         :ok <- failure_caller(state, caller),
         entered = now(),
         true <-
           entered < requested and entered < publication and
             (state.expires == :infinity or entered < state.expires),
         {:ok, authority} <-
           Authority.cancel(state.authority, Authority.lease(state.authority), entered, requested) do
      {:ok, record_failure(state, authority, min(publication, entered + 1_000))}
    else
      _ -> {{:error, :unauthorized_tls_failure}, state}
    end
  end

  defp operate({:record_tls_failure, _publication, _requested}, _caller, state),
    do: {{:error, :invalid_deadline}, state}

  defp operate({:record_connect_failure, reason, existing, requested}, caller, state)
       when is_integer(existing) and is_integer(requested) and
              reason in [:econnrefused, :enetunreach, :ehostunreach] do
    with true <- connect_window?(existing, requested),
         :ok <- connect_caller(state, caller),
         entered = now(),
         true <-
           entered < requested and entered < existing and
             (state.expires == :infinity or entered < state.expires),
         {:ok, authority} <-
           Authority.cancel(state.authority, Authority.lease(state.authority), entered, requested) do
      {:ok, record_connect_outcome(state, authority, min(existing, entered + 1_000))}
    else
      _ -> {{:error, :unauthorized_connect_failure}, state}
    end
  end

  defp operate({:record_connect_failure, _reason, _existing, _requested}, _caller, state),
    do: {{:error, :invalid_connect_failure}, state}

  defp operate(
         {:record_socket_connect_failure, socket, reason, existing, requested},
         caller,
         state
       )
       when is_integer(existing) and is_integer(requested) and
              reason in [:econnrefused, :enetunreach, :ehostunreach] do
    with true <- connect_window?(existing, requested),
         :ok <- socket_connect_caller(state, caller, socket, existing),
         entered = now(),
         true <-
           entered < requested and entered < existing and
             (state.expires == :infinity or entered < state.expires),
         {:ok, authority} <-
           Authority.cancel(state.authority, Authority.lease(state.authority), entered, requested) do
      {:ok, record_connect_outcome(state, authority, min(existing, entered + 1_000))}
    else
      _ -> {{:error, :unauthorized_connect_failure}, state}
    end
  end

  defp operate({:record_socket_connect_failure, _, _, _, _}, _caller, state),
    do: {{:error, :invalid_connect_failure}, state}

  defp operate({:publish_setup, result}, caller, state) do
    if state.setup == :pending and open?(state) and match?({:setup, _}, creator(state, caller)),
      do: publish(state, result),
      else: {{:error, :setup_not_permitted}, state}
  end

  defp connect_window?(existing, requested) do
    instant = now()
    instant < requested and requested <= existing and requested <= instant + 250
  end

  defp connect_caller(state, caller) do
    with true <- state.scope == :dial and state.setup == :pending and open?(state),
         true <- handoff_process_live?(state.owner) and handoff_process_live?(state.controller),
         {:ok, {monitor, :process, ^caller}} <- handoff_resource(state, :allocator),
         :ok <- connect_permit(state, caller, monitor) do
      :ok
    else
      _ -> {:error, :unauthorized_connect_failure}
    end
  end

  defp connect_permit(state, caller, monitor) do
    with %{
           token: token,
           creator: ^caller,
           parent: {:allocator, ^monitor},
           creator_monitor: ^monitor
         } <- Map.get(state.permits, :tcp),
         true <- is_reference(token),
         :error <- Map.fetch(state.resources, :tcp),
         :error <- ResourceLedger.enrollment_view(state.ledger, :tcp) do
      :ok
    else
      _ -> {:error, :unknown_tcp_allocation}
    end
  end

  defp socket_connect_caller(state, caller, socket, existing) do
    with true <- state.scope == :dial and state.setup == :pending and open?(state),
         true <- handoff_process_live?(state.owner) and handoff_process_live?(state.controller),
         {:ok, {allocator_ref, :process, ^caller}} <- handoff_resource(state, :allocator),
         %{
           live: true,
           done: false,
           identity: {_socket_ref, :socket, ^socket} = identity,
           creator: {:allocator, ^allocator_ref},
           creator_pid: ^caller,
           creator_monitor: ^allocator_ref,
           allocation_deadline: original
         } <-
           Map.get(state.resources, :tcp),
         {:ok, %{state: :live, identity: ^identity, creator: {:allocator, ^allocator_ref}}} <-
           ResourceLedger.enrollment_view(state.ledger, :tcp),
         true <- is_integer(original) and existing <= original,
         false <- Handoff.committed?(state.handoff),
         false <- Handoff.involves?(state.handoff, identity),
         true <- socket_owned?(socket, caller),
         true <-
           handoff_process_live?(caller) and handoff_process_live?(state.owner) and
             handoff_process_live?(state.controller) do
      :ok
    else
      _ -> {:error, :unauthorized_connect_failure}
    end
  end

  defp record_connect_outcome(state, authority, completion) do
    expiry = if state.expires == :infinity, do: completion, else: min(state.expires, completion)

    _ =
      if is_reference(state.timer),
        do: Process.cancel_timer(state.timer, async: false, info: false)

    %{
      state
      | authority: authority,
        ledger: ResourceLedger.close_admission(state.ledger),
        setup: :failed,
        failure: :connect,
        expires: expiry,
        timer: schedule_deadline(expiry)
    }
  end

  defp failure_window?(publication, requested) do
    instant = now()
    instant < requested and requested <= instant + 250 and requested <= publication - 250
  end

  defp failure_caller(state, caller) do
    with true <- state.scope == :dial and state.setup == :pending and open?(state),
         true <- Handoff.committed?(state.handoff),
         true <- handoff_process_live?(state.owner) and handoff_process_live?(state.controller),
         {:ok, _setup} <- handoff_resource(state, :setup),
         {:ok, {_ref, :process, ^caller}} <- handoff_resource(state, :connection),
         {:ok, _writer} <- handoff_resource(state, :writer),
         :ok <- failure_tcp(state, caller) do
      :ok
    else
      _ -> {:error, :unauthorized_tls_failure}
    end
  end

  defp failure_tcp(state, caller) do
    with %{
           live: true,
           done: false,
           identity: {_monitor, :port, port} = identity,
           creator: {:allocator, allocation} = creator,
           creator_pid: allocator,
           creator_monitor: creator_monitor
         } <- Map.get(state.resources, :tcp),
         true <- allocation == creator_monitor,
         {:ok, %{state: :live, identity: ^identity, creator: ^creator}} <-
           ResourceLedger.enrollment_view(state.ledger, :tcp),
         :ok <- failure_allocator(state, allocation, allocator),
         true <- Port.info(port, :connected) == {:connected, caller} do
      :ok
    else
      _ -> {:error, :foreign_tls_resource}
    end
  end

  # Committed ownership retains the allocator generation after its normal done-DOWN.
  defp failure_allocator(state, monitor, pid) do
    with %{identity: {^monitor, :process, ^pid} = identity, creator: :observer} = resource <-
           Map.get(state.resources, :allocator),
         true <- handoff_parent_live?(state, :allocator, resource),
         {:ok, %{identity: ^identity, creator: :observer} = view} <-
           ResourceLedger.enrollment_view(state.ledger, :allocator),
         true <- failure_allocator_live?(resource, view, pid) do
      :ok
    else
      _ -> {:error, :foreign_tls_creator}
    end
  end

  defp failure_allocator_live?(%{done: true}, _view, _pid), do: true

  defp failure_allocator_live?(%{live: true}, %{state: :live}, pid),
    do: handoff_process_live?(pid)

  defp failure_allocator_live?(_resource, _view, _pid), do: false

  defp record_failure(state, authority, publication) do
    expiry = if state.expires == :infinity, do: publication, else: min(state.expires, publication)

    _ =
      if is_reference(state.timer),
        do: Process.cancel_timer(state.timer, async: false, info: false)

    %{
      state
      | authority: authority,
        ledger: ResourceLedger.close_admission(state.ledger),
        setup: :failed,
        failure: :tls,
        expires: expiry,
        timer: schedule_deadline(expiry)
    }
  end

  defp handoff_context(state, caller, role, roles, deadline) do
    with true <- state.scope == :dial and open?(state),
         true <- handoff_process_live?(state.owner) and handoff_process_live?(state.controller),
         {:ok, identities} <- handoff_resources(state, roles),
         true <- elem(Map.fetch!(identities, role), 2) == caller do
      identities =
        Map.merge(identities, %{
          owner: {state.owner_monitor, :process, state.owner},
          controller: {state.controller_monitor, :process, state.controller}
        })

      {:ok, %{observer: self(), identities: identities, deadline: deadline, now: now()}}
    else
      false -> {:error, :unauthorized_handoff_caller}
      {:error, reason} -> {:error, reason}
    end
  end

  defp handoff_resources(state, roles) do
    Enum.reduce_while(roles, {:ok, %{}}, fn role, {:ok, identities} ->
      case handoff_resource(state, role) do
        {:ok, identity} -> {:cont, {:ok, Map.put(identities, role, identity)}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp handoff_resource(state, role) do
    with %{live: true, done: false, identity: identity, creator: creator} = resource <-
           Map.get(state.resources, role),
         {:ok, %{state: :live, identity: ^identity, creator: ^creator}} <-
           ResourceLedger.enrollment_view(state.ledger, role),
         true <- handoff_identity_live?(identity),
         true <- handoff_parent_live?(state, role, resource) do
      {:ok, identity}
    else
      _ -> {:error, :handoff_resources_pending}
    end
  end

  defp handoff_parent_live?(state, role, %{creator: :observer} = resource)
       when role in [:allocator, :setup] do
    resource.creator_pid == state.owner and resource.creator_monitor == state.owner_monitor
  end

  defp handoff_parent_live?(state, role, %{creator: {parent, ref}} = resource) do
    expected = %{connection: :setup, writer: :connection, tcp: :allocator}

    case Map.get(state.resources, parent) do
      %{live: true, done: false, identity: {^ref, :process, pid}} ->
        Map.get(expected, role) == parent and resource.creator_pid == pid and
          resource.creator_monitor == ref and handoff_process_live?(pid)

      _ ->
        false
    end
  end

  defp handoff_parent_live?(_state, _role, _resource), do: false

  defp handoff_process_live?(pid),
    do: is_pid(pid) and node(pid) == node() and Process.alive?(pid)

  defp handoff_identity_live?({_ref, :process, pid}), do: handoff_process_live?(pid)
  defp handoff_identity_live?({_ref, :port, port}), do: Port.info(port) != nil
  defp handoff_identity_live?({_ref, :socket, _socket}), do: false

  defp handoff_owner(%{identities: %{tcp: {_ref, :port, _port}}} = context, role) do
    port = elem(context.identities.tcp, 2)
    owner = elem(Map.fetch!(context.identities, role), 2)

    if Port.info(port, :connected) == {:connected, owner},
      do: :ok,
      else: {:error, :port_not_owned}
  end

  defp handoff_owner(_context, _role), do: {:error, :port_not_owned}

  defp update_handoff(state, handoff) do
    timer =
      cond do
        not Handoff.pending?(handoff) ->
          _ = if state.handoff_timer, do: Process.cancel_timer(state.handoff_timer)
          nil

        state.handoff_timer != nil ->
          state.handoff_timer

        true ->
          schedule_handoff(Handoff.deadline(handoff))
      end

    %{state | handoff: handoff, handoff_timer: timer}
  end

  defp schedule_handoff(deadline),
    do: :erlang.start_timer(min(max(0, deadline - now()), 0xFFFFFFFF), self(), :handoff)

  defp reserve(%{scope: :upgrade} = state, :tcp, _creator, _caller),
    do: {{:error, :adoption_not_implemented}, state}

  defp reserve(state, role, creator, caller) do
    token = make_ref()

    with true <- open?(state),
         {:ok, ledger} <- ResourceLedger.reserve(state.ledger, role, creator, token) do
      ref = if creator == :observer, do: state.owner_monitor, else: elem(creator, 1)
      permit = %{token: token, creator: caller, parent: creator, creator_monitor: ref}
      {{:ok, token}, %{state | ledger: ledger, permits: Map.put(state.permits, role, permit)}}
    else
      false -> {{:error, :admission_closed}, state}
      {:error, reason} -> {{:error, reason}, state}
    end
  end

  defp permit(state, role, token) do
    case Map.get(state.permits, role) do
      %{token: ^token} = permit -> {:ok, permit}
      _ -> {:error, :unknown_permit}
    end
  end

  defp constructor_creator(
         state,
         %{creator: expected, parent: :observer, creator_monitor: ref},
         caller
       )
       when caller == expected do
    if caller == state.owner and ref == state.owner_monitor and Process.alive?(caller),
      do: :ok,
      else: {:error, :unauthorized_creator}
  end

  defp constructor_creator(
         state,
         %{creator: expected, parent: {parent, ref}, creator_monitor: monitor},
         caller
       )
       when caller == expected and ref == monitor do
    case creator(state, caller) do
      {^parent, %{identity: {^ref, :process, ^caller}, done: false}} ->
        if Process.alive?(caller), do: :ok, else: {:error, :unauthorized_creator}

      _ ->
        {:error, :unauthorized_creator}
    end
  end

  defp constructor_creator(_state, _permit, _caller), do: {:error, :unauthorized_creator}

  defp socket_creator(state, %{parent: {:allocator, ref}, creator_monitor: ref} = permit, caller) do
    with true <- state.scope == :dial,
         :ok <- constructor_creator(state, permit, caller),
         {:ok, {^ref, :process, ^caller}} <- handoff_resource(state, :allocator) do
      :ok
    else
      _ -> {:error, :unauthorized_creator}
    end
  end

  defp socket_creator(_state, _permit, _caller), do: {:error, :unauthorized_creator}

  defp socket_candidate(state, socket, caller) do
    with false <- duplicate?(state, socket),
         {:ok, ^caller} <- :socket.getopt(socket, :otp, :controlling_process),
         %{type: :stream, protocol: :tcp, domain: domain} <- :socket.info(socket),
         true <- domain in [:inet, :inet6] do
      :ok
    else
      _ -> {:error, :foreign_or_duplicate_resource}
    end
  catch
    _, _ -> {:error, :invalid_resource}
  end

  defp monitor_socket(socket) do
    {:ok, :socket.monitor(socket)}
  catch
    _, _ -> {:error, :monitor_unavailable}
  end

  defp socket_authorization(state, socket, caller, deadline) do
    owned = socket_owned?(socket, caller)
    state = expire(state)

    eligible =
      owned and open?(state) and ResourceLedger.snapshot(state.ledger).admission == :open and
        handoff_process_live?(caller) and handoff_process_live?(state.owner) and
        handoff_process_live?(state.controller)

    instant = now()

    if eligible and instant < deadline and
         (state.expires == :infinity or instant < state.expires),
       do: state,
       else: retire(state, :internal)
  end

  defp socket_owned?(socket, caller) do
    :socket.getopt(socket, :otp, :controlling_process) == {:ok, caller}
  catch
    _, _ -> false
  end

  defp enroll_socket_identity(state, permit, token, socket, ref, deadline) do
    case ResourceLedger.enroll(state.ledger, :tcp, token, {ref, :socket, socket}) do
      {:ok, ledger, action} ->
        resource = %{
          identity: {ref, :socket, socket},
          live: true,
          done: false,
          creator: permit.parent,
          creator_pid: permit.creator,
          creator_monitor: permit.creator_monitor,
          allocation_deadline: deadline
        }

        next = %{
          state
          | ledger: ledger,
            permits: Map.delete(state.permits, :tcp),
            resources: Map.put(state.resources, :tcp, resource)
        }

        {action, next}

      {:error, reason} ->
        _ = cancel_socket_monitor(ref)
        {{:error, reason}, state}
    end
  end

  defp cancel_socket_monitor(ref) do
    :socket.cancel_monitor(ref)
  catch
    _, _ -> :ok
  end

  defp enrollment(state, :tcp, permit, caller, port) when is_port(port) do
    if caller == permit.creator and Port.info(port, :connected) == {:connected, caller} and
         not duplicate?(state, port), do: :ok, else: {:error, :foreign_or_duplicate_resource}
  end

  defp enrollment(state, role, _permit, caller, object) when role in @process_roles do
    if object == caller and node(caller) == node() and not prohibited?(state, caller) and
         not duplicate?(state, caller), do: :ok, else: {:error, :foreign_or_duplicate_resource}
  end

  defp enrollment(_, _, _, _, _), do: {:error, :invalid_resource}

  defp prohibited?(state, pid) do
    pid in [self(), state.controller, state.owner] or
      Enum.any?(
        [SSL.Supervisor, SSL.ConnectionSupervisor, ObserverSupervisor, SSL.TicketCache],
        fn name -> Process.whereis(name) == pid end
      )
  end

  defp duplicate?(state, object),
    do: Enum.any?(state.resources, fn {_, resource} -> elem(resource.identity, 2) == object end)

  defp creator(state, pid),
    do:
      Enum.find(state.resources, fn {_, resource} ->
        resource.live and elem(resource.identity, 2) == pid
      end)

  defp authority_view(state), do: Authority.snapshot(state.authority, now())

  defp open?(state),
    do: match?(%{bound?: true, phase: :open}, authority_view(state)) and state.grace == nil

  defp publish(%{resources: %{tcp: %{identity: {_ref, :socket, _socket}}}} = state, :connected),
    do: {{:error, :socket_transport_not_implemented}, state}

  defp publish(state, :connected) do
    if Enum.all?([:connection, :writer, :tcp], fn role ->
         match?(%{live: true}, Map.get(state.resources, role))
       end) do
      _ = if state.timer, do: Process.cancel_timer(state.timer)
      {:ok, %{state | setup: :connected, failure: :none, expires: :infinity, timer: nil}}
    else
      {{:error, :resources_pending}, state}
    end
  end

  defp publish(state, {:failed, failure}) when failure in @failures,
    do: {:ok, retire(%{state | setup: :failed, failure: failure}, :internal)}

  defp publish(state, _), do: {{:error, :invalid_outcome}, state}

  defp record_down(state, identity, event) do
    cond do
      identity == {state.controller_monitor, :process, state.controller} ->
        retire(state, :owner_down)

      identity == {state.owner_monitor, :process, state.owner} ->
        retire(state, :owner_down)

      true ->
        resource_down(state, identity, event)
    end
  end

  defp resource_down(state, identity, event) do
    case Enum.find(state.resources, fn {_, resource} ->
           resource.identity == identity and resource.live
         end) do
      nil ->
        state

      {role, resource} ->
        next = %{
          state
          | ledger: ResourceLedger.down(state.ledger, event),
            resources: Map.put(state.resources, role, %{resource | live: false})
        }

        if role in [:allocator, :setup] and resource.done and
             not Handoff.involves?(state.handoff, identity),
           do: next,
           else: retire(next, :internal)
    end
  end

  defp expire(%{grace: nil} = state) do
    instant = now()

    if (is_integer(state.expires) and instant >= state.expires) or
         Handoff.expired?(state.handoff, instant), do: retire(state, :timeout), else: state
  end

  defp expire(state), do: state

  defp retire(%{grace: nil} = state, reason) do
    state = update_handoff(state, Handoff.invalidate(state.handoff))
    instant = now()

    {:ok, authority} =
      Authority.cancel(state.authority, Authority.lease(state.authority), instant, instant + 1)

    ledger = ResourceLedger.close_admission(state.ledger)
    grace = now() + @grace_ms
    grace_timer = :erlang.start_timer(@grace_ms, self(), :grace)
    next = %{state | authority: authority, ledger: ledger, grace: grace, grace_timer: grace_timer}
    Enum.each(next.resources, fn {_, resource} -> stop_process(resource) end)
    outcome(next, reason)
  end

  defp retire(state, _reason), do: state

  defp outcome(%{setup: setup} = state, _reason) when setup in [:connected, :failed], do: state

  defp outcome(state, reason) when reason in [:cancelled, :timeout, :owner_down],
    do: %{state | setup: :cancelled, failure: reason}

  defp outcome(state, _reason), do: %{state | setup: :failed, failure: :internal}

  defp stop_process(%{identity: {_, :process, pid}, live: true}), do: Process.exit(pid, :kill)
  # Its enrolled provider creator/owner exits independently. Never block this
  # observer in native close or infer port DOWN from the owner's death.
  defp stop_process(_resource), do: :ok

  defp settle(reply, state) do
    case terminal(state) do
      :stop -> {:stop, :normal, reply, state}
      :pending -> {:reply, reply, state}
    end
  end

  defp settle_info(state) do
    case terminal(state) do
      :stop -> {:stop, :normal, state}
      :pending -> {:noreply, state}
    end
  end

  defp terminal(%{grace: nil}), do: :pending

  defp terminal(state) do
    case ResourceLedger.proof(state.ledger) do
      {:ok, _} ->
        :ok =
          Receipt.seal(state.receipt, state.ledger, %{
            setup: state.setup,
            failure: state.failure,
            epoch: authority_view(state).epoch
          })

        :stop

      {:pending, _} ->
        if now() >= state.grace, do: :stop, else: :pending
    end
  end

  defp call(receipt, operation, deadline),
    do: request(Receipt.observer(receipt), operation, deadline)

  defp request(pid, operation, {:abs_ms, deadline}) when is_integer(deadline) do
    remaining = deadline - now()

    if remaining > 0,
      do: GenServer.call(pid, {operation, {:abs_ms, deadline}}, min(remaining, @call_ms)),
      else: {:error, :deadline_exceeded}
  catch
    :exit, _ -> {:error, :acceptance_unconfirmed}
  end

  defp request(_, _, _), do: {:error, :invalid_deadline}

  defp validate(controller, deadline, scope) do
    cond do
      not is_pid(controller) ->
        {:error, :invalid_controller}

      node(controller) != node() ->
        {:error, :invalid_controller}

      scope not in [:dial, :upgrade] ->
        {:error, :invalid_scope}

      deadline == :infinity ->
        :ok

      match?({:abs_ms, value} when is_integer(value), deadline) ->
        if elem(deadline, 1) > now(), do: :ok, else: {:error, :deadline_exceeded}

      true ->
        {:error, :invalid_deadline}
    end
  end

  defp min_deadline(value, :infinity), do: value
  defp min_deadline(:infinity, {:abs_ms, value}), do: value
  defp min_deadline(value, {:abs_ms, deadline}), do: min(value, deadline)
  defp schedule_deadline(:infinity), do: nil

  defp schedule_deadline(deadline),
    do: :erlang.start_timer(min(max(0, deadline - now()), 0xFFFFFFFF), self(), :deadline)

  defp now, do: System.monotonic_time(:millisecond)
end

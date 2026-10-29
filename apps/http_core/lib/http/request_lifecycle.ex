defmodule HTTP.RequestLifecycle do
  @moduledoc false
  use GenServer

  # The latch outlives the coordinator. No request process owns the evidence.
  @spec start(:request | :client) :: {pid(), :atomics.atomics_ref()}
  def start(mode \\ :request) when mode in [:request, :client] do
    latch = :atomics.new(1, [])
    :atomics.put(latch, 1, 1)
    {:ok, pid} = GenServer.start(__MODULE__, {self(), latch, mode})
    {pid, latch}
  end

  def launch(tracker, fun) do
    fun.()
  catch
    kind, reason ->
      if tracker, do: send(tracker, :launch_failed)
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  def current, do: Process.get(__MODULE__)

  # Admission retains a creation permit before the caller allocates a child.
  # Unknown permits count against the fixed client bound for their lifetime.
  def reserve_attempt(tracker, deadline),
    do: client_call(tracker, {:reserve_attempt, make_ref(), deadline}, deadline)

  def retain_attempt(tracker, permit, receipt, deadline) do
    {child, latch} = HTTP.ClientCompletion.retention(receipt)
    client_call(tracker, {:retain_attempt, permit, child, latch, deadline}, deadline)
  end

  defp client_call(tracker, message, deadline) do
    # Even expired publication is enqueued: a known child must remain retained.
    GenServer.call(tracker, message, remaining(deadline))
  catch
    :exit, {:timeout, _} -> {:error, :request_timeout}
    :exit, _ -> {:error, :cleanup_unconfirmed}
  end

  def retire_owner(nil), do: :ok
  def retire_owner(tracker), do: GenServer.cast(tracker, {:retire_owner, self()})

  # Supervised workers are inert until the actual PID has been retained. Losing
  # admission or the creator never permits connect/send effects.
  def start_worker(tracker, kind, deadline, fun, on_rejected \\ nil) do
    creator = self()
    deadline = if deadline == :infinity, do: now() + 1_000, else: deadline
    launch = make_ref()

    case Task.Supervisor.start_child(:http_runtime_task_supervisor, fn ->
           run_worker(tracker, creator, deadline, launch, fun, on_rejected)
         end) do
      {:ok, worker} when is_function(on_rejected, 1) ->
        # Enqueue from the creator before returning, so its later retirement
        # cannot overtake the known worker obligation. Only the tracker launches.
        GenServer.cast(tracker, {:admit_worker, worker, kind, deadline, creator, launch})
        {:ok, worker}

      {:ok, worker} ->
        admission =
          if tracker,
            do: deadline_call(tracker, {:register_worker, worker, kind, deadline}, deadline),
            else: :ok

        case admission do
          :ok ->
            if remaining(deadline) > 0 and Process.alive?(creator) do
              send(worker, {:launch, launch})
              {:ok, worker}
            else
              send(worker, :abort)
              {:error, :request_timeout}
            end

          error ->
            send(worker, :abort)
            error
        end

      error ->
        error
    end
  end

  defp run_worker(tracker, creator, deadline, launch, fun, on_rejected) do
    monitor = Process.monitor(creator)
    tracker_monitor = if tracker, do: Process.monitor(tracker)

    admission =
      receive do
        {:launch, ^launch} -> :ok
        {:rejected, ^launch, reason} -> {:error, reason}
        {:DOWN, ^monitor, :process, ^creator, _} -> {:error, :aborted}
        {:DOWN, ^tracker_monitor, :process, ^tracker, _} -> {:error, :cleanup_unconfirmed}
        :abort -> {:error, :aborted}
      after
        remaining(deadline) -> {:error, :request_timeout}
      end

    Process.demonitor(monitor, [:flush])
    if tracker_monitor, do: Process.demonitor(tracker_monitor, [:flush])
    Process.put(__MODULE__, tracker)

    result =
      cond do
        admission != :ok ->
          reject_worker(on_rejected, admission)

        remaining(deadline) == 0 ->
          reject_worker(on_rejected, {:error, :request_timeout})

        not Process.alive?(creator) ->
          reject_worker(on_rejected, {:error, :aborted})

        tracker && not Process.alive?(tracker) ->
          reject_worker(on_rejected, {:error, :cleanup_unconfirmed})

        true ->
          fun.()
      end

    complete(tracker, deadline)
    result
  end

  defp reject_worker(nil, _error), do: :ok
  defp reject_worker(on_rejected, {:error, reason}), do: on_rejected.(reason)

  # Expected local cancellation is recorded before stopping an inert/opening or
  # write worker. The provider obligation is independent and still must join.
  def cancel_worker(nil, pid), do: Process.exit(pid, :kill)

  def cancel_worker(tracker, pid),
    do: GenServer.cast(tracker, {:cancel_worker, self(), pid})

  def bind_scope(tracker, scope, deadline),
    do: deadline_call(tracker, {:bind_scope, scope, deadline}, deadline)

  def bind_scope(tracker, scope, deadline, :completion_proof),
    do: deadline_call(tracker, {:bind_scope, scope, deadline, :completion_proof}, deadline)

  def bind_connector(tracker, token, deadline),
    do: deadline_call(tracker, {:bind_connector, token}, deadline)

  # The controller stores the obligation before acknowledging admission. A dial
  # worker that dies before receiving the reply cannot orphan provider evidence.
  def begin_provider(tracker, backend, deadline) when backend in [:ex_ssl, :ex_ssl_pair] do
    timeout = if deadline == :infinity, do: 1_000, else: remaining(deadline)
    operation = if backend == :ex_ssl_pair, do: :begin_provider_pair, else: :begin_provider

    if timeout == 0,
      do: {:error, :request_timeout},
      else: GenServer.call(tracker, {operation, deadline}, timeout)
  catch
    :exit, {:timeout, _} ->
      unconfirmed(tracker)
      abort(tracker)
      {:error, :request_timeout}

    :exit, _ ->
      {:error, :cleanup_unconfirmed}
  end

  # Only public await's top-level cleanup establishes provider completion. Extra
  # receipt dimensions/versions must not override pending or missing evidence.
  def provider_cleanup({:ok, %{cleanup: :confirmed}}), do: :confirmed
  def provider_cleanup({:pending, _}), do: :pending
  def provider_cleanup(_), do: :unconfirmed

  def provider_failed(nil), do: :ok
  def provider_failed(tracker), do: GenServer.cast(tracker, :provider_failed)

  def bind_provider(nil, _socket), do: :ok

  def bind_provider(tracker, socket),
    do: GenServer.call(tracker, {:bind_provider, socket}, :infinity)

  def bind_provider(nil, _socket, _deadline), do: :ok

  def bind_provider(tracker, socket, :infinity),
    do: bind_provider(tracker, socket, now() + 1_000)

  def bind_provider(tracker, socket, deadline),
    do: deadline_call(tracker, {:bind_provider, socket}, deadline)

  # Successful public prepared adoption is acknowledged before forgetting the
  # exact pre-upgrade Port. Opaque provider sockets are never inspected here.
  def adopt_provider(nil, _descriptor, _tcp, _socket, _deadline), do: :ok

  def adopt_provider(tracker, descriptor, tcp, socket, deadline),
    do: deadline_call(tracker, {:adopt_provider, descriptor, tcp, socket, deadline}, deadline)

  # The pair is already retained before TCP allocation. Only the acknowledged
  # outer scalar adoption can discharge that exact pre-TLS Port; the final
  # provider socket remains unset until the independently verified inner attach.
  def adopt_outer_provider(nil, _descriptor, _tcp, _deadline), do: :ok

  def adopt_outer_provider(tracker, descriptor, tcp, deadline),
    do: deadline_call(tracker, {:adopt_outer_provider, descriptor, tcp, deadline}, deadline)

  def offer_provider(tracker, socket, target, deadline),
    do: provider_call(tracker, {:offer_provider, socket, target, deadline}, deadline)

  def accept_provider(tracker, carrier, socket, deadline),
    do: provider_call(tracker, {:accept_provider, carrier, socket, deadline}, deadline)

  def release_provider(tracker, carrier, deadline),
    do: provider_call(tracker, {:release_provider, carrier}, deadline)

  defp provider_call(tracker, message, deadline) do
    if remaining(deadline) > 0,
      do: GenServer.call(tracker, message, remaining(deadline)),
      else: {:error, :handoff_expired}
  catch
    :exit, _ -> {:error, :handoff_unconfirmed}
  end

  # Public fields correlate one opaque offer; epochs alone cannot prove handoff.
  def transfer_state(carrier), do: transfer_state(carrier, SSL.Lifecycle.status(carrier.handle))

  def transfer_state(
        %{epoch: {outer_epoch, inner_epoch}, nonce: {outer_nonce, inner_nonce}},
        {:pending, %{layers: %{outer: outer, inner: inner}}}
      ) do
    outer = transfer_state(%{epoch: outer_epoch, nonce: outer_nonce}, {:pending, outer})
    inner = transfer_state(%{epoch: inner_epoch, nonce: inner_nonce}, {:pending, inner})

    case {outer, inner} do
      {:accepted, :accepted} -> :accepted
      {:unconfirmed, _} -> :unconfirmed
      {_, :unconfirmed} -> :unconfirmed
      _ -> :pending
    end
  end

  def transfer_state(%{epoch: epoch, nonce: nonce}, {:pending, snapshot})
      when is_integer(epoch) and is_reference(nonce) do
    case snapshot do
      %{epoch: next, transfer_nonce: ^nonce, transfer: :accepted} when next == epoch + 1 ->
        :accepted

      %{epoch: ^epoch, transfer_nonce: ^nonce, transfer: outcome}
      when outcome in [:pending, :unknown, :expired, :cancelled] ->
        :pending

      _ ->
        :unconfirmed
    end
  end

  def transfer_state(_carrier, _evidence), do: :unconfirmed

  def offer_transfer(handle, lease, target, deadline) do
    with {:pending, %{epoch: epoch}} <- SSL.Lifecycle.status(handle),
         {:ok, transfer} <- SSL.Lifecycle.offer(lease, target, {:abs_ms, deadline}) do
      nonce =
        case SSL.Lifecycle.status(handle) do
          {:pending, %{epoch: ^epoch, transfer_nonce: nonce}} -> nonce
          _ -> nil
        end

      {:ok, %{handle: handle, transfer: transfer, epoch: epoch, nonce: nonce}}
    else
      {:error, _} = error -> error
      _ -> {:error, :handoff_unconfirmed}
    end
  end

  def track_tls(opts, _socket) do
    case Keyword.get(opts, :request_lifecycle) do
      nil ->
        :ok

      tracker ->
        unconfirmed_tls(tracker)
        {:error, :unsupported_tls_socket_representation}
    end
  end

  def enter(nil, _kind), do: :ok

  def enter(tracker, kind) do
    Process.put(__MODULE__, tracker)
    register(tracker, self(), kind)
  end

  def enter(nil, _kind, _deadline), do: :ok

  def enter(tracker, kind, deadline) do
    Process.put(__MODULE__, tracker)
    register(tracker, self(), kind, deadline)
  end

  def register(nil, _resource, _kind), do: :ok

  def register(tracker, resource, kind) do
    GenServer.call(tracker, {:register, resource, kind}, :infinity)
  end

  def register(nil, _resource, _kind, _deadline), do: :ok

  def register(tracker, resource, kind, :infinity),
    do: register(tracker, resource, kind, now() + 1_000)

  def register(tracker, resource, kind, deadline) do
    # Even zero-budget admission must retain the existing HTTP worker obligation.
    # A late bookkeeping ACK cannot authorize work; the caller has already failed.
    GenServer.call(tracker, {:register, resource, kind}, remaining(deadline))
  catch
    :exit, {:timeout, _} ->
      abort(tracker)
      {:error, :request_timeout}

    :exit, _ ->
      {:error, :transport_scope_retired}
  end

  def complete(nil), do: :ok
  def complete(tracker), do: GenServer.call(tracker, {:complete, self()}, :infinity)

  def complete(tracker, nil), do: complete(tracker)
  def complete(nil, _deadline), do: :ok

  # The task's completion signal precedes its DOWN signal even if the tracker
  # is suspended. Recording it must not extend the managed request deadline.
  def complete(tracker, _deadline), do: GenServer.cast(tracker, {:complete, self()})

  def abort(nil), do: :ok
  def abort(tracker), do: send(tracker, :abort)

  # Published response streams retain internal failures for their first reader.
  # Untracked streams retain their legacy terminal delivery even on cancellation.
  def fail_response(nil, stream, reason) do
    send(stream, {:error, reason})
    :ok
  end

  # Tracked cancellation or lost worker evidence still terminates unread streams.
  def fail_response(tracker, stream, reason) when reason in [:aborted, :request_timeout],
    do: cancel_response(tracker, stream, reason)

  def fail_response(tracker, stream, {kind, _} = reason)
      when kind in [:request_process_down, :body_delivery_down, :connection_owner_down],
      do: cancel_response(tracker, stream, reason)

  def fail_response(tracker, stream, reason) do
    send(stream, {:error, reason})
    if tracker, do: send(tracker, {:response_failure, stream})
    :ok
  end

  defp cancel_response(tracker, stream, reason) do
    abort(tracker)
    send(stream, {:request_lifecycle_stop, reason})
    :ok
  end

  def unconfirmed(nil), do: :ok
  def unconfirmed(tracker), do: GenServer.cast(tracker, :unconfirmed)

  def unconfirmed_tls(nil), do: :ok
  def unconfirmed_tls(tracker), do: GenServer.cast(tracker, :unconfirmed_tls)

  def track_socket(opts, socket) when is_port(socket) or is_pid(socket) do
    register(Keyword.get(opts, :request_lifecycle), socket, :socket)
    socket
  end

  def track_socket(opts, socket) do
    _ = track_tls(opts, socket)
    socket
  end

  # Called at the ownership boundary, before a pool makes the connection
  # available to another request. Cancellation must never close a handed-off socket.
  def handoff_socket(nil, _socket), do: :ok

  def handoff_socket(tracker, socket), do: handoff_connection_resources(tracker, socket, [])

  def handoff_socket(nil, _socket, deadline) do
    if remaining(deadline) > 0, do: :ok, else: {:error, :handoff_expired}
  end

  # The tracker decides deadline acceptance before releasing its monitors.
  # A delayed reply after acceptance does not undo the transfer to the pool.
  def handoff_socket(tracker, socket, deadline) do
    case connection_resources(socket) do
      {:ok, resources} ->
        GenServer.call(tracker, {:handoff, resources, deadline}, :infinity)

      :error ->
        unconfirmed_tls(tracker)
        {:error, :unsupported_tls_socket_representation}
    end
  catch
    :exit, _ -> {:error, :handoff_unconfirmed}
  end

  def handoff_connection(nil, _socket, _owner), do: :ok

  def handoff_connection(tracker, socket, owner),
    do: handoff_connection_resources(tracker, socket, [owner])

  defp handoff_connection_resources(tracker, socket, owners) do
    case connection_resources(socket) do
      {:ok, resources} ->
        handoff(tracker, owners ++ resources)

      :error ->
        unconfirmed_tls(tracker)
        {:error, :unsupported_tls_socket_representation}
    end
  end

  defp connection_resources(socket) when is_port(socket) or is_pid(socket),
    do: {:ok, [socket]}

  defp connection_resources(_socket), do: :error

  defp handoff(tracker, resources) do
    GenServer.call(tracker, {:handoff, resources}, :infinity)
  catch
    # A lost coordinator already makes its handle unconfirmed. It must not
    # crash the pool, which may own unrelated idle connections.
    :exit, _ -> :ok
  end

  def attach_stream(nil, _stream), do: :ok

  def attach_stream(tracker, stream) do
    register(tracker, stream, :stream_starting)
    ref = make_ref()
    monitor = Process.monitor(stream)
    send(stream, {:request_lifecycle, tracker, self(), ref})

    receive do
      {:request_lifecycle_attached, ^ref} ->
        Process.demonitor(monitor, [:flush])
        GenServer.call(tracker, {:stream_ready, stream}, :infinity)

      {:DOWN, ^monitor, :process, ^stream, _reason} ->
        unconfirmed(tracker)
    end

    :ok
  end

  def attach_stream(nil, _stream, _deadline), do: :ok
  def attach_stream(tracker, stream, nil), do: attach_stream(tracker, stream)

  def attach_stream(tracker, stream, :infinity),
    do: attach_stream(tracker, stream, now() + 1_000)

  def attach_stream(tracker, stream, deadline) do
    case register(tracker, stream, :managed_stream_starting, deadline) do
      :ok ->
        ref = make_ref()
        monitor = Process.monitor(stream)
        send(stream, {:request_lifecycle, tracker, self(), ref})

        result =
          receive do
            {:request_lifecycle_attached, ^ref} ->
              deadline_call(tracker, {:stream_ready, stream}, deadline)

            {:DOWN, ^monitor, :process, ^stream, _reason} ->
              unconfirmed(tracker)
              {:error, :body_stream_closed}
          after
            remaining(deadline) -> {:error, :request_timeout}
          end

        Process.demonitor(monitor, [:flush])
        if result != :ok, do: send(stream, {:request_lifecycle_stop, :request_timeout})
        result

      error ->
        send(stream, {:request_lifecycle_stop, :request_timeout})
        error
    end
  end

  defp deadline_call(tracker, message, deadline) do
    case remaining(deadline) do
      0 -> {:error, :request_timeout}
      timeout -> GenServer.call(tracker, message, timeout)
    end
  catch
    :exit, {:timeout, _} ->
      abort(tracker)
      {:error, :request_timeout}

    :exit, _ ->
      {:error, :transport_scope_retired}
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  @impl true
  def init({starter, latch}), do: init({starter, latch, :request})

  def init({starter, latch, mode}) do
    {:ok,
     %{
       latch: latch,
       resources: %{Process.monitor(starter) => {starter, :starter}},
       completed: MapSet.new(),
       providers: %{},
       constructor_entered?: false,
       aborted?: false,
       sealed?: false,
       uncertain?: false,
       scope: nil,
       scope_monitor: nil,
       deadline: nil,
       connector: nil,
       client?: mode == :client,
       children: %{},
       children_timer: nil
     }}
  end

  @impl true
  def handle_call({:register_worker, worker, kind, deadline}, from, state) do
    {:reply, :ok, state} = handle_call({:register, worker, kind}, from, state)

    result =
      if state.aborted? or remaining(deadline) == 0, do: {:error, :request_timeout}, else: :ok

    {:reply, result, state}
  end

  def handle_call({:reserve_attempt, permit, deadline}, {creator, _}, state) do
    state = poll_children(state)

    cond do
      not state.client? or state.sealed? or state.aborted? ->
        {:reply, {:error, :aborted}, state}

      remaining(deadline) == 0 or not Process.alive?(creator) ->
        {:reply, {:error, :request_timeout}, state}

      map_size(state.children) >= 2 ->
        {:reply, {:error, :cleanup_capacity}, state}

      true ->
        entry = %{
          creator: creator,
          monitor: Process.monitor(creator),
          child: nil,
          latch: nil,
          terminal?: false
        }

        state = put_in(state.children[permit], entry)
        {:reply, {:ok, permit}, schedule_children_poll(state)}
    end
  end

  def handle_call({:retain_attempt, permit, child, latch, deadline}, {creator, _}, state) do
    case state.children[permit] do
      %{creator: ^creator, child: nil} = entry ->
        # Retain even a late publication, but it cannot authorize any work.
        state = put_in(state.children[permit], %{entry | child: child, latch: latch})

        if remaining(deadline) > 0 and not state.aborted? and not state.sealed? and
             Process.alive?(creator) do
          {:reply, :ok, state}
        else
          abort(child)
          {:reply, {:error, :request_timeout}, state}
        end

      _ ->
        abort(child)
        {:reply, {:error, :cleanup_unconfirmed}, %{state | uncertain?: true}}
    end
  end

  def handle_call({:bind_scope, scope, deadline}, _, state),
    do:
      {:reply, :ok,
       %{state | scope: scope, scope_monitor: Process.monitor(scope), deadline: deadline}}

  def handle_call({:bind_scope, scope, deadline, :completion_proof}, from, state) do
    {:reply, :ok, state} = handle_call({:bind_scope, scope, deadline}, from, state)
    {:reply, {:ok, state.latch}, state}
  end

  def handle_call({:bind_connector, token}, _, state),
    do: {:reply, :ok, %{state | connector: token}}

  def handle_call({operation, _deadline}, _, %{aborted?: true} = state)
      when operation in [:begin_provider, :begin_provider_pair],
      do: {:reply, {:error, :aborted}, state}

  def handle_call({operation, _deadline}, _, %{providers: providers} = state)
      when operation in [:begin_provider, :begin_provider_pair] and map_size(providers) != 0,
      do: {:reply, {:error, :provider_already_registered}, state}

  def handle_call({operation, deadline}, _, state)
      when operation in [:begin_provider, :begin_provider_pair] do
    deadline = if state.deadline, do: min(deadline, state.deadline), else: deadline
    setup_deadline = if deadline == :infinity, do: :infinity, else: {:abs_ms, deadline}
    state = %{state | constructor_entered?: true}

    constructor = if operation == :begin_provider_pair, do: :new_pair, else: :new

    case apply(SSL.Lifecycle, constructor, [[controller: self(), deadline: setup_deadline]]) do
      {:ok, handle, lease} ->
        Process.send_after(self(), :poll_providers, 10)
        provider = %{lease: lease, socket: nil, outgoing: nil, incoming: nil}
        state = %{state | providers: %{handle => provider}}

        case retain_provider(state, handle, deadline) do
          :ok ->
            {:reply, {:ok, {handle, lease}}, state}

          _ ->
            state = cancel_providers(%{state | uncertain?: true})
            {:reply, {:error, :cleanup_unconfirmed}, state}
        end

      {:error, reason} = error ->
        {:reply, error,
         %{state | uncertain?: state.uncertain? or reason == :acceptance_unconfirmed}}
    end
  end

  def handle_call({:bind_provider, socket}, _from, state) do
    case Map.to_list(state.providers) do
      [{handle, %{socket: nil} = provider}] ->
        {:reply, :ok, put_in(state.providers[handle], %{provider | socket: socket})}

      _ ->
        {:reply, {:error, :provider_not_registered}, %{state | uncertain?: true}}
    end
  end

  def handle_call(
        {:adopt_provider, _descriptor, _tcp, _socket, _deadline},
        _,
        %{aborted?: true} = state
      ),
      do: {:reply, {:error, :aborted}, state}

  def handle_call({:adopt_provider, {handle, lease}, tcp, socket, deadline}, {caller, _}, state) do
    with true <- remaining(deadline) > 0 and is_port(tcp),
         %{lease: ^lease, socket: nil} = provider <- Map.get(state.providers, handle),
         true <- resource_kind(state, caller) == :dial,
         true <- resource_kind(state, tcp) == :socket,
         {:pending, %{bound?: true, setup: :connected}} <-
           SSL.Lifecycle.status(handle, {:abs_ms, deadline}),
         true <- remaining(deadline) > 0 do
      state = put_in(state.providers[handle], %{provider | socket: socket})
      handle_call({:handoff, [tcp]}, {caller, nil}, state)
    else
      _ -> {:reply, {:error, :adoption_unconfirmed}, %{state | uncertain?: true}}
    end
  end

  def handle_call({:adopt_provider, _descriptor, _tcp, _socket, _deadline}, _, state),
    do: {:reply, {:error, :adoption_unconfirmed}, state}

  def handle_call({:adopt_outer_provider, descriptor, tcp, deadline}, {caller, _}, state) do
    with false <- state.aborted?,
         true <- remaining(deadline) > 0 and is_port(tcp),
         [{handle, %{lease: lease, socket: nil}}] <- Map.to_list(state.providers),
         {:ok, %{outer: ^descriptor}} <- SSL.Lifecycle.layers({handle, lease}),
         true <- resource_kind(state, caller) == :dial,
         true <- resource_kind(state, tcp) == :socket,
         {:pending, %{scope: :upgrade, bound?: true, setup: :connected}} <-
           SSL.Lifecycle.status(elem(descriptor, 0), {:abs_ms, deadline}),
         true <- remaining(deadline) > 0 do
      handle_call({:handoff, [tcp]}, {caller, nil}, state)
    else
      _ -> {:reply, {:error, :adoption_unconfirmed}, %{state | uncertain?: true}}
    end
  end

  def handle_call({:offer_provider, _, _, _}, _, %{aborted?: true} = state),
    do: {:reply, {:error, :aborted}, state}

  def handle_call({:offer_provider, socket, target, deadline}, _, state) do
    case Enum.find(state.providers, fn {_, provider} -> provider.socket == socket end) do
      {handle, %{outgoing: nil} = provider} ->
        case offer_transfer(handle, provider.lease, target, deadline) do
          {:ok, carrier} ->
            provider =
              Map.put(
                %{provider | outgoing: carrier, incoming: nil},
                :outgoing_owner,
                target.owner
              )

            {:reply, {:ok, carrier}, put_in(state.providers[handle], provider)}

          error ->
            {:reply, error, cancel_providers(state)}
        end

      _ ->
        {:reply, {:error, :provider_not_registered}, state}
    end
  end

  def handle_call({:accept_provider, _, _, _}, _, %{aborted?: true} = state),
    do: {:reply, {:error, :aborted}, state}

  def handle_call({:accept_provider, carrier, socket, deadline}, _, state) do
    case Map.get(state.providers, carrier.handle) do
      nil ->
        provider = %{lease: nil, socket: socket, outgoing: nil, incoming: carrier}
        state = put_in(state.providers[carrier.handle], provider)
        Process.send_after(self(), :poll_providers, 10)
        {result, state} = accept_incoming(state, carrier.handle, deadline)
        {:reply, result, state}

      %{incoming: ^carrier} ->
        {result, state} = accept_incoming(state, carrier.handle, deadline)
        {:reply, result, state}

      _ ->
        {:reply, {:error, :provider_already_registered}, state}
    end
  end

  def handle_call({:release_provider, carrier}, _, state) do
    case Map.get(state.providers, carrier.handle) do
      %{outgoing: ^carrier} = provider ->
        if transfer_state(carrier) == :accepted do
          {:reply, :ok, release_outgoing(state, carrier.handle, provider)}
        else
          {:reply, {:error, :handoff_unconfirmed}, state}
        end

      nil ->
        result =
          if transfer_state(carrier) == :accepted, do: :ok, else: {:error, :handoff_unconfirmed}

        {:reply, result, state}

      _ ->
        {:reply, {:error, :handoff_unconfirmed}, state}
    end
  end

  def handle_call({:register, resource, kind}, _from, state) do
    state = track_scope(state, resource, kind)
    state = if kind in [:task, :owner], do: release_starter(state), else: state

    state =
      if resource_kind(state, resource) do
        state
      else
        monitor =
          if is_port(resource), do: Port.monitor(resource), else: Process.monitor(resource)

        %{state | resources: Map.put(state.resources, monitor, {resource, kind})}
      end

    if state.aborted? do
      cancel_owners(state.resources)
      if kind != :owner, do: cancel(resource, kind)
    end

    {:reply, :ok, state}
  end

  def handle_call({:handoff, handed_off, deadline}, from, state) do
    if remaining(deadline) > 0,
      do: handle_call({:handoff, handed_off}, from, state),
      else: {:reply, {:error, :handoff_expired}, state}
  end

  def handle_call({:handoff, handed_off}, _from, state) do
    resources =
      Enum.reduce(state.resources, state.resources, fn {ref, {resource, kind}}, acc ->
        if kind in [:socket, :connection, :tls] and resource in handed_off do
          Process.demonitor(ref, [:flush])
          Map.delete(acc, ref)
        else
          acc
        end
      end)

    {:reply, :ok, %{state | resources: resources}}
  end

  def handle_call({:stream_ready, stream}, _from, state) do
    resources =
      Map.new(state.resources, fn
        {ref, {^stream, kind}} when kind in [:stream_starting, :managed_stream_starting] ->
          {ref, {stream, :stream}}

        entry ->
          entry
      end)

    if state.aborted?, do: cancel(stream, :stream)
    {:reply, :ok, %{state | resources: resources}}
  end

  def handle_call({:complete, pid}, _from, state) do
    {:reply, :ok, mark_complete(state, pid)}
  end

  @impl true
  def handle_cast({:admit_worker, worker, kind, deadline, creator, launch}, state) do
    {:reply, result, state} =
      handle_call({:register_worker, worker, kind, deadline}, {creator, nil}, state)

    if result == :ok and Process.alive?(creator) do
      send(worker, {:launch, launch})
    else
      send(worker, {:rejected, launch, :request_timeout})
    end

    {:noreply, state}
  end

  def handle_cast({:retire_owner, owner}, state) do
    if resource_kind(state, owner) in [:owner, :starter] do
      resources =
        Enum.reduce(state.resources, state.resources, fn
          {ref, {^owner, kind}}, acc when kind in [:owner, :starter] ->
            Process.demonitor(ref, [:flush])
            Map.delete(acc, ref)

          _, acc ->
            acc
        end)

      settle(%{state | resources: resources, sealed?: true})
    else
      {:noreply, %{state | uncertain?: true}}
    end
  end

  def handle_cast({:cancel_worker, owner, worker}, state) do
    case {resource_kind(state, owner), resource_kind(state, worker)} do
      {:owner, kind} when kind in [:dial, :client_write] ->
        Process.exit(worker, :kill)
        {:noreply, mark_complete(state, worker)}

      {:owner, nil} ->
        # The worker's completion and DOWN can precede its owner's cancellation.
        # DOWN already preserves unexplained death as sticky uncertainty; an
        # absent worker needs no new obligation or unbounded completed history.
        {:noreply, state}

      _ ->
        {:noreply, %{state | uncertain?: true}}
    end
  end

  def handle_cast(:unconfirmed, state), do: {:noreply, %{state | uncertain?: true}}

  def handle_cast(:provider_failed, state), do: {:noreply, cancel_providers(state)}

  def handle_cast(:unconfirmed_tls, state) do
    if state.scope, do: GenServer.cast(state.scope, :unconfirmed)
    {:noreply, %{state | uncertain?: true}}
  end

  def handle_cast({:complete, pid}, state), do: {:noreply, mark_complete(state, pid)}

  defp mark_complete(state, pid) do
    state = %{state | completed: MapSet.put(state.completed, pid)}
    if resource_kind(state, pid) in [:owner, :task], do: %{state | sealed?: true}, else: state
  end

  @impl true
  def handle_info(:launch_failed, state) do
    state = release_starter(state)
    settle(%{state | sealed?: true, uncertain?: true})
  end

  def handle_info(:abort, state) do
    state = release_accepted(state)
    cancel_resources(state.resources)
    Enum.each(state.children, fn {_, entry} -> if entry.child, do: abort(entry.child) end)
    {:noreply, cancel_providers(state)}
  end

  def handle_info({:poll_children, token}, %{children_timer: token} = state) do
    state = state |> Map.put(:children_timer, nil) |> poll_children() |> schedule_children_poll()
    settle(state)
  end

  def handle_info({:poll_children, _stale_token}, state), do: {:noreply, state}

  def handle_info(:poll_providers, state) do
    state = Enum.reduce(Map.keys(state.providers), state, &poll_provider/2)

    _timer =
      if map_size(state.providers) != 0, do: Process.send_after(self(), :poll_providers, 10)

    settle(state)
  end

  def handle_info({:response_failure, stream}, state) do
    state = release_accepted(state)

    state.resources
    |> Enum.reject(fn {_ref, {pid, kind}} -> pid == stream and kind == :stream end)
    |> cancel_resources()

    {:noreply, cancel_providers(state)}
  end

  def handle_info({:DOWN, ref, :process, _, _}, %{scope_monitor: ref} = state) do
    state = release_accepted(state)
    cancel_resources(state.resources)
    {:noreply, cancel_providers(%{state | uncertain?: true})}
  end

  def handle_info({:DOWN, ref, _type, resource, _reason}, state) do
    state = release_accepted(state)

    case Map.pop(state.resources, ref) do
      {nil, _} ->
        children =
          Map.new(state.children, fn
            {permit, %{monitor: ^ref, child: nil} = entry} ->
              {permit, %{entry | terminal?: true}}

            entry ->
              entry
          end)

        settle(%{state | children: children})

      {{_, kind}, resources} ->
        incomplete? =
          kind in [:owner, :task, :dial, :starter, :client_write] and
            not MapSet.member?(state.completed, resource)

        state = %{
          state
          | resources: resources,
            completed: MapSet.delete(state.completed, resource),
            uncertain?: state.uncertain? or incomplete?
        }

        state =
          if kind == :owner or (kind in [:task, :starter] and incomplete?),
            do: %{state | sealed?: true},
            else: state

        state = if incomplete?, do: cancel_providers(state), else: state
        if incomplete?, do: cancel_resources(resources)

        settle(state)
    end
  end

  defp poll_provider(handle, state) do
    provider = state.providers[handle]

    if provider.outgoing != nil and transfer_state(provider.outgoing) == :accepted do
      release_outgoing(state, handle, provider)
    else
      state = recover_incoming(state, handle)

      case provider_cleanup(SSL.Lifecycle.await(handle, {:abs_ms, now()})) do
        :confirmed ->
          %{state | providers: Map.delete(state.providers, handle)}

        :pending ->
          state

        :unconfirmed ->
          %{state | providers: Map.delete(state.providers, handle), uncertain?: true}
      end
    end
  end

  # Provider acceptance and release of the HTTP shared-owner obligation must be
  # observed together, including when abort wins the next tracker mailbox turn.
  defp release_accepted(state) do
    Enum.reduce(state.providers, state, fn {handle, provider}, acc ->
      if provider.outgoing != nil and transfer_state(provider.outgoing) == :accepted,
        do: release_outgoing(acc, handle, provider),
        else: acc
    end)
  end

  defp release_outgoing(state, handle, provider) do
    owner = Map.get(provider, :outgoing_owner)

    resources =
      Enum.reduce(state.resources, state.resources, fn
        {ref, {^owner, :connection}}, acc ->
          Process.demonitor(ref, [:flush])
          Map.delete(acc, ref)

        _, acc ->
          acc
      end)

    %{state | providers: Map.delete(state.providers, handle), resources: resources}
  end

  defp recover_incoming(state, handle) do
    case state.providers[handle] do
      %{lease: nil, incoming: carrier} when carrier != nil ->
        if transfer_state(carrier) == :accepted do
          {_result, state} = accept_incoming(state, handle, now() + 250)
          state
        else
          state
        end

      _ ->
        state
    end
  end

  defp accept_incoming(state, handle, deadline) do
    provider = state.providers[handle]

    case SSL.Lifecycle.accept(provider.incoming.transfer, {:abs_ms, deadline}) do
      {:ok, lease} ->
        state = put_in(state.providers[handle].lease, lease)
        # Cancellation only requests retirement; poll_provider retains the handle
        # until public await confirms cleanup, including a lost cancel reply.
        _cancel = if state.aborted?, do: SSL.Lifecycle.cancel(lease, {:abs_ms, now() + 250})
        {:ok, state}

      {:error, _} = error ->
        {error, state}
    end
  end

  defp settle(%{sealed?: true, resources: resources, providers: providers} = state)
       when map_size(resources) == 0 and map_size(providers) == 0 do
    state = poll_children(state)

    if Enum.all?(state.children, fn {_, entry} -> entry.terminal? end) do
      discharge_no_birth(state)
      uncertain? = state.uncertain? or map_size(state.children) != 0
      :atomics.put(state.latch, 1, if(uncertain?, do: 3, else: 2))
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end

  defp settle(state), do: {:noreply, state}

  defp poll_children(state) do
    children =
      Enum.reduce(state.children, state.children, fn
        {permit, %{child: child, latch: latch} = entry}, acc when is_pid(child) ->
          if Process.alive?(child) do
            acc
          else
            if :atomics.get(latch, 1) == 2 do
              Process.demonitor(entry.monitor, [:flush])
              Map.delete(acc, permit)
            else
              Map.put(acc, permit, %{entry | terminal?: true})
            end
          end

        _, acc ->
          acc
      end)

    %{state | children: children}
  end

  defp schedule_children_poll(%{children_timer: nil} = state) do
    if Enum.any?(state.children, fn {_, entry} -> not entry.terminal? end) do
      token = make_ref()
      Process.send_after(self(), {:poll_children, token}, 10)
      %{state | children_timer: token}
    else
      state
    end
  end

  defp schedule_children_poll(state), do: state

  defp discharge_no_birth(%{scope: scope, connector: token, constructor_entered?: false})
       when is_pid(scope) and is_reference(token) do
    # A zero-time call still enqueues authenticated sender evidence. There is no
    # new admission/cleanup wait, and this assertion is made only if no constructor
    # was ever entered, never for a lost constructor reply.
    GenServer.call(scope, {:provider_not_started, token}, 0)
  catch
    :exit, _ -> :ok
  end

  defp discharge_no_birth(_state), do: :ok

  defp cancel_providers(%{aborted?: true} = state), do: state

  defp cancel_providers(state) do
    Enum.each(state.providers, fn {_handle, provider} ->
      # A cancel ACK is acceptance only. The polling join retains the obligation
      # until public await confirms cleanup and observer absence.
      if provider.lease, do: SSL.Lifecycle.cancel(provider.lease, {:abs_ms, now() + 250})
    end)

    %{state | aborted?: true}
  end

  defp now, do: System.monotonic_time(:millisecond)

  defp release_starter(state) do
    resources =
      Enum.reduce(state.resources, state.resources, fn
        {ref, {_pid, :starter}}, acc ->
          Process.demonitor(ref, [:flush])
          Map.delete(acc, ref)

        _, acc ->
          acc
      end)

    %{state | resources: resources}
  end

  defp resource_kind(state, pid) do
    Enum.find_value(state.resources, fn {_ref, {resource, kind}} ->
      if resource == pid, do: kind
    end)
  end

  defp retain_provider(%{scope: nil}, _handle, _deadline), do: :ok

  defp retain_provider(state, handle, deadline) do
    GenServer.call(
      state.scope,
      {:track_provider, state.connector, handle, deadline},
      max(remaining(deadline), 0)
    )
  catch
    :exit, _ -> {:error, :acceptance_unconfirmed}
  end

  defp track_scope(%{scope: nil} = state, _resource, _kind), do: state

  defp track_scope(state, resource, kind) do
    timeout = if state.deadline, do: max(remaining(state.deadline), 1), else: 5_000
    :ok = GenServer.call(state.scope, {:track, resource, kind, state.connector}, timeout)
    state
  catch
    :exit, _ ->
      cancel_owners(state.resources)
      cancel(resource, kind)
      %{state | uncertain?: true, aborted?: true}
  end

  defp cancel_resources(resources) do
    # Notify owners before invalidating sockets or stopping send workers. A
    # syscall released by closure must not beat its causal cancellation message.
    cancel_owners(resources)

    Enum.each(resources, fn
      {_ref, {_pid, :owner}} -> :ok
      {_ref, {pid, kind}} -> cancel(pid, kind)
    end)
  end

  defp cancel_owners(resources) do
    Enum.each(resources, fn
      {_ref, {pid, :owner}} -> cancel(pid, :owner)
      _ -> :ok
    end)
  end

  defp cancel(pid, :owner), do: send(pid, :abort)
  defp cancel(pid, :dial), do: send(pid, :abort)
  # Upload workers are linked to the owner, which unlinks before stopping them.
  defp cancel(pid, :upload), do: send(pid, :abort)
  defp cancel(pid, :body_bridge), do: GenServer.cast(pid, :stop)
  defp cancel(pid, :connection), do: send(pid, :http2_shutdown_exclusive)
  defp cancel(_pid, :starter), do: :ok
  defp cancel(_pid, :task), do: :ok
  # TCP closure initiates TLS shutdown; each TLS process must actually go DOWN.
  defp cancel(_pid, :tls), do: :ok
  defp cancel(_pid, :stream_starting), do: :ok

  defp cancel(pid, :managed_stream_starting),
    do: send(pid, {:request_lifecycle_stop, :aborted})

  defp cancel(pid, :stream), do: send(pid, {:request_lifecycle_stop, :aborted})

  defp cancel(port, :socket) do
    _ = :inet.setopts(port, linger: {true, 0})
    :gen_tcp.close(port)
  end

  defp cancel(pid, _kind), do: Process.exit(pid, :kill)
end

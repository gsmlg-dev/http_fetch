defmodule HTTP.HTTP3.ConnectionOwner do
  @moduledoc "Serialized native HTTP/3 ownership with bounded operations, demand and continuations."
  use GenServer
  alias QuicHttp3.Session

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)
  def await_ready(owner, timeout \\ 5_000), do: GenServer.call(owner, :await_ready, timeout)

  def open(owner, fields, body, subscriber, generation, opts \\ []) do
    case GenServer.call(
           owner,
           {:open, fields, body, subscriber, generation, opts},
           Keyword.get(opts, :timeout, 5_000) + 1_000
         ) do
      {:error, {:not_sent, reason}} -> {:error, reason}
      result -> result
    end
  end

  def send_data(owner, ref, bytes, fin, recipient, write_ref),
    do: GenServer.cast(owner, {:write, ref, bytes, fin, recipient, write_ref})

  def acknowledge(owner, ref), do: GenServer.cast(owner, {:ack, ref})

  def cancel_open(owner, subscriber, generation),
    do: GenServer.cast(owner, {:cancel_open, subscriber, generation})

  def cancel(owner, ref), do: GenServer.call(owner, {:cancel, ref})
  def status(owner), do: GenServer.call(owner, :status)

  @impl true
  def init(opts) do
    {:ok, opts} = HTTP.HTTP3.ReceiveBudget.normalize(opts)
    owner = self()

    {:ok, watchdog} =
      Task.Supervisor.start_child(:http_runtime_task_supervisor, fn -> watchdog(owner) end)

    timeout = Keyword.get(opts, :operation_timeout, 1_000)

    {:ok, session} =
      Session.new(Keyword.put(Keyword.get(opts, :session_options, []), :timeout, timeout))

    {:ok,
     %{
       session: session,
       opts: opts,
       watchdog: watchdog,
       timeout: timeout,
       lifecycle: :connecting,
       ready_waiters: [],
       requests: %{},
       pending: nil,
       continuations: [],
       queue: [],
       allocations: 0,
       writable_epoch: 0,
       continuation_turn?: true,
       max_streams: Keyword.get(opts, :max_streams, 32),
       rotation: Keyword.get(opts, :rotation_after, 960),
       pool: nil,
       pool_monitor: nil,
       last_activity: now(),
       idle_timeout: Keyword.get(opts, :idle_timeout, 30_000),
       opening_deadline: now() + Keyword.get(opts, :connect_timeout, 5_000)
     }, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    result =
      guarded(state, state.opening_deadline - now(), fn ->
        Session.connect(
          state.session,
          state.opts[:host],
          state.opts[:port],
          Keyword.drop(state.opts, [
            :host,
            :port,
            :max_streams,
            :rotation_after,
            :operation_timeout
          ])
        )
      end)

    next = result(state, :connect, result)
    Process.send_after(self(), :tick, 1)
    {:noreply, next}
  end

  @impl true
  def handle_call(:await_ready, _from, %{lifecycle: :ready} = state), do: {:reply, :ok, state}

  def handle_call(:await_ready, from, state),
    do: {:noreply, %{state | ready_waiters: [from | state.ready_waiters]}}

  def handle_call(:status, _from, state) do
    endpoint = if state.session.connection, do: state.session.connection.endpoint

    {:reply,
     %{
       lifecycle: state.lifecycle,
       requests: map_size(state.requests),
       allocations: state.allocations,
       pending: state.pending != nil,
       continuations: length(state.continuations),
       queued: length(state.queue),
       endpoint: endpoint
     }, state}
  end

  def handle_call(
        {:open, _fields, _body, _subscriber, _generation, _opts},
        _from,
        %{lifecycle: :draining} = state
      ),
      do: {:reply, {:error, {:not_sent, :goaway}}, state}

  def handle_call({:open, fields, body, subscriber, generation, opts}, from, state) do
    if map_size(state.requests) + open_count(state) >= state.max_streams do
      {:reply, {:error, :owner_capacity}, state}
    else
      action = {:open, from, subscriber, generation, fields, body, opts}
      {:noreply, enqueue(state, action)}
    end
  end

  def handle_call({:cancel, ref}, _from, state) do
    next = remove_request(state, ref)
    action = {:cancel, ref}
    {:reply, :ok, enqueue(next, action)}
  end

  @impl true
  def handle_cast({:cancel_open, subscriber, generation}, state) do
    {cancelled, retained} =
      Enum.split_with(state.queue, &match?({:open, _, ^subscriber, ^generation, _, _, _}, &1))

    next = Enum.reduce(cancelled, %{state | queue: retained}, &reject(&2, &1, :aborted))
    {:noreply, next}
  end

  def handle_cast({:write, ref, bytes, fin, recipient, write_ref}, state),
    do: {:noreply, enqueue(state, {:write, ref, bytes, fin, recipient, write_ref})}

  def handle_cast({:ack, ref}, state) do
    next =
      if Map.has_key?(state.requests, ref),
        do: put_in(state.requests[ref].paused, false),
        else: state

    next = touch(next)
    {:noreply, next}
  end

  @impl true
  def handle_info(:tick, state) do
    next = tick(state)

    if map_size(next.requests) == 0 and next.pending == nil and next.queue == [] and
         next.continuations == [] and
         (next.lifecycle == :draining or now() - next.last_activity >= next.idle_timeout) do
      {:stop, :normal, next}
    else
      Process.send_after(self(), :tick, 5)
      {:noreply, next}
    end
  end

  def handle_info({:quic_ready, _handle, _metadata}, state), do: {:noreply, state}
  def handle_info({:quic_closed, _handle, reason}, state), do: {:stop, {:shutdown, reason}, state}

  def handle_info({:http3_pool, pool, _key}, state) do
    if state.pool_monitor, do: Process.demonitor(state.pool_monitor, [:flush])
    if state.lifecycle == :draining, do: HTTP.HTTP3.Pool.drain(pool, self())
    {:noreply, %{state | pool: pool, pool_monitor: Process.monitor(pool)}}
  end

  def handle_info(:http3_pool_down, state), do: {:stop, :normal, state}

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    if monitor == state.pool_monitor, do: send(self(), :http3_pool_down)
    refs = for {ref, request} <- state.requests, request.monitor == monitor, do: ref

    next =
      Enum.reduce(refs, state, fn ref, acc ->
        enqueue(remove_request(acc, ref), {:cancel, ref})
      end)

    {:noreply, next}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(reason, state) do
    fail_all(state, {:owner_down, reason})

    if state.session.connection,
      do: guarded(state, state.timeout, fn -> Session.abort(state.session) end)

    send(state.watchdog, :stop)
    :ok
  end

  defp tick(%{pending: context} = state) when context != nil,
    do:
      result(
        state,
        context,
        guarded(state, pending_budget(state), fn -> Session.resume(state.session) end)
      )

  defp tick(%{lifecycle: :connecting} = state) do
    if now() >= state.opening_deadline do
      exit({:shutdown, :opening_timeout})
    else
      case guarded(state, state.opening_deadline - now(), fn -> Session.ready(state.session) end) do
        :ready ->
          result(
            %{state | lifecycle: :initializing},
            :initialize,
            guarded(state, state.timeout, fn -> Session.open(state.session) end)
          )

        :pending ->
          state

        {:error, reason} ->
          exit({:shutdown, reason})
      end
    end
  end

  defp tick(state) do
    paused = MapSet.new(for {ref, request} <- state.requests, request.paused, do: ref)

    polled =
      result(
        state,
        :poll,
        guarded(state, state.timeout, fn ->
          Session.poll(state.session, 128, paused: paused, max_read_batches: 1)
        end)
      )

    if polled.pending != nil do
      polled
    else
      runnable =
        Enum.find_index(polled.continuations, fn {_, continuation, epoch} ->
          epoch < polled.writable_epoch or continuation.pending.deadline <= now()
        end)

      cond do
        runnable != nil and (polled.continuation_turn? or polled.queue == []) ->
          {{context, continuation, _epoch}, rest} = List.pop_at(polled.continuations, runnable)
          next = %{polled | continuations: rest, continuation_turn?: false}

          result(
            next,
            context,
            guarded(
              next,
              min(next.timeout, max(continuation.pending.deadline - now(), 1)),
              fn ->
                Session.resume(next.session, continuation)
              end,
              context
            )
          )

        polled.queue != [] ->
          [action | rest] = polled.queue
          perform(%{polled | queue: rest, continuation_turn?: true}, action)

        true ->
          polled
      end
    end
  end

  defp enqueue(state, action) do
    state = touch(state)

    if state.lifecycle == :ready and state.pending == nil and state.queue == [] do
      perform(state, action)
    else
      if length(state.queue) < 128,
        do: %{state | queue: state.queue ++ [action]},
        else: reject(state, action, :owner_queue_full)
    end
  end

  defp perform(state, {:open, _from, subscriber, _generation, fields, body, opts} = action) do
    cond do
      not Process.alive?(subscriber) ->
        reject(state, action, :subscriber_down)

      opts[:deadline_at] != nil and opts[:deadline_at] != :infinity and
          now() >= opts[:deadline_at] ->
        reject(state, action, :opening_timeout)

      true ->
        result(
          state,
          action,
          guarded(
            state,
            min(state.timeout, Keyword.get(opts, :timeout, state.timeout)),
            fn ->
              Session.request(state.session, fields, body, opts)
            end,
            action
          )
        )
    end
  end

  defp perform(state, {:write, ref, bytes, fin, _recipient, _write_ref} = action),
    do:
      result(
        state,
        action,
        guarded(state, state.timeout, fn ->
          Session.send_data(state.session, ref, bytes, fin, [])
        end)
      )

  defp perform(state, {:cancel, ref} = action) do
    if Map.has_key?(state.session.requests, ref),
      do:
        result(
          state,
          action,
          guarded(state, state.timeout, fn -> Session.cancel(state.session, ref) end)
        ),
      else: state
  end

  defp perform(state, {:reset_send, ref, _header} = action),
    do:
      result(
        state,
        action,
        guarded(state, state.timeout, fn -> Session.reset_send(state.session, ref) end)
      )

  defp perform(state, {:reset_send, ref} = action),
    do:
      result(
        state,
        action,
        guarded(state, state.timeout, fn -> Session.reset_send(state.session, ref) end)
      )

  defp result(state, context, response) do
    next = apply_result(state, context, response)

    allocations =
      div(next.session.next_stream_id, 4) + if(next.session.control_stream, do: 1, else: 0)

    next = %{next | allocations: allocations}
    if next.lifecycle == :ready and allocations >= next.rotation, do: draining(next), else: next
  end

  defp apply_result(state, context, {:unknown, session, _ref}),
    do: %{state | session: session, pending: context}

  defp apply_result(state, context, {:blocked, session, _reason}) do
    case Session.suspend_blocked(session) do
      {:ok, next, continuation} ->
        %{
          state
          | session: next,
            pending: nil,
            continuations: state.continuations ++ [{context, continuation, state.writable_epoch}]
        }

      {:error, next, _} ->
        %{state | session: next, pending: context}
    end
  end

  defp apply_result(state, context, {:error, session, reason}) do
    if session.pending != nil, do: exit({:shutdown, reason})
    next = %{state | session: session, pending: nil}

    case context do
      value when value in [:connect, :initialize, :poll] -> exit({:shutdown, reason})
      _ -> reject(next, context, reason)
    end
  end

  defp apply_result(state, :connect, {:ok, session}),
    do: %{state | session: session, pending: nil}

  defp apply_result(state, :initialize, {:ok, session}) do
    for from <- state.ready_waiters, do: GenServer.reply(from, :ok)
    %{state | session: session, lifecycle: :ready, ready_waiters: [], pending: nil}
  end

  defp apply_result(state, :poll, {:ok, session, events}) do
    Enum.reduce(events, %{state | session: session, pending: nil}, &event/2)
  end

  defp apply_result(
         state,
         {:open, from, subscriber, generation, _fields, _body, _opts},
         {:ok, session, ref}
       ) do
    monitor = Process.monitor(subscriber)

    request = %{
      subscriber: subscriber,
      generation: generation,
      monitor: monitor,
      paused: false,
      headers_pending?: false,
      deferred: []
    }

    GenServer.reply(from, {:ok, ref})

    next = %{
      state
      | session: session,
        pending: nil,
        requests: Map.put(state.requests, ref, request)
    }

    if Process.alive?(subscriber),
      do: next,
      else: enqueue(remove_request(next, ref), {:cancel, ref})
  end

  defp apply_result(state, {:write, _ref, _bytes, _fin, recipient, write_ref}, {:ok, session}) do
    send(recipient, {:http3_write, write_ref, :done})
    %{state | session: session, pending: nil}
  end

  defp apply_result(state, {:reset_send, ref, header}, {:ok, session}) do
    next = %{state | session: session, pending: nil}

    if request = next.requests[ref] do
      notify(next, ref, header)

      unpaused =
        put_in(next.requests[ref], %{
          request
          | headers_pending?: false,
            paused: false,
            deferred: []
        })

      Enum.reduce(request.deferred, unpaused, &event/2)
    else
      next
    end
  end

  defp apply_result(state, _context, {:ok, session}),
    do: %{state | session: session, pending: nil}

  defp event(event, state) do
    ref = if is_tuple(event) and tuple_size(event) >= 2, do: elem(event, 1)
    request = state.requests[ref]

    if request && request.headers_pending? do
      if length(request.deferred) < 128 do
        put_in(state.requests[ref].deferred, request.deferred ++ [event])
      else
        notify(state, ref, {:error, :consumer_overloaded})
        enqueue(remove_request(state, ref), {:cancel, ref})
      end
    else
      dispatch_event(event, state)
    end
  end

  defp dispatch_event(:writable, state), do: %{state | writable_epoch: state.writable_epoch + 1}

  defp dispatch_event({:headers, ref, fields}, state) do
    {":status", value} = List.keyfind(fields, ":status", 0)
    event({:headers, ref, String.to_integer(value), List.keydelete(fields, ":status", 0)}, state)
  end

  defp dispatch_event({:headers, ref, status, fields}, state) do
    state = stop_blocked_upload(state, ref)

    if Map.has_key?(state.session.requests, ref) and state.session.requests[ref].upload == :open and
         Map.has_key?(state.requests, ref) do
      next =
        put_in(state.requests[ref], %{state.requests[ref] | headers_pending?: true, paused: true})

      enqueue(next, {:reset_send, ref, {:headers, status, fields}})
    else
      notify(state, ref, {:headers, status, fields})
      state
    end
  end

  defp dispatch_event({:informational, ref, status, fields}, state),
    do: deliver(state, ref, {:informational, status, fields})

  defp dispatch_event({:trailers, ref, fields}, state),
    do: deliver(state, ref, {:trailers, fields})

  defp dispatch_event({:data, ref, bytes}, state) do
    notify(state, ref, {:data, bytes})
    state = touch(state)

    if Map.has_key?(state.requests, ref),
      do: put_in(state.requests[ref].paused, true),
      else: state
  end

  defp dispatch_event({:done, ref}, state) do
    notify(state, ref, :done)
    remove_request(state, ref)
  end

  defp dispatch_event({:stream_error, ref, code, reason}, state),
    do: event({:stream_error, ref, {:http3_error, :stream, code, reason}}, state)

  defp dispatch_event({:stream_error, ref, reason}, state) do
    notify(state, ref, {:error, reason})
    remove_request(state, ref)
  end

  defp dispatch_event({:stream_reset, ref, code, final_size}, state),
    do: event({:stream_error, ref, {:reset, code, final_size}}, state)

  defp dispatch_event({:stopped, ref, _code}, state), do: enqueue(state, {:reset_send, ref})

  defp dispatch_event({:goaway, id}, state) do
    rejected =
      for {ref, request} <- state.session.requests, request.stream.handle.id >= id, do: ref

    next =
      Enum.reduce(rejected, state, fn ref, acc ->
        notify(acc, ref, {:error, :request_rejected})
        enqueue(remove_request(acc, ref), {:cancel, ref})
      end)

    draining(next)
  end

  defp dispatch_event(_event, state), do: state

  defp stop_blocked_upload(state, ref) do
    {blocked, retained} =
      Enum.split_with(state.continuations, fn {context, _, _} ->
        match?({:write, ^ref, _, _, _, _}, context)
      end)

    {queued, queue} = Enum.split_with(state.queue, &match?({:write, ^ref, _, _, _, _}, &1))
    actions = Enum.map(blocked, &elem(&1, 0)) ++ queued
    next = Enum.reduce(actions, state, &reject(&2, &1, :upload_closed))
    %{next | continuations: retained, queue: queue}
  end

  defp deliver(state, ref, event) do
    notify(state, ref, event)
    state
  end

  defp notify(state, ref, event) do
    if request = state.requests[ref],
      do: send(request.subscriber, {:http3, request.generation, ref, event})
  end

  defp remove_request(state, ref) do
    case Map.pop(state.requests, ref) do
      {nil, _} ->
        state

      {request, requests} ->
        Process.demonitor(request.monitor, [:flush])
        touch(%{state | requests: requests})
    end
  end

  defp draining(state) do
    if state.pool, do: HTTP.HTTP3.Pool.drain(state.pool, self())
    {opens, retained} = Enum.split_with(state.queue, &match?({:open, _, _, _, _, _, _}, &1))
    # Only queued actions have not entered Session.request/4. Pending and
    # suspended native operations retain their original reconciliation path.
    next = Enum.reduce(opens, state, &reject(&2, &1, {:not_sent, :goaway}))
    %{next | lifecycle: :draining, queue: retained}
  end

  defp reject(state, {:open, from, _, _, _, _, _}, reason) do
    GenServer.reply(from, {:error, reason})
    state
  end

  defp reject(state, {:write, _, _, _, recipient, ref}, reason) do
    send(recipient, {:http3_write, ref, {:error, reason}})
    state
  end

  defp reject(state, {:reset_send, ref, _header}, reason) do
    notify(state, ref, {:error, reason})
    remove_request(state, ref)
  end

  defp reject(state, _context, _reason), do: state

  defp fail_all(state, reason) do
    for {ref, _} <- state.requests, do: notify(state, ref, {:error, reason})
    for from <- state.ready_waiters, do: GenServer.reply(from, {:error, reason})

    actions =
      state.queue ++
        Enum.map(state.continuations, &elem(&1, 0)) ++
        if(state.pending, do: [state.pending], else: [])

    Enum.reduce(actions, state, &reject(&2, &1, reason))
  end

  defp open_count(state) do
    contexts =
      state.queue ++
        Enum.map(state.continuations, &elem(&1, 0)) ++
        if(state.pending, do: [state.pending], else: [])

    Enum.count(contexts, &match?({:open, _, _, _, _, _, _}, &1))
  end

  defp pending_budget(state) do
    min(state.timeout, max(state.session.pending.deadline - now(), 1))
  end

  defp touch(state), do: %{state | last_activity: now()}

  defp guarded(state, timeout, fun, context \\ nil) do
    token = make_ref()
    # Session creates native refs inside its synchronous calls. Until a call
    # returns, admission may have happened without exposing that identity.
    operation = if state.session.pending, do: state.session.pending.ref, else: :unknown

    recipients =
      Enum.map(state.requests, fn {_, request} -> request.subscriber end) ++
        case context || state.pending do
          {:open, _from, subscriber, _, _, _, _} -> [subscriber]
          _ -> []
        end

    send(state.watchdog, {:arm, token, max(timeout, 1), Enum.uniq(recipients), operation})
    result = fun.()
    send(state.watchdog, {:disarm, token})
    result
  end

  defp watchdog(owner) do
    monitor = Process.monitor(owner)

    receive do
      {:arm, token, timeout, recipients, operation} ->
        receive do
          {:disarm, ^token} ->
            Process.demonitor(monitor, [:flush])
            watchdog(owner)

          {:DOWN, ^monitor, :process, _, _} ->
            :ok

          :stop ->
            :ok
        after
          timeout ->
            if operation, do: Enum.each(recipients, &send(&1, {:http3_indeterminate, operation}))
            Process.exit(owner, :kill)
        end

      {:DOWN, ^monitor, :process, _, _} ->
        :ok

      :stop ->
        :ok
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end

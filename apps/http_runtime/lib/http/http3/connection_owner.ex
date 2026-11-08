defmodule HTTP.HTTP3.ConnectionOwner do
  @moduledoc """
  Serialized native HTTP/3 ownership with bounded operations, demand and continuations.

  With `resumption: %{early: early?}` (beta) the owner dials through the shared
  `HTTP.HTTP3.Resumption` endpoint of its partition and records the peer
  SETTINGS it receives there. When `early?` is true, the connection offers
  0-RTT and SETTINGS are remembered for the partition, `await_ready(owner,
  timeout, :early)` returns before the handshake completes and opens marked
  `early_data: true` are admitted as early requests; other opens wait for the
  handshake. An early open that the session cannot admit is queued for the
  handshake instead. Opens marked `connection_info: true` receive a
  `{:connection_info, %{resumed: boolean, early_data: boolean}}` event before
  their response headers.
  """
  use GenServer
  alias QuicHttp3.Session

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, Keyword.put_new(opts, :creator, self()))

  def activate(owner, token), do: GenServer.call(owner, {:activate, token})
  def await_ready(owner, timeout \\ 5_000), do: GenServer.call(owner, :await_ready, timeout)

  def await_ready(owner, timeout, :early),
    do: GenServer.call(owner, {:await_ready, :early}, timeout)

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

  def send_trailers(owner, ref, fields, recipient, write_ref),
    do: GenServer.cast(owner, {:write, ref, {:trailers, fields}, true, recipient, write_ref})

  def acknowledge(owner, ref), do: GenServer.cast(owner, {:ack, ref})

  def cancel_open(owner, subscriber, generation),
    do: GenServer.cast(owner, {:cancel_open, subscriber, generation})

  def cancel(owner, ref), do: GenServer.call(owner, {:cancel, ref})

  @doc """
  Retires every request and queued open of `subscriber`, then reports settlement.

  Returns `:settled` only when no demux entry, native session request among
  `refs`, or queued/pending/suspended action remains for that subscriber.
  Otherwise returns `{:pending, refs}`, including any refs retired by this call.
  """
  def settle(owner, subscriber, refs, timeout),
    do: GenServer.call(owner, {:settle, subscriber, refs}, timeout)

  def status(owner), do: GenServer.call(owner, :status)

  @doc """
  Runs one WebTransport operation for the accepted `webtransport-h3` CONNECT `ref`.

  Only that CONNECT's subscriber may call. Operations are serialized with all
  other native work under the absolute deadline `timeout` from now and are never
  replayed: `{:open, :bidi | :uni}` returns `{:ok, stream_key}`; `{:send, key,
  bytes, fin}`, `{:reset, key, code}`, `{:stop, key, code}`, `{:datagram,
  bytes}` and `{:close, code, reason}` return `:ok`. `:info` reads the session
  identity and DATAGRAM payload limit.
  """
  def webtransport(owner, ref, op, timeout) when is_integer(timeout) and timeout > 0,
    do: GenServer.call(owner, {:webtransport, ref, op, now() + timeout}, timeout + 1_000)

  @doc "Releases owner delivery credit retained for a WT event receipt."
  def webtransport_ack(owner, ref, receipt),
    do: GenServer.cast(owner, {:webtransport_ack, ref, receipt})

  @impl true
  def init(opts) do
    {:ok, opts} = HTTP.HTTP3.ReceiveBudget.normalize(opts)
    timeout = Keyword.get(opts, :operation_timeout, 1_000)

    opening_deadline =
      Keyword.get(opts, :opening_deadline_at, now() + Keyword.get(opts, :connect_timeout, 5_000))

    request_deadline = Keyword.get(opts, :deadline_at)
    session_opts = Keyword.put(Keyword.get(opts, :session_options, []), :timeout, timeout)

    session_opts =
      if opts[:cleanup],
        do: Keyword.put(session_opts, :cleanup, opts[:cleanup]),
        else: session_opts

    session_opts =
      if opts[:opening_deadline_at],
        do: Keyword.put(session_opts, :deadline, {:abs_ms, opening_deadline}),
        else: session_opts

    {:ok, session} = Session.new(session_opts)
    inert? = Keyword.get(opts, :inert, false)

    state = %{
      session: session,
      opts: opts,
      watchdog: nil,
      watchdog_monitor: nil,
      tracker_monitor:
        if(opts[:request_lifecycle], do: Process.monitor(opts[:request_lifecycle])),
      creator_monitor: if(inert?, do: Process.monitor(opts[:creator])),
      activation: opts[:activation],
      cleanup: opts[:cleanup],
      exclusive?: Keyword.get(opts, :exclusive?, false),
      lease_token: nil,
      request_deadline: request_deadline,
      timeout: timeout,
      lifecycle: if(inert?, do: :inert, else: :connecting),
      ready_waiters: [],
      requests: %{},
      pending: nil,
      continuations: [],
      queue: [],
      allocations: 0,
      extension_bytes: 0,
      writable_epoch: 0,
      continuation_turn?: true,
      max_streams: Keyword.get(opts, :max_streams, 32),
      rotation: Keyword.get(opts, :rotation_after, 960),
      pool: nil,
      pool_monitor: nil,
      last_activity: now(),
      idle_timeout: Keyword.get(opts, :idle_timeout, 30_000),
      opening_deadline: opening_deadline,
      resumption: opts[:resumption],
      partition: nil,
      remembered: nil,
      early: nil,
      resumed: false
    }

    if inert?, do: {:ok, state}, else: {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    owner = self()

    {:ok, watchdog} =
      HTTP.RequestLifecycle.start_worker(
        state.opts[:request_lifecycle],
        :http3_watchdog,
        state.opening_deadline,
        fn -> watchdog(owner, state.cleanup, state.opts[:request_lifecycle]) end
      )

    state = %{state | watchdog: watchdog, watchdog_monitor: Process.monitor(watchdog)}
    {state, endpoint} = checkout_resumption(state)

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
            :operation_timeout,
            :deadline_at,
            :opening_deadline_at,
            :exclusive?,
            :inert,
            :activation,
            :creator,
            :request_lifecycle,
            :session_options,
            :webtransport,
            :resumption
          ])
          |> Keyword.merge(endpoint)
          |> Keyword.put(:deadline, {:abs_ms, state.opening_deadline})
          |> Keyword.put(:timeout, min(state.timeout, max(state.opening_deadline - now(), 1)))
        )
      end)

    next = state |> result(:connect, result) |> offer_early()
    Process.send_after(self(), :tick, 1)
    {:noreply, next}
  end

  # The shared endpoint is configured exactly as the owned endpoint `connect`
  # would otherwise create, plus the runtime resumption policy.
  defp checkout_resumption(%{resumption: %{early: early?}} = state) do
    client =
      Keyword.take(state.opts, [:host, :tls, :profile, :streams, :datagram, :socket, :limits])

    case HTTP.HTTP3.Resumption.checkout(client, state.opts[:port], early?) do
      {:ok, endpoint, partition, remembered} ->
        {%{state | partition: partition, remembered: remembered}, [endpoint: endpoint]}

      {:error, _reason} ->
        {%{state | resumption: nil}, []}
    end
  end

  defp checkout_resumption(state), do: {state, []}

  defp offer_early(%{resumption: %{early: true}, remembered: remembered} = state)
       when is_list(remembered) do
    if state.lifecycle == :connecting and state.pending == nil and
         Session.early_offered?(state.session),
       do: %{state | early: :offered},
       else: state
  end

  defp offer_early(state), do: state

  defp early_open?(state, {:open, _from, _subscriber, _generation, _fields, body, opts}) do
    state.early == :offered and state.lifecycle == :connecting and state.pending == nil and
      state.queue == [] and opts[:early_data] == true and body == "" and
      opts[:purpose] != :extended_connect
  end

  defp early_open?(_state, _action), do: false

  @impl true
  def handle_call({:activate, token}, {creator, _}, %{lifecycle: :inert} = state) do
    cond do
      token != state.activation or creator != state.opts[:creator] ->
        {:reply, {:error, :invalid_activation}, state}

      now() >= state.opening_deadline ->
        {:stop, :normal, {:error, :opening_timeout}, state}

      true ->
        {:reply, :ok, %{state | lifecycle: :connecting}, {:continue, :connect}}
    end
  end

  def handle_call({:activate, _}, _from, state), do: {:reply, {:error, :already_activated}, state}

  def handle_call(:await_ready, _from, %{lifecycle: :inert} = state),
    do: {:reply, {:error, :owner_inert}, state}

  def handle_call(:await_ready, _from, %{lifecycle: :ready} = state), do: {:reply, :ok, state}

  def handle_call(:await_ready, from, state),
    do: {:noreply, %{state | ready_waiters: [from | state.ready_waiters]}}

  def handle_call({:await_ready, :early}, from, state) do
    if state.early == :offered and state.lifecycle == :connecting,
      do: {:reply, :ok, state},
      else: handle_call(:await_ready, from, state)
  end

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
       extension_bytes: state.extension_bytes,
       endpoint: endpoint,
       watchdog: state.watchdog,
       exclusive?: state.exclusive?,
       request_deadline: state.request_deadline,
       opening_deadline: state.opening_deadline
     }, state}
  end

  def handle_call({:open, _, _, _, _, _}, _from, %{lifecycle: :inert} = state),
    do: {:reply, {:error, :owner_inert}, state}

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

  def handle_call({:webtransport, _ref, _op, _deadline}, _from, %{lifecycle: :inert} = state),
    do: {:reply, {:error, :owner_inert}, state}

  def handle_call({:webtransport, ref, op, deadline}, {caller, _} = from, state) do
    case state.requests[ref] do
      %{subscriber: ^caller, protocol: "webtransport-h3"} when op == :info ->
        {:reply, QuicHttp3.Session.webtransport_info(state.session), state}

      %{subscriber: ^caller, protocol: "webtransport-h3"} ->
        {:noreply, enqueue(state, {:webtransport, from, ref, op, deadline})}

      _ ->
        {:reply, {:error, :unknown_webtransport_session}, state}
    end
  end

  def handle_call({:cancel, ref}, _from, state) do
    next = remove_request(state, ref)
    action = {:cancel, ref}
    {:reply, :ok, enqueue(next, action)}
  end

  def handle_call({:settle, subscriber, refs}, _from, state) do
    {opens, queue} =
      Enum.split_with(state.queue, &match?({:open, _, ^subscriber, _, _, _, _}, &1))

    state = Enum.reduce(opens, %{state | queue: queue}, &reject(&2, &1, :aborted))
    owned = for {ref, %{subscriber: ^subscriber}} <- state.requests, do: ref

    state =
      Enum.reduce(owned, state, fn ref, acc ->
        enqueue(remove_request(acc, ref), {:cancel, ref})
      end)

    refs = Enum.uniq(owned ++ refs)

    settled? =
      owned == [] and not Enum.any?(refs, &Map.has_key?(state.session.requests, &1)) and
        not Enum.any?(actions(state), &involves?(&1, subscriber, refs))

    {:reply, if(settled?, do: :settled, else: {:pending, refs}), state}
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

  def handle_cast({:webtransport_ack, ref, receipt}, state) do
    next =
      with %{protocol: "webtransport-h3"} <- state.requests[ref],
           {:ok, session} <- Session.webtransport_acknowledge(state.session, receipt) do
        %{state | session: session}
      else
        _ -> state
      end

    {:noreply, touch(next)}
  end

  def handle_cast({:ack, ref}, state) do
    next =
      if Map.has_key?(state.requests, ref),
        do: release_credit(state, ref),
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

  def handle_info(
        {:http3_retire, pool, token},
        %{pool: pool, lease_token: token, exclusive?: true} = state
      ) do
    retire_native(state.cleanup)
    {:stop, :normal, %{state | lifecycle: :retiring}}
  end

  def handle_info({:http3_retire, _, _}, state), do: {:noreply, state}

  def handle_info({:http3_pool, pool, key, token, exclusive?}, state) do
    {:noreply, next} = handle_info({:http3_pool, pool, key}, state)
    {:noreply, %{next | lease_token: token, exclusive?: exclusive?}}
  end

  def handle_info({:http3_pool, pool, _key}, state) do
    if state.pool_monitor, do: Process.demonitor(state.pool_monitor, [:flush])
    if state.lifecycle == :draining, do: HTTP.HTTP3.Pool.drain(pool, self())
    {:noreply, %{state | pool: pool, pool_monitor: Process.monitor(pool)}}
  end

  def handle_info(:http3_pool_down, state), do: {:stop, :normal, state}

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state)
      when monitor == state.watchdog_monitor or monitor == state.tracker_monitor or
             (monitor == state.creator_monitor and state.pool == nil) do
    retire_native(state.cleanup)
    {:stop, :normal, state}
  end

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

    if state.cleanup do
      retire_native(state.cleanup)
    else
      if state.session.connection && state.watchdog,
        do: guarded(state, state.timeout, fn -> Session.abort(state.session) end)
    end

    stop_watchdog(state.watchdog, state.watchdog_monitor)
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

    cond do
      state.lifecycle == :ready and state.pending == nil and state.queue == [] ->
        perform(state, action)

      early_open?(state, action) ->
        perform_early(state, action)

      true ->
        queue(state, action)
    end
  end

  defp queue(state, action) do
    if length(state.queue) < 128,
      do: %{state | queue: state.queue ++ [action]},
      else: reject(state, action, :owner_queue_full)
  end

  # A definite early admission failure leaves no native work behind, so the
  # open waits for the handshake like any other.
  defp perform_early(state, {:open, _from, subscriber, _generation, fields, body, opts} = action) do
    if Process.alive?(subscriber) do
      response =
        guarded(
          state,
          min(state.timeout, Keyword.get(opts, :timeout, state.timeout)),
          fn ->
            Session.request(
              state.session,
              fields,
              body,
              Keyword.put(opts, :early_data, state.remembered)
            )
          end,
          action
        )

      case response do
        {:error, session, _reason} when session.pending == nil ->
          queue(%{state | session: session, early: :unavailable}, action)

        response ->
          result(state, action, response)
      end
    else
      reject(state, action, :subscriber_down)
    end
  end

  defp perform(state, {:open, _from, subscriber, _generation, fields, body, opts} = action) do
    cond do
      not Process.alive?(subscriber) ->
        reject(state, action, :subscriber_down)

      opts[:deadline_at] != nil and opts[:deadline_at] != :infinity and
          now() >= opts[:deadline_at] ->
        reject(state, action, :opening_timeout)

      opts[:purpose] == :extended_connect and
          QuicHttp3.Connect.ready(state.session.control) == :pending ->
        %{state | queue: state.queue ++ [action]}

      true ->
        result(
          state,
          action,
          guarded(
            state,
            min(state.timeout, Keyword.get(opts, :timeout, state.timeout)),
            fn ->
              if opts[:purpose] == :extended_connect,
                do: Session.extended_connect(state.session, opts[:protocol], fields, opts),
                else: Session.request(state.session, fields, body, opts)
            end,
            action
          )
        )
    end
  end

  defp perform(state, {:write, ref, bytes, fin, _recipient, _write_ref} = action) do
    deadline =
      case state.requests[ref] do
        %{deadline: deadline} -> deadline
        _ -> nil
      end

    if is_integer(deadline) and now() >= deadline do
      reject(state, action, :request_timeout)
    else
      opts = if is_integer(deadline), do: [deadline: {:abs_ms, deadline}], else: []

      budget =
        if is_integer(deadline),
          do: min(state.timeout, max(deadline - now(), 1)),
          else: state.timeout

      result(
        state,
        action,
        guarded(state, budget, fn -> write(state.session, ref, bytes, fin, opts) end)
      )
    end
  end

  defp perform(state, {:webtransport, _from, ref, op, deadline} = action) do
    cond do
      now() >= deadline ->
        reject(state, action, :operation_timeout)

      not Map.has_key?(state.requests, ref) ->
        reject(state, action, :unknown_webtransport_session)

      true ->
        opts = [deadline: {:abs_ms, deadline}]

        result(
          state,
          action,
          guarded(
            state,
            min(state.timeout, max(deadline - now(), 1)),
            fn -> webtransport_call(state.session, op, opts) end,
            action
          )
        )
    end
  end

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

  defp webtransport_call(session, {:open, kind}, opts),
    do: Session.webtransport_open(session, kind, opts)

  defp webtransport_call(session, {:send, key, bytes, fin}, opts),
    do: Session.webtransport_send(session, key, bytes, fin, opts)

  defp webtransport_call(session, {:reset, key, code}, opts),
    do: Session.webtransport_reset(session, key, code, opts)

  defp webtransport_call(session, {:stop, key, code}, opts),
    do: Session.webtransport_stop(session, key, code, opts)

  defp webtransport_call(session, {:datagram, bytes}, opts),
    do: Session.webtransport_datagram(session, bytes, opts)

  defp webtransport_call(session, {:close, code, reason}, opts),
    do: Session.webtransport_close(session, code, reason, opts)

  defp webtransport_call(session, _op, _opts), do: {:error, session, :invalid_operation}

  defp write(session, ref, {:trailers, fields}, true, opts),
    do: Session.send_trailers(session, ref, fields, opts)

  defp write(session, ref, bytes, fin, opts),
    do: Session.send_data(session, ref, bytes, fin, opts)

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

    deadline =
      if state.exclusive? and is_integer(state.request_deadline),
        do: {:abs_ms, state.request_deadline}

    session = %{session | deadline: deadline}
    resumed = state.resumption != nil and Session.resumed?(session)

    %{
      state
      | session: session,
        lifecycle: :ready,
        ready_waiters: [],
        pending: nil,
        early: nil,
        resumed: resumed
    }
  end

  defp apply_result(state, :poll, {:ok, session, events}) do
    Enum.reduce(events, %{state | session: session, pending: nil}, &event/2)
  end

  defp apply_result(
         state,
         {:open, from, subscriber, generation, _fields, _body, opts},
         {:ok, session, ref}
       ) do
    monitor = Process.monitor(subscriber)

    request = %{
      subscriber: subscriber,
      generation: generation,
      purpose: opts[:purpose],
      protocol: opts[:protocol],
      data_bytes: 0,
      deadline: opts[:request_deadline_at],
      monitor: monitor,
      paused: false,
      headers_pending?: false,
      deferred: [],
      info?: opts[:connection_info] == true
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

  defp apply_result(state, {:webtransport, from, _, _, _}, {:ok, session, key}) do
    GenServer.reply(from, {:ok, key})
    %{state | session: session, pending: nil}
  end

  defp apply_result(state, {:webtransport, from, _, _, _}, {:ok, session}) do
    GenServer.reply(from, :ok)
    %{state | session: session, pending: nil}
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

  # Session-associated WT deliveries; byte credit stays in the Session router
  # until the subscriber returns the receipt through webtransport_ack/3.
  defp dispatch_event({:wt, ref, event}, state), do: deliver(state, ref, {:wt, event})

  defp dispatch_event({:headers, ref, fields}, state) do
    {":status", value} = List.keyfind(fields, ":status", 0)
    event({:headers, ref, String.to_integer(value), List.keydelete(fields, ":status", 0)}, state)
  end

  defp dispatch_event({:settings, settings}, state) do
    if state.partition, do: HTTP.HTTP3.Resumption.remember(state.partition, settings)
    state
  end

  defp dispatch_event({:headers, ref, status, fields}, state) do
    if match?(%{info?: true}, state.requests[ref]),
      do:
        notify(
          state,
          ref,
          {:connection_info,
           %{resumed: state.resumed, early_data: Session.early_data?(state.session, ref)}}
        )

    tunnel? = match?(%{purpose: :extended_connect}, state.requests[ref]) and status in 200..299
    if tunnel?, do: notify(state, ref, {:headers, status, fields})
    if tunnel?, do: state, else: response_headers(state, ref, status, fields)
  end

  defp dispatch_event({:informational, ref, status, fields}, state),
    do: deliver(state, ref, {:informational, status, fields})

  defp dispatch_event({:trailers, ref, fields}, state),
    do: deliver(state, ref, {:trailers, fields})

  defp dispatch_event({:data, ref, bytes}, state) do
    request = state.requests[ref]
    tunnel? = match?(%{purpose: :extended_connect}, request)

    if tunnel? and state.extension_bytes + byte_size(bytes) > 262_144 do
      notify(state, ref, {:error, :consumer_overloaded})
      enqueue(remove_request(state, ref), {:cancel, ref})
    else
      notify(state, ref, {:data, bytes})
      state = touch(state)

      if request do
        next = put_in(state.requests[ref].paused, true)

        if tunnel? do
          next = put_in(next.requests[ref].data_bytes, request.data_bytes + byte_size(bytes))
          %{next | extension_bytes: next.extension_bytes + byte_size(bytes)}
        else
          next
        end
      else
        state
      end
    end
  end

  defp dispatch_event({:done, ref}, state) do
    notify(state, ref, :done)

    if match?(%{purpose: :extended_connect}, state.requests[ref]),
      do: state,
      else: remove_request(state, ref)
  end

  defp dispatch_event({:stream_error, ref, code, reason}, state),
    do: event({:stream_error, ref, {:http3_error, :stream, code, reason}}, state)

  defp dispatch_event({:stream_error, ref, reason}, state) do
    notify(state, ref, {:error, reason})
    remove_request(state, ref)
  end

  defp dispatch_event({:stream_reset, ref, code, final_size}, state),
    do: event({:stream_error, ref, {:reset, code, final_size}}, state)

  defp dispatch_event({:stopped, ref, code}, state) do
    if match?(%{purpose: :extended_connect}, state.requests[ref]) do
      notify(state, ref, {:error, {:stop_sending, code}})
      enqueue(remove_request(state, ref), {:cancel, ref})
    else
      enqueue(state, {:reset_send, ref})
    end
  end

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

  defp response_headers(state, ref, status, fields) do
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

  defp release_credit(state, ref) do
    request = state.requests[ref]
    next = put_in(state.requests[ref], %{request | paused: false, data_bytes: 0})
    %{next | extension_bytes: max(0, next.extension_bytes - request.data_bytes)}
  end

  defp remove_request(state, ref) do
    case Map.pop(state.requests, ref) do
      {nil, _} ->
        state

      {request, requests} ->
        Process.demonitor(request.monitor, [:flush])

        touch(%{
          state
          | requests: requests,
            extension_bytes: max(0, state.extension_bytes - request.data_bytes)
        })
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

  defp reject(state, {:webtransport, from, _, _, _}, reason) do
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

  defp open_count(state),
    do: Enum.count(actions(state), &match?({:open, _, _, _, _, _, _}, &1))

  defp actions(state) do
    state.queue ++
      Enum.map(state.continuations, &elem(&1, 0)) ++
      if(state.pending, do: [state.pending], else: [])
  end

  defp involves?({:open, _, subscriber, _, _, _, _}, subscriber, _refs), do: true
  defp involves?({:open, _, _, _, _, _, _}, _subscriber, _refs), do: false

  defp involves?(action, _subscriber, refs) when is_tuple(action),
    do: tuple_size(action) >= 2 and elem(action, 1) in refs

  defp involves?(_action, _subscriber, _refs), do: false

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

  defp watchdog(owner, cleanup, tracker) do
    monitor = Process.monitor(owner)
    tracker_monitor = if tracker, do: Process.monitor(tracker)

    receive do
      {:arm, token, timeout, recipients, operation} ->
        receive do
          {:disarm, ^token} ->
            Process.demonitor(monitor, [:flush])
            if tracker_monitor, do: Process.demonitor(tracker_monitor, [:flush])
            watchdog(owner, cleanup, tracker)

          {:DOWN, ^monitor, :process, _, _} ->
            retire_native(cleanup)

          {:DOWN, ^tracker_monitor, :process, _, _} ->
            retire_native(cleanup)
            Process.exit(owner, :kill)

          :stop ->
            :ok
        after
          timeout ->
            if operation, do: Enum.each(recipients, &send(&1, {:http3_indeterminate, operation}))
            retire_native(cleanup)
            Process.exit(owner, :kill)
        end

      {:DOWN, ^monitor, :process, _, _} ->
        retire_native(cleanup)

      {:DOWN, ^tracker_monitor, :process, _, _} ->
        retire_native(cleanup)
        Process.exit(owner, :kill)

      :stop ->
        :ok
    end
  end

  defp retire_native(%{lease: lease}) do
    _ = Quic.Cleanup.retire(lease, {:abs_ms, now()})
    :ok
  end

  defp retire_native(nil), do: :ok

  defp stop_watchdog(nil, _monitor), do: :ok

  defp stop_watchdog(watchdog, monitor) do
    send(watchdog, :stop)

    receive do
      {:DOWN, ^monitor, :process, ^watchdog, _} -> :ok
    after
      1_000 -> Process.exit(watchdog, :kill)
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end

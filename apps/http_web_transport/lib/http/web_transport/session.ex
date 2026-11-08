defmodule HTTP.WebTransport.Session do
  @moduledoc false

  use GenServer

  alias HTTP.WebTransport
  alias HTTP.WebTransport.BidirectionalStream
  alias HTTP.WebTransport.CloseInfo
  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.ReceiveStream
  alias HTTP.WebTransport.SendStream
  alias HTTP.WebTransport.Stats
  alias HTTP.WebTransport.Telemetry

  defstruct owner: nil,
            owner_monitor: nil,
            operations: %{},
            operation_order: [],
            backend_closed: false,
            backend_close_result: nil,
            target: nil,
            uri: nil,
            url: nil,
            backend: nil,
            options: nil,
            session_ref: nil,
            state: :connecting,
            reliability: "pending",
            congestion_control: :default,
            response_headers: nil,
            protocol: "",
            max_datagram_size: 64 * 1024,
            max_incoming_datagrams: 1_024,
            max_outgoing_datagrams: 1_024,
            incoming_datagrams_max_age: nil,
            outgoing_datagrams_max_age: nil,
            ready_status: :pending,
            ready_waiters: [],
            closed_status: :pending,
            closed_waiters: [],
            draining_status: :pending,
            draining_waiters: [],
            datagram_queue: [],
            datagram_waiters: [],
            outgoing_datagrams: [],
            incoming_bidi_queue: [],
            incoming_bidi_waiters: [],
            incoming_uni_queue: [],
            incoming_uni_waiters: [],
            streams: %{},
            stats: %Stats{},
            connect_started_at: nil

  @type waiter :: %{from: GenServer.from(), timer: reference() | nil, monitor: reference()}

  @spec start_link(Options.t()) :: GenServer.on_start()
  def start_link(%Options{} = options) do
    GenServer.start_link(__MODULE__, options)
  end

  def child_spec(%Options{ref: ref} = options) do
    %{
      id: {__MODULE__, ref},
      start: {__MODULE__, :start_link, [options]},
      restart: :temporary,
      type: :worker
    }
  end

  @impl true
  def init(%Options{} = options) do
    target = %WebTransport{pid: self(), ref: options.ref, url: options.url}

    state = %__MODULE__{
      owner: options.owner,
      owner_monitor: Process.monitor(options.owner),
      target: target,
      uri: options.uri,
      url: options.url,
      backend: options.backend,
      options: options,
      congestion_control: options.congestion_control,
      max_datagram_size: options.max_datagram_size,
      max_incoming_datagrams: options.max_incoming_datagrams,
      max_outgoing_datagrams: options.max_outgoing_datagrams
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    started_at = System.monotonic_time(:microsecond)
    Telemetry.connect_start(state.uri)

    case state.backend.connect(state.uri, state.options) do
      {:ok, session_ref, info} ->
        duration = System.monotonic_time(:microsecond) - started_at
        state = connect_success(state, session_ref, info, duration)
        {:noreply, state}

      {:error, reason} ->
        duration = System.monotonic_time(:microsecond) - started_at
        Telemetry.connect_exception(state.uri, reason, duration)
        {:noreply, fail_session(state, reason)}
    end
  end

  @impl true
  def handle_call({:operation_status, ref}, _from, state) do
    {:reply, Map.get(state.operations, ref, :unknown), state}
  end

  def handle_call({:operation, ref, deadline, request}, from, state) do
    case Map.fetch(state.operations, ref) do
      {:ok, result} ->
        {:reply, result, state}

      :error ->
        if System.monotonic_time(:millisecond) >= deadline do
          reply = {:error, :deadline_exceeded}
          {:reply, reply, retain_operation(state, ref, reply)}
        else
          {:reply, reply, state} = handle_call(request, from, state)
          {:reply, reply, retain_operation(state, ref, reply)}
        end
    end
  end

  def handle_call(:state, _from, state), do: {:reply, state.state, state}
  def handle_call(:reliability, _from, state), do: {:reply, state.reliability, state}

  def handle_call(:congestion_control, _from, state),
    do: {:reply, state.congestion_control, state}

  def handle_call(:response_headers, _from, state), do: {:reply, state.response_headers, state}
  def handle_call(:protocol, _from, state), do: {:reply, state.protocol, state}
  def handle_call(:max_datagram_size, _from, state), do: {:reply, state.max_datagram_size, state}

  def handle_call(:incoming_datagrams_max_age, _from, state),
    do: {:reply, state.incoming_datagrams_max_age, state}

  def handle_call(:outgoing_datagrams_max_age, _from, state),
    do: {:reply, state.outgoing_datagrams_max_age, state}

  def handle_call({:set_incoming_datagrams_max_age, age}, _from, state) do
    case normalize_age(age) do
      {:ok, age} -> {:reply, :ok, %{state | incoming_datagrams_max_age: age}}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:set_outgoing_datagrams_max_age, age}, _from, state) do
    case normalize_age(age) do
      {:ok, age} -> {:reply, :ok, %{state | outgoing_datagrams_max_age: age}}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:await, _kind, timeout}, _from, state)
      when timeout != :infinity and (not is_integer(timeout) or timeout < 0),
      do: {:reply, {:error, :invalid_timeout}, state}

  def handle_call({:await, kind, timeout}, from, state) do
    case promise_status(state, kind) do
      :pending ->
        cond do
          timeout == 0 ->
            {:reply, {:error, :timeout}, state}

          waiter_count(state) >= state.options.max_pending_waiters ->
            {:reply, {:error, :backpressure}, state}

          true ->
            {:noreply, add_promise_waiter(state, kind, from, timeout)}
        end

      {:resolved, value} ->
        {:reply, resolved_reply(kind, value), state}

      {:rejected, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:send_datagram, bytes, options}, _from, state) when is_binary(bytes) do
    {:reply, reply, state} = send_datagram(bytes, options, state)
    {:reply, reply, state}
  end

  def handle_call({:read_datagram, timeout}, _from, state)
      when timeout != :infinity and (not is_integer(timeout) or timeout < 0),
      do: {:reply, {:error, :invalid_timeout}, state}

  def handle_call({:read_stream_queue, _kind, timeout}, _from, state)
      when timeout != :infinity and (not is_integer(timeout) or timeout < 0),
      do: {:reply, {:error, :invalid_timeout}, state}

  def handle_call({:read_stream, _ref, timeout}, _from, state)
      when timeout != :infinity and (not is_integer(timeout) or timeout < 0),
      do: {:reply, {:error, :invalid_timeout}, state}

  def handle_call({:read_datagram, timeout}, from, state) do
    read_queued(:datagram, timeout, from, state)
  end

  def handle_call({:read_stream_queue, kind, timeout}, from, state) do
    read_queued(kind, timeout, from, state)
  end

  def handle_call({:create_bidirectional_stream, options}, _from, state) do
    case create_stream(:bidirectional, options, state) do
      {:ok, stream, state} -> {:reply, {:ok, stream}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:create_unidirectional_stream, options}, _from, state) do
    case create_stream(:unidirectional, options, state) do
      {:ok, stream, state} -> {:reply, {:ok, stream}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:send_stream, stream_ref, data, options}, _from, state) do
    with {:ok, bytes} <- normalize_iodata(data),
         :ok <- ensure_writable_state(state),
         :ok <- ensure_send_stream(state, stream_ref),
         :ok <- ensure_send_size(state, bytes),
         :ok <- state.backend.send_stream(stream_ref, bytes, options) do
      Telemetry.stream_sent(state.uri, stream_ref, byte_size(bytes))
      state = update_stats(state, :sent, byte_size(bytes))
      {:reply, :ok, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:close_send_stream, stream_ref}, _from, state) do
    {reply, state} =
      finish_send(state, stream_ref, fn -> state.backend.close_send_stream(stream_ref) end)

    if reply == :ok, do: Telemetry.stream_closed(state.uri, stream_ref)
    {:reply, reply, state}
  end

  def handle_call({:abort_send_stream, stream_ref, code}, _from, state) do
    {reply, state} =
      finish_send(state, stream_ref, fn -> state.backend.abort_send_stream(stream_ref, code) end)

    {:reply, reply, state}
  end

  def handle_call({:cancel_receive_stream, stream_ref, code}, _from, state) do
    case Map.fetch(state.streams, stream_ref) do
      {:ok, %{readable: true, terminal: nil} = stream} ->
        reply =
          backend_or_invalid_state(state, fn ->
            state.backend.cancel_receive_stream(stream_ref, code)
          end)

        state =
          if reply == :ok do
            Enum.each(stream.credits, &acknowledge(state, &1))
            state = put_stream_state(state, stream_ref, %{stream | queue: [], credits: []})
            deliver_stream(stream_ref, {:error, :cancelled}, state)
          else
            state
          end

        {:reply, reply, state}

      _ ->
        {:reply, {:error, :invalid_state}, state}
    end
  end

  def handle_call({:read_stream, stream_ref, timeout}, from, state) do
    read_stream(stream_ref, timeout, from, state)
  end

  def handle_call(:get_stats, _from, %{session_ref: nil} = state) do
    {:reply, {:ok, state.stats}, state}
  end

  def handle_call(:get_stats, _from, state) do
    case state.backend.get_stats(state.session_ref) do
      {:ok, stats} -> {:reply, {:ok, stats}, state}
      {:error, _reason} -> {:reply, {:ok, state.stats}, state}
    end
  end

  def handle_call({:close, close_info}, _from, state) do
    state = close_session(state, close_info)

    reply =
      case state.backend_close_result do
        {:error, reason} -> {:error, {:cleanup_failed, reason}}
        _ -> :ok
      end

    {:reply, reply, state}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, _pid, _reason}, %{owner_monitor: monitor} = state) do
    {:stop, :normal, close_session(state, %CloseInfo{reason: "owner exited"})}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason} = message, state) do
    case backend_message(state, message) do
      {:ok, events} -> {:noreply, apply_backend_events(events, state)}
      :ignore -> {:noreply, remove_dead_waiters(state, monitor)}
    end
  end

  def handle_info(_message, %{state: status} = state) when status in [:closed, :failed],
    do: {:noreply, state}

  def handle_info({:webtransport_draining, session_ref}, state)
      when session_ref == state.session_ref do
    {:noreply, drain_session(state)}
  end

  def handle_info({:webtransport_closed, session_ref, close_info}, state)
      when session_ref == state.session_ref do
    {:noreply, close_session(state, normalize_close_info(close_info))}
  end

  def handle_info({:webtransport_failed, session_ref, reason}, state)
      when session_ref == state.session_ref do
    {:noreply, fail_session(state, reason)}
  end

  def handle_info({:webtransport_datagram, session_ref, bytes}, state)
      when session_ref == state.session_ref and is_binary(bytes) do
    {:noreply, receive_datagram(bytes, state)}
  end

  def handle_info({:webtransport_incoming_bidi_stream, session_ref, stream_ref}, state)
      when session_ref == state.session_ref do
    {:noreply, admit_incoming(:incoming_bidirectional, stream_ref, state)}
  end

  def handle_info({:webtransport_incoming_uni_stream, session_ref, stream_ref}, state)
      when session_ref == state.session_ref do
    {:noreply, admit_incoming(:incoming_unidirectional, stream_ref, state)}
  end

  def handle_info({:webtransport_stream_data, stream_ref, bytes}, state) when is_binary(bytes) do
    {:noreply, deliver_stream(stream_ref, {:data, bytes}, state)}
  end

  def handle_info({:webtransport_stream_data, stream_ref, bytes, receipt}, state)
      when is_binary(bytes) do
    {:noreply, deliver_stream(stream_ref, {:data, bytes}, state, receipt)}
  end

  def handle_info({:webtransport_send_stopped, stream_ref, _code}, state) do
    case Map.fetch(state.streams, stream_ref) do
      {:ok, %{writable: true} = stream} ->
        {:noreply, put_stream_state(state, stream_ref, %{stream | send_closed: true})}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:webtransport_stream_fin, stream_ref}, state) do
    {:noreply, deliver_stream(stream_ref, :fin, state)}
  end

  def handle_info({:webtransport_stream_error, stream_ref, reason}, state) do
    {:noreply, deliver_stream(stream_ref, {:error, reason}, state)}
  end

  def handle_info({:promise_timeout, kind, from}, state) do
    case remove_waiter(promise_waiters(state, kind), from) do
      {:ok, waiter, rest} ->
        release_waiter(waiter)
        GenServer.reply(from, {:error, :timeout})
        {:noreply, put_promise(state, kind, promise_status(state, kind), rest)}

      :not_found ->
        {:noreply, state}
    end
  end

  def handle_info({:waiter_timeout, kind, from}, state) do
    {:noreply, timeout_waiter(kind, from, state)}
  end

  def handle_info({:stream_waiter_timeout, stream_ref, from}, state) do
    {:noreply, timeout_stream_waiter(stream_ref, from, state)}
  end

  def handle_info(message, state) do
    case backend_message(state, message) do
      {:ok, events} -> {:noreply, apply_backend_events(events, state)}
      :ignore -> {:noreply, state}
    end
  end

  # Backends with push delivery translate their own messages into the session
  # events above; unknown messages are ignored.
  defp backend_message(%{session_ref: nil}, _message), do: :ignore

  defp backend_message(state, message) do
    if function_exported?(state.backend, :handle_message, 2),
      do: state.backend.handle_message(state.session_ref, message),
      else: :ignore
  end

  defp apply_backend_events(events, state) do
    Enum.reduce(events, state, fn event, acc ->
      {:noreply, next} = handle_info(event, acc)
      next
    end)
  end

  defp acknowledge(_state, nil), do: :ok

  defp acknowledge(state, receipt) do
    if function_exported?(state.backend, :acknowledge, 2),
      do: state.backend.acknowledge(state.session_ref, receipt)

    :ok
  end

  defp connect_success(state, session_ref, info, duration) do
    protocol = Map.get(info, :protocol, "")
    reliability = Map.get(info, :reliability, "supports-unreliable")
    response_headers = Map.get(info, :response_headers, [])

    max_datagram_size =
      min(Map.get(info, :max_datagram_size, state.max_datagram_size), state.max_datagram_size)

    Telemetry.connect_stop(state.uri, protocol, reliability, duration)

    state
    |> Map.merge(%{
      session_ref: session_ref,
      state: :connected,
      protocol: protocol,
      reliability: reliability,
      response_headers: response_headers,
      max_datagram_size: max_datagram_size,
      connect_started_at: System.monotonic_time(:microsecond)
    })
    |> resolve_promise(:ready, :ok)
    |> flush_outgoing_datagrams()
    |> emit({:state, :connected})
  end

  defp send_datagram(_bytes, _options, %{state: status} = state)
       when status in [:closed, :failed],
       do: {:reply, {:error, :invalid_state}, state}

  defp send_datagram(bytes, _options, state) when byte_size(bytes) > state.max_datagram_size do
    datagrams = Map.update!(state.stats.datagrams, :dropped, fn count -> count + 1 end)
    stats = %{state.stats | datagrams: datagrams}

    {:reply, :ok, %{state | stats: stats}}
  end

  defp send_datagram(bytes, options, %{state: :connecting} = state) do
    if length(state.outgoing_datagrams) >= state.max_outgoing_datagrams or
         not buffer_fits?(state, byte_size(bytes), 1) do
      {:reply, {:error, :backpressure}, state}
    else
      {:reply, :ok, %{state | outgoing_datagrams: state.outgoing_datagrams ++ [{bytes, options}]}}
    end
  end

  defp send_datagram(bytes, options, state) do
    case state.backend.send_datagram(state.session_ref, bytes, options) do
      :ok ->
        Telemetry.datagram_sent(state.uri, byte_size(bytes), length(state.outgoing_datagrams))
        state = update_stats(state, :datagram_sent, byte_size(bytes))
        {:reply, :ok, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  defp receive_datagram(bytes, state) when byte_size(bytes) > state.max_datagram_size, do: state

  defp receive_datagram(bytes, state) do
    Telemetry.datagram_received(state.uri, byte_size(bytes), length(state.datagram_queue))
    state = update_stats(state, :datagram_received, byte_size(bytes))
    deliver_queue(:datagram, bytes, state)
  end

  defp create_stream(_kind, _options, %{state: state} = session)
       when state in [:connecting, :draining, :closed, :failed] do
    {:error, :invalid_state, session}
  end

  defp create_stream(_kind, _options, state)
       when map_size(state.streams) >= state.options.max_streams,
       do: {:error, :backpressure, state}

  defp create_stream(:bidirectional, options, state) do
    case state.backend.open_bidirectional_stream(state.session_ref, options) do
      {:ok, stream_ref} ->
        Telemetry.stream_opened(state.uri, stream_ref, :bidirectional)
        state = ensure_stream(state, stream_ref)
        {:ok, bidirectional_stream(state.target, stream_ref), state}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp create_stream(:unidirectional, options, state) do
    case state.backend.open_unidirectional_stream(state.session_ref, options) do
      {:ok, stream_ref} ->
        Telemetry.stream_opened(state.uri, stream_ref, :unidirectional)
        state = ensure_stream(state, stream_ref, false, true)
        {:ok, send_stream(state.target, stream_ref), state}

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp read_queued(kind, timeout, from, state) do
    case pop_queue(kind, state) do
      {:ok, value, state} ->
        {:reply, {:ok, value}, state}

      :empty ->
        cond do
          state.state in [:closed, :failed] ->
            {:reply, {:error, :closed}, state}

          timeout == 0 ->
            {:reply, {:error, :timeout}, state}

          waiter_count(state) >= state.options.max_pending_waiters ->
            {:reply, {:error, :backpressure}, state}

          true ->
            {:noreply, add_queue_waiter(kind, from, timeout, state)}
        end
    end
  end

  defp read_stream(_ref, _timeout, _from, %{state: status} = state)
       when status in [:closed, :failed],
       do: {:reply, {:error, :closed}, state}

  defp read_stream(stream_ref, timeout, from, state) do
    case Map.fetch(state.streams, stream_ref) do
      {:ok, %{readable: true} = stream_state} ->
        read_known_stream(stream_ref, stream_state, timeout, from, state)

      _ ->
        {:reply, {:error, :invalid_state}, state}
    end
  end

  defp read_known_stream(stream_ref, stream_state, timeout, from, state) do
    case stream_state.queue do
      [{:data, bytes} | rest] ->
        {credits, receipt} = pop_credit(stream_state.credits)
        acknowledge(state, receipt)

        state =
          put_stream_state(state, stream_ref, %{stream_state | queue: rest, credits: credits})

        {:reply, {:ok, bytes}, state}

      [] ->
        cond do
          state.state in [:closed, :failed] ->
            {:reply, {:error, :closed}, state}

          stream_state.terminal != nil ->
            {:reply, stream_reply(stream_state.terminal), state}

          timeout == 0 ->
            {:reply, {:error, :timeout}, state}

          waiter_count(state) >= state.options.max_pending_waiters ->
            {:reply, {:error, :backpressure}, state}

          true ->
            {:noreply, add_stream_waiter(stream_ref, from, timeout, state)}
        end
    end
  end

  defp deliver_queue(kind, value, state) do
    case take_queue_waiter(kind, state) do
      {:ok, waiter, state} ->
        release_waiter(waiter)
        GenServer.reply(waiter.from, {:ok, value})
        state

      :empty ->
        push_queue(kind, value, state)
    end
  end

  # A data receipt is returned to the backend once its bytes leave the session:
  # immediately for a waiting reader or a dropped event, otherwise when read.
  defp deliver_stream(stream_ref, event, state, receipt \\ nil) do
    case Map.fetch(state.streams, stream_ref) do
      {:ok, %{readable: true, terminal: nil} = stream} ->
        state = record_stream_event(state, stream_ref, event)
        terminal = if match?({:data, _}, event), do: nil, else: event
        stream = %{stream | terminal: terminal}

        case stream.waiters do
          [waiter | rest] ->
            acknowledge(state, receipt)
            release_waiter(waiter)
            GenServer.reply(waiter.from, stream_reply(event))
            stream = %{stream | waiters: rest}
            state = put_stream_state(state, stream_ref, stream)
            if terminal, do: reply_terminal_waiters(state, stream_ref, event), else: state

          [] ->
            cond do
              terminal != nil ->
                put_stream_state(state, stream_ref, stream)

              buffer_fits?(state, event_bytes(event), 1) ->
                put_stream_state(state, stream_ref, %{
                  stream
                  | queue: stream.queue ++ [event],
                    credits: stream.credits ++ [receipt]
                })

              true ->
                acknowledge(state, receipt)
                fail_session(state, :receive_buffer_exceeded)
            end
        end

      _ ->
        acknowledge(state, receipt)
        state
    end
  end

  defp pop_credit([receipt | rest]), do: {rest, receipt}
  defp pop_credit([]), do: {[], nil}

  defp record_stream_event(state, ref, {:data, bytes}) do
    Telemetry.stream_received(state.uri, ref, byte_size(bytes))
    update_stats(state, :received, byte_size(bytes))
  end

  defp record_stream_event(state, ref, :fin) do
    Telemetry.stream_closed(state.uri, ref)
    state
  end

  defp record_stream_event(state, _ref, _event), do: state

  defp reply_terminal_waiters(state, stream_ref, event) do
    stream = Map.fetch!(state.streams, stream_ref)

    Enum.each(stream.waiters, fn waiter ->
      release_waiter(waiter)
      GenServer.reply(waiter.from, stream_reply(event))
    end)

    put_stream_state(state, stream_ref, %{stream | waiters: []})
  end

  defp close_session(%{state: state} = session, _close_info) when state in [:closed, :failed],
    do: session

  defp close_session(state, %CloseInfo{} = close_info) do
    state = cleanup_backend(state, close_info)

    Telemetry.session_closed(state.uri, close_info.close_code, close_info.reason)

    state
    |> Map.put(:state, :closed)
    |> reject_pending_ready(:closed)
    |> resolve_promise(:closed, close_info)
    |> resolve_pending_draining()
    |> reply_all_queue_waiters({:error, :closed})
    |> reply_all_stream_waiters({:error, :closed})
    |> clear_retained()
    |> emit({:state, :closed, close_info})
  end

  defp drain_session(%{state: state} = session) when state in [:draining, :closed, :failed],
    do: session

  defp drain_session(state) do
    Telemetry.session_draining(state.uri)

    state
    |> Map.put(:state, :draining)
    |> resolve_promise(:draining, :ok)
    |> emit({:state, :draining})
  end

  defp fail_session(%{state: status} = state, _reason) when status in [:closed, :failed],
    do: state

  defp fail_session(state, reason) do
    state = cleanup_backend(state, %CloseInfo{reason: "session failed"})
    Telemetry.session_exception(state.uri, reason)

    state
    |> Map.put(:state, :failed)
    |> reject_pending_ready(reason)
    |> reject_promise(:closed, reason)
    |> reject_promise(:draining, reason)
    |> reply_all_queue_waiters({:error, reason})
    |> reply_all_stream_waiters({:error, reason})
    |> clear_retained()
    |> emit({:error, %WebTransport.Error{source: "session", reason: reason}})
  end

  defp flush_outgoing_datagrams(%{outgoing_datagrams: []} = state), do: state

  defp flush_outgoing_datagrams(state) do
    Enum.reduce(state.outgoing_datagrams, %{state | outgoing_datagrams: []}, fn {bytes, options},
                                                                                acc ->
      case send_datagram(bytes, options, acc) do
        {:reply, :ok, acc} -> acc
        {:reply, {:error, _reason}, acc} -> acc
      end
    end)
  end

  defp ensure_writable_state(%{state: state}) when state in [:connected, :draining], do: :ok
  defp ensure_writable_state(_state), do: {:error, :invalid_state}

  defp backend_or_invalid_state(%{state: state}, _fun)
       when state in [:connecting, :closed, :failed],
       do: {:error, :invalid_state}

  defp backend_or_invalid_state(_state, fun), do: fun.()

  defp promise_status(state, :ready), do: state.ready_status
  defp promise_status(state, :closed), do: state.closed_status
  defp promise_status(state, :draining), do: state.draining_status

  defp add_promise_waiter(state, kind, from, timeout) do
    waiter = new_waiter(from, {:promise_timeout, kind, from}, timeout)
    put_promise(state, kind, :pending, promise_waiters(state, kind) ++ [waiter])
  end

  defp resolve_promise(state, kind, value) do
    if promise_status(state, kind) == :pending,
      do: settle_resolved_promise(state, kind, value),
      else: state
  end

  defp settle_resolved_promise(state, kind, value) do
    reply = resolved_reply(kind, value)

    state
    |> promise_waiters(kind)
    |> Enum.each(fn waiter ->
      release_waiter(waiter)
      GenServer.reply(waiter.from, reply)
    end)

    put_promise(state, kind, {:resolved, value}, [])
  end

  defp reject_promise(state, kind, reason) do
    if promise_status(state, kind) == :pending,
      do: settle_rejected_promise(state, kind, reason),
      else: state
  end

  defp settle_rejected_promise(state, kind, reason) do
    state
    |> promise_waiters(kind)
    |> Enum.each(fn waiter ->
      release_waiter(waiter)
      GenServer.reply(waiter.from, {:error, reason})
    end)

    put_promise(state, kind, {:rejected, reason}, [])
  end

  defp reject_pending_ready(%{ready_status: :pending} = state, reason),
    do: reject_promise(state, :ready, reason)

  defp reject_pending_ready(state, _reason), do: state

  defp resolve_pending_draining(%{draining_status: :pending} = state),
    do: resolve_promise(state, :draining, :ok)

  defp resolve_pending_draining(state), do: state

  defp promise_waiters(state, :ready), do: state.ready_waiters
  defp promise_waiters(state, :closed), do: state.closed_waiters
  defp promise_waiters(state, :draining), do: state.draining_waiters

  defp put_promise(state, :ready, status, waiters),
    do: %{state | ready_status: status, ready_waiters: waiters}

  defp put_promise(state, :closed, status, waiters),
    do: %{state | closed_status: status, closed_waiters: waiters}

  defp put_promise(state, :draining, status, waiters),
    do: %{state | draining_status: status, draining_waiters: waiters}

  defp resolved_reply(:closed, value), do: {:ok, value}
  defp resolved_reply(_kind, :ok), do: :ok
  defp resolved_reply(_kind, value), do: {:ok, value}

  defp add_queue_waiter(kind, from, timeout, state) do
    waiter = new_waiter(from, {:waiter_timeout, kind, from}, timeout)

    case kind do
      :datagram ->
        %{state | datagram_waiters: state.datagram_waiters ++ [waiter]}

      :incoming_bidirectional ->
        %{state | incoming_bidi_waiters: state.incoming_bidi_waiters ++ [waiter]}

      :incoming_unidirectional ->
        %{state | incoming_uni_waiters: state.incoming_uni_waiters ++ [waiter]}
    end
  end

  defp take_queue_waiter(:datagram, %{datagram_waiters: [waiter | rest]} = state),
    do: {:ok, waiter, %{state | datagram_waiters: rest}}

  defp take_queue_waiter(
         :incoming_bidirectional,
         %{incoming_bidi_waiters: [waiter | rest]} = state
       ),
       do: {:ok, waiter, %{state | incoming_bidi_waiters: rest}}

  defp take_queue_waiter(
         :incoming_unidirectional,
         %{incoming_uni_waiters: [waiter | rest]} = state
       ),
       do: {:ok, waiter, %{state | incoming_uni_waiters: rest}}

  defp take_queue_waiter(_kind, _state), do: :empty

  defp pop_queue(:datagram, %{datagram_queue: [value | rest]} = state),
    do: {:ok, value, %{state | datagram_queue: rest}}

  defp pop_queue(:incoming_bidirectional, %{incoming_bidi_queue: [value | rest]} = state),
    do: {:ok, value, %{state | incoming_bidi_queue: rest}}

  defp pop_queue(:incoming_unidirectional, %{incoming_uni_queue: [value | rest]} = state),
    do: {:ok, value, %{state | incoming_uni_queue: rest}}

  defp pop_queue(_kind, _state), do: :empty

  defp push_queue(:datagram, value, state) do
    queue = bounded_push(state.datagram_queue, value, state.max_incoming_datagrams)
    candidate = %{state | datagram_queue: queue}
    if buffer_fits?(candidate, 0, 0), do: candidate, else: state
  end

  defp push_queue(:incoming_bidirectional, value, state) do
    if buffer_fits?(state, 0, 1),
      do: %{state | incoming_bidi_queue: state.incoming_bidi_queue ++ [value]},
      else: fail_session(state, :receive_buffer_exceeded)
  end

  defp push_queue(:incoming_unidirectional, value, state) do
    if buffer_fits?(state, 0, 1),
      do: %{state | incoming_uni_queue: state.incoming_uni_queue ++ [value]},
      else: fail_session(state, :receive_buffer_exceeded)
  end

  defp timeout_waiter(kind, from, state) do
    case remove_queue_waiter(kind, from, state) do
      {:ok, waiter, state} ->
        release_waiter(waiter)
        GenServer.reply(waiter.from, {:error, :timeout})
        state

      :not_found ->
        state
    end
  end

  defp remove_queue_waiter(kind, from, state) do
    {waiters, put_fun} =
      case kind do
        :datagram ->
          {state.datagram_waiters,
           fn session, waiters ->
             %{session | datagram_waiters: waiters}
           end}

        :incoming_bidirectional ->
          {state.incoming_bidi_waiters,
           fn session, waiters ->
             %{session | incoming_bidi_waiters: waiters}
           end}

        :incoming_unidirectional ->
          {state.incoming_uni_waiters,
           fn session, waiters ->
             %{session | incoming_uni_waiters: waiters}
           end}
      end

    remove_waiter(waiters, from)
    |> case do
      {:ok, waiter, waiters} -> {:ok, waiter, put_fun.(state, waiters)}
      :not_found -> :not_found
    end
  end

  defp add_stream_waiter(stream_ref, from, timeout, state) do
    waiter = new_waiter(from, {:stream_waiter_timeout, stream_ref, from}, timeout)

    stream_state = Map.fetch!(state.streams, stream_ref)

    put_stream_state(state, stream_ref, %{
      stream_state
      | waiters: stream_state.waiters ++ [waiter]
    })
  end

  defp timeout_stream_waiter(stream_ref, from, state) do
    case Map.fetch(state.streams, stream_ref) do
      {:ok, stream_state} ->
        case remove_waiter(stream_state.waiters, from) do
          {:ok, waiter, waiters} ->
            release_waiter(waiter)
            GenServer.reply(waiter.from, {:error, :timeout})
            put_stream_state(state, stream_ref, %{stream_state | waiters: waiters})

          :not_found ->
            state
        end

      :error ->
        state
    end
  end

  defp reply_all_queue_waiters(state, reply) do
    waiters = state.datagram_waiters ++ state.incoming_bidi_waiters ++ state.incoming_uni_waiters

    Enum.each(waiters, fn waiter ->
      release_waiter(waiter)
      GenServer.reply(waiter.from, reply)
    end)

    %{state | datagram_waiters: [], incoming_bidi_waiters: [], incoming_uni_waiters: []}
  end

  defp reply_all_stream_waiters(state, reply) do
    streams =
      Map.new(state.streams, fn {stream_ref, stream_state} ->
        Enum.each(stream_state.waiters, fn waiter ->
          release_waiter(waiter)
          GenServer.reply(waiter.from, reply)
        end)

        {stream_ref, %{stream_state | waiters: []}}
      end)

    %{state | streams: streams}
  end

  defp remove_waiter(waiters, from) do
    case Enum.split_while(waiters, fn waiter -> waiter.from != from end) do
      {_before, []} ->
        :not_found

      {before, [waiter | after_waiters]} ->
        {:ok, waiter, before ++ after_waiters}
    end
  end

  defp ensure_stream(state, stream_ref, readable \\ true, writable \\ true) do
    Map.update!(state, :streams, fn streams ->
      Map.put_new(streams, stream_ref, %{
        queue: [],
        credits: [],
        waiters: [],
        readable: readable,
        writable: writable,
        terminal: nil,
        send_closed: false
      })
    end)
  end

  defp put_stream_state(state, stream_ref, stream_state) do
    %{state | streams: Map.put(state.streams, stream_ref, stream_state)}
  end

  defp retain_operation(state, ref, result) do
    order = state.operation_order ++ [ref]
    operations = Map.put(state.operations, ref, result)

    if length(order) > 128 do
      [oldest | rest] = order
      %{state | operations: Map.delete(operations, oldest), operation_order: rest}
    else
      %{state | operations: operations, operation_order: order}
    end
  end

  defp new_waiter(from, message, timeout) do
    %{
      from: from,
      timer: schedule_timeout(message, timeout),
      monitor: Process.monitor(elem(from, 0))
    }
  end

  defp release_waiter(waiter) do
    cancel_timer(waiter.timer)
    Process.demonitor(waiter.monitor, [:flush])
  end

  defp waiter_count(state) do
    length(state.ready_waiters) + length(state.closed_waiters) + length(state.draining_waiters) +
      length(state.datagram_waiters) + length(state.incoming_bidi_waiters) +
      length(state.incoming_uni_waiters) +
      Enum.reduce(state.streams, 0, fn {_, stream}, n -> n + length(stream.waiters) end)
  end

  defp remove_dead_waiters(state, monitor) do
    discard = fn waiters ->
      Enum.reject(waiters, fn waiter ->
        if waiter.monitor == monitor, do: release_waiter(waiter)
        waiter.monitor == monitor
      end)
    end

    state =
      Enum.reduce(
        [
          :ready_waiters,
          :closed_waiters,
          :draining_waiters,
          :datagram_waiters,
          :incoming_bidi_waiters,
          :incoming_uni_waiters
        ],
        state,
        fn key, acc -> Map.update!(acc, key, discard) end
      )

    %{
      state
      | streams:
          Map.new(state.streams, fn {ref, stream} ->
            {ref, %{stream | waiters: discard.(stream.waiters)}}
          end)
    }
  end

  defp ensure_send_size(state, bytes) do
    if byte_size(bytes) <= state.options.max_buffered_bytes,
      do: :ok,
      else: {:error, :backpressure}
  end

  defp ensure_send_stream(state, ref) do
    case Map.fetch(state.streams, ref) do
      {:ok, %{writable: true, send_closed: false}} -> :ok
      _ -> {:error, :invalid_state}
    end
  end

  defp finish_send(state, ref, fun) do
    with :ok <- ensure_writable_state(state),
         :ok <- ensure_send_stream(state, ref),
         :ok <- fun.() do
      stream = Map.fetch!(state.streams, ref)
      {:ok, put_stream_state(state, ref, %{stream | send_closed: true})}
    else
      {:error, _} = error -> {error, state}
    end
  end

  defp admit_incoming(kind, ref, state) do
    cond do
      Map.has_key?(state.streams, ref) ->
        state

      map_size(state.streams) >= state.options.max_streams ->
        fail_session(state, :stream_limit_exceeded)

      true ->
        bidi? = kind == :incoming_bidirectional
        state = ensure_stream(state, ref, true, bidi?)

        stream =
          if bidi?,
            do: bidirectional_stream(state.target, ref),
            else: receive_stream(state.target, ref)

        deliver_queue(kind, stream, state)
    end
  end

  defp event_bytes({:data, bytes}), do: byte_size(bytes)
  defp event_bytes(_event), do: 0

  defp buffer_fits?(state, added_bytes, added_items) do
    {bytes, items} =
      Enum.reduce(state.streams, {0, 0}, fn {_, stream}, {b, n} ->
        {b + Enum.reduce(stream.queue, 0, &(event_bytes(&1) + &2)), n + length(stream.queue)}
      end)

    bytes = bytes + Enum.reduce(state.datagram_queue, 0, &(byte_size(&1) + &2))

    bytes =
      bytes +
        Enum.reduce(state.outgoing_datagrams, 0, fn {data, _}, total ->
          total + byte_size(data)
        end)

    items =
      items + length(state.outgoing_datagrams) + length(state.datagram_queue) +
        length(state.incoming_bidi_queue) +
        length(state.incoming_uni_queue)

    bytes + added_bytes <= state.options.max_buffered_bytes and
      items + added_items <= state.options.max_buffered_items
  end

  defp cleanup_backend(%{backend_closed: true} = state, _info), do: state

  defp cleanup_backend(state, info) do
    result = if state.session_ref, do: state.backend.close(state.session_ref, info), else: :ok
    %{state | backend_closed: true, backend_close_result: result}
  end

  defp clear_retained(state),
    do: %{
      state
      | streams: %{},
        datagram_queue: [],
        outgoing_datagrams: [],
        incoming_bidi_queue: [],
        incoming_uni_queue: []
    }

  @impl true
  def terminate(_reason, state) do
    cleanup_backend(state, %CloseInfo{reason: "session terminated"})
    :ok
  end

  defp bidirectional_stream(transport, stream_ref) do
    %BidirectionalStream{
      transport: transport,
      readable: receive_stream(transport, stream_ref),
      writable: send_stream(transport, stream_ref)
    }
  end

  defp receive_stream(transport, stream_ref),
    do: %ReceiveStream{transport: transport, ref: stream_ref}

  defp send_stream(transport, stream_ref), do: %SendStream{transport: transport, ref: stream_ref}

  defp stream_reply({:data, bytes}), do: {:ok, bytes}
  defp stream_reply(:fin), do: :fin
  defp stream_reply({:error, reason}), do: {:error, reason}

  defp normalize_iodata(data) do
    {:ok, IO.iodata_to_binary(data)}
  rescue
    _error -> {:error, :invalid_stream_data}
  end

  defp normalize_age(nil), do: {:ok, nil}
  defp normalize_age(age) when is_integer(age) and age >= 0, do: {:ok, age}
  defp normalize_age(_age), do: {:error, :invalid_datagram_age}

  defp normalize_close_info(%CloseInfo{} = close_info), do: close_info

  defp normalize_close_info(%{close_code: close_code, reason: reason}) do
    %CloseInfo{close_code: close_code, reason: reason}
  end

  defp normalize_close_info(_close_info), do: %CloseInfo{}

  defp bounded_push(queue, value, max) do
    queue = queue ++ [value]
    overflow = length(queue) - max

    if overflow > 0 do
      Enum.drop(queue, overflow)
    else
      queue
    end
  end

  defp schedule_timeout(_message, :infinity), do: nil
  defp schedule_timeout(message, timeout), do: Process.send_after(self(), message, timeout)

  defp cancel_timer(nil), do: :ok

  defp cancel_timer(timer) do
    _ = Process.cancel_timer(timer)
    :ok
  end

  defp update_stats(state, :sent, bytes),
    do: %{state | stats: %{state.stats | bytes_sent: state.stats.bytes_sent + bytes}}

  defp update_stats(state, :received, bytes),
    do: %{state | stats: %{state.stats | bytes_received: state.stats.bytes_received + bytes}}

  defp update_stats(state, :datagram_sent, bytes) do
    datagrams = Map.update!(state.stats.datagrams, :sent, fn count -> count + 1 end)

    %{
      state
      | stats: %{state.stats | bytes_sent: state.stats.bytes_sent + bytes, datagrams: datagrams}
    }
  end

  defp update_stats(state, :datagram_received, bytes) do
    datagrams = Map.update!(state.stats.datagrams, :received, fn count -> count + 1 end)

    %{
      state
      | stats: %{
          state.stats
          | bytes_received: state.stats.bytes_received + bytes,
            datagrams: datagrams
        }
    }
  end

  defp emit(state, event) do
    send(state.owner, {WebTransport, state.target, event})
    state
  end
end

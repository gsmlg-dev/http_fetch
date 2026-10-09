defmodule Quic.Connection do
  @moduledoc """
  Temporary serialized QUIC connection runtime using an externally owned IO capability.

  The endpoint owner calls `deliver/4` synchronously after routing a datagram.
  Only that owner may deliver; it must acquire receive credit before forwarding.
  A connection never closes the shared socket. The IO capability's `send/3`
  must return a local completion timestamp or a bounded failure.

  Public consumers use the generation handles and pull operations in `Quic`.
  See `docs/consumer-contract.md` for readiness, admission outcomes and limits.
  """
  @behaviour :gen_statem
  alias Quic.{HandshakeScheduler, TLSDriver, TransportParameters, Recovery}
  alias Quic.IO.Endpoint
  alias Quic.Runtime.{ConnectionHandle, StreamHandle}

  def start_link(opts) do
    :gen_statem.start_link(__MODULE__, Keyword.put_new(opts, :owner, self()), [])
  end

  def start(opts), do: :gen_statem.start(__MODULE__, Keyword.put_new(opts, :owner, self()), [])

  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :temporary}

  def status(pid), do: :gen_statem.call(pid, :status)
  def close(pid), do: :gen_statem.call(pid, :close)

  @doc "Open a locally initiated bidirectional or unidirectional stream."
  def open_stream(pid, kind, timeout \\ 5_000),
    do: :gen_statem.call(pid, {:stream_open, kind}, timeout)

  @doc "Admit bounded application bytes to a connection-owned stream."
  def send_stream(pid, stream_id, data, fin \\ false, timeout \\ 5_000) do
    try do
      :gen_statem.call(pid, {:stream_send, stream_id, data, fin}, timeout)
    catch
      :exit, {:timeout, _} -> {:unknown, :legacy_send}
    end
  end

  @doc "Consume at most `max_bytes` from a manually delivered stream queue."
  def consume_stream(pid, stream_id, max_bytes, timeout \\ 5_000),
    do: :gen_statem.call(pid, {:stream_consume, stream_id, max_bytes}, timeout)

  def deliver(pid, generation, bytes, received_at),
    do: :gen_statem.call(pid, {:datagram, generation, bytes, received_at})

  def attach(pid, generation, consumer, opts),
    do: safe_call(pid, {:attach, generation, consumer, opts}, Keyword.get(opts, :timeout, 5_000))

  def ready(pid, generation), do: safe_call(pid, {:ready, generation}, 5_000)
  def info(pid, generation), do: safe_call(pid, {:info, generation}, 5_000)

  def events(pid, generation, max, opts \\ []),
    do: durable_call(pid, {:events, max}, generation, opts)

  def read(pid, generation, id, max, opts \\ []),
    do: durable_call(pid, {:read, id, max}, generation, opts)

  def operation_status(pid, generation, ref),
    do: safe_call(pid, {:operation_status, generation, ref}, 5_000)

  def close_public(pid, generation, code \\ 0, reason \\ <<>>, opts \\ []),
    do: operation_call(pid, generation, {:close, code, reason}, opts)

  def open_public_stream(pid, generation, kind, opts \\ []),
    do: operation_call(pid, generation, {:open, kind}, opts)

  def send_public_stream(pid, generation, id, data, fin, opts),
    do: operation_call(pid, generation, {:send, id, data, fin}, opts)

  def send_public_datagram(pid, generation, data, opts \\ []),
    do: operation_call(pid, generation, {:send_datagram, data}, opts)

  def read_datagrams(pid, generation, max, opts \\ []),
    do: durable_call(pid, {:read_datagrams, max}, generation, opts)

  def reset_public_stream(pid, generation, id, code, opts \\ []),
    do: operation_call(pid, generation, {:reset, id, code}, opts)

  def stop_public_stream(pid, generation, id, code, opts \\ []),
    do: operation_call(pid, generation, {:stop, id, code}, opts)

  defp operation_call(pid, generation, request, opts) do
    ref = Keyword.get(opts, :ref, make_ref())
    timeout = Keyword.get(opts, :timeout, 5_000)
    deadline = System.monotonic_time(:millisecond) + Keyword.get(opts, :deadline, timeout)

    try do
      :gen_statem.call(pid, {:operation, generation, ref, deadline, request}, timeout)
    catch
      :exit, {:timeout, _} -> {:unknown, ref}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {_reason, _call} -> {:unknown, ref}
    end
  end

  defp durable_call(pid, request, generation, opts) do
    ref = Keyword.get(opts, :ref, make_ref())
    timeout = Keyword.get(opts, :timeout, 5_000)
    deadline = System.monotonic_time(:millisecond) + Keyword.get(opts, :deadline, timeout)

    try do
      :gen_statem.call(pid, {:public_pull, generation, ref, deadline, request}, timeout)
    catch
      :exit, {:timeout, _} -> {:unknown, ref}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {_reason, _call} -> {:unknown, ref}
    end
  end

  defp safe_call(pid, request, timeout) do
    try do
      :gen_statem.call(pid, request, timeout)
    catch
      :exit, {:timeout, _} -> {:error, :timeout}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {:normal, _} -> {:error, :closed}
      :exit, {reason, _call} -> {:error, {:closed, reason}}
    end
  end

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(opts) do
    role = Keyword.fetch!(opts, :role)
    {adapter, writer} = Keyword.fetch!(opts, :io)
    timeout = Keyword.get(opts, :handshake_timeout, 10_000)
    idle_timeout = Keyword.get(opts, :idle_timeout, 30_000)
    closing_timeout = Keyword.get(opts, :closing_timeout)
    draining_timeout = Keyword.get(opts, :draining_timeout)
    owner = Keyword.fetch!(opts, :owner)

    event_limit = Keyword.get(opts, :event_limit, 128)
    operation_limit = Keyword.get(opts, :operation_limit, 256)

    if role in [:client, :server] and is_pid(writer) and is_pid(owner) and
         valid_timeout?(timeout) and valid_timeout?(idle_timeout) and
         valid_item_limit?(event_limit) and valid_item_limit?(operation_limit) and
         valid_optional_timeout?(closing_timeout) and valid_optional_timeout?(draining_timeout) do
      case Endpoint.new(Keyword.get(opts, :limits, [])) do
        {:ok, budget} ->
          # Clients are not subject to the server's pre-validation amplification limit.
          budget =
            if role == :client or Keyword.get(opts, :address_validated, false),
              do: %{budget | address_validated: true},
              else: budget

          generation = make_ref()

          data = %{
            role: role,
            address_validated: Keyword.get(opts, :address_validated, false),
            adapter: adapter,
            writer: writer,
            owner: owner,
            writer_monitor: Process.monitor(writer),
            owner_monitor: Process.monitor(owner),
            remote: Keyword.fetch!(opts, :remote),
            scheduler_opts: Keyword.fetch!(opts, :scheduler),
            scheduler: nil,
            budget: budget,
            pending: [],
            ready: false,
            parameters_valid: false,
            generation: generation,
            deadline: adapter.monotonic_time() + timeout * 1000,
            idle_timeout: idle_timeout,
            idle_deadline: nil,
            closing_timeout: closing_timeout,
            draining_timeout: draining_timeout,
            closing_deadline: nil,
            draining_deadline: nil,
            reason: :closed,
            local: Keyword.get(opts, :local),
            public: Keyword.get(opts, :public, false),
            ready_notified: false,
            seen_streams: MapSet.new(),
            event_error: nil,
            consumer: nil,
            consumer_monitor: nil,
            events: [],
            datagrams: [],
            datagram_bytes: 0,
            datagram_drops: 0,
            datagram_max_items: Keyword.get(Keyword.get(opts, :datagram, []), :max_items, 64),
            datagram_max_bytes:
              Keyword.get(Keyword.get(opts, :datagram, []), :max_buffer_bytes, 65_536),
            event_limit: event_limit,
            operations: %{},
            operation_sequence: 0,
            operation_limit: operation_limit,
            highwaters: %{}
          }

          {:ok, :handshaking, data,
           [{:next_event, :internal, :start}, {{:timeout, :handshake}, timeout, generation}]}

        {:error, reason} ->
          {:stop, reason}
      end
    else
      {:stop, :invalid_connection_options}
    end
  end

  @impl true
  def handle_event(:internal, :start, :handshaking, data) do
    case HandshakeScheduler.new(data.role, data.scheduler_opts) do
      {:ok, scheduler, effects} ->
        scheduler =
          if data.address_validated,
            do: %{scheduler | tls: TLSDriver.mark_address_validated(scheduler.tls)},
            else: scheduler

        advance(%{data | scheduler: scheduler}, effects, [])

      {:error, reason} ->
        stop(data, {:initialization, reason})

      {:error, reason, scheduler} ->
        stop(%{data | scheduler: scheduler}, {:initialization, reason})
    end
  end

  def handle_event({:call, from}, :status, phase, data) do
    packets =
      Map.new(data.scheduler.recovery.spaces, fn {space, state} ->
        counts = Enum.frequencies_by(Map.values(state.sent), & &1.status)
        {space, Map.merge(%{sent: 0, acked: 0, queued: 0, failed: 0}, counts)}
      end)

    status = %{
      phase: phase,
      cipher_suite: TLSDriver.info(data.scheduler.tls)[:cipher_suite],
      alpn: TLSDriver.info(data.scheduler.tls)[:alpn],
      tls_complete: data.scheduler.tls.facts.tls_complete,
      parameters_valid: data.parameters_valid,
      quic_confirmed: data.scheduler.tls.facts.quic_confirmed,
      peer_authenticated: data.scheduler.tls.facts.peer_authenticated,
      generation: data.generation,
      packets: packets,
      retired_levels:
        Enum.filter([:initial, :handshake], &HandshakeScheduler.retired?(data.scheduler, &1)),
      pending_datagrams: length(data.pending),
      bytes_sent: data.budget.bytes_sent,
      bytes_received: data.budget.bytes_received,
      address_validated: data.scheduler.tls.facts.address_validated
    }

    {:keep_state_and_data, [{:reply, from, status}]}
  end

  def handle_event(
        {:call, {caller, _} = from},
        {:attach, generation, consumer, _opts},
        _phase,
        %{generation: generation} = data
      )
      when is_pid(consumer) do
    if is_nil(data.consumer) or caller == data.consumer or caller == data.owner do
      if data.consumer_monitor, do: Process.demonitor(data.consumer_monitor, [:flush])
      next = %{data | consumer: consumer, consumer_monitor: Process.monitor(consumer)}
      if data.ready, do: send(consumer, {:quic_ready, public_handle(data), metadata(data)})
      {:keep_state, next, [{:reply, from, :ok}]}
    else
      reply(from, {:error, :not_consumer})
    end
  end

  def handle_event(
        {:call, from},
        {:ready, generation},
        _phase,
        %{generation: generation, ready: ready} = _data
      ),
      do: {:keep_state_and_data, [{:reply, from, if(ready, do: :ready, else: :pending)}]}

  def handle_event({:call, from}, {:info, generation}, _phase, %{generation: generation} = data) do
    {:keep_state_and_data, [{:reply, from, {:ok, metadata(data)}}]}
  end

  def handle_event(
        {:call, {caller, _} = from},
        {:events, generation, max},
        _phase,
        %{generation: generation} = data
      )
      when is_integer(max) and max in 1..128 do
    if caller == data.consumer do
      {out, rest} = Enum.split(data.events, max)
      {:keep_state, %{data | events: rest}, [{:reply, from, {:ok, out}}]}
    else
      reply(from, {:error, :not_consumer})
    end
  end

  def handle_event(
        {:call, {caller, _} = from},
        {:read, generation, id, max},
        :established,
        %{generation: generation} = data
      )
      when is_integer(max) and max in 1..16_384 do
    if caller == data.consumer do
      with {:ok, scheduler, events} <- HandshakeScheduler.consume_stream(data.scheduler, id, max),
           {:ok, scheduler, effects} <- HandshakeScheduler.schedule(scheduler) do
        advance(%{data | scheduler: scheduler}, effects, [{:reply, from, {:ok, events}}])
      else
        {:error, reason} ->
          reply(from, {:error, reason})

        {:error, reason, scheduler} ->
          stop_with_replies(%{data | scheduler: scheduler}, reason, [
            {:reply, from, {:error, reason}}
          ])
      end
    else
      reply(from, {:error, :not_consumer})
    end
  end

  def handle_event(
        {:call, from},
        {:operation_status, generation, ref},
        _phase,
        %{generation: generation} = data
      ),
      do:
        {:keep_state_and_data,
         [
           {:reply, from,
            case Map.get(data.operations, ref) do
              nil -> :unknown
              entry -> Map.take(entry, [:status, :result])
            end}
         ]}

  def handle_event(
        {:call, {caller, _} = from},
        {:public_pull, generation, ref, deadline, request},
        phase,
        data
      ) do
    signature = :crypto.hash(:sha256, :erlang.term_to_binary({:pull, request}))

    cond do
      generation != data.generation ->
        reply(from, {:error, :stale_handle})

      not valid_operation_identity?(ref, deadline) ->
        reply(from, {:error, :invalid_operation})

      Map.has_key?(data.operations, ref) ->
        previous = data.operations[ref]

        reply(
          from,
          if(previous.signature == signature,
            do: previous.result,
            else: {:error, :operation_ref_conflict}
          )
        )

      System.monotonic_time(:millisecond) >= deadline ->
        result = {:error, :deadline_expired}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}

      caller != data.consumer ->
        result = {:error, :not_consumer}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}

      match?({:events, _}, request) ->
        {:events, max} = request

        if is_integer(max) and max in 1..128 do
          {out, rest} = Enum.split(data.events, max)
          result = {:ok, out}
          next = record_operation(%{data | events: rest}, ref, signature, :completed, result)
          {:keep_state, next, [{:reply, from, result}]}
        else
          result = {:error, :invalid_operation}

          {:keep_state, record_operation(data, ref, signature, :rejected, result),
           [{:reply, from, result}]}
        end

      match?({:read_datagrams, _}, request) and phase == :established ->
        read_public_datagrams(data, from, ref, signature, request)

      match?({:read, _, _}, request) and phase == :established ->
        read_public_stream(data, from, ref, signature, request)

      true ->
        result = {:error, :invalid_operation}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}
    end
  end

  def handle_event({:call, from}, {:operation, generation, ref, deadline, request}, phase, data) do
    signature = :crypto.hash(:sha256, :erlang.term_to_binary(request))

    cond do
      generation != data.generation ->
        reply(from, {:error, :stale_handle})

      not is_reference(ref) or not is_integer(deadline) ->
        reply(from, {:error, :invalid_operation})

      Map.has_key?(data.operations, ref) ->
        previous = data.operations[ref]

        reply(
          from,
          if(previous.signature == signature,
            do: previous.result,
            else: {:error, :operation_ref_conflict}
          )
        )

      System.monotonic_time(:millisecond) >= deadline ->
        result = {:error, :deadline_expired}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}

      phase in [:closing, :draining] and elem(request, 0) == :close ->
        result = :ok

        {:keep_state, record_operation(data, ref, signature, :admitted, result),
         [{:reply, from, result}]}

      phase != :established and elem(request, 0) != :close ->
        result = {:error, :not_established}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}

      true ->
        execute_operation(data, from, ref, signature, request)
    end
  end

  def handle_event({:call, from}, :close, phase, _data) when phase in [:closing, :draining],
    do: {:keep_state_and_data, [{:reply, from, :ok}]}

  def handle_event({:call, from}, :close, phase, data)
      when phase in [:handshaking, :established] do
    case begin_closing(data, :closed) do
      {:ok, next, actions} ->
        {:next_state, :closing, next, [{:reply, from, :ok} | actions]}

      {:error, reason, next} ->
        stop_with_replies(next, reason, [{:reply, from, {:error, reason}}])
    end
  end

  def handle_event({:call, from}, {:stream_send, stream_id, bytes, fin}, :established, data)
      when is_integer(stream_id) and is_binary(bytes) and is_boolean(fin) do
    case HandshakeScheduler.send_stream(data.scheduler, stream_id, bytes, fin) do
      {:ok, scheduler, effects} ->
        advance(%{data | scheduler: scheduler}, effects, [{:reply, from, :ok}])

      {:blocked, frame} ->
        reply(from, {:blocked, frame})

      {:error, reason} ->
        reply(from, {:error, reason})

      {:error, reason, scheduler} ->
        stop_with_replies(%{data | scheduler: scheduler}, reason, [
          {:reply, from, {:error, reason}}
        ])
    end
  end

  def handle_event({:call, from}, {:stream_open, kind}, :established, data)
      when kind in [:bidi, :uni] do
    case HandshakeScheduler.open_stream(data.scheduler, kind) do
      {:ok, scheduler, stream_id} ->
        {:keep_state, %{data | scheduler: scheduler}, [{:reply, from, {:ok, stream_id}}]}

      {:blocked, frame} ->
        reply(from, {:blocked, frame})

      {:error, reason} ->
        reply(from, {:error, reason})
    end
  end

  def handle_event({:call, from}, {:stream_open, _kind}, _phase, _data),
    do: reply(from, {:error, :not_established})

  def handle_event({:call, from}, {:stream_send, _stream_id, _bytes, _fin}, _phase, _data),
    do: reply(from, {:error, :not_established})

  def handle_event({:call, from}, {:stream_consume, stream_id, max_bytes}, :established, data)
      when is_integer(stream_id) and is_integer(max_bytes) and max_bytes > 0 do
    case HandshakeScheduler.consume_stream(data.scheduler, stream_id, max_bytes) do
      {:ok, scheduler, events} ->
        case HandshakeScheduler.schedule(scheduler) do
          {:ok, scheduler, effects} ->
            advance(%{data | scheduler: scheduler}, effects, [{:reply, from, {:ok, events}}])

          {:error, reason, scheduler} ->
            stop_with_replies(%{data | scheduler: scheduler}, reason, [
              {:reply, from, {:error, reason}}
            ])
        end

      {:error, reason} ->
        reply(from, {:error, reason})
    end
  end

  def handle_event({:call, from}, {:stream_consume, _stream_id, _max_bytes}, _phase, _data),
    do: reply(from, {:error, :not_established})

  def handle_event(
        {:call, {caller, _} = from},
        {:datagram, generation, bytes, at},
        phase,
        data
      )
      when phase in [:handshaking, :established] do
    cond do
      caller != data.owner ->
        reply(from, {:error, :not_owner})

      generation != data.generation ->
        reply(from, {:error, :stale_generation})

      not is_binary(bytes) or not is_integer(at) or byte_size(bytes) > 65_527 ->
        reply(from, {:error, :invalid_datagram})

      data.role == :server and initial_packet?(bytes) and byte_size(bytes) < 1200 ->
        reply(from, {:error, :undersized_unvalidated_datagram})

      expired?(data) ->
        {:stop_and_reply, :normal, [{:reply, from, {:error, :handshake_timeout}}],
         %{data | reason: :handshake_timeout}}

      true ->
        receive_packet(data, bytes, at, from)
    end
  end

  def handle_event(
        {:call, {caller, _} = from},
        {:datagram, generation, _bytes, _at},
        phase,
        data
      )
      when phase in [:closing, :draining] do
    cond do
      caller != data.owner -> reply(from, {:error, :not_owner})
      generation != data.generation -> reply(from, {:error, :stale_generation})
      true -> reply(from, :ok)
    end
  end

  def handle_event(
        {:timeout, :handshake},
        generation,
        :handshaking,
        %{generation: generation} = data
      ),
      do: stop(data, :handshake_timeout)

  def handle_event({:timeout, :idle}, generation, :established, %{generation: generation} = data) do
    now = data.adapter.monotonic_time()

    if is_integer(data.idle_deadline) and now >= data.idle_deadline do
      stop(data, :idle_timeout)
    else
      {:keep_state, data, idle_timer(data)}
    end
  end

  def handle_event({:timeout, :closing}, generation, :closing, %{generation: generation} = data) do
    deadline = data.closing_deadline
    now = data.adapter.monotonic_time()

    if is_integer(deadline) and now >= deadline do
      next = %{data | draining_deadline: now + data.draining_timeout * 1000}
      {:next_state, :draining, next, [{{:timeout, :draining}, data.draining_timeout, generation}]}
    else
      {:keep_state, data, closing_timer(data)}
    end
  end

  def handle_event({:timeout, :draining}, generation, :draining, %{generation: generation} = data) do
    if is_integer(data.draining_deadline) and
         data.adapter.monotonic_time() >= data.draining_deadline do
      stop(data, data.reason)
    else
      {:keep_state, data, draining_timer(data)}
    end
  end

  def handle_event({:timeout, :recovery}, {generation, token}, phase, data)
      when phase in [:handshaking, :established] do
    recovery = data.scheduler.recovery
    now = data.adapter.monotonic_time()

    if generation == data.generation and Recovery.timer_expired?(recovery, token, now) do
      {:ok, recovery, result} = Recovery.on_time(recovery, now)
      scheduler = %{data.scheduler | recovery: recovery}

      case retry_packets(scheduler, result.lost ++ result.probes, []) do
        {:ok, scheduler, effects} -> advance(%{data | scheduler: scheduler}, effects, [])
        {:error, reason} -> stop(data, {:recovery, reason})
      end
    else
      :keep_state_and_data
    end
  end

  def handle_event({:timeout, :recovery}, _token, phase, _data)
      when phase in [:closing, :draining],
      do: :keep_state_and_data

  def handle_event(:info, {:DOWN, ref, :process, _pid, reason}, _phase, data) do
    cond do
      ref == data.writer_monitor -> stop(data, {:writer_down, reason})
      ref == data.owner_monitor -> stop(data, :owner_down)
      ref == data.consumer_monitor -> stop(data, :consumer_down)
      true -> :keep_state_and_data
    end
  end

  def handle_event({:call, from}, request, _phase, data) when is_tuple(request) do
    if tuple_size(request) >= 2 and
         elem(request, 0) in [
           :attach,
           :ready,
           :info,
           :events,
           :read,
           :operation_status,
           :public_open,
           :public_send,
           :public_reset,
           :public_stop,
           :public_close
         ] do
      reason = if elem(request, 1) != data.generation, do: :stale_handle, else: :invalid_operation
      reply(from, {:error, reason})
    else
      reply(from, {:error, :invalid_operation})
    end
  end

  def handle_event(_, _, _, _), do: :keep_state_and_data

  defp receive_packet(data, bytes, at, from) do
    case HandshakeScheduler.receive_datagram(data.scheduler, bytes, at) do
      {:ok, scheduler, events} ->
        {:ok, budget} = Endpoint.receive_bytes(data.budget, byte_size(bytes))

        {scheduler, budget} =
          if data.role == :server and scheduler.tls.facts.address_validated do
            {:ok, validated} = Endpoint.validate_address(budget)
            {%{scheduler | tls: TLSDriver.mark_address_validated(scheduler.tls)}, validated}
          else
            {scheduler, budget}
          end

        pending =
          if Enum.any?(events, &(&1.type == :retry)),
            do: Enum.reject(data.pending, &(&1.level == :initial)),
            else: data.pending

        data = refresh_idle(%{data | scheduler: scheduler, budget: budget, pending: pending})
        data = collect_stream_events(data, events)
        effects = Enum.flat_map(events, &Map.get(&1, :generated, []))

        if Enum.any?(events, &(&1.type in [:connection_close, :application_close])) do
          drain_timeout = lifecycle_timeout(data, :draining)

          next = %{
            data
            | reason: :peer_closed,
              draining_timeout: drain_timeout,
              draining_deadline: data.adapter.monotonic_time() + drain_timeout * 1000
          }

          {:next_state, :draining, next,
           close_cancel_actions() ++
             [{{:timeout, :draining}, drain_timeout, data.generation}, {:reply, from, :ok}]}
        else
          case readiness(data) do
            {:ok, data, extra} ->
              advance_received(data, events, effects, extra, from)

            {:error, reason} ->
              {:stop_and_reply, :normal, [{:reply, from, {:error, reason}}],
               %{data | reason: reason}}
          end
        end

      {:error, :bad_tag, _scheduler} ->
        # RFC9001 section5.5: unauthenticated packets do not affect the connection.
        reply(from, :ok)

      {:error, {:key_update_error, _} = reason, scheduler} ->
        close_transport_error(%{data | scheduler: scheduler}, from, reason, 0x0E, 0)

      {:error, %SSL.QUIC.Error{} = error, _scheduler} ->
        reason = {:tls, error.kind, error.alert, error.reason}
        {:stop_and_reply, :normal, [{:reply, from, {:error, reason}}], %{data | reason: reason}}

      {:error, {:protocol_violation, 0x0A, frame_type} = reason, scheduler} ->
        close_transport_error(%{data | scheduler: scheduler}, from, reason, 0x0A, frame_type)

      {:error, reason, _scheduler} ->
        stop_with_replies(data, reason, [{:reply, from, {:error, reason}}])
    end
  end

  defp close_transport_error(data, from, reason, code, frame_type) do
    case begin_closing(data, {:transport, code, frame_type}) do
      {:ok, next, actions} ->
        {:next_state, :closing, next, [{:reply, from, {:error, reason}} | actions]}

      {:error, close_reason, next} ->
        stop_with_replies(next, close_reason, [{:reply, from, {:error, reason}}])
    end
  end

  defp readiness(%{ready: true} = data), do: {:ok, data, []}

  defp readiness(data) do
    facts = data.scheduler.tls.facts

    if facts.tls_complete do
      scheduler = data.scheduler
      peer_role = if data.role == :client, do: :server, else: :client

      with true <- facts.peer_parameters_authenticated,
           true <- data.role == :server or facts.peer_authenticated,
           true <- is_binary(scheduler.peer_initial_scid),
           {:ok, parameters} <- TransportParameters.decode(facts.peer_transport_parameters),
           :ok <-
             TransportParameters.validate(parameters,
               role: peer_role,
               initial_source_connection_id: scheduler.peer_initial_scid,
               retry_source_connection_id: if(peer_role == :server, do: scheduler.retry_scid),
               original_destination_connection_id:
                 if(peer_role == :server, do: scheduler.original_dcid)
             ) do
        scheduler = HandshakeScheduler.install_peer_parameters(scheduler, parameters.values)
        timeout = effective_idle_timeout(data.idle_timeout, scheduler.peer_idle_timeout)
        data = %{data | scheduler: scheduler, idle_timeout: timeout}

        if data.role == :server do
          case HandshakeScheduler.handshake_done(HandshakeScheduler.confirm_handshake(scheduler)) do
            {:ok, scheduler, effects} ->
              {:ok, %{data | scheduler: scheduler, ready: true, parameters_valid: true}, effects}

            {:error, reason, _} ->
              {:error, reason}

            {:error, reason} ->
              {:error, reason}
          end
        else
          {:ok, %{data | ready: true, parameters_valid: true}, []}
        end
      else
        false -> {:error, :incomplete_authentication}
        {:error, reason} -> {:error, {:transport_parameters, reason}}
      end
    else
      {:ok, data, []}
    end
  end

  defp advance(data, effects, replies) do
    pending =
      Enum.reject(data.pending ++ effects, &HandshakeScheduler.retired?(data.scheduler, &1.level))

    cond do
      data.event_error != nil ->
        stop_with_replies(data, data.event_error, replies)

      length(pending) > data.budget.max_queue ->
        stop_with_replies(data, :send_queue_limit, replies)

      Enum.reduce(pending, 0, &(byte_size(&1.bytes) + &2)) > data.budget.max_queue_bytes ->
        stop_with_replies(data, :send_queue_bytes_limit, replies)

      true ->
        case flush(observe(%{data | pending: pending})) do
          {:ok, %{ready: true} = data} ->
            data = notify_ready(data)

            established_data = %{
              data
              | idle_deadline:
                  data.adapter.monotonic_time() + Map.get(data, :idle_timeout, 30_000) * 1000
            }

            {:next_state, :established, established_data,
             replies ++
               [{{:timeout, :handshake}, :cancel}] ++
               recovery_timer(established_data) ++
               idle_timer(established_data)}

          {:ok, data} ->
            {:keep_state, data, replies ++ recovery_timer(data) ++ idle_timer(data)}

          {:error, reason, data} ->
            stop_with_replies(data, reason, replies)
        end
    end
  end

  defp flush(%{pending: []} = data), do: {:ok, data}

  defp flush(%{pending: [effect | rest]} = data) do
    cond do
      HandshakeScheduler.retired?(data.scheduler, effect.level) ->
        flush(%{data | pending: rest})

      expired?(data) ->
        {:error, :handshake_timeout, data}

      true ->
        case Endpoint.enqueue(
               data.budget,
               effect.bytes,
               data.remote,
               data.adapter.monotonic_time()
             ) do
          {:error, :anti_amplification} ->
            {:ok, data}

          {:error, reason} ->
            {:error, reason, data}

          {:ok, budget, send} ->
            data = observe(%{data | budget: budget})
            {:ok, budget, ^send} = Endpoint.dequeue(budget)
            data = observe(%{data | budget: budget})
            {result, at} = local_send(data, effect.bytes)
            {:ok, budget, _receipt} = Endpoint.local_send(budget, send, result, at)

            case HandshakeScheduler.local_send(
                   data.scheduler,
                   effect.space,
                   effect.packet_number,
                   result,
                   at
                 ) do
              {:ok, scheduler, _statuses} ->
                next = observe(%{data | scheduler: scheduler, budget: budget, pending: rest})

                flush_sent(result, next)

              {:error, reason} ->
                {:error, {:send_accounting, reason}, data}
            end
        end
    end
  end

  defp recovery_timer(data) do
    recovery = data.scheduler.recovery

    case recovery.deadline do
      nil ->
        [{{:timeout, :recovery}, :cancel}]

      deadline ->
        delay = max(0, div(deadline - data.adapter.monotonic_time() + 999, 1000))
        [{{:timeout, :recovery}, delay, {data.generation, recovery.timer_generation}}]
    end
  end

  defp idle_timer(%{idle_deadline: deadline} = data) when is_integer(deadline) do
    delay =
      max(0, div(Map.fetch!(data, :idle_deadline) - data.adapter.monotonic_time() + 999, 1000))

    [{{:timeout, :idle}, delay, data.generation}]
  end

  defp idle_timer(_data), do: [{{:timeout, :idle}, :cancel}]

  defp closing_timer(data) do
    delay = max(0, div(data.closing_deadline - data.adapter.monotonic_time() + 999, 1000))
    [{{:timeout, :closing}, delay, data.generation}]
  end

  defp draining_timer(data) do
    delay = max(0, div(data.draining_deadline - data.adapter.monotonic_time() + 999, 1000))
    [{{:timeout, :draining}, delay, data.generation}]
  end

  defp effective_idle_timeout(local, 0), do: local
  defp effective_idle_timeout(0, peer), do: peer
  defp effective_idle_timeout(local, peer), do: min(local, peer)

  defp refresh_idle(data) do
    timeout = Map.get(data, :idle_timeout, 30_000)
    Map.put(data, :idle_deadline, data.adapter.monotonic_time() + timeout * 1000)
  end

  defp lifecycle_timeout(data, kind) do
    pto_ms = div(Recovery.pto_duration(data.scheduler.recovery) * 3 + 999, 1000)

    configured =
      if kind == :closing,
        do: Map.get(data, :closing_timeout),
        else: Map.get(data, :draining_timeout)

    configured || pto_ms
  end

  defp close_cancel_actions do
    [
      {{:timeout, :handshake}, :cancel},
      {{:timeout, :recovery}, :cancel},
      {{:timeout, :idle}, :cancel}
    ]
  end

  # A close is sent once at the strongest currently available encryption level.
  # The process remains routable while closing so late packets cannot create a new
  # connection, then drains without emitting normal traffic before route cleanup.
  defp begin_closing(data, reason) do
    send(data.owner, {:quic_closing, self(), data.generation, reason})
    scheduler = data.scheduler
    closing_timeout = lifecycle_timeout(data, :closing)
    draining_timeout = lifecycle_timeout(data, :draining)

    level =
      cond do
        Map.has_key?(scheduler.keys, :application) -> :application
        Map.has_key?(scheduler.keys, :handshake) -> :handshake
        Map.has_key?(scheduler.keys, :initial) -> :initial
        true -> nil
      end

    if level == nil do
      now = data.adapter.monotonic_time()

      {:ok,
       %{
         data
         | pending: [],
           reason: reason,
           closing_timeout: closing_timeout,
           draining_timeout: draining_timeout,
           closing_deadline: now + closing_timeout * 1000
       }, close_cancel_actions() ++ [{{:timeout, :closing}, closing_timeout, data.generation}]}
    else
      frame =
        if level == :application do
          case reason do
            {:application, code, opaque} ->
              %{type: :application_close, error_code: code, reason: opaque}

            {:transport, code, frame_type} ->
              %{type: :connection_close, error_code: code, frame_type: frame_type, reason: <<>>}

            _ ->
              %{type: :application_close, error_code: 0, reason: <<>>}
          end
        else
          %{type: :connection_close, error_code: 0, frame_type: 0, reason: <<>>}
        end

      scheduler = %{
        scheduler
        | pending: [],
          effects: [],
          pending_acks: %{},
          pending_control: Map.put(scheduler.pending_control, level, [frame])
      }

      case HandshakeScheduler.schedule(scheduler) do
        {:ok, scheduler, effects} ->
          now = data.adapter.monotonic_time()

          next = %{
            data
            | scheduler: scheduler,
              pending: effects,
              reason: reason,
              closing_timeout: closing_timeout,
              draining_timeout: draining_timeout,
              closing_deadline: now + closing_timeout * 1000
          }

          case flush(next) do
            {:ok, flushed} ->
              {:ok, flushed,
               close_cancel_actions() ++
                 [{{:timeout, :closing}, closing_timeout, data.generation}]}

            {:error, send_reason, flushed} ->
              {:error, send_reason, flushed}
          end

        {:error, schedule_reason, scheduler} ->
          {:error, schedule_reason, %{data | scheduler: scheduler, reason: reason}}
      end
    end
  end

  defp retry_packets(scheduler, [], effects), do: {:ok, scheduler, effects}

  defp retry_packets(scheduler, [{space, number} | rest], effects) do
    if HandshakeScheduler.retired?(scheduler, space) do
      retry_packets(scheduler, rest, effects)
    else
      case HandshakeScheduler.retry_crypto(scheduler, space, number) do
        {:ok, next, sends} -> retry_packets(next, rest, effects ++ sends)
        {:error, :not_retransmittable} -> retry_packets(scheduler, rest, effects)
        {:error, reason} -> {:error, reason}
        {:error, reason, _} -> {:error, reason}
      end
    end
  end

  defp local_send(data, bytes) do
    case data.adapter.send(data.writer, bytes, data.remote) do
      {:ok, at} when is_integer(at) -> {:ok, at}
      {:error, reason} -> {{:error, reason}, data.adapter.monotonic_time()}
    end
  catch
    :exit, _ -> {{:error, :writer_unavailable}, data.adapter.monotonic_time()}
  end

  defp public_handle(data), do: %ConnectionHandle{id: self(), generation: data.generation}

  defp metadata(data) do
    resources = resources(data)

    %{
      local: data.local,
      remote: data.remote,
      alpn: TLSDriver.info(data.scheduler.tls)[:alpn],
      tls_complete: data.scheduler.tls.facts.tls_complete,
      parameters_valid: data.parameters_valid,
      peer_authenticated: data.scheduler.tls.facts.peer_authenticated,
      quic_confirmed: data.scheduler.tls.facts.quic_confirmed,
      datagram: %{
        send_max_bytes:
          datagram_payload_limit(HandshakeScheduler.effective_datagram_frame_size(data.scheduler)),
        receive_max_bytes: datagram_payload_limit(data.scheduler.local_max_datagram_frame_size)
      },
      resources: resources,
      highwaters:
        Map.merge(resources, data.highwaters, fn _key, current, peak -> max(current, peak) end)
    }
  end

  defp resources(data) do
    streams = data.scheduler.streams

    %{
      pending_datagrams: length(data.pending),
      io_queue_entries: :queue.len(data.budget.queue),
      io_queue_bytes: data.budget.queue_bytes,
      in_flight_sends: map_size(data.budget.in_flight),
      application_crypto_bytes: data.scheduler.tls.levels.application.recv.next,
      operation_result_bytes:
        Enum.reduce(data.operations, 0, fn {_, operation}, bytes ->
          bytes + :erlang.external_size(operation.result)
        end),
      queued_bytes: data.scheduler.queued_bytes,
      datagram_ready_bytes: data.datagram_bytes,
      datagram_ready_items: length(data.datagrams),
      datagram_drops: data.datagram_drops,
      ready_bytes: streams.ready_bytes,
      receive_buffered_bytes:
        Enum.reduce(streams.streams, 0, fn {_, s}, acc -> acc + s.recv_buffered end),
      recovery_packets:
        Enum.reduce(data.scheduler.recovery.spaces, 0, fn {_, s}, acc ->
          acc + map_size(s.sent)
        end),
      stream_records: map_size(streams.streams),
      event_count: length(data.events),
      operations: map_size(data.operations),
      tracked_references:
        map_size(data.operations) + map_size(data.budget.in_flight) + map_size(data.budget.timers) +
          Enum.count(
            [
              data.generation,
              Map.get(data, :owner_monitor),
              Map.get(data, :writer_monitor),
              Map.get(data, :consumer_monitor)
            ],
            &is_reference/1
          ),
      mailbox_messages: Process.info(self(), :message_queue_len) |> elem(1)
    }
  end

  defp observe(data) do
    highwaters =
      Enum.reduce(resources(data), data.highwaters, fn {name, value}, highwaters ->
        Map.update(highwaters, name, value, &max(&1, value))
      end)

    %{data | highwaters: highwaters}
  end

  defp notify_ready(%{ready_notified: true} = data), do: data

  defp notify_ready(data) do
    meta = metadata(data)

    if data.public do
      send(data.owner, {:quic_ready, self(), data.generation, meta})
      if is_pid(data.consumer), do: send(data.consumer, {:quic_ready, public_handle(data), meta})
    end

    observe(%{data | ready_notified: true, events: [{:ready, meta} | data.events]})
  end

  defp collect_stream_events(%{public: false} = data, events) do
    Enum.each(events, fn
      %{type: :stream, frame: frame, events: items} ->
        send(data.owner, {:quic_stream, self(), frame.stream_id, items})

      %{type: :reset_stream, frame: frame, events: items} ->
        send(data.owner, {:quic_stream_reset, self(), frame.stream_id, items})

      _ ->
        :ok
    end)

    data
  end

  defp collect_stream_events(data, events) do
    Enum.reduce(events, data, fn
      %{type: :datagram, data: bytes}, data ->
        if length(data.datagrams) < data.datagram_max_items and
             data.datagram_bytes + byte_size(bytes) <= data.datagram_max_bytes do
          data
          |> Map.update!(:datagrams, &(&1 ++ [bytes]))
          |> Map.update!(:datagram_bytes, &(&1 + byte_size(bytes)))
          |> queue_event(:datagram_readable)
        else
          %{data | datagram_drops: data.datagram_drops + 1}
        end

      %{type: type, frame: frame}, data when type in [:stream, :reset_stream] ->
        id = frame.stream_id
        handle = %StreamHandle{connection: public_handle(data), id: id}

        data =
          if MapSet.member?(data.seen_streams, id),
            do: data,
            else:
              queue_event(
                %{data | seen_streams: MapSet.put(data.seen_streams, id)},
                {:stream_open, handle, if(Bitwise.band(id, 2) == 0, do: :bidi, else: :uni)}
              )

        if Map.get(data.scheduler.streams.ready, id, []) == [],
          do: data,
          else: queue_event(data, {:readable, handle})

      %{type: :stop_sending, stream_id: id, error_code: code}, data ->
        queue_event(
          data,
          {:stopped, %StreamHandle{connection: public_handle(data), id: id}, code}
        )

      %{type: type}, data
      when type in [:ack, :max_data, :max_stream_data, :max_streams_bidi, :max_streams_uni] ->
        queue_event(data, :writable)

      _, data ->
        data
    end)
  end

  defp queue_event(data, event) do
    cond do
      event in data.events -> data
      length(data.events) >= data.event_limit - 1 -> %{data | event_error: :consumer_event_limit}
      true -> observe(%{data | events: data.events ++ [event]})
    end
  end

  defp datagram_payload_limit(max_frame) when max_frame <= 1, do: 0
  defp datagram_payload_limit(max_frame), do: datagram_payload_limit(max_frame, 0, max_frame)

  defp datagram_payload_limit(_frame, low, high) when low >= high, do: low

  defp datagram_payload_limit(frame, low, high) do
    candidate = div(low + high + 1, 2)
    {:ok, length} = Quic.Codec.encode_varint(candidate)

    if 1 + byte_size(length) + candidate <= frame,
      do: datagram_payload_limit(frame, candidate, high),
      else: datagram_payload_limit(frame, low, candidate - 1)
  end

  defp record_operation(data, ref, signature, status, result) do
    entry = %{
      signature: signature,
      status: status,
      result: result,
      sequence: data.operation_sequence
    }

    operations = Map.put(data.operations, ref, entry)

    operations =
      if map_size(operations) > data.operation_limit do
        {oldest, _} = Enum.min_by(operations, fn {_, entry} -> entry.sequence end)
        Map.delete(operations, oldest)
      else
        operations
      end

    observe(%{data | operations: operations, operation_sequence: data.operation_sequence + 1})
  end

  defp execute_operation(data, from, ref, signature, {:open, kind}) do
    case HandshakeScheduler.open_stream(data.scheduler, kind) do
      {:ok, scheduler, id} ->
        result = {:ok, %StreamHandle{connection: public_handle(data), id: id}}
        next = record_operation(%{data | scheduler: scheduler}, ref, signature, :admitted, result)
        {:keep_state, next, [{:reply, from, result}]}

      result ->
        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}
    end
  end

  defp execute_operation(data, from, ref, signature, {:close, code, reason})
       when is_integer(code) and code >= 0 and code < 4_611_686_018_427_387_904 and
              is_binary(reason) and byte_size(reason) <= 256 do
    case begin_closing(data, {:application, code, reason}) do
      {:ok, next, actions} ->
        next = record_operation(next, ref, signature, :admitted, :ok)
        {:next_state, :closing, next, [{:reply, from, :ok} | actions]}

      {:error, reason, next} ->
        stop_with_replies(next, reason, [{:reply, from, {:error, reason}}])
    end
  end

  defp execute_operation(data, from, ref, signature, request) do
    outcome = scheduler_operation(data.scheduler, request)

    case outcome do
      {:ok, scheduler, effects} ->
        result = {:ok, ref}
        next = record_operation(%{data | scheduler: scheduler}, ref, signature, :admitted, result)
        advance(next, effects, [{:reply, from, result}])

      {:error, reason, scheduler} ->
        stop_with_replies(%{data | scheduler: scheduler}, reason, [
          {:reply, from, {:error, reason}}
        ])

      result ->
        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}
    end
  end

  defp initial_packet?(<<first, _::binary>>), do: Bitwise.band(first, 0xF0) == 0xC0
  defp initial_packet?(_), do: false

  defp expired?(data), do: not data.ready and data.adapter.monotonic_time() >= data.deadline
  defp reply(from, result), do: {:keep_state_and_data, [{:reply, from, result}]}

  defp stop(data, reason), do: {:stop, :normal, %{data | reason: reason}}

  defp stop_with_replies(data, reason, []), do: stop(data, reason)

  defp stop_with_replies(data, reason, replies),
    do: {:stop_and_reply, :normal, replies, %{data | reason: reason}}

  @impl true
  def terminate(_reason, _phase, data) do
    if data.scheduler, do: TLSDriver.abort(data.scheduler.tls, data.reason)
    send(data.owner, {:quic_closed, self(), data.generation, data.reason})

    if is_pid(data.consumer),
      do: send(data.consumer, {:quic_closed, public_handle(data), data.reason})

    :ok
  end

  defp advance_received(data, events, effects, extra, from) do
    lost =
      Enum.flat_map(events, fn
        %{type: :ack, result: %{lost: lost}} -> lost
        _ -> []
      end)

    with {:ok, scheduler, retries} <- retry_packets(data.scheduler, lost, []),
         {:ok, scheduler, acks} <- HandshakeScheduler.schedule(scheduler) do
      advance(%{data | scheduler: scheduler}, effects ++ extra ++ retries ++ acks, [
        {:reply, from, :ok}
      ])
    else
      {:error, reason} ->
        stop_with_replies(data, reason, [{:reply, from, {:error, reason}}])

      {:error, reason, scheduler} ->
        stop_with_replies(%{data | scheduler: scheduler}, reason, [
          {:reply, from, {:error, reason}}
        ])
    end
  end

  defp flush_sent(result, next) do
    case result do
      :ok -> flush(next)
      {:error, reason} -> {:error, {:local_send, reason}, next}
    end
  end

  defp valid_item_limit?(value), do: is_integer(value) and value in 1..10_000
  defp valid_optional_timeout?(value), do: is_nil(value) or (is_integer(value) and value > 0)

  defp read_public_datagrams(data, from, ref, signature, request) do
    {:read_datagrams, max} = request

    cond do
      data.scheduler.local_max_datagram_frame_size == 0 ->
        result = {:error, :datagram_unsupported}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}

      is_integer(max) and max in 1..128 ->
        {out, rest} = Enum.split(data.datagrams, max)
        bytes = Enum.reduce(out, 0, &(byte_size(&1) + &2))
        next = %{data | datagrams: rest, datagram_bytes: data.datagram_bytes - bytes}

        next =
          if rest == [],
            do: %{next | events: List.delete(next.events, :datagram_readable)},
            else: queue_event(next, :datagram_readable)

        result = {:ok, out}
        next = record_operation(next, ref, signature, :completed, result)
        {:keep_state, next, [{:reply, from, result}]}

      true ->
        result = {:error, :invalid_operation}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}
    end
  end

  defp read_public_stream(data, from, ref, signature, request) do
    {:read, id, max} = request

    if is_integer(id) and id >= 0 and is_integer(max) and max in 1..16_384 do
      case HandshakeScheduler.consume_stream(data.scheduler, id, max) do
        {:ok, scheduler, events} ->
          case HandshakeScheduler.schedule(scheduler) do
            {:ok, scheduler, effects} ->
              result = {:ok, events}

              next =
                record_operation(
                  %{data | scheduler: scheduler},
                  ref,
                  signature,
                  :completed,
                  result
                )

              advance(next, effects, [{:reply, from, result}])

            {:error, reason, scheduler} ->
              result = {:ok, events}

              next =
                record_operation(
                  %{data | scheduler: scheduler},
                  ref,
                  signature,
                  :completed,
                  result
                )

              stop_with_replies(next, reason, [{:reply, from, result}])
          end

        {:error, reason} ->
          result = {:error, reason}

          {:keep_state, record_operation(data, ref, signature, :rejected, result),
           [{:reply, from, result}]}
      end
    else
      result = {:error, :invalid_operation}

      {:keep_state, record_operation(data, ref, signature, :rejected, result),
       [{:reply, from, result}]}
    end
  end

  defp scheduler_operation(scheduler, {:send, id, bytes, fin})
       when is_integer(id) and id >= 0 and is_binary(bytes) and is_boolean(fin) do
    HandshakeScheduler.send_stream(scheduler, id, bytes, fin)
  end

  defp scheduler_operation(scheduler, {:send_datagram, bytes}) do
    HandshakeScheduler.send_datagram(scheduler, bytes)
  end

  defp scheduler_operation(scheduler, {:reset, id, code})
       when is_integer(id) and id >= 0 and is_integer(code) and code >= 0 and
              code < 4_611_686_018_427_387_904 do
    HandshakeScheduler.reset_stream(scheduler, id, code)
  end

  defp scheduler_operation(scheduler, {:stop, id, code})
       when is_integer(id) and id >= 0 and is_integer(code) and code >= 0 and
              code < 4_611_686_018_427_387_904 do
    HandshakeScheduler.stop_stream(scheduler, id, code)
  end

  defp scheduler_operation(_scheduler, _) do
    {:error, :invalid_operation}
  end

  defp valid_timeout?(value), do: is_integer(value) and value > 0
  defp valid_operation_identity?(ref, deadline), do: is_reference(ref) and is_integer(deadline)
end

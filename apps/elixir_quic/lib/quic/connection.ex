defmodule Quic.Connection do
  @moduledoc """
  Temporary serialized QUIC connection runtime using an externally owned IO capability.

  The endpoint owner calls `deliver/5` synchronously with local/remote metadata
  after routing a datagram; `deliver/4` retains the selected path for compatibility.
  Only that owner may deliver; it must acquire receive credit before forwarding.
  A connection never closes the shared socket. The IO capability's `send/3`
  must return a local completion timestamp or a bounded failure.

  Public consumers use the generation handles and pull operations in `Quic`.
  See `docs/consumer-contract.md` for readiness, admission outcomes and limits.
  """
  @behaviour :gen_statem
  alias Quic.{HandshakeScheduler, LocalCIDs, Paths, Recovery, TLSDriver, TransportParameters}
  alias Quic.IO.Endpoint
  alias Quic.Runtime.{ConnectionHandle, StreamHandle}

  @tls_alert_codes %{
    unexpected_message: 10,
    bad_record_mac: 20,
    record_overflow: 22,
    handshake_failure: 40,
    bad_certificate: 42,
    unsupported_certificate: 43,
    certificate_revoked: 44,
    certificate_expired: 45,
    certificate_unknown: 46,
    illegal_parameter: 47,
    unknown_ca: 48,
    access_denied: 49,
    decode_error: 50,
    decrypt_error: 51,
    protocol_version: 70,
    insufficient_security: 71,
    internal_error: 80,
    inappropriate_fallback: 86,
    user_canceled: 90,
    missing_extension: 109,
    unsupported_extension: 110,
    unrecognized_name: 112,
    bad_certificate_status_response: 113,
    unknown_psk_identity: 115,
    certificate_required: 116,
    no_application_protocol: 120
  }

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
    :gen_statem.call(pid, {:stream_send, stream_id, data, fin}, timeout)
  catch
    :exit, {:timeout, _} -> {:unknown, :legacy_send}
  end

  @doc "Consume at most `max_bytes` from a manually delivered stream queue."
  def consume_stream(pid, stream_id, max_bytes, timeout \\ 5_000),
    do: :gen_statem.call(pid, {:stream_consume, stream_id, max_bytes}, timeout)

  def deliver(pid, generation, bytes, received_at),
    do: :gen_statem.call(pid, {:datagram, generation, bytes, received_at})

  def deliver(pid, generation, bytes, received_at, arrival),
    do: :gen_statem.call(pid, {:datagram, generation, bytes, received_at, arrival})

  def attach(pid, generation, consumer, opts) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    deadline = absolute_deadline(Keyword.get(opts, :deadline, timeout))
    remaining = max(0, min(timeout, deadline - System.monotonic_time(:millisecond)))

    if remaining > 0,
      do: safe_call(pid, {:attach, generation, consumer, opts, deadline}, remaining),
      else: {:error, :deadline_expired}
  end

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

  def open_public_stream(pid, generation, kind, opts \\ []) do
    request =
      case Keyword.fetch(opts, :reliable_prefix) do
        {:ok, prefix} -> {:open, kind, prefix}
        :error -> {:open, kind}
      end

    operation_call(pid, generation, request, opts)
  end

  def send_public_stream(pid, generation, id, data, fin, opts),
    do: operation_call(pid, generation, {:send, id, data, fin}, opts)

  def send_public_datagram(pid, generation, data, opts \\ []),
    do: operation_call(pid, generation, {:send_datagram, data}, opts)

  def migrate(pid, generation, opts),
    do: operation_call(pid, generation, {:migrate, Keyword.get(opts, :local)}, opts)

  def ping(pid, generation, opts \\ []),
    do: operation_call(pid, generation, {:ping}, opts)

  def read_datagrams(pid, generation, max, opts \\ []),
    do: durable_call(pid, {:read_datagrams, max}, generation, opts)

  def reset_public_stream(pid, generation, id, code, opts \\ []),
    do: operation_call(pid, generation, {:reset, id, code}, opts)

  def reset_public_stream_at(pid, generation, id, code, reliable, opts),
    do: operation_call(pid, generation, {:reset_at, id, code, reliable}, opts)

  def stop_public_stream(pid, generation, id, code, opts \\ []),
    do: operation_call(pid, generation, {:stop, id, code}, opts)

  defp handshake_deadline(opts, adapter, timeout) do
    relative = adapter.monotonic_time() + timeout * 1000

    case Keyword.get(opts, :cleanup_deadline) do
      {:abs_ms, deadline} when is_integer(deadline) -> min(relative, deadline * 1000)
      _ -> relative
    end
  end

  defp handshake_timeout(opts) do
    timeout = Keyword.get(opts, :handshake_timeout, 10_000)

    case Keyword.get(opts, :cleanup_deadline) do
      {:abs_ms, deadline} when is_integer(timeout) and timeout > 0 and is_integer(deadline) ->
        max(1, min(timeout, deadline - System.monotonic_time(:millisecond)))

      _ ->
        timeout
    end
  end

  defp enroll_cleanup(opts) do
    case Keyword.get(opts, :cleanup_birth) do
      nil -> :ok
      birth -> Quic.Cleanup.enroll(birth, self())
    end
  end

  defp start_handshake(data) do
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

  defp operation_call(pid, generation, request, opts) do
    request =
      if Keyword.has_key?(opts, :stream_epoch),
        do: {:stream_epoch, opts[:stream_epoch], request},
        else: request

    request =
      if Keyword.get(opts, :early_data) == :replayable, do: {:early, request}, else: request

    ref = Keyword.get(opts, :ref, make_ref())
    timeout = Keyword.get(opts, :timeout, 5_000)
    bound = Keyword.get(opts, :deadline, timeout)
    deadline = absolute_deadline(bound)
    timeout = call_timeout(timeout, bound)

    try do
      :gen_statem.call(pid, {:operation, generation, ref, deadline, request}, timeout)
    catch
      :exit, {:timeout, _} -> {:unknown, ref}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {_reason, _call} -> {:unknown, ref}
    end
  end

  defp durable_call(pid, request, generation, opts) do
    request =
      if Keyword.has_key?(opts, :stream_epoch),
        do: {:stream_epoch, opts[:stream_epoch], request},
        else: request

    ref = Keyword.get(opts, :ref, make_ref())
    timeout = Keyword.get(opts, :timeout, 5_000)
    bound = Keyword.get(opts, :deadline, timeout)
    deadline = absolute_deadline(bound)
    timeout = call_timeout(timeout, bound)

    try do
      :gen_statem.call(pid, {:public_pull, generation, ref, deadline, request}, timeout)
    catch
      :exit, {:timeout, _} -> {:unknown, ref}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, {_reason, _call} -> {:unknown, ref}
    end
  end

  defp call_timeout(timeout, {:abs_ms, deadline}),
    do: max(0, min(timeout, deadline - System.monotonic_time(:millisecond)))

  # Legacy duration options retain their existing call wait semantics.
  defp call_timeout(timeout, _duration), do: timeout

  defp absolute_deadline({:abs_ms, deadline}) when is_integer(deadline), do: deadline
  defp absolute_deadline(duration), do: System.monotonic_time(:millisecond) + duration

  defp safe_call(pid, request, timeout) do
    :gen_statem.call(pid, request, timeout)
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, {:noproc, _} -> {:error, :closed}
    :exit, {:normal, _} -> {:error, :closed}
    :exit, {reason, _call} -> {:error, {:closed, reason}}
  end

  @impl true
  def callback_mode, do: :handle_event_function

  @impl true
  def init(opts) do
    role = Keyword.fetch!(opts, :role)
    {adapter, writer} = Keyword.fetch!(opts, :io)
    timeout = handshake_timeout(opts)
    idle_timeout = Keyword.get(opts, :idle_timeout, 30_000)
    closing_timeout = Keyword.get(opts, :closing_timeout)
    draining_timeout = Keyword.get(opts, :draining_timeout)
    owner = Keyword.fetch!(opts, :owner)

    event_limit = Keyword.get(opts, :event_limit, 128)
    operation_limit = Keyword.get(opts, :operation_limit, 256)

    if role in [:client, :server] and is_pid(writer) and is_pid(owner) and
         valid_timeout?(timeout) and valid_idle_timeout?(idle_timeout) and
         valid_item_limit?(event_limit) and valid_item_limit?(operation_limit) and
         valid_optional_timeout?(closing_timeout) and valid_optional_timeout?(draining_timeout) do
      case Endpoint.new(Keyword.get(opts, :limits, [])) do
        {:ok, budget} ->
          # Clients are not subject to the server's pre-validation amplification limit.
          budget =
            if role == :client or Keyword.get(opts, :address_validated, false) do
              {:ok, validated} = Endpoint.validate_address(budget)
              validated
            else
              budget
            end

          generation = make_ref()

          data = %{
            cleanup: Keyword.get(opts, :cleanup),
            cleanup_monitor: Quic.Cleanup.monitor(Keyword.get(opts, :cleanup)),
            role: role,
            address_validated: Keyword.get(opts, :address_validated, false),
            adapter: adapter,
            writer: writer,
            path_writers: %{default: writer},
            local_migration: nil,
            exclusive_io: Keyword.get(opts, :exclusive_io, false),
            owner: owner,
            writer_monitor: Process.monitor(writer),
            owner_monitor: Process.monitor(owner),
            remote: Keyword.fetch!(opts, :remote),
            paths:
              Paths.new(
                role,
                Keyword.get(opts, :local),
                Keyword.fetch!(opts, :remote),
                role == :client or Keyword.get(opts, :address_validated, false)
              ),
            scheduler_opts: Keyword.fetch!(opts, :scheduler),
            scheduler: nil,
            pending_tls: nil,
            budget: budget,
            pending: [],
            ready: false,
            parameters_valid: false,
            generation: generation,
            deadline: handshake_deadline(opts, adapter, timeout),
            idle_timeout: idle_timeout,
            effective_idle_timeout: idle_timeout,
            idle_deadline: nil,
            idle_last_activity: nil,
            idle_send_allowed: true,
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
            operation_result_bytes: 0,
            operation_sequence: 0,
            operation_limit: operation_limit,
            highwaters: %{}
          }

          finish_init(opts, data, timeout)

        {:error, reason} ->
          {:stop, reason}
      end
    else
      {:stop, :invalid_connection_options}
    end
  end

  defp finish_init(opts, data, timeout) do
    case enroll_cleanup(opts) do
      :ok ->
        {:ok, :handshaking, data,
         [{:next_event, :internal, :start}, {{:timeout, :handshake}, timeout, data.generation}]}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_event(:internal, :start, :handshaking, data) do
    with :ok <- Quic.Cleanup.authorize(data.cleanup),
         true <- data.adapter.monotonic_time() < data.deadline do
      start_handshake(data)
    else
      {:error, reason} -> {:stop, {:cleanup, reason}, data}
      false -> {:stop, :normal, data}
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
      reliable_reset: %{
        draft: 11,
        local: data.scheduler.local_reset_stream_at,
        peer: data.scheduler.peer_reset_stream_at,
        negotiated: data.scheduler.local_reset_stream_at and data.scheduler.peer_reset_stream_at
      },
      resumption: %{
        resumed: TLSDriver.info(data.scheduler.tls)[:resumed] == true,
        early_data: data.scheduler.early_status
      },
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

  def handle_event({:call, from}, {:attach, generation, consumer, opts, deadline}, phase, data) do
    if System.monotonic_time(:millisecond) >= deadline,
      do: reply(from, {:error, :deadline_expired}),
      else: handle_event({:call, from}, {:attach, generation, consumer, opts}, phase, data)
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
              entry -> Map.take(entry, [:status, :result, :outcome])
            end}
         ]}

  def handle_event(
        {:call, {caller, _} = from},
        {:public_pull, generation, ref, deadline, request},
        phase,
        data
      ) do
    signature = :crypto.hash(:sha256, :erlang.term_to_binary({:pull, request}))
    {request, valid_epoch} = unwrap_stream_epoch(request, data.scheduler.early_epoch)

    cond do
      not valid_epoch ->
        reply(from, {:error, :stale_stream_epoch})

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

      true ->
        execute_public_pull(data, from, ref, signature, request, phase)
    end
  end

  def handle_event({:call, from}, {:operation, generation, ref, deadline, request}, phase, data) do
    signature = :crypto.hash(:sha256, :erlang.term_to_binary(request))

    {early, request} =
      case request do
        {:early, request} -> {true, request}
        request -> {false, request}
      end

    {request, valid_epoch} = unwrap_stream_epoch(request, data.scheduler.early_epoch)

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

      closing_request?(phase, request) ->
        result = :ok

        {:keep_state, record_operation(data, ref, signature, :admitted, result),
         [{:reply, from, result}]}

      not valid_epoch ->
        result = {:error, :stale_stream_epoch}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}

      early_admissible?(data, phase, early, request) ->
        execute_early_operation(data, from, ref, signature, request)

      phase != :established and elem(request, 0) != :close ->
        result = {:error, :not_established}

        {:keep_state, record_operation(data, ref, signature, :rejected, result),
         [{:reply, from, result}]}

      match?({:migrate, _}, request) ->
        start_local_migration(data, from, ref, signature, request, deadline)

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

  def handle_event({:call, from}, {:datagram, generation, bytes, at}, phase, data) do
    handle_event(
      {:call, from},
      {:datagram, generation, bytes, at, %{local: data.local, remote: data.remote}},
      phase,
      data
    )
  end

  def handle_event(
        {:call, {caller, _} = from},
        {:datagram, generation, bytes, at, arrival},
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
        receive_arrival(data, bytes, at, from, arrival)
    end
  end

  def handle_event(
        {:call, {caller, _} = from},
        {:datagram, generation, _bytes, _at, _arrival},
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
    # PTO can grow after the timer was armed (RFC 9000 section 10.1).
    data = update_idle_deadline(data)
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

  def handle_event({:timeout, :early_keys}, generation, phase, %{generation: generation} = data)
      when phase in [:handshaking, :established] do
    deadline = data.scheduler.early_key_deadline

    if is_integer(deadline) and data.adapter.monotonic_time() >= deadline do
      {:keep_state, %{data | scheduler: HandshakeScheduler.retire_early_keys(data.scheduler)}}
    else
      {:keep_state, data, early_keys_timer(data)}
    end
  end

  def handle_event({:timeout, :recovery}, {generation, token}, phase, data)
      when phase in [:handshaking, :established] do
    recovery = data.scheduler.recovery
    now = data.adapter.monotonic_time()

    if generation == data.generation and Recovery.timer_expired?(recovery, token, now) do
      {:ok, recovery, result} = Recovery.on_time(recovery, now)
      scheduler = %{data.scheduler | recovery: recovery}

      with {:ok, scheduler, effects} <- retry_packets(scheduler, result.lost, []),
           {:ok, scheduler, effects} <- retry_packets(scheduler, result.probes, effects, :probe) do
        advance(%{data | scheduler: scheduler}, effects, [])
      else
        {:error, reason} -> stop(data, {:recovery, reason})
      end
    else
      :keep_state_and_data
    end
  end

  def handle_event({:timeout, :recovery}, _token, phase, _data)
      when phase in [:closing, :draining],
      do: :keep_state_and_data

  def handle_event({:timeout, :path}, {generation, candidate}, :established, data) do
    if generation == data.generation and candidate == data.paths.candidate do
      now = data.adapter.monotonic_time()

      available =
        Enum.filter(
          Map.keys(data.paths.paths),
          &HandshakeScheduler.path_available?(data.scheduler, &1)
        )

      case Paths.on_time(data.paths, now, available) do
        {:ok, paths, _retiring} ->
          data = select_path(%{data | paths: paths})

          data =
            if data.local_migration && data.local_migration.phase in [:binding, :validating],
              do: migration_outcome(data, {:error, :validation_timeout}),
              else: data

          data = reclaim_path(data)
          {data, effects} = path_probes(data, now, [])
          advance(data, effects, [])

        {:error, reason} ->
          stop(data, {:migration, reason})
      end
    else
      :keep_state_and_data
    end
  end

  def handle_event(
        :info,
        {:quic_path_bound, generation, ref, id, result},
        :established,
        %{generation: generation, local_migration: %{ref: ref, id: id, phase: :binding}} = data
      ) do
    case result do
      {:ok, writer, local} ->
        paths = data.paths
        paths = put_in(paths.paths[id].local, local)
        paths = put_in(paths.paths[id].retry_at, data.adapter.monotonic_time())
        migration = %{data.local_migration | phase: :validating}

        next = %{
          data
          | paths: paths,
            path_writers: Map.put(data.path_writers, id, writer),
            local_migration: migration
        }

        if data.adapter.monotonic_time() >= paths.paths[id].deadline do
          fail_local_migration(next, :validation_timeout)
        else
          {next, effects} = path_probes(next, data.adapter.monotonic_time(), [])
          advance(next, effects, [])
        end

      {:error, reason} ->
        fail_local_migration(data, reason)
    end
  end

  def handle_event(
        :info,
        {:quic_path_bound, generation, _ref, id, _result},
        _phase,
        %{generation: generation} = data
      ) do
    send(data.owner, {:quic_retire_local_path, self(), generation, id})
    :keep_state_and_data
  end

  def handle_event(
        :info,
        {:quic_path_retired, generation, id},
        :established,
        %{generation: generation, local_migration: %{phase: :retiring}} = data
      ) do
    if data.paths.retiring == id do
      {:ok, paths} = Paths.drop(data.paths, id)

      next = %{
        data
        | paths: paths,
          path_writers: Map.delete(data.path_writers, id),
          local_migration: nil
      }

      advance(next, [], [])
    else
      :keep_state_and_data
    end
  end

  def handle_event(
        :info,
        {:quic_local_path_failed, generation, id},
        :established,
        %{generation: generation, local_migration: %{id: id, phase: phase}} = data
      )
      when phase in [:binding, :validating] do
    fail_local_migration(data, :candidate_socket_closed)
  end

  def handle_event(
        :info,
        {:quic_tls_result, generation, id, result},
        phase,
        %{generation: generation, pending_tls: %{id: id, deadline: deadline}} = data
      )
      when phase in [:handshaking, :established] do
    reply = if System.monotonic_time(:millisecond) < deadline, do: result, else: :miss
    if reply == :miss, do: send(data.owner, {:quic_early_release, self(), data.generation})
    continue_tls_request(%{data | pending_tls: nil}, id, reply)
  end

  def handle_event(
        {:timeout, :tls_authority},
        {generation, id},
        phase,
        %{generation: generation, pending_tls: %{id: id}} = data
      )
      when phase in [:handshaking, :established] do
    send(data.owner, {:quic_early_release, self(), data.generation})
    continue_tls_request(%{data | pending_tls: nil}, id, :miss)
  end

  def handle_event(:info, {:quic_cid_registered, generation, identity}, phase, data)
      when phase in [:handshaking, :established] do
    if generation == data.generation do
      case LocalCIDs.registered(data.scheduler.local_cids, identity) do
        {:ok, cids, frame} ->
          scheduler =
            HandshakeScheduler.queue_control(%{data.scheduler | local_cids: cids}, :application, [
              frame
            ])

          case HandshakeScheduler.schedule(scheduler) do
            {:ok, scheduler, effects} -> advance(%{data | scheduler: scheduler}, effects, [])
            {:error, reason, scheduler} -> stop(%{data | scheduler: scheduler}, reason)
          end

        {:error, _} ->
          :keep_state_and_data
      end
    else
      :keep_state_and_data
    end
  end

  def handle_event(
        :info,
        {:quic_cid_registration_failed, generation, _identity},
        _phase,
        %{generation: generation} = data
      ),
      do: stop(data, :cid_registration_failed)

  def handle_event(
        :info,
        {:quic_cleanup_retire, observer},
        _phase,
        %{cleanup: %Quic.Cleanup.Lease{handle: %{observer: observer}}} = data
      ),
      do: {:stop, :normal, data}

  def handle_event(:info, {:DOWN, ref, :process, _pid, reason}, _phase, data) do
    cond do
      ref == data.cleanup_monitor -> {:stop, :normal, data}
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

  defp execute_public_pull(data, from, ref, signature, {:events, max}, _phase)
       when is_integer(max) and max in 1..128 do
    {out, rest} = Enum.split(data.events, max)
    result = {:ok, out}
    next = record_operation(%{data | events: rest}, ref, signature, :completed, result)
    {:keep_state, next, [{:reply, from, result}]}
  end

  defp execute_public_pull(
         data,
         from,
         ref,
         signature,
         {:read_datagrams, _} = request,
         :established
       ),
       do: read_public_datagrams(data, from, ref, signature, request)

  defp execute_public_pull(data, from, ref, signature, {:read, _, _} = request, :established),
    do: read_public_stream(data, from, ref, signature, request)

  defp execute_public_pull(data, from, ref, signature, _request, _phase) do
    result = {:error, :invalid_operation}

    {:keep_state, record_operation(data, ref, signature, :rejected, result),
     [{:reply, from, result}]}
  end

  defp closing_request?(phase, request),
    do: phase in [:closing, :draining] and elem(request, 0) == :close

  defp early_admissible?(data, phase, early, request) do
    phase == :handshaking and early and early_request?(request) and
      HandshakeScheduler.early_writable?(data.scheduler) and
      Enum.count(data.operations, fn {_, entry} -> Map.get(entry, :early, false) end) <
        data.operation_limit - 1
  end

  defp receive_arrival(data, bytes, at, from, %{local: local, remote: remote}) do
    case Paths.lookup_local(data.paths, local, remote) do
      {:ok, id}
      when data.local_migration != nil and data.local_migration.phase == :retiring and
             data.paths.retiring == id ->
        # Keep path identity until native IO retirement is acknowledged, but never
        # decrypt or account ingress after its controller and ledger are released.
        reply(from, :ok)

      {:ok, id} ->
        receive_packet(data, bytes, at, from, remote, id)

      :error
      when local == data.local and data.role == :server and data.ready and
             map_size(data.paths.paths) < 2 ->
        if data.scheduler.tls.facts.quic_confirmed and byte_size(bytes) > 0 and
             Bitwise.band(:binary.at(bytes, 0), 0x80) == 0 do
          receive_packet(data, bytes, at, from, remote, data.paths.next_id)
        else
          reply(from, :ok)
        end

      _ ->
        reply(from, :ok)
    end
  end

  defp receive_arrival(_data, _bytes, _at, from, _), do: reply(from, {:error, :invalid_path})

  defp receive_packet(data, bytes, at, from, remote, path_id) do
    case HandshakeScheduler.receive_datagram(data.scheduler, bytes, at, path_id) do
      {:ok, scheduler, events} ->
        authenticated = scheduler.authenticated_packets > data.scheduler.authenticated_packets

        case account_arrival(data, scheduler, events, remote, at, byte_size(bytes), path_id) do
          {:ok, data} -> receive_authenticated(data, events, path_id, at, from, authenticated)
          :discard -> reply(from, :ok)
        end

      {:error, _reason, %{authenticated_error: false}} ->
        reply(from, :ok)

      {:error, :bad_tag, _scheduler} ->
        # RFC9001 section5.5: unauthenticated packets do not affect the connection.
        reply(from, :ok)

      {:error, {:wrong_encryption_level, type, _} = reason, scheduler} ->
        frame_type = wrong_level_frame_type(type)

        close_transport_error(%{data | scheduler: scheduler}, from, reason, 0x0A, frame_type)

      {:error, {:key_update_error, _} = reason, scheduler} ->
        close_transport_error(%{data | scheduler: scheduler}, from, reason, 0x0E, 0)

      {:error, %SSL.QUIC.Error{kind: :tls} = error, scheduler} ->
        {next, reason} = tls_failure_state(%{data | scheduler: scheduler}, error)
        stop_with_replies(next, reason, [{:reply, from, {:error, reason}}])

      {:error, %SSL.QUIC.Error{} = error, _scheduler} ->
        reason = {:tls, error.kind, error.alert, error.reason}
        {:stop_and_reply, :normal, [{:reply, from, {:error, reason}}], %{data | reason: reason}}

      {:error, {:transport_parameters, :reduced_early_transport_limits} = reason, scheduler} ->
        close_transport_error(%{data | scheduler: scheduler}, from, reason, 0x08, 0x06)

      {:error, {:transport_error, code, frame_type, reason}, scheduler} ->
        close_transport_error(%{data | scheduler: scheduler}, from, reason, code, frame_type)

      {:error, {:protocol_violation, 0x0A, frame_type} = reason, scheduler} ->
        close_transport_error(%{data | scheduler: scheduler}, from, reason, 0x0A, frame_type)

      {:error, reason, scheduler} ->
        close_authenticated_error(data, scheduler, from, reason)
    end
  end

  defp close_authenticated_error(data, scheduler, from, reason) do
    case authenticated_error_code(reason) do
      {code, frame_type} ->
        close_transport_error(%{data | scheduler: scheduler}, from, reason, code, frame_type)

      nil ->
        stop_with_replies(data, reason, [{:reply, from, {:error, reason}}])
    end
  end

  defp wrong_level_frame_type(:ack), do: 0x02
  defp wrong_level_frame_type(:crypto), do: 0x06
  defp wrong_level_frame_type(:new_token), do: 0x07
  defp wrong_level_frame_type(:path_response), do: 0x1B
  defp wrong_level_frame_type(:handshake_done), do: 0x1E
  defp wrong_level_frame_type(_type), do: 0

  # RFC 9000 section 20.1 codes for authenticated frame and packet failures that
  # the scheduler reports without a transport code (section 10.2: close, not drop).
  defp authenticated_error_code({:invalid_ack, :ack_never_issued}), do: {0x0A, 0x02}
  defp authenticated_error_code({:invalid_ack, :ack_range_limit}), do: {0x01, 0x02}
  defp authenticated_error_code({:invalid_ack, _}), do: {0x07, 0x02}
  defp authenticated_error_code({:malformed_frame, _}), do: {0x07, 0}
  defp authenticated_error_code(:trailing_frame_bytes), do: {0x07, 0}
  defp authenticated_error_code(:unexpected_handshake_done), do: {0x0A, 0x1E}
  defp authenticated_error_code(:unexpected_new_token), do: {0x0A, 0x07}
  defp authenticated_error_code(:missing_peer_connection_id), do: {0x0A, 0x18}
  defp authenticated_error_code(:connection_id_conflict), do: {0x0A, 0x18}
  defp authenticated_error_code(:invalid_retire_prior_to), do: {0x07, 0x18}
  defp authenticated_error_code(:connection_id_limit), do: {0x09, 0x18}
  defp authenticated_error_code(:control_queue_limit), do: {0x01, 0}
  defp authenticated_error_code(_reason), do: nil

  defp tls_failure_state(data, error) do
    reason = {:tls, error.kind, error.alert, error.reason}
    code = 0x100 + Map.get(@tls_alert_codes, error.alert, 80)

    # Fatal TLS failures emit the alert before terminal route retirement.
    next =
      case begin_closing(data, {:transport, code, 0x06}) do
        {:ok, next, _actions} -> next
        {:error, _close_reason, next} -> next
      end

    {next, reason}
  end

  defp receive_authenticated(data, events, path_id, at, from, authenticated) do
    pending =
      if Enum.any?(events, &(&1.type == :retry)),
        do: Enum.reject(data.pending, &(&1.level == :initial)),
        else: data.pending

    data = %{data | pending: pending}
    data = if authenticated, do: refresh_idle(%{data | idle_send_allowed: true}), else: data
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
          advance_received(data, events, effects, extra, from, path_id, at)

        {:error, reason} ->
          {:stop_and_reply, :normal, [{:reply, from, {:error, reason}}], %{data | reason: reason}}
      end
    end
  end

  defp account_arrival(data, scheduler, events, remote, at, bytes, path_id) do
    facts = Enum.filter(events, &(&1.type == :authenticated_packet and &1.level == :application))
    known = Map.has_key?(data.paths.paths, path_id)

    if known or facts != [] do
      {budget, recovery} =
        if known do
          {data.budget, scheduler.recovery}
        else
          {:ok, budget} = Endpoint.add_path(data.budget, path_id, false)
          {:ok, recovery} = Recovery.add_path(scheduler.recovery, path_id)
          {budget, recovery}
        end

      pto = max(Recovery.pto_duration(recovery), Recovery.pto_duration(recovery, path_id))

      scheduler = %{scheduler | recovery: recovery}

      case bind_arrival(data, scheduler, facts, path_id, known) do
        {:ok, scheduler} ->
          paths = arrival_paths(data, scheduler, facts, path_id, remote, at, pto)

          {:ok, budget} = Endpoint.receive_bytes(budget, bytes, path_id)

          {budget, paths} =
            if not data.ready and scheduler.tls.facts.address_validated do
              {:ok, budget} = Endpoint.validate_address(budget, :default)
              {budget, Paths.validate(paths, :default)}
            else
              {budget, paths}
            end

          scheduler = %{
            scheduler
            | recovery: recovery,
              max_packet_size:
                if(known,
                  do: scheduler.max_packet_size,
                  else: min(1200, scheduler.max_packet_size)
                )
          }

          {:ok, select_path(%{data | scheduler: scheduler, paths: paths, budget: budget})}

        {:error, :no_unused_connection_id} ->
          :discard
      end
    else
      :discard
    end
  end

  defp arrival_paths(%{role: :client} = data, _scheduler, facts, path_id, _remote, _at, _pto) do
    Enum.reduce(facts, data.paths, fn packet, paths ->
      Paths.note_cid(paths, path_id, packet.dcid, packet.number)
    end)
  end

  defp arrival_paths(data, scheduler, facts, _path_id, remote, at, pto),
    do: observe_paths(data, scheduler, facts, remote, at, pto)

  defp observe_paths(data, scheduler, facts, remote, at, pto) do
    Enum.reduce(facts, data.paths, fn packet, paths ->
      {paths, id} =
        if data.ready and scheduler.tls.facts.quic_confirmed do
          {:ok, paths, id, _new} =
            Paths.observe(paths, remote, packet.number, packet.probing, at, pto)

          {paths, id}
        else
          {:ok, id} = Paths.lookup(paths, remote)
          {paths, id}
        end

      Paths.note_cid(paths, id, packet.dcid, packet.number)
    end)
  end

  defp bind_arrival(_data, scheduler, _facts, _path_id, true), do: {:ok, scheduler}

  defp bind_arrival(data, scheduler, [packet | _], path_id, false) do
    previous = data.paths.active
    previous_dcid = data.paths.paths[previous].dcid || scheduler.scid
    HandshakeScheduler.bind_path(scheduler, path_id, previous, packet.dcid == previous_dcid)
  end

  defp select_path(data) do
    id = data.paths.active
    {:ok, recovery} = Recovery.select_path(data.scheduler.recovery, id)
    {:ok, budget} = Endpoint.select_path(data.budget, id)

    next = %{
      data
      | scheduler: %{data.scheduler | recovery: recovery},
        budget: budget,
        remote: data.paths.paths[id].remote
    }

    writer = data.path_writers[id]

    if data.role == :client and is_pid(writer) and writer != data.writer do
      Process.demonitor(data.writer_monitor, [:flush])
      send(data.owner, {:quic_select_local_path, self(), data.generation, id})

      %{
        next
        | writer: writer,
          writer_monitor: Process.monitor(writer),
          local: data.paths.paths[id].local
      }
    else
      next
    end
  end

  defp receive_path_response(data, value, at, effects) do
    case Paths.response(data.paths, value, at) do
      {:ok, paths, id} ->
        {:ok, budget} = Endpoint.validate_address(data.budget, id)
        next = %{data | paths: paths, budget: budget}

        case data.local_migration do
          %{id: ^id, phase: :validating} ->
            case Paths.commit_local(paths, id) do
              {:ok, paths} ->
                next = select_path(%{next | paths: paths})

                {:ok, scheduler, sends} =
                  HandshakeScheduler.send_path_frames(
                    next.scheduler,
                    id,
                    [%{type: :ping}],
                    0
                  )

                next =
                  migration_outcome(
                    %{next | scheduler: scheduler},
                    {:ok, paths.paths[id].local}
                  )

                {next, effects ++ sends}

              {:error, :unvalidated_path} ->
                {next, effects}
            end

          _ ->
            {next, effects}
        end

      :ignore ->
        {data, effects}
    end
  end

  defp path_events(data, events, arrival, at, effects) do
    {data, effects} =
      Enum.reduce(events, {data, effects}, fn
        %{type: :path_response, data: value}, {data, effects} ->
          receive_path_response(data, value, at, effects)

        %{type: :path_challenge, data: value}, {data, effects} ->
          padding = path_padding(data, arrival, effects)

          case HandshakeScheduler.send_path_frames(
                 data.scheduler,
                 arrival,
                 [%{type: :path_response, data: value}],
                 padding
               ) do
            {:ok, scheduler, sends} -> {%{data | scheduler: scheduler}, effects ++ sends}
            {:blocked, _} -> {data, effects}
          end

        %{type: :retire_connection_id, cid: cid}, {data, effects} when is_binary(cid) ->
          send(data.owner, {:quic_retire_cid, self(), data.generation, cid})
          {data, effects}

        _, acc ->
          acc
      end)

    path_probes(data, at, effects)
  end

  defp path_padding(data, id, effects) do
    ledger = Endpoint.path(data.budget, id)

    planned =
      Enum.reduce(data.pending ++ effects, 0, fn effect, bytes ->
        if Map.get(effect, :path_id, :default) == id,
          do: bytes + byte_size(effect.bytes),
          else: bytes
      end)

    if ledger.address_validated or
         3 * ledger.bytes_received - ledger.bytes_sent -
           ledger.bytes_pending - planned >= 1200,
       do: 1200,
       else: 0
  end

  defp path_probes(data, at, effects) do
    Enum.reduce(Paths.due(data.paths, at), {data, effects}, fn id, {data, effects} ->
      padding = path_padding(data, id, effects)
      value = :crypto.strong_rand_bytes(8)

      pto =
        max(
          Recovery.pto_duration(data.scheduler.recovery, id),
          Recovery.pto_duration(data.scheduler.recovery)
        )

      case HandshakeScheduler.send_path_frames(
             data.scheduler,
             id,
             [%{type: :path_challenge, data: value}],
             padding
           ) do
        {:ok, scheduler, sends} ->
          {:ok, paths} = Paths.probe(data.paths, id, value, padding >= 1200, at, pto)
          {%{data | scheduler: scheduler, paths: paths}, effects ++ sends}

        {:blocked, _} ->
          paths = data.paths

          paths =
            put_in(paths.paths[id].retry_at, min(paths.paths[id].deadline, at + pto))

          {%{data | paths: paths}, effects}
      end
    end)
  end

  defp reclaim_path(%{paths: %{retiring: nil}} = data), do: data

  defp reclaim_path(%{local_migration: %{phase: :retiring}} = data), do: data

  defp reclaim_path(data) do
    id = data.paths.retiring
    pending = Enum.any?(data.pending, &(Map.get(&1, :path_id, :default) == id))

    with false <- pending,
         {:ok, recovery} <- Recovery.drop_path(data.scheduler.recovery, id),
         {:ok, budget} <- Endpoint.drop_path(data.budget, id) do
      scheduler = HandshakeScheduler.drop_path_binding(%{data.scheduler | recovery: recovery}, id)

      if data.local_migration do
        send(data.owner, {:quic_retire_local_path, self(), data.generation, id})

        %{
          data
          | scheduler: scheduler,
            budget: budget,
            local_migration: %{data.local_migration | phase: :retiring}
        }
      else
        {:ok, paths} = Paths.drop(data.paths, id)
        %{data | scheduler: scheduler, paths: paths, budget: budget}
      end
    else
      _ -> data
    end
  end

  defp refill_local_cids(data) do
    if LocalCIDs.refill?(data.scheduler.local_cids) do
      identity = make_ref()

      {:ok, cids, registration} =
        LocalCIDs.reserve(
          data.scheduler.local_cids,
          :crypto.strong_rand_bytes(byte_size(data.scheduler.scid)),
          :crypto.strong_rand_bytes(16),
          identity
        )

      send(data.owner, {:quic_register_cid, self(), data.generation, registration})
      %{data | scheduler: %{data.scheduler | local_cids: cids}}
    else
      data
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

        data =
          refresh_idle(%{
            data
            | scheduler: scheduler,
              effective_idle_timeout: timeout
          })

        finish_readiness(data)
      else
        false -> {:error, :incomplete_authentication}
        {:error, reason} -> {:error, {:transport_parameters, reason}}
      end
    else
      {:ok, data, []}
    end
  end

  defp finish_readiness(data) do
    {scheduler, early_events} = HandshakeScheduler.take_early_events(data.scheduler)

    case complete_handshake(scheduler, data.role) do
      {:ok, scheduler, effects} ->
        send(data.owner, {:quic_early_release, self(), data.generation})

        next =
          %{data | scheduler: scheduler, ready: true, parameters_valid: true}
          |> notify_ready()
          |> collect_stream_events(early_events)

        {:ok, next, effects}

      {:error, reason, _} ->
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp complete_handshake(scheduler, :server),
    do: HandshakeScheduler.handshake_done(HandshakeScheduler.confirm_handshake(scheduler))

  defp complete_handshake(scheduler, :client), do: {:ok, scheduler, []}

  defp advance(data, effects, replies) do
    data = data |> dispatch_tls_actions() |> settle_early_operations()

    pending =
      Enum.reject(data.pending ++ effects, &HandshakeScheduler.retired?(data.scheduler, &1.level))

    case settle_pending(%{data | pending: pending}) do
      {:ok, data} ->
        data = reclaim_path(data)

        case HandshakeScheduler.schedule(data.scheduler) do
          {:ok, scheduler, sends} ->
            advance_pending(
              %{data | scheduler: scheduler, pending: data.pending ++ sends},
              replies
            )

          {:error, reason, _scheduler} ->
            stop_with_replies(data, reason, replies)
        end

      {:error, reason} ->
        stop_with_replies(data, {:pending_send, reason}, replies)
    end
  end

  # Only effects that have never reached the writer may be cancelled. Their
  # reservations remain attributed to the original path until this settlement;
  # reliable ranges are subsequently protected with fresh packet numbers.
  defp settle_pending(data) do
    {cancel, keep} =
      Enum.split_with(data.pending, fn effect ->
        Map.get(effect, :path_id, :default) == data.paths.retiring or
          not HandshakeScheduler.pending_send_valid?(data.scheduler, effect)
      end)

    if cancel == [] do
      {:ok, data}
    else
      result =
        Enum.reduce_while(cancel, {:ok, data.scheduler}, fn effect, {:ok, scheduler} ->
          result =
            if match?(
                 %{status: :discarded},
                 scheduler.recovery.spaces[effect.space].sent[effect.packet_number]
               ),
               do: {:ok, scheduler},
               else:
                 HandshakeScheduler.cancel_unsent(scheduler, effect.space, effect.packet_number)

          case result do
            {:ok, scheduler} -> {:cont, {:ok, scheduler}}
            {:error, reason} -> {:halt, {:error, reason}}
          end
        end)

      with {:ok, scheduler} <- result,
           {:ok, scheduler, effects} <- HandshakeScheduler.schedule(scheduler) do
        {:ok, %{data | scheduler: scheduler, pending: keep ++ effects}}
      else
        {:error, reason, _scheduler} -> {:error, reason}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp advance_pending(%{pending: pending} = data, replies) do
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
            data = data |> refill_local_cids() |> notify_ready()

            established_data = data

            {:next_state, :established, established_data,
             replies ++
               [{{:timeout, :handshake}, :cancel}] ++
               early_keys_timer(established_data) ++
               recovery_timer(established_data) ++
               idle_timer(established_data) ++
               path_timer(established_data) ++ tls_authority_timer(established_data)}

          {:ok, data} ->
            {:keep_state, data,
             replies ++
               early_keys_timer(data) ++
               recovery_timer(data) ++ idle_timer(data) ++ tls_authority_timer(data)}

          {:error, reason, data} ->
            stop_with_replies(data, reason, replies)
        end
    end
  end

  defp flush(%{pending: []} = data), do: {:ok, data}

  defp flush(data) do
    if expired?(data) do
      {:error, :handshake_timeout, data}
    else
      case eligible_send(data) do
        :blocked ->
          {:ok, data}

        {:error, reason} ->
          {:error, reason, data}

        {:ok, budget, send, effect, rest, remote} ->
          data = observe(%{data | budget: budget})
          {:ok, budget, ^send} = Endpoint.dequeue(budget)
          data = observe(%{data | budget: budget})
          packet = data.scheduler.recovery.spaces[effect.space].sent[effect.packet_number]
          ack_eliciting = packet.metadata.ack_eliciting

          {result, at} =
            local_send(data, effect.bytes, remote, Map.get(effect, :path_id, :default))

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

              next = refresh_sent_idle(next, result, ack_eliciting, at)
              flush_sent(result, next)

            {:error, reason} ->
              {:error, {:send_accounting, reason}, data}
          end
      end
    end
  end

  # Amplification credit belongs to each path. A large blocked application
  # packet must not prevent a smaller validation probe or old-path response.
  defp eligible_send(data) do
    now = data.adapter.monotonic_time()

    data.pending
    |> Enum.with_index()
    |> Enum.reduce_while(:blocked, fn {effect, index}, :blocked ->
      id = Map.get(effect, :path_id, :default)
      remote = data.paths.paths[id].remote

      case Endpoint.enqueue(data.budget, effect.bytes, remote, now, id) do
        {:error, :anti_amplification} ->
          {:cont, :blocked}

        {:error, reason} ->
          {:halt, {:error, reason}}

        {:ok, budget, send} ->
          {:halt, {:ok, budget, send, effect, List.delete_at(data.pending, index), remote}}
      end
    end)
  end

  defp dispatch_tls_actions(data) do
    {scheduler, actions} = HandshakeScheduler.take_tls_actions(data.scheduler)

    Enum.reduce(actions, %{data | scheduler: scheduler}, fn
      {:session_ticket, session}, data ->
        send(data.owner, {:quic_session_ticket, self(), data.generation, session})
        data

      {_kind, request}, data ->
        now = System.monotonic_time(:millisecond)
        deadline = if data.ready, do: now + 100, else: min(now + 100, div(data.deadline, 1000))
        send(data.owner, {:quic_tls_request, self(), data.generation, request, deadline})
        %{data | pending_tls: %{id: request.id, deadline: deadline}}
    end)
  end

  defp continue_tls_request(data, id, result) do
    case HandshakeScheduler.continue_tls(data.scheduler, id, result) do
      {:ok, scheduler, effects} ->
        case readiness(%{data | scheduler: scheduler}) do
          {:ok, data, extra} -> advance(data, effects ++ extra, [])
          {:error, reason} -> stop(%{data | scheduler: scheduler}, reason)
        end

      {:error, %SSL.QUIC.Error{kind: :tls} = error, scheduler} ->
        {next, reason} = tls_failure_state(%{data | scheduler: scheduler}, error)
        stop(next, reason)

      {:error, reason, scheduler} ->
        stop(%{data | scheduler: scheduler}, {:tls_continuation, reason})
    end
  end

  defp tls_authority_timer(data)
       when not is_map_key(data, :pending_tls) or data.pending_tls == nil,
       do: [{{:timeout, :tls_authority}, :cancel}]

  defp tls_authority_timer(data) do
    delay = max(0, data.pending_tls.deadline - System.monotonic_time(:millisecond))
    [{{:timeout, :tls_authority}, delay, {data.generation, data.pending_tls.id}}]
  end

  defp early_keys_timer(data) do
    case data.scheduler.early_key_deadline do
      nil ->
        [{{:timeout, :early_keys}, :cancel}]

      deadline ->
        delay = max(0, div(deadline - data.adapter.monotonic_time() + 999, 1000))
        [{{:timeout, :early_keys}, delay, data.generation}]
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

  defp path_timer(data) do
    case Paths.next_deadline(data.paths) do
      nil ->
        [{{:timeout, :path}, :cancel}]

      deadline ->
        delay = max(0, div(deadline - data.adapter.monotonic_time() + 999, 1000))
        [{{:timeout, :path}, delay, {data.generation, data.paths.candidate}}]
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
  defp effective_idle_timeout(:infinity, peer), do: peer
  defp effective_idle_timeout(local, peer), do: min(local, peer)

  defp idle_period(%{effective_idle_timeout: :infinity}), do: :infinity

  defp idle_period(data) do
    max(data.effective_idle_timeout * 1000, 3 * Recovery.pto_duration(data.scheduler.recovery))
  end

  defp refresh_sent_idle(%{ready: true, idle_send_allowed: true} = data, :ok, true, at),
    do: refresh_idle(%{data | idle_send_allowed: false}, at)

  defp refresh_sent_idle(data, _result, _ack_eliciting, _at), do: data

  defp refresh_idle(data), do: refresh_idle(data, data.adapter.monotonic_time())

  defp refresh_idle(%{ready: false} = data, _at), do: data

  defp refresh_idle(data, at) do
    update_idle_deadline(%{data | idle_last_activity: at})
  end

  defp update_idle_deadline(%{effective_idle_timeout: :infinity} = data),
    do: %{data | idle_deadline: nil}

  defp update_idle_deadline(data),
    do: %{data | idle_deadline: data.idle_last_activity + idle_period(data)}

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
      {{:timeout, :idle}, :cancel},
      {{:timeout, :path}, :cancel},
      {{:timeout, :tls_authority}, :cancel}
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

    level = closing_level(scheduler.keys)

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
          {code, frame_type} =
            case reason do
              {:transport, code, frame_type} -> {code, frame_type}
              _ -> {0, 0}
            end

          %{type: :connection_close, error_code: code, frame_type: frame_type, reason: <<>>}
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

  defp closing_level(keys) do
    cond do
      Map.has_key?(keys, :application) -> :application
      Map.has_key?(keys, :handshake) -> :handshake
      Map.has_key?(keys, :initial) -> :initial
      true -> nil
    end
  end

  defp retry_packets(scheduler, packets, effects),
    do: retry_packets(scheduler, packets, effects, :retry)

  defp retry_packets(scheduler, [], effects, _mode), do: {:ok, scheduler, effects}

  defp retry_packets(scheduler, [{space, number} | rest], effects, mode) do
    if HandshakeScheduler.retired?(scheduler, space) do
      retry_packets(scheduler, rest, effects, mode)
    else
      result =
        case mode do
          :probe -> HandshakeScheduler.probe(scheduler, space, number)
          :retry -> HandshakeScheduler.retry_crypto(scheduler, space, number)
        end

      case result do
        {:ok, next, sends} -> retry_packets(next, rest, effects ++ sends, mode)
        {:error, :not_retransmittable} -> retry_packets(scheduler, rest, effects, mode)
        {:error, reason} -> {:error, reason}
        {:error, reason, _} -> {:error, reason}
      end
    end
  end

  defp local_send(data, bytes, remote, path_id) do
    writer =
      if data.scheduler.role == :client,
        do: Map.get(Map.get(data, :path_writers, %{}), path_id, data.writer),
        else: data.writer

    case data.adapter.send(writer, bytes, remote) do
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
      migration: %{
        active_path: data.paths.active,
        paths:
          Map.new(data.paths.paths, fn {id, path} ->
            {id, Map.take(path, [:local, :remote, :validated, :mtu_validated])}
          end)
      },
      reliable_reset: %{
        draft: 11,
        local: data.scheduler.local_reset_stream_at,
        peer: data.scheduler.peer_reset_stream_at,
        negotiated: data.scheduler.local_reset_stream_at and data.scheduler.peer_reset_stream_at
      },
      resumption: %{
        resumed: TLSDriver.info(data.scheduler.tls)[:resumed] == true,
        early_data: data.scheduler.early_status
      },
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
      idle_timeout: %{
        local_ms: data.idle_timeout,
        peer_ms:
          if(data.scheduler.peer_idle_timeout == 0,
            do: :infinity,
            else: data.scheduler.peer_idle_timeout
          ),
        negotiated_ms: data.effective_idle_timeout,
        effective_ms:
          if(idle_period(data) == :infinity,
            do: :infinity,
            else: div(idle_period(data) + 999, 1000)
          )
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
      path_records: map_size(data.paths.paths),
      local_cid_records:
        map_size(data.scheduler.local_cids.ids) +
          if(data.scheduler.local_cids.pending, do: 1, else: 0),
      io_queue_entries: :queue.len(data.budget.queue),
      io_queue_bytes: data.budget.queue_bytes,
      in_flight_sends: map_size(data.budget.in_flight),
      application_crypto_bytes: data.scheduler.tls.levels.application.recv.next,
      early_staged_bytes: data.scheduler.early_staged_bytes,
      early_staged_datagrams: length(data.scheduler.early_staged),
      early_datagram_bytes: data.scheduler.early_datagram_bytes,
      early_datagram_items: length(data.scheduler.early_datagrams),
      operation_result_bytes: data.operation_result_bytes,
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
    {data, events} =
      Enum.map_reduce(events, data, fn
        %{type: :stream, frame: %{stream_id: id}, events: :retained} = event, data ->
          {:ok, scheduler, items} = HandshakeScheduler.consume_stream(data.scheduler, id, 65_536)
          {%{event | events: items}, %{data | scheduler: scheduler}}

        event, data ->
          {event, data}
      end)
      |> then(fn {events, data} -> {data, events} end)

    Enum.each(events, fn
      %{type: :stream, frame: frame, events: items} ->
        send(data.owner, {:quic_stream, self(), frame.stream_id, items})

      %{type: type, frame: frame, events: items} when type in [:reset_stream, :reset_stream_at] ->
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

      %{type: type, frame: frame}, data when type in [:stream, :reset_stream, :reset_stream_at] ->
        id = frame.stream_id

        handle = %StreamHandle{
          connection: public_handle(data),
          id: id,
          epoch: data.scheduler.early_epoch
        }

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
          {:stopped,
           %StreamHandle{
             connection: public_handle(data),
             id: id,
             epoch: data.scheduler.early_epoch
           }, code}
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
    result_bytes = :erlang.external_size(result)

    previous_bytes =
      case data.operations[ref] do
        nil -> 0
        previous -> previous.result_bytes
      end

    entry = %{
      signature: signature,
      status: status,
      result: result,
      result_bytes: result_bytes,
      sequence: data.operation_sequence
    }

    operations = Map.put(data.operations, ref, entry)
    total_bytes = data.operation_result_bytes + result_bytes - previous_bytes

    {operations, total_bytes} =
      if map_size(operations) > data.operation_limit do
        pinned = if data.local_migration, do: data.local_migration.ref

        {oldest, removed} =
          operations
          |> Enum.reject(fn {key, entry} ->
            key == pinned or
              (Map.get(entry, :early, false) and Map.get(entry, :outcome) == :pending)
          end)
          |> Enum.min_by(fn {_, entry} -> entry.sequence end)

        {Map.delete(operations, oldest), total_bytes - removed.result_bytes}
      else
        {operations, total_bytes}
      end

    observe(%{
      data
      | operations: operations,
        operation_result_bytes: total_bytes,
        operation_sequence: data.operation_sequence + 1
    })
  end

  defp start_local_migration(data, from, ref, signature, {:migrate, local}, deadline) do
    reason =
      cond do
        data.role != :client -> :client_only
        not data.exclusive_io -> :endpoint_not_exclusive
        not data.scheduler.tls.facts.quic_confirmed -> :handshake_not_confirmed
        data.scheduler.peer_disable_active_migration -> :peer_disabled_migration
        data.local_migration != nil or map_size(data.paths.paths) >= 2 -> :migration_busy
        not valid_migration_local?(local) -> :invalid_local_address
        local == data.local -> :unchanged_local_address
        true -> nil
      end

    if reason do
      result = {:error, reason}

      {:keep_state, record_operation(data, ref, signature, :rejected, result),
       [{:reply, from, result}]}
    else
      id = data.paths.next_id

      with {:ok, scheduler} <-
             HandshakeScheduler.bind_path(data.scheduler, id, data.paths.active, false),
           {:ok, recovery} <- Recovery.add_path(scheduler.recovery, id),
           {:ok, budget} <- Endpoint.add_path(data.budget, id, true) do
        pto = max(Recovery.pto_duration(recovery), Recovery.pto_duration(recovery, id))

        {:ok, paths, ^id} =
          Paths.start_local(
            data.paths,
            local,
            data.adapter.monotonic_time(),
            pto,
            deadline * 1000
          )

        paths = put_in(paths.paths[id].retry_at, nil)
        migration = %{ref: ref, id: id, deadline: deadline, phase: :binding}

        next =
          record_operation(
            %{
              data
              | scheduler: %{scheduler | recovery: recovery},
                budget: budget,
                paths: paths,
                local_migration: migration
            },
            ref,
            signature,
            :admitted,
            {:ok, ref}
          )

        send(data.owner, {:quic_bind_path, self(), data.generation, ref, id, local, deadline})
        {:keep_state, next, [{:reply, from, {:ok, ref}} | path_timer(next)]}
      else
        {:error, reason} ->
          result = {:error, reason}

          {:keep_state, record_operation(data, ref, signature, :rejected, result),
           [{:reply, from, result}]}
      end
    end
  end

  defp valid_migration_local?({ip, port})
       when is_tuple(ip) and tuple_size(ip) in [4, 8] and
              is_integer(port) and port in 0..65_535 do
    max = if tuple_size(ip) == 4, do: 255, else: 65_535
    parts = Tuple.to_list(ip)
    Enum.all?(parts, &(is_integer(&1) and &1 in 0..max)) and Enum.any?(parts, &(&1 != 0))
  end

  defp valid_migration_local?(_), do: false

  defp migration_outcome(data, outcome) do
    ref = data.local_migration.ref
    entry = data.operations[ref]
    # Preserve the original admission result for same-ref retries.
    operations =
      if entry,
        do:
          Map.put(data.operations, ref, Map.merge(entry, %{status: :completed, outcome: outcome})),
        else: data.operations

    queue_event(
      %{
        data
        | operations: operations,
          local_migration: %{data.local_migration | phase: :settling}
      },
      {:migration, ref, outcome}
    )
  end

  defp fail_local_migration(data, reason) do
    id = data.local_migration.id
    paths = %{data.paths | retiring: id}
    paths = update_in(paths.paths[id], &%{&1 | deadline: nil, retry_at: nil, challenges: []})
    next = migration_outcome(%{data | paths: paths}, {:error, reason})
    advance(next, [], [])
  end

  defp execute_operation(data, from, ref, signature, {:open, kind}),
    do: execute_operation(data, from, ref, signature, {:open, kind, 0})

  defp execute_operation(data, from, ref, signature, {:open, kind, prefix}) do
    case HandshakeScheduler.open_stream(data.scheduler, kind, prefix) do
      {:ok, scheduler, id} ->
        result =
          {:ok,
           %StreamHandle{
             connection: public_handle(data),
             id: id,
             epoch: data.scheduler.early_epoch
           }}

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

  defp unwrap_stream_epoch({:stream_epoch, epoch, request}, current),
    do: {request, epoch == current}

  defp unwrap_stream_epoch(request, _), do: {request, true}
  defp early_request?({:open, kind}), do: kind in [:uni, :bidi]
  defp early_request?({:open, kind, _prefix}), do: kind in [:uni, :bidi]
  defp early_request?({:send, _, _, _}), do: true
  defp early_request?({:send_datagram, _}), do: true
  defp early_request?(_), do: false

  defp execute_early_operation(data, from, ref, signature, request) do
    case execute_operation(data, from, ref, signature, request) do
      {transition, data, actions} when transition in [:keep_state, :next_state] ->
        {transition, mark_early_operation(data, ref), actions}

      {:next_state, phase, data, actions} ->
        {:next_state, phase, mark_early_operation(data, ref), actions}

      other ->
        other
    end
  end

  defp mark_early_operation(data, ref) do
    case data.operations[ref] do
      %{status: :admitted} = entry ->
        %{
          data
          | operations:
              Map.put(data.operations, ref, Map.merge(entry, %{early: true, outcome: :pending}))
        }

      _ ->
        data
    end
  end

  defp settle_early_operations(data) do
    status = data.scheduler.early_status

    if status in [:accepted, :rejected] do
      Enum.reduce(data.operations, data, fn {ref, entry}, data ->
        if Map.get(entry, :early, false) and Map.get(entry, :outcome) == :pending do
          operations = Map.put(data.operations, ref, %{entry | outcome: {:early_data, status}})
          queue_event(%{data | operations: operations}, {:early_data, ref, status})
        else
          data
        end
      end)
    else
      data
    end
  end

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

  defp advance_received(data, events, effects, extra, from, arrival, at) do
    lost =
      Enum.flat_map(events, fn
        %{type: :ack, result: %{lost: lost}} -> lost
        _ -> []
      end)

    with {:ok, scheduler, retries} <- retry_packets(data.scheduler, lost, []),
         {:ok, scheduler, acks} <- HandshakeScheduler.schedule(scheduler) do
      {data, effects} =
        path_events(
          %{data | scheduler: scheduler},
          events,
          arrival,
          at,
          effects ++ extra ++ retries ++ acks
        )

      advance(data, effects, [{:reply, from, :ok}])
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

  defp scheduler_operation(scheduler, {:ping}), do: HandshakeScheduler.ping(scheduler)

  defp scheduler_operation(scheduler, {:send_datagram, bytes}) do
    HandshakeScheduler.send_datagram(scheduler, bytes)
  end

  defp scheduler_operation(scheduler, {:reset, id, code})
       when is_integer(id) and id >= 0 and is_integer(code) and code >= 0 and
              code < 4_611_686_018_427_387_904 do
    HandshakeScheduler.reset_stream(scheduler, id, code)
  end

  defp scheduler_operation(scheduler, {:reset_at, id, code, reliable})
       when is_integer(id) and id >= 0 and is_integer(code) and code >= 0 and
              code < 4_611_686_018_427_387_904 and is_integer(reliable) and reliable >= 0 do
    HandshakeScheduler.reset_stream_at(scheduler, id, code, reliable)
  end

  defp scheduler_operation(scheduler, {:stop, id, code})
       when is_integer(id) and id >= 0 and is_integer(code) and code >= 0 and
              code < 4_611_686_018_427_387_904 do
    HandshakeScheduler.stop_stream(scheduler, id, code)
  end

  defp scheduler_operation(_scheduler, _) do
    {:error, :invalid_operation}
  end

  defp valid_idle_timeout?(:infinity), do: true
  defp valid_idle_timeout?(value), do: valid_timeout?(value)

  defp valid_timeout?(value), do: is_integer(value) and value > 0
  defp valid_operation_identity?(ref, deadline), do: is_reference(ref) and is_integer(deadline)
end

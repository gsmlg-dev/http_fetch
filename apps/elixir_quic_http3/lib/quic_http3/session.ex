defmodule QuicHttp3.Session do
  @moduledoc """
  Caller-driven HTTP/3 session with resumable QUIC admission.

  Mutating failures return the advanced session. Call `resume/1` to reconcile an
  unknown operation, or retry a definitely blocked operation after credit changes.
  Unknown operations are never replayed, including after result-cache eviction.
  Native query calls and DNS retain their transport timeout bounds; the session
  deadline is an admission/reconciliation budget, not a shorter wall-clock bound.
  """

  alias QuicHttp3.{Control, Frame, Qpack, Stream}
  alias QuicHttp3.Transport.Quic.Stream, as: TransportStream

  defstruct transport: QuicHttp3.Transport.Quic,
            connection: nil,
            control: nil,
            control_stream: nil,
            peer_streams: %{},
            requests: %{},
            next_request: 1,
            max_frame: 16_384,
            timeout: 5_000,
            pending: nil,
            work: nil,
            runnable: [],
            retired: MapSet.new(),
            aborted_operation: nil,
            open?: false

  @type t :: %__MODULE__{}
  @type failure :: {:error, t(), term()} | {:blocked, t(), term()} | {:unknown, t(), reference()}

  def new(opts \\ [])

  def new(opts) when is_list(opts) do
    transport = Keyword.get(opts, :transport, QuicHttp3.Transport.Quic)
    max_frame = Keyword.get(opts, :max_frame, 16_384)
    timeout = Keyword.get(opts, :timeout, 5_000)

    if is_atom(transport) and is_integer(max_frame) and max_frame in 1..16_384 and
         is_integer(timeout) and timeout > 0 do
      {:ok, %__MODULE__{transport: transport, max_frame: max_frame, timeout: timeout}}
    else
      {:error, :invalid_session_options}
    end
  end

  def new(_), do: {:error, :invalid_session_options}

  def connect(session, remote, port, opts) do
    if session.connection == nil do
      begin(session, :connect, [{:connect, remote, port, opts}], opts)
    else
      {:error, session, :already_connected}
    end
  end

  def ready(%__MODULE__{connection: nil}), do: {:error, :not_connected}
  def ready(session), do: session.transport.ready(session.connection, session.timeout)

  def open(%__MODULE__{connection: nil} = session), do: {:error, session, :not_connected}
  def open(%__MODULE__{open?: true} = session), do: {:error, session, :already_open}

  def open(session) do
    if session.pending do
      {:error, session, :operation_pending}
    else
      case ready(session) do
        :ready ->
          {:ok, control} = Control.new(:client)
          begin(%{session | control: control}, :open, [:open_control], [])

        :pending ->
          {:blocked, session, :not_ready}

        {:error, reason} ->
          {:error, session, reason}
      end
    end
  end

  def request(%__MODULE__{open?: false} = session, _fields, _body, _opts),
    do: {:error, session, :not_open}

  def request(session, fields, body, opts) when is_list(fields) and is_binary(body) do
    with {:ok, headers} <- Qpack.encode_header_block(fields, opts),
         {:ok, header_frame} <- Frame.encode(:headers, headers) do
      ref = make_ref()
      begin(session, {:request, ref}, [{:open_request, ref, header_frame, body}], opts)
    else
      {:error, reason} -> {:error, session, reason}
    end
  end

  def poll(session, max, opts \\ [])

  def poll(session, max, opts) when is_integer(max) and max in 1..128 do
    begin(session, :poll, [{:events, max}, :drain], opts)
  end

  def poll(session, _, _), do: {:error, session, :invalid_event_limit}

  def cancel(session, ref) do
    if Map.has_key?(session.requests, ref) do
      begin(session, :cancel, [{:reset, ref}, {:stop, ref}, {:remove_request, ref}], [])
    else
      {:error, session, :unknown_request}
    end
  end

  def close(%__MODULE__{connection: nil} = session), do: {:error, session, :not_connected}
  def close(session), do: begin(session, :close, [:close, :cleanup], [])

  @doc """
  Terminate transport resources without replaying pending application work.

  This does not prove an indeterminate request was unsent. The returned session
  retains its abandoned operation identity in `aborted_operation`.
  """
  def abort(%__MODULE__{connection: nil} = session), do: {:ok, session}

  def abort(session) do
    abandoned =
      if session.pending,
        do: Map.take(session.pending, [:ref, :kind, :status]),
        else: session.aborted_operation

    begin(
      %{session | pending: nil, work: nil, aborted_operation: abandoned},
      :abort,
      [:abort],
      []
    )
  end

  def resume(%__MODULE__{pending: nil} = session), do: {:error, session, :no_pending_operation}

  def resume(%__MODULE__{pending: %{status: :indeterminate, ref: ref}} = session),
    do: {:error, session, {:indeterminate_operation, ref}}

  def resume(%__MODULE__{pending: pending} = session) do
    cond do
      now() >= pending.deadline ->
        reason =
          if pending.status == :unknown,
            do: {:indeterminate_operation, pending.ref},
            else: :deadline_expired

        {:error, %{session | pending: %{pending | status: :indeterminate}}, reason}

      pending.status == :blocked ->
        drive(%{session | pending: nil})

      true ->
        case session.transport.operation_status(session.connection, pending.ref, pending.kind) do
          %{status: status, result: result} when status in [:admitted, :completed, :rejected] ->
            complete(session, pending.action, result)

          :unknown ->
            {:unknown, session, pending.ref}

          {:error, reason} ->
            {:error, session, {:unresolved_operation, pending.ref, reason}}
        end
    end
  end

  defp begin(%{pending: pending} = session, _kind, _steps, _opts) when not is_nil(pending),
    do: {:error, session, :operation_pending}

  defp begin(session, kind, steps, opts) do
    timeout = Keyword.get(opts, :timeout, session.timeout)
    batches = Keyword.get(opts, :max_read_batches, 128)
    paused = Keyword.get(opts, :paused, MapSet.new())

    if is_integer(timeout) and timeout > 0 and is_integer(batches) and batches in 1..128 and
         is_struct(paused, MapSet) do
      work = %{
        kind: kind,
        steps: steps,
        deadline: now() + timeout,
        acc: [],
        reads: batches,
        paused: paused,
        bytes: 16_384
      }

      drive(%{session | work: work})
    else
      {:error, session, :invalid_operation_options}
    end
  end

  defp drive(%{work: %{steps: []}} = session), do: finish(session)

  defp drive(%{work: %{steps: [action | rest]}} = session) do
    case action do
      {:event, event} ->
        case consume_event(session, event) do
          {:ok, next} -> drive(put_in(next.work.steps, rest))
          {:error, reason} -> {:error, session, reason}
        end

      :drain ->
        drain(session, rest)

      {:remove_request, ref} ->
        stream = session.requests[ref].stream

        if MapSet.size(session.retired) < 1024 do
          drive(%{
            session
            | requests: Map.delete(session.requests, ref),
              runnable: List.delete(session.runnable, stream),
              retired: MapSet.put(session.retired, stream),
              work: %{session.work | steps: rest}
          })
        else
          {:error, session, :terminal_stream_limit}
        end

      :cleanup ->
        case session.transport.cleanup(session.connection) do
          :ok -> drive(put_in(session.work.steps, rest))
          {:error, reason} -> {:error, session, reason}
        end

      _ ->
        invoke(session, action)
    end
  end

  defp drain(%{work: %{reads: 0}} = session, _rest), do: finish(session)
  defp drain(%{work: %{bytes: 0}} = session, _rest), do: finish(session)

  defp drain(session, rest) do
    case Enum.find(session.runnable, &read_allowed?(session, &1)) do
      nil -> drive(put_in(session.work.steps, rest))
      stream -> drive(put_in(session.work.steps, [{:read, stream}, :drain | rest]))
    end
  end

  defp read_allowed?(session, stream) do
    case request_for_stream(session.requests, stream) do
      {ref, _} -> not MapSet.member?(session.work.paused, ref)
      nil -> true
    end
  end

  defp invoke(session, action) do
    remaining = session.work.deadline - now()

    if remaining <= 0 do
      {:error, session, :deadline_expired}
    else
      ref = make_ref()

      pending = %{
        action: action,
        kind: operation_kind(action),
        ref: ref,
        deadline: session.work.deadline,
        status: :unknown
      }

      opts = [ref: ref, timeout: remaining, deadline: remaining]
      result = operation(session, action, opts)
      complete(%{session | pending: pending}, action, result)
    end
  end

  defp operation(session, {:connect, remote, port, opts}, operation_opts),
    do: session.transport.connect(remote, port, Keyword.merge(opts, operation_opts))

  defp operation(session, :open_control, opts),
    do: session.transport.open_stream(session.connection, :uni, opts)

  defp operation(session, {:open_request, _, _, _}, opts),
    do: session.transport.open_stream(session.connection, :bidi, opts)

  defp operation(session, {:send, stream, bytes, fin}, opts),
    do: session.transport.send_stream(stream, bytes, fin, opts)

  defp operation(session, {:events, max}, opts),
    do: session.transport.events(session.connection, max, opts)

  defp operation(session, {:read, stream}, opts),
    do: session.transport.read(stream, min(session.max_frame, session.work.bytes), opts)

  defp operation(session, {:reset, ref}, opts),
    do: session.transport.reset_stream(session.requests[ref].stream, 0x10C, opts)

  defp operation(session, {:stop, ref}, opts),
    do: session.transport.stop_stream(session.requests[ref].stream, 0x10C, opts)

  defp operation(session, :abort, opts), do: session.transport.abort(session.connection, opts)

  defp operation(session, :close, opts),
    do: session.transport.close(session.connection, 0x100, <<>>, opts)

  defp operation_kind({:connect, _, _, _}), do: :connect
  defp operation_kind(:open_control), do: :open_stream
  defp operation_kind({:open_request, _, _, _}), do: :open_stream
  defp operation_kind({:send, _, _, _}), do: :send_stream
  defp operation_kind({:events, _}), do: :events
  defp operation_kind({:read, _}), do: :read
  defp operation_kind({:reset, _}), do: :reset_stream
  defp operation_kind({:stop, _}), do: :stop_stream
  defp operation_kind(:close), do: :close
  defp operation_kind(:abort), do: :close

  defp complete(session, _action, {:unknown, connection, ref}),
    do:
      {:unknown, %{session | connection: connection, pending: %{session.pending | ref: ref}}, ref}

  defp complete(session, _action, {:unknown, ref}),
    do: {:unknown, %{session | pending: %{session.pending | ref: ref}}, ref}

  defp complete(session, _action, {:blocked, reason}),
    do: {:blocked, %{session | pending: %{session.pending | status: :blocked}}, reason}

  defp complete(session, :close, {:error, :closed}), do: complete(session, :close, :ok)

  defp complete(session, _action, {:error, {:attach_failed, connection, error}}),
    do: {:error, %{session | connection: connection, pending: nil}, {:attach_failed, error}}

  defp complete(session, _action, {:error, reason}),
    do: {:error, %{session | pending: nil}, reason}

  defp complete(session, action, success) when success == :ok or elem(success, 0) == :ok do
    [_ | rest] = session.work.steps
    session = %{session | pending: nil, work: %{session.work | steps: rest}}

    case accepted(session, action, success) do
      {:ok, next} -> drive(next)
      {:error, reason} -> {:error, session, reason}
    end
  end

  defp accepted(session, {:connect, _, _, _}, {:ok, connection}),
    do: {:ok, %{session | connection: connection}}

  defp accepted(session, :open_control, {:ok, stream}) do
    steps = chunks(stream, Control.local_payload(session.control), false, session.max_frame)

    {:ok,
     %{
       session
       | control_stream: stream,
         work: %{session.work | steps: steps ++ session.work.steps}
     }}
  end

  defp accepted(session, {:open_request, ref, headers, body}, {:ok, stream}) do
    request = %{stream: stream, ref: ref, buffer: <<>>, headers_received?: false}

    steps =
      chunks(stream, headers, body == <<>>, session.max_frame) ++
        chunks(stream, body, true, session.max_frame)

    {:ok,
     %{
       session
       | requests: Map.put(session.requests, ref, request),
         next_request: session.next_request + 1,
         work: %{session.work | steps: steps ++ session.work.steps}
     }}
  end

  defp accepted(_session, {:events, _}, {:ok, events}) when not is_list(events),
    do: {:error, :invalid_event_batch}

  defp accepted(_session, {:events, _}, {:ok, events}) when length(events) > 128,
    do: {:error, :invalid_event_batch}

  defp accepted(session, {:events, _}, {:ok, events}) do
    {:ok, put_in(session.work.steps, Enum.map(events, &{:event, &1}) ++ session.work.steps)}
  end

  defp accepted(session, {:read, stream}, {:ok, items}) do
    with :ok <- valid_read_batch(stream, items),
         {:ok, next, events} <- consume_items(session, stream, items) do
      terminal? = Enum.any?(items, &(elem(&1, 0) in [:fin, :reset]))
      runnable = List.delete(next.runnable, stream)
      runnable = if items != [] and not terminal?, do: runnable ++ [stream], else: runnable

      {:ok,
       record_events(
         %{
           next
           | runnable: runnable,
             work: %{
               next.work
               | reads: next.work.reads - 1,
                 bytes: max(0, next.work.bytes - read_bytes(items))
             }
         },
         events
       )}
    end
  end

  defp accepted(session, _action, _success), do: {:ok, session}

  defp chunks(_stream, <<>>, _fin, _max), do: []

  defp chunks(stream, bytes, fin, max) do
    size = min(byte_size(bytes), max)
    <<chunk::binary-size(^size), rest::binary>> = bytes
    [{:send, stream, chunk, fin and rest == <<>>} | chunks(stream, rest, fin, max)]
  end

  defp finish(%{work: %{kind: kind, acc: acc}} = session) do
    next = %{session | work: nil, pending: nil}

    case kind do
      :poll ->
        {:ok, next, Enum.reverse(acc)}

      {:request, ref} ->
        {:ok, next, ref}

      :open ->
        {:ok, %{next | open?: true}}

      :close ->
        :ok

      :abort ->
        {:ok,
         %{
           next
           | connection: nil,
             control: nil,
             control_stream: nil,
             requests: %{},
             peer_streams: %{},
             runnable: [],
             retired: MapSet.new(),
             open?: false
         }}

      _ ->
        {:ok, next}
    end
  end

  defp record_events(session, events),
    do: put_in(session.work.acc, Enum.reverse(events) ++ session.work.acc)

  defp consume_event(session, {:stream_open, stream, :uni}),
    do:
      {:ok,
       %{
         session
         | peer_streams: Map.put_new(session.peer_streams, stream, %{type: nil, buffer: <<>>})
       }}

  defp consume_event(session, {:stream_open, stream, :bidi}) do
    if request_for_stream(session.requests, stream) || MapSet.member?(session.retired, stream),
      do: {:ok, session},
      else: {:error, :peer_bidirectional_stream}
  end

  defp consume_event(session, {:readable, stream}) do
    cond do
      MapSet.member?(session.retired, stream) ->
        {:ok, session}

      request_for_stream(session.requests, stream) || Map.has_key?(session.peer_streams, stream) ->
        {:ok, %{session | runnable: Enum.uniq(session.runnable ++ [stream])}}

      true ->
        {:error, :unknown_stream_event}
    end
  end

  defp consume_event(session, {:stopped, stream, code}) do
    case request_for_stream(session.requests, stream) do
      {ref, _request} ->
        {:ok, record_events(session, [{:stopped, ref, code}])}

      nil ->
        if MapSet.member?(session.retired, stream),
          do: {:ok, session},
          else: {:error, :unknown_stream_event}
    end
  end

  defp consume_event(_session, {:closed, reason}), do: {:error, {:connection_closed, reason}}
  defp consume_event(_session, {:error, reason}), do: {:error, reason}

  defp consume_event(session, event) when event in [:ready, :writable, :datagram_readable],
    do: {:ok, record_events(session, [event])}

  defp consume_event(session, {:ready, _} = event), do: {:ok, record_events(session, [event])}
  defp consume_event(_session, _event), do: {:error, :invalid_transport_event}

  defp consume_items(session, stream, items) do
    case request_for_stream(session.requests, stream) do
      {ref, request} ->
        case parse_items(request, items, []) do
          {:ok, request, events} ->
            {:ok, %{session | requests: Map.put(session.requests, ref, request)},
             Enum.reverse(events)}

          error ->
            error
        end

      nil ->
        consume_peer_items(session, stream, items)
    end
  end

  defp valid_read_batch(_stream, items) when not is_list(items), do: {:error, :invalid_read_batch}

  defp valid_read_batch(_stream, items) when length(items) > 16_384,
    do: {:error, :invalid_read_batch}

  defp valid_read_batch(stream, items) do
    if read_bytes(items) > 16_384,
      do: {:error, :invalid_read_batch},
      else: valid_read_identity(stream, items)
  end

  defp valid_read_identity(%TransportStream{handle: %{id: id}}, items) do
    if Enum.all?(items, &valid_read_item?(&1, id)),
      do: :ok,
      else: {:error, :invalid_stream_identity}
  end

  defp valid_read_identity(_stream, _items), do: :ok

  defp valid_read_item?({:data, id, bytes}, id) when is_binary(bytes), do: true
  defp valid_read_item?({:fin, id}, id), do: true

  defp valid_read_item?({:reset, id, code, final_size}, id)
       when is_integer(code) and is_integer(final_size),
       do: true

  defp valid_read_item?(_item, _id), do: false

  defp read_bytes(items) do
    Enum.reduce(items, 0, fn
      {:data, _id, bytes}, acc when is_binary(bytes) -> acc + byte_size(bytes)
      {:data, bytes}, acc when is_binary(bytes) -> acc + byte_size(bytes)
      _, acc -> acc
    end)
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp consume_peer_items(session, _stream, []), do: {:ok, session, []}

  defp consume_peer_items(session, stream, [{:data, bytes} | rest]) when is_binary(bytes),
    do: consume_peer_bytes(session, stream, bytes, rest)

  defp consume_peer_items(session, stream, [{:data, _id, bytes} | rest]) when is_binary(bytes),
    do: consume_peer_bytes(session, stream, bytes, rest)

  defp consume_peer_items(_session, _stream, [{:reset, _id, _code, _final_size} | _rest]),
    do: {:error, :peer_control_stream_reset}

  defp consume_peer_items(_session, _stream, [{:fin} | _rest]),
    do: {:error, :peer_control_stream_closed}

  defp consume_peer_items(_session, _stream, [{:fin, _id} | _rest]),
    do: {:error, :peer_control_stream_closed}

  defp consume_peer_items(_session, _stream, _items), do: {:error, :invalid_stream_event}

  defp consume_peer_bytes(session, stream, bytes, rest) do
    state = Map.fetch!(session.peer_streams, stream)
    data = state.buffer <> bytes

    case state.type do
      :control ->
        with {:ok, control, events} <- Control.receive_peer(session.control, stream, bytes),
             {:ok, next, more} <- consume_peer_items(%{session | control: control}, stream, rest) do
          {:ok, next, events ++ more}
        end

      nil ->
        case Stream.decode_type(data) do
          {:ok, :control, _rest} ->
            next = put_in(session.peer_streams[stream], %{type: :control, buffer: <<>>})

            with {:ok, control, events} <- Control.receive_peer(next.control, stream, data),
                 {:ok, next, more} <- consume_peer_items(%{next | control: control}, stream, rest) do
              {:ok, next, events ++ more}
            end

          {:ok, type, _rest} when type in [:qpack_encoder, :qpack_decoder] ->
            next = put_in(session.peer_streams[stream], %{type: type, buffer: <<>>})
            consume_peer_items(next, stream, rest)

          {:ok, {:unknown, type}, _rest} ->
            {:error, {:unsupported_peer_stream, type}}

          :more ->
            next = put_in(session.peer_streams[stream], %{type: nil, buffer: data})
            consume_peer_items(next, stream, rest)
        end

      type when type in [:qpack_encoder, :qpack_decoder] ->
        consume_peer_items(session, stream, rest)
    end
  end

  defp request_for_stream(requests, stream) do
    Enum.find_value(requests, fn
      {ref, %{stream: ^stream} = request} -> {ref, request}
      _ -> nil
    end)
  end

  defp parse_items(request, [], events), do: parse_buffer(request, events)

  defp parse_items(request, [{:data, bytes} | rest], events) when is_binary(bytes) do
    case parse_buffer(%{request | buffer: request.buffer <> bytes}, events) do
      {:ok, next, emitted} -> parse_items(next, rest, emitted)
      error -> error
    end
  end

  defp parse_items(request, [{:data, _stream_id, bytes} | rest], events) when is_binary(bytes),
    do: parse_items(request, [{:data, bytes} | rest], events)

  defp parse_items(request, [{:fin} | rest], events) do
    case parse_buffer(request, events) do
      {:ok, %{buffer: <<>>} = next, emitted} ->
        parse_items(next, rest, [{:done, request.ref} | emitted])

      {:ok, _next, _emitted} ->
        {:error, :truncated_http3_frame}

      error ->
        error
    end
  end

  defp parse_items(request, [{:fin, _stream_id} | rest], events),
    do: parse_items(request, [{:fin} | rest], events)

  defp parse_items(request, [{:reset, _id, code, final_size} | _rest], events),
    do: {:ok, request, [{:stream_reset, request.ref, code, final_size} | events]}

  defp parse_items(_request, _items, _events), do: {:error, :invalid_stream_event}

  defp parse_buffer({:ok, request, events}, extra), do: parse_buffer(request, extra ++ events)

  defp parse_buffer(%{buffer: buffer} = request, events) do
    case Frame.decode(buffer) do
      :more ->
        {:ok, request, events}

      {:ok, %{type: 0, payload: _payload}, _rest} when not request.headers_received? ->
        {:error, :data_before_headers}

      {:ok, %{type: 0, payload: payload}, rest} ->
        parse_buffer(%{request | buffer: rest}, [{:data, request.ref, payload} | events])

      {:ok, %{type: 1, payload: payload}, rest} ->
        case Qpack.decode_header_block(payload) do
          {:ok, fields} ->
            parse_buffer(
              %{request | buffer: rest, headers_received?: true},
              [{:headers, request.ref, fields} | events]
            )

          error ->
            error
        end

      {:ok, _frame, _rest} ->
        {:error, :forbidden_response_frame}
    end
  end
end

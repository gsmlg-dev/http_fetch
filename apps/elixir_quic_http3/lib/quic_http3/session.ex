defmodule QuicHttp3.Session do
  @moduledoc """
  Caller-driven HTTP/3 session with resumable QUIC admission.

  Mutating failures return the advanced session. Call `resume/1` to reconcile an
  unknown operation, or retry a definitely blocked operation after credit changes.
  Unknown operations are never replayed, including after result-cache eviction.
  Native query calls and DNS retain their transport timeout bounds; the session
  deadline is an admission/reconciliation budget, not a shorter wall-clock bound.
  """

  alias QuicHttp3.{Control, Frame, Qpack, Response, Stream}
  alias QuicHttp3.Transport.Quic.Stream, as: TransportStream

  defstruct transport: QuicHttp3.Transport.Quic,
            connection: nil,
            control: nil,
            control_stream: nil,
            peer_streams: %{},
            requests: %{},
            next_request: 1,
            next_stream_id: 0,
            max_fields: 128,
            max_encoded_headers: 65_536,
            max_header_bytes: 65_536,
            max_retained_bytes: 262_144,
            qpack_streams: %{},
            continuations: %{},
            max_frame: 16_384,
            timeout: 5_000,
            pending: nil,
            work: nil,
            runnable: [],
            retired: MapSet.new(),
            aborted_operation: nil,
            open?: false

  defmodule Continuation do
    @moduledoc false
    @enforce_keys [:id, :connection, :work, :pending, :request_ref]
    defstruct [:id, :connection, :work, :pending, :request_ref]
  end

  @type t :: %__MODULE__{}
  @type failure :: {:error, t(), term()} | {:blocked, t(), term()} | {:unknown, t(), reference()}

  def new(opts \\ [])

  def new(opts) when is_list(opts) do
    transport = Keyword.get(opts, :transport, QuicHttp3.Transport.Quic)
    max_frame = Keyword.get(opts, :max_frame, 16_384)
    timeout = Keyword.get(opts, :timeout, 5_000)

    if is_atom(transport) and is_integer(max_frame) and max_frame in 1..16_384 and
         is_integer(timeout) and timeout > 0 do
      limits =
        Keyword.take(opts, [
          :max_fields,
          :max_encoded_headers,
          :max_header_bytes,
          :max_retained_bytes
        ])

      session =
        struct!(
          __MODULE__,
          [transport: transport, max_frame: max_frame, timeout: timeout] ++ limits
        )

      if valid_limits?(session), do: {:ok, session}, else: {:error, :invalid_session_options}
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
          {:ok, control} = Control.new(:client, [{1, 0}, {6, session.max_header_bytes}, {7, 0}])
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

  def request(session, fields, body, opts)
      when is_list(fields) and (is_binary(body) or body == :stream) do
    with :ok <- request_admission(session),
         :ok <- outgoing_fields(session, fields),
         {:ok, headers} <- Qpack.encode_header_block(fields, opts),
         :ok <- encoded_headers(session, headers),
         {:ok, header_frame} <- Frame.encode(:headers, headers) do
      ref = make_ref()

      method =
        Enum.find_value(fields, "GET", fn {name, value} -> if name == ":method", do: value end)

      begin(session, {:request, ref}, [{:open_request, ref, header_frame, body, method}], opts)
    else
      {:error, reason} -> {:error, session, reason}
    end
  end

  def send_data(session, ref, bytes, fin, opts)
      when is_binary(bytes) and byte_size(bytes) <= 16_384 and is_boolean(fin) do
    case Map.fetch(session.requests, ref) do
      {:ok, %{upload: :open, stream: stream}} ->
        begin(session, :send_data, data_steps(stream, bytes, fin, session.max_frame), opts)

      {:ok, _request} ->
        {:error, session, :upload_closed}

      :error ->
        {:error, session, :unknown_request}
    end
  end

  def send_data(session, _ref, _bytes, _fin, _opts), do: {:error, session, :invalid_upload_chunk}

  def suspend_blocked(%{pending: %{status: :blocked}} = session) do
    if map_size(session.continuations) < 128 do
      id = make_ref()
      ref = work_request_ref(session)

      token = %Continuation{
        id: id,
        connection: session.connection,
        work: session.work,
        pending: session.pending,
        request_ref: ref
      }

      {:ok,
       %{
         session
         | work: nil,
           pending: nil,
           continuations: Map.put(session.continuations, id, ref)
       }, token}
    else
      {:error, session, :continuation_limit}
    end
  end

  def suspend_blocked(session), do: {:error, session, :operation_not_definitely_blocked}

  def resume(%{pending: pending} = session, _continuation) when not is_nil(pending),
    do: {:error, session, :operation_pending}

  def resume(session, %Continuation{} = continuation) do
    if Map.has_key?(session.continuations, continuation.id) and
         continuation.connection == session.connection and continuation.pending.status == :blocked do
      next = %{session | continuations: Map.delete(session.continuations, continuation.id)}

      if continuation_live?(next, continuation) do
        resume(%{next | work: continuation.work, pending: continuation.pending})
      else
        {:error, next, :stale_continuation}
      end
    else
      {:error, session, :stale_continuation}
    end
  end

  def reset_send(session, ref) do
    case Map.fetch(session.requests, ref) do
      :error ->
        {:error, session, :unknown_request}

      {:ok, %{upload: upload}} when upload != :open ->
        {:ok, session}

      {:ok, _request} ->
        cond do
          session.pending == nil ->
            reset_send_work(session, ref)

          session.pending.status == :blocked and work_request_ref(session) == ref ->
            reset_send_work(%{session | pending: nil, work: nil}, ref)

          true ->
            {:error, session, :operation_pending}
        end
    end
  end

  defp reset_send_work(session, ref) do
    begin(
      drop_continuations(session, ref),
      :reset_send,
      [{:reset, ref}, {:upload_reset, ref}],
      []
    )
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
        case retire_request(session, ref) do
          {:ok, next} -> drive(put_in(next.work.steps, rest))
          {:error, reason} -> {:error, session, reason}
        end

      {:upload_reset, ref} ->
        drive(
          session
          |> put_in([Access.key(:requests), ref, :upload], :reset)
          |> put_in([Access.key(:work), :steps], rest)
        )

      {:body, _ref, <<>>} ->
        drive(put_in(session.work.steps, rest))

      {:body, ref, bytes} ->
        size = min(byte_size(bytes), 16_384)
        <<chunk::binary-size(^size), remaining::binary>> = bytes
        stream = session.requests[ref].stream

        steps =
          data_steps(stream, chunk, remaining == <<>>, session.max_frame) ++
            [{:body, ref, remaining} | rest]

        drive(put_in(session.work.steps, steps))

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

      result =
        if operation_kind(action) == :open_stream and match?({:open_request, _, _, _, _}, action) do
          case request_admission(session) do
            :ok -> operation(session, action, opts)
            error -> error
          end
        else
          operation(session, action, opts)
        end

      complete(%{session | pending: pending}, action, result)
    end
  end

  defp operation(session, {:connect, remote, port, opts}, operation_opts),
    do: session.transport.connect(remote, port, Keyword.merge(opts, operation_opts))

  defp operation(session, :open_control, opts),
    do: session.transport.open_stream(session.connection, :uni, opts)

  defp operation(session, {:open_request, _, _, _, _}, opts),
    do: session.transport.open_stream(session.connection, :bidi, opts)

  defp operation(session, {:send, stream, bytes, fin}, opts),
    do: session.transport.send_stream(stream, bytes, fin, opts)

  defp operation(session, {:events, max}, opts),
    do: session.transport.events(session.connection, max, opts)

  defp operation(session, {:read, stream}, opts),
    do: session.transport.read(stream, min(session.max_frame, session.work.bytes), opts)

  defp operation(session, {:reset_code, stream, code}, opts),
    do: session.transport.reset_stream(stream, code, opts)

  defp operation(session, {:stop_code, stream, code}, opts),
    do: session.transport.stop_stream(stream, code, opts)

  defp operation(session, {:reset, ref}, opts),
    do: session.transport.reset_stream(session.requests[ref].stream, 0x10C, opts)

  defp operation(session, {:stop, ref}, opts),
    do: session.transport.stop_stream(session.requests[ref].stream, 0x10C, opts)

  defp operation(session, :abort, opts), do: session.transport.abort(session.connection, opts)

  defp operation(session, :close, opts),
    do: session.transport.close(session.connection, 0x100, <<>>, opts)

  defp operation_kind({:connect, _, _, _}), do: :connect
  defp operation_kind(:open_control), do: :open_stream
  defp operation_kind({:open_request, _, _, _, _}), do: :open_stream
  defp operation_kind({:send, _, _, _}), do: :send_stream
  defp operation_kind({:events, _}), do: :events
  defp operation_kind({:read, _}), do: :read
  defp operation_kind({:reset, _}), do: :reset_stream
  defp operation_kind({:reset_code, _, _}), do: :reset_stream
  defp operation_kind({:stop_code, _, _}), do: :stop_stream
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
      {:error, next, reason} -> {:error, next, reason}
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

  defp accepted(session, {:open_request, ref, headers, body, method}, {:ok, stream}) do
    decoder =
      Response.new(
        method: method,
        max_fields: session.max_fields,
        max_encoded_headers: session.max_encoded_headers,
        max_header_bytes: session.max_header_bytes
      )

    request = %{stream: stream, ref: ref, decoder: decoder, upload: :open}
    id = stream_id(stream, session.next_stream_id)

    next = %{
      session
      | requests: Map.put(session.requests, ref, request),
        next_request: session.next_request + 1,
        next_stream_id: id + 4
    }

    if session.control.goaway_id != nil and id >= session.control.goaway_id do
      steps = [{:reset_code, stream, 0x10B}, {:stop_code, stream, 0x10B}, {:remove_request, ref}]
      {:ok, %{next | work: %{next.work | kind: {:rejected, ref, :goaway}, steps: steps}}}
    else
      tail = if body in [:stream, <<>>], do: [], else: [{:body, ref, body}]
      steps = chunks(stream, headers, body == <<>>, session.max_frame) ++ tail
      {:ok, put_in(next.work.steps, steps ++ next.work.steps)}
    end
  end

  defp accepted(session, {:send, stream, _bytes, true}, _success) do
    case request_for_stream(session.requests, stream) do
      {ref, _request} -> {:ok, put_in(session.requests[ref].upload, :closed)}
      nil -> {:ok, session}
    end
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
      terminal? =
        Enum.any?(items, &(elem(&1, 0) in [:fin, :reset])) or MapSet.member?(next.retired, stream)

      runnable = List.delete(next.runnable, stream)
      runnable = if items != [] and not terminal?, do: runnable ++ [stream], else: runnable

      result =
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
        )

      case retained_budget(result) do
        :ok -> {:ok, result}
        {:error, reason} -> {:error, result, reason}
      end
    end
  end

  defp accepted(session, _action, _success), do: {:ok, session}

  defp data_steps(stream, <<>>, true, _max), do: [{:send, stream, <<>>, true}]
  defp data_steps(_stream, <<>>, false, _max), do: []

  defp data_steps(stream, bytes, fin, max),
    do: chunks(stream, Frame.encode!(:data, bytes), fin, max)

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

      {:rejected, ref, reason} ->
        {:error, next, {:request_rejected, ref, reason}}

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
             continuations: %{},
             qpack_streams: %{},
             open?: false
         }}

      _ ->
        {:ok, next}
    end
  end

  defp record_events(session, events),
    do: put_in(session.work.acc, Enum.reverse(events) ++ session.work.acc)

  defp consume_event(session, {:stream_open, stream, :uni}) do
    cond do
      MapSet.member?(session.retired, stream) ->
        {:ok, session}

      map_size(session.peer_streams) >= 128 ->
        protocol_error(0x107, :peer_stream_limit)

      true ->
        {:ok,
         %{
           session
           | peer_streams: Map.put_new(session.peer_streams, stream, %{type: nil, buffer: <<>>})
         }}
    end
  end

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
        case response_items(request, items, []) do
          {:ok, request, events, terminal?} ->
            next = put_in(session.requests[ref], request)

            if terminal?,
              do: finish_response(next, ref, request, events),
              else: {:ok, next, events}

          {:error, {:http3_error, :stream, code, reason}} ->
            steps = [{:reset_code, stream, code}, {:stop_code, stream, code}]

            with {:ok, next} <- retire_request(session, ref) do
              {:ok, put_in(next.work.steps, steps ++ next.work.steps),
               [{:stream_error, ref, code, reason}]}
            end

          error ->
            error
        end

      nil ->
        consume_peer_items(session, stream, items)
    end
  end

  defp finish_response(session, ref, request, events) do
    with {:ok, next} <- retire_request(session, ref) do
      steps = if request.upload == :open, do: [{:reset_code, request.stream, 0x10C}], else: []
      {:ok, put_in(next.work.steps, steps ++ next.work.steps), events}
    end
  end

  defp response_items(request, [], events), do: {:ok, request, Enum.reverse(events), false}

  defp response_items(request, [{:data, _id, bytes} | rest], events),
    do: response_items(request, [{:data, bytes} | rest], events)

  defp response_items(request, [{:data, bytes} | rest], events) when is_binary(bytes) do
    with {:ok, decoder, emitted} <- Response.feed(request.decoder, bytes) do
      mapped = Enum.map(emitted, &response_event(request.ref, &1))
      response_items(%{request | decoder: decoder}, rest, Enum.reverse(mapped, events))
    end
  end

  defp response_items(request, [{:fin, _id} | rest], events),
    do: response_items(request, [{:fin} | rest], events)

  defp response_items(request, [{:fin}], events) do
    with {:ok, decoder, emitted} <- Response.finish(request.decoder) do
      mapped = Enum.map(emitted, &response_event(request.ref, &1))
      {:ok, %{request | decoder: decoder}, Enum.reverse(Enum.reverse(mapped, events)), true}
    end
  end

  defp response_items(request, [{:reset, _id, code, final_size}], events),
    do:
      {:ok, request, Enum.reverse([{:stream_reset, request.ref, code, final_size} | events]),
       true}

  defp response_items(_request, _items, _events), do: protocol_error(0x101, :invalid_stream_event)

  defp response_event(ref, {:headers, status, fields}),
    do: {:headers, ref, [{":status", Integer.to_string(status)} | fields]}

  defp response_event(ref, {:informational, status, fields}),
    do: {:informational, ref, status, fields}

  defp response_event(ref, {:data, bytes}), do: {:data, ref, bytes}
  defp response_event(ref, {:trailers, fields}), do: {:trailers, ref, fields}
  defp response_event(ref, :done), do: {:done, ref}

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

  defp valid_limits?(session) do
    session.max_fields in 1..128 and session.max_encoded_headers in 1..65_536 and
      session.max_header_bytes in 1..65_536 and session.max_retained_bytes in 1..1_048_576
  end

  defp request_admission(%{pending: pending}) when not is_nil(pending),
    do: {:error, :operation_pending}

  defp request_admission(%{control: %{goaway_id: id}, next_stream_id: next})
       when is_integer(id) and next >= id,
       do: {:error, :goaway}

  defp request_admission(session) do
    if MapSet.size(session.retired) >= 1024, do: {:error, :terminal_stream_limit}, else: :ok
  end

  defp outgoing_fields(session, fields) do
    cond do
      length(fields) > session.max_fields ->
        {:error, :request_field_limit}

      not Enum.all?(fields, fn
        {name, value} when is_binary(name) and is_binary(value) -> true
        _ -> false
      end) ->
        {:error, :invalid_fields}

      true ->
        size =
          Enum.reduce(fields, 0, fn {name, value}, acc ->
            acc + byte_size(name) + byte_size(value) + 32
          end)

        peer =
          if session.control.peer_settings,
            do: List.keyfind(session.control.peer_settings, 6, 0),
            else: nil

        cond do
          size > session.max_header_bytes -> {:error, :request_header_bytes_limit}
          peer != nil and size > elem(peer, 1) -> {:error, :peer_field_section_limit}
          true -> :ok
        end
    end
  end

  defp encoded_headers(session, bytes) do
    if byte_size(bytes) > session.max_encoded_headers,
      do: {:error, :request_encoded_headers_limit},
      else: :ok
  end

  defp stream_id(%TransportStream{handle: %{id: id}}, _fallback), do: id
  defp stream_id(_stream, fallback), do: fallback

  defp retire_request(session, ref) do
    request = session.requests[ref]

    with {:ok, next} <- retire_stream(session, request.stream) do
      {:ok, %{drop_continuations(next, ref) | requests: Map.delete(next.requests, ref)}}
    end
  end

  defp retire_stream(session, stream) do
    if MapSet.size(session.retired) < 1024 or MapSet.member?(session.retired, stream) do
      {:ok,
       %{
         session
         | retired: MapSet.put(session.retired, stream),
           runnable: List.delete(session.runnable, stream),
           peer_streams: Map.delete(session.peer_streams, stream)
       }}
    else
      {:error, :terminal_stream_limit}
    end
  end

  defp drop_continuations(session, ref) do
    %{
      session
      | continuations:
          Map.reject(session.continuations, fn {_id, request_ref} -> request_ref == ref end)
    }
  end

  defp work_request_ref(%{work: %{kind: {:request, ref}}}), do: ref

  defp work_request_ref(%{pending: %{action: {:send, stream, _, _}}} = session) do
    case request_for_stream(session.requests, stream) do
      {ref, _} -> ref
      nil -> nil
    end
  end

  defp work_request_ref(_), do: nil
  defp continuation_live?(_session, %{request_ref: nil}), do: true
  defp continuation_live?(_session, %{pending: %{action: {:open_request, _, _, _, _}}}), do: true

  defp continuation_live?(session, %{request_ref: ref}),
    do: match?(%{upload: :open}, session.requests[ref])

  defp retained_budget(session) do
    requests =
      Enum.reduce(session.requests, 0, fn {_, request}, acc ->
        acc + Response.retained_bytes(request.decoder)
      end)

    peers =
      Enum.reduce(session.peer_streams, 0, fn {_, peer}, acc -> acc + byte_size(peer.buffer) end)

    control =
      if session.control,
        do: byte_size(session.control.buffer) + byte_size(session.control.peer_type_buffer),
        else: 0

    if requests + peers + control <= session.max_retained_bytes,
      do: :ok,
      else: protocol_error(0x107, :session_retained_bytes_limit)
  end

  defp consume_peer_items(session, _stream, []), do: {:ok, session, []}

  defp consume_peer_items(session, stream, [{:data, _id, bytes} | rest]),
    do: consume_peer_items(session, stream, [{:data, bytes} | rest])

  defp consume_peer_items(session, stream, [{:data, bytes} | rest]) when is_binary(bytes) do
    with {:ok, next, events} <- consume_peer_bytes(session, stream, bytes),
         {:ok, next, more} <- consume_peer_items(next, stream, rest) do
      {:ok, next, events ++ more}
    end
  end

  defp consume_peer_items(session, stream, [{:fin, _id} | rest]),
    do: consume_peer_items(session, stream, [{:fin} | rest])

  defp consume_peer_items(session, stream, [terminal])
       when terminal == {:fin} or elem(terminal, 0) == :reset do
    case session.peer_streams[stream].type do
      type when type in [:control, :qpack_encoder, :qpack_decoder] ->
        protocol_error(0x104, :closed_critical_stream)

      _ ->
        with {:ok, next} <- retire_stream(session, stream), do: {:ok, next, []}
    end
  end

  defp consume_peer_items(_session, _stream, _items),
    do: protocol_error(0x101, :invalid_stream_event)

  defp consume_peer_bytes(session, stream, bytes) do
    peer = session.peer_streams[stream]

    if peer.type == nil do
      data = peer.buffer <> bytes

      case Stream.decode_type(data) do
        :more ->
          {:ok, put_in(session.peer_streams[stream].buffer, :binary.copy(data)), []}

        {:ok, type, rest} ->
          with {:ok, next} <- identify_peer_stream(session, stream, type) do
            payload = if type == :control, do: data, else: rest
            receive_peer_payload(next, stream, type, payload)
          end
      end
    else
      receive_peer_payload(session, stream, peer.type, bytes)
    end
  end

  defp identify_peer_stream(session, stream, type)
       when type in [:qpack_encoder, :qpack_decoder] do
    if Map.has_key?(session.qpack_streams, type) do
      protocol_error(
        0x103,
        if(type == :qpack_encoder, do: :duplicate_qpack_encoder, else: :duplicate_qpack_decoder)
      )
    else
      {:ok,
       %{
         put_in(session.peer_streams[stream], %{type: type, buffer: <<>>})
         | qpack_streams: Map.put(session.qpack_streams, type, stream)
       }}
    end
  end

  defp identify_peer_stream(_session, _stream, :push),
    do: protocol_error(0x108, :push_not_enabled)

  defp identify_peer_stream(session, stream, type),
    do: {:ok, put_in(session.peer_streams[stream], %{type: type, buffer: <<>>})}

  defp receive_peer_payload(session, stream, :control, bytes) do
    case Control.receive_peer(session.control, stream, bytes) do
      {:ok, control, events} -> {:ok, %{session | control: control}, events}
      {:error, {:http3_error, _, _, _}} = error -> error
      {:error, reason} -> protocol_error(control_code(reason), reason)
    end
  end

  defp receive_peer_payload(session, _stream, :qpack_encoder, bytes) do
    if Enum.all?(:binary.bin_to_list(bytes), &(&1 == 0x20)),
      do: {:ok, session, []},
      else: protocol_error(0x201, :invalid_static_encoder_instruction)
  end

  defp receive_peer_payload(session, _stream, :qpack_decoder, <<>>), do: {:ok, session, []}

  defp receive_peer_payload(_session, _stream, :qpack_decoder, _bytes),
    do: protocol_error(0x202, :invalid_static_decoder_instruction)

  defp receive_peer_payload(session, _stream, {:unknown, _type}, _bytes), do: {:ok, session, []}

  defp control_code(reason)
       when reason in [:duplicate_peer_control_stream, :invalid_peer_control_stream],
       do: 0x103

  defp control_code(reason) when reason in [:invalid_goaway, :increasing_goaway], do: 0x108
  defp control_code(:settings_must_be_first), do: 0x10A
  defp control_code(:duplicate_settings), do: 0x109
  defp control_code({:duplicate_setting, _id}), do: 0x109
  defp control_code({:reserved_setting, _id}), do: 0x109
  defp control_code({:invalid_setting_value, _id, _value}), do: 0x109
  defp control_code(:control_frame_too_large), do: 0x107

  defp control_code(reason)
       when reason in [:truncated_setting_identifier, :truncated_setting_value],
       do: 0x106

  defp control_code(_reason), do: 0x105
  defp protocol_error(code, reason), do: {:error, {:http3_error, :connection, code, reason}}

  defp request_for_stream(requests, stream) do
    Enum.find_value(requests, fn
      {ref, %{stream: ^stream} = request} -> {ref, request}
      _ -> nil
    end)
  end
end

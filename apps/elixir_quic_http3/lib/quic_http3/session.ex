defmodule QuicHttp3.Session do
  @moduledoc """
  Deterministic HTTP/3 session coordinator over `QuicHttp3.Transport`.

  The session owns no processes. Callers drive readiness and event polling
  explicitly; transport flow-control outcomes are returned unchanged.
  """

  alias QuicHttp3.{Control, Frame, Qpack, Stream}

  defstruct transport: QuicHttp3.Transport.Quic,
            connection: nil,
            control: nil,
            control_stream: nil,
            peer_streams: %{},
            requests: %{},
            next_request: 1,
            max_frame: 16_384

  @type t :: %__MODULE__{}

  @spec new([{atom(), term()}]) :: {:ok, t()} | {:error, term()}
  def new(opts \\ [])

  def new(opts) when is_list(opts) do
    transport = Keyword.get(opts, :transport, QuicHttp3.Transport.Quic)
    max_frame = Keyword.get(opts, :max_frame, 16_384)

    if is_atom(transport) and is_integer(max_frame) and max_frame in 1..16_384 do
      {:ok, %__MODULE__{transport: transport, max_frame: max_frame}}
    else
      {:error, :invalid_session_options}
    end
  end

  def new(_opts), do: {:error, :invalid_session_options}

  @spec connect(t(), binary() | tuple(), :inet.port_number(), keyword()) ::
          {:ok, t()} | {:error, term()} | {:blocked, term()} | {:unknown, reference()}
  def connect(%__MODULE__{transport: transport} = session, remote, port, opts) do
    case transport.connect(remote, port, opts) do
      {:ok, connection} -> {:ok, %{session | connection: connection}}
      result -> result
    end
  end

  @spec ready(t()) ::
          :ready | :pending | {:error, term()} | {:blocked, term()} | {:unknown, reference()}
  def ready(%__MODULE__{transport: transport, connection: connection}),
    do: transport.ready(connection, 5_000)

  @spec open(t()) :: {:ok, t()} | {:error, term()} | {:blocked, term()} | {:unknown, reference()}
  def open(%__MODULE__{connection: nil}), do: {:error, :not_connected}
  def open(%__MODULE__{control: %Control{}}), do: {:error, :already_open}

  def open(%__MODULE__{transport: transport, connection: connection} = session) do
    with {:ok, control} <- Control.new(:client),
         {:ok, stream} <- transport.open_stream(connection, :uni, []),
         bytes = Control.local_payload(control),
         :ok <- send_chunks(transport, stream, bytes, false, session.max_frame) do
      {:ok, %{session | control: control, control_stream: stream}}
    end
  end

  @spec request(t(), [Qpack.field()], binary(), keyword()) ::
          {:ok, t(), reference()}
          | {:error, term()}
          | {:blocked, term()}
          | {:unknown, reference()}
  def request(%__MODULE__{control: nil}), do: {:error, :not_open}

  def request(
        %__MODULE__{transport: transport, connection: connection} = session,
        fields,
        body,
        opts
      )
      when is_list(fields) and is_binary(body) do
    with {:ok, headers} <- Qpack.encode_header_block(fields, opts),
         {:ok, header_frame} <- Frame.encode(:headers, headers),
         {:ok, stream} <- transport.open_stream(connection, :bidi, []),
         {:ok, ref} <- send_request(transport, stream, header_frame, body, session.max_frame) do
      request = %{stream: stream, ref: ref, buffer: <<>>, headers_received?: false}

      {:ok,
       %{
         session
         | requests: Map.put(session.requests, ref, request),
           next_request: session.next_request + 1
       }, ref}
    end
  end

  @spec poll(t(), pos_integer()) ::
          {:ok, t(), [term()]} | {:error, term()} | {:blocked, term()} | {:unknown, reference()}
  def poll(%__MODULE__{transport: transport, connection: connection} = session, max)
      when is_integer(max) and max in 1..128 do
    case transport.events(connection, max, []) do
      {:ok, events} -> poll_events(session, events, [])
      result -> result
    end
  end

  def poll(_, _), do: {:error, :invalid_event_limit}

  @spec cancel(t(), reference()) ::
          {:ok, t()} | {:error, term()} | {:blocked, term()} | {:unknown, reference()}
  def cancel(%__MODULE__{transport: transport} = session, ref) do
    case Map.pop(session.requests, ref) do
      {nil, _} ->
        {:error, :unknown_request}

      {%{stream: stream}, requests} ->
        with :ok <- transport.stop_stream(stream, 0, []) do
          {:ok, %{session | requests: requests}}
        end
    end
  end

  @spec close(t()) :: :ok | {:error, term()} | {:blocked, term()} | {:unknown, reference()}
  def close(%__MODULE__{transport: transport, connection: connection})
      when not is_nil(connection),
      do: transport.close(connection, 0, <<>>, [])

  def close(_), do: {:error, :not_connected}

  defp send_request(transport, stream, headers, body, max) do
    with :ok <- send_chunks(transport, stream, headers, body == <<>>, max),
         :ok <- send_chunks(transport, stream, body, true, max) do
      {:ok, make_ref()}
    end
  end

  defp send_chunks(_transport, _stream, <<>>, fin, _max) when fin, do: :ok
  defp send_chunks(_transport, _stream, <<>>, false, _max), do: :ok

  defp send_chunks(transport, stream, data, fin, max) do
    size = min(byte_size(data), max)
    <<chunk::binary-size(^size), rest::binary>> = data
    final? = fin and rest == <<>>

    case transport.send_stream(stream, chunk, final?, []) do
      {:ok, _} when rest != <<>> -> send_chunks(transport, stream, rest, fin, max)
      :ok when rest != <<>> -> send_chunks(transport, stream, rest, fin, max)
      {:ok, _} when final? -> :ok
      :ok when final? -> :ok
      :ok -> send_chunks(transport, stream, rest, fin, max)
      {:ok, _} -> send_chunks(transport, stream, rest, fin, max)
      result -> result
    end
  end

  defp poll_events(session, [], acc), do: {:ok, session, Enum.reverse(acc)}

  defp poll_events(session, [{:stream_open, stream, :uni} | rest], acc) do
    next = %{
      session
      | peer_streams: Map.put_new(session.peer_streams, stream, %{type: nil, buffer: <<>>})
    }

    poll_events(next, rest, acc)
  end

  defp poll_events(session, [{:stream_open, _stream, _kind} | rest], acc),
    do: poll_events(session, rest, acc)

  defp poll_events(session, [{:readable, stream} | rest], acc) do
    cond do
      request_for_stream(session.requests, stream) != nil ->
        poll_request_stream(session, stream, rest, acc)

      Map.has_key?(session.peer_streams, stream) ->
        poll_peer_stream(session, stream, rest, acc)

      true ->
        {:error, :unknown_stream_event}
    end
  end

  defp poll_events(session, [{kind, stream, code} | rest], acc)
       when kind in [:stream_reset, :stopped] do
    case request_for_stream(session.requests, stream) do
      {ref, _request} ->
        next = %{session | requests: Map.delete(session.requests, ref)}
        poll_events(next, rest, [{kind, ref, code} | acc])

      nil ->
        if Map.has_key?(session.peer_streams, stream),
          do: {:error, :peer_control_stream_reset},
          else: {:error, :unknown_stream_event}
    end
  end

  defp poll_events(_session, [{:closed, reason} | _rest], _acc),
    do: {:error, {:connection_closed, reason}}

  defp poll_events(_session, [{:error, reason} | _rest], _acc), do: {:error, reason}

  defp poll_events(session, [:ready | rest], acc), do: poll_events(session, rest, [:ready | acc])

  defp poll_events(session, [{:ready, metadata} | rest], acc),
    do: poll_events(session, rest, [{:ready, metadata} | acc])

  defp poll_events(session, [:writable | rest], acc),
    do: poll_events(session, rest, [:writable | acc])

  defp poll_events(session, [:datagram_readable | rest], acc),
    do: poll_events(session, rest, [:datagram_readable | acc])

  defp poll_events(_session, [_event | _rest], _acc), do: {:error, :invalid_transport_event}

  defp poll_request_stream(session, stream, rest, acc) do
    {ref, request} = request_for_stream(session.requests, stream)

    case session.transport.read(stream, session.max_frame, []) do
      {:ok, items} ->
        case parse_items(request, items, []) do
          {:ok, request, emitted} ->
            next = %{session | requests: Map.put(session.requests, ref, request)}
            poll_events(next, rest, Enum.reverse(emitted) ++ acc)

          {:error, _} = error ->
            error
        end

      result ->
        result
    end
  end

  defp poll_peer_stream(session, stream, rest, acc) do
    case session.transport.read(stream, session.max_frame, []) do
      {:ok, items} ->
        case consume_peer_items(session, stream, items) do
          {:ok, next, emitted} -> poll_events(next, rest, Enum.reverse(emitted) ++ acc)
          {:error, _} = error -> error
        end

      result ->
        result
    end
  end

  defp consume_peer_items(session, _stream, []), do: {:ok, session, []}

  defp consume_peer_items(session, stream, [{:data, bytes} | rest]) when is_binary(bytes),
    do: consume_peer_bytes(session, stream, bytes, rest)

  defp consume_peer_items(session, stream, [{:data, _id, bytes} | rest]) when is_binary(bytes),
    do: consume_peer_bytes(session, stream, bytes, rest)

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

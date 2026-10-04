defmodule Quic.Streams do
  @moduledoc """
  Connection-owned QUIC stream state.

  Stream values are data references; this module creates no processes. All
  peer-controlled offsets and buffering are checked against the configured
  limits before bytes are retained.
  """
  import Bitwise

  defstruct role: :client,
            streams: %{},
            max_data: 1_048_576,
            data_sent: 0,
            data_received: 0,
            data_delivered: 0,
            data_consumed: 0,
            max_stream_data: 65_536,
            max_stream_data_bidi_local: 65_536,
            max_stream_data_bidi_remote: 65_536,
            max_stream_data_uni: 65_536,
            max_streams_bidi: 16,
            max_streams_uni: 16,
            max_stream_records: 1024,
            max_peer_stream_records: 32,
            max_local_stream_records: 992,
            max_recv_ranges: 256,
            next_local_bidi: 0,
            next_local_uni: 0,
            max_buffer: 262_144,
            peer_max_data: 1_048_576,
            peer_max_stream_data: 65_536,
            peer_max_stream_data_bidi_local: 65_536,
            peer_max_stream_data_bidi_remote: 65_536,
            peer_max_stream_data_uni: 65_536,
            peer_max_streams_bidi: 16,
            peer_max_streams_uni: 16,
            blocked: MapSet.new(),
            delivery: :immediate,
            ready: %{},
            ready_bytes: 0,
            max_ready_bytes: 262_144,
            pending_credit: %{}

  defmodule Stream do
    @moduledoc false
    defstruct id: 0,
              bidi: true,
              local_initiated: false,
              send_offset: 0,
              send_limit: 0,
              send_final: nil,
              recv_next: 0,
              recv_limit: 0,
              recv_accounted: 0,
              recv_consumed: 0,
              recv_final: nil,
              recv_highest: 0,
              recv_terminal: nil,
              recv_chunks: %{},
              recv_buffered: 0,
              reset: nil,
              receive_stopped: nil,
              send_reset: nil,
              stopped: nil
  end

  @type t :: %__MODULE__{blocked: MapSet.t()}
  @type initial_state :: %__MODULE__{
          role: :client | :server,
          blocked: MapSet.t(),
          streams: %{},
          data_sent: 0,
          data_received: 0,
          data_delivered: 0,
          data_consumed: 0,
          next_local_bidi: 0,
          next_local_uni: 0,
          delivery: :immediate | :manual,
          ready: %{},
          ready_bytes: 0,
          pending_credit: %{},
          max_stream_records: number(),
          max_peer_stream_records: number(),
          max_local_stream_records: number(),
          max_streams_bidi: number(),
          max_streams_uni: number()
        }

  @spec new(:client | :server, keyword()) :: initial_state()
  def new(role, opts \\ [])

  def new(role, opts) when role in [:client, :server] do
    max_buffer = positive(opts, :max_buffer, 262_144)

    max_ready_bytes =
      positive(opts, :max_ready_bytes, Keyword.get(opts, :max_receive_buffer, 262_144))

    delivery = delivery_mode(opts)
    max_stream_records = positive(opts, :max_stream_records, 1024)
    max_streams_bidi = min(nonnegative(opts, :max_streams_bidi, 16), max_stream_records)

    max_streams_uni =
      min(nonnegative(opts, :max_streams_uni, 16), max_stream_records - max_streams_bidi)

    %__MODULE__{
      role: role,
      max_data:
        receive_credit_limit(
          nonnegative(opts, :max_data, 1_048_576),
          delivery,
          max_buffer,
          max_ready_bytes
        ),
      max_stream_data: nonnegative(opts, :max_stream_data, 65_536),
      max_stream_data_bidi_local:
        nonnegative(
          opts,
          :max_stream_data_bidi_local,
          Keyword.get(opts, :max_stream_data, 65_536)
        ),
      max_stream_data_bidi_remote:
        nonnegative(
          opts,
          :max_stream_data_bidi_remote,
          Keyword.get(opts, :max_stream_data, 65_536)
        ),
      max_stream_data_uni:
        nonnegative(opts, :max_stream_data_uni, Keyword.get(opts, :max_stream_data, 65_536)),
      max_streams_bidi: max_streams_bidi,
      max_streams_uni: max_streams_uni,
      max_stream_records: max_stream_records,
      max_peer_stream_records: max_streams_bidi + max_streams_uni,
      max_local_stream_records: max_stream_records - max_streams_bidi - max_streams_uni,
      max_recv_ranges: positive(opts, :max_recv_ranges, 256),
      max_buffer: max_buffer,
      peer_max_data: nonnegative(opts, :peer_max_data, 1_048_576),
      peer_max_stream_data: nonnegative(opts, :peer_max_stream_data, 65_536),
      peer_max_stream_data_bidi_local:
        nonnegative(
          opts,
          :peer_max_stream_data_bidi_local,
          Keyword.get(opts, :peer_max_stream_data, 65_536)
        ),
      peer_max_stream_data_bidi_remote:
        nonnegative(
          opts,
          :peer_max_stream_data_bidi_remote,
          Keyword.get(opts, :peer_max_stream_data, 65_536)
        ),
      peer_max_stream_data_uni:
        nonnegative(
          opts,
          :peer_max_stream_data_uni,
          Keyword.get(opts, :peer_max_stream_data, 65_536)
        ),
      peer_max_streams_bidi: nonnegative(opts, :peer_max_streams_bidi, 16),
      peer_max_streams_uni: nonnegative(opts, :peer_max_streams_uni, 16),
      delivery: delivery,
      max_ready_bytes: max_ready_bytes
    }
  end

  def new(_, _), do: raise(ArgumentError, "invalid stream role")

  @doc "Install authenticated peer transport parameters into stream send limits."
  def install_peer_parameters(%__MODULE__{} = state, values) when is_map(values) do
    next = %{
      state
      | peer_max_data: parameter(values, :initial_max_data, 0),
        peer_max_streams_bidi: parameter(values, :initial_max_streams_bidi, 0),
        peer_max_streams_uni: parameter(values, :initial_max_streams_uni, 0),
        peer_max_stream_data_bidi_local:
          parameter(values, :initial_max_stream_data_bidi_local, 0),
        peer_max_stream_data_bidi_remote:
          parameter(values, :initial_max_stream_data_bidi_remote, 0),
        peer_max_stream_data_uni: parameter(values, :initial_max_stream_data_uni, 0)
    }

    streams =
      Map.new(next.streams, fn {id, stream} ->
        {id, %{stream | send_limit: peer_stream_limit(next, stream)}}
      end)

    %{next | streams: streams}
  end

  def install_peer_parameters(%__MODULE__{} = state, _), do: state

  @doc "Open a locally initiated stream and return its stable stream id."
  def open(%__MODULE__{} = state, kind) when kind in [:bidi, :uni] do
    limit = if kind == :bidi, do: state.peer_max_streams_bidi, else: state.peer_max_streams_uni

    count = if kind == :bidi, do: state.next_local_bidi, else: state.next_local_uni

    local_records = Enum.count(state.streams, fn {_id, stream} -> stream.local_initiated end)

    if count >= limit or
         local_records >=
           state.max_stream_records - state.max_streams_bidi - state.max_streams_uni do
      {:blocked, blocked_frame(kind, count)}
    else
      id = 4 * count + role_bit(state.role) + if(kind == :uni, do: 2, else: 0)
      stream = make_stream(state, id, kind == :bidi, true)

      next =
        state
        |> Map.put(:streams, Map.put(state.streams, id, stream))
        |> Map.update!(if(kind == :bidi, do: :next_local_bidi, else: :next_local_uni), &(&1 + 1))

      {:ok, next, id}
    end
  end

  @doc "Admit bytes to a stream send queue; returned frame can be packetized."
  def send(%__MODULE__{} = state, id, data, fin \\ false)
      when is_integer(id) and id >= 0 and is_binary(data) and is_boolean(fin) do
    with {:ok, stream} <- fetch_stream(state, id),
         :ok <- can_send?(stream),
         :ok <- valid_final_send(stream, byte_size(data), fin),
         :ok <- send_credit(state, stream, byte_size(data)) do
      next_offset = stream.send_offset + byte_size(data)

      stream = %{
        stream
        | send_offset: next_offset,
          send_final: if(fin, do: next_offset, else: stream.send_final)
      }

      next = %{
        state
        | streams: Map.put(state.streams, id, stream),
          data_sent: state.data_sent + byte_size(data)
      }

      {:ok, next,
       %{
         type: :stream,
         stream_id: id,
         offset: stream.send_offset - byte_size(data),
         data: data,
         fin: fin
       }}
    else
      {:error, _} = error -> error
      :blocked -> {:blocked, %{type: :data_blocked, value: state.data_sent}}
    end
  end

  @doc "Process one authenticated STREAM frame and emit newly contiguous bytes."
  def receive(%__MODULE__{} = state, %{
        type: :stream,
        stream_id: id,
        offset: offset,
        data: data,
        fin: fin
      })
      when is_integer(id) and id >= 0 and is_integer(offset) and offset >= 0 and is_binary(data) and
             is_boolean(fin) do
    with {:ok, state, stream} <- ensure_peer_stream(state, id), :ok <- can_receive?(stream) do
      if stream.reset != nil do
        case consistent_final(stream, offset + byte_size(data), fin) do
          :ok -> {:ok, state, []}
          {:error, _} = error -> error
        end
      else
        with :ok <- receive_bounds(state, stream, offset, data),
             :ok <- consistent_final(stream, offset + byte_size(data), fin),
             {:ok, state, stream} <- account_receive(state, stream, offset + byte_size(data)),
             stream <- %{
               stream
               | recv_final: if(fin, do: offset + byte_size(data), else: stream.recv_final),
                 recv_highest: max(stream.recv_highest, offset + byte_size(data))
             },
             {:ok, stream} <- insert_chunk(state, stream, offset, data),
             {:ok, stream, events} <- consume_chunks(stream, id) do
          next = %{state | streams: Map.put(state.streams, id, stream)}

          case retain_events(next, id, events) do
            {:ok, next, delivered} ->
              next = replenish_credit(next, id, emitted_bytes(delivered))

              {:ok, %{next | data_delivered: next.data_delivered + emitted_bytes(delivered)},
               delivered}

            {:error, _} = error ->
              error
          end
        else
          {:error, _} = error -> error
        end
      end
    end
  end

  def receive(_, _), do: {:error, :invalid_stream_frame}

  @doc "Consume queued stream events when `delivery: :manual` is configured."
  def consume(%__MODULE__{delivery: :manual} = state, id, max_bytes)
      when is_integer(id) and id >= 0 and is_integer(max_bytes) and max_bytes > 0 do
    with {:ok, stream} <- fetch_stream(state, id), :ok <- can_receive?(stream) do
      {events, rest, bytes} = take_events(Map.get(state.ready, id, []), max_bytes, [], 0)

      ready = if rest == [], do: Map.delete(state.ready, id), else: Map.put(state.ready, id, rest)
      next = %{state | ready: ready, ready_bytes: state.ready_bytes - bytes}

      next =
        next
        |> replenish_credit(id, bytes)
        |> release_reset_credit(id, events)
        |> replenish_stream_slot(id, events)

      {:ok, %{next | data_delivered: next.data_delivered + bytes}, events}
    end
  end

  def consume(%__MODULE__{}, _id, _max_bytes), do: {:error, :manual_delivery_disabled}

  @doc "Return coalesced receive-credit frames and clear their pending state."
  def take_credit(%__MODULE__{} = state) do
    frames =
      state.pending_credit
      |> Enum.map(fn
        {:max_data, value} -> %{type: :max_data, value: value}
        {{:max_stream_data, id}, value} -> %{type: :max_stream_data, stream_id: id, value: value}
        {:max_streams_bidi, value} -> %{type: :max_streams_bidi, value: value}
        {:max_streams_uni, value} -> %{type: :max_streams_uni, value: value}
      end)
      |> Enum.sort_by(fn frame -> {frame.type, Map.get(frame, :stream_id, -1)} end)

    {%{state | pending_credit: %{}}, frames}
  end

  def reset(%__MODULE__{} = state, id, error_code, final_size)
      when is_integer(error_code) and error_code >= 0 and is_integer(final_size) and
             final_size >= 0 do
    with {:ok, stream} <- fetch_stream(state, id),
         :ok <- can_receive?(stream),
         :ok <- reset_final(stream, final_size) do
      stream = %{
        stream
        | reset: error_code,
          recv_final: final_size,
          recv_chunks: %{},
          recv_buffered: 0
      }

      {:ok, %{state | streams: Map.put(state.streams, id, stream)},
       [{:reset, id, error_code, final_size}]}
    end
  end

  @doc "Reset the local send direction at its admitted final size."
  def reset_send(%__MODULE__{} = state, id, error_code)
      when is_integer(error_code) and error_code >= 0 do
    with {:ok, stream} <- fetch_stream(state, id), :ok <- can_send?(stream) do
      stream = %{stream | send_reset: error_code, stopped: error_code}

      frame = %{
        type: :reset_stream,
        stream_id: id,
        error_code: error_code,
        final_size: stream.send_offset
      }

      {:ok, %{state | streams: Map.put(state.streams, id, stream)}, frame}
    else
      {:error, :stopped} ->
        case fetch_stream(state, id) do
          {:ok, %Stream{send_reset: ^error_code}} -> {:ok, state, nil}
          {:ok, %Stream{send_reset: _}} -> {:error, :stopped}
          error -> error
        end

      {:error, _} = error ->
        error
    end
  end

  @doc "Apply a peer RESET_STREAM, admitting a previously unseen peer stream."
  def receive_reset(%__MODULE__{} = state, id, error_code, final_size)
      when is_integer(id) and id >= 0 do
    with {:ok, state, stream} <- ensure_peer_stream(state, id), :ok <- can_receive?(stream) do
      case {stream.recv_terminal, stream.reset} do
        {:fin, _} ->
          with :ok <- reset_final(stream, final_size), do: {:ok, state, []}

        {_, nil} ->
          with :ok <- reset_final(stream, final_size),
               {:ok, state, stream} <- account_receive(state, stream, final_size) do
            stream = %{
              stream
              | reset: error_code,
                recv_final: final_size,
                recv_chunks: %{},
                recv_buffered: 0,
                recv_terminal: :reset
            }

            next =
              state
              |> clear_ready_stream(id)
              |> Map.put(:streams, Map.put(state.streams, id, stream))

            case retain_events(next, id, [{:reset, id, error_code, final_size}]) do
              {:ok, next, events} -> {:ok, next, events}
              {:error, _} = error -> error
            end
          end

        {_, ^error_code} when stream.recv_final == final_size ->
          {:ok, state, []}

        _ ->
          {:error, :final_size_error}
      end
    end
  end

  def stop_sending(%__MODULE__{} = state, id, error_code)
      when is_integer(error_code) and error_code >= 0 do
    with {:ok, stream} <- fetch_stream(state, id), :ok <- can_receive?(stream) do
      released = stream.recv_accounted - stream.recv_consumed

      stream = %{
        stream
        | receive_stopped: error_code,
          recv_consumed: stream.recv_accounted,
          recv_chunks: %{},
          recv_buffered: 0
      }

      next =
        state
        |> clear_ready_stream(id)
        |> Map.put(:streams, Map.put(state.streams, id, stream))
        |> release_connection_credit(released)

      {:ok, next, %{type: :stop_sending, stream_id: id, error_code: error_code}}
    end
  end

  @doc "Apply a peer STOP_SENDING to the local send direction."
  def peer_stop_sending(%__MODULE__{} = state, id, error_code)
      when is_integer(error_code) and error_code >= 0 do
    reset_send(state, id, error_code)
  end

  def update_credit(%__MODULE__{} = state, %{type: :max_data, value: value})
      when is_integer(value) and value >= 0,
      do: {:ok, %{state | peer_max_data: max(state.peer_max_data, value)}, :unblocked}

  def update_credit(%__MODULE__{} = state, %{type: :max_stream_data, stream_id: id, value: value})
      when is_integer(id) and is_integer(value) and value >= 0 do
    with {:ok, stream} <- fetch_stream(state, id) do
      stream = %{stream | send_limit: max(stream.send_limit, value)}
      {:ok, %{state | streams: Map.put(state.streams, id, stream)}, :unblocked}
    end
  end

  def update_credit(%__MODULE__{} = state, %{type: :max_streams_bidi, value: value})
      when is_integer(value) and value >= 0,
      do:
        {:ok, %{state | peer_max_streams_bidi: max(state.peer_max_streams_bidi, value)},
         :unblocked}

  def update_credit(%__MODULE__{} = state, %{type: :max_streams_uni, value: value})
      when is_integer(value) and value >= 0,
      do:
        {:ok, %{state | peer_max_streams_uni: max(state.peer_max_streams_uni, value)}, :unblocked}

  def update_credit(_, _), do: {:error, :invalid_credit_frame}

  def stream(%__MODULE__{} = state, id), do: Map.get(state.streams, id)

  defp fetch_stream(state, id) do
    case Map.fetch(state.streams, id) do
      {:ok, stream} -> {:ok, stream}
      :error -> {:error, :unknown_stream}
    end
  end

  defp ensure_peer_stream(state, id) do
    case Map.fetch(state.streams, id) do
      {:ok, stream} ->
        {:ok, state, stream}

      :error ->
        ensure_new_peer_stream(state, id)
    end
  end

  defp ensure_new_peer_stream(state, id) do
    local = (id &&& 1) == role_bit(state.role)

    if local do
      {:error, :peer_stream_id_invalid}
    else
      bidi = (id &&& 2) == 0

      limit = if bidi, do: state.max_streams_bidi, else: state.max_streams_uni

      if div(id, 4) >= limit do
        {:error, :stream_limit}
      else
        peer_records =
          Enum.count(state.streams, fn {_id, stream} -> not stream.local_initiated end)

        if peer_records >= state.max_stream_records do
          {:error, :stream_resource_limit}
        else
          next = put_peer_stream(state, id, bidi)
          {:ok, next, next.streams[id]}
        end
      end
    end
  end

  defp put_peer_stream(state, id, bidi) do
    stream = make_stream(state, id, bidi, false)
    %{state | streams: Map.put(state.streams, id, stream)}
  end

  defp make_stream(state, id, bidi, local) do
    %Stream{
      id: id,
      bidi: bidi,
      local_initiated: local,
      send_limit: peer_stream_limit(state, %{bidi: bidi, local_initiated: local}),
      recv_limit: local_stream_limit(state, bidi, local)
    }
  end

  defp peer_stream_limit(state, %{bidi: false, local_initiated: true}),
    do: state.peer_max_stream_data_uni

  defp peer_stream_limit(state, %{bidi: true, local_initiated: true}),
    do: state.peer_max_stream_data_bidi_remote

  defp peer_stream_limit(state, %{bidi: true, local_initiated: false}),
    do: state.peer_max_stream_data_bidi_local

  defp peer_stream_limit(_state, %{bidi: false, local_initiated: false}), do: 0

  defp local_stream_limit(state, false, _local), do: state.max_stream_data_uni
  defp local_stream_limit(state, true, true), do: state.max_stream_data_bidi_local
  defp local_stream_limit(state, true, false), do: state.max_stream_data_bidi_remote

  defp can_send?(%Stream{stopped: reason}) when not is_nil(reason), do: {:error, :stopped}
  defp can_send?(%Stream{bidi: true}), do: :ok
  defp can_send?(%Stream{local_initiated: true}), do: :ok
  defp can_send?(_), do: {:error, :send_on_receive_only_stream}
  defp can_receive?(%Stream{bidi: true}), do: :ok
  defp can_receive?(%Stream{local_initiated: false}), do: :ok
  defp can_receive?(_), do: {:error, :receive_on_send_only_stream}

  defp send_credit(state, stream, bytes) do
    cond do
      state.data_sent + bytes > state.peer_max_data -> :blocked
      stream.send_offset + bytes > stream.send_limit -> :blocked
      true -> :ok
    end
  end

  defp valid_final_send(%Stream{send_final: nil}, _bytes, true), do: :ok
  defp valid_final_send(%Stream{send_final: nil}, _bytes, false), do: :ok

  defp valid_final_send(%Stream{send_final: final, send_offset: offset}, bytes, fin),
    do: if(offset + bytes == final and fin, do: :ok, else: {:error, :final_size_error})

  defp receive_bounds(state, stream, offset, data) do
    end_offset = offset + byte_size(data)

    cond do
      end_offset > stream.recv_limit -> {:error, :flow_control}
      offset > stream.recv_next + state.max_buffer -> {:error, :buffer_limit}
      true -> :ok
    end
  end

  defp account_receive(state, stream, end_offset) do
    increase = max(0, end_offset - stream.recv_accounted)

    if end_offset > stream.recv_limit or state.data_received + increase > state.max_data do
      {:error, :flow_control}
    else
      {:ok, %{state | data_received: state.data_received + increase},
       %{stream | recv_accounted: max(stream.recv_accounted, end_offset)}}
    end
  end

  defp consistent_final(%Stream{recv_final: nil}, _end_offset, false), do: :ok

  defp consistent_final(%Stream{recv_final: nil, recv_highest: highest}, end_offset, true)
       when end_offset < highest,
       do: {:error, :final_size_error}

  defp consistent_final(%Stream{recv_final: nil}, _end_offset, true), do: :ok

  defp consistent_final(%Stream{recv_final: final}, end_offset, fin)
       when fin and final != end_offset,
       do: {:error, :final_size_error}

  defp consistent_final(%Stream{recv_final: final}, end_offset, _fin) when end_offset > final,
    do: {:error, :final_size_error}

  defp consistent_final(_, _, _), do: :ok

  defp insert_chunk(_state, stream, _offset, <<>>), do: {:ok, stream}

  defp insert_chunk(state, stream, offset, data) do
    {offset, data} = trim_delivered_prefix(stream, offset, data)

    if data == <<>> do
      {:ok, stream}
    else
      with :ok <- check_buffered_overlaps(stream.recv_chunks, offset, data),
           additions <- subtract_buffered_ranges([{offset, data}], stream.recv_chunks),
           added_bytes <- Enum.sum(Enum.map(additions, fn {_at, bytes} -> byte_size(bytes) end)),
           :ok <- check_buffer_limit(state, stream, added_bytes),
           :ok <- check_range_limit(state, stream, additions) do
        chunks =
          Enum.reduce(additions, stream.recv_chunks, fn {at, bytes}, acc ->
            Map.put(acc, at, bytes)
          end)

        {:ok, %{stream | recv_chunks: chunks, recv_buffered: stream.recv_buffered + added_bytes}}
      end
    end
  end

  defp trim_delivered_prefix(stream, offset, data) do
    end_offset = offset + byte_size(data)

    if end_offset <= stream.recv_next do
      {stream.recv_next, <<>>}
    else
      kept_offset = max(offset, stream.recv_next)
      {kept_offset, binary_part(data, kept_offset - offset, end_offset - kept_offset)}
    end
  end

  defp check_buffered_overlaps(chunks, offset, data) do
    if Enum.any?(chunks, fn {at, old} -> overlap_conflict?(offset, data, at, old) end),
      do: {:error, :overlap_conflict},
      else: :ok
  end

  defp subtract_buffered_ranges(ranges, chunks) do
    Enum.reduce(chunks, ranges, fn {at, old}, remaining ->
      Enum.flat_map(remaining, &subtract_buffered_range(&1, at, old))
    end)
  end

  defp subtract_buffered_range({offset, data}, at, old) do
    left = max(offset, at)
    right = min(offset + byte_size(data), at + byte_size(old))

    if right <= left do
      [{offset, data}]
    else
      prefix = if left > offset, do: [{offset, binary_part(data, 0, left - offset)}], else: []
      suffix_offset = right
      suffix_length = offset + byte_size(data) - right

      suffix =
        if suffix_length > 0,
          do: [{suffix_offset, binary_part(data, right - offset, suffix_length)}],
          else: []

      prefix ++ suffix
    end
  end

  defp check_buffer_limit(_state, _stream, 0), do: :ok

  defp check_buffer_limit(state, stream, bytes) do
    if stream.recv_buffered + bytes > state.max_buffer, do: {:error, :buffer_limit}, else: :ok
  end

  defp check_range_limit(_state, _stream, []), do: :ok

  defp check_range_limit(state, stream, additions) do
    if map_size(stream.recv_chunks) + length(additions) > state.max_recv_ranges,
      do: {:error, :range_limit},
      else: :ok
  end

  defp overlap_conflict?(a, bytes, b, old) do
    left = max(a, b)
    right = min(a + byte_size(bytes), b + byte_size(old))

    right > left and
      binary_part(bytes, left - a, right - left) != binary_part(old, left - b, right - left)
  end

  defp consume_chunks(stream, id), do: consume_chunks(stream, id, [])

  defp consume_chunks(stream, id, events) do
    case Map.pop(stream.recv_chunks, stream.recv_next) do
      {nil, _} ->
        if is_integer(stream.recv_final) and stream.recv_next == stream.recv_final and
             stream.reset == nil and stream.recv_terminal == nil do
          {:ok, %{stream | recv_terminal: :fin}, Enum.reverse([{:fin, id} | events])}
        else
          {:ok, stream, Enum.reverse(events)}
        end

      {data, chunks} ->
        next = %{
          stream
          | recv_chunks: chunks,
            recv_next: stream.recv_next + byte_size(data),
            recv_buffered: stream.recv_buffered - byte_size(data)
        }

        consume_chunks(next, id, [{:data, id, data} | events])
    end
  end

  defp reset_final(%Stream{recv_final: nil, recv_highest: highest}, final) when final >= highest,
    do: :ok

  defp reset_final(%Stream{recv_final: final}, final), do: :ok
  defp reset_final(_, _), do: {:error, :final_size_error}

  defp emitted_bytes(events),
    do:
      Enum.reduce(events, 0, fn
        {:data, _, bytes}, acc -> acc + byte_size(bytes)
        _, acc -> acc
      end)

  defp retain_events(%{delivery: :immediate} = state, _id, events), do: {:ok, state, events}

  defp retain_events(%{delivery: :manual} = state, id, events) do
    bytes = emitted_bytes(events)

    if state.ready_bytes + bytes > state.max_ready_bytes do
      {:error, :receive_queue_limit}
    else
      ready = Map.update(state.ready, id, events, &(&1 ++ events))
      {:ok, %{state | ready: ready, ready_bytes: state.ready_bytes + bytes}, []}
    end
  end

  defp clear_ready_stream(state, id) do
    removed = Map.get(state.ready, id, []) |> emitted_bytes()
    %{state | ready: Map.delete(state.ready, id), ready_bytes: state.ready_bytes - removed}
  end

  defp take_events([], _limit, acc, bytes), do: {Enum.reverse(acc), [], bytes}

  defp take_events([{:data, id, data} | rest], limit, acc, bytes) when bytes < limit do
    size = min(byte_size(data), limit - bytes)
    <<taken::binary-size(^size), remaining::binary>> = data
    next_rest = if remaining == <<>>, do: rest, else: [{:data, id, remaining} | rest]
    take_events(next_rest, limit, [{:data, id, taken} | acc], bytes + size)
  end

  defp take_events([event | rest], limit, acc, bytes) do
    event_bytes = emitted_bytes([event])

    if event_bytes > 0 and bytes + event_bytes > limit do
      {Enum.reverse(acc), [event | rest], bytes}
    else
      take_events(rest, limit, [event | acc], bytes + event_bytes)
    end
  end

  defp role_bit(:client), do: 0
  defp role_bit(:server), do: 1
  defp blocked_frame(:bidi, count), do: %{type: :streams_blocked_bidi, value: count}
  defp blocked_frame(:uni, count), do: %{type: :streams_blocked_uni, value: count}
  defp positive(opts, key, default), do: max(1, Keyword.get(opts, key, default))
  defp nonnegative(opts, key, default), do: max(0, Keyword.get(opts, key, default))

  defp receive_credit_limit(value, :manual, max_buffer, max_ready_bytes),
    do: min(value, min(max_buffer, max_ready_bytes))

  defp receive_credit_limit(value, :immediate, _max_buffer, _max_ready_bytes), do: value

  defp parameter(values, key, default) do
    case Map.get(values, key, default) do
      value when is_integer(value) and value >= 0 -> value
      _ -> default
    end
  end

  defp replenish_credit(state, _id, 0), do: state

  defp replenish_credit(state, id, bytes) do
    case Map.fetch(state.streams, id) do
      {:ok, stream} ->
        stream = %{
          stream
          | recv_limit: stream.recv_limit + bytes,
            recv_consumed: stream.recv_consumed + bytes
        }

        pending_credit =
          state.pending_credit
          |> coalesce_credit(:max_data, state.max_data + bytes)
          |> coalesce_credit({:max_stream_data, id}, stream.recv_limit)

        %{
          state
          | streams: Map.put(state.streams, id, stream),
            max_data: state.max_data + bytes,
            data_consumed: state.data_consumed + bytes,
            pending_credit: pending_credit
        }

      :error ->
        state
    end
  end

  defp coalesce_credit(pending, key, value), do: Map.update(pending, key, value, &max(&1, value))

  defp release_reset_credit(state, id, events) do
    if Enum.any?(events, &match?({:reset, ^id, _, _}, &1)) do
      case Map.get(state.streams, id) do
        %Stream{reset: reset, recv_accounted: accounted, recv_consumed: consumed} = stream
        when not is_nil(reset) and accounted > consumed ->
          released = accounted - consumed
          stream = %{stream | recv_consumed: accounted}
          max_data = state.max_data + released

          %{
            state
            | streams: Map.put(state.streams, id, stream),
              max_data: max_data,
              data_consumed: state.data_consumed + released,
              pending_credit: coalesce_credit(state.pending_credit, :max_data, max_data)
          }

        _ ->
          state
      end
    else
      state
    end
  end

  defp release_connection_credit(state, 0), do: state

  defp release_connection_credit(state, bytes) do
    max_data = state.max_data + bytes

    %{
      state
      | max_data: max_data,
        data_consumed: state.data_consumed + bytes,
        pending_credit: coalesce_credit(state.pending_credit, :max_data, max_data)
    }
  end

  defp replenish_stream_slot(state, id, events) do
    terminal? =
      Enum.any?(events, fn event ->
        match?({:fin, ^id}, event) or match?({:reset, ^id, _, _}, event)
      end)

    local_records = Enum.count(state.streams, fn {_id, stream} -> stream.local_initiated end)

    case {terminal?, Map.get(state.streams, id),
          state.max_streams_bidi + state.max_streams_uni <
            state.max_stream_records - local_records} do
      {true, %Stream{local_initiated: false, bidi: bidi}, true} ->
        {field, frame_type} =
          if bidi,
            do: {:max_streams_bidi, :max_streams_bidi},
            else: {:max_streams_uni, :max_streams_uni}

        value = Map.fetch!(state, field) + 1

        state
        |> Map.put(field, value)
        |> Map.put(:pending_credit, coalesce_credit(state.pending_credit, frame_type, value))

      _ ->
        state
    end
  end

  defp delivery_mode(opts) do
    case Keyword.get(opts, :delivery, :immediate) do
      mode when mode in [:immediate, :manual] -> mode
      _ -> :immediate
    end
  end
end

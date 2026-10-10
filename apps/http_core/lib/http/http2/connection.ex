defmodule HTTP.HTTP2.Connection do
  @moduledoc "Pure HTTP/2 connection state and protocol effects."
  import Bitwise
  alias HTTP.HTTP2.{Frame, HPACK, Settings, StreamState}
  @max_id 2_147_483_647
  @max_window 2_147_483_647
  defstruct next_stream_id: 1,
            streams: %{},
            local: Settings.new(),
            peer: Settings.new(),
            connection_send_window: 65_535,
            connection_receive_window: 65_535,
            connection_unacknowledged: 0,
            encoder: HPACK.new_encoder(),
            encoder_options: [],
            decoder: HPACK.new_decoder(),
            state: :ready,
            goaway_last_stream_id: nil,
            max_streams: :infinity,
            header_block: nil,
            committed: MapSet.new(),
            pending_headers: %{},
            priorities: %{},
            promised: MapSet.new()

  @type t :: %__MODULE__{}

  def new(opts \\ []) do
    %__MODULE__{
      connection_send_window: Keyword.get(opts, :send_window, 65_535),
      connection_receive_window: Keyword.get(opts, :receive_window, 65_535),
      local: Keyword.get(opts, :local_settings, Settings.new()),
      peer: Keyword.get(opts, :peer_settings, Settings.new()),
      encoder_options: Keyword.get(opts, :hpack, [])
    }
    |> then(&%{&1 | max_streams: &1.peer.values.max_concurrent_streams})
  end

  def open_stream(%__MODULE__{} = c, opts \\ []) do
    purpose = Keyword.get(opts, :purpose, :request)

    cond do
      purpose not in [:request, :extended_connect] ->
        {:error, :invalid_stream_purpose}

      purpose == :extended_connect and c.peer.values.enable_connect_protocol != 1 ->
        {:error, :extended_connect_not_supported}

      c.state != :ready ->
        {:error, :draining}

      c.next_stream_id > @max_id ->
        {:error, :stream_id_exhausted}

      c.max_streams != :infinity and map_size(c.streams) >= c.max_streams ->
        {:error, :max_concurrent_streams}

      c.goaway_last_stream_id && c.next_stream_id > c.goaway_last_stream_id ->
        {:error, :draining}

      true ->
        id = c.next_stream_id

        stream =
          StreamState.new(id,
            send_window: c.peer.values.initial_window_size,
            receive_window: c.local.values.initial_window_size,
            request_ref: Keyword.get(opts, :request_ref),
            request_method: Keyword.get(opts, :request_method),
            purpose: purpose
          )

        {:ok, stream} = StreamState.open(stream)

        c = %{
          c
          | next_stream_id: if(id == @max_id, do: @max_id + 2, else: id + 2),
            streams: Map.put(c.streams, id, stream)
        }

        {:ok, stream, c}
    end
  end

  def accept_new_stream?(%__MODULE__{state: :ready}), do: true
  def accept_new_stream?(_), do: false

  def put_stream(%__MODULE__{} = c, %StreamState{id: id} = s),
    do: %{c | streams: Map.put(c.streams, id, s)}

  def stream(%__MODULE__{} = c, id), do: Map.fetch(c.streams, id)

  def remove_stream(%__MODULE__{} = c, id) do
    %{
      c
      | streams: Map.delete(c.streams, id),
        committed: MapSet.delete(c.committed, id),
        pending_headers: Map.delete(c.pending_headers, id),
        priorities: Map.delete(c.priorities, id)
    }
  end

  def update_peer_settings(%__MODULE__{} = c, entries) do
    with :ok <- validate_peer_push(entries),
         {:ok, peer, effect} <- Settings.apply_peer(c.peer, entries),
         {:ok, streams} <- apply_initial_delta(c.streams, effect.initial_window_delta) do
      encoder = HPACK.set_max_dynamic_size(c.encoder, peer.values.header_table_size)

      {:ok,
       %{
         c
         | peer: peer,
           streams: streams,
           encoder: encoder,
           max_streams: peer.values.max_concurrent_streams
       }, [{:settings_ack, entries}]}
    end
  end

  defp validate_peer_push(entries) when is_list(entries) do
    if Enum.any?(entries, fn
         {key, 1} when key in [2, :enable_push] -> true
         _ -> false
       end),
       do: {:error, :protocol_error},
       else: :ok
  end

  defp validate_peer_push(_), do: :ok

  def update_local_settings(%__MODULE__{} = c, entries) do
    with {:ok, local} <- Settings.begin_local(c.local, entries),
         {:ok, payload} <- Settings.encode(entries) do
      {:ok, %{c | local: local}, [{:settings, payload}]}
    end
  end

  def acknowledge_settings(%__MODULE__{} = c) do
    with {:ok, local} <- Settings.ack(c.local) do
      decoder =
        HPACK.acknowledge_max_dynamic_size(c.decoder, local.acknowledged_values.header_table_size)

      {:ok, %{c | local: local, decoder: decoder}, []}
    end
  end

  def update_send_window(%__MODULE__{} = c, 0, increment),
    do: add_connection_window(c, :connection_send_window, increment)

  def update_send_window(%__MODULE__{} = c, id, increment) when increment > 0 do
    with {:ok, s} <- Map.fetch(c.streams, id),
         {:ok, s} <- StreamState.update_send_window(s, increment) do
      {:ok, put_stream(c, s), []}
    else
      :error -> {:error, :unknown_stream}
      error -> error
    end
  end

  def update_send_window(_, _, _), do: {:error, :invalid_window_update}

  def update_receive_window(%__MODULE__{} = c, 0, increment),
    do: add_connection_window(c, :connection_receive_window, increment)

  def update_receive_window(%__MODULE__{} = c, id, increment) when increment > 0 do
    with {:ok, s} <- Map.fetch(c.streams, id),
         {:ok, s} <- StreamState.update_receive_window(s, increment) do
      {:ok, put_stream(c, s), []}
    else
      :error -> {:error, :unknown_stream}
      error -> error
    end
  end

  def update_receive_window(_, _, _), do: {:error, :invalid_window_update}

  @doc "Consumes inbound DATA wire credit without replenishing it."
  def receive_data(c, id, bytes, end_stream? \\ false)

  def receive_data(%__MODULE__{} = c, id, bytes, end_stream?)
      when is_integer(bytes) and bytes >= 0 do
    with {:ok, stream} <- Map.fetch(c.streams, id),
         {:ok, stream} <- StreamState.receive_data(stream, bytes, end_stream?),
         :ok <-
           if(bytes <= c.connection_receive_window, do: :ok, else: {:error, :flow_control_error}) do
      connection = %{
        c
        | streams: Map.put(c.streams, id, stream),
          connection_receive_window: c.connection_receive_window - bytes
      }

      {:ok, %{connection | connection_unacknowledged: c.connection_unacknowledged + bytes}, []}
    else
      :error -> {:error, :unknown_stream}
      {:error, _} = error -> error
    end
  end

  def receive_data(_, _, _, _), do: {:error, :invalid_data_length}

  @doc "Restores receive credit after wire bytes have been consumed or safely buffered."
  def acknowledge_data(%__MODULE__{} = c, id, bytes)
      when is_integer(bytes) and bytes > 0 do
    with {:ok, stream} <- Map.fetch(c.streams, id),
         true <- bytes <= stream.unacknowledged and bytes <= c.connection_unacknowledged,
         {:ok, stream} <- StreamState.acknowledge_data(stream, bytes),
         true <- c.connection_receive_window + bytes <= @max_window do
      {:ok,
       %{
         c
         | streams: Map.put(c.streams, id, stream),
           connection_receive_window: c.connection_receive_window + bytes,
           connection_unacknowledged: c.connection_unacknowledged - bytes
       }, [{:window_update, 0, bytes}, {:window_update, id, bytes}]}
    else
      :error -> {:error, :unknown_stream}
      false -> {:error, :invalid_acknowledgement}
      {:error, _} = error -> error
    end
  end

  def acknowledge_data(_, _, _), do: {:error, :invalid_acknowledgement}

  def goaway(%__MODULE__{} = c, last_id) when is_integer(last_id) and last_id >= 0 do
    if c.goaway_last_stream_id && last_id > c.goaway_last_stream_id do
      {:error, :goaway_last_stream_id_increased}
    else
      {:ok, %{c | state: :draining, goaway_last_stream_id: last_id}, []}
    end
  end

  def receive_goaway(c, last_id), do: goaway(c, last_id)

  @doc "Commits a complete header block as one non-interleavable effect batch."
  def commit_headers(%__MODULE__{} = c, id, headers, opts \\ []) when is_list(headers) do
    requested_max = Keyword.get(opts, :max_frame_size, c.peer.values.max_frame_size)

    if is_integer(requested_max) and requested_max > 0 do
      commit_headers_with_max(
        c,
        id,
        headers,
        opts,
        min(requested_max, c.peer.values.max_frame_size)
      )
    else
      {:error, :invalid_frame_size}
    end
  end

  defp commit_headers_with_max(c, id, headers, opts, max_frame_size) do
    case Map.fetch(c.streams, id) do
      :error ->
        {:error, :unknown_stream}

      {:ok, _s} when is_map_key(c.committed, id) ->
        {:error, :headers_already_committed}

      {:ok, s} ->
        with {:ok, s} <- StreamState.send_headers(s, Keyword.get(opts, :end_stream, false)) do
          {encoder, block} = HPACK.encode_headers(c.encoder, headers, c.encoder_options)

          frames =
            header_frames(
              id,
              block,
              Keyword.get(opts, :end_stream, false),
              max_frame_size
            )

          priority_effects =
            case Keyword.get(opts, :priority, :none) do
              :legacy -> [{:priority, id, 0, 16, false}]
              _ -> []
            end

          c = %{
            c
            | streams: Map.put(c.streams, id, s),
              encoder: encoder,
              committed: MapSet.put(c.committed, id)
          }

          {:ok, c, priority_effects ++ [{:headers, id, frames}]}
        end
    end
  end

  def cancel_headers(%__MODULE__{} = c, id) do
    if MapSet.member?(c.committed, id),
      do: {:ok, c, [{:rst_stream, id, :cancel}]},
      else: {:ok, %{c | pending_headers: Map.delete(c.pending_headers, id)}, []}
  end

  @doc "Commits bounded request trailers using the connection encoder and closes the send half."
  def send_trailers(%__MODULE__{} = c, id, fields) do
    with {:ok, stream} <- Map.fetch(c.streams, id),
         true <- MapSet.member?(c.committed, id) || {:error, :headers_not_committed},
         {:ok, trailers} <- HTTP.Trailers.validate(fields),
         headers <-
           Enum.map(trailers.headers, fn {name, value} -> {String.downcase(name), value} end),
         :ok <- trailer_header_limit(c, headers),
         {:ok, stream} <- StreamState.send_data(stream, 0, true) do
      {encoder, block} = HPACK.encode_headers(c.encoder, headers, c.encoder_options)
      frames = header_frames(id, block, true, c.peer.values.max_frame_size)
      connection = %{c | encoder: encoder, streams: Map.put(c.streams, id, stream)}
      {:ok, connection, [{:headers, id, frames}]}
    else
      :error -> {:error, :unknown_stream}
      {:error, _} = error -> error
    end
  end

  defp trailer_header_limit(c, headers) do
    bytes =
      Enum.reduce(headers, 0, fn {name, value}, total ->
        total + byte_size(name) + byte_size(value) + 32
      end)

    if c.peer.values.max_header_list_size == :infinity or
         bytes <= c.peer.values.max_header_list_size,
       do: :ok,
       else: {:error, :trailers_too_large}
  end

  @doc """
  Consumes connection and stream send credit and returns one DATA effect.
  """
  def send_data(%__MODULE__{} = c, id, data, end_stream? \\ false)
      when is_binary(data) do
    with {:ok, stream} <- Map.fetch(c.streams, id),
         {:ok, stream} <- StreamState.send_data(stream, byte_size(data), end_stream?),
         :ok <-
           if(byte_size(data) <= c.connection_send_window,
             do: :ok,
             else: {:error, :flow_control_blocked}
           ) do
      frames =
        data
        |> chunk_binary(c.peer.values.max_frame_size)
        |> Enum.with_index()
        |> Enum.map(fn {chunk, index} ->
          final? = index == div(byte_size(data) - 1, c.peer.values.max_frame_size)
          Frame.encode(:data, if(end_stream? and final?, do: 0x1, else: 0), id, chunk)
        end)

      frames = if data == "" and end_stream?, do: [Frame.encode(:data, 0x1, id, "")], else: frames

      {:ok,
       %{
         c
         | streams: Map.put(c.streams, id, stream),
           connection_send_window: c.connection_send_window - byte_size(data)
       }, [{:data, id, frames}]}
    else
      :error -> {:error, :unknown_stream}
      {:error, _} = error -> error
    end
  end

  @doc "Sends at most the currently eligible DATA prefix and returns the remainder."
  def send_data_prefix(%__MODULE__{} = c, id, data, end_stream?, quantum)
      when is_binary(data) and is_boolean(end_stream?) and is_integer(quantum) and quantum > 0 do
    case Map.fetch(c.streams, id) do
      {:ok, stream} ->
        eligible =
          Enum.min([
            byte_size(data),
            max(c.connection_send_window, 0),
            max(stream.send_window, 0),
            c.peer.values.max_frame_size,
            quantum
          ])

        cond do
          data == "" and end_stream? ->
            with {:ok, next, effects} <- send_data(c, id, "", true),
                 do: {:ok, next, 0, "", effects}

          eligible == 0 ->
            {:error, :flow_control_blocked}

          true ->
            <<prefix::binary-size(^eligible), remainder::binary>> = data

            with {:ok, next, effects} <-
                   send_data(c, id, prefix, end_stream? and remainder == ""),
                 do: {:ok, next, eligible, remainder, effects}
        end

      :error ->
        {:error, :unknown_stream}
    end
  end

  def send_data_prefix(_, _, _, _, _), do: {:error, :invalid_data_length}

  def handle_priority(c, id, dependency, weight, exclusive \\ false)

  def handle_priority(%__MODULE__{} = c, id, dependency, weight, exclusive)
      when id > 0 and dependency >= 0 and dependency != id and weight in 1..256 and
             is_boolean(exclusive) do
    {:ok,
     %{
       c
       | priorities:
           Map.put(c.priorities, id, %{
             dependency: dependency,
             weight: weight,
             exclusive: exclusive
           })
     }, []}
  end

  def handle_priority(_, _, _, _, _), do: {:error, :invalid_priority}

  def priority_update(%__MODULE__{} = c, frame_stream_id, target_stream_id, value)
      when frame_stream_id == 0 and target_stream_id > 0 and is_binary(value) and
             byte_size(value) in 1..256 do
    case Map.get(c.streams, target_stream_id) do
      %StreamState{state: state} when state != :closed ->
        {:ok,
         %{
           c
           | priorities: Map.put(c.priorities, target_stream_id, %{value: value, rfc9218: true})
         }, []}

      _ ->
        {:ok, c, []}
    end
  end

  def priority_update(_, _, _, _), do: {:error, :invalid_priority_update}

  def reject_push(%__MODULE__{} = c, _stream_id, promised_id, block)
      when promised_id > 0 and is_binary(block) do
    cond do
      c.local.values.enable_push == 0 ->
        {:error, :protocol_error}

      byte_size(block) > 65_536 ->
        {:error, :header_block_too_large}

      true ->
        with {:ok, decoder, _headers} <- HPACK.decode(c.decoder, block) do
          {:ok, %{c | decoder: decoder, promised: MapSet.put(c.promised, promised_id)},
           [{:rst_stream, promised_id, :cancel}]}
        end
    end
  end

  def reject_push(_, _, _, _), do: {:error, :invalid_push_promise}

  defp header_frames(id, block, end_stream?, max) do
    chunks = chunk_binary(block, max)
    flags = 0x4 ||| if(end_stream?, do: 0x1, else: 0)

    case chunks do
      [one] ->
        [Frame.encode(:headers, flags, id, one)]

      [first | rest] ->
        [
          Frame.encode(:headers, if(end_stream?, do: 0x1, else: 0), id, first)
          | Enum.with_index(rest)
            |> Enum.map(fn {chunk, i} ->
              Frame.encode(:continuation, if(i == length(rest) - 1, do: 0x4, else: 0), id, chunk)
            end)
        ]

      [] ->
        [Frame.encode(:headers, flags, id, "")]
    end
  end

  defp chunk_binary(<<>>, _size), do: []

  defp chunk_binary(binary, size) when size > 0 do
    take = min(size, byte_size(binary))
    <<chunk::binary-size(^take), rest::binary>> = binary
    [chunk | chunk_binary(rest, size)]
  end

  defp apply_initial_delta(streams, delta) do
    Enum.reduce_while(streams, {:ok, %{}}, fn {id, s}, {:ok, acc} ->
      value = s.send_window + delta

      if value > @max_window,
        do: {:halt, {:error, :flow_control_error}},
        else: {:cont, {:ok, Map.put(acc, id, %{s | send_window: value})}}
    end)
  end

  defp add_connection_window(c, key, increment) when is_integer(increment) and increment > 0 do
    value = Map.fetch!(c, key)

    if value + increment > @max_window,
      do: {:error, :flow_control_error},
      else: {:ok, Map.put(c, key, value + increment), []}
  end

  defp add_connection_window(_, _, _), do: {:error, :invalid_window_update}
end

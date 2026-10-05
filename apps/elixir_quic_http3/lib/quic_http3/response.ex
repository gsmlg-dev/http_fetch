defmodule QuicHttp3.Response do
  @moduledoc """
  Bounded incremental HTTP/3 response message decoder for the static QPACK profile.

  DATA and unknown extension payloads are consumed without buffering a complete
  frame. HEADERS have independent encoded, decoded and field-count limits.
  Protocol errors carry their stream/connection scope and application error code.
  """
  alias QuicHttp3.{Qpack, Varint}

  defstruct phase: :initial,
            method: :get,
            status: nil,
            content_length: nil,
            received: 0,
            prefix: <<>>,
            frame: nil,
            max_encoded_headers: 65_536,
            max_header_bytes: 65_536,
            max_fields: 128

  def new(opts \\ []), do: struct!(__MODULE__, opts)

  def retained_bytes(state) do
    byte_size(state.prefix) +
      case state.frame do
        {1, _remaining, bytes} -> byte_size(bytes)
        _ -> 0
      end
  end

  def feed(%__MODULE__{phase: :done} = state, <<>>), do: {:ok, state, []}
  def feed(%__MODULE__{phase: :done}, _), do: message_error(:data_after_fin)
  def feed(%__MODULE__{} = state, bytes) when is_binary(bytes), do: parse(state, bytes, [])

  def finish(%__MODULE__{phase: :done} = state), do: {:ok, state, []}

  def finish(%__MODULE__{} = state) do
    cond do
      state.frame != nil or state.prefix != <<>> ->
        connection_error(0x106, :truncated_frame)

      state.phase == :initial ->
        message_error(:missing_final_headers)

      state.content_length != nil and not bodyless?(state) and
          state.received != state.content_length ->
        message_error(:content_length_mismatch)

      true ->
        {:ok, %{state | phase: :done}, [:done]}
    end
  end

  defp parse(%{frame: nil} = state, bytes, events) do
    data = state.prefix <> bytes

    with {:ok, type, tail} <- Varint.decode(data),
         {:ok, length, payload} <- Varint.decode(tail),
         :ok <- validate_frame(state, type, length) do
      parse(%{state | prefix: <<>>, frame: {type, length, <<>>}}, payload, events)
    else
      :more -> {:ok, %{state | prefix: :binary.copy(data)}, Enum.reverse(events)}
      {:error, _} = error -> error
    end
  end

  defp parse(%{frame: {type, 0, bytes}} = state, data, events) do
    case complete_frame(state, type, bytes) do
      {:ok, next, emitted} -> parse(%{next | frame: nil}, data, Enum.reverse(emitted, events))
      {:error, _} = error -> error
    end
  end

  defp parse(state, <<>>, events), do: {:ok, state, Enum.reverse(events)}

  defp parse(%{frame: {type, remaining, buffered}} = state, data, events) do
    size = min(remaining, byte_size(data))
    <<chunk::binary-size(^size), rest::binary>> = data
    next = %{state | frame: {type, remaining - size, buffered}}

    case type do
      0 ->
        with :ok <- validate_data(state, size) do
          next = %{next | received: state.received + size}
          emitted = if size == 0, do: events, else: [{:data, :binary.copy(chunk)} | events]
          parse(next, rest, emitted)
        end

      1 ->
        parse(%{next | frame: {type, remaining - size, buffered <> chunk}}, rest, events)

      _ ->
        parse(next, rest, events)
    end
  end

  defp validate_frame(_state, type, _length) when type in [2, 3, 4, 6, 7, 8, 9, 13],
    do: connection_error(0x105, :forbidden_response_frame)

  # This client never advertises MAX_PUSH_ID in the initial request profile.
  defp validate_frame(_state, 5, _length), do: connection_error(0x108, :push_not_permitted)

  defp validate_frame(%{phase: :initial}, 0, _),
    do: connection_error(0x105, :data_before_final_headers)

  defp validate_frame(%{phase: :trailers}, 0, _),
    do: connection_error(0x105, :data_after_trailers)

  defp validate_frame(%{phase: :trailers}, 1, _),
    do: connection_error(0x105, :headers_after_trailers)

  defp validate_frame(state, 1, length) when length > state.max_encoded_headers,
    do: stream_error(0x107, :encoded_headers_too_large)

  defp validate_frame(_state, _type, _length), do: :ok

  defp complete_frame(state, 1, bytes) do
    case Qpack.decode_header_block(bytes, max_fields: state.max_fields) do
      {:ok, fields} ->
        with :ok <- decoded_budget(state, fields),
             :ok <- validate_fields(fields) do
          receive_headers(state, fields)
        end

      :more ->
        connection_error(0x200, :malformed_qpack)

      {:error, :field_limit} ->
        stream_error(0x107, :too_many_fields)

      {:error, :invalid_fields} ->
        message_error(:invalid_header_name)

      {:error, reason} ->
        connection_error(0x200, reason)
    end
  end

  defp complete_frame(state, _type, _bytes), do: {:ok, state, []}

  defp decoded_budget(state, fields) do
    size =
      Enum.reduce(fields, 0, fn {name, value}, total ->
        total + byte_size(name) + byte_size(value) + 32
      end)

    if size <= state.max_header_bytes,
      do: :ok,
      else: stream_error(0x107, :decoded_headers_too_large)
  end

  defp validate_fields(fields) do
    Enum.reduce_while(fields, :pseudo, fn {name, value}, phase ->
      cond do
        name in [
          "connection",
          "proxy-connection",
          "keep-alive",
          "transfer-encoding",
          "upgrade",
          "te"
        ] ->
          {:halt, message_error(:forbidden_header)}

        invalid_value?(value) ->
          {:halt, message_error(:invalid_header_value)}

        String.starts_with?(name, ":") and phase == :regular ->
          {:halt, message_error(:pseudo_header_order)}

        String.starts_with?(name, ":") ->
          {:cont, phase}

        true ->
          {:cont, :regular}
      end
    end)
    |> case do
      phase when phase in [:pseudo, :regular] -> :ok
      error -> error
    end
  end

  defp invalid_value?(<<>>), do: false

  defp invalid_value?(value) do
    :binary.first(value) in [9, 32] or :binary.last(value) in [9, 32] or
      Enum.any?(:binary.bin_to_list(value), &((&1 < 32 and &1 != 9) or &1 == 127))
  end

  defp receive_headers(%{phase: :initial} = state, fields) do
    {pseudo, regular} =
      Enum.split_with(fields, fn {name, _} -> String.starts_with?(name, ":") end)

    case pseudo do
      [{":status", <<a, b, c>>}] when a in ?1..?5 and b in ?0..?9 and c in ?0..?9 ->
        status = (a - ?0) * 100 + (b - ?0) * 10 + c - ?0
        receive_status(state, status, regular)

      _ ->
        message_error(:invalid_response_status)
    end
  end

  defp receive_headers(%{phase: :final} = state, fields) do
    if Enum.any?(fields, fn {name, _} ->
         String.starts_with?(name, ":") or name == "content-length"
       end),
       do: message_error(:invalid_trailers),
       else: {:ok, %{state | phase: :trailers}, [{:trailers, fields}]}
  end

  defp receive_status(_state, 101, _fields), do: message_error(:invalid_response_status)

  defp receive_status(state, status, fields) when status < 200 do
    if Enum.any?(fields, &(elem(&1, 0) == "content-length")),
      do: message_error(:content_length_forbidden),
      else: {:ok, state, [{:informational, status, fields}]}
  end

  defp receive_status(state, status, fields) do
    with {:ok, length} <- content_length(fields),
         :ok <- validate_length_status(status, length) do
      {:ok, %{state | phase: :final, status: status, content_length: length},
       [{:headers, status, fields}]}
    end
  end

  defp content_length(fields) do
    fields
    |> Enum.filter(&(elem(&1, 0) == "content-length"))
    |> Enum.flat_map(fn {_, value} -> String.split(value, ",") end)
    |> Enum.map(&String.trim/1)
    |> Enum.reduce_while({:ok, nil}, fn value, {:ok, previous} ->
      case Integer.parse(value) do
        {length, ""} when length >= 0 ->
          if String.match?(value, ~r/\A[0-9]+\z/) and (previous == nil or previous == length),
            do: {:cont, {:ok, length}},
            else: {:halt, message_error(:invalid_content_length)}

        _ ->
          {:halt, message_error(:invalid_content_length)}
      end
    end)
  end

  defp validate_length_status(204, length) when length != nil,
    do: message_error(:content_length_forbidden)

  defp validate_length_status(_, _), do: :ok
  defp bodyless?(state), do: state.method in [:head, "HEAD"] or state.status in [204, 205, 304]

  defp validate_data(state, size) do
    cond do
      size > 0 and bodyless?(state) ->
        message_error(:body_forbidden)

      state.content_length != nil and state.received + size > state.content_length ->
        message_error(:content_length_mismatch)

      true ->
        :ok
    end
  end

  defp message_error(reason), do: stream_error(0x10E, reason)
  defp stream_error(code, reason), do: {:error, {:http3_error, :stream, code, reason}}
  defp connection_error(code, reason), do: {:error, {:http3_error, :connection, code, reason}}
end

defmodule HTTP.HTTP2.StreamState do
  @moduledoc "Pure lifecycle and two-sided flow-control state for one stream."
  @max_window 2_147_483_647
  defstruct id: nil,
            state: :idle,
            send_window: 65_535,
            receive_window: 65_535,
            unacknowledged: 0,
            headers?: false,
            request_headers_sent?: false,
            response_phase: :awaiting_final,
            response_status: nil,
            request_method: nil,
            expected_content_length: nil,
            received_body_bytes: 0,
            end_stream_sent?: false,
            end_stream_received?: false,
            request_ref: nil,
            metadata: %{}

  @type t :: %__MODULE__{}

  def new(id, opts \\ []) when is_integer(id) and id > 0 do
    %__MODULE__{
      id: id,
      send_window: Keyword.get(opts, :send_window, 65_535),
      receive_window: Keyword.get(opts, :receive_window, 65_535),
      request_ref: Keyword.get(opts, :request_ref),
      request_method: Keyword.get(opts, :request_method)
    }
  end

  def open(%__MODULE__{state: :idle} = s), do: {:ok, %{s | state: :open}}
  def open(_), do: {:error, :invalid_stream_transition}

  def send_headers(%__MODULE__{} = s, end_stream? \\ false) do
    with :ok <- can_send_headers(s),
         do:
           {:ok,
            transition_local(%{s | headers?: true, request_headers_sent?: true}, end_stream?)}
  end

  def receive_headers(%__MODULE__{} = s, end_stream? \\ false) do
    with :ok <- can_receive_headers(s),
         do: {:ok, transition_remote(%{s | headers?: true}, end_stream?)}
  end

  def send_data(s, bytes, end_stream? \\ false)

  def send_data(%__MODULE__{} = s, bytes, end_stream?) when is_integer(bytes) and bytes >= 0 do
    cond do
      s.state not in [:open, :half_closed_remote] -> {:error, :stream_closed}
      bytes > 0 and bytes > s.send_window -> {:error, :flow_control_blocked}
      true -> {:ok, transition_local(%{s | send_window: s.send_window - bytes}, end_stream?)}
    end
  end

  def send_data(_, _, _), do: {:error, :invalid_data_length}
  def receive_data(s, bytes, end_stream? \\ false)

  def receive_data(%__MODULE__{} = s, bytes, end_stream?) when is_integer(bytes) and bytes >= 0 do
    cond do
      s.state not in [:open, :half_closed_local] ->
        {:error, :stream_closed}

      s.receive_window < 0 or bytes > s.receive_window ->
        {:error, :flow_control_error}

      true ->
        {:ok,
         transition_remote(
           %{
             s
             | receive_window: s.receive_window - bytes,
               unacknowledged: s.unacknowledged + bytes
           },
           end_stream?
         )}
    end
  end

  def receive_data(_, _, _), do: {:error, :invalid_data_length}

  def acknowledge_data(%__MODULE__{} = s, bytes)
      when is_integer(bytes) and bytes > 0 and bytes <= s.unacknowledged do
    with {:ok, s} <- update_receive_window(s, bytes),
         do: {:ok, %{s | unacknowledged: s.unacknowledged - bytes}}
  end

  def acknowledge_data(_, _), do: {:error, :invalid_acknowledgement}

  @doc "Validates an inbound response header block and advances its phase."
  def receive_response_headers(%__MODULE__{} = s, headers, end_stream?)
      when is_list(headers) and is_boolean(end_stream?) do
    with :ok <- validate_header_fields(headers) do
      case s.response_phase do
        :awaiting_final -> receive_initial_response_headers(s, headers, end_stream?)
        :body -> receive_trailers(s, headers, end_stream?)
        _ -> {:error, :invalid_headers_transition}
      end
    end
  end

  def receive_response_headers(_, _, _), do: {:error, :invalid_response_headers}

  @doc "Tracks application DATA bytes independently of flow-control wire bytes."
  def receive_response_data(%__MODULE__{response_phase: :body} = s, bytes, end_stream?)
      when is_integer(bytes) and bytes >= 0 and is_boolean(end_stream?) do
    total = s.received_body_bytes + bytes

    cond do
      body_forbidden?(s) and bytes > 0 ->
        {:error, :body_forbidden}

      not body_forbidden?(s) and s.expected_content_length != nil and
          total > s.expected_content_length ->
        {:error, :content_length_mismatch}

      end_stream? and not body_forbidden?(s) and s.expected_content_length != nil and
          total != s.expected_content_length ->
        {:error, :content_length_mismatch}

      true ->
        {:ok,
         %{
           s
           | received_body_bytes: total,
             response_phase: if(end_stream?, do: :complete, else: :body)
         }}
    end
  end

  def receive_response_data(_, _, _), do: {:error, :invalid_data_transition}

  def rst(%__MODULE__{} = s, _code), do: {:ok, %{s | state: :closed}}
  def close(%__MODULE__{} = s), do: %{s | state: :closed}

  def update_send_window(%__MODULE__{} = s, increment) when increment > 0,
    do: add_window(s, :send_window, increment)

  def update_send_window(_, _), do: {:error, :invalid_window_update_increment}

  def update_receive_window(%__MODULE__{} = s, increment) when increment > 0,
    do: add_window(s, :receive_window, increment)

  def update_receive_window(_, _), do: {:error, :invalid_window_update_increment}

  def sendable?(%__MODULE__{state: state, send_window: window}),
    do: state in [:open, :half_closed_remote] and window > 0

  def closed?(%__MODULE__{state: :closed}), do: true
  def closed?(_), do: false

  defp receive_initial_response_headers(s, headers, end_stream?) do
    with {:ok, status} <- parse_response_status(headers),
         {:ok, content_length} <- parse_content_length(headers) do
      cond do
        (status < 200 or status == 204) and content_length != nil ->
          {:error, :invalid_content_length}

        status < 200 and end_stream? ->
          {:error, :invalid_response_headers}

        status < 200 ->
          {:ok, s, :informational}

        end_stream? and content_length != nil and content_length != 0 and
            not body_forbidden?(%{s | response_status: status}) ->
          {:error, :content_length_mismatch}

        true ->
          phase = if(end_stream?, do: :complete, else: :body)

          {:ok,
           s
           |> Map.merge(%{
             headers?: true,
             response_phase: phase,
             response_status: status,
             expected_content_length: content_length
           })
           |> transition_remote(end_stream?), :final}
      end
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_response_status(headers) do
    statuses = for {":status", value} <- headers, do: value

    with [status_text] <- statuses,
         true <-
           byte_size(status_text) == 3 and
             Enum.all?(:binary.bin_to_list(status_text), &(&1 in ?0..?9)),
         {status, ""} <- Integer.parse(status_text),
         true <- status in 100..599 and status != 101,
         true <- hd(headers) == {":status", status_text},
         true <-
           Enum.all?(headers, fn {name, _} ->
             name == ":status" or not String.starts_with?(name, ":")
           end) do
      {:ok, status}
    else
      _ -> {:error, :invalid_response_headers}
    end
  end

  defp receive_trailers(s, headers, true) do
    if Enum.any?(headers, fn {name, _} ->
         String.starts_with?(name, ":") or name == "content-length"
       end) do
      {:error, :invalid_response_trailers}
    else
      if not body_forbidden?(s) and s.expected_content_length != nil and
           s.received_body_bytes != s.expected_content_length do
        {:error, :content_length_mismatch}
      else
        {:ok, s |> Map.put(:response_phase, :complete) |> transition_remote(true), :trailers}
      end
    end
  end

  defp receive_trailers(_, _, false), do: {:error, :invalid_headers_transition}

  defp validate_header_fields(headers) do
    if Enum.all?(headers, fn
         {name, value} when is_binary(name) and is_binary(value) ->
           name != "" and valid_header_name?(name) and
             name not in [
               "connection",
               "keep-alive",
               "proxy-connection",
               "transfer-encoding",
               "upgrade"
             ] and
             (name != "te" or value == "trailers") and
             not Enum.any?(:binary.bin_to_list(value), &(&1 in [0, 10, 13])) and
             (value == "" or
                (:binary.first(value) not in [9, 32] and :binary.last(value) not in [9, 32]))

         _ ->
           false
       end),
       do: :ok,
       else: {:error, :invalid_response_headers}
  end

  defp valid_header_name?(<<":", rest::binary>>), do: valid_header_name?(rest)

  defp valid_header_name?(name) do
    name != "" and
      Enum.all?(:binary.bin_to_list(name), fn char ->
        char in ?a..?z or char in ?0..?9 or char in ~c"!#$%&'*+-.^_`|~"
      end)
  end

  defp parse_content_length(headers) do
    values = for {"content-length", value} <- headers, do: value

    case values do
      [] ->
        {:ok, nil}

      [value] ->
        if value != "" and byte_size(value) <= 20 and
             Enum.all?(:binary.bin_to_list(value), &(&1 in ?0..?9)) do
          length = String.to_integer(value)

          if length <= 18_446_744_073_709_551_615,
            do: {:ok, length},
            else: {:error, :invalid_content_length}
        else
          {:error, :invalid_content_length}
        end

      _ ->
        {:error, :invalid_content_length}
    end
  end

  defp body_forbidden?(s), do: s.response_status in [204, 304] or s.request_method == :head

  defp can_send_headers(%__MODULE__{state: state, headers?: false})
       when state in [:idle, :open, :half_closed_remote],
       do: :ok

  defp can_send_headers(_), do: {:error, :invalid_headers_transition}

  defp can_receive_headers(%__MODULE__{state: state, headers?: false})
       when state in [:idle, :open, :half_closed_local],
       do: :ok

  defp can_receive_headers(_), do: {:error, :invalid_headers_transition}

  defp transition_local(s, false),
    do: %{s | state: if(s.state == :idle, do: :open, else: s.state)}

  defp transition_local(s, true),
    do: %{
      s
      | state: if(s.state == :half_closed_remote, do: :closed, else: :half_closed_local),
        end_stream_sent?: true
    }

  defp transition_remote(s, false),
    do: %{s | state: if(s.state == :idle, do: :open, else: s.state)}

  defp transition_remote(s, true),
    do: %{
      s
      | state: if(s.state == :half_closed_local, do: :closed, else: :half_closed_remote),
        end_stream_received?: true
    }

  defp add_window(s, key, increment) do
    value = Map.fetch!(s, key)

    if value + increment > @max_window,
      do: {:error, :flow_control_error},
      else: {:ok, Map.put(s, key, value + increment)}
  end
end

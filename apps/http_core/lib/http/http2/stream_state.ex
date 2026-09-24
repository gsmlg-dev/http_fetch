defmodule HTTP.HTTP2.StreamState do
  @moduledoc "Pure lifecycle and two-sided flow-control state for one stream."
  @max_window 2_147_483_647
  defstruct id: nil,
            state: :idle,
            send_window: 65_535,
            receive_window: 65_535,
            headers?: false,
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
      request_ref: Keyword.get(opts, :request_ref)
    }
  end

  def open(%__MODULE__{state: :idle} = s), do: {:ok, %{s | state: :open}}
  def open(_), do: {:error, :invalid_stream_transition}

  def send_headers(%__MODULE__{} = s, end_stream? \\ false) do
    with :ok <- can_send_headers(s),
         do: {:ok, transition_local(%{s | headers?: true}, end_stream?)}
  end

  def receive_headers(%__MODULE__{} = s, end_stream? \\ false) do
    with :ok <- can_receive_headers(s),
         do: {:ok, transition_remote(%{s | headers?: true}, end_stream?)}
  end

  def send_data(s, bytes, end_stream? \\ false)

  def send_data(%__MODULE__{} = s, bytes, end_stream?) when is_integer(bytes) and bytes >= 0 do
    cond do
      s.state not in [:open, :half_closed_remote] -> {:error, :stream_closed}
      s.send_window <= 0 or bytes > s.send_window -> {:error, :flow_control_blocked}
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
        {:ok, transition_remote(%{s | receive_window: s.receive_window - bytes}, end_stream?)}
    end
  end

  def receive_data(_, _, _), do: {:error, :invalid_data_length}

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

  defp can_send_headers(%__MODULE__{state: state, headers?: false})
       when state in [:idle, :open, :half_closed_remote], do: :ok

  defp can_send_headers(_), do: {:error, :invalid_headers_transition}

  defp can_receive_headers(%__MODULE__{state: state, headers?: false})
       when state in [:idle, :open, :half_closed_local], do: :ok

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

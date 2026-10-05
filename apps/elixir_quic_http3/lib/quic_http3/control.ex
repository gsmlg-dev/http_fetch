defmodule QuicHttp3.Control do
  @moduledoc """
  HTTP/3 control-stream state and SETTINGS handling.

  The state machine is transport-agnostic. Callers provide received stream
  bytes and send the returned encoded bytes through `QuicHttp3.Transport`.
  """

  alias QuicHttp3.{Frame, Settings, Stream}

  @default_settings [
    {1, 0},
    {6, 65_536},
    {7, 0}
  ]

  defstruct role: :client,
            local_settings: [],
            peer_settings: nil,
            buffer: <<>>,
            control_stream_id: nil,
            peer_control_stream_id: nil,
            peer_type_buffer: <<>>,
            local_open?: false,
            peer_open?: false,
            received_settings?: false,
            goaway_id: nil

  @type t :: %__MODULE__{
          role: :client | :server,
          local_settings: [Settings.setting()],
          peer_settings: [Settings.setting()] | nil,
          buffer: binary(),
          control_stream_id: non_neg_integer() | nil,
          peer_control_stream_id: term() | nil,
          peer_type_buffer: binary(),
          local_open?: boolean(),
          peer_open?: boolean(),
          received_settings?: boolean(),
          goaway_id: non_neg_integer() | nil
        }

  @type event :: {:settings, [Settings.setting()]} | {:goaway, non_neg_integer()}

  @spec new(:client | :server) :: {:ok, t()} | {:error, term()}
  @spec new(:client | :server, Settings.settings()) :: {:ok, t()} | {:error, term()}
  def new(role, settings \\ @default_settings)

  def new(role, settings) when role in [:client, :server] do
    with {:ok, normalized} <- Settings.normalize(settings),
         :ok <- Settings.validate(normalized) do
      {:ok, %__MODULE__{role: role, local_settings: normalized}}
    end
  end

  def new(_role, _settings), do: {:error, :invalid_role}

  @spec open(t(), non_neg_integer()) :: {:ok, t(), binary()} | {:error, term()}
  def open(%__MODULE__{local_open?: true}, _stream_id),
    do: {:error, :control_stream_already_open}

  def open(%__MODULE__{} = state, stream_id) do
    with {:ok, :unidirectional} <- Stream.classify(stream_id, state.role),
         true <- Stream.local?(stream_id, state.role) do
      payload = Settings.encode!(state.local_settings)
      frame = Frame.encode!(:settings, payload)

      {:ok, %{state | control_stream_id: stream_id, local_open?: true},
       encode_type(:control) <> frame}
    else
      {:ok, _other} -> {:error, :invalid_control_stream_type}
      false -> {:error, :control_stream_must_be_local}
      {:error, _reason} = error -> error
    end
  end

  @doc "Return the local control stream type and SETTINGS bytes without stream-id validation."
  @spec local_payload(t()) :: binary()
  def local_payload(%__MODULE__{} = state) do
    encode_type(:control) <> Frame.encode!(:settings, Settings.encode!(state.local_settings))
  end

  @spec receive(t(), non_neg_integer(), binary()) :: {:ok, t(), [event()]} | {:error, term()}
  def receive(%__MODULE__{} = state, stream_id, bytes) when is_binary(bytes) do
    with :ok <- validate_peer_stream(state, stream_id),
         {:ok, state, payload} <- open_peer_stream(state, stream_id, bytes) do
      parse_frames(%{state | buffer: state.buffer <> payload}, [])
    end
  end

  def receive(_state, _stream_id, _bytes), do: {:error, :invalid_control_stream_data}

  @doc "Receive bytes from an opaque peer control-stream handle."
  @spec receive_peer(t(), term(), binary()) :: {:ok, t(), [event()]} | {:error, term()}
  def receive_peer(%__MODULE__{} = state, stream_key, bytes) when is_binary(bytes) do
    with :ok <- validate_peer_key(state, stream_key),
         {:ok, state, payload} <- open_peer_stream_key(state, stream_key, bytes) do
      parse_frames(%{state | buffer: state.buffer <> payload}, [])
    end
  end

  def receive_peer(_state, _stream_key, _bytes), do: {:error, :invalid_control_stream_data}

  defp validate_peer_stream(%__MODULE__{role: role}, stream_id) do
    case Stream.classify(stream_id, role) do
      {:ok, :unidirectional} ->
        if Stream.local?(stream_id, role),
          do: {:error, :control_stream_must_be_peer_owned},
          else: :ok

      {:ok, _kind} ->
        {:error, :control_stream_must_be_unidirectional}

      {:error, _reason} = error ->
        error
    end
  end

  defp validate_peer_key(
         %__MODULE__{peer_open?: true, peer_control_stream_id: stream_key},
         stream_key
       ),
       do: :ok

  defp validate_peer_key(%__MODULE__{peer_open?: true}, _stream_key),
    do: {:error, :duplicate_peer_control_stream}

  defp validate_peer_key(
         %__MODULE__{peer_open?: false, peer_control_stream_id: existing},
         stream_key
       )
       when not is_nil(existing) and existing != stream_key,
       do: {:error, :duplicate_peer_control_stream}

  defp validate_peer_key(%__MODULE__{}, stream_key) do
    if is_nil(stream_key), do: {:error, :invalid_peer_control_stream}, else: :ok
  end

  defp open_peer_stream_key(
         %__MODULE__{peer_open?: true, peer_control_stream_id: stream_key} = state,
         stream_key,
         bytes
       ),
       do: {:ok, state, bytes}

  defp open_peer_stream_key(%__MODULE__{} = state, stream_key, bytes) do
    data = state.peer_type_buffer <> bytes

    case Stream.decode_type(data) do
      {:ok, :control, rest} ->
        {:ok,
         %{
           state
           | peer_open?: true,
             peer_control_stream_id: stream_key,
             peer_type_buffer: <<>>
         }, rest}

      {:ok, _type, _rest} ->
        {:error, :invalid_peer_control_stream_type}

      :more ->
        {:ok, %{state | peer_control_stream_id: stream_key, peer_type_buffer: data}, <<>>}
    end
  end

  defp open_peer_stream(
         %__MODULE__{peer_open?: true, peer_control_stream_id: stream_id} = state,
         stream_id,
         bytes
       ),
       do: {:ok, state, bytes}

  defp open_peer_stream(%__MODULE__{peer_open?: true}, _stream_id, _bytes),
    do: {:error, :duplicate_peer_control_stream}

  defp open_peer_stream(%__MODULE__{peer_control_stream_id: existing}, stream_id, _bytes)
       when is_integer(existing) and existing != stream_id,
       do: {:error, :duplicate_peer_control_stream}

  defp open_peer_stream(%__MODULE__{} = state, stream_id, bytes) do
    data = state.peer_type_buffer <> bytes

    case Stream.decode_type(data) do
      {:ok, :control, rest} ->
        {:ok,
         %{
           state
           | peer_open?: true,
             peer_control_stream_id: stream_id,
             peer_type_buffer: <<>>
         }, rest}

      {:ok, _type, _rest} ->
        {:error, :invalid_peer_control_stream_type}

      :more ->
        {:ok, %{state | peer_control_stream_id: stream_id, peer_type_buffer: data}, <<>>}
    end
  end

  defp parse_frames(%__MODULE__{buffer: buffer} = state, events) do
    case bounded_frame(buffer) do
      :more ->
        {:ok, state, Enum.reverse(events)}

      {:ok, frame, rest} ->
        case handle_frame(state, frame) do
          {:ok, next, event} -> parse_frames(%{next | buffer: rest}, add_event(events, event))
          {:error, _reason} = error -> error
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp bounded_frame(buffer) do
    with {:ok, _type, rest} <- QuicHttp3.Varint.decode(buffer),
         {:ok, length, _payload} <- QuicHttp3.Varint.decode(rest) do
      if length > 65_536, do: {:error, :control_frame_too_large}, else: Frame.decode(buffer)
    end
  end

  defp handle_frame(%__MODULE__{received_settings?: false}, %{type: type})
       when type != 4,
       do: {:error, :settings_must_be_first}

  defp handle_frame(%__MODULE__{received_settings?: false} = state, %{type: 4, payload: payload}) do
    with {:ok, settings} <- Settings.decode(payload),
         :ok <- Settings.validate(settings) do
      {:ok, %{state | received_settings?: true, peer_settings: settings}, {:settings, settings}}
    end
  end

  defp handle_frame(%__MODULE__{received_settings?: true}, %{type: 4}),
    do: {:error, :duplicate_settings}

  defp handle_frame(%__MODULE__{} = state, %{type: 7, payload: payload}) do
    case QuicHttp3.Varint.decode(payload) do
      {:ok, id, <<>>} ->
        cond do
          state.role == :client and rem(id, 4) != 0 -> {:error, :invalid_goaway}
          state.goaway_id != nil and id > state.goaway_id -> {:error, :increasing_goaway}
          true -> {:ok, %{state | goaway_id: id}, {:goaway, id}}
        end

      _ ->
        {:error, :invalid_goaway}
    end
  end

  defp handle_frame(%__MODULE__{}, %{type: type}) when type in [0, 1, 2, 5, 6, 8, 9],
    do: {:error, :forbidden_control_frame}

  defp handle_frame(%__MODULE__{role: :client}, %{type: 13}),
    do: {:error, {:http3_error, :connection, 0x105, :forbidden_control_frame}}

  defp handle_frame(%__MODULE__{role: :client}, %{type: 3}),
    do: {:error, {:http3_error, :connection, 0x108, :push_not_permitted}}

  defp handle_frame(state, _frame), do: {:ok, state, nil}

  defp add_event(events, nil), do: events
  defp add_event(events, event), do: [event | events]

  defp encode_type(type), do: QuicHttp3.Varint.encode!(Stream.type_id(type))
end

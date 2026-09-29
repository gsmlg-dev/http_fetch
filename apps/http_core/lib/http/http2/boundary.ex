defmodule HTTP.HTTP2.Boundary do
  @moduledoc false
  alias HTTP.HTTP2.Frame

  def decode(<<length::24, _::binary>>, maximum) when length > maximum,
    do: {:error, :frame_size_error}

  def decode(bytes, _maximum), do: Frame.decode(bytes)

  def validate(frame, peer_settings?, continuation) do
    cond do
      continuation != nil and
          (frame.type != :continuation or frame.stream_id != continuation) ->
        {:error, :expected_continuation}

      not peer_settings? and
          (frame.type != :settings or Frame.flag?(frame.flags, 1)) ->
        {:error, :expected_settings}

      frame.type in [:settings, :ping, :goaway] and frame.stream_id != 0 ->
        {:error, :protocol_error}

      frame.type in [:data, :headers, :priority, :rst_stream, :push_promise, :continuation] and
          frame.stream_id == 0 ->
        {:error, :protocol_error}

      true ->
        validate_length(frame)
    end
  end

  def data_payload(frame) do
    with {:ok, payload} <- unpad(frame.payload, frame.flags) do
      {:ok, payload, byte_size(frame.payload)}
    end
  end

  def header_payload(frame) do
    with {:ok, payload} <- unpad(frame.payload, frame.flags) do
      if Frame.flag?(frame.flags, 0x20) do
        case payload do
          <<_exclusive::1, dependency::31, _weight, block::binary>>
          when dependency != frame.stream_id ->
            {:ok, block}

          _ ->
            {:error, :protocol_error}
        end
      else
        {:ok, payload}
      end
    end
  end

  defp validate_length(%{type: type, payload: payload} = frame) do
    size = byte_size(payload)

    invalid? =
      case type do
        :ping -> size != 8
        :priority -> size != 5
        :rst_stream -> size != 4
        :window_update -> size != 4
        :goaway -> size < 8
        :settings -> rem(size, 6) != 0 or (Frame.flag?(frame.flags, 1) and size != 0)
        _ -> false
      end

    if invalid?, do: {:error, :frame_size_error}, else: :ok
  end

  defp unpad(payload, flags) do
    if Frame.flag?(flags, 8) do
      case payload do
        <<padding, rest::binary>> when padding <= byte_size(rest) ->
          {:ok, binary_part(rest, 0, byte_size(rest) - padding)}

        _ ->
          {:error, :protocol_error}
      end
    else
      {:ok, payload}
    end
  end
end

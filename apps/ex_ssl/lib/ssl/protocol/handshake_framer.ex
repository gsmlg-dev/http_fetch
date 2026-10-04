defmodule SSL.Protocol.HandshakeFramer do
  @moduledoc """
  Frames complete TLS handshake messages from an arbitrarily chunked byte stream.

  Incomplete data is retained as an opaque chunk accumulator so repeated small
  feeds do not rebuild the entire buffered message.
  """

  @default_max_handshake_length 1_048_576

  @opaque t :: %__MODULE__{
            chunks: [binary()],
            size: non_neg_integer(),
            frame_size: pos_integer() | nil
          }

  defstruct chunks: [], size: 0, frame_size: nil

  @spec new() :: t()
  def new, do: %__MODULE__{}

  @spec feed(t() | binary(), binary(), keyword()) ::
          {:ok, [binary()], t()} | {:error, term()}
  def feed(buffer, bytes, opts \\ []) when is_binary(bytes) do
    with {:ok, max_length} <- configured_limit(opts) do
      buffer
      |> normalize_buffer()
      |> append(bytes)
      |> parse([], max_length)
    end
  end

  @spec buffered_size(t() | binary()) :: non_neg_integer()
  def buffered_size(%__MODULE__{size: size}), do: size
  def buffered_size(buffer) when is_binary(buffer), do: byte_size(buffer)

  @spec buffered_bytes(t() | binary()) :: binary()
  def buffered_bytes(%__MODULE__{chunks: chunks}) do
    chunks |> Enum.reverse() |> IO.iodata_to_binary()
  end

  def buffered_bytes(buffer) when is_binary(buffer), do: buffer

  defp configured_limit(opts) do
    case Keyword.fetch(opts, :max_handshake_length) do
      :error -> {:ok, @default_max_handshake_length}
      {:ok, limit} when is_integer(limit) and limit >= 0 -> {:ok, limit}
      {:ok, _limit} -> {:error, {:invalid_limit, :max_handshake_length}}
    end
  end

  defp normalize_buffer(%__MODULE__{} = buffer), do: buffer
  defp normalize_buffer(buffer) when is_binary(buffer), do: from_binary(buffer)

  defp append(buffer, <<>>), do: buffer

  defp append(%__MODULE__{} = buffer, bytes) do
    %{buffer | chunks: [bytes | buffer.chunks], size: buffer.size + byte_size(bytes)}
  end

  defp parse(%__MODULE__{frame_size: nil, size: size} = buffer, messages, _max_length)
       when size < 4 do
    {:ok, Enum.reverse(messages), buffer}
  end

  defp parse(%__MODULE__{frame_size: nil} = buffer, messages, max_length) do
    data = buffered_bytes(buffer)
    <<_type, length::24, _rest::binary>> = data

    if length > max_length do
      {:error, {:handshake_length_exceeded, length, max_length}}
    else
      parse(%{buffer | chunks: [data], frame_size: 4 + length}, messages, max_length)
    end
  end

  defp parse(%__MODULE__{size: size, frame_size: frame_size} = buffer, messages, _max_length)
       when size < frame_size do
    {:ok, Enum.reverse(messages), buffer}
  end

  defp parse(%__MODULE__{frame_size: frame_size} = buffer, messages, max_length) do
    data = buffered_bytes(buffer)
    <<message::binary-size(^frame_size), remainder::binary>> = data
    parse(from_binary(remainder), [message | messages], max_length)
  end

  defp from_binary(<<>>), do: new()
  defp from_binary(buffer), do: %__MODULE__{chunks: [buffer], size: byte_size(buffer)}
end

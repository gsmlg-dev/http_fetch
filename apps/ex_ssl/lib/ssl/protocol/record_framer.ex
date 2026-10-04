defmodule SSL.Protocol.RecordFramer do
  @moduledoc """
  Frames complete TLS records from an arbitrarily chunked byte stream.

  Incomplete data is retained as an opaque chunk accumulator so repeated small
  feeds do not rebuild the entire buffered record.
  """

  @default_max_plaintext_length 16_384
  @default_max_ciphertext_length 16_640

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
    with {:ok, configured_limit} <- configured_limit(opts) do
      buffer
      |> normalize_buffer()
      |> append(bytes)
      |> parse([], configured_limit)
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
    case Keyword.fetch(opts, :max_record_length) do
      :error -> {:ok, :default}
      {:ok, limit} when is_integer(limit) and limit >= 0 -> {:ok, limit}
      {:ok, _limit} -> {:error, {:invalid_limit, :max_record_length}}
    end
  end

  defp normalize_buffer(%__MODULE__{} = buffer), do: buffer
  defp normalize_buffer(buffer) when is_binary(buffer), do: from_binary(buffer)

  defp append(buffer, <<>>), do: buffer

  defp append(%__MODULE__{} = buffer, bytes) do
    %{buffer | chunks: [bytes | buffer.chunks], size: buffer.size + byte_size(bytes)}
  end

  defp parse(%__MODULE__{frame_size: nil, size: size} = buffer, records, _limit)
       when size < 5 do
    {:ok, Enum.reverse(records), buffer}
  end

  defp parse(%__MODULE__{frame_size: nil} = buffer, records, configured_limit) do
    data = buffered_bytes(buffer)
    <<type, _legacy_version::16, length::16, _rest::binary>> = data
    max_length = max_length(type, configured_limit)

    if length > max_length do
      {:error, {:record_length_exceeded, length, max_length}}
    else
      parse(%{buffer | chunks: [data], frame_size: 5 + length}, records, configured_limit)
    end
  end

  defp parse(%__MODULE__{size: size, frame_size: frame_size} = buffer, records, _limit)
       when size < frame_size do
    {:ok, Enum.reverse(records), buffer}
  end

  defp parse(%__MODULE__{frame_size: frame_size} = buffer, records, configured_limit) do
    data = buffered_bytes(buffer)
    <<record::binary-size(^frame_size), remainder::binary>> = data
    parse(from_binary(remainder), [record | records], configured_limit)
  end

  defp max_length(type, :default), do: protocol_max_length(type)
  defp max_length(type, configured_limit), do: min(configured_limit, protocol_max_length(type))

  defp protocol_max_length(23), do: @default_max_ciphertext_length
  defp protocol_max_length(_type), do: @default_max_plaintext_length

  defp from_binary(<<>>), do: new()
  defp from_binary(buffer), do: %__MODULE__{chunks: [buffer], size: byte_size(buffer)}
end

defmodule HTTP.H3.Varint do
  @moduledoc false

  import Bitwise, only: [<<<: 2, &&&: 2]

  @max (1 <<< 62) - 1

  @type encoded_size :: 1 | 2 | 4 | 8
  @type decode_result :: {:ok, non_neg_integer(), binary()} | :more

  @spec max() :: 4_611_686_018_427_387_903
  def max, do: @max

  @spec encoded_size(non_neg_integer()) :: {:ok, encoded_size()} | {:error, :invalid_varint}
  def encoded_size(value) when is_integer(value) and value >= 0 and value <= @max do
    cond do
      value <= 63 -> {:ok, 1}
      value <= 16_383 -> {:ok, 2}
      value <= 1_073_741_823 -> {:ok, 4}
      true -> {:ok, 8}
    end
  end

  def encoded_size(_value), do: {:error, :invalid_varint}

  @spec encode(non_neg_integer(), :shortest | encoded_size()) ::
          {:ok, binary()} | {:error, term()}
  def encode(value, bytes \\ :shortest)

  def encode(value, :shortest) do
    with {:ok, bytes} <- encoded_size(value) do
      encode(value, bytes)
    end
  end

  def encode(value, bytes) when bytes in [1, 2, 4, 8] do
    with {:ok, ^bytes} <- encoded_size_for(value, bytes) do
      prefix = length_prefix(bytes)
      bits = bytes * 8 - 2

      {:ok, <<prefix::2, value::integer-size(bits)>>}
    end
  end

  def encode(_value, _bytes), do: {:error, :invalid_varint_length}

  @spec encode!(non_neg_integer(), :shortest | encoded_size()) :: nonempty_binary()
  def encode!(value, bytes \\ :shortest) do
    case encode(value, bytes) do
      {:ok, encoded} -> encoded
      {:error, reason} -> raise ArgumentError, "invalid QUIC varint: #{inspect(reason)}"
    end
  end

  @spec decode(binary()) :: decode_result()
  def decode(<<>>), do: :more

  def decode(<<prefix::2, _value_prefix::6, _rest::binary>> = data) do
    bytes = 1 <<< prefix

    if byte_size(data) < bytes do
      :more
    else
      bit_count = bytes * 8
      value_bits = bit_count - 2
      value_mask = (1 <<< value_bits) - 1
      <<encoded::integer-size(bit_count), rest::binary>> = data

      {:ok, encoded &&& value_mask, rest}
    end
  end

  defp encoded_size_for(value, bytes) do
    case encoded_size(value) do
      {:ok, min_bytes} when min_bytes <= bytes -> {:ok, bytes}
      {:ok, _min_bytes} -> {:error, :varint_value_too_large}
      {:error, reason} -> {:error, reason}
    end
  end

  defp length_prefix(1), do: 0b00
  defp length_prefix(2), do: 0b01
  defp length_prefix(4), do: 0b10
  defp length_prefix(8), do: 0b11
end

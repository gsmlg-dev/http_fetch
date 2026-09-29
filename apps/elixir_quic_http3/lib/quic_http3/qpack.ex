defmodule QuicHttp3.Qpack do
  @moduledoc """
  QPACK wire primitives for literal-name header fields.

  This slice intentionally supports only raw literal names and values with a
  zero dynamic table. Huffman coding and static/dynamic table references remain
  explicit follow-up work; unsupported representations return errors.
  """

  import Bitwise, only: [&&&: 2, <<<: 2, |||: 2, >>>: 2]

  @max_integer (1 <<< 62) - 1

  @type decode_result ::
          {:ok, non_neg_integer(), binary()} | :more | {:error, term()}
  @type field :: {binary(), binary()}

  @spec encode_integer(non_neg_integer(), 1..8, non_neg_integer()) ::
          {:ok, binary()} | {:error, term()}
  def encode_integer(value, prefix_bits, prefix)
      when is_integer(value) and value >= 0 and prefix_bits in 1..8 and is_integer(prefix) and
             prefix in 0..255 do
    max_prefix = (1 <<< prefix_bits) - 1

    cond do
      (prefix &&& max_prefix) != 0 -> {:error, :invalid_integer_prefix}
      value > @max_integer -> {:error, :integer_overflow}
      value < max_prefix -> {:ok, <<prefix ||| value>>}
      true -> {:ok, <<prefix ||| max_prefix>> <> encode_continuation(value - max_prefix, [])}
    end
  end

  def encode_integer(_value, _prefix_bits, _prefix), do: {:error, :invalid_integer}

  @spec decode_integer(binary(), 1..8) :: decode_result()
  def decode_integer(_data, prefix_bits) when prefix_bits not in 1..8,
    do: {:error, :invalid_integer_prefix}

  def decode_integer(<<first, rest::binary>>, prefix_bits) when prefix_bits in 1..8 do
    max_prefix = (1 <<< prefix_bits) - 1
    prefix_value = first &&& max_prefix

    if prefix_value < max_prefix do
      {:ok, prefix_value, rest}
    else
      decode_continuation(rest, max_prefix, 0, 0)
    end
  end

  def decode_integer(<<>>, _prefix_bits), do: :more
  def decode_integer(_data, _prefix_bits), do: {:error, :invalid_integer_prefix}

  @spec encode_string(binary()) :: {:ok, binary()} | {:error, term()}
  def encode_string(value) when is_binary(value) do
    with {:ok, length} <- encode_integer(byte_size(value), 7, 0) do
      {:ok, length <> value}
    end
  end

  def encode_string(_value), do: {:error, :invalid_string}

  @spec decode_string(binary()) ::
          {:ok, binary(), binary()} | :more | {:error, :huffman_not_supported}
  def decode_string(<<first, _rest::binary>> = data) do
    if (first &&& 0x80) != 0 do
      {:error, :huffman_not_supported}
    else
      with {:ok, length, rest} <- decode_integer(data, 7) do
        if byte_size(rest) < length do
          :more
        else
          <<value::binary-size(^length), tail::binary>> = rest
          {:ok, value, tail}
        end
      end
    end
  end

  def decode_string(<<>>), do: :more

  @spec encode_header_block([field()], keyword()) :: {:ok, binary()} | {:error, term()}
  def encode_header_block(fields, opts \\ [])

  def encode_header_block(fields, opts) when is_list(fields) do
    never_indexed? = Keyword.get(opts, :never_indexed, false)

    with :ok <- validate_fields(fields),
         {:ok, prefix} <- encode_integer(0, 8, 0),
         {:ok, base} <- encode_integer(0, 7, 0),
         {:ok, encoded} <- encode_fields(fields, never_indexed?, []) do
      {:ok, IO.iodata_to_binary([prefix, base, encoded])}
    end
  end

  def encode_header_block(_fields, _opts), do: {:error, :invalid_fields}

  @spec decode_header_block(binary(), keyword()) ::
          {:ok, [field()]} | :more | {:error, term()}
  def decode_header_block(data, opts \\ [])

  def decode_header_block(data, opts) when is_binary(data) do
    limit = Keyword.get(opts, :max_fields, 128)

    if is_integer(limit) and limit >= 0 do
      with {:ok, required_insert_count, rest} <- decode_integer(data, 8),
           {:ok, delta_base, rest} <- decode_base(rest),
           :ok <- validate_prefix(required_insert_count, delta_base) do
        decode_fields(rest, [], limit)
      end
    else
      {:error, :invalid_field_limit}
    end
  end

  def decode_header_block(_data, _opts), do: {:error, :invalid_header_block}

  defp validate_fields(fields) do
    if Enum.all?(fields, fn
         {name, value} -> is_binary(value) and valid_field_name?(name)
         _field -> false
       end) do
      :ok
    else
      {:error, :invalid_fields}
    end
  end

  defp encode_fields([], _never_indexed?, acc), do: {:ok, Enum.reverse(acc)}

  defp encode_fields([{name, value} | rest], never_indexed?, acc) do
    prefix = if never_indexed?, do: 0x30, else: 0x20

    with {:ok, name_length} <- encode_integer(byte_size(name), 3, prefix),
         {:ok, encoded_value} <- encode_string(value) do
      encode_fields(rest, never_indexed?, [[name_length, name, encoded_value] | acc])
    end
  end

  defp decode_base(<<first, _rest::binary>> = data) do
    negative? = (first &&& 0x80) != 0

    with {:ok, value, rest} <- decode_integer(data, 7) do
      {:ok, if(negative?, do: {:negative, value}, else: {:positive, value}), rest}
    end
  end

  defp decode_base(<<>>), do: :more

  defp validate_prefix(0, {:positive, 0}), do: :ok
  defp validate_prefix(_required, _base), do: {:error, :dynamic_table_not_supported}

  defp decode_fields(<<>>, fields, _limit), do: {:ok, Enum.reverse(fields)}

  defp decode_fields(_data, _fields, limit) when limit <= 0, do: {:error, :field_limit}

  defp decode_fields(<<first, _rest::binary>> = data, fields, limit) do
    cond do
      (first &&& 0x80) != 0 -> {:error, :indexed_field_not_supported}
      (first &&& 0xC0) == 0x40 -> {:error, :name_reference_not_supported}
      (first &&& 0xE0) == 0x20 -> decode_literal_field(data, fields, limit)
      true -> {:error, :unsupported_field_representation}
    end
  end

  defp decode_literal_field(data, fields, limit) do
    first = :binary.at(data, 0)
    huffman? = (first &&& 0x08) != 0

    if huffman? do
      {:error, :huffman_not_supported}
    else
      with {:ok, name_length, rest} <- decode_integer(data, 3),
           {:ok, name, rest} <- take_bytes(rest, name_length),
           :ok <- validate_decoded_name(name),
           {:ok, value, rest} <- decode_string(rest) do
        decode_fields(rest, [{name, value} | fields], limit - 1)
      end
    end
  end

  defp validate_decoded_name(name) do
    if valid_field_name?(name), do: :ok, else: {:error, :invalid_fields}
  end

  defp valid_field_name?(name) when is_binary(name) do
    lowercase? = name == String.downcase(name)

    lowercase? and
      case name do
        <<?:, rest::binary>> -> valid_token?(rest)
        <<first, _rest::binary>> when first != ?: -> valid_token?(name)
        _ -> false
      end
  end

  defp valid_field_name?(_name), do: false

  defp valid_token?(<<>>), do: false

  defp valid_token?(name) do
    Enum.all?(:binary.bin_to_list(name), &token_byte?/1)
  end

  defp token_byte?(byte) when byte in ?0..?9, do: true
  defp token_byte?(byte) when byte in ?A..?Z, do: true
  defp token_byte?(byte) when byte in ?a..?z, do: true

  defp token_byte?(byte)
       when byte in [?!, ?#, ?$, ?%, ?&, ?', ?*, ?+, ?-, ?., ?^, ?_, ?`, ?|, ?~], do: true

  defp token_byte?(_byte), do: false

  defp take_bytes(data, length) when byte_size(data) < length, do: :more

  defp take_bytes(data, length) when is_binary(data) and is_integer(length) and length >= 0 do
    {:ok, binary_part(data, 0, length), binary_part(data, length, byte_size(data) - length)}
  end

  defp encode_continuation(value, acc) do
    byte = value &&& 0x7F
    next = value >>> 7

    if next > 0 do
      encode_continuation(next, [byte ||| 0x80 | acc])
    else
      [byte | acc] |> Enum.reverse() |> IO.iodata_to_binary()
    end
  end

  defp decode_continuation(<<byte, rest::binary>>, prefix_value, shift, value) do
    chunk = byte &&& 0x7F
    next = value + (chunk <<< shift)

    cond do
      next > @max_integer -> {:error, :integer_overflow}
      (byte &&& 0x80) == 0 -> {:ok, prefix_value + next, rest}
      shift >= 56 -> {:error, :integer_overflow}
      true -> decode_continuation(rest, prefix_value, shift + 7, next)
    end
  end

  defp decode_continuation(<<>>, _prefix_value, _shift, _value), do: :more
end

defmodule HTTP.HTTP2.HPACK do
  @moduledoc false

  import Bitwise

  defstruct dynamic: [], dynamic_size: 0, max_dynamic_size: 4096

  @type header :: {String.t(), String.t()}
  @type t :: %__MODULE__{
          dynamic: [header()],
          dynamic_size: non_neg_integer(),
          max_dynamic_size: non_neg_integer()
        }

  @static_table [
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""}
  ]

  @static_count length(@static_table)

  @huffman_table [
    {0, 0x1FF8, 13},
    {1, 0x7FFFD8, 23},
    {2, 0xFFFFFE2, 28},
    {3, 0xFFFFFE3, 28},
    {4, 0xFFFFFE4, 28},
    {5, 0xFFFFFE5, 28},
    {6, 0xFFFFFE6, 28},
    {7, 0xFFFFFE7, 28},
    {8, 0xFFFFFE8, 28},
    {9, 0xFFFFEA, 24},
    {10, 0x3FFFFFFC, 30},
    {11, 0xFFFFFE9, 28},
    {12, 0xFFFFFEA, 28},
    {13, 0x3FFFFFFD, 30},
    {14, 0xFFFFFEB, 28},
    {15, 0xFFFFFEC, 28},
    {16, 0xFFFFFED, 28},
    {17, 0xFFFFFEE, 28},
    {18, 0xFFFFFEF, 28},
    {19, 0xFFFFFF0, 28},
    {20, 0xFFFFFF1, 28},
    {21, 0xFFFFFF2, 28},
    {22, 0x3FFFFFFE, 30},
    {23, 0xFFFFFF3, 28},
    {24, 0xFFFFFF4, 28},
    {25, 0xFFFFFF5, 28},
    {26, 0xFFFFFF6, 28},
    {27, 0xFFFFFF7, 28},
    {28, 0xFFFFFF8, 28},
    {29, 0xFFFFFF9, 28},
    {30, 0xFFFFFFA, 28},
    {31, 0xFFFFFFB, 28},
    {32, 0x14, 6},
    {33, 0x3F8, 10},
    {34, 0x3F9, 10},
    {35, 0xFFA, 12},
    {36, 0x1FF9, 13},
    {37, 0x15, 6},
    {38, 0xF8, 8},
    {39, 0x7FA, 11},
    {40, 0x3FA, 10},
    {41, 0x3FB, 10},
    {42, 0xF9, 8},
    {43, 0x7FB, 11},
    {44, 0xFA, 8},
    {45, 0x16, 6},
    {46, 0x17, 6},
    {47, 0x18, 6},
    {48, 0x0, 5},
    {49, 0x1, 5},
    {50, 0x2, 5},
    {51, 0x19, 6},
    {52, 0x1A, 6},
    {53, 0x1B, 6},
    {54, 0x1C, 6},
    {55, 0x1D, 6},
    {56, 0x1E, 6},
    {57, 0x1F, 6},
    {58, 0x5C, 7},
    {59, 0xFB, 8},
    {60, 0x7FFC, 15},
    {61, 0x20, 6},
    {62, 0xFFB, 12},
    {63, 0x3FC, 10},
    {64, 0x1FFA, 13},
    {65, 0x21, 6},
    {66, 0x5D, 7},
    {67, 0x5E, 7},
    {68, 0x5F, 7},
    {69, 0x60, 7},
    {70, 0x61, 7},
    {71, 0x62, 7},
    {72, 0x63, 7},
    {73, 0x64, 7},
    {74, 0x65, 7},
    {75, 0x66, 7},
    {76, 0x67, 7},
    {77, 0x68, 7},
    {78, 0x69, 7},
    {79, 0x6A, 7},
    {80, 0x6B, 7},
    {81, 0x6C, 7},
    {82, 0x6D, 7},
    {83, 0x6E, 7},
    {84, 0x6F, 7},
    {85, 0x70, 7},
    {86, 0x71, 7},
    {87, 0x72, 7},
    {88, 0xFC, 8},
    {89, 0x73, 7},
    {90, 0xFD, 8},
    {91, 0x1FFB, 13},
    {92, 0x7FFF0, 19},
    {93, 0x1FFC, 13},
    {94, 0x3FFC, 14},
    {95, 0x22, 6},
    {96, 0x7FFD, 15},
    {97, 0x3, 5},
    {98, 0x23, 6},
    {99, 0x4, 5},
    {100, 0x24, 6},
    {101, 0x5, 5},
    {102, 0x25, 6},
    {103, 0x26, 6},
    {104, 0x27, 6},
    {105, 0x6, 5},
    {106, 0x74, 7},
    {107, 0x75, 7},
    {108, 0x28, 6},
    {109, 0x29, 6},
    {110, 0x2A, 6},
    {111, 0x7, 5},
    {112, 0x2B, 6},
    {113, 0x76, 7},
    {114, 0x2C, 6},
    {115, 0x8, 5},
    {116, 0x9, 5},
    {117, 0x2D, 6},
    {118, 0x77, 7},
    {119, 0x78, 7},
    {120, 0x79, 7},
    {121, 0x7A, 7},
    {122, 0x7B, 7},
    {123, 0x7FFE, 15},
    {124, 0x7FC, 11},
    {125, 0x3FFD, 14},
    {126, 0x1FFD, 13},
    {127, 0xFFFFFFC, 28},
    {128, 0xFFFE6, 20},
    {129, 0x3FFFD2, 22},
    {130, 0xFFFE7, 20},
    {131, 0xFFFE8, 20},
    {132, 0x3FFFD3, 22},
    {133, 0x3FFFD4, 22},
    {134, 0x3FFFD5, 22},
    {135, 0x7FFFD9, 23},
    {136, 0x3FFFD6, 22},
    {137, 0x7FFFDA, 23},
    {138, 0x7FFFDB, 23},
    {139, 0x7FFFDC, 23},
    {140, 0x7FFFDD, 23},
    {141, 0x7FFFDE, 23},
    {142, 0xFFFFEB, 24},
    {143, 0x7FFFDF, 23},
    {144, 0xFFFFEC, 24},
    {145, 0xFFFFED, 24},
    {146, 0x3FFFD7, 22},
    {147, 0x7FFFE0, 23},
    {148, 0xFFFFEE, 24},
    {149, 0x7FFFE1, 23},
    {150, 0x7FFFE2, 23},
    {151, 0x7FFFE3, 23},
    {152, 0x7FFFE4, 23},
    {153, 0x1FFFDC, 21},
    {154, 0x3FFFD8, 22},
    {155, 0x7FFFE5, 23},
    {156, 0x3FFFD9, 22},
    {157, 0x7FFFE6, 23},
    {158, 0x7FFFE7, 23},
    {159, 0xFFFFEF, 24},
    {160, 0x3FFFDA, 22},
    {161, 0x1FFFDD, 21},
    {162, 0xFFFE9, 20},
    {163, 0x3FFFDB, 22},
    {164, 0x3FFFDC, 22},
    {165, 0x7FFFE8, 23},
    {166, 0x7FFFE9, 23},
    {167, 0x1FFFDE, 21},
    {168, 0x7FFFEA, 23},
    {169, 0x3FFFDD, 22},
    {170, 0x3FFFDE, 22},
    {171, 0xFFFFF0, 24},
    {172, 0x1FFFDF, 21},
    {173, 0x3FFFDF, 22},
    {174, 0x7FFFEB, 23},
    {175, 0x7FFFEC, 23},
    {176, 0x1FFFE0, 21},
    {177, 0x1FFFE1, 21},
    {178, 0x3FFFE0, 22},
    {179, 0x1FFFE2, 21},
    {180, 0x7FFFED, 23},
    {181, 0x3FFFE1, 22},
    {182, 0x7FFFEE, 23},
    {183, 0x7FFFEF, 23},
    {184, 0xFFFEA, 20},
    {185, 0x3FFFE2, 22},
    {186, 0x3FFFE3, 22},
    {187, 0x3FFFE4, 22},
    {188, 0x7FFFF0, 23},
    {189, 0x3FFFE5, 22},
    {190, 0x3FFFE6, 22},
    {191, 0x7FFFF1, 23},
    {192, 0x3FFFFE0, 26},
    {193, 0x3FFFFE1, 26},
    {194, 0xFFFEB, 20},
    {195, 0x7FFF1, 19},
    {196, 0x3FFFE7, 22},
    {197, 0x7FFFF2, 23},
    {198, 0x3FFFE8, 22},
    {199, 0x1FFFFEC, 25},
    {200, 0x3FFFFE2, 26},
    {201, 0x3FFFFE3, 26},
    {202, 0x3FFFFE4, 26},
    {203, 0x7FFFFDE, 27},
    {204, 0x7FFFFDF, 27},
    {205, 0x3FFFFE5, 26},
    {206, 0xFFFFF1, 24},
    {207, 0x1FFFFED, 25},
    {208, 0x7FFF2, 19},
    {209, 0x1FFFE3, 21},
    {210, 0x3FFFFE6, 26},
    {211, 0x7FFFFE0, 27},
    {212, 0x7FFFFE1, 27},
    {213, 0x3FFFFE7, 26},
    {214, 0x7FFFFE2, 27},
    {215, 0xFFFFF2, 24},
    {216, 0x1FFFE4, 21},
    {217, 0x1FFFE5, 21},
    {218, 0x3FFFFE8, 26},
    {219, 0x3FFFFE9, 26},
    {220, 0xFFFFFFD, 28},
    {221, 0x7FFFFE3, 27},
    {222, 0x7FFFFE4, 27},
    {223, 0x7FFFFE5, 27},
    {224, 0xFFFEC, 20},
    {225, 0xFFFFF3, 24},
    {226, 0xFFFED, 20},
    {227, 0x1FFFE6, 21},
    {228, 0x3FFFE9, 22},
    {229, 0x1FFFE7, 21},
    {230, 0x1FFFE8, 21},
    {231, 0x7FFFF3, 23},
    {232, 0x3FFFEA, 22},
    {233, 0x3FFFEB, 22},
    {234, 0x1FFFFEE, 25},
    {235, 0x1FFFFEF, 25},
    {236, 0xFFFFF4, 24},
    {237, 0xFFFFF5, 24},
    {238, 0x3FFFFEA, 26},
    {239, 0x7FFFF4, 23},
    {240, 0x3FFFFEB, 26},
    {241, 0x7FFFFE6, 27},
    {242, 0x3FFFFEC, 26},
    {243, 0x3FFFFED, 26},
    {244, 0x7FFFFE7, 27},
    {245, 0x7FFFFE8, 27},
    {246, 0x7FFFFE9, 27},
    {247, 0x7FFFFEA, 27},
    {248, 0x7FFFFEB, 27},
    {249, 0xFFFFFFE, 28},
    {250, 0x7FFFFEC, 27},
    {251, 0x7FFFFED, 27},
    {252, 0x7FFFFEE, 27},
    {253, 0x7FFFFEF, 27},
    {254, 0x7FFFFF0, 27},
    {255, 0x3FFFFEE, 26},
    {256, 0x3FFFFFFF, 30}
  ]

  @spec new_decoder() :: t()
  def new_decoder, do: %__MODULE__{}

  @spec encode_headers([header()]) :: iodata()
  def encode_headers(headers) when is_list(headers) do
    Enum.map(headers, fn {name, value} ->
      [encode_integer(0, 4, 0x00), encode_string(name), encode_string(value)]
    end)
  end

  @spec decode(t(), binary()) :: {:ok, t(), [header()]} | {:error, term()}
  def decode(%__MODULE__{} = decoder, block) when is_binary(block) do
    decode_headers(decoder, block, [])
  end

  @spec encode_integer(non_neg_integer(), 1..8, non_neg_integer()) :: binary()
  def encode_integer(value, prefix_bits, high_bits)
      when value >= 0 and prefix_bits >= 1 and prefix_bits <= 8 do
    prefix_max = (1 <<< prefix_bits) - 1

    if value < prefix_max do
      <<high_bits ||| value>>
    else
      [<<high_bits ||| prefix_max>>, encode_integer_tail(value - prefix_max)]
      |> IO.iodata_to_binary()
    end
  end

  defp encode_integer_tail(value) when value >= 128 do
    [<<rem(value, 128) ||| 0x80>>, encode_integer_tail(value >>> 7)]
  end

  defp encode_integer_tail(value), do: <<value>>

  @spec encode_string(String.t()) :: binary()
  def encode_string(value) when is_binary(value) do
    [encode_integer(byte_size(value), 7, 0), value] |> IO.iodata_to_binary()
  end

  defp decode_headers(decoder, <<>>, acc), do: {:ok, decoder, Enum.reverse(acc)}

  defp decode_headers(%__MODULE__{} = decoder, <<first, _::binary>> = block, acc) do
    cond do
      (first &&& 0x80) == 0x80 ->
        with {:ok, index, rest} <- decode_integer(block, 7),
             {:ok, header} <- lookup(decoder, index) do
          decode_headers(decoder, rest, [header | acc])
        end

      (first &&& 0x40) == 0x40 ->
        with {:ok, decoder, header, rest} <- decode_literal(decoder, block, 6, true) do
          decode_headers(decoder, rest, [header | acc])
        end

      (first &&& 0x20) == 0x20 ->
        with {:ok, size, rest} <- decode_integer(block, 5),
             {:ok, decoder} <- resize_dynamic_table(decoder, size) do
          decode_headers(decoder, rest, acc)
        end

      (first &&& 0x10) == 0x10 ->
        with {:ok, decoder, header, rest} <- decode_literal(decoder, block, 4, false) do
          decode_headers(decoder, rest, [header | acc])
        end

      true ->
        with {:ok, decoder, header, rest} <- decode_literal(decoder, block, 4, false) do
          decode_headers(decoder, rest, [header | acc])
        end
    end
  end

  defp decode_literal(decoder, block, prefix_bits, index?) do
    with {:ok, name_index, rest} <- decode_integer(block, prefix_bits),
         {:ok, name, rest} <- decode_name(decoder, name_index, rest),
         {:ok, value, rest} <- decode_string(rest) do
      header = {name, value}
      decoder = if index?, do: add_dynamic(decoder, header), else: decoder

      {:ok, decoder, header, rest}
    end
  end

  defp decode_name(_decoder, 0, rest), do: decode_string(rest)

  defp decode_name(decoder, index, rest) do
    case lookup(decoder, index) do
      {:ok, {name, _value}} -> {:ok, name, rest}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_integer(<<first, rest::binary>>, prefix_bits) do
    prefix_max = (1 <<< prefix_bits) - 1
    value = first &&& prefix_max

    if value < prefix_max do
      {:ok, value, rest}
    else
      decode_integer_tail(rest, value, 0, 0)
    end
  end

  defp decode_integer(<<>>, _prefix_bits), do: {:error, :truncated_hpack_integer}

  defp decode_integer_tail(<<>>, _value, _shift, _octets), do: {:error, :truncated_hpack_integer}
  defp decode_integer_tail(_rest, _value, _shift, 8), do: {:error, :hpack_integer_too_large}

  defp decode_integer_tail(<<byte, rest::binary>>, value, shift, octets) do
    value = value + ((byte &&& 0x7F) <<< shift)

    if (byte &&& 0x80) == 0 do
      {:ok, value, rest}
    else
      decode_integer_tail(rest, value, shift + 7, octets + 1)
    end
  end

  defp decode_string(<<first, _::binary>> = data) do
    huffman? = (first &&& 0x80) == 0x80

    with {:ok, length, rest} <- decode_integer(data, 7),
         {:ok, encoded, rest} <- take_bytes(rest, length) do
      if huffman? do
        with {:ok, decoded} <- decode_huffman(encoded) do
          {:ok, decoded, rest}
        end
      else
        {:ok, encoded, rest}
      end
    end
  end

  defp decode_string(<<>>), do: {:error, :truncated_hpack_string}

  defp take_bytes(data, length) when byte_size(data) >= length do
    <<value::binary-size(length), rest::binary>> = data
    {:ok, value, rest}
  end

  defp take_bytes(_data, _length), do: {:error, :truncated_hpack_string}

  defp lookup(_decoder, 0), do: {:error, :invalid_hpack_index}

  defp lookup(_decoder, index) when index <= @static_count do
    {:ok, Enum.at(@static_table, index - 1)}
  end

  defp lookup(%__MODULE__{dynamic: dynamic}, index) do
    dynamic_index = index - @static_count

    case Enum.at(dynamic, dynamic_index - 1) do
      nil -> {:error, :invalid_hpack_index}
      header -> {:ok, header}
    end
  end

  defp resize_dynamic_table(%__MODULE__{} = decoder, size)
       when size <= decoder.max_dynamic_size do
    {:ok, evict_dynamic(%{decoder | max_dynamic_size: size})}
  end

  defp resize_dynamic_table(_decoder, _size), do: {:error, :invalid_dynamic_table_size_update}

  defp add_dynamic(%__MODULE__{} = decoder, {name, value} = header) do
    entry_size = byte_size(name) + byte_size(value) + 32

    if entry_size > decoder.max_dynamic_size do
      %{decoder | dynamic: [], dynamic_size: 0}
    else
      decoder
      |> Map.update!(:dynamic, &[header | &1])
      |> Map.update!(:dynamic_size, &(&1 + entry_size))
      |> evict_dynamic()
    end
  end

  defp evict_dynamic(%__MODULE__{dynamic_size: size, max_dynamic_size: max} = decoder)
       when size <= max do
    decoder
  end

  defp evict_dynamic(%__MODULE__{dynamic: dynamic, dynamic_size: size} = decoder) do
    {name, value} = List.last(dynamic)
    entry_size = byte_size(name) + byte_size(value) + 32

    %{decoder | dynamic: Enum.drop(dynamic, -1), dynamic_size: size - entry_size}
    |> evict_dynamic()
  end

  defp decode_huffman(data) do
    tree = huffman_tree()

    data
    |> huffman_bits()
    |> Enum.reduce_while({tree, [], 0, 0}, fn bit, {node, acc, pending_value, pending_len} ->
      case Map.get(node, bit) do
        nil ->
          {:halt, {:error, :invalid_huffman_code}}

        next ->
          pending_value = pending_value <<< 1 ||| bit
          pending_len = pending_len + 1

          case Map.get(next, :symbol) do
            nil -> {:cont, {next, acc, pending_value, pending_len}}
            256 -> {:halt, {:error, :invalid_huffman_eos}}
            symbol -> {:cont, {tree, [<<symbol>> | acc], 0, 0}}
          end
      end
    end)
    |> case do
      {:error, reason} ->
        {:error, reason}

      {_node, acc, pending_value, pending_len} ->
        if valid_huffman_padding?(pending_value, pending_len) do
          {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}
        else
          {:error, :invalid_huffman_padding}
        end
    end
  end

  defp huffman_bits(data) do
    for <<byte <- data>>, shift <- 7..0//-1 do
      byte >>> shift &&& 1
    end
  end

  defp valid_huffman_padding?(_value, 0), do: true

  defp valid_huffman_padding?(value, length) when length <= 7 do
    value == (1 <<< length) - 1
  end

  defp valid_huffman_padding?(_value, _length), do: false

  defp huffman_tree do
    Enum.reduce(@huffman_table, %{}, fn {symbol, code, length}, tree ->
      insert_huffman_code(tree, huffman_code_bits(code, length), symbol)
    end)
  end

  defp huffman_code_bits(code, length) do
    for shift <- (length - 1)..0//-1 do
      code >>> shift &&& 1
    end
  end

  defp insert_huffman_code(tree, [], symbol), do: Map.put(tree, :symbol, symbol)

  defp insert_huffman_code(tree, [bit | rest], symbol) do
    Map.update(tree, bit, insert_huffman_code(%{}, rest, symbol), fn child ->
      insert_huffman_code(child, rest, symbol)
    end)
  end
end

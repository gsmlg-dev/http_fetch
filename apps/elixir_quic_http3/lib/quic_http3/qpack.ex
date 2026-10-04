defmodule QuicHttp3.Qpack do
  @moduledoc """
  QPACK wire primitives for static and literal header fields.

  Dynamic table state is bounded and opt-in. Encoder/decoder stream
  synchronization remains the responsibility of the HTTP/3 session layer.
  """

  import Bitwise, only: [&&&: 2, <<<: 2, |||: 2, >>>: 2]

  @max_integer (1 <<< 62) - 1
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
  @static_table [
    {":authority", ""},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "103"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "302"},
    {":status", "304"},
    {":status", "400"},
    {":status", "401"},
    {":status", "403"},
    {":status", "404"},
    {":status", "421"},
    {":status", "425"},
    {":status", "500"},
    {":status", "501"},
    {":status", "502"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-headers", ""},
    {"access-control-allow-origin", ""},
    {"cache-control", ""},
    {"content-encoding", ""},
    {"content-length", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"forwarded", ""},
    {"for", ""},
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
    {"www-authenticate", ""},
    {"access-control-allow-credentials", "true"},
    {"access-control-allow-credentials", "false"},
    {"access-control-allow-headers", "cache-control"},
    {"access-control-allow-headers", "content-type"},
    {"access-control-allow-origin", "*"},
    {"access-control-allow-origin", "https://www.example.com"},
    {"access-control-expose-headers", "content-length"},
    {"access-control-request-headers", "content-type"},
    {"access-control-request-method", "get"},
    {"access-control-request-method", "post"},
    {"alt-svc", "clear"},
    {"authorization", ""},
    {"content-security-policy", "script-src 'none';"},
    {"early-data", "1"},
    {"expect-ct", ""},
    {"origin", ""},
    {"purpose", "prefetch"},
    {"server-timing", ""},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", ""},
    {"x-forwarded-for", ""},
    {"x-frame-options", "deny"},
    {"x-frame-options", "sameorigin"}
  ]

  defstruct capacity: 0, entries: [], size: 0, insert_count: 0

  @type dynamic_entry :: %{name: binary(), value: binary(), size: pos_integer()}
  @type t :: %__MODULE__{
          capacity: non_neg_integer(),
          entries: [dynamic_entry()],
          size: non_neg_integer(),
          insert_count: non_neg_integer()
        }

  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    capacity = Keyword.get(opts, :capacity, 0)

    if is_integer(capacity) and capacity >= 0,
      do: %__MODULE__{capacity: capacity},
      else: %__MODULE__{}
  end

  @spec insert(t(), binary(), binary()) :: {:ok, t()} | {:error, term()}
  def insert(%__MODULE__{} = table, name, value) when is_binary(name) and is_binary(value) do
    entry_size = byte_size(name) + byte_size(value) + 32

    if entry_size > table.capacity do
      {:ok, %{table | entries: [], size: 0, insert_count: table.insert_count + 1}}
    else
      entries = [%{name: name, value: value, size: entry_size} | table.entries]
      entries = evict(entries, table.capacity, table.size + entry_size)

      {:ok,
       %{
         table
         | entries: entries,
           size: Enum.reduce(entries, 0, &(&1.size + &2)),
           insert_count: table.insert_count + 1
       }}
    end
  end

  def insert(_, _, _), do: {:error, :invalid_dynamic_entry}

  @spec dynamic(t(), non_neg_integer()) :: {:ok, field()} | {:error, :invalid_dynamic_index}
  def dynamic(%__MODULE__{entries: entries}, index) when is_integer(index) and index >= 0 do
    case Enum.at(entries, index) do
      %{name: name, value: value} -> {:ok, {name, value}}
      nil -> {:error, :invalid_dynamic_index}
    end
  end

  def dynamic(_, _), do: {:error, :invalid_dynamic_index}

  @spec static(non_neg_integer()) :: {:ok, field()} | {:error, :invalid_static_index}
  def static(index) when is_integer(index) and index >= 0 do
    case Enum.at(@static_table, index) do
      nil -> {:error, :invalid_static_index}
      field -> {:ok, field}
    end
  end

  def static(_), do: {:error, :invalid_static_index}

  defp evict(entries, capacity, size) when size <= capacity, do: entries
  defp evict([], _capacity, _size), do: []

  defp evict(entries, capacity, size),
    do: evict(Enum.drop(entries, -1), capacity, size - List.last(entries).size)

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

  def encode_string(value, huffman: true) when is_binary(value) do
    encoded = encode_huffman(value)

    with {:ok, length} <- encode_integer(byte_size(encoded), 7, 0x80) do
      {:ok, length <> encoded}
    end
  end

  @spec decode_string(binary()) ::
          {:ok, binary(), binary()} | :more | {:error, term()}
  def decode_string(<<first, _rest::binary>> = data) do
    if (first &&& 0x80) != 0 do
      with {:ok, length, rest} <- decode_integer(data, 7),
           {:ok, encoded, tail} <- take_bytes(rest, length),
           {:ok, value} <- decode_huffman(encoded) do
        {:ok, value, tail}
      end
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
    indexed? = Keyword.get(opts, :indexed, false)

    with :ok <- validate_fields(fields),
         {:ok, prefix} <- encode_integer(0, 8, 0),
         {:ok, base} <- encode_integer(0, 7, 0),
         {:ok, encoded} <- encode_fields(fields, never_indexed?, indexed?, []) do
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

  defp encode_fields([], _never_indexed?, _indexed?, acc), do: {:ok, Enum.reverse(acc)}

  defp encode_fields([{name, value} | rest], never_indexed?, indexed?, acc) do
    case if(indexed?, do: static_index({name, value}), else: nil) do
      index when is_integer(index) ->
        with {:ok, encoded} <- encode_integer(index, 6, 0xC0),
             {:ok, tail} <- encode_fields(rest, never_indexed?, indexed?, acc) do
          {:ok, [encoded | tail]}
        end

      _ ->
        encode_literal_or_reference(name, value, rest, never_indexed?, indexed?, acc)
    end
  end

  defp encode_literal_or_reference(name, value, rest, never_indexed?, indexed?, acc) do
    static_name = static_name_index(name)

    if indexed? and is_integer(static_name) do
      prefix = if never_indexed?, do: 0x70, else: 0x50

      with {:ok, name_index} <- encode_integer(static_name, 4, prefix),
           {:ok, encoded_value} <- encode_string(value),
           {:ok, tail} <- encode_fields(rest, never_indexed?, indexed?, acc) do
        {:ok, [[name_index, encoded_value] | tail]}
      end
    else
      prefix = if never_indexed?, do: 0x30, else: 0x20

      with {:ok, name_length} <- encode_integer(byte_size(name), 3, prefix),
           {:ok, encoded_value} <- encode_string(value) do
        encode_fields(rest, never_indexed?, indexed?, [[name_length, name, encoded_value] | acc])
      end
    end
  end

  defp static_index(field), do: Enum.find_index(@static_table, &(&1 == field))

  defp static_name_index(name),
    do: Enum.find_index(@static_table, fn {entry_name, _} -> entry_name == name end)

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
      (first &&& 0x80) != 0 -> decode_indexed_field(data, fields, limit)
      (first &&& 0xC0) == 0x40 -> decode_name_reference(data, fields, limit)
      (first &&& 0xE0) == 0x20 -> decode_literal_field(data, fields, limit)
      true -> {:error, :unsupported_field_representation}
    end
  end

  defp decode_indexed_field(data, fields, limit) do
    first = :binary.at(data, 0)
    static? = (first &&& 0x40) != 0

    if static? do
      with {:ok, index, rest} <- decode_integer(data, 6),
           {:ok, field} <- static(index) do
        decode_fields(rest, [field | fields], limit - 1)
      end
    else
      {:error, :indexed_field_not_supported}
    end
  end

  defp decode_name_reference(data, fields, limit) do
    first = :binary.at(data, 0)
    static? = (first &&& 0x10) != 0

    if static? do
      with {:ok, index, rest} <- decode_integer(data, 4),
           {:ok, {name, _}} <- static(index),
           {:ok, value, rest} <- decode_string(rest) do
        decode_fields(rest, [{name, value} | fields], limit - 1)
      end
    else
      {:error, :dynamic_table_not_supported}
    end
  end

  defp decode_literal_field(data, fields, limit) do
    first = :binary.at(data, 0)
    huffman? = (first &&& 0x08) != 0

    if huffman? do
      with {:ok, name_length, rest} <- decode_integer(data, 3),
           {:ok, encoded_name, rest} <- take_bytes(rest, name_length),
           {:ok, name} <- decode_huffman(encoded_name),
           :ok <- validate_decoded_name(name),
           {:ok, value, rest} <- decode_string(rest) do
        decode_fields(rest, [{name, value} | fields], limit - 1)
      end
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
       when byte in [?!, ?#, ?$, ?%, ?&, ?', ?*, ?+, ?-, ?., ?^, ?_, ?`, ?|, ?~],
       do: true

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

  defp encode_huffman(value) do
    {bits, length} =
      Enum.reduce(:binary.bin_to_list(value), {0, 0}, fn symbol, {acc, size} ->
        {_, code, width} = Enum.at(@huffman_table, symbol)
        {acc <<< width ||| code, size + width}
      end)

    padding = rem(8 - rem(length, 8), 8)
    <<bits <<< padding ||| (1 <<< padding) - 1::unsigned-integer-size(length + padding)>>
  end

  defp decode_huffman(data) do
    tree = huffman_tree()

    {result, _node, pending, pending_len} =
      for <<byte <- data>>, shift <- 7..0//-1, reduce: {[], tree, 0, 0} do
        {acc, current, value, length} ->
          bit = byte >>> shift &&& 1
          next = Map.get(current, bit)

          if next == nil do
            throw({:error, :invalid_huffman_code})
          else
            next_value = value <<< 1 ||| bit
            next_length = length + 1

            case Map.get(next, :symbol) do
              nil -> {acc, next, next_value, next_length}
              256 -> throw({:error, :invalid_huffman_eos})
              symbol -> {[<<symbol>> | acc], tree, 0, 0}
            end
          end
      end

    if pending_len <= 7 and pending == (1 <<< pending_len) - 1 do
      {:ok, IO.iodata_to_binary(Enum.reverse(result))}
    else
      {:error, :invalid_huffman_padding}
    end
  catch
    {:error, reason} -> {:error, reason}
  end

  defp huffman_tree do
    Enum.reduce(@huffman_table, %{}, fn {symbol, code, width}, tree ->
      bits = for shift <- (width - 1)..0//-1, do: code >>> shift &&& 1
      insert_huffman_code(tree, bits, symbol)
    end)
  end

  defp insert_huffman_code(tree, [], symbol), do: Map.put(tree, :symbol, symbol)

  defp insert_huffman_code(tree, [bit | rest], symbol) do
    Map.update(tree, bit, insert_huffman_code(%{}, rest, symbol), fn child ->
      insert_huffman_code(child, rest, symbol)
    end)
  end
end

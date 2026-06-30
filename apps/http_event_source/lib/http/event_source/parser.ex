defmodule HTTP.EventSource.Parser do
  @moduledoc false

  @bom <<0xEF, 0xBB, 0xBF>>
  @default_max_line_size 64 * 1024

  defstruct buffer: <<>>,
            bom_seen?: false,
            data_parts: [],
            event_type: "",
            last_event_id: "",
            id_changed?: false,
            max_line_size: @default_max_line_size

  @type event ::
          {:event, String.t(), String.t(), String.t()}
          | {:retry, non_neg_integer()}
          | {:last_event_id, String.t()}

  @type t :: %__MODULE__{
          buffer: binary(),
          bom_seen?: boolean(),
          data_parts: [binary()],
          event_type: String.t(),
          last_event_id: String.t(),
          id_changed?: boolean(),
          max_line_size: pos_integer()
        }

  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      max_line_size: Keyword.get(opts, :max_line_size, @default_max_line_size),
      last_event_id: Keyword.get(opts, :last_event_id, "")
    }
  end

  @spec parse(t(), binary()) :: {:ok, t(), [event()]} | {:error, term()}
  def parse(%__MODULE__{} = parser, data) when is_binary(data) do
    parser
    |> append(data)
    |> strip_bom()
    |> parse_lines([])
  end

  @spec close(t()) :: {:ok, t(), [event()]} | {:error, term()}
  def close(%__MODULE__{buffer: <<>>} = parser), do: {:ok, parser, []}

  def close(%__MODULE__{buffer: buffer} = parser) do
    parser =
      if :binary.last(buffer) == ?\r do
        %{parser | buffer: buffer <> "\n"}
      else
        parser
      end

    case parse_lines(parser, []) do
      {:ok, parser, events} -> {:ok, %{parser | buffer: <<>>}, events}
      {:error, _reason} = error -> error
    end
  end

  defp append(%__MODULE__{buffer: buffer} = parser, data), do: %{parser | buffer: buffer <> data}

  defp strip_bom(%__MODULE__{bom_seen?: true} = parser), do: {:ok, parser}

  defp strip_bom(%__MODULE__{buffer: <<@bom, rest::binary>>} = parser) do
    {:ok, %{parser | buffer: rest, bom_seen?: true}}
  end

  defp strip_bom(%__MODULE__{buffer: buffer} = parser) when byte_size(buffer) < 3 do
    if bytes_prefix?(@bom, buffer) do
      {:wait, parser}
    else
      {:ok, %{parser | bom_seen?: true}}
    end
  end

  defp strip_bom(%__MODULE__{} = parser), do: {:ok, %{parser | bom_seen?: true}}

  defp parse_lines({:wait, parser}, acc), do: {:ok, parser, Enum.reverse(acc)}
  defp parse_lines({:ok, parser}, acc), do: parse_lines(parser, acc)

  defp parse_lines(%__MODULE__{} = parser, acc) do
    case read_line(parser.buffer, parser.max_line_size) do
      {:ok, line, rest} ->
        with {:ok, parser, events} <- process_line(%{parser | buffer: rest}, line) do
          parse_lines(parser, Enum.reverse(events, acc))
        end

      :more ->
        {:ok, parser, Enum.reverse(acc)}

      {:error, _reason} = error ->
        error
    end
  end

  defp read_line(buffer, max_line_size) do
    case first_line_break(buffer) do
      nil ->
        if byte_size(buffer) > max_line_size do
          {:error, :line_too_long}
        else
          :more
        end

      {index, :cr} when index > max_line_size ->
        {:error, :line_too_long}

      {index, :lf} when index > max_line_size ->
        {:error, :line_too_long}

      {index, :cr} when index == byte_size(buffer) - 1 ->
        :more

      {index, :cr} ->
        line = binary_part(buffer, 0, index)

        rest =
          case binary_part(buffer, index + 1, 1) do
            "\n" -> binary_part(buffer, index + 2, byte_size(buffer) - index - 2)
            _other -> binary_part(buffer, index + 1, byte_size(buffer) - index - 1)
          end

        {:ok, line, rest}

      {index, :lf} ->
        line = binary_part(buffer, 0, index)
        rest = binary_part(buffer, index + 1, byte_size(buffer) - index - 1)
        {:ok, line, rest}
    end
  end

  defp first_line_break(buffer) do
    cr = :binary.match(buffer, "\r")
    lf = :binary.match(buffer, "\n")

    case {cr, lf} do
      {:nomatch, :nomatch} -> nil
      {{index, 1}, :nomatch} -> {index, :cr}
      {:nomatch, {index, 1}} -> {index, :lf}
      {{cr_index, 1}, {lf_index, 1}} when cr_index < lf_index -> {cr_index, :cr}
      {{_cr_index, 1}, {lf_index, 1}} -> {lf_index, :lf}
    end
  end

  defp process_line(parser, line) do
    cond do
      not String.valid?(line) ->
        {:error, :invalid_utf8}

      line == "" ->
        dispatch(parser)

      String.starts_with?(line, ":") ->
        {:ok, parser, []}

      true ->
        {field, value} = split_field(line)
        process_field(parser, field, value)
    end
  end

  defp split_field(line) do
    case :binary.match(line, ":") do
      {index, 1} ->
        field = binary_part(line, 0, index)
        value = binary_part(line, index + 1, byte_size(line) - index - 1)
        {field, strip_one_leading_space(value)}

      :nomatch ->
        {line, ""}
    end
  end

  defp strip_one_leading_space(<<" ", rest::binary>>), do: rest
  defp strip_one_leading_space(value), do: value

  defp process_field(parser, "event", value), do: {:ok, %{parser | event_type: value}, []}

  defp process_field(%__MODULE__{data_parts: parts} = parser, "data", value) do
    {:ok, %{parser | data_parts: [value <> "\n" | parts]}, []}
  end

  defp process_field(parser, "id", value) do
    if :binary.match(value, <<0>>) == :nomatch do
      {:ok, %{parser | last_event_id: value, id_changed?: true}, []}
    else
      {:ok, parser, []}
    end
  end

  defp process_field(parser, "retry", value) do
    if ascii_digits?(value) do
      {:ok, parser, [{:retry, String.to_integer(value)}]}
    else
      {:ok, parser, []}
    end
  end

  defp process_field(parser, _field, _value), do: {:ok, parser, []}

  defp dispatch(%__MODULE__{data_parts: [], id_changed?: true} = parser) do
    parser = %{parser | event_type: "", id_changed?: false}
    {:ok, parser, [{:last_event_id, parser.last_event_id}]}
  end

  defp dispatch(%__MODULE__{data_parts: []} = parser) do
    {:ok, %{parser | event_type: ""}, []}
  end

  defp dispatch(%__MODULE__{} = parser) do
    type = if parser.event_type == "", do: "message", else: parser.event_type

    data =
      parser.data_parts
      |> Enum.reverse()
      |> IO.iodata_to_binary()
      |> trim_final_lf()

    event = {:event, type, data, parser.last_event_id}

    parser = %{parser | data_parts: [], event_type: "", id_changed?: false}
    {:ok, parser, [event]}
  end

  defp trim_final_lf(<<>>), do: <<>>

  defp trim_final_lf(data) do
    if :binary.last(data) == ?\n do
      binary_part(data, 0, byte_size(data) - 1)
    else
      data
    end
  end

  defp ascii_digits?(""), do: false

  defp ascii_digits?(value) do
    value
    |> :binary.bin_to_list()
    |> Enum.all?(fn char -> char in ?0..?9 end)
  end

  defp bytes_prefix?(bytes, prefix) do
    prefix_size = byte_size(prefix)

    if prefix_size <= byte_size(bytes) do
      binary_part(bytes, 0, prefix_size) == prefix
    else
      false
    end
  end
end

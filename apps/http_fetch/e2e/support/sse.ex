defmodule E2E.SSE do
  @moduledoc """
  Minimal Server-Sent Events parser used by the e2e suite.

  SSE wire format (per the WHATWG spec) is line-oriented:

      id: 42
      event: tick
      data: {"n":1}
      data: line two

      id: 43
      event: tick
      data: {"n":2}

  A blank line (`\\n\\n`) terminates one event. Lines starting with `:` are
  comments and are dropped.
  """

  @type event :: %__MODULE__.Event{
          id: String.t() | nil,
          event: String.t() | nil,
          data: String.t()
        }

  defmodule Event do
    @moduledoc false
    defstruct id: nil, event: nil, data: ""
  end

  @doc """
  Parses an SSE response body into a list of `E2E.SSE.Event` structs.

  Multiple `data:` lines within a single event are joined with `\\n` per spec.

      iex> E2E.SSE.parse("id: 1\\nevent: tick\\ndata: hello\\n\\n")
      [%E2E.SSE.Event{id: "1", event: "tick", data: "hello"}]
  """
  @spec parse(String.t()) :: [event()]
  def parse(body) when is_binary(body) do
    body
    |> String.split("\n")
    |> Stream.chunk_by(&(&1 == ""))
    |> Stream.reject(&all_empty?/1)
    |> Enum.map(&event_from_lines/1)
  end

  defp all_empty?(lines), do: Enum.all?(lines, &(&1 == ""))

  defp event_from_lines(lines) do
    Enum.reduce(lines, %Event{}, fn line, acc ->
      cond do
        String.starts_with?(line, ":") ->
          acc

        String.starts_with?(line, "id:") ->
          %{acc | id: String.trim_leading(line, "id:") |> String.trim()}

        String.starts_with?(line, "event:") ->
          %{acc | event: String.trim_leading(line, "event:") |> String.trim()}

        String.starts_with?(line, "data:") ->
          piece = String.trim_leading(line, "data:") |> String.trim_leading()
          data = if acc.data == "", do: piece, else: acc.data <> "\n" <> piece
          %{acc | data: data}

        true ->
          acc
      end
    end)
  end
end

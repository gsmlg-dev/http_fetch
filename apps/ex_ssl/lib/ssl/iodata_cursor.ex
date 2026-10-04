defmodule SSL.IodataCursor do
  @moduledoc false

  @opaque t :: [iodata() | byte()]

  @spec new(iodata()) :: {:ok, t(), non_neg_integer()} | {:error, :badarg}
  def new(iodata) do
    {:ok, [iodata], :erlang.iolist_size(iodata)}
  rescue
    ArgumentError -> {:error, :badarg}
  end

  @spec next(t(), pos_integer()) :: :done | {:ok, binary(), t()}
  def next(cursor, maximum) when is_integer(maximum) and maximum > 0 do
    take(cursor, maximum, [], 0)
  end

  defp take([], _remaining, [], 0), do: :done

  defp take([], _remaining, chunks, _size),
    do: {:ok, IO.iodata_to_binary(Enum.reverse(chunks)), []}

  defp take(cursor, 0, chunks, _size),
    do: {:ok, IO.iodata_to_binary(Enum.reverse(chunks)), cursor}

  defp take([<<>> | rest], remaining, chunks, size),
    do: take(rest, remaining, chunks, size)

  defp take([binary | rest], remaining, chunks, size) when is_binary(binary) do
    if byte_size(binary) <= remaining do
      take(rest, remaining - byte_size(binary), [binary | chunks], size + byte_size(binary))
    else
      <<head::binary-size(^remaining), tail::binary>> = binary
      {:ok, IO.iodata_to_binary(Enum.reverse([head | chunks])), [tail | rest]}
    end
  end

  defp take([byte | rest], remaining, chunks, size) when is_integer(byte) and byte in 0..255,
    do: take(rest, remaining - 1, [<<byte>> | chunks], size + 1)

  defp take([[] | rest], remaining, chunks, size),
    do: take(rest, remaining, chunks, size)

  defp take([[head | tail] | rest], remaining, chunks, size),
    do: take([head, tail | rest], remaining, chunks, size)
end

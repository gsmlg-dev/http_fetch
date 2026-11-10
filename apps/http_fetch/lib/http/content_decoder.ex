defmodule HTTP.ContentDecoder do
  @moduledoc false

  alias HTTP.Headers

  # Decoders carry the remaining decoded-byte budget of one response body.
  # Inflation is incremental (`:zlib.safeInflate/2`), so a compressed body that
  # expands past the budget fails before the expansion is held in memory.
  @type t :: %{layers: [{String.t(), :zlib.zstream()}], remaining: non_neg_integer() | :infinity}

  def encodings(headers) do
    encodings =
      headers
      |> Headers.get_all("content-encoding")
      |> Enum.flat_map(&String.split(&1, ","))
      |> Enum.map(&(String.trim(&1) |> String.downcase()))

    if Enum.all?(encodings, &(&1 in ["gzip", "deflate", "identity"])) do
      encodings |> Enum.reject(&(&1 == "identity")) |> Enum.reverse()
    else
      []
    end
  end

  # Zlib handles belong to the calling process and must be closed on every exit.
  @spec open([String.t()], pos_integer() | :infinity) :: t()
  def open(encodings, limit \\ :infinity) do
    layers =
      Enum.map(encodings, fn encoding ->
        zlib = :zlib.open()
        {bits, eos} = if encoding == "gzip", do: {31, :reset}, else: {15, :error}
        :ok = :zlib.inflateInit(zlib, bits, eos)
        {encoding, zlib}
      end)

    %{layers: layers, remaining: limit}
  end

  @spec decode(t(), binary()) :: {:ok, binary(), t()} | {:error, term()}
  def decode(%{layers: []} = decoders, chunk), do: {:ok, chunk, decoders}

  def decode(%{layers: layers, remaining: remaining} = decoders, chunk) do
    result =
      Enum.reduce_while(layers, {:ok, chunk}, fn {encoding, zlib}, {:ok, bytes} ->
        case inflate(zlib, encoding, bytes, remaining) do
          {:ok, _decoded} = ok -> {:cont, ok}
          error -> {:halt, error}
        end
      end)

    with {:ok, decoded} <- result,
         do: {:ok, decoded, %{decoders | remaining: subtract(remaining, byte_size(decoded))}}
  end

  def finish(%{layers: layers}) do
    Enum.reduce_while(layers, :ok, fn {encoding, zlib}, :ok ->
      try do
        :ok = :zlib.inflateEnd(zlib)
        {:cont, :ok}
      catch
        :error, _reason -> {:halt, {:error, {:invalid_content_encoding, encoding}}}
      end
    end)
  end

  def close(%{layers: layers}),
    do: Enum.each(layers, fn {_encoding, zlib} -> :zlib.close(zlib) end)

  @spec buffered(Headers.t(), binary(), pos_integer() | :infinity) ::
          {:ok, binary()} | {:error, term()}
  def buffered(headers, body, limit \\ :infinity) do
    decoders = headers |> encodings() |> open(limit)

    try do
      with {:ok, decoded, decoders} <- decode(decoders, body),
           :ok <- finish(decoders) do
        {:ok, decoded}
      end
    after
      close(decoders)
    end
  end

  defp inflate(zlib, encoding, bytes, limit) do
    zlib |> :zlib.safeInflate(bytes) |> collect(zlib, limit, [], 0)
  catch
    :error, _reason -> {:error, {:invalid_content_encoding, encoding}}
  end

  defp collect({status, output}, zlib, limit, acc, size) when status in [:continue, :finished] do
    size = size + IO.iodata_length(output)
    acc = [acc | output]

    cond do
      limit != :infinity and size > limit -> {:error, :decoded_body_too_large}
      status == :finished -> {:ok, IO.iodata_to_binary(acc)}
      true -> zlib |> :zlib.safeInflate([]) |> collect(zlib, limit, acc, size)
    end
  end

  defp collect({:need_dictionary, _adler, _output}, _zlib, _limit, _acc, _size),
    do: :erlang.error(:need_dictionary)

  defp subtract(:infinity, _bytes), do: :infinity
  defp subtract(remaining, bytes), do: remaining - bytes
end

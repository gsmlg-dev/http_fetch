defmodule HTTP.ContentDecoder do
  @moduledoc false

  alias HTTP.Headers

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
  def open(encodings) do
    Enum.map(encodings, fn encoding ->
      zlib = :zlib.open()
      {bits, eos} = if encoding == "gzip", do: {31, :reset}, else: {15, :error}
      :ok = :zlib.inflateInit(zlib, bits, eos)
      {encoding, zlib}
    end)
  end

  def decode(decoders, chunk) do
    Enum.reduce_while(decoders, {:ok, chunk}, fn {encoding, zlib}, {:ok, bytes} ->
      try do
        {:cont, {:ok, zlib |> :zlib.inflate(bytes) |> IO.iodata_to_binary()}}
      catch
        :error, _reason -> {:halt, {:error, {:invalid_content_encoding, encoding}}}
      end
    end)
  end

  def finish(decoders) do
    Enum.reduce_while(decoders, :ok, fn {encoding, zlib}, :ok ->
      try do
        :ok = :zlib.inflateEnd(zlib)
        {:cont, :ok}
      catch
        :error, _reason -> {:halt, {:error, {:invalid_content_encoding, encoding}}}
      end
    end)
  end

  def close(decoders), do: Enum.each(decoders, fn {_encoding, zlib} -> :zlib.close(zlib) end)

  def buffered(headers, body) do
    decoders = headers |> encodings() |> open()

    try do
      with {:ok, decoded} <- decode(decoders, body),
           :ok <- finish(decoders) do
        {:ok, decoded}
      end
    after
      close(decoders)
    end
  end
end

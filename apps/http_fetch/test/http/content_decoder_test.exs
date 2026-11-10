defmodule HTTP.ContentDecoderTest do
  use ExUnit.Case, async: true

  alias HTTP.ContentDecoder
  alias HTTP.Headers

  # ~1 KiB of gzip that inflates to 1 MB of zeros.
  @plain :binary.copy(<<0>>, 1_000_000)

  defp headers(encoding), do: Headers.new([{"content-encoding", encoding}])

  defp raw_deflate(bytes) do
    zlib = :zlib.open()
    :ok = :zlib.deflateInit(zlib, :default, :deflated, -15, 8, :default)
    out = zlib |> :zlib.deflate(bytes, :finish) |> IO.iodata_to_binary()
    :zlib.close(zlib)
    out
  end

  for {encoding, encode} <- [{"gzip", &:zlib.gzip/1}, {"deflate", &:zlib.compress/1}] do
    test "buffered #{encoding} bomb stops at the decoded-size limit" do
      bomb = unquote(encode).(@plain)
      assert byte_size(bomb) < 2_000

      assert ContentDecoder.buffered(headers(unquote(encoding)), bomb, 100_000) ==
               {:error, :decoded_body_too_large}

      assert ContentDecoder.buffered(headers(unquote(encoding)), bomb, 1_000_000) ==
               {:ok, @plain}

      assert ContentDecoder.buffered(headers(unquote(encoding)), bomb, 999_999) ==
               {:error, :decoded_body_too_large}

      assert ContentDecoder.buffered(headers(unquote(encoding)), bomb, :infinity) ==
               {:ok, @plain}
    end

    test "streamed #{encoding} limit counts decoded bytes across chunks" do
      bomb = unquote(encode).(@plain)
      half = div(byte_size(bomb), 2)
      <<first::binary-size(half), second::binary>> = bomb
      decoders = ContentDecoder.open([unquote(encoding)], 600_000)

      try do
        assert {:ok, decoded, decoders} = ContentDecoder.decode(decoders, first)
        assert byte_size(decoded) <= 600_000
        assert {:error, :decoded_body_too_large} = ContentDecoder.decode(decoders, second)
      after
        ContentDecoder.close(decoders)
      end
    end
  end

  test "stacked encodings bound every decoding layer" do
    bomb = @plain |> :zlib.gzip() |> :zlib.compress()

    assert ContentDecoder.buffered(
             Headers.new([{"content-encoding", "gzip, deflate"}]),
             bomb,
             10_000
           ) == {:error, :decoded_body_too_large}
  end

  test "concatenated gzip members decode completely within the limit" do
    encoded = :zlib.gzip("one") <> :zlib.gzip("two")
    assert ContentDecoder.buffered(headers("gzip"), encoded, 6) == {:ok, "onetwo"}

    assert ContentDecoder.buffered(headers("gzip"), encoded, 5) ==
             {:error, :decoded_body_too_large}
  end

  test "raw (headerless) deflate is rejected before it can expand" do
    assert ContentDecoder.buffered(headers("deflate"), raw_deflate(@plain), 100_000) ==
             {:error, {:invalid_content_encoding, "deflate"}}
  end

  test "identity and undecoded bodies are not limited" do
    assert ContentDecoder.buffered(Headers.new(), @plain, 10) == {:ok, @plain}
    assert ContentDecoder.buffered(headers("br"), @plain, 10) == {:ok, @plain}
  end

  test "default limit is a multiple of the streaming threshold" do
    assert HTTP.Config.max_decoded_body_size() == 10 * HTTP.Config.streaming_threshold()
  end
end

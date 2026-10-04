defmodule SSL.Protocol.RecordFramerTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.RecordFramer

  test "returns a complete record exactly as encoded" do
    record = <<23, 3, 3, 0, 3, "abc">>

    assert {:ok, [^record], remainder} = RecordFramer.feed(RecordFramer.new(), record)
    assert RecordFramer.buffered_bytes(remainder) == <<>>
  end

  test "frames a record split at every byte boundary" do
    record = <<22, 3, 3, 0, 7, "payload">>

    for split <- 0..byte_size(record) do
      <<first::binary-size(^split), second::binary>> = record

      assert {[record], <<>>} == feed_chunks([first, second])
    end
  end

  test "returns multiple records and retains an incomplete trailing record" do
    first = <<22, 3, 3, 0, 1, 1>>
    second = <<23, 3, 3, 0, 2, 2, 3>>
    trailing = <<21, 3, 3, 0, 4, 4>>

    assert {:ok, [^first, ^second], remainder} =
             RecordFramer.feed(RecordFramer.new(), first <> second <> trailing)

    assert RecordFramer.buffered_bytes(remainder) == trailing
  end

  test "rejects a length beyond the TLSCiphertext default before buffering the body" do
    header = <<23, 3, 3, 16_641::16>>

    assert {:error, {:record_length_exceeded, 16_641, 16_640}} =
             RecordFramer.feed(<<>>, header)
  end

  test "applies the smaller TLSPlaintext limit to unencrypted record types" do
    header = <<22, 3, 3, 16_385::16>>

    assert {:error, {:record_length_exceeded, 16_385, 16_384}} =
             RecordFramer.feed(<<>>, header)
  end

  test "uses the configured maximum record length" do
    allowed = <<23, 3, 3, 0, 3, "abc">>
    oversized_header = <<23, 3, 3, 0, 4>>

    assert {:ok, [^allowed], remainder} =
             RecordFramer.feed(RecordFramer.new(), allowed, max_record_length: 3)

    assert RecordFramer.buffered_bytes(remainder) == <<>>

    assert {:error, {:record_length_exceeded, 4, 3}} =
             RecordFramer.feed(<<>>, oversized_header, max_record_length: 3)
  end

  test "does not let a configured maximum exceed protocol record limits" do
    ciphertext_header = <<23, 3, 3, 16_641::16>>
    plaintext_header = <<22, 3, 3, 16_385::16>>

    assert {:error, {:record_length_exceeded, 16_641, 16_640}} =
             RecordFramer.feed(<<>>, ciphertext_header, max_record_length: 0xFFFF)

    assert {:error, {:record_length_exceeded, 16_385, 16_384}} =
             RecordFramer.feed(<<>>, plaintext_header, max_record_length: 0xFFFF)
  end

  test "rejects malformed configured limits instead of disabling the bound" do
    for limit <- [nil, :infinity, "bad", -1] do
      assert {:error, {:invalid_limit, :max_record_length}} =
               RecordFramer.feed(<<>>, <<23, 3, 3, 0, 0>>, max_record_length: limit)
    end
  end

  test "retains an incomplete record in an opaque accumulator" do
    buffer = RecordFramer.new()

    assert {:ok, [], buffer} = RecordFramer.feed(buffer, <<23, 3, 3, 0, 3, "a">>)
    assert RecordFramer.buffered_size(buffer) == 6
    assert RecordFramer.buffered_bytes(buffer) == <<23, 3, 3, 0, 3, "a">>
  end

  property "frames randomly fragmented record streams" do
    check all(
            bodies <- list_of(binary(max_length: 64), min_length: 1, max_length: 6),
            chunk_sizes <- list_of(integer(1..17), min_length: 1, max_length: 32)
          ) do
      records = Enum.map(bodies, &<<23, 3, 3, byte_size(&1)::16, &1::binary>>)
      chunks = fragment(IO.iodata_to_binary(records), chunk_sizes)

      assert {records, <<>>} == feed_chunks(chunks)
    end
  end

  defp feed_chunks(chunks, opts \\ []) do
    {records, buffer} =
      Enum.reduce(chunks, {[], RecordFramer.new()}, fn chunk, {records, buffer} ->
        assert {:ok, complete, remainder} = RecordFramer.feed(buffer, chunk, opts)
        {records ++ complete, remainder}
      end)

    {records, RecordFramer.buffered_bytes(buffer)}
  end

  defp fragment(<<>>, _sizes), do: []
  defp fragment(data, []), do: [data]

  defp fragment(data, [size | sizes]) do
    take = min(size, byte_size(data))
    <<chunk::binary-size(^take), remainder::binary>> = data
    [chunk | fragment(remainder, sizes)]
  end
end

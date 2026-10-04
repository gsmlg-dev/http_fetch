defmodule SSL.Protocol.HandshakeFramerTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.HandshakeFramer

  test "returns a complete handshake message exactly as encoded" do
    message = <<1, 0, 0, 3, "abc">>

    assert {:ok, [^message], remainder} =
             HandshakeFramer.feed(HandshakeFramer.new(), message)

    assert HandshakeFramer.buffered_bytes(remainder) == <<>>
  end

  test "frames a handshake message split at every byte boundary" do
    message = <<8, 0, 0, 7, "payload">>

    for split <- 0..byte_size(message) do
      <<first::binary-size(^split), second::binary>> = message

      assert {[message], <<>>} == feed_chunks([first, second])
    end
  end

  test "returns multiple messages and retains an incomplete trailing message" do
    first = <<2, 0, 0, 1, 1>>
    second = <<8, 0, 0, 2, 2, 3>>
    trailing = <<11, 0, 0, 4, 4>>

    assert {:ok, [^first, ^second], remainder} =
             HandshakeFramer.feed(HandshakeFramer.new(), first <> second <> trailing)

    assert HandshakeFramer.buffered_bytes(remainder) == trailing
  end

  test "reads the handshake body length as a 24-bit integer" do
    body = :binary.copy(<<7>>, 65_536)
    message = <<11, 65_536::24, body::binary>>

    assert {:ok, [^message], remainder} =
             HandshakeFramer.feed(HandshakeFramer.new(), message)

    assert HandshakeFramer.buffered_bytes(remainder) == <<>>
  end

  test "rejects a length beyond the default before buffering the body" do
    header = <<11, 1_048_577::24>>

    assert {:error, {:handshake_length_exceeded, 1_048_577, 1_048_576}} =
             HandshakeFramer.feed(<<>>, header)
  end

  test "uses the configured maximum handshake length" do
    allowed = <<20, 0, 0, 3, "abc">>
    oversized_header = <<20, 0, 0, 4>>

    assert {:ok, [^allowed], remainder} =
             HandshakeFramer.feed(HandshakeFramer.new(), allowed, max_handshake_length: 3)

    assert HandshakeFramer.buffered_bytes(remainder) == <<>>

    assert {:error, {:handshake_length_exceeded, 4, 3}} =
             HandshakeFramer.feed(<<>>, oversized_header, max_handshake_length: 3)
  end

  test "rejects malformed configured limits instead of disabling the bound" do
    for limit <- [nil, :infinity, "bad", -1] do
      assert {:error, {:invalid_limit, :max_handshake_length}} =
               HandshakeFramer.feed(<<>>, <<1, 0, 0, 0>>, max_handshake_length: limit)
    end
  end

  test "retains an incomplete message in an opaque accumulator" do
    buffer = HandshakeFramer.new()

    assert {:ok, [], buffer} = HandshakeFramer.feed(buffer, <<1, 0, 0, 3, "a">>)
    assert HandshakeFramer.buffered_size(buffer) == 5
    assert HandshakeFramer.buffered_bytes(buffer) == <<1, 0, 0, 3, "a">>
  end

  property "frames randomly fragmented handshake streams" do
    check all(
            bodies <- list_of(binary(max_length: 64), min_length: 1, max_length: 6),
            chunk_sizes <- list_of(integer(1..17), min_length: 1, max_length: 32)
          ) do
      messages = Enum.map(bodies, &<<1, byte_size(&1)::24, &1::binary>>)
      chunks = fragment(IO.iodata_to_binary(messages), chunk_sizes)

      assert {messages, <<>>} == feed_chunks(chunks)
    end
  end

  defp feed_chunks(chunks, opts \\ []) do
    {messages, buffer} =
      Enum.reduce(chunks, {[], HandshakeFramer.new()}, fn chunk, {messages, buffer} ->
        assert {:ok, complete, remainder} = HandshakeFramer.feed(buffer, chunk, opts)
        {messages ++ complete, remainder}
      end)

    {messages, HandshakeFramer.buffered_bytes(buffer)}
  end

  defp fragment(<<>>, _sizes), do: []
  defp fragment(data, []), do: [data]

  defp fragment(data, [size | sizes]) do
    take = min(size, byte_size(data))
    <<chunk::binary-size(^take), remainder::binary>> = data
    [chunk | fragment(remainder, sizes)]
  end
end

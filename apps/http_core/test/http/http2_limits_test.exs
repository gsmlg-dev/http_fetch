defmodule HTTP.HTTP2LimitsTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2
  alias HTTP.HTTP2.{Frame, HPACK}

  test "rejects an oversized advertised frame before retaining its payload at every header split" do
    header = <<16_385::24, 0, 0, 1::32>>

    for split <- 1..8 do
      <<first::binary-size(split), rest::binary>> = header
      assert {:ok, conn, []} = HTTP2.stream(HTTP2.new(:get), first)
      assert {:error, :frame_size_error} = HTTP2.stream(conn, rest)
    end
  end

  test "bounds accumulated CONTINUATION fragments even without END_HEADERS" do
    fragment = :binary.copy(<<0>>, 16_384)
    assert {:ok, conn, []} = HTTP2.stream(HTTP2.new(:get), Frame.encode(:headers, 0, 1, fragment))

    conn =
      Enum.reduce(1..3, conn, fn _, conn ->
        assert {:ok, conn, []} = HTTP2.stream(conn, Frame.encode(:continuation, 0, 1, fragment))
        conn
      end)

    assert {:error, :header_block_too_large} =
             HTTP2.stream(conn, Frame.encode(:continuation, 0, 1, <<0>>))
  end

  test "accepts a bounded header block split over legal frames and TCP chunks" do
    value = :binary.copy("v", 20_000)

    block =
      HPACK.encode_headers([{":status", "200"}, {"x-large", value}]) |> IO.iodata_to_binary()

    <<first::binary-size(16_384), rest::binary>> = block
    wire = Frame.encode(:headers, 1, 1, first) <> Frame.encode(:continuation, 4, 1, rest)

    {conn, events} =
      for <<chunk::binary-size(1) <- wire>>, reduce: {HTTP2.new(:get), []} do
        {conn, events} ->
          assert {:ok, conn, next} = HTTP2.stream(conn, chunk)
          {conn, events ++ next}
      end

    assert HTTP2.complete_response?(conn)
    assert [{:headers, 200, headers}, :done] = events
    assert HTTP.Headers.get(headers, "x-large") == value
  end

  test "rejects whitespace around HTTP/2 Content-Length" do
    for value <- [" 2", "2 ", "\t2"] do
      frame =
        Frame.encode(
          :headers,
          4,
          1,
          HPACK.encode_headers([{":status", "200"}, {"content-length", value}])
        )

      assert {:error, :invalid_content_length} = HTTP2.stream(HTTP2.new(:get), frame)
    end
  end
end

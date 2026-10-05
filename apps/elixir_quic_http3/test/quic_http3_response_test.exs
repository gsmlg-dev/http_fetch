defmodule QuicHttp3.ResponseTest do
  use ExUnit.Case, async: true
  alias QuicHttp3.{Frame, Qpack, Response, Varint}

  defp headers(fields) do
    {:ok, block} = Qpack.encode_header_block(fields)
    Frame.encode!(:headers, block)
  end

  defp error(reason), do: {:error, {:http3_error, :stream, 0x10E, reason}}

  test "valid compression with invalid HTTP field names is a stream message error" do
    assert error(:invalid_header_name) ==
             Response.feed(Response.new(), Frame.encode!(:headers, <<0, 0, 0x21, "A", 0>>))
  end

  test "field-content rejects CTLs, DEL and edge whitespace, permits interior HTAB and obs-text" do
    for value <- [<<1>>, <<127>>, " leading", "trailing ", "\tleading", "trailing\t"] do
      assert error(:invalid_header_value) ==
               Response.feed(Response.new(), headers([{":status", "200"}, {"x", value}]))
    end

    for value <- ["", "a\tb", <<128, 255>>] do
      assert {:ok, _, _} =
               Response.feed(Response.new(), headers([{":status", "200"}, {"x", value}]))
    end
  end

  test "informational, final, body and trailers survive bytewise fragmentation" do
    bytes =
      headers([{":status", "103"}, {"link", "x"}]) <>
        headers([{":status", "200"}, {"content-length", "2"}]) <>
        Frame.encode!(:data, "ok") <> headers([{"x-trailer", "yes"}])

    {state, events} =
      Enum.reduce(:binary.bin_to_list(bytes), {Response.new(), []}, fn byte, {state, events} ->
        assert {:ok, next, emitted} = Response.feed(state, <<byte>>)
        {next, events ++ emitted}
      end)

    assert {:ok, state, [:done]} = Response.finish(state)
    assert state.phase == :done
    assert {:informational, 103, [{"link", "x"}]} in events
    assert {:headers, 200, [{"content-length", "2"}]} in events
    assert {:trailers, [{"x-trailer", "yes"}]} in events
    assert for({:data, bytes} <- events, do: bytes) |> IO.iodata_to_binary() == "ok"
  end

  test "DATA streams incrementally without retaining a declared large payload" do
    {:ok, state, _} = Response.feed(Response.new(), headers([{":status", "200"}]))
    prefix = Varint.encode!(0) <> Varint.encode!(10_000_000)
    assert {:ok, state, [{:data, "abc"}]} = Response.feed(state, prefix <> "abc")
    assert Response.retained_bytes(state) == 0

    assert {:error, {:http3_error, :connection, 0x106, :truncated_frame}} ==
             Response.finish(state)
  end

  test "unknown extension payload is discarded incrementally" do
    prefix = Varint.encode!(33) <> Varint.encode!(10_000_000)
    assert {:ok, state, []} = Response.feed(Response.new(), prefix <> "abc")
    assert Response.retained_bytes(state) == 0
  end

  test "complete HEADERS with incomplete QPACK is a structured connection error" do
    for payload <- [<<>>, <<0>>, <<0, 0, 0x21>>] do
      assert {:error, {:http3_error, :connection, 0x200, :malformed_qpack}} =
               Response.feed(Response.new(), Frame.encode!(:headers, payload))
    end
  end

  test "message ordering and end-of-stream are validated" do
    assert {:error, {:http3_error, :connection, 0x105, :data_before_final_headers}} ==
             Response.feed(Response.new(), Frame.encode!(:data, "x"))

    assert error(:missing_final_headers) == Response.finish(Response.new())
    {:ok, state, _} = Response.feed(Response.new(), headers([{":status", "103"}]))
    assert error(:missing_final_headers) == Response.finish(state)
    {:ok, state, _} = Response.feed(Response.new(), headers([{":status", "200"}]) <> headers([]))

    assert {:error, {:http3_error, :connection, 0x105, :data_after_trailers}} ==
             Response.feed(state, Frame.encode!(:data, "x"))
  end

  test "pseudo fields, status and forbidden fields are rejected" do
    for fields <- [
          [{":status", "101"}],
          [{":status", "600"}],
          [],
          [{":status", "200"}, {":status", "200"}],
          [{"x", "a"}, {":status", "200"}],
          [{":status", "200"}, {":path", "/"}],
          [{":status", "200"}, {"connection", "close"}]
        ] do
      assert {:error, {:http3_error, :stream, 0x10E, _}} =
               Response.feed(Response.new(), headers(fields))
    end
  end

  test "content length and bodyless responses are enforced" do
    {:ok, state, _} =
      Response.feed(Response.new(), headers([{":status", "200"}, {"content-length", "2"}]))

    assert error(:content_length_mismatch) == Response.finish(state)
    assert error(:content_length_mismatch) == Response.feed(state, Frame.encode!(:data, "abc"))

    for status <- ["204", "304"] do
      {:ok, state, _} = Response.feed(Response.new(), headers([{":status", status}]))
      assert error(:body_forbidden) == Response.feed(state, Frame.encode!(:data, "x"))
    end

    {:ok, state, _} =
      Response.feed(
        Response.new(method: :head),
        headers([{":status", "200"}, {"content-length", "99"}])
      )

    assert {:ok, _, [:done]} = Response.finish(state)
  end

  test "encoded and decoded header budgets and field counts are separate" do
    prefix = Varint.encode!(1) <> Varint.encode!(65_537)

    assert {:error, {:http3_error, :stream, 0x107, :encoded_headers_too_large}} =
             Response.feed(Response.new(), prefix)

    assert {:error, {:http3_error, :stream, 0x107, :decoded_headers_too_large}} =
             Response.feed(
               Response.new(max_header_bytes: 40),
               headers([{":status", "200"}, {"x", "12345"}])
             )

    assert {:error, {:http3_error, :stream, 0x107, :too_many_fields}} =
             Response.feed(Response.new(max_fields: 1), headers([{":status", "200"}, {"x", "y"}]))
  end

  test "known control and HTTP/2 frame types are forbidden on request streams" do
    for type <- [2, 3, 4, 6, 7, 8, 9, 13] do
      assert {:error, {:http3_error, :connection, 0x105, :forbidden_response_frame}} =
               Response.feed(Response.new(), Frame.encode!(type, <<>>))
    end

    assert {:error, {:http3_error, :connection, 0x108, :push_not_permitted}} =
             Response.feed(Response.new(), Frame.encode!(:push_promise, <<0>>))
  end
end

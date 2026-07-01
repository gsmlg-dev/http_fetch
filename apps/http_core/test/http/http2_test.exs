defmodule HTTP.HTTP2Test do
  use ExUnit.Case, async: true

  import Bitwise

  alias HTTP.HTTP2.Frame
  alias HTTP.HTTP2.HPACK

  @end_stream 0x1
  @ack 0x1
  @end_headers 0x4

  describe "serialize_request/1" do
    test "serializes the connection preface, settings, and request headers" do
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("http://example.com:8080/widgets?q=1"),
        headers: HTTP.Headers.new([{"Accept", "application/json"}, {"Connection", "close"}])
      }

      wire = request |> HTTP.HTTP2.serialize_request() |> IO.iodata_to_binary()
      preface = HTTP.HTTP2.connection_preface()
      preface_size = byte_size(preface)
      assert <<^preface::binary-size(preface_size), frames::binary>> = wire

      assert {:ok, %Frame{type: :settings, stream_id: 0, payload: ""}, frames} =
               Frame.decode(frames)

      assert {:ok,
              %Frame{
                type: :headers,
                stream_id: 1,
                flags: flags,
                payload: header_block
              }, ""} = Frame.decode(frames)

      assert (flags &&& @end_headers) == @end_headers
      assert (flags &&& @end_stream) == @end_stream

      assert {:ok, _decoder, headers} = HPACK.decode(HPACK.new_decoder(), header_block)

      assert {":method", "GET"} in headers
      assert {":scheme", "http"} in headers
      assert {":authority", "example.com:8080"} in headers
      assert {":path", "/widgets?q=1"} in headers
      assert {"accept", "application/json"} in headers
      assert Enum.any?(headers, &match?({"user-agent", _}, &1))
      refute Enum.any?(headers, &match?({"connection", _}, &1))
    end

    test "serializes request bodies as DATA frames" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        content_type: "text/plain",
        body: "hello"
      }

      wire = request |> HTTP.HTTP2.serialize_request() |> IO.iodata_to_binary()
      preface = HTTP.HTTP2.connection_preface()
      preface_size = byte_size(preface)
      <<^preface::binary-size(preface_size), frames::binary>> = wire
      {:ok, %Frame{type: :settings}, frames} = Frame.decode(frames)

      assert {:ok, %Frame{type: :headers, flags: flags, payload: header_block}, frames} =
               Frame.decode(frames)

      assert (flags &&& @end_headers) == @end_headers
      assert (flags &&& @end_stream) == 0

      assert {:ok, _decoder, headers} = HPACK.decode(HPACK.new_decoder(), header_block)
      assert {"content-type", "text/plain"} in headers
      assert {"content-length", "5"} in headers

      assert {:ok, %Frame{type: :data, flags: @end_stream, stream_id: 1, payload: "hello"}, ""} =
               Frame.decode(frames)
    end
  end

  describe "stream/2" do
    test "acks server settings and emits HTTP1-shaped response events" do
      conn = HTTP.HTTP2.new(:get)

      frames = [
        Frame.encode(:settings, 0, 0, ""),
        response_headers_frame([{":status", "200"}, {"content-length", "2"}]),
        Frame.encode(:data, @end_stream, 1, "ok")
      ]

      assert {:ok, conn, [{:headers, 200, headers}, {:body, "ok"}, :done]} =
               HTTP.HTTP2.stream(conn, IO.iodata_to_binary(frames))

      assert HTTP.Headers.get(headers, "content-length") == "2"

      {conn, outbound} = HTTP.HTTP2.take_outbound(conn)
      outbound = IO.iodata_to_binary(outbound)

      assert {:ok, %Frame{type: :settings, flags: flags, stream_id: 0, payload: ""}, outbound} =
               Frame.decode(outbound)

      assert (flags &&& @ack) == @ack
      outbound = assert_window_update(outbound, 0, 2)
      assert "" = assert_window_update(outbound, 1, 2)
      assert {^conn, []} = HTTP.HTTP2.take_outbound(conn)
    end

    test "combines HEADERS and CONTINUATION before decoding" do
      conn = HTTP.HTTP2.new(:get)
      header_block = HPACK.encode_headers([{":status", "204"}, {"x-test", "split"}])
      size = div(IO.iodata_length(header_block), 2)
      header_block = IO.iodata_to_binary(header_block)
      <<first::binary-size(size), second::binary>> = header_block

      frames = [
        Frame.encode(:headers, @end_stream, 1, first),
        Frame.encode(:continuation, @end_headers, 1, second)
      ]

      assert {:ok, _conn, [{:headers, 204, headers}, :done]} =
               HTTP.HTTP2.stream(conn, IO.iodata_to_binary(frames))

      assert HTTP.Headers.get(headers, "x-test") == "split"
    end

    test "decodes hpack static, dynamic, and huffman response headers" do
      decoder = HPACK.new_decoder()
      huffman_example = <<0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF>>

      block = [
        <<0x88>>,
        <<0x40, 0x06, "x-test", 0x03, "one">>,
        <<0xBE>>,
        <<0x00, 0x06, "x-host", 0x8C>>,
        huffman_example
      ]

      assert {:ok, _decoder,
              [
                {":status", "200"},
                {"x-test", "one"},
                {"x-test", "one"},
                {"x-host", "www.example.com"}
              ]} = HPACK.decode(decoder, IO.iodata_to_binary(block))
    end

    test "returns stream reset and goaway errors" do
      assert {:error, {:stream_reset, :cancel}} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 Frame.encode(:rst_stream, 0, 1, <<0x8::32>>)
               )

      assert {:error, {:goaway, :protocol_error, "debug"}} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 Frame.encode(:goaway, 0, 0, <<0::1, 0::31, 0x1::32, "debug">>)
               )
    end

    test "allows graceful goaway to drain stream 1" do
      frames = [
        response_headers_frame([{":status", "200"}, {"content-length", "2"}]),
        Frame.encode(:goaway, 0, 0, <<0::1, 1::31, 0x0::32, "drain">>),
        Frame.encode(:data, @end_stream, 1, "ok")
      ]

      assert {:ok, _conn, [{:headers, 200, _headers}, {:body, "ok"}, :done]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), IO.iodata_to_binary(frames))
    end

    test "rejects zero window update increments" do
      for stream_id <- [0, 1] do
        assert {:error, :invalid_window_update_increment} =
                 HTTP.HTTP2.stream(
                   HTTP.HTTP2.new(:get),
                   Frame.encode(:window_update, 0, stream_id, <<0::1, 0::31>>)
                 )
      end
    end
  end

  defp response_headers_frame(headers) do
    Frame.encode(:headers, @end_headers, 1, HPACK.encode_headers(headers))
  end

  defp assert_window_update(buffer, stream_id, increment) do
    assert {:ok,
            %Frame{
              type: :window_update,
              stream_id: ^stream_id,
              payload: <<0::1, received_increment::31>>
            }, rest} = Frame.decode(buffer)

    assert received_increment == increment
    rest
  end
end

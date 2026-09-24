defmodule HTTP.HTTP2Test do
  use ExUnit.Case, async: true

  import Bitwise

  alias HTTP.HTTP2.Frame
  alias HTTP.HTTP2.HPACK

  @end_stream 0x1
  @ack 0x1
  @end_headers 0x4
  @padded 0x8
  @initial_window_size 65_535
  @max_window_size 2_147_483_647

  describe "outbound_control_only?/1" do
    test "classifies only acknowledgements and window updates" do
      controls = [
        Frame.encode(:settings, @ack, 0, ""),
        Frame.encode(:ping, @ack, 0, "12345678"),
        Frame.encode(:window_update, 0, 1, <<0::1, 1::31>>)
      ]

      conn = %HTTP.HTTP2{outbound: controls}
      assert HTTP.HTTP2.outbound_control_only?(conn)
      assert HTTP.HTTP2.outbound_control_only?(%{conn | pending_body: "unsent"})

      for required <- [
            Frame.encode(:data, @end_stream, 1, "upload"),
            Frame.encode(:settings, 0, 0, ""),
            Frame.encode(:ping, 0, 0, "12345678")
          ] do
        refute HTTP.HTTP2.outbound_control_only?(%{conn | outbound: [required | controls]})
      end
    end
  end

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

    test "buffers request body bytes beyond the send window until WINDOW_UPDATE" do
      body = :binary.copy("x", @initial_window_size + 5)

      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        content_type: "text/plain",
        body: body
      }

      {conn, wire} = HTTP.HTTP2.prepare_request(HTTP.HTTP2.new(:post), request)
      wire = IO.iodata_to_binary(wire)
      preface = HTTP.HTTP2.connection_preface()
      preface_size = byte_size(preface)
      <<^preface::binary-size(preface_size), frames::binary>> = wire

      {:ok, %Frame{type: :settings}, frames} = Frame.decode(frames)
      {:ok, %Frame{type: :headers, flags: flags}, frames} = Frame.decode(frames)

      assert (flags &&& @end_stream) == 0

      data_frames = collect_data_frames(frames)
      assert data_payload(data_frames) == binary_part(body, 0, @initial_window_size)
      refute Enum.any?(data_frames, &Frame.flag?(&1.flags, @end_stream))

      {_conn, outbound} = HTTP.HTTP2.take_outbound(conn)
      assert [] = outbound

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(
                 conn,
                 Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>)
               )

      {_conn, outbound} = HTTP.HTTP2.take_outbound(conn)
      assert [] = outbound

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(
                 conn,
                 Frame.encode(:window_update, 0, 1, <<0::1, 5::31>>)
               )

      {_conn, outbound} = HTTP.HTTP2.take_outbound(conn)

      assert {:ok, %Frame{type: :data, flags: @end_stream, payload: "xxxxx"}, ""} =
               outbound |> IO.iodata_to_binary() |> Frame.decode()
    end

    test "raises for direct serialization when a request body needs flow-control state" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        body: :binary.copy("x", @initial_window_size + 1)
      }

      assert_raise ArgumentError, ~r/use prepare_request\/2/, fn ->
        HTTP.HTTP2.serialize_request(request)
      end
    end

    test "raises clearly for streaming request bodies" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        body: self(),
        duplex: :half
      }

      assert_raise ArgumentError, ~r/HTTP\/2 streaming request bodies are not supported/, fn ->
        HTTP.HTTP2.prepare_request(HTTP.HTTP2.new(:post), request)
      end
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

    test "rejects a final DATA frame shorter or longer than Content-Length" do
      for {declared_length, body} <- [{3, "ok"}, {2, "too"}] do
        frames = [
          response_headers_frame([
            {":status", "200"},
            {"content-length", Integer.to_string(declared_length)}
          ]),
          Frame.encode(:data, @end_stream, 1, body)
        ]

        assert {:error, :content_length_mismatch} =
                 HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), IO.iodata_to_binary(frames))
      end
    end

    test "rejects DATA exceeding Content-Length before END_STREAM" do
      frames = [
        response_headers_frame([{":status", "200"}, {"content-length", "2"}]),
        Frame.encode(:data, 0, 1, "too")
      ]

      assert {:error, :content_length_mismatch} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), IO.iodata_to_binary(frames))
    end

    test "rejects malformed and conflicting Content-Length response headers" do
      for headers <- [
            [{":status", "200"}, {"content-length", "two"}],
            [{":status", "200"}, {"content-length", "2"}, {"content-length", "3"}],
            [{":status", "200"}, {"content-length", String.duplicate("9", 21)}],
            [{":status", "200"}, {"content-length", "18446744073709551616"}]
          ] do
        assert {:error, :invalid_content_length} =
                 HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), response_headers_frame(headers))
      end
    end

    test "accepts the largest unsigned 64-bit Content-Length" do
      assert {:ok, %{expected_content_length: 18_446_744_073_709_551_615},
              [{:headers, 200, _headers}]} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 response_headers_frame([
                   {":status", "200"},
                   {"content-length", "18446744073709551615"}
                 ])
               )
    end

    test "rejects Content-Length on informational response headers" do
      assert {:error, :invalid_content_length} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 response_headers_frame([{":status", "100"}, {"content-length", "0"}])
               )
    end

    test "counts DATA payload without padding toward Content-Length" do
      frames = [
        response_headers_frame([{":status", "200"}, {"content-length", "2"}]),
        Frame.encode(:data, @padded ||| @end_stream, 1, <<2, "ok", 0, 0>>)
      ]

      assert {:ok, _conn, [{:headers, 200, _headers}, {:body, "ok"}, :done]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), IO.iodata_to_binary(frames))
    end

    test "validates Content-Length when trailers complete a streamed response" do
      headers = response_headers_frame([{":status", "200"}, {"content-length", "4"}])

      trailers =
        Frame.encode(
          :headers,
          @end_headers ||| @end_stream,
          1,
          HPACK.encode_headers([{"x-checksum", "ok"}])
        )

      assert {:ok, conn, [{:headers, 200, _headers}, {:body, "he"}]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), headers <> Frame.encode(:data, 0, 1, "he"))

      assert {:error, :content_length_mismatch} =
               HTTP.HTTP2.stream(conn, trailers)

      assert {:ok, conn, [{:headers, 200, _headers}, {:body, "four"}]} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 headers <> Frame.encode(:data, 0, 1, "four")
               )

      assert {:ok, _conn, [:done]} = HTTP.HTTP2.stream(conn, trailers)
    end

    test "rejects Content-Length in response trailers" do
      headers = response_headers_frame([{":status", "200"}, {"content-length", "2"}])

      trailers =
        Frame.encode(
          :headers,
          @end_headers ||| @end_stream,
          1,
          HPACK.encode_headers([{"content-length", "2"}])
        )

      assert {:ok, conn, [{:headers, 200, _headers}, {:body, "ok"}]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), headers <> Frame.encode(:data, 0, 1, "ok"))

      assert {:error, :invalid_response_trailers} = HTTP.HTTP2.stream(conn, trailers)
    end

    test "completes a Content-Length response streamed across calls" do
      headers = response_headers_frame([{":status", "200"}, {"content-length", "4"}])

      assert {:ok, conn, [{:headers, 200, _headers}, {:body, "he"}]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), headers <> Frame.encode(:data, 0, 1, "he"))

      assert {:ok, _conn, [{:body, "ll"}, :done]} =
               HTTP.HTTP2.stream(conn, Frame.encode(:data, @end_stream, 1, "ll"))
    end

    test "allows HEAD and 304 representation lengths without response content" do
      for {method, status} <- [{:head, "200"}, {:get, "304"}] do
        frame =
          Frame.encode(
            :headers,
            @end_headers ||| @end_stream,
            1,
            HPACK.encode_headers([{":status", status}, {"content-length", "10"}])
          )

        assert {:ok, _conn, [{:headers, _status, _headers}, :done]} =
                 HTTP.HTTP2.stream(HTTP.HTTP2.new(method), frame)
      end
    end

    test "rejects Content-Length on a 204 response" do
      assert {:error, :invalid_content_length} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 response_headers_frame([{":status", "204"}, {"content-length", "0"}])
               )
    end

    test "rejects nonempty DATA on a body-forbidden response" do
      headers = response_headers_frame([{":status", "204"}])

      assert {:ok, conn, [{:headers, 204, _headers}]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), headers)

      assert {:error, :invalid_response_body} =
               HTTP.HTTP2.stream(conn, Frame.encode(:data, @end_stream, 1, "nope"))
    end

    test "rejects DATA and HEADERS after response completion" do
      complete =
        Frame.encode(
          :headers,
          @end_headers ||| @end_stream,
          1,
          HPACK.encode_headers([{":status", "200"}])
        )

      assert {:ok, conn, [{:headers, 200, _headers}, :done]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), complete)

      for frame <- [
            Frame.encode(:data, @end_stream, 1, ""),
            response_headers_frame([{":status", "200"}])
          ] do
        assert {:error, :stream_closed} = HTTP.HTTP2.stream(conn, frame)
      end
    end

    test "combines HEADERS and CONTINUATION before decoding" do
      body = :binary.copy("x", @initial_window_size + 5)

      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        body: body
      }

      {conn, _wire} = HTTP.HTTP2.prepare_request(HTTP.HTTP2.new(:post), request)
      header_block = HPACK.encode_headers([{":status", "204"}, {"x-test", "split"}])
      size = div(IO.iodata_length(header_block), 2)
      header_block = IO.iodata_to_binary(header_block)
      <<first::binary-size(size), second::binary>> = header_block

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(conn, Frame.encode(:headers, @end_stream, 1, first))

      refute HTTP.HTTP2.complete_response?(conn)
      refute HTTP.HTTP2.request_stopped?(conn)
      assert conn.pending_body == "xxxxx"

      assert {:ok, conn, [{:headers, 204, headers}, :done]} =
               HTTP.HTTP2.stream(conn, Frame.encode(:continuation, @end_headers, 1, second))

      assert HTTP.Headers.get(headers, "x-test") == "split"
      assert HTTP.HTTP2.complete_response?(conn)
      assert HTTP.HTTP2.request_stopped?(conn)
    end

    test "does not complete a bodyless response until END_STREAM arrives" do
      assert {:ok, conn, [{:headers, 204, _headers}]} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 response_headers_frame([{":status", "204"}])
               )

      refute HTTP.HTTP2.complete_response?(conn)
      assert {:error, :closed} = HTTP.HTTP2.close(conn)

      assert {:ok, conn, [:done]} =
               HTTP.HTTP2.stream(conn, Frame.encode(:data, @end_stream, 1, ""))

      assert HTTP.HTTP2.complete_response?(conn)
    end

    test "stops an upload explicitly without discarding non-upload frames" do
      conn = %HTTP.HTTP2{
        pending_body: "unsent",
        outbound: [
          Frame.encode(:data, @end_stream, 1, "upload"),
          Frame.encode(:settings, @ack, 0, ""),
          Frame.encode(:settings, 0, 0, "")
        ]
      }

      conn = HTTP.HTTP2.stop_request(conn)
      {conn, outbound} = HTTP.HTTP2.take_outbound(conn)
      assert [] = conn.outbound

      assert {:ok, %Frame{type: :settings, flags: 0, payload: ""}, outbound} =
               outbound |> IO.iodata_to_binary() |> Frame.decode()

      assert {:ok, %Frame{type: :settings, flags: @ack, payload: ""}, ""} =
               Frame.decode(outbound)

      refute HTTP.HTTP2.outbound_control_only?(%{
               conn
               | outbound: [Frame.encode(:settings, 0, 0, "")]
             })

      refute HTTP.HTTP2.complete_response?(conn)
      assert HTTP.HTTP2.request_stopped?(conn)

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(
                 conn,
                 Frame.encode(:window_update, 0, 1, <<0::1, 1::31>>)
               )

      assert {^conn, []} = HTTP.HTTP2.take_outbound(conn)
    end

    test "stops a pending upload after an early final response and preserves control frames" do
      body = :binary.copy("x", @initial_window_size + 5)

      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        body: body
      }

      {conn, _wire} = HTTP.HTTP2.prepare_request(HTTP.HTTP2.new(:post), request)

      final_response =
        Frame.encode(
          :headers,
          @end_headers ||| @end_stream,
          1,
          HPACK.encode_headers([{":status", "200"}])
        )

      frames = [
        Frame.encode(:settings, 0, 0, ""),
        Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>),
        Frame.encode(:window_update, 0, 1, <<0::1, 5::31>>),
        final_response
      ]

      assert {:ok, conn, [{:headers, 200, _headers}, :done]} =
               HTTP.HTTP2.stream(conn, IO.iodata_to_binary(frames))

      assert HTTP.HTTP2.complete_response?(conn)

      {conn, outbound} = HTTP.HTTP2.take_outbound(conn)

      assert {:ok, %Frame{type: :settings, flags: flags, payload: ""}, ""} =
               outbound |> IO.iodata_to_binary() |> Frame.decode()

      assert (flags &&& @ack) == @ack
      assert HTTP.HTTP2.outbound_control_only?(conn)
      assert HTTP.HTTP2.request_stopped?(conn)

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(
                 conn,
                 IO.iodata_to_binary([
                   Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>),
                   Frame.encode(:window_update, 0, 1, <<0::1, 5::31>>)
                 ])
               )

      assert {^conn, []} = HTTP.HTTP2.take_outbound(conn)
    end

    test "does not restart an upload when WINDOW_UPDATE follows an early final response" do
      body = :binary.copy("x", @initial_window_size + 5)

      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        body: body
      }

      {conn, _wire} = HTTP.HTTP2.prepare_request(HTTP.HTTP2.new(:post), request)

      final_response =
        Frame.encode(
          :headers,
          @end_headers ||| @end_stream,
          1,
          HPACK.encode_headers([{":status", "200"}])
        )

      frames = [
        final_response,
        Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>),
        Frame.encode(:window_update, 0, 1, <<0::1, 5::31>>)
      ]

      assert {:ok, conn, [{:headers, 200, _headers}, :done]} =
               HTTP.HTTP2.stream(conn, IO.iodata_to_binary(frames))

      assert {_conn, []} = HTTP.HTTP2.take_outbound(conn)
      assert HTTP.HTTP2.request_stopped?(conn)
    end

    test "accepts NO_ERROR reset after a complete response without duplicate events" do
      final_headers =
        Frame.encode(
          :headers,
          @end_headers ||| @end_stream,
          1,
          HPACK.encode_headers([{":status", "200"}])
        )

      reset = Frame.encode(:rst_stream, 0, 1, <<0::32>>)

      assert {:ok, conn, [{:headers, 200, _headers}, :done]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), final_headers)

      assert HTTP.HTTP2.complete_response?(conn)
      assert {:ok, ^conn, []} = HTTP.HTTP2.stream(conn, reset)
      assert {:ok, ^conn, []} = HTTP.HTTP2.stream(conn, reset)

      assert {:ok, _conn, [{:headers, 200, _headers}, :done]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), final_headers <> reset)

      assert {:error, {:stream_reset, :no_error}} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 Frame.encode(:rst_stream, 0, 1, <<0::32>>)
               )
    end

    test "keeps an incomplete response reset as an error" do
      headers = response_headers_frame([{":status", "200"}])
      reset = Frame.encode(:rst_stream, 0, 1, <<0::32>>)

      assert {:ok, conn, [{:headers, 200, _headers}]} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), headers)

      refute HTTP.HTTP2.complete_response?(conn)
      assert {:error, {:stream_reset, :no_error}} = HTTP.HTTP2.stream(conn, reset)
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

    test "shrinks and restores the HPACK dynamic table without stale indexes" do
      decoder = HPACK.new_decoder()
      indexed = <<0x40, 0x06, "x-test", 0x03, "one">>

      assert {:ok, decoder, [{"x-test", "one"}]} = HPACK.decode(decoder, indexed)

      assert {:ok, decoder, []} = HPACK.decode(decoder, <<0x20>>)

      assert {:error, :invalid_hpack_index} =
               HPACK.decode(decoder, <<0xBE>>)

      restore = HPACK.encode_integer(4096, 5, 0x20)
      assert {:ok, decoder, []} = HPACK.decode(decoder, restore)

      assert {:ok, decoder, [{"x-test", "three"}]} =
               HPACK.decode(decoder, <<0x40, 0x06, "x-test", 0x05, "three">>)

      assert {:ok, _decoder, [{"x-test", "three"}]} = HPACK.decode(decoder, <<0xBE>>)
    end

    test "encodes profile HPACK indexing and Huffman policies" do
      {encoder, first} =
        HPACK.encode_headers(HPACK.new_encoder(), [{"x-test", "one"}],
          indexing: :incremental,
          huffman: :always
        )

      assert {:ok, _decoder, [{"x-test", "one"}]} = HPACK.decode(HPACK.new_decoder(), first)

      {_encoder, second} =
        HPACK.encode_headers(encoder, [{"x-test", "one"}], indexing: :incremental)

      assert second == <<0xBE>>

      {_encoder, sensitive} =
        HPACK.encode_headers(HPACK.new_encoder(), [{"authorization", "secret"}],
          indexing: :incremental,
          sensitive: ["authorization"]
        )

      <<first, _rest::binary>> = sensitive
      assert (first &&& 0xF0) == 0x10
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

    test "does not discard a reset following END_STREAM in the same batch" do
      frames = [
        response_headers_frame([{":status", "200"}, {"content-length", "2"}]),
        Frame.encode(:data, @end_stream, 1, "ok"),
        Frame.encode(:rst_stream, 0, 1, <<0x8::32>>)
      ]

      assert {:error, {:stream_reset, :cancel}} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), IO.iodata_to_binary(frames))
    end

    test "does not discard a protocol error following END_STREAM in the same batch" do
      frames = [
        response_headers_frame([{":status", "200"}, {"content-length", "2"}]),
        Frame.encode(:data, @end_stream, 1, "ok"),
        Frame.encode(:window_update, 0, 0, <<0::32>>)
      ]

      assert {:error, :invalid_window_update_increment} =
               HTTP.HTTP2.stream(HTTP.HTTP2.new(:get), IO.iodata_to_binary(frames))
    end

    test "rejects data before final response headers" do
      assert {:error, :data_before_response_headers} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 Frame.encode(:data, 0, 1, "body")
               )
    end

    test "ignores response trailers and completes the stream" do
      frames = [
        response_headers_frame([{":status", "200"}]),
        Frame.encode(:data, 0, 1, "ok"),
        Frame.encode(
          :headers,
          @end_headers ||| @end_stream,
          1,
          HPACK.encode_headers([{"x-checksum", "ok"}])
        )
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

    test "uses SETTINGS_INITIAL_WINDOW_SIZE changes when draining queued request body" do
      body = :binary.copy("x", @initial_window_size + 5)

      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://example.com/widgets"),
        body: body
      }

      {conn, _wire} = HTTP.HTTP2.prepare_request(HTTP.HTTP2.new(:post), request)

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(
                 conn,
                 Frame.encode(:window_update, 0, 0, <<0::1, 5::31>>)
               )

      settings = <<0x4::16, @initial_window_size + 5::32>>

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(conn, Frame.encode(:settings, 0, 0, settings))

      {_conn, outbound} = HTTP.HTTP2.take_outbound(conn)
      outbound = IO.iodata_to_binary(outbound)

      assert {:ok, %Frame{type: :settings, flags: flags}, outbound} = Frame.decode(outbound)
      assert (flags &&& @ack) == @ack

      assert {:ok, %Frame{type: :data, flags: @end_stream, payload: "xxxxx"}, ""} =
               Frame.decode(outbound)
    end

    test "rejects invalid peer flow-control settings" do
      assert {:error, :flow_control_error} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 Frame.encode(:settings, 0, 0, <<0x4::16, 2_147_483_648::32>>)
               )

      assert {:error, :protocol_error} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:get),
                 Frame.encode(:settings, 0, 0, <<0x5::16, 16_383::32>>)
               )
    end

    test "rejects settings that overflow the stream send window" do
      increment = @max_window_size - @initial_window_size

      assert {:ok, conn, []} =
               HTTP.HTTP2.stream(
                 HTTP.HTTP2.new(:post),
                 Frame.encode(:window_update, 0, 1, <<0::1, increment::31>>)
               )

      assert {:error, :flow_control_error} =
               HTTP.HTTP2.stream(
                 conn,
                 Frame.encode(:settings, 0, 0, <<0x4::16, @max_window_size::32>>)
               )
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

  defp collect_data_frames(buffer), do: collect_data_frames(buffer, [])

  defp collect_data_frames("", frames), do: Enum.reverse(frames)

  defp collect_data_frames(buffer, frames) do
    assert {:ok, %Frame{type: :data, stream_id: 1} = frame, rest} = Frame.decode(buffer)
    collect_data_frames(rest, [frame | frames])
  end

  defp data_payload(frames) do
    frames
    |> Enum.map(& &1.payload)
    |> IO.iodata_to_binary()
  end
end

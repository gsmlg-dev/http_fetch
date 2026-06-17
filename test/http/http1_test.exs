defmodule HTTP.HTTP1Test do
  use ExUnit.Case, async: true

  describe "serialize_request/1" do
    test "serializes path, query, host, connection, content headers, and body" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("http://example.com:8080/widgets?q=1"),
        headers: HTTP.Headers.new([{"Accept", "application/json"}]),
        content_type: "text/plain",
        body: "hello"
      }

      wire = request |> HTTP.HTTP1.serialize_request() |> IO.iodata_to_binary()

      assert wire =~ "POST /widgets?q=1 HTTP/1.1\r\n"
      assert wire =~ "Host: example.com:8080\r\n"
      assert wire =~ "Connection: close\r\n"
      assert wire =~ "Content-Type: text/plain\r\n"
      assert wire =~ "Content-Length: 5\r\n"
      assert String.ends_with?(wire, "\r\n\r\nhello")
    end

    test "serializes charlist content types" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("http://example.com/widgets"),
        headers: HTTP.Headers.new(),
        content_type: ~c"text/plain",
        body: "hello"
      }

      wire = request |> HTTP.HTTP1.serialize_request() |> IO.iodata_to_binary()

      assert wire =~ "Content-Type: text/plain\r\n"
    end

    test "rejects unsupported methods" do
      request = %HTTP.Request{
        method: "GET\r\nHost: attacker",
        url: URI.parse("http://example.com/"),
        headers: HTTP.Headers.new()
      }

      assert_raise ArgumentError, ~r/unsupported HTTP method/, fn ->
        HTTP.HTTP1.serialize_request(request)
      end
    end

    test "rejects header injection" do
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("http://example.com/"),
        headers: HTTP.Headers.new([{"X-Test", "ok\r\nInjected: yes"}])
      }

      assert_raise ArgumentError, ~r/invalid HTTP header value/, fn ->
        HTTP.HTTP1.serialize_request(request)
      end
    end

    test "rejects request target control characters" do
      request = %HTTP.Request{
        method: :get,
        url: %URI{scheme: "http", host: "example.com", path: "/ok\r\nInjected: yes"},
        headers: HTTP.Headers.new()
      }

      assert_raise ArgumentError,
                   ~r/request target contains invalid whitespace or control characters/,
                   fn ->
                     HTTP.HTTP1.serialize_request(request)
                   end
    end

    test "rejects request target spaces" do
      request = %HTTP.Request{
        method: :get,
        url: %URI{scheme: "http", host: "example.com", path: "/has space"},
        headers: HTTP.Headers.new()
      }

      assert_raise ArgumentError, ~r/request target contains invalid whitespace/, fn ->
        HTTP.HTTP1.serialize_request(request)
      end
    end

    test "rejects transfer-encoding request headers" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("http://example.com/widgets"),
        headers: HTTP.Headers.new([{"Transfer-Encoding", "chunked"}]),
        body: "hello"
      }

      assert_raise ArgumentError, ~r/Transfer-Encoding request headers are not supported/, fn ->
        HTTP.HTTP1.serialize_request(request)
      end
    end

    test "rejects trailer request headers" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("http://example.com/widgets"),
        headers: HTTP.Headers.new([{"Trailer", "X-Checksum"}]),
        body: "hello"
      }

      assert_raise ArgumentError, ~r/Trailer request headers are not supported/, fn ->
        HTTP.HTTP1.serialize_request(request)
      end
    end

    test "removes user content-length when no request body is sent" do
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("http://example.com/widgets"),
        headers: HTTP.Headers.new([{"Content-Length", "5"}])
      }

      wire = request |> HTTP.HTTP1.serialize_request() |> IO.iodata_to_binary()

      refute wire =~ "Content-Length:"
    end
  end

  describe "stream/2" do
    test "parses a content-length response split across packets" do
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, conn, [{:headers, 200, headers}, {:body, "he"}]} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe")

      assert HTTP.Headers.get(headers, "content-length") == "5"
      assert {:ok, _conn, [{:body, "llo"}, :done]} = HTTP.HTTP1.stream(conn, "llo")
    end

    test "decodes chunked responses split across chunk boundaries" do
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, conn, [{:headers, 200, headers}, {:body, "te"}]} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nte"
               )

      assert HTTP.Headers.get(headers, "transfer-encoding") == "chunked"

      assert {:ok, conn, [{:body, "st"}]} = HTTP.HTTP1.stream(conn, "st\r\n")

      assert {:ok, _conn, [{:body, "ing"}, :done]} =
               HTTP.HTTP1.stream(conn, "3\r\ning\r\n0\r\n\r\n")
    end

    test "waits for split chunk trailers" do
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, conn, [{:headers, 200, _headers}]} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
               )

      assert {:ok, _conn, [:done]} = HTTP.HTTP1.stream(conn, "\r\n")
    end

    test "emits oversized chunk bodies in bounded pieces" do
      body = String.duplicate("a", 70_000)
      chunk_size = body |> byte_size() |> Integer.to_string(16)
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, _conn, events} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" <>
                   chunk_size <> "\r\n" <> body <> "\r\n0\r\n\r\n"
               )

      chunks = for {:body, chunk} <- events, do: chunk

      assert length(chunks) > 1
      assert IO.iodata_to_binary(chunks) == body
      assert List.last(events) == :done
    end

    test "ignores informational responses before final response" do
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, _conn, [{:headers, 200, headers}, {:body, "ok"}, :done]} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
               )

      assert HTTP.Headers.get(headers, "content-length") == "2"
    end

    test "rejects invalid content-length responses" do
      conn = HTTP.HTTP1.new(:get)

      assert {:error, :invalid_content_length} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n")
    end

    test "rejects negative content-length responses" do
      conn = HTTP.HTTP1.new(:get)

      assert {:error, :invalid_content_length} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n")
    end

    test "rejects conflicting duplicate content-length responses" do
      conn = HTTP.HTTP1.new(:get)

      assert {:error, :invalid_content_length} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok"
               )
    end

    test "rejects comma-joined content-length responses" do
      conn = HTTP.HTTP1.new(:get)

      assert {:error, :invalid_content_length} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok"
               )
    end

    test "accepts matching duplicate content-length responses" do
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, _conn, [{:headers, 200, _headers}, {:body, "ok"}, :done]} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok"
               )
    end

    test "rejects truncated content-length responses on close" do
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, conn, [{:headers, 200, _headers}, {:body, "he"}]} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe")

      assert {:error, :closed} = HTTP.HTTP1.close(conn)
    end

    test "rejects oversized response headers" do
      conn = HTTP.HTTP1.new(:get)
      header_value = String.duplicate("a", 70_000)

      assert {:error, :headers_too_large} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 200 OK\r\nX-Large: #{header_value}\r\n\r\n")
    end

    test "rejects protocol switch responses" do
      conn = HTTP.HTTP1.new(:get)

      assert {:error, :unsupported_protocol_switch} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 101 Switching Protocols\r\n\r\n")
    end

    test "completes read-to-close responses on close" do
      conn = HTTP.HTTP1.new(:get)

      assert {:ok, conn, [{:headers, 200, _headers}, {:body, "partial"}]} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 200 OK\r\n\r\npartial")

      assert {:ok, _conn, [:done]} = HTTP.HTTP1.close(conn)
    end

    test "does not emit a body for HEAD responses" do
      conn = HTTP.HTTP1.new(:head)

      assert {:ok, _conn, [{:headers, 200, _headers}, :done]} =
               HTTP.HTTP1.stream(conn, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nignored")
    end
  end
end

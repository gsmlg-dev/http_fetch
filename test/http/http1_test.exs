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

      assert {:ok, conn, [{:headers, 200, headers}]} =
               HTTP.HTTP1.stream(
                 conn,
                 "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nte"
               )

      assert HTTP.Headers.get(headers, "transfer-encoding") == "chunked"

      assert {:ok, conn, [{:body, "test"}]} = HTTP.HTTP1.stream(conn, "st\r\n")

      assert {:ok, _conn, [{:body, "ing"}, :done]} =
               HTTP.HTTP1.stream(conn, "3\r\ning\r\n0\r\n\r\n")
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

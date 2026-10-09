defmodule HTTP.HTTP1TrailersTest do
  use ExUnit.Case, async: true

  test "retains fragmented ordered trailers before response completion" do
    {:ok, conn, [{:headers, 200, _}, {:body, "data"}]} =
      HTTP.HTTP1.stream(
        HTTP.HTTP1.new(:get),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n4\r\ndata\r\n0\r\nX-Check"
      )

    assert {:ok, conn, []} = HTTP.HTTP1.stream(conn, "sum: first\r\nX-Checksum: second\r\n")
    assert {:ok, _conn, [{:trailers, headers}, :done]} = HTTP.HTTP1.stream(conn, "\r\n")
    assert HTTP.Headers.to_list(headers) == [{"X-Checksum", "first"}, {"X-Checksum", "second"}]
  end

  test "permitted undeclared trailers are retained separately from headers" do
    assert {:ok, _conn, [{:headers, 200, initial}, {:trailers, trailers}, :done]} =
             parse("X-Checksum: undeclared\r\n")

    refute HTTP.Headers.has?(initial, "x-checksum")
    assert HTTP.Headers.get(trailers, "x-checksum") == "undeclared"
  end

  for field <-
        ~w(Content-Length Transfer-Encoding Host Connection Keep-Alive Trailer TE Upgrade
                  Authorization Proxy-Authorization Proxy-Authenticate WWW-Authenticate Cookie Set-Cookie
                  Content-Encoding Content-Type Content-Range Cache-Control Expect Max-Forwards Pragma Range) do
    test "rejects forbidden #{field} trailers" do
      field = unquote(field)
      assert {:error, {:forbidden_trailer, name}} = parse(field <> ": forbidden\r\n")
      assert name == String.downcase(field)
    end
  end

  test "rejects fields nominated by Connection" do
    assert {:error, {:forbidden_trailer, "x-hop"}} =
             parse("X-Hop: secret\r\n", "Connection: X-Hop\r\n")
  end

  for wire <- [
        "No-Colon\r\n",
        " X-Folded: value\r\n",
        "X : value\r\n",
        "X: a\nb\r\n",
        "X: a" <> <<0>> <> "b\r\n",
        ": value\r\n"
      ] do
    test "rejects malformed trailers #{inspect(wire)}" do
      assert {:error, :invalid_trailer} = parse(unquote(wire))
    end
  end

  test "enforces field count and serialized bytes at the boundary" do
    assert {:ok, _, _} = parse(String.duplicate("X: a\r\n", 128))
    assert {:error, :trailers_too_large} = parse(String.duplicate("X: a\r\n", 129))
    assert {:ok, _, _} = parse("X: " <> String.duplicate("a", 65_529) <> "\r\n")
    assert {:error, :trailers_too_large} = parse("X: " <> String.duplicate("a", 65_530) <> "\r\n")
  end

  test "caps an incomplete fragmented trailer block" do
    {:ok, conn, [{:headers, 200, _}]} =
      HTTP.HTTP1.stream(
        HTTP.HTTP1.new(:get),
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"
      )

    assert {:ok, conn, []} = HTTP.HTTP1.stream(conn, "X: " <> String.duplicate("a", 60_000))
    assert {:error, :trailers_too_large} = HTTP.HTTP1.stream(conn, String.duplicate("b", 6_000))
  end

  for declaration <- ["Host", "X-Checksum,", "Bad Field"] do
    test "rejects invalid declaration #{declaration}" do
      assert {:error, _} =
               parse("X-Checksum: ok\r\n", "Trailer: " <> unquote(declaration) <> "\r\n")
    end
  end

  test "validates upload declaration and preserves duplicate order" do
    initial = HTTP.Headers.new([{"Trailer", "X-Checksum"}])

    assert {:ok, headers} =
             HTTP.Trailers.upload([{"X-Checksum", "one"}, {"x-checksum", "two"}], initial)

    assert headers.headers == [{"X-Checksum", "one"}, {"x-checksum", "two"}]
    assert {:error, :undeclared_trailer} = HTTP.Trailers.upload([{"X-Other", "one"}], initial)

    assert {:error, :trailers_too_large} =
             HTTP.Trailers.declaration(
               HTTP.Headers.new([{"Trailer", String.duplicate("a", 65_537)}])
             )
  end

  defp parse(fields, initial \\ "") do
    HTTP.HTTP1.stream(
      HTTP.HTTP1.new(:get),
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" <>
        initial <> "\r\n0\r\n" <> fields <> "\r\n"
    )
  end
end

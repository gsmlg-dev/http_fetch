defmodule HTTP.ResponseHeaderLimitsTest do
  use ExUnit.Case, async: true

  defp parser(limits), do: apply(HTTP.HTTP1, :new, [:get, limits])

  defp wire(fields, status \\ "200 OK", body \\ ""),
    do: "HTTP/1.1 #{status}\r\n" <> Enum.join(fields, "\r\n") <> "\r\n\r\n" <> body

  test "an explicit larger budget accepts a head over 64 KiB and ignores same-read body bytes" do
    fields = [
      "Content-Length: 3" | for(n <- 1..18, do: "X-Pad-#{n}: " <> String.duplicate("a", 4096))
    ]

    bytes = wire(fields, "200 OK", "abc")
    assert {:error, :headers_too_large} = HTTP.HTTP1.stream(HTTP.HTTP1.new(:get), bytes)

    assert {:ok, _, [{:headers, 200, _}, {:body, "abc"}, :done]} =
             HTTP.HTTP1.stream(parser(max_head_bytes: 262_144), bytes)
  end

  test "complete wire head boundaries are exact and structured" do
    head = wire(["Content-Length: 0"])
    assert {:ok, _, _} = HTTP.HTTP1.stream(parser(max_head_bytes: byte_size(head)), head)

    assert {:error,
            {:response_header_limit,
             %{stage: :response, limit: :max_head_bytes, maximum: maximum, observed: observed}}} =
             HTTP.HTTP1.stream(parser(max_head_bytes: byte_size(head) - 1), head)

    assert maximum + 1 == observed
  end

  test "fields and field counts are bounded before a fragmented head completes" do
    assert {:error, {:response_header_limit, %{limit: :max_field_bytes}}} =
             HTTP.HTTP1.stream(parser(max_field_bytes: 8), "HTTP/1.1 200 OK\r\nX: 123456")

    assert {:error, {:response_header_limit, %{limit: :max_fields}}} =
             HTTP.HTTP1.stream(parser(max_fields: 1), "HTTP/1.1 200 OK\r\nX: 1\r\nY")
  end

  test "a field exactly at the limit tolerates a fragmented CRLF" do
    assert {:ok, conn, []} =
             HTTP.HTTP1.stream(
               parser(max_field_bytes: 17),
               "HTTP/1.1 200 OK\r\nContent-Length: 0\r"
             )

    assert {:ok, _, [{:headers, 200, _}, :done]} = HTTP.HTTP1.stream(conn, "\n\r\n")
  end

  test "complete fields count a bare trailing CR as a field byte" do
    for suffix <- ["\r\n\r\n", "\r\nY:b"] do
      assert {:error, {:response_header_limit, %{limit: :max_field_bytes, observed: 4}}} =
               HTTP.HTTP1.stream(parser(max_field_bytes: 3), "HTTP/1.1 200 OK\r\nX:a\r" <> suffix)
    end
  end

  test "independent callers retain different limits" do
    head = wire(["Content-Length: 0", "X: " <> String.duplicate("x", 100)])
    assert {:ok, _, _} = HTTP.HTTP1.stream(parser(max_head_bytes: 200), head)

    assert {:error, {:response_header_limit, %{limit: :max_head_bytes}}} =
             HTTP.HTTP1.stream(parser(max_head_bytes: 100), head)
  end

  test "informational counts and cumulative bytes cannot bypass a per-head bound" do
    hint = wire(["X: y"], "103 Early Hints")
    final = wire(["Content-Length: 0"])

    assert {:ok, _, [{:headers, 200, _}, :done]} =
             HTTP.HTTP1.stream(parser(max_informational_responses: 2), hint <> hint <> final)

    assert {:error, {:response_header_limit, %{limit: :max_informational_responses}}} =
             HTTP.HTTP1.stream(parser(max_informational_responses: 1), hint <> hint <> final)

    assert {:error, {:response_header_limit, %{limit: :max_informational_bytes}}} =
             HTTP.HTTP1.stream(
               parser(max_informational_bytes: byte_size(hint)),
               hint <> hint <> final
             )
  end

  test "configuration rejects unknown, nonpositive and infinite bounds" do
    for config <- [
          [unknown: 2],
          [max_head_bytes: 0],
          [max_fields: :infinity],
          [max_field_bytes: -1],
          [max_fields: 2, max_fields: 3]
        ] do
      assert_raise ArgumentError, fn -> parser(config) end
    end
  end
end

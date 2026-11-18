defmodule HTTP.HTTP1HeaderRetentionTest do
  use ExUnit.Case, async: true

  alias HTTP.{Headers, HTTP1}

  for framing <- [:content_length, :chunked, :eof] do
    test "#{framing} response fields own their bytes across read layouts" do
      body = String.duplicate("a", 8192)
      name = "X-" <> String.duplicate("Long-Name-", 10)
      value = String.duplicate("v", 100)

      fields = [
        {name, value},
        {name, String.duplicate("second", 20)},
        {"X-Empty", ""},
        {"X-Whitespace", "inside \t space"}
      ]

      {framing_fields, wire_body} =
        case unquote(framing) do
          :content_length -> {[{"Content-Length", "8192"}], body}
          :chunked -> {[{"Transfer-Encoding", "chunked"}], "2000\r\n" <> body <> "\r\n0\r\n\r\n"}
          :eof -> {[], body}
        end

      expected = framing_fields ++ fields

      head =
        "HTTP/1.1 200 OK\r\n" <>
          Enum.map_join(expected, fn {key, val} -> key <> ": \t" <> val <> " \t\r\n" end) <>
          "\r\n"

      <<prefix::binary-size(64), tail::binary>> = wire_body
      split = byte_size(head) - 3
      <<head_prefix::binary-size(^split), head_tail::binary>> = head

      for chunks <- [
            [head <> wire_body],
            [head, wire_body],
            [head <> prefix, tail],
            [head_prefix, head_tail <> prefix, tail]
          ] do
        {conn, events} =
          Enum.reduce(chunks, {HTTP1.new(:get), []}, fn bytes, {conn, events} ->
            assert {:ok, conn, next} = HTTP1.stream(conn, bytes)
            {conn, events ++ next}
          end)

        assert {:ok, %{state: :done} = conn, closing} = HTTP1.close(conn)
        assert [{:headers, 200, headers} | rest] = events ++ closing
        assert Headers.to_list(headers) == expected
        assert Headers.to_list(conn.headers) == expected
        assert IO.iodata_to_binary(for {:body, bytes} <- rest, do: bytes) == body
        assert Enum.count(rest, &(&1 == :done)) == 1
        assert [:done] = Enum.take(rest, -1)

        for {key, val} <- Headers.to_list(headers), field <- [val, key] do
          assert :binary.referenced_byte_size(field) == byte_size(field),
                 "response field retains unrelated read bytes: #{inspect(key)}"
        end
      end
    end
  end
end

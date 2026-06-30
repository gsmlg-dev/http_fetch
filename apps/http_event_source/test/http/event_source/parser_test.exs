defmodule HTTP.EventSource.ParserTest do
  use ExUnit.Case, async: true

  alias HTTP.EventSource.Parser

  test "parses multiline default messages with ids" do
    parser = Parser.new()

    assert {:ok, _parser, [{:event, "message", "first\nsecond", "1"}]} =
             Parser.parse(parser, "id: 1\ndata:first\ndata: second\n\n")
  end

  test "parses custom event types and empty data events" do
    parser = Parser.new()

    assert {:ok, _parser, events} =
             Parser.parse(parser, ": comment\nevent: add\ndata: 123\n\ndata\n\n")

    assert [
             {:event, "add", "123", ""},
             {:event, "message", "", ""}
           ] = events
  end

  test "supports retry fields and id-only blocks" do
    parser = Parser.new()

    assert {:ok, _parser, events} = Parser.parse(parser, "id: 2\n\nretry: 10\n\nretry: x\n\n")

    assert [
             {:last_event_id, "2"},
             {:retry, 10}
           ] = events
  end

  test "empty id resets the last event id" do
    parser = Parser.new(last_event_id: "old")

    assert {:ok, _parser, [{:event, "message", "reset", ""}]} =
             Parser.parse(parser, "id:\ndata: reset\n\n")
  end

  test "handles chunk boundaries and CRLF line endings" do
    parser = Parser.new()

    assert {:ok, parser, []} = Parser.parse(parser, "data: hel")
    assert {:ok, parser, []} = Parser.parse(parser, "lo\r")
    assert {:ok, _parser, [{:event, "message", "hello", ""}]} = Parser.parse(parser, "\n\r\n")
  end

  test "strips a leading UTF-8 BOM" do
    parser = Parser.new()

    assert {:ok, _parser, [{:event, "message", "ok", ""}]} =
             Parser.parse(parser, <<0xEF, 0xBB, 0xBF, "data: ok\n\n">>)
  end

  test "rejects invalid UTF-8 in completed lines" do
    parser = Parser.new()

    assert {:error, :invalid_utf8} = Parser.parse(parser, <<"data: ", 0xFF, "\n">>)
  end

  test "enforces max line size" do
    parser = Parser.new(max_line_size: 4)

    assert {:error, :line_too_long} = Parser.parse(parser, "data: too long")
  end
end

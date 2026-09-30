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

  test "bounds retained event bytes and parts across chunks" do
    parser = Parser.new(max_event_size: 8, max_event_parts: 3)
    assert {:ok, parser, []} = Parser.parse(parser, "data: ab\n")
    assert {:ok, parser, []} = Parser.parse(parser, "data: cd\n")
    assert {:error, :event_too_large} = Parser.parse(parser, "data: ef\n")

    parser = Parser.new(max_event_parts: 2)
    assert {:ok, parser, []} = Parser.parse(parser, "data:\ndata:\n")
    assert {:error, :too_many_event_parts} = Parser.parse(parser, "data:\n")
  end

  test "bounds metadata and unfinished input and resets data accounting on dispatch" do
    assert {:error, :event_too_large} =
             Parser.parse(Parser.new(max_event_size: 4), "event: abcde\n")

    assert {:error, :event_too_large} =
             Parser.parse(Parser.new(max_event_size: 4), "data:")

    assert {:ok, parser, [_first, _second]} =
             Parser.parse(Parser.new(max_event_size: 4), "data: ab\n\ndata: cd\n\n")

    assert parser.event_bytes == 0
    assert parser.event_parts == 0
  end

  test "copies retained fragments and discards an incomplete event at EOF" do
    assert {:ok, parser, []} = Parser.parse(Parser.new(), "data: hello\n")
    assert {:ok, parser, []} = Parser.close(parser)
    assert parser.data_parts == []
    assert parser.event_bytes == 0
  end

  test "rejects unsafe server cursors but preserves the NUL ignore policy" do
    assert {:error, :invalid_last_event_id} = Parser.parse(Parser.new(), "id: bad\tvalue\n")
    assert {:ok, parser, []} = Parser.parse(Parser.new(), <<"id: bad", 0, "value\n">>)
    assert parser.last_event_id == ""
  end

  test "enforces max line size" do
    parser = Parser.new(max_line_size: 4)

    assert {:error, :line_too_long} = Parser.parse(parser, "data: too long")
  end
end

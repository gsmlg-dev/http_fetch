defmodule E2E.SSETest do
  @moduledoc """
  Server-Sent Events (`text/event-stream`) round-trips.

  The test server emits a small batch of events with a 50ms delay between
  each so the parser can be exercised against a body that arrives in
  multiple chunks.
  """
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias E2E.ResponseView

  test "returns text/event-stream content type" do
    resp = E2E.Server.url("/sse?n=1") |> HTTP.fetch() |> HTTP.Promise.await()
    view = E2E.ResponseView.from(resp)
    assert view.status == 200
    assert E2E.ResponseView.get_header(view, "content-type") =~ "text/event-stream"
  end

  test "parses id, event, and data fields" do
    resp = E2E.Server.url("/sse?n=3") |> HTTP.fetch() |> HTTP.Promise.await()
    view = E2E.ResponseView.from(resp)

    events = E2E.ResponseView.sse_events(view)
    assert length(events) == 3
    [first, second, third] = events

    for ev <- [first, second, third] do
      assert ev.event == "tick"
    end

    assert first.id == "1"
    assert second.id == "2"
    assert third.id == "3"

    # Server emits two data: lines per event; the parser joins them with \n.
    [d1, d2] = String.split(first.data, "\n")
    assert d1 == ~s({"n":1})
    assert d2 == "line-two"
  end

  test "events have monotonically increasing ids" do
    resp = E2E.Server.url("/sse?n=5") |> HTTP.fetch() |> HTTP.Promise.await()
    view = E2E.ResponseView.from(resp)

    ids =
      E2E.ResponseView.sse_events(view)
      |> Enum.map(& &1.id)
      |> Enum.map(&String.to_integer/1)

    assert ids == Enum.to_list(1..5)
  end
end

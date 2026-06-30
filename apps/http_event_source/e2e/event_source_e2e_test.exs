defmodule E2E.EventSourceTest do
  @moduledoc """
  End-to-end tests for the browser-like EventSource API over local TCP streams.
  """

  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias HTTP.EventSource
  alias HTTP.EventSource.Event.Error
  alias HTTP.EventSource.Event.Message
  alias HTTP.EventSource.Event.Open

  test "receives custom events with multiline data" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(
        body: [
          "event: inventory\n",
          "id: 10\n",
          "data: {\"sku\":\"abc\"}\n",
          "data: stock=5\n\n"
        ],
        close: false
      )

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Open{}}, 1_000

    assert_receive {EventSource, ^source,
                    %Message{
                      type: "inventory",
                      data: "{\"sku\":\"abc\"}\nstock=5",
                      last_event_id: "10"
                    }},
                   1_000

    assert EventSource.last_event_id(source) == "10"
    assert :ok = EventSource.close(source)
  end

  test "reconnects and sends Last-Event-ID" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(
        responses: [
          [body: "id: 41\ndata: first\n\n"],
          [body: "data: second\n\n", close: false]
        ]
      )

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {:event_source_server_request, first_request}, 1_000
    refute first_request =~ "Last-Event-ID"
    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert_receive {EventSource, ^source, %Message{data: "first", last_event_id: "41"}}, 1_000
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 1_000

    assert_receive {:event_source_server_request, second_request}, 1_000
    assert second_request =~ "Last-Event-ID: 41"
    assert_receive {EventSource, ^source, %Open{}}, 1_000

    assert_receive {EventSource, ^source, %Message{data: "second", last_event_id: "41"}},
                   1_000

    assert :ok = EventSource.close(source)
  end
end

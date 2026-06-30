defmodule HTTP.EventSourceTest do
  use ExUnit.Case, async: true

  alias HTTP.EventSource
  alias HTTP.EventSource.Event.Error
  alias HTTP.EventSource.Event.Message
  alias HTTP.EventSource.Event.Open

  test "defines browser ready state constants" do
    assert EventSource.connecting() == 0
    assert EventSource.open() == 1
    assert EventSource.closed() == 2
  end

  test "connects, receives events, and closes" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(
        body: "event: add\nid: 1\ndata: 123\n\n",
        close: false
      )

    source =
      EventSource.new("http://127.0.0.1:#{port}/events",
        with_credentials: true,
        reconnect_time: 10
      )

    assert %EventSource{} = source
    assert EventSource.url(source) == "http://127.0.0.1:#{port}/events"
    assert EventSource.with_credentials(source) == true

    assert_receive {:event_source_server_request, request}, 1_000
    assert request =~ "Accept: text/event-stream"
    assert request =~ "Cache-Control: no-cache"

    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert EventSource.ready_state(source) == EventSource.open()

    assert_receive {EventSource, ^source, %Message{type: "add", data: "123", last_event_id: "1"}},
                   1_000

    assert EventSource.last_event_id(source) == "1"
    assert :ok = EventSource.close(source)
    assert EventSource.ready_state(source) == EventSource.closed()
    assert_receive :event_source_server_closed, 1_000
  end

  test "reconnects with last event id after EOF" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(
        responses: [
          [body: "id: 7\ndata: first\n\n"],
          [body: "data: second\n\n", close: false]
        ]
      )

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {:event_source_server_request, first_request}, 1_000
    refute first_request =~ "Last-Event-ID"
    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert_receive {EventSource, ^source, %Message{data: "first", last_event_id: "7"}}, 1_000
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 1_000

    assert_receive {:event_source_server_request, second_request}, 1_000
    assert second_request =~ "Last-Event-ID: 7"
    assert_receive {EventSource, ^source, %Open{}}, 1_000

    assert_receive {EventSource, ^source, %Message{data: "second", last_event_id: "7"}},
                   1_000

    assert :ok = EventSource.close(source)
  end

  test "stops on 204 responses" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(status: 204, content_type: nil, body: "")

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Error{reason: {:http_status, 204}}}, 1_000
    assert EventSource.ready_state(source) == EventSource.closed()
  end

  test "stops on invalid content type" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(content_type: "application/json", body: "{}")

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Error{reason: :invalid_content_type}}, 1_000
    assert EventSource.ready_state(source) == EventSource.closed()
  end

  test "honors retry fields from the stream" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(body: "retry: 25\ndata: ready\n\n", close: false)

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert_receive {EventSource, ^source, %Message{data: "ready"}}, 1_000
    assert EventSource.reconnect_time(source) == 25
    assert :ok = EventSource.close(source)
  end

  test "rejects invalid constructor input synchronously" do
    assert {:error, {:unsupported_scheme, "ftp"}} = EventSource.new("ftp://example.com/events")
  end
end

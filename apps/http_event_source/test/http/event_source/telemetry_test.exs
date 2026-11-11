defmodule HTTP.EventSource.TelemetryTest do
  use ExUnit.Case, async: false

  alias HTTP.EventSource.Telemetry

  test "emits lifecycle and message events" do
    test_pid = self()
    handler_id = "http-event-source-telemetry-test-#{System.unique_integer()}"

    events = [
      [:http_event_source, :connect, :start],
      [:http_event_source, :connect, :stop],
      [:http_event_source, :connect, :exception],
      [:http_event_source, :message, :received],
      [:http_event_source, :reconnect, :start],
      [:http_event_source, :reconnect, :stop],
      [:http_event_source, :close, :stop]
    ]

    :ok =
      :telemetry.attach_many(
        handler_id,
        events,
        &__MODULE__.handle_event/4,
        test_pid
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    uri = URI.parse("http://user:secret@example.com:8080/events?token=secret#hashpart")

    Telemetry.connect_start(uri)
    Telemetry.connect_stop(uri, 200, 10)
    Telemetry.connect_exception(uri, :closed, 11)
    Telemetry.message_received(uri, "message", "1", 5)
    Telemetry.reconnect_start(uri, :eof, 100, 1)
    Telemetry.reconnect_stop(uri, 1)
    Telemetry.close_stop(uri, :closed)

    for event <- events do
      assert_receive {:telemetry_event, ^event, _measurements, metadata}
      assert URI.to_string(metadata.url) == "http://example.com:8080/events"
      assert %URI{userinfo: nil, authority: nil, query: nil, fragment: nil} = metadata.url
      refute inspect(metadata) =~ "secret"
      refute inspect(metadata) =~ "hashpart"
    end
  end

  def handle_event(event, measurements, metadata, test_pid) do
    send(test_pid, {:telemetry_event, event, measurements, metadata})
  end
end

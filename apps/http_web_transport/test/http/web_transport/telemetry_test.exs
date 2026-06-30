defmodule HTTP.WebTransport.TelemetryTest do
  use ExUnit.Case, async: false

  alias HTTP.WebTransport.Telemetry

  test "emits lifecycle, datagram, and stream events" do
    test_pid = self()
    handler_id = "http-web-transport-telemetry-test-#{System.unique_integer()}"

    events = [
      [:http_web_transport, :connect, :start],
      [:http_web_transport, :connect, :stop],
      [:http_web_transport, :connect, :exception],
      [:http_web_transport, :session, :draining],
      [:http_web_transport, :session, :closed],
      [:http_web_transport, :session, :exception],
      [:http_web_transport, :datagram, :sent],
      [:http_web_transport, :datagram, :received],
      [:http_web_transport, :stream, :opened],
      [:http_web_transport, :stream, :sent],
      [:http_web_transport, :stream, :received],
      [:http_web_transport, :stream, :closed]
    ]

    :ok =
      :telemetry.attach_many(
        handler_id,
        events,
        &__MODULE__.handle_event/4,
        test_pid
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    uri = URI.parse("https://example.com/transport")

    Telemetry.connect_start(uri)
    Telemetry.connect_stop(uri, "chat.v1", "supports-unreliable", 10)
    Telemetry.connect_exception(uri, :closed, 11)
    Telemetry.session_draining(uri)
    Telemetry.session_closed(uri, 0, "done")
    Telemetry.session_exception(uri, :boom)
    Telemetry.datagram_sent(uri, 3, 0)
    Telemetry.datagram_received(uri, 4, 1)
    Telemetry.stream_opened(uri, 1, :bidirectional)
    Telemetry.stream_sent(uri, 1, 5)
    Telemetry.stream_received(uri, 1, 6)
    Telemetry.stream_closed(uri, 1)

    for event <- events do
      assert_receive {:telemetry_event, ^event, _measurements, _metadata}
    end
  end

  def handle_event(event, measurements, metadata, test_pid) do
    send(test_pid, {:telemetry_event, event, measurements, metadata})
  end
end

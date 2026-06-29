defmodule HTTP.WebSocket.TelemetryTest do
  use ExUnit.Case, async: false

  alias HTTP.WebSocket.Telemetry

  test "emits lifecycle and message events" do
    test_pid = self()
    handler_id = "http-web-socket-telemetry-test-#{System.unique_integer()}"

    events = [
      [:http_web_socket, :connect, :start],
      [:http_web_socket, :connect, :stop],
      [:http_web_socket, :connect, :exception],
      [:http_web_socket, :message, :received],
      [:http_web_socket, :message, :sent],
      [:http_web_socket, :close, :start],
      [:http_web_socket, :close, :stop]
    ]

    :ok =
      :telemetry.attach_many(
        handler_id,
        events,
        &__MODULE__.handle_event/4,
        test_pid
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    uri = URI.parse("ws://example.com/socket")

    Telemetry.connect_start(uri)
    Telemetry.connect_stop(uri, "chat", 10)
    Telemetry.connect_exception(uri, :closed, 11)
    Telemetry.message_received(uri, "text", 5)
    Telemetry.message_sent(uri, "text", 5, 0)
    Telemetry.close_start(uri, 1000)
    Telemetry.close_stop(uri, 1000, true)

    for event <- events do
      assert_receive {:telemetry_event, ^event, _measurements, _metadata}
    end
  end

  def handle_event(event, measurements, metadata, test_pid) do
    send(test_pid, {:telemetry_event, event, measurements, metadata})
  end
end

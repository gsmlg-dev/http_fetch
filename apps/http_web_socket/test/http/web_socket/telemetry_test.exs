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

    uri = URI.parse("ws://user:secret@example.com/socket?signature=hmac-value#token")

    Telemetry.connect_start(uri)
    Telemetry.connect_stop(uri, "chat", 10)
    Telemetry.connect_exception(uri, :closed, 11)
    Telemetry.message_received(uri, "text", 5)
    Telemetry.message_sent(uri, "text", 5, 0)
    Telemetry.close_start(uri, 1000)
    Telemetry.close_stop(uri, 1000, true)

    for event <- events do
      assert_receive {:telemetry_event, ^event, _measurements, metadata}
      assert URI.to_string(metadata.url) == "ws://example.com/socket"
      assert metadata.url.userinfo == nil
      assert metadata.url.authority == nil
      assert metadata.url.query == nil
      assert metadata.url.fragment == nil
    end
  end

  test "omission and replacement apply to every telemetry helper" do
    events = events()
    attach(events)

    for url <- [nil, URI.parse("ws://user:secret@127.0.0.1:8080?token=secret#secret")] do
      Telemetry.connect_start(url)
      Telemetry.connect_stop(url, "chat", 10, :http2, true)
      Telemetry.connect_exception(url, :closed, 11)
      Telemetry.message_received(url, "text", 5)
      Telemetry.message_sent(url, "text", 5, 0)
      Telemetry.close_start(url, 1000)
      Telemetry.close_stop(url, 1000, true)

      for event <- events do
        assert_receive {:telemetry_event, ^event, _measurements, metadata}
        assert_safe_metadata(metadata, url)
      end
    end
  end

  test "live connections redact telemetry while retaining the original handshake URL" do
    alias HTTP.WebSocket
    alias HTTP.WebSocket.Event.{Open, Message, Close}
    attach(events())

    for replacement <- [nil, URI.parse("ws://127.0.0.1:8080")] do
      {:ok, _server, port} = HTTPWebSocket.TestServer.start_link(open_message: "welcome")
      actual = "ws://127.0.0.1:#{port}/private-target?signature=secret"
      socket = WebSocket.new(actual, [], telemetry_url: replacement)
      assert_receive {WebSocket, ^socket, %Open{}}, 1_000
      assert_receive {:websocket_server_handshake, request}, 1_000
      assert request =~ "GET /private-target?signature=secret HTTP/1.1"
      assert WebSocket.url(socket) == actual
      assert_receive {WebSocket, ^socket, %Message{data: "welcome"}}, 1_000
      assert :ok = WebSocket.send(socket, "hello")
      assert_receive {WebSocket, ^socket, %Message{data: "echo:hello"}}, 1_000
      assert :ok = WebSocket.close(socket, 1000)
      assert_receive {WebSocket, ^socket, %Close{was_clean: true}}, 1_000

      for event <- events() -- [[:http_web_socket, :connect, :exception]] do
        assert_receive {:telemetry_event, ^event, _measurements, metadata}, 1_000
        assert_safe_metadata(metadata, replacement)
      end

      # The echo produces a second received event; consume it before the next connection.
      assert_receive {:telemetry_event, [:http_web_socket, :message, :received], _, metadata}
      assert_safe_metadata(metadata, replacement)
    end
  end

  defp events do
    for {group, names} <- [
          connect: [:start, :stop, :exception],
          message: [:received, :sent],
          close: [:start, :stop]
        ],
        name <- names,
        do: [:http_web_socket, group, name]
  end

  defp attach(events) do
    id = "telemetry-redaction-#{System.unique_integer()}"
    :ok = :telemetry.attach_many(id, events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(id) end)
  end

  defp assert_safe_metadata(metadata, nil) do
    refute Map.has_key?(metadata, :url)
    refute Map.has_key?(metadata, :scheme)
    refute Map.has_key?(metadata, :host)
    refute Map.has_key?(metadata, :port)
  end

  defp assert_safe_metadata(metadata, _url) do
    assert URI.to_string(metadata.url) == "ws://127.0.0.1:8080"
    assert metadata.url.path == nil
    assert metadata.url.query == nil
    assert metadata.url.userinfo == nil
    assert metadata.url.authority == nil
    assert metadata.url.fragment == nil
    if Map.has_key?(metadata, :port), do: assert(metadata.port == 8080)
  end

  def handle_event(event, measurements, metadata, test_pid) do
    send(test_pid, {:telemetry_event, event, measurements, metadata})
  end
end

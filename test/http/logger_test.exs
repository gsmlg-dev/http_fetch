defmodule HTTP.LoggerTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias HTTP.Logger
  alias HTTP.Telemetry

  setup do
    # It's already attached by the application, but we can re-attach for the test
    # to be sure. This is safe to do.
    Logger.attach()
    :ok
  end

  test "logs request start event" do
    log =
      capture_log(fn ->
        Telemetry.request_start("GET", URI.parse("http://example.com"), %{})
      end)

    assert log =~ "GET http://example.com - Request started"
  end

  test "logs request stop event" do
    log =
      capture_log(fn ->
        Telemetry.request_stop(200, URI.parse("http://example.com"), 1024, 123)
      end)

    assert log =~ "200 http://example.com - Request completed in 123µs"
  end

  test "logs request exception event" do
    log =
      capture_log(fn ->
        Telemetry.request_exception(URI.parse("http://example.com"), :timeout, 456)
      end)

    assert log =~ "Request to http://example.com failed: :timeout"
  end
end

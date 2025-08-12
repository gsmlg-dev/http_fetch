defmodule HTTP.TelemetryTest do
  use ExUnit.Case
  doctest HTTP.Telemetry

  setup do
    # Start telemetry event capture
    :telemetry.attach_many(
      "test_handler",
      [
        [:http_fetch, :request, :start],
        [:http_fetch, :request, :stop],
        [:http_fetch, :request, :exception],
        [:http_fetch, :response, :body_read_start],
        [:http_fetch, :response, :body_read_stop],
        [:http_fetch, :streaming, :start],
        [:http_fetch, :streaming, :chunk],
        [:http_fetch, :streaming, :stop]
      ],
      fn event_name, measurements, metadata, _config ->
        send(self(), {:telemetry_event, event_name, measurements, metadata})
      end,
      nil
    )

    on_exit(fn ->
      :telemetry.detach("test_handler")
    end)

    :ok
  end

  describe "request telemetry" do
    test "request_start emits telemetry event" do
      url = URI.parse("https://example.com")
      headers = HTTP.Headers.new([{"Content-Type", "application/json"}])

      HTTP.Telemetry.request_start("GET", url, headers)

      assert_receive {:telemetry_event, [:http_fetch, :request, :start], measurements, metadata}
      assert is_integer(measurements.start_time)
      assert metadata.method == "GET"
      assert metadata.url == url
      assert %HTTP.Headers{} = metadata.headers
    end

    test "request_stop emits telemetry event" do
      url = URI.parse("https://example.com")

      HTTP.Telemetry.request_stop(200, url, 1024, 1500)

      assert_receive {:telemetry_event, [:http_fetch, :request, :stop], measurements, metadata}
      assert measurements.duration == 1500
      assert measurements.status == 200
      assert measurements.response_size == 1024
      assert metadata.url == url
      assert metadata.status == 200
    end

    test "request_exception emits telemetry event" do
      url = URI.parse("https://example.com")

      HTTP.Telemetry.request_exception(url, :timeout, 5000)

      assert_receive {:telemetry_event, [:http_fetch, :request, :exception], measurements,
                      metadata}

      assert measurements.duration == 5000
      assert metadata.url == url
      assert metadata.error == :timeout
    end
  end

  describe "response telemetry" do
    test "response_body_read_start emits telemetry event" do
      HTTP.Telemetry.response_body_read_start(1024)

      assert_receive {:telemetry_event, [:http_fetch, :response, :body_read_start], measurements,
                      _metadata}

      assert measurements.content_length == 1024
    end

    test "response_body_read_stop emits telemetry event" do
      HTTP.Telemetry.response_body_read_stop(1024, 500)

      assert_receive {:telemetry_event, [:http_fetch, :response, :body_read_stop], measurements,
                      _metadata}

      assert measurements.bytes_read == 1024
      assert measurements.duration == 500
    end
  end

  describe "streaming telemetry" do
    test "streaming_start emits telemetry event" do
      HTTP.Telemetry.streaming_start(5_242_880)

      assert_receive {:telemetry_event, [:http_fetch, :streaming, :start], measurements,
                      _metadata}

      assert measurements.content_length == 5_242_880
    end

    test "streaming_chunk emits telemetry event" do
      HTTP.Telemetry.streaming_chunk(8192, 16384)

      assert_receive {:telemetry_event, [:http_fetch, :streaming, :chunk], measurements,
                      _metadata}

      assert measurements.bytes_received == 8192
      assert measurements.total_bytes == 16384
    end

    test "streaming_stop emits telemetry event" do
      HTTP.Telemetry.streaming_stop(5_242_880, 10000)

      assert_receive {:telemetry_event, [:http_fetch, :streaming, :stop], measurements, _metadata}
      assert measurements.total_bytes == 5_242_880
      assert measurements.duration == 10000
    end
  end
end

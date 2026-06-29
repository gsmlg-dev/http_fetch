defmodule HTTP.Telemetry do
  @moduledoc """
  Telemetry integration for comprehensive HTTP request and response monitoring.

  This module provides automatic telemetry event emission for all HTTP operations,
  enabling observability, metrics collection, and performance monitoring. All
  events use the `[:http_fetch, ...]` prefix.

  ## Automatic Events

  All `HTTP.fetch/2` operations automatically emit telemetry events. No
  configuration is required - simply attach handlers to receive events.

  ## Event Types

  ### Request Events

  **`[:http_fetch, :request, :start]`** - Emitted when a request begins

  - Measurements: `%{start_time: integer}` (microseconds)
  - Metadata: `%{method: atom, url: URI.t(), headers: HTTP.Headers.t()}`

  **`[:http_fetch, :request, :stop]`** - Emitted when a request completes successfully

  - Measurements: `%{duration: integer, status: integer, response_size: integer}`
    - `duration` - Request duration in microseconds
    - `status` - HTTP status code
    - `response_size` - Response body size in bytes
  - Metadata: `%{url: URI.t(), status: integer}`

  **`[:http_fetch, :request, :exception]`** - Emitted when a request fails

  - Measurements: `%{duration: integer}` (microseconds)
  - Metadata: `%{url: URI.t(), error: term()}`

  ### Streaming Events

  **`[:http_fetch, :streaming, :start]`** - Emitted when response streaming begins

  - Measurements: `%{content_length: integer}` (0 if unknown)
  - Metadata: `%{}`

  **`[:http_fetch, :streaming, :chunk]`** - Emitted for each stream chunk received

  - Measurements: `%{bytes_received: integer, total_bytes: integer}`
  - Metadata: `%{}`

  **`[:http_fetch, :streaming, :stop]`** - Emitted when streaming completes

  - Measurements: `%{total_bytes: integer, duration: integer}` (duration in microseconds)
  - Metadata: `%{}`

  ### Response Body Events

  **`[:http_fetch, :response, :body_read_start]`** - Emitted when reading response body

  - Measurements: `%{content_length: integer}`
  - Metadata: `%{}`

  **`[:http_fetch, :response, :body_read_stop]`** - Emitted when body read completes

  - Measurements: `%{bytes_read: integer, duration: integer}`
  - Metadata: `%{}`

  ## Usage Example

      # Attach a simple logger handler
      :telemetry.attach_many(
        "http-logger",
        [
          [:http_fetch, :request, :start],
          [:http_fetch, :request, :stop],
          [:http_fetch, :request, :exception]
        ],
        fn event_name, measurements, metadata, _config ->
          case event_name do
            [:http_fetch, :request, :start] ->
              IO.puts("Request started: " <> to_string(metadata.url))

            [:http_fetch, :request, :stop] ->
              duration_ms = measurements.duration / 1000
              IO.puts("Request completed in " <> Float.to_string(duration_ms) <> "ms")

            [:http_fetch, :request, :exception] ->
              IO.puts("Request failed: " <> inspect(metadata.error))
          end
        end,
        nil
      )

  ## Metrics Collection

      # Collect request duration metrics
      :telemetry.attach(
        "http-metrics",
        [:http_fetch, :request, :stop],
        fn _event, measurements, metadata, _config ->
          # Send to your metrics system
          MyMetrics.record_http_request(
            url: to_string(metadata.url),
            status: metadata.status,
            duration_us: measurements.duration
          )
        end,
        nil
      )

  ## Integration with Telemetry.Metrics

      # Define metrics for visualization
      import Telemetry.Metrics

      [
        # Request duration histogram
        distribution("http_fetch.request.duration",
          unit: {:native, :millisecond},
          tags: [:status]
        ),

        # Request count by status
        counter("http_fetch.request.count",
          tags: [:status]
        ),

        # Response size summary
        summary("http_fetch.request.response_size",
          unit: :byte
        ),

        # Streaming throughput
        distribution("http_fetch.streaming.chunk.bytes_received",
          unit: :byte
        )
      ]
  """

  @doc """
  Emits a telemetry event for request start.

  ## Examples
      iex> HTTP.Telemetry.request_start("GET", URI.parse("https://example.com"), %HTTP.Headers{})
      :ok
  """
  @spec request_start(String.t(), URI.t(), HTTP.Headers.t()) :: :ok
  def request_start(method, url, headers) do
    measurements = %{start_time: System.system_time(:microsecond)}

    metadata = %{
      method: method,
      url: url,
      headers: headers
    }

    :telemetry.execute([:http_fetch, :request, :start], measurements, metadata)
  end

  @doc """
  Emits a telemetry event for request completion.

  ## Examples
      iex> HTTP.Telemetry.request_stop(200, URI.parse("https://example.com"), 1024, 1500)
      :ok
  """
  @spec request_stop(integer(), URI.t(), integer(), integer()) :: :ok
  def request_stop(status, url, response_size, duration_us) do
    measurements = %{
      duration: duration_us,
      status: status,
      response_size: response_size
    }

    metadata = %{url: url, status: status}

    :telemetry.execute([:http_fetch, :request, :stop], measurements, metadata)
  end

  @doc """
  Emits a telemetry event for request failure.

  ## Examples
      iex> HTTP.Telemetry.request_exception(URI.parse("https://example.com"), :timeout, 5000)
      :ok
  """
  @spec request_exception(URI.t(), term(), integer()) :: :ok
  def request_exception(url, error, duration_us) do
    measurements = %{duration: duration_us}
    metadata = %{url: url, error: error}

    :telemetry.execute([:http_fetch, :request, :exception], measurements, metadata)
  end

  @doc """
  Emits a telemetry event for response body reading start.

  ## Examples
      iex> HTTP.Telemetry.response_body_read_start(1024)
      :ok
  """
  @spec response_body_read_start(integer()) :: :ok
  def response_body_read_start(content_length) do
    measurements = %{content_length: content_length}
    :telemetry.execute([:http_fetch, :response, :body_read_start], measurements, %{})
  end

  @doc """
  Emits a telemetry event for response body reading completion.

  ## Examples
      iex> HTTP.Telemetry.response_body_read_stop(1024, 500)
      :ok
  """
  @spec response_body_read_stop(integer(), integer()) :: :ok
  def response_body_read_stop(bytes_read, duration_us) do
    measurements = %{bytes_read: bytes_read, duration: duration_us}
    :telemetry.execute([:http_fetch, :response, :body_read_stop], measurements, %{})
  end

  @doc """
  Emits a telemetry event for streaming start.

  ## Examples
      iex> HTTP.Telemetry.streaming_start(5242880)
      :ok
  """
  @spec streaming_start(integer()) :: :ok
  def streaming_start(content_length) do
    measurements = %{content_length: content_length}
    :telemetry.execute([:http_fetch, :streaming, :start], measurements, %{})
  end

  @doc """
  Emits a telemetry event for streaming chunk received.

  ## Examples
      iex> HTTP.Telemetry.streaming_chunk(8192, 16384)
      :ok
  """
  @spec streaming_chunk(integer(), integer()) :: :ok
  def streaming_chunk(bytes_received, total_bytes) do
    measurements = %{
      bytes_received: bytes_received,
      total_bytes: total_bytes
    }

    :telemetry.execute([:http_fetch, :streaming, :chunk], measurements, %{})
  end

  @doc """
  Emits a telemetry event for streaming completion.

  ## Examples
      iex> HTTP.Telemetry.streaming_stop(5242880, 10000)
      :ok
  """
  @spec streaming_stop(integer(), integer()) :: :ok
  def streaming_stop(total_bytes, duration_us) do
    measurements = %{total_bytes: total_bytes, duration: duration_us}
    :telemetry.execute([:http_fetch, :streaming, :stop], measurements, %{})
  end
end

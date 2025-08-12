defmodule HTTP.Logger do
  @moduledoc """
  Attaches to HTTP telemetry events and logs them.
  """
  require Logger

  @doc """
  Attaches the logger to the telemetry events.
  """
  def attach do
    :telemetry.attach_many(
      "http-logger",
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
      &__MODULE__.handle_event/4,
      nil
    )
  end

  def handle_event([:http_fetch, :request, :start], _measurements, metadata, _config) do
    Logger.info(
      "#{metadata.method} #{metadata.url} - Request started",
      request_id: metadata.url
    )
  end

  def handle_event([:http_fetch, :request, :stop], measurements, metadata, _config) do
    Logger.info(
      "#{metadata.status} #{metadata.url} - Request completed in #{measurements.duration}µs",
      request_id: metadata.url,
      duration: measurements.duration,
      status: measurements.status,
      response_size: measurements.response_size
    )
  end

  def handle_event([:http_fetch, :request, :exception], measurements, metadata, _config) do
    Logger.error(
      "Request to #{metadata.url} failed: #{inspect(metadata.error)}",
      request_id: metadata.url,
      duration: measurements.duration,
      error: metadata.error
    )
  end

  def handle_event([:http_fetch, :response, :body_read_start], measurements, _metadata, _config) do
    Logger.debug(
      "Response body reading started. Content-Length: #{measurements.content_length}",
      content_length: measurements.content_length
    )
  end

  def handle_event([:http_fetch, :response, :body_read_stop], measurements, _metadata, _config) do
    Logger.debug(
      "Response body reading stopped. Bytes read: #{measurements.bytes_read} in #{measurements.duration}µs",
      bytes_read: measurements.bytes_read,
      duration: measurements.duration
    )
  end

  def handle_event([:http_fetch, :streaming, :start], measurements, _metadata, _config) do
    Logger.debug(
      "Streaming started. Content-Length: #{measurements.content_length}",
      content_length: measurements.content_length
    )
  end

  def handle_event([:http_fetch, :streaming, :chunk], measurements, _metadata, _config) do
    Logger.debug(
      "Streaming chunk received. Bytes: #{measurements.bytes_received}/#{measurements.total_bytes}",
      bytes_received: measurements.bytes_received,
      total_bytes: measurements.total_bytes
    )
  end

  def handle_event([:http_fetch, :streaming, :stop], measurements, _metadata, _config) do
    Logger.debug(
      "Streaming stopped. Total bytes: #{measurements.total_bytes} in #{measurements.duration}µs",
      total_bytes: measurements.total_bytes,
      duration: measurements.duration
    )
  end
end

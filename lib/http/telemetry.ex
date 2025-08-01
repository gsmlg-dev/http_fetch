defmodule HTTP.Telemetry do
  @moduledoc """
  Telemetry integration for HTTP fetch operations.

  Provides event tracking and metrics collection for HTTP requests and responses.
  """

  @doc """
  Emits a telemetry event for request start.

  ## Examples
      iex> HTTP.Telemetry.request_start("GET", URI.parse("https://example.com"), %HTTP.Headers{})
      :ok
  """
  @spec request_start(String.t(), URI.t(), HTTP.Headers.t()) :: :ok
  def request_start(method, url, headers) do
    measurements = %{start_time: System.system_time(:millisecond)}

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

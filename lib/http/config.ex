defmodule HTTP.Config do
  @moduledoc """
  Configuration module for HTTP fetch library.

  This module centralizes configuration values that control HTTP client behavior,
  including timeouts, streaming thresholds, and other runtime parameters.

  ## Configuration Values

  Configuration values can be overridden at runtime with application environment:

      config :http_fetch,
        streaming_threshold: 5_000_000,
        default_request_timeout: 120_000,
        streaming_timeout: 60_000

  ### Streaming Configuration

  - `streaming_threshold/0` - Size threshold (in bytes) above which responses are automatically streamed.
    Default: 5MB (5,000,000 bytes)

  ### Timeout Configuration

  - `default_request_timeout/0` - Maximum time (in milliseconds) to wait for a complete HTTP response.
    Default: 120 seconds (120,000 ms)

  - `streaming_timeout/0` - Maximum time (in milliseconds) to wait for streaming operations.
    Default: 60 seconds (60,000 ms)

  ## Usage

      # Check if response should be streamed
      if content_length > HTTP.Config.streaming_threshold() do
        # Stream the response
      end

      # Use default timeout
      receive do
        {:http, response} -> handle_response(response)
      after
        HTTP.Config.default_request_timeout() -> :timeout
      end
  """

  @streaming_threshold 5_000_000
  @default_request_timeout 120_000
  @streaming_timeout 60_000

  @doc """
  Returns the size threshold (in bytes) for automatic streaming.

  Responses with Content-Length greater than this value will be automatically
  streamed to avoid loading large files into memory.

  Default: 5MB (5,000,000 bytes)

  ## Examples

      iex> HTTP.Config.streaming_threshold()
      5_000_000
  """
  @spec streaming_threshold() :: non_neg_integer()
  def streaming_threshold do
    Application.get_env(:http_fetch, :streaming_threshold, @streaming_threshold)
  end

  @doc """
  Returns the default request timeout in milliseconds.

  This is the maximum time the HTTP client will wait for a complete response
  after sending a request.

  Default: 120 seconds (120,000 milliseconds)

  ## Examples

      iex> HTTP.Config.default_request_timeout()
      120_000
  """
  @spec default_request_timeout() :: non_neg_integer()
  def default_request_timeout do
    Application.get_env(:http_fetch, :default_request_timeout, @default_request_timeout)
  end

  @doc """
  Returns the streaming timeout in milliseconds.

  This is the maximum time to wait for streaming operations, including:
  - Waiting for stream chunks in `collect_stream/2`
  - Waiting for messages in the stream loop

  Default: 60 seconds (60,000 milliseconds)

  ## Examples

      iex> HTTP.Config.streaming_timeout()
      60_000
  """
  @spec streaming_timeout() :: non_neg_integer()
  def streaming_timeout do
    Application.get_env(:http_fetch, :streaming_timeout, @streaming_timeout)
  end
end

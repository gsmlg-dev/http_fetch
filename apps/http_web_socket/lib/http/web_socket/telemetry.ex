defmodule HTTP.WebSocket.Telemetry do
  @moduledoc """
  Telemetry helpers for WebSocket lifecycle and message events.

  Emitted URLs retain scheme, host, port, and path, but omit userinfo,
  authority, query, and fragment so URL credentials cannot reach handlers.
  """

  @spec connect_start(URI.t()) :: :ok
  def connect_start(url) do
    :telemetry.execute([:http_web_socket, :connect, :start], %{start_time: now()}, %{
      url: redact_url(url),
      scheme: url.scheme,
      host: url.host,
      port: url.port
    })
  end

  @spec connect_stop(URI.t(), String.t(), non_neg_integer()) :: :ok
  @spec connect_stop(URI.t(), String.t(), non_neg_integer(), :http1 | :http2, boolean()) :: :ok
  def connect_stop(url, protocol, duration, http_version \\ :http1, fallback \\ false) do
    :telemetry.execute([:http_web_socket, :connect, :stop], %{duration: duration}, %{
      url: redact_url(url),
      scheme: url.scheme,
      host: url.host,
      port: url.port,
      protocol: protocol,
      http_version: http_version,
      fallback: fallback
    })
  end

  @spec connect_exception(URI.t(), term(), non_neg_integer()) :: :ok
  def connect_exception(url, error, duration) do
    :telemetry.execute([:http_web_socket, :connect, :exception], %{duration: duration}, %{
      url: redact_url(url),
      scheme: url.scheme,
      host: url.host,
      port: url.port,
      error: error
    })
  end

  @spec message_received(URI.t(), String.t(), non_neg_integer()) :: :ok
  def message_received(url, opcode, bytes) do
    :telemetry.execute([:http_web_socket, :message, :received], %{bytes: bytes}, %{
      url: redact_url(url),
      opcode: opcode
    })
  end

  @spec message_sent(URI.t(), String.t(), non_neg_integer(), non_neg_integer()) :: :ok
  def message_sent(url, opcode, bytes, buffered_amount) do
    :telemetry.execute(
      [:http_web_socket, :message, :sent],
      %{bytes: bytes, buffered_amount: buffered_amount},
      %{url: redact_url(url), opcode: opcode}
    )
  end

  @spec close_start(URI.t(), non_neg_integer() | nil) :: :ok
  def close_start(url, code) do
    :telemetry.execute([:http_web_socket, :close, :start], %{start_time: now()}, %{
      url: redact_url(url),
      close_code: code
    })
  end

  @spec close_stop(URI.t(), non_neg_integer() | nil, boolean()) :: :ok
  def close_stop(url, code, was_clean) do
    :telemetry.execute([:http_web_socket, :close, :stop], %{}, %{
      url: redact_url(url),
      close_code: code,
      was_clean: was_clean
    })
  end

  defp redact_url(url),
    do: %{url | userinfo: nil, authority: nil, query: nil, fragment: nil}

  defp now, do: System.system_time(:microsecond)
end

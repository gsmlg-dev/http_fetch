defmodule HTTP.WebTransport.Telemetry do
  @moduledoc """
  Telemetry helpers for WebTransport lifecycle, datagram, and stream events.
  """

  @spec connect_start(URI.t()) :: :ok
  def connect_start(url) do
    :telemetry.execute([:http_web_transport, :connect, :start], %{start_time: now()}, %{
      url: url,
      scheme: url.scheme,
      host: url.host,
      port: url.port
    })
  end

  @spec connect_stop(URI.t(), String.t(), String.t(), non_neg_integer()) :: :ok
  def connect_stop(url, protocol, reliability, duration) do
    :telemetry.execute([:http_web_transport, :connect, :stop], %{duration: duration}, %{
      url: url,
      scheme: url.scheme,
      host: url.host,
      port: url.port,
      protocol: protocol,
      reliability: reliability
    })
  end

  @spec connect_exception(URI.t(), term(), non_neg_integer()) :: :ok
  def connect_exception(url, error, duration) do
    :telemetry.execute([:http_web_transport, :connect, :exception], %{duration: duration}, %{
      url: url,
      scheme: url.scheme,
      host: url.host,
      port: url.port,
      error: error
    })
  end

  @spec session_draining(URI.t()) :: :ok
  def session_draining(url) do
    :telemetry.execute([:http_web_transport, :session, :draining], %{}, %{url: url})
  end

  @spec session_closed(URI.t(), non_neg_integer(), String.t()) :: :ok
  def session_closed(url, close_code, reason) do
    :telemetry.execute([:http_web_transport, :session, :closed], %{}, %{
      url: url,
      close_code: close_code,
      reason: reason
    })
  end

  @spec session_exception(URI.t(), term()) :: :ok
  def session_exception(url, error) do
    :telemetry.execute([:http_web_transport, :session, :exception], %{}, %{
      url: url,
      error: error
    })
  end

  @spec datagram_sent(URI.t(), non_neg_integer(), non_neg_integer()) :: :ok
  def datagram_sent(url, bytes, queue_length) do
    :telemetry.execute(
      [:http_web_transport, :datagram, :sent],
      %{
        bytes: bytes,
        datagram_size: bytes,
        queue_length: queue_length
      },
      %{url: url}
    )
  end

  @spec datagram_received(URI.t(), non_neg_integer(), non_neg_integer()) :: :ok
  def datagram_received(url, bytes, queue_length) do
    :telemetry.execute(
      [:http_web_transport, :datagram, :received],
      %{
        bytes: bytes,
        datagram_size: bytes,
        queue_length: queue_length
      },
      %{url: url}
    )
  end

  @spec stream_opened(URI.t(), term(), atom()) :: :ok
  def stream_opened(url, stream_id, direction) do
    :telemetry.execute([:http_web_transport, :stream, :opened], %{}, %{
      url: url,
      stream_id: stream_id,
      direction: direction
    })
  end

  @spec stream_sent(URI.t(), term(), non_neg_integer()) :: :ok
  def stream_sent(url, stream_id, bytes) do
    :telemetry.execute([:http_web_transport, :stream, :sent], %{bytes: bytes}, %{
      url: url,
      stream_id: stream_id
    })
  end

  @spec stream_received(URI.t(), term(), non_neg_integer()) :: :ok
  def stream_received(url, stream_id, bytes) do
    :telemetry.execute([:http_web_transport, :stream, :received], %{bytes: bytes}, %{
      url: url,
      stream_id: stream_id
    })
  end

  @spec stream_closed(URI.t(), term()) :: :ok
  def stream_closed(url, stream_id) do
    :telemetry.execute([:http_web_transport, :stream, :closed], %{}, %{
      url: url,
      stream_id: stream_id
    })
  end

  defp now, do: System.system_time(:microsecond)
end

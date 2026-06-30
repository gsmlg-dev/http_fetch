defmodule HTTP.EventSource.Telemetry do
  @moduledoc """
  Telemetry helpers for EventSource lifecycle and message events.
  """

  @spec connect_start(URI.t()) :: :ok
  def connect_start(url) do
    :telemetry.execute([:http_event_source, :connect, :start], %{start_time: now()}, %{
      url: url,
      scheme: url.scheme,
      host: url.host,
      port: url.port
    })
  end

  @spec connect_stop(URI.t(), non_neg_integer(), non_neg_integer()) :: :ok
  def connect_stop(url, status, duration) do
    :telemetry.execute([:http_event_source, :connect, :stop], %{duration: duration}, %{
      url: url,
      scheme: url.scheme,
      host: url.host,
      port: url.port,
      status: status
    })
  end

  @spec connect_exception(URI.t(), term(), non_neg_integer()) :: :ok
  def connect_exception(url, error, duration) do
    :telemetry.execute([:http_event_source, :connect, :exception], %{duration: duration}, %{
      url: url,
      scheme: url.scheme,
      host: url.host,
      port: url.port,
      error: error
    })
  end

  @spec message_received(URI.t(), String.t(), String.t(), non_neg_integer()) :: :ok
  def message_received(url, event_type, last_event_id, bytes) do
    :telemetry.execute([:http_event_source, :message, :received], %{bytes: bytes}, %{
      url: url,
      event_type: event_type,
      last_event_id: last_event_id
    })
  end

  @spec reconnect_start(URI.t(), term(), non_neg_integer(), non_neg_integer()) :: :ok
  def reconnect_start(url, reason, reconnect_time, attempt) do
    :telemetry.execute(
      [:http_event_source, :reconnect, :start],
      %{reconnect_time: reconnect_time, attempt: attempt},
      %{url: url, error: reason}
    )
  end

  @spec reconnect_stop(URI.t(), non_neg_integer()) :: :ok
  def reconnect_stop(url, attempt) do
    :telemetry.execute([:http_event_source, :reconnect, :stop], %{attempt: attempt}, %{
      url: url
    })
  end

  @spec close_stop(URI.t(), term()) :: :ok
  def close_stop(url, reason) do
    :telemetry.execute([:http_event_source, :close, :stop], %{}, %{
      url: url,
      error: reason
    })
  end

  defp now, do: System.system_time(:microsecond)
end

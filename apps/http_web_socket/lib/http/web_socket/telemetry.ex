defmodule HTTP.WebSocket.Telemetry do
  @moduledoc """
  Telemetry helpers for WebSocket lifecycle and message events.

  Emitted URLs retain scheme, host, port, and path, but omit userinfo,
  authority, query, and fragment so URL credentials cannot reach handlers.
  A nil URL omits all URL-derived metadata.
  """

  @type url :: URI.t() | nil

  @spec connect_start(url()) :: :ok
  def connect_start(url) do
    :telemetry.execute(
      [:http_web_socket, :connect, :start],
      %{start_time: now()},
      connection_metadata(url)
    )
  end

  @spec connect_stop(url(), String.t(), non_neg_integer()) :: :ok
  @spec connect_stop(url(), String.t(), non_neg_integer(), :http1 | :http2, boolean()) :: :ok
  def connect_stop(url, protocol, duration, http_version \\ :http1, fallback \\ false) do
    :telemetry.execute(
      [:http_web_socket, :connect, :stop],
      %{duration: duration},
      Map.merge(connection_metadata(url), %{
        protocol: protocol,
        http_version: http_version,
        fallback: fallback
      })
    )
  end

  @spec connect_exception(url(), term(), non_neg_integer()) :: :ok
  def connect_exception(url, error, duration) do
    :telemetry.execute(
      [:http_web_socket, :connect, :exception],
      %{duration: duration},
      Map.put(connection_metadata(url), :error, error)
    )
  end

  @spec message_received(url(), String.t(), non_neg_integer()) :: :ok
  def message_received(url, opcode, bytes) do
    :telemetry.execute(
      [:http_web_socket, :message, :received],
      %{bytes: bytes},
      Map.put(url_metadata(url), :opcode, opcode)
    )
  end

  @spec message_sent(url(), String.t(), non_neg_integer(), non_neg_integer()) :: :ok
  def message_sent(url, opcode, bytes, buffered_amount) do
    :telemetry.execute(
      [:http_web_socket, :message, :sent],
      %{bytes: bytes, buffered_amount: buffered_amount},
      Map.put(url_metadata(url), :opcode, opcode)
    )
  end

  @spec close_start(url(), non_neg_integer() | nil) :: :ok
  def close_start(url, code) do
    :telemetry.execute(
      [:http_web_socket, :close, :start],
      %{start_time: now()},
      Map.put(url_metadata(url), :close_code, code)
    )
  end

  @spec close_stop(url(), non_neg_integer() | nil, boolean()) :: :ok
  def close_stop(url, code, was_clean) do
    :telemetry.execute(
      [:http_web_socket, :close, :stop],
      %{},
      Map.merge(url_metadata(url), %{close_code: code, was_clean: was_clean})
    )
  end

  defp connection_metadata(nil), do: %{}

  defp connection_metadata(url),
    do: Map.merge(url_metadata(url), %{scheme: url.scheme, host: url.host, port: url.port})

  defp url_metadata(nil), do: %{}

  defp url_metadata(url),
    do: %{url: %{url | userinfo: nil, authority: nil, query: nil, fragment: nil}}

  defp now, do: System.system_time(:microsecond)
end

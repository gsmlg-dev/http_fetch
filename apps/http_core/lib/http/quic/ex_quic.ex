defmodule HTTP.QUIC.ExQuic do
  @moduledoc false

  # Internal raw-stream client boundary. The optional driver argument is a test
  # seam; production always uses Quic. Handles and operation results are opaque
  # and are never rewritten, retried or interpreted as HTTP/3 success.
  alias HTTP.QUIC.TLSOptions

  def client(host, tls, options \\ [], driver \\ Quic) do
    with :ok <- endpoint_options(options),
         {:ok, tls} <- TLSOptions.normalize(host, tls) do
      driver.client(Keyword.put(options, :tls, tls))
    end
  end

  def local(endpoint, driver \\ Quic), do: driver.local(endpoint)

  def connect(endpoint, remote, options \\ [], driver \\ Quic),
    do: driver.connect(endpoint, remote, options)

  def attach(connection, consumer, options \\ [], driver \\ Quic),
    do: driver.attach(connection, consumer, options)

  def ready(connection, driver \\ Quic), do: driver.ready(connection)
  def info(connection, driver \\ Quic), do: driver.info(connection)
  def capabilities(driver \\ Quic), do: driver.capabilities()

  def open_stream(connection, kind, options \\ [], driver \\ Quic),
    do: driver.open_stream(connection, kind, options)

  def send_stream(stream, bytes, fin \\ false, options \\ [], driver \\ Quic)

  def send_stream(stream, bytes, fin, options, driver)
      when is_binary(bytes) and byte_size(bytes) <= 16_384 and is_boolean(fin),
      do: driver.send_stream(stream, bytes, fin, options)

  def send_stream(_stream, _bytes, _fin, _options, _driver),
    do: {:error, :invalid_write}

  def read(stream, max_bytes, options \\ [], driver \\ Quic)

  def read(stream, max_bytes, options, driver)
      when is_integer(max_bytes) and max_bytes in 1..16_384,
      do: driver.read(stream, max_bytes, options)

  def read(_stream, _max_bytes, _options, _driver), do: {:error, :invalid_read_limit}

  def events(connection, max \\ 32, options \\ [], driver \\ Quic)

  def events(connection, max, options, driver) when is_integer(max) and max in 1..128,
    do: driver.events(connection, max, options)

  def events(_connection, _max, _options, _driver), do: {:error, :invalid_event_limit}

  def reset_stream(stream, code, options \\ [], driver \\ Quic),
    do: driver.reset_stream(stream, code, options)

  def stop_stream(stream, code, options \\ [], driver \\ Quic),
    do: driver.stop_stream(stream, code, options)

  def close(connection, code \\ 0, reason \\ <<>>, options \\ [], driver \\ Quic),
    do: driver.close(connection, code, reason, options)

  def operation_status(target, ref, driver \\ Quic),
    do: driver.operation_status(target, ref)

  # Endpoint processes use standard OTP shutdown. Connection close above remains
  # distinct from endpoint shutdown and from per-stream cancellation.
  def stop_endpoint(endpoint), do: GenServer.stop(endpoint, :normal, 5_000)

  def normalize_message({:quic_ready, connection, metadata}, connection),
    do: {:ready, metadata}

  def normalize_message({:quic_closed, connection, reason}, connection),
    do: {:closed, reason}

  def normalize_message(_message, _connection), do: :unknown

  defp endpoint_options(options) do
    allowed = [:streams, :max_connections, :event_limit, :operation_limit]

    if Keyword.keyword?(options) and
         length(Keyword.keys(options)) == length(Enum.uniq(Keyword.keys(options))) and
         Enum.all?(options, fn {key, _} -> key in allowed end) do
      :ok
    else
      {:error, {:options, :invalid_endpoint_options}}
    end
  end
end

defmodule QuicHttp3.Transport.Quic do
  @moduledoc """
  Adapter from the HTTP/3 transport contract to public `elixir_quic` APIs.

  A connection retains its endpoint explicitly. Closing a connection does not
  implicitly terminate the endpoint; callers use `stop_endpoint/1` when the
  endpoint is no longer needed.
  """

  @behaviour QuicHttp3.Transport

  defstruct [:endpoint, :handle, :ops]

  defmodule Stream do
    @moduledoc false
    defstruct [:handle, :ops]
  end

  @default_datagram [max_frame_size: 1200, max_items: 64, max_buffer_bytes: 65_536]
  @max_stream_bytes 16_384
  @max_events 128

  @impl true
  def client(options) when is_list(options) do
    {ops, options} = Keyword.pop(options, :ops, Quic)

    with {:ok, profile} <- profile(options),
         {:ok, datagram} <- datagram_options(Keyword.get(options, :datagram, @default_datagram)) do
      ops.client(endpoint_options(options, profile, datagram))
    end
  end

  def client(_), do: {:error, :invalid_options}

  @impl true
  def connect(remote, port, options) when is_list(options) and is_integer(port) do
    {ops, options} = Keyword.pop(options, :ops, Quic)
    {injected_endpoint, options} = Keyword.pop(options, :endpoint)

    with {:ok, profile} <- profile(options),
         {:ok, datagram} <- datagram_options(Keyword.get(options, :datagram, @default_datagram)),
         {:ok, normalized_remote} <- normalize_remote(remote, port),
         {:ok, endpoint, owned?} <-
           start_endpoint(ops, injected_endpoint, options, profile, datagram),
         result <- ops.connect(endpoint, normalized_remote, connect_options(options)) do
      case result do
        {:ok, handle} ->
          {:ok, %__MODULE__{endpoint: endpoint, handle: handle, ops: ops}}

        failure ->
          if owned?, do: stop_owned_endpoint(ops, endpoint)
          failure
      end
    end
  end

  def connect(_, _, _), do: {:error, :invalid_remote}

  @impl true
  def ready(%__MODULE__{handle: handle, ops: ops}, _timeout), do: ops.ready(handle)

  @impl true
  def open_stream(%__MODULE__{handle: handle, ops: ops}, kind, options) do
    case ops.open_stream(handle, kind, options) do
      {:ok, stream} -> {:ok, %Stream{handle: stream, ops: ops}}
      result -> result
    end
  end

  @impl true
  def send_stream(%Stream{handle: stream, ops: ops}, bytes, fin, options)
      when is_binary(bytes) and byte_size(bytes) <= @max_stream_bytes and is_boolean(fin),
      do: ops.send_stream(stream, bytes, fin, options)

  def send_stream(_, _, _, _), do: {:error, :invalid_write}

  @impl true
  def read(%Stream{handle: stream, ops: ops}, max, options)
      when is_integer(max) and max in 1..@max_stream_bytes,
      do: ops.read(stream, max, options)

  def read(_, _, _), do: {:error, :invalid_read_limit}

  @impl true
  def events(%__MODULE__{handle: handle, ops: ops}, max, options)
      when is_integer(max) and max in 1..@max_events,
      do: ops.events(handle, max, options)

  def events(_, _, _), do: {:error, :invalid_event_limit}

  @impl true
  def reset_stream(%Stream{handle: stream, ops: ops}, code, options),
    do: ops.reset_stream(stream, code, options)

  @impl true
  def stop_stream(%Stream{handle: stream, ops: ops}, code, options),
    do: ops.stop_stream(stream, code, options)

  @impl true
  def close(%__MODULE__{handle: handle, ops: ops}, code, reason, options),
    do: ops.close(handle, code, reason, options)

  @impl true
  def send_datagram(%__MODULE__{handle: handle, ops: ops}, bytes, options) when is_binary(bytes),
    do: ops.send_datagram(handle, bytes, options)

  def send_datagram(_, _, _), do: {:error, :invalid_datagram}

  @impl true
  def read_datagrams(%__MODULE__{handle: handle, ops: ops}, max, options)
      when is_integer(max) and max in 1..@max_events,
      do: ops.read_datagrams(handle, max, options)

  def read_datagrams(_, _, _), do: {:error, :invalid_datagram_limit}

  @impl true
  def stop_endpoint(endpoint) when is_pid(endpoint), do: GenServer.stop(endpoint, :normal, 5_000)
  def stop_endpoint(_), do: {:error, :invalid_endpoint}

  @impl true
  def capabilities do
    Quic.capabilities()
    |> Map.merge(%{alpn: "h3", datagram: true})
  end

  defp profile(options) do
    name = Keyword.get(options, :profile, :ordered)
    alpn = Keyword.get(options, :alpn, ["h3"])

    if name in [:ordered, :compact] and is_list(alpn) do
      apply(Quic.Profile, :compile, [name, [alpn: alpn]])
    else
      {:error, {:invalid_profile, name}}
    end
  end

  defp datagram_options(value) when is_list(value) do
    if Keyword.keyword?(value), do: {:ok, value}, else: {:error, :invalid_datagram_options}
  end

  defp datagram_options(_), do: {:error, :invalid_datagram_options}

  defp endpoint_options(options, profile, datagram) do
    options
    |> Keyword.drop([:ops, :alpn, :profile, :timeout, :connect_timeout, :datagram])
    |> Keyword.put(:profile, profile)
    |> Keyword.put(:datagram, datagram)
  end

  defp start_endpoint(_ops, endpoint, _options, _profile, _datagram) when is_pid(endpoint),
    do: {:ok, endpoint, false}

  defp start_endpoint(ops, nil, options, profile, datagram) do
    case ops.client(endpoint_options(options, profile, datagram)) do
      {:ok, endpoint} -> {:ok, endpoint, true}
      failure -> failure
    end
  end

  defp stop_owned_endpoint(ops, endpoint) do
    if function_exported?(ops, :stop_endpoint, 1) do
      _ = ops.stop_endpoint(endpoint)
    else
      _ = GenServer.stop(endpoint, :normal, 5_000)
    end

    :ok
  end

  defp connect_options(options), do: Keyword.take(options, [:timeout, :deadline, :ref])

  defp normalize_remote({address, existing_port}, _port)
       when is_tuple(address) and is_integer(existing_port),
       do: {:ok, {address, existing_port}}

  defp normalize_remote(address, port) when is_tuple(address), do: {:ok, {address, port}}

  defp normalize_remote(host, port) when is_binary(host) do
    hostname = String.to_charlist(host)

    case :inet.getaddr(hostname, :inet) do
      {:ok, address} ->
        {:ok, {address, port}}

      {:error, _} ->
        case :inet.getaddr(hostname, :inet6) do
          {:ok, address} -> {:ok, {address, port}}
          {:error, reason} -> {:error, {:resolve, reason}}
        end
    end
  end

  defp normalize_remote(_, _), do: {:error, :invalid_remote}
end

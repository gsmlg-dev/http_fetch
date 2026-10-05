defmodule QuicHttp3.Transport.Quic do
  @moduledoc """
  Adapter from the HTTP/3 transport contract to public `elixir_quic` APIs.

  A connection retains its endpoint explicitly. Closing a connection does not
  implicitly terminate the endpoint; callers use `stop_endpoint/1` when the
  endpoint is no longer needed.
  """

  @behaviour QuicHttp3.Transport

  alias Quic.Profile
  alias SSL.ClientHello.Profile, as: TLSProfile

  defstruct [:endpoint, :handle, :ops, :consumer, :connect_ref, endpoint_owned?: false]

  defmodule Stream do
    @moduledoc false
    defstruct [:handle, :ops]
  end

  defmodule Endpoint do
    @moduledoc """
    Shared endpoint descriptor produced by `client/1`. The TLS and profile
    configuration are immutable and checked before every borrowed connection.
    """
    @enforce_keys [:pid, :tls, :profile, :ops, :host]
    defstruct [:pid, :tls, :profile, :ops, :host, :streams]
  end

  @default_datagram [max_frame_size: 1200, max_items: 64, max_buffer_bytes: 65_536]
  @max_stream_bytes 16_384
  @max_events 128

  @impl true
  def client(options) when is_list(options) do
    {ops, options} = Keyword.pop(options, :ops, Quic)

    with :ok <- valid_options(options),
         {:ok, host} <- reference_host(Keyword.get(options, :host)),
         {:ok, tls} <- QuicHttp3.TLSOptions.normalize(host, Keyword.get(options, :tls, [])),
         options = options |> Keyword.put(:tls, tls) |> Keyword.put(:host, host),
         {:ok, profile} <- profile(options),
         {:ok, datagram} <- datagram_options(Keyword.get(options, :datagram, @default_datagram)),
         {:ok, endpoint} <- ops.client(endpoint_options(options, profile, datagram)) do
      {:ok,
       %Endpoint{
         pid: endpoint,
         tls: tls,
         profile: profile,
         ops: ops,
         host: host,
         streams: stream_budget(Keyword.get(options, :streams, []))
       }}
    end
  end

  def client(_), do: {:error, :invalid_options}

  @impl true
  def connect(remote, port, options) when is_list(options) and port in 1..65_535 do
    {ops, options} = Keyword.pop(options, :ops, Quic)
    {injected_endpoint, options} = Keyword.pop(options, :endpoint)

    with :ok <- valid_options(options),
         {:ok, host} <- reference_host(remote),
         {:ok, tls} <- QuicHttp3.TLSOptions.normalize(host, Keyword.get(options, :tls, [])),
         options = options |> Keyword.put(:tls, tls) |> Keyword.put(:host, host),
         {:ok, profile} <- profile(options),
         {:ok, datagram} <- datagram_options(Keyword.get(options, :datagram, @default_datagram)),
         {:ok, normalized_remote} <- normalize_remote(remote, port),
         {:ok, endpoint, owned?} <-
           start_endpoint(ops, injected_endpoint, options, profile, datagram) do
      connect_ref = Keyword.get(options, :ref, make_ref())
      options = Keyword.put(options, :ref, connect_ref)

      connection = %__MODULE__{
        endpoint: endpoint,
        ops: ops,
        endpoint_owned?: owned?,
        consumer: Keyword.get(options, :consumer, self()),
        connect_ref: connect_ref
      }

      case ops.connect(endpoint, normalized_remote, connect_options(options)) do
        {:ok, handle} ->
          attach(%{connection | handle: handle})

        {:unknown, ref} ->
          {:unknown, connection, ref}

        failure ->
          _ = cleanup(connection)
          failure
      end
    end
  end

  def connect(_, _, _), do: {:error, :invalid_remote}

  @impl true
  def ready(%__MODULE__{handle: nil}, _timeout), do: :pending

  def ready(%__MODULE__{handle: handle, ops: ops} = connection, _timeout) do
    case ops.ready(handle) do
      :ready ->
        with {:ok, metadata} <- info(connection), do: authenticated_h3(metadata)

      result ->
        result
    end
  end

  @impl true
  def info(%__MODULE__{handle: handle, ops: ops}), do: ops.info(handle)

  @impl true
  def operation_status(%__MODULE__{handle: handle, connect_ref: ref} = connection, ref, :connect)
      when not is_nil(handle) do
    %{status: :admitted, result: attach(connection)}
  end

  def operation_status(
        %__MODULE__{handle: handle, endpoint: endpoint, ops: ops} = connection,
        ref,
        kind
      ) do
    target = if kind == :connect, do: endpoint, else: handle

    case ops.operation_status(target, ref) do
      %{result: result} = status ->
        case normalize_result(connection, kind, result) do
          {:ok, value} -> %{status | result: {:ok, value}}
          result -> %{status | result: result}
        end

      result ->
        result
    end
  end

  defp normalize_result(connection, :connect, {:ok, handle}),
    do: attach(%{connection | handle: handle})

  defp normalize_result(%{ops: ops}, :open_stream, {:ok, handle}),
    do: {:ok, %Stream{handle: handle, ops: ops}}

  defp normalize_result(connection, :events, {:ok, events}),
    do: normalize_events(connection, events)

  defp normalize_result(_connection, _kind, result), do: result

  defp attach(%__MODULE__{ops: ops, handle: handle, consumer: consumer} = connection) do
    case ops.attach(handle, consumer, []) do
      :ok -> {:ok, connection}
      {:error, :timeout} -> {:unknown, connection, connection.connect_ref}
      {:unknown, _ref} -> {:unknown, connection, connection.connect_ref}
      error -> {:error, {:attach_failed, connection, error}}
    end
  end

  defp authenticated_h3(%{alpn: alpn}) when alpn != "h3", do: {:error, :h3_not_negotiated}
  defp authenticated_h3(%{peer_authenticated: false}), do: {:error, :peer_not_authenticated}

  defp authenticated_h3(%{tls_complete: true, peer_authenticated: true, parameters_valid: true}),
    do: :ready

  defp authenticated_h3(_), do: {:error, :incomplete_authentication}

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
      do:
        normalize_result(
          %__MODULE__{handle: handle, ops: ops},
          :events,
          ops.events(handle, max, options)
        )

  def events(_, _, _), do: {:error, :invalid_event_limit}

  @impl true
  def reset_stream(%Stream{handle: stream, ops: ops}, code, options),
    do: ops.reset_stream(stream, code, options)

  @impl true
  def stop_stream(%Stream{handle: stream, ops: ops}, code, options),
    do: ops.stop_stream(stream, code, options)

  @impl true
  def close(%__MODULE__{handle: nil}, _code, _reason, _options), do: :ok

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
  def stop_endpoint(%Endpoint{pid: endpoint}), do: stop_endpoint(endpoint)

  def stop_endpoint(endpoint) when is_pid(endpoint) do
    try do
      GenServer.stop(endpoint, :normal, 5_000)
    catch
      :exit, {:noproc, _} -> :ok
      :exit, {:normal, _} -> :ok
      :exit, reason -> {:error, {:endpoint_stop, reason}}
    end
  end

  def stop_endpoint(_), do: {:error, :invalid_endpoint}

  @impl true
  def cleanup(%__MODULE__{endpoint_owned?: false}), do: :ok
  def cleanup(%__MODULE__{ops: ops, endpoint: endpoint}), do: stop_owned_endpoint(ops, endpoint)

  @impl true
  def abort(%__MODULE__{endpoint_owned?: true} = connection, _opts), do: cleanup(connection)
  def abort(%__MODULE__{handle: nil}, _opts), do: {:error, :unresolved_shared_connect}

  def abort(connection, opts) do
    case close(connection, 0x100, <<>>, opts) do
      {:error, :closed} -> :ok
      result -> result
    end
  end

  @impl true
  def capabilities do
    Quic.capabilities()
    |> Map.merge(%{alpn: "h3", datagram: true})
  end

  @doc false
  def stream_budget(options) when is_list(options) do
    Quic.Streams.new(:client, Keyword.put(options, :delivery, :manual))
    |> Map.take([
      :delivery,
      :max_data,
      :max_buffer,
      :max_ready_bytes,
      :max_stream_data_bidi_local,
      :max_stream_data_uni,
      :max_streams_bidi,
      :max_streams_uni,
      :max_stream_records,
      :max_local_stream_records
    ])
  end

  defp profile(options) do
    name = Keyword.get(options, :profile, :ordered)
    tls = Keyword.get(options, :tls, [])

    with {:ok, compiled} <- Profile.compile(name, alpn: ["h3"]),
         wire = Keyword.get(tls, :profile, compiled.tls),
         {:ok, wire} <- TLSProfile.validate(wire, Profile.capabilities()),
         :ok <- h3_wire_policy(wire),
         :ok <- matching_tls_options(tls, wire),
         wire = add_sni(wire, tls[:server_name]),
         {:ok, validated} <- TLSProfile.validate(wire, Profile.capabilities()) do
      {:ok, %{compiled | tls: validated}}
    end
  end

  defp h3_wire_policy(wire) do
    allowed =
      List.keyfind(wire.extensions, :alpn, 0) == {:alpn, ["h3"]} and
        List.keyfind(wire.extensions, :supported_versions, 0) == {:supported_versions, [0x0304]} and
        Enum.count(wire.extensions, &match?({:raw, 57, <<>>}, &1)) == 1 and
        not Enum.any?(wire.extensions, fn
          {:raw, 57, bytes} when bytes != <<>> ->
            true

          {tag, _}
          when tag in [
                 :pre_shared_key,
                 :psk_key_exchange_modes,
                 :extended_master_secret,
                 :renegotiation_info
               ] ->
            true

          _ ->
            false
        end)

    if allowed, do: :ok, else: {:error, :invalid_h3_wire_profile}
  end

  defp matching_tls_options(tls, wire) do
    expected = [
      ciphers: wire.cipher_suites,
      groups: extension_value(wire, :supported_groups),
      signature_algorithms: extension_value(wire, :signature_algorithms)
    ]

    case Enum.find(expected, fn {key, value} ->
           Keyword.has_key?(tls, key) and tls[key] != value
         end) do
      nil -> :ok
      {key, _} -> {:error, {:profile_option_mismatch, key}}
    end
  end

  defp extension_value(wire, name) do
    case List.keyfind(wire.extensions, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  defp add_sni(wire, nil), do: wire

  defp add_sni(wire, _server_name) do
    if List.keymember?(wire.extensions, :server_name, 0),
      do: wire,
      else: %{wire | extensions: [{:server_name, :from_connection} | wire.extensions]}
  end

  defp datagram_options(value) when is_list(value) do
    if Keyword.keyword?(value), do: {:ok, value}, else: {:error, :invalid_datagram_options}
  end

  defp datagram_options(_), do: {:error, :invalid_datagram_options}

  defp endpoint_options(options, profile, datagram) do
    options
    |> Keyword.drop([
      :ops,
      :host,
      :alpn,
      :profile,
      :timeout,
      :connect_timeout,
      :datagram,
      :deadline,
      :ref,
      :consumer,
      :tls_backend
    ])
    |> Keyword.put(:profile, profile)
    |> Keyword.put(:datagram, datagram)
  end

  defp start_endpoint(ops, %Endpoint{} = endpoint, options, profile, _datagram) do
    if endpoint.ops == ops and endpoint.tls == options[:tls] and endpoint.profile == profile and
         endpoint.host == options[:host] and
         (options[:streams] == nil or endpoint.streams == stream_budget(options[:streams])) do
      {:ok, endpoint.pid, false}
    else
      {:error, :endpoint_configuration_mismatch}
    end
  end

  defp start_endpoint(_ops, endpoint, _options, _profile, _datagram) when not is_nil(endpoint),
    do: {:error, :unverified_endpoint}

  defp start_endpoint(ops, nil, options, profile, datagram) do
    case ops.client(endpoint_options(options, profile, datagram)) do
      {:ok, endpoint} -> {:ok, endpoint, true}
      failure -> failure
    end
  end

  defp stop_owned_endpoint(ops, endpoint) do
    if function_exported?(ops, :stop_endpoint, 1) do
      ops.stop_endpoint(endpoint)
    else
      stop_endpoint(endpoint)
    end
  end

  defp connect_options(options), do: Keyword.take(options, [:timeout, :deadline, :ref])

  defp normalize_events(%{handle: connection, ops: ops}, events) do
    Enum.reduce_while(events, {:ok, []}, fn event, {:ok, acc} ->
      normalized =
        case event do
          {:stream_open, %{connection: ^connection} = stream, kind} ->
            {:stream_open, %Stream{handle: stream, ops: ops}, kind}

          {:readable, %{connection: ^connection} = stream} ->
            {:readable, %Stream{handle: stream, ops: ops}}

          {:stopped, %{connection: ^connection} = stream, code} ->
            {:stopped, %Stream{handle: stream, ops: ops}, code}

          tuple when is_tuple(tuple) and elem(tuple, 0) in [:stream_open, :readable, :stopped] ->
            :stale_stream

          value ->
            value
        end

      if normalized == :stale_stream,
        do: {:halt, {:error, :stale_stream_handle}},
        else: {:cont, {:ok, [normalized | acc]}}
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      error -> error
    end
  end

  defp valid_options(options) do
    cond do
      not Keyword.keyword?(options) -> {:error, :invalid_options}
      options[:tls_backend] != nil -> {:error, :tls_backend_not_supported_for_quic}
      Keyword.get(options, :alpn, ["h3"]) != ["h3"] -> {:error, :invalid_h3_alpn}
      true -> :ok
    end
  end

  defp reference_host(host) when is_binary(host), do: {:ok, host}
  defp reference_host({address, _port}) when is_tuple(address), do: reference_host(address)

  defp reference_host(address) when is_tuple(address) do
    case :inet.ntoa(address) do
      value when is_list(value) -> {:ok, List.to_string(value)}
      _ -> {:error, :invalid_remote}
    end
  catch
    _, _ -> {:error, :invalid_remote}
  end

  defp reference_host(_), do: {:error, :invalid_remote}

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
end

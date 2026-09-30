defmodule HTTP.EventSource.Options do
  @moduledoc false

  @default_connect_timeout 30_000
  @default_reconnect_time 3_000
  @default_max_reconnect_time 30_000
  @default_max_line_size 64 * 1024

  @string_keys %{
    "connect_timeout" => :connect_timeout,
    "connectTimeout" => :connect_timeout,
    "headers" => :headers,
    "idle_timeout" => :idle_timeout,
    "idleTimeout" => :idle_timeout,
    "last_event_id" => :last_event_id,
    "lastEventId" => :last_event_id,
    "max_event_size" => :max_event_size,
    "maxEventSize" => :max_event_size,
    "max_event_parts" => :max_event_parts,
    "maxEventParts" => :max_event_parts,
    "max_redirects" => :max_redirects,
    "maxRedirects" => :max_redirects,
    "max_line_size" => :max_line_size,
    "maxLineSize" => :max_line_size,
    "max_reconnect_time" => :max_reconnect_time,
    "maxReconnectTime" => :max_reconnect_time,
    "owner" => :owner,
    "reconnect_time" => :reconnect_time,
    "reconnectTime" => :reconnect_time,
    "socket_opts" => :socket_opts,
    "socketOpts" => :socket_opts,
    "ssl" => :ssl,
    "tls_backend" => :tls_backend,
    "tlsBackend" => :tls_backend,
    "unix_socket" => :unix_socket,
    "unixSocket" => :unix_socket,
    "with_credentials" => :with_credentials,
    "withCredentials" => :with_credentials
  }

  defstruct uri: nil,
            url: nil,
            owner: nil,
            with_credentials: false,
            headers: [],
            last_event_id: "",
            reconnect_time: @default_reconnect_time,
            max_reconnect_time: @default_max_reconnect_time,
            connect_timeout: @default_connect_timeout,
            idle_timeout: :infinity,
            ssl: [],
            socket_opts: [],
            tls_backend: :ssl,
            unix_socket: nil,
            max_line_size: @default_max_line_size,
            http_version: :http1,
            http2_profile: nil,
            http2_scope: nil,
            http2_reuse: true,
            delivery: :legacy,
            max_queue_bytes: 2_097_152,
            max_queue_events: 64,
            max_event_size: 1_048_576,
            max_event_parts: 16_384,
            max_redirects: 5,
            ref: nil

  @type t :: %__MODULE__{
          uri: URI.t(),
          url: String.t(),
          owner: pid(),
          with_credentials: boolean(),
          headers: [{String.t(), String.t()}],
          last_event_id: String.t(),
          reconnect_time: non_neg_integer(),
          max_reconnect_time: non_neg_integer(),
          connect_timeout: timeout(),
          idle_timeout: timeout(),
          ssl: keyword(),
          socket_opts: keyword(),
          tls_backend: HTTP.TLSBackend.t(),
          unix_socket: String.t() | nil,
          max_line_size: pos_integer(),
          ref: reference()
        }

  @spec new(String.t() | URI.t(), keyword() | map()) :: {:ok, t()} | {:error, term()}
  def new(url, init \\ []) do
    with {:ok, uri} <- normalize_url(url),
         {:ok, init} <- normalize_init(init),
         {:ok, init} <- HTTP.Runtime.Options.validate(uri, init),
         :ok <- validate_limits(init),
         :ok <- validate_delivery_capacity(init) do
      {:ok,
       %__MODULE__{
         uri: uri,
         url: URI.to_string(uri),
         owner: Keyword.get(init, :owner, self()),
         with_credentials: Keyword.get(init, :with_credentials, false),
         headers: Keyword.get(init, :headers, []),
         last_event_id: Keyword.get(init, :last_event_id, ""),
         reconnect_time: Keyword.get(init, :reconnect_time, @default_reconnect_time),
         max_reconnect_time: Keyword.get(init, :max_reconnect_time, @default_max_reconnect_time),
         connect_timeout: Keyword.get(init, :connect_timeout, @default_connect_timeout),
         idle_timeout: Keyword.get(init, :idle_timeout, :infinity),
         ssl: Keyword.get(init, :ssl, []),
         socket_opts: Keyword.get(init, :socket_opts, []),
         tls_backend: Keyword.fetch!(init, :tls_backend),
         unix_socket: Keyword.get(init, :unix_socket),
         max_line_size: Keyword.get(init, :max_line_size, @default_max_line_size),
         http_version: Keyword.get(init, :http_version, :http1),
         http2_profile: Keyword.get(init, :http2_profile),
         http2_scope: Keyword.get(init, :http2_scope),
         http2_reuse: Keyword.get(init, :http2_reuse, true),
         delivery: Keyword.get(init, :delivery, :legacy),
         max_queue_bytes: Keyword.get(init, :max_queue_bytes, 2_097_152),
         max_queue_events: Keyword.get(init, :max_queue_events, 64),
         max_event_size: Keyword.get(init, :max_event_size, 1_048_576),
         max_event_parts: Keyword.get(init, :max_event_parts, 16_384),
         max_redirects: Keyword.get(init, :max_redirects, 5),
         ref: Keyword.get(init, :ref, make_ref())
       }}
    end
  end

  defp normalize_url(%URI{} = uri), do: normalize_uri(uri)

  defp normalize_url(url) when is_binary(url) do
    url
    |> URI.parse()
    |> normalize_uri()
  end

  defp normalize_url(_url), do: {:error, :invalid_url}

  defp normalize_uri(%URI{scheme: scheme, host: host} = uri) when is_binary(host) do
    case scheme do
      "http" -> {:ok, uri}
      "https" -> {:ok, uri}
      _ -> {:error, {:unsupported_scheme, scheme}}
    end
  end

  defp normalize_uri(%URI{scheme: scheme}), do: {:error, {:unsupported_scheme, scheme}}

  defp normalize_init(init) when is_map(init) do
    init
    |> Enum.map(fn {key, value} -> {normalize_key(key), value} end)
    |> HTTP.Runtime.Options.normalize_keys()
    |> normalize_init()
  end

  defp normalize_init(init) when is_list(init) do
    init = Enum.map(init, fn {key, value} -> {normalize_key(key), value} end)
    init = HTTP.Runtime.Options.normalize_keys(init)

    with {:ok, headers} <- normalize_headers(Keyword.get(init, :headers, [])),
         {:ok, owner} <- normalize_owner(Keyword.get(init, :owner, self())),
         {:ok, with_credentials} <-
           normalize_boolean(
             Keyword.get(init, :with_credentials, false),
             :invalid_with_credentials
           ),
         {:ok, last_event_id} <- normalize_last_event_id(Keyword.get(init, :last_event_id, "")),
         {:ok, reconnect_time} <-
           normalize_non_neg_integer(
             Keyword.get(init, :reconnect_time, @default_reconnect_time),
             :invalid_reconnect_time
           ),
         {:ok, max_reconnect_time} <-
           normalize_non_neg_integer(
             Keyword.get(init, :max_reconnect_time, @default_max_reconnect_time),
             :invalid_max_reconnect_time
           ),
         {:ok, connect_timeout} <-
           normalize_timeout(
             Keyword.get(init, :connect_timeout, @default_connect_timeout),
             :invalid_connect_timeout
           ),
         {:ok, idle_timeout} <-
           normalize_timeout(Keyword.get(init, :idle_timeout, :infinity), :invalid_idle_timeout),
         {:ok, ssl} <- normalize_keyword(Keyword.get(init, :ssl, []), :invalid_ssl_options),
         {:ok, socket_opts} <-
           normalize_keyword(Keyword.get(init, :socket_opts, []), :invalid_socket_options),
         {:ok, tls_backend} <- HTTP.TLSBackend.resolve(Keyword.get(init, :tls_backend)),
         {:ok, unix_socket} <- normalize_unix_socket(Keyword.get(init, :unix_socket)),
         {:ok, max_line_size} <-
           normalize_pos_integer(
             Keyword.get(init, :max_line_size, @default_max_line_size),
             :invalid_max_line_size
           ) do
      {:ok,
       init
       |> Keyword.put(:headers, headers)
       |> Keyword.put(:owner, owner)
       |> Keyword.put(:with_credentials, with_credentials)
       |> Keyword.put(:last_event_id, last_event_id)
       |> Keyword.put(:reconnect_time, reconnect_time)
       |> Keyword.put(:max_reconnect_time, max_reconnect_time)
       |> Keyword.put(:connect_timeout, connect_timeout)
       |> Keyword.put(:idle_timeout, idle_timeout)
       |> Keyword.put(:ssl, ssl)
       |> Keyword.put(:socket_opts, socket_opts)
       |> Keyword.put(:tls_backend, tls_backend)
       |> Keyword.put(:unix_socket, unix_socket)
       |> Keyword.put(:max_line_size, max_line_size)}
    end
  end

  defp normalize_init(_init), do: {:error, :invalid_options}

  defp normalize_key(key) when is_binary(key), do: Map.get(@string_keys, key, key)
  defp normalize_key(key), do: key

  defp normalize_headers(%HTTP.Headers{headers: headers}), do: normalize_headers(headers)

  defp normalize_headers(headers) when is_map(headers) do
    headers
    |> Map.to_list()
    |> normalize_headers()
  end

  defp normalize_headers(headers) when is_list(headers) do
    headers =
      Enum.map(headers, fn {name, value} ->
        {HTTP.Headers.normalize_name(to_string(name)), to_string(value)}
      end)

    {:ok, headers}
  rescue
    _error -> {:error, :invalid_headers}
  end

  defp normalize_headers(_headers), do: {:error, :invalid_headers}

  defp normalize_owner(owner) when is_pid(owner), do: {:ok, owner}
  defp normalize_owner(_owner), do: {:error, :invalid_owner}

  defp normalize_boolean(value, _error) when is_boolean(value), do: {:ok, value}
  defp normalize_boolean(_value, error), do: {:error, error}

  defp normalize_last_event_id(value) when is_binary(value) do
    if not String.valid?(value) or
         Enum.any?(:binary.bin_to_list(value), &(&1 < 32 or &1 == 127)) do
      {:error, :invalid_last_event_id}
    else
      {:ok, value}
    end
  end

  defp normalize_last_event_id(_value), do: {:error, :invalid_last_event_id}

  defp normalize_timeout(:infinity, _error), do: {:ok, :infinity}
  defp normalize_timeout(value, error), do: normalize_pos_integer(value, error)

  defp normalize_pos_integer(value, _error) when is_integer(value) and value > 0, do: {:ok, value}
  defp normalize_pos_integer(_value, error), do: {:error, error}

  defp normalize_non_neg_integer(value, _error) when is_integer(value) and value >= 0 do
    {:ok, value}
  end

  defp normalize_non_neg_integer(_value, error), do: {:error, error}

  defp normalize_keyword(value, _error) when is_list(value), do: {:ok, value}
  defp normalize_keyword(_value, error), do: {:error, error}

  defp normalize_unix_socket(nil), do: {:ok, nil}
  defp normalize_unix_socket(value) when is_binary(value), do: {:ok, value}
  defp normalize_unix_socket(_value), do: {:error, :invalid_unix_socket}

  defp validate_delivery_capacity(init) do
    if init[:delivery] == :ack and
         Keyword.get(init, :max_queue_bytes, 2_097_152) <
           Keyword.get(init, :max_event_size, 1_048_576) + 7,
       do: {:error, :event_limit_exceeds_delivery_limit},
       else: :ok
  end

  defp validate_limits(init) do
    Enum.reduce_while(
      [{:max_event_size, 1_048_576}, {:max_event_parts, 16_384}, {:max_redirects, 5}],
      :ok,
      fn {key, default}, :ok ->
        value = Keyword.get(init, key, default)
        minimum = if key == :max_redirects, do: 0, else: 1

        if is_integer(value) and value >= minimum do
          {:cont, :ok}
        else
          {:halt, {:error, {:invalid_option, key}}}
        end
      end
    )
  end
end

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
            unix_socket: nil,
            max_line_size: @default_max_line_size,
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
          unix_socket: String.t() | nil,
          max_line_size: pos_integer(),
          ref: reference()
        }

  @spec new(String.t() | URI.t(), keyword() | map()) :: {:ok, t()} | {:error, term()}
  def new(url, init \\ []) do
    with {:ok, uri} <- normalize_url(url),
         {:ok, init} <- normalize_init(init) do
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
         unix_socket: Keyword.get(init, :unix_socket),
         max_line_size: Keyword.get(init, :max_line_size, @default_max_line_size),
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
    |> normalize_init()
  end

  defp normalize_init(init) when is_list(init) do
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
    if binary_part_contains?(value, [<<0>>, "\n", "\r"]) do
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

  defp binary_part_contains?(value, parts) do
    Enum.any?(parts, fn part -> :binary.match(value, part) != :nomatch end)
  end
end

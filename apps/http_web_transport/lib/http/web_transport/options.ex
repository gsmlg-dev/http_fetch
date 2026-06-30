defmodule HTTP.WebTransport.Options do
  @moduledoc false

  @default_connect_timeout 30_000
  @default_max_datagram_size 64 * 1024
  @default_max_datagrams 1_024

  @string_keys %{
    "allowPooling" => :allow_pooling,
    "allow_pooling" => :allow_pooling,
    "anticipatedConcurrentIncomingBidirectionalStreams" =>
      :anticipated_concurrent_incoming_bidirectional_streams,
    "anticipatedConcurrentIncomingUnidirectionalStreams" =>
      :anticipated_concurrent_incoming_unidirectional_streams,
    "backend" => :backend,
    "congestionControl" => :congestion_control,
    "congestion_control" => :congestion_control,
    "connectTimeout" => :connect_timeout,
    "connect_timeout" => :connect_timeout,
    "datagramsReadableType" => :datagrams_readable_type,
    "datagrams_readable_type" => :datagrams_readable_type,
    "headers" => :headers,
    "idleTimeout" => :idle_timeout,
    "idle_timeout" => :idle_timeout,
    "maxDatagramSize" => :max_datagram_size,
    "maxIncomingDatagrams" => :max_incoming_datagrams,
    "maxOutgoingDatagrams" => :max_outgoing_datagrams,
    "max_datagram_size" => :max_datagram_size,
    "max_incoming_datagrams" => :max_incoming_datagrams,
    "max_outgoing_datagrams" => :max_outgoing_datagrams,
    "owner" => :owner,
    "protocols" => :protocols,
    "quic" => :quic,
    "requireUnreliable" => :require_unreliable,
    "require_unreliable" => :require_unreliable,
    "serverCertificateHashes" => :server_certificate_hashes,
    "server_certificate_hashes" => :server_certificate_hashes,
    "socketOpts" => :socket_opts,
    "socket_opts" => :socket_opts,
    "ssl" => :ssl
  }

  defstruct uri: nil,
            url: nil,
            owner: nil,
            allow_pooling: false,
            require_unreliable: false,
            headers: [],
            server_certificate_hashes: [],
            congestion_control: :default,
            anticipated_concurrent_incoming_unidirectional_streams: nil,
            anticipated_concurrent_incoming_bidirectional_streams: nil,
            protocols: [],
            datagrams_readable_type: :default,
            backend: HTTP.WebTransport.Transport.QUIC,
            connect_timeout: @default_connect_timeout,
            idle_timeout: :infinity,
            ssl: [],
            quic: [],
            socket_opts: [],
            max_incoming_datagrams: @default_max_datagrams,
            max_outgoing_datagrams: @default_max_datagrams,
            max_datagram_size: @default_max_datagram_size,
            ref: nil

  @type t :: %__MODULE__{
          uri: URI.t(),
          url: String.t(),
          owner: pid(),
          allow_pooling: boolean(),
          require_unreliable: boolean(),
          headers: [{String.t(), String.t()}],
          server_certificate_hashes: list(),
          congestion_control: :default | :throughput | :low_latency,
          anticipated_concurrent_incoming_unidirectional_streams: non_neg_integer() | nil,
          anticipated_concurrent_incoming_bidirectional_streams: non_neg_integer() | nil,
          protocols: [String.t()],
          datagrams_readable_type: :default | :bytes,
          backend: module(),
          connect_timeout: timeout(),
          idle_timeout: timeout(),
          ssl: keyword(),
          quic: keyword(),
          socket_opts: keyword(),
          max_incoming_datagrams: pos_integer(),
          max_outgoing_datagrams: pos_integer(),
          max_datagram_size: pos_integer(),
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
         allow_pooling: Keyword.get(init, :allow_pooling, false),
         require_unreliable: Keyword.get(init, :require_unreliable, false),
         headers: Keyword.get(init, :headers, []),
         server_certificate_hashes: Keyword.get(init, :server_certificate_hashes, []),
         congestion_control: Keyword.get(init, :congestion_control, :default),
         anticipated_concurrent_incoming_unidirectional_streams:
           Keyword.get(init, :anticipated_concurrent_incoming_unidirectional_streams),
         anticipated_concurrent_incoming_bidirectional_streams:
           Keyword.get(init, :anticipated_concurrent_incoming_bidirectional_streams),
         protocols: Keyword.get(init, :protocols, []),
         datagrams_readable_type: Keyword.get(init, :datagrams_readable_type, :default),
         backend: Keyword.get(init, :backend, HTTP.WebTransport.Transport.QUIC),
         connect_timeout: Keyword.get(init, :connect_timeout, @default_connect_timeout),
         idle_timeout: Keyword.get(init, :idle_timeout, :infinity),
         ssl: Keyword.get(init, :ssl, []),
         quic: Keyword.get(init, :quic, []),
         socket_opts: Keyword.get(init, :socket_opts, []),
         max_incoming_datagrams:
           Keyword.get(init, :max_incoming_datagrams, @default_max_datagrams),
         max_outgoing_datagrams:
           Keyword.get(init, :max_outgoing_datagrams, @default_max_datagrams),
         max_datagram_size: Keyword.get(init, :max_datagram_size, @default_max_datagram_size),
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

  defp normalize_uri(%URI{fragment: fragment}) when is_binary(fragment),
    do: {:error, :fragment_not_allowed}

  defp normalize_uri(%URI{scheme: "https", host: host} = uri) when is_binary(host),
    do: {:ok, uri}

  defp normalize_uri(%URI{scheme: scheme}), do: {:error, {:unsupported_scheme, scheme}}

  defp normalize_init(init) when is_map(init) do
    init
    |> Enum.map(fn {key, value} -> {normalize_key(key), value} end)
    |> normalize_init()
  end

  defp normalize_init(init) when is_list(init) do
    with {:ok, headers} <- normalize_headers(Keyword.get(init, :headers, [])),
         {:ok, owner} <- normalize_owner(Keyword.get(init, :owner, self())),
         {:ok, allow_pooling} <-
           normalize_boolean(Keyword.get(init, :allow_pooling, false), :invalid_allow_pooling),
         {:ok, require_unreliable} <-
           normalize_boolean(
             Keyword.get(init, :require_unreliable, false),
             :invalid_require_unreliable
           ),
         {:ok, server_certificate_hashes} <-
           normalize_server_certificate_hashes(Keyword.get(init, :server_certificate_hashes, [])),
         {:ok, congestion_control} <-
           normalize_congestion_control(Keyword.get(init, :congestion_control, :default)),
         {:ok, incoming_uni} <-
           normalize_optional_non_neg_integer(
             Keyword.get(init, :anticipated_concurrent_incoming_unidirectional_streams),
             :invalid_anticipated_concurrent_incoming_unidirectional_streams
           ),
         {:ok, incoming_bidi} <-
           normalize_optional_non_neg_integer(
             Keyword.get(init, :anticipated_concurrent_incoming_bidirectional_streams),
             :invalid_anticipated_concurrent_incoming_bidirectional_streams
           ),
         {:ok, protocols} <- normalize_protocols(Keyword.get(init, :protocols, [])),
         {:ok, datagrams_readable_type} <-
           normalize_datagrams_readable_type(
             Keyword.get(init, :datagrams_readable_type, :default)
           ),
         {:ok, backend} <- normalize_backend(Keyword.get(init, :backend, default_backend())),
         {:ok, connect_timeout} <-
           normalize_timeout(
             Keyword.get(init, :connect_timeout, @default_connect_timeout),
             :invalid_connect_timeout
           ),
         {:ok, idle_timeout} <-
           normalize_timeout(Keyword.get(init, :idle_timeout, :infinity), :invalid_idle_timeout),
         {:ok, ssl} <- normalize_keyword(Keyword.get(init, :ssl, []), :invalid_ssl_options),
         {:ok, quic} <- normalize_keyword(Keyword.get(init, :quic, []), :invalid_quic_options),
         {:ok, socket_opts} <-
           normalize_keyword(Keyword.get(init, :socket_opts, []), :invalid_socket_options),
         {:ok, max_incoming_datagrams} <-
           normalize_pos_integer(
             Keyword.get(init, :max_incoming_datagrams, @default_max_datagrams),
             :invalid_max_incoming_datagrams
           ),
         {:ok, max_outgoing_datagrams} <-
           normalize_pos_integer(
             Keyword.get(init, :max_outgoing_datagrams, @default_max_datagrams),
             :invalid_max_outgoing_datagrams
           ),
         {:ok, max_datagram_size} <-
           normalize_pos_integer(
             Keyword.get(init, :max_datagram_size, @default_max_datagram_size),
             :invalid_max_datagram_size
           ) do
      {:ok,
       init
       |> Keyword.put(:headers, headers)
       |> Keyword.put(:owner, owner)
       |> Keyword.put(:allow_pooling, allow_pooling)
       |> Keyword.put(:require_unreliable, require_unreliable)
       |> Keyword.put(:server_certificate_hashes, server_certificate_hashes)
       |> Keyword.put(:congestion_control, congestion_control)
       |> Keyword.put(:anticipated_concurrent_incoming_unidirectional_streams, incoming_uni)
       |> Keyword.put(:anticipated_concurrent_incoming_bidirectional_streams, incoming_bidi)
       |> Keyword.put(:protocols, protocols)
       |> Keyword.put(:datagrams_readable_type, datagrams_readable_type)
       |> Keyword.put(:backend, backend)
       |> Keyword.put(:connect_timeout, connect_timeout)
       |> Keyword.put(:idle_timeout, idle_timeout)
       |> Keyword.put(:ssl, ssl)
       |> Keyword.put(:quic, quic)
       |> Keyword.put(:socket_opts, socket_opts)
       |> Keyword.put(:max_incoming_datagrams, max_incoming_datagrams)
       |> Keyword.put(:max_outgoing_datagrams, max_outgoing_datagrams)
       |> Keyword.put(:max_datagram_size, max_datagram_size)}
    end
  end

  defp normalize_init(_init), do: {:error, :invalid_options}

  defp default_backend, do: HTTP.WebTransport.Transport.QUIC

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

  defp normalize_server_certificate_hashes([]), do: {:ok, []}

  defp normalize_server_certificate_hashes(_hashes),
    do: {:error, :unsupported_server_certificate_hashes}

  defp normalize_congestion_control(value) when value in [:default, :throughput, :low_latency] do
    {:ok, value}
  end

  defp normalize_congestion_control("default"), do: {:ok, :default}
  defp normalize_congestion_control("throughput"), do: {:ok, :throughput}
  defp normalize_congestion_control("low-latency"), do: {:ok, :low_latency}
  defp normalize_congestion_control("low_latency"), do: {:ok, :low_latency}
  defp normalize_congestion_control(_value), do: {:error, :invalid_congestion_control}

  defp normalize_optional_non_neg_integer(nil, _error), do: {:ok, nil}

  defp normalize_optional_non_neg_integer(value, _error)
       when is_integer(value) and value >= 0 do
    {:ok, value}
  end

  defp normalize_optional_non_neg_integer(_value, error), do: {:error, error}

  defp normalize_protocols(nil), do: {:ok, []}
  defp normalize_protocols(protocol) when is_binary(protocol), do: normalize_protocols([protocol])

  defp normalize_protocols(protocols) when is_list(protocols) do
    with :ok <- validate_protocols(protocols),
         :ok <- reject_duplicate_protocols(protocols) do
      {:ok, protocols}
    end
  end

  defp normalize_protocols(_protocols), do: {:error, :invalid_protocols}

  defp validate_protocols(protocols) do
    if Enum.all?(protocols, &valid_protocol?/1) do
      :ok
    else
      {:error, :invalid_protocol}
    end
  end

  defp valid_protocol?(protocol) when is_binary(protocol) do
    byte_size(protocol) in 1..512
  end

  defp valid_protocol?(_protocol), do: false

  defp reject_duplicate_protocols(protocols) do
    if Enum.uniq(protocols) == protocols do
      :ok
    else
      {:error, :duplicate_protocol}
    end
  end

  defp normalize_datagrams_readable_type(value) when value in [:default, :bytes], do: {:ok, value}
  defp normalize_datagrams_readable_type("bytes"), do: {:ok, :bytes}
  defp normalize_datagrams_readable_type("default"), do: {:ok, :default}
  defp normalize_datagrams_readable_type(_value), do: {:error, :invalid_datagrams_readable_type}

  defp normalize_backend(backend) when is_atom(backend), do: {:ok, backend}
  defp normalize_backend(_backend), do: {:error, :invalid_backend}

  defp normalize_timeout(:infinity, _error), do: {:ok, :infinity}
  defp normalize_timeout(value, error), do: normalize_pos_integer(value, error)

  defp normalize_pos_integer(value, _error) when is_integer(value) and value > 0, do: {:ok, value}
  defp normalize_pos_integer(_value, error), do: {:error, error}

  defp normalize_keyword(value, _error) when is_list(value), do: {:ok, value}
  defp normalize_keyword(_value, error), do: {:error, error}
end

defmodule HTTP.Runtime.Options do
  @moduledoc false
  alias HTTP.HTTP2.WireProfile
  alias HTTP.Request
  alias HTTP.Runtime.Dialer

  @keys %{
    "http_version" => :http_version,
    "httpVersion" => :http_version,
    "http2_profile" => :http2_profile,
    "http2Profile" => :http2_profile,
    "http2_scope" => :http2_scope,
    "http2Scope" => :http2_scope,
    "http2_reuse" => :http2_reuse,
    "http2Reuse" => :http2_reuse,
    "http3_profile" => :http3_profile,
    "http3Profile" => :http3_profile,
    "http3_reuse" => :http3_reuse,
    "http3Reuse" => :http3_reuse,
    "delivery" => :delivery,
    "max_queue_bytes" => :max_queue_bytes,
    "maxQueueBytes" => :max_queue_bytes,
    "max_queue_events" => :max_queue_events,
    "maxQueueEvents" => :max_queue_events
  }

  def normalize_keys(init) when is_list(init) or is_map(init),
    do: Enum.map(init, fn {key, value} -> {Map.get(@keys, key, key), value} end)

  def validate(uri, init, opts \\ []) do
    init = normalize_keys(init)

    with {:ok, version} <-
           version(Keyword.get(init, :http_version, :http1), opts[:allow_http3] == true),
         {:ok, profile} <- profile(Keyword.get(init, :http2_profile)),
         :ok <- scope(Keyword.get(init, :http2_scope)),
         :ok <- boolean(Keyword.get(init, :http2_reuse, true), :invalid_http2_reuse),
         {:ok, delivery} <- delivery(Keyword.get(init, :delivery, :legacy)),
         :ok <-
           positive(Keyword.get(init, :max_queue_bytes, 2_097_152), :invalid_max_queue_bytes),
         :ok <- positive(Keyword.get(init, :max_queue_events, 64), :invalid_max_queue_events),
         {:ok, backend} <- backend(version, init[:tls_backend]),
         init =
           init
           |> Keyword.put(:http_version, version)
           |> Keyword.put(:http2_profile, profile)
           |> Keyword.put(:http2_reuse, Keyword.get(init, :http2_reuse, true))
           |> Keyword.put(:delivery, delivery)
           |> Keyword.put(:tls_backend, backend),
         request = %Request{
           url: origin_uri(uri),
           transport_options: transport_options(Map.new(init))
         },
         {:ok, selection} <- protocol_selection(request, init),
         :ok <- validate_alpn(init[:ssl] || [], selection),
         :ok <- validate_headers(init[:headers] || [], selection) do
      {:ok, init}
    end
  end

  def transport_options(options) do
    options = if is_struct(options), do: Map.from_struct(options), else: Map.new(options)

    for key <- [
          :http_version,
          :http2_profile,
          :http2_scope,
          :http2_reuse,
          :http3_profile,
          :http3_reuse,
          :tls_backend,
          :ssl,
          :socket_opts,
          :connect_timeout,
          :unix_socket
        ],
        Map.has_key?(options, key),
        not is_nil(options[key]),
        key not in [:http3_profile, :http3_reuse] or options[:http_version] == :http3,
        do: {key, options[key]}
  end

  def origin_uri(%URI{scheme: "ws"} = uri), do: %{uri | scheme: "http"}
  def origin_uri(%URI{scheme: "wss"} = uri), do: %{uri | scheme: "https"}
  def origin_uri(%URI{} = uri), do: uri

  def h2?(options) do
    options.http_version in [:http2, :h2c] or
      (options.http_version == :auto and options.uri.scheme in ["https", "wss"])
  end

  defp version(value, true) when value in [:http3, "http3", "h3"], do: {:ok, :http3}
  defp version(value, _allow_http3), do: version(value)

  defp backend(:http3, nil), do: {:ok, nil}
  defp backend(:http3, _value), do: {:error, :tls_backend_not_supported_for_quic}
  defp backend(_version, value), do: HTTP.TLSBackend.resolve(value)

  defp protocol_selection(request, init) do
    if init[:http_version] == :http3 do
      with :ok <- h3_route(request.url, init),
           {:ok, _key, _connect} <- HTTP.HTTP3.PoolKey.build(request) do
        {:ok, %{mode: :http3, alpn_protocols: ["h3"]}}
      end
    else
      with {:ok, transport, _host, _port} <- Dialer.select_transport(request, init[:unix_socket]) do
        Dialer.protocol_selection(request, transport)
      end
    end
  end

  defp h3_route(uri, init) do
    cond do
      uri.scheme != "https" ->
        {:error, :http3_requires_https}

      init[:unix_socket] != nil ->
        {:error, :unix_socket_not_supported_for_quic}

      init[:proxy] != nil ->
        {:error, :proxy_not_supported_for_quic}

      init[:http2_profile] != nil or init[:http2_scope] != nil or init[:http2_reuse] == false ->
        {:error, :http2_options_require_http2}

      init[:socket_opts] not in [nil, []] ->
        {:error, :socket_options_not_supported_for_quic}

      init[:connect_timeout] == :infinity ->
        {:error, :invalid_connect_timeout}

      true ->
        :ok
    end
  end

  defp version(version) when version in [:http1, :http2, :h2c, :auto], do: {:ok, version}
  defp version(version) when version in ["http1", "http/1.1"], do: {:ok, :http1}
  defp version(version) when version in ["http2", "h2"], do: {:ok, :http2}
  defp version("h2c"), do: {:ok, :h2c}
  defp version("auto"), do: {:ok, :auto}
  defp version(_), do: {:error, :invalid_http_version}

  defp profile(nil), do: {:ok, nil}
  defp profile(value), do: WireProfile.compile(value)
  defp scope(value) when is_nil(value) or is_atom(value) or is_binary(value), do: :ok
  defp scope(_value), do: {:error, :invalid_http2_scope}
  defp boolean(value, _reason) when is_boolean(value), do: :ok
  defp boolean(_value, reason), do: {:error, reason}
  defp positive(value, _reason) when is_integer(value) and value > 0, do: :ok
  defp positive(_value, reason), do: {:error, reason}
  defp delivery(value) when value in [:legacy, :ack], do: {:ok, value}
  defp delivery("legacy"), do: {:ok, :legacy}
  defp delivery("ack"), do: {:ok, :ack}
  defp delivery(_), do: {:error, :invalid_delivery}

  defp validate_alpn(ssl, selection) when is_list(ssl) do
    if Keyword.keyword?(ssl) do
      compatible? =
        Enum.all?([:alpn_advertised_protocols, :alpn_preferred_protocols], fn key ->
          not Keyword.has_key?(ssl, key) or compatible_alpn?(ssl[key], selection)
        end)

      if compatible?, do: :ok, else: {:error, :incompatible_alpn}
    else
      {:error, :invalid_ssl_options}
    end
  end

  defp validate_alpn(_ssl, _selection), do: {:error, :invalid_ssl_options}

  defp compatible_alpn?(protocols, %{mode: :force_h2}), do: protocols == ["h2"]

  defp compatible_alpn?(protocols, %{mode: :auto_https}) when is_list(protocols),
    do: Enum.sort(protocols) == ["h2", "http/1.1"]

  defp compatible_alpn?(protocols, %{mode: :http1}), do: protocols in [[], ["http/1.1"]]
  defp compatible_alpn?(protocols, %{mode: :h2c}), do: protocols == []
  defp compatible_alpn?(protocols, %{mode: :http3}), do: protocols == ["h3"]
  defp compatible_alpn?(_protocols, _selection), do: false

  defp validate_headers(%HTTP.Headers{headers: headers}, selection),
    do: validate_headers(headers, selection)

  defp validate_headers(headers, selection) when is_map(headers),
    do: validate_headers(Map.to_list(headers), selection)

  defp validate_headers(headers, selection) when is_list(headers) do
    if Enum.all?(headers, fn
         {name, value} when is_binary(name) and is_binary(value) ->
           not String.starts_with?(name, ":") and
             not Enum.any?(:binary.bin_to_list(value), &((&1 < 32 and &1 != 9) or &1 == 127)) and
             valid_h2_field?(name, value, selection)

         _ ->
           false
       end),
       do: :ok,
       else: {:error, :invalid_headers}
  end

  defp validate_headers(_headers, _selection), do: {:error, :invalid_headers}

  defp valid_h2_field?(_name, _value, %{mode: :http1}), do: true

  defp valid_h2_field?(name, value, %{mode: :http3}) do
    valid_h2_field?(name, value, %{mode: :force_h2}) and
      (String.downcase(name) != "te" or value == "trailers")
  end

  defp valid_h2_field?(name, value, _selection) do
    String.downcase(name) not in ~w(connection upgrade keep-alive proxy-connection transfer-encoding) and
      (value == "" or (:binary.first(value) not in [9, 32] and :binary.last(value) not in [9, 32]))
  end
end

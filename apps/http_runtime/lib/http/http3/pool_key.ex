defmodule HTTP.HTTP3.PoolKey do
  @moduledoc "Origin, TLS identity, profile and ownership identity for HTTP/3 reuse."
  alias HTTP.Request

  def build(request, opts \\ [])

  def build(%Request{url: %URI{scheme: "https", host: host, port: port}} = request, opts)
      when is_binary(host) do
    options = Keyword.merge(request.transport_options, opts)
    tls_options = Keyword.get(options, :tls, Keyword.get(options, :ssl, []))
    profile = Keyword.get(options, :profile, Keyword.get(options, :http3_profile, :ordered))
    endpoint = Keyword.get(options, :endpoint)

    with :ok <- compatible_route(options),
         {:ok, options} <- HTTP.HTTP3.ReceiveBudget.normalize(options),
         {:ok, tls} <- QuicHttp3.TLSOptions.normalize(host, tls_options),
         {:ok, compiled} <- Quic.Profile.compile(profile, alpn: ["h3"]) do
      policy =
        options
        |> Keyword.take([
          :operation_timeout,
          :idle_timeout,
          :max_streams,
          :rotation_after,
          :streams,
          :datagram,
          :socket,
          :limits
        ])
        |> Map.new()

      identity = {String.downcase(host), port || 443, tls, compiled, endpoint, policy}
      reuse = Keyword.get(options, :http3_reuse, true)
      key = :crypto.hash(:sha256, :erlang.term_to_binary(identity, [:deterministic]))
      key = if reuse and safe?(tls), do: key, else: {key, make_ref()}

      connect =
        Keyword.take(options, [
          :connect_timeout,
          :operation_timeout,
          :idle_timeout,
          :max_streams,
          :rotation_after,
          :streams,
          :datagram,
          :socket,
          :limits
        ])

      connect =
        Keyword.merge(connect, host: host, port: port || 443, tls: tls_options, profile: profile)

      connect = if endpoint, do: Keyword.put(connect, :endpoint, endpoint), else: connect
      {:ok, key, connect}
    end
  end

  def build(_, _), do: {:error, :http3_requires_https}

  defp compatible_route(options) do
    cond do
      options[:tls_backend] != nil -> {:error, :tls_backend_not_supported_for_quic}
      options[:unix_socket] != nil -> {:error, :unix_socket_not_supported_for_quic}
      options[:socket_opts] not in [nil, []] -> {:error, :socket_opts_not_supported_for_quic}
      options[:http2_profile] != nil -> {:error, :http2_profile_not_supported_for_quic}
      options[:proxy] != nil -> {:error, :proxy_not_supported_for_quic}
      options[:http3_reuse] not in [nil, true, false] -> {:error, :invalid_http3_reuse}
      true -> :ok
    end
  end

  defp safe?(value) when is_function(value), do: false
  defp safe?(value) when is_list(value), do: Enum.all?(value, &safe?/1)
  defp safe?(value) when is_tuple(value), do: value |> Tuple.to_list() |> Enum.all?(&safe?/1)

  defp safe?(value) when is_map(value),
    do: Enum.all?(value, fn {key, item} -> safe?(key) and safe?(item) end)

  defp safe?(_), do: true
end

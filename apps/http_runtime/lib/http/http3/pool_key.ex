defmodule HTTP.HTTP3.PoolKey do
  @moduledoc """
  Origin, TLS identity, profile and ownership identity for HTTP/3 reuse.

  The optional `http3_connect_port` (an Alt-Svc alternative) changes only the
  dialed UDP port and the pool identity; authority, SNI and certificate identity
  remain those of the request origin.

  `http3_resumption: true` (beta) adds `{:resumption, early?}` to the identity
  and asks the owner to dial through the shared `HTTP.HTTP3.Resumption`
  endpoint. `early?` is true only when the request also sets `early_data: true`
  and is a GET, HEAD or OPTIONS request without a body; early and non-early
  requests therefore never share a connection or a ticket partition.
  """
  @early_methods ~w(GET HEAD OPTIONS)
  alias HTTP.Request

  def build(request, opts \\ [])

  def build(%Request{url: %URI{scheme: "https", host: host, port: port}} = request, opts)
      when is_binary(host) do
    options = Keyword.merge(request.transport_options, opts)
    tls_options = Keyword.get(options, :tls, Keyword.get(options, :ssl, []))
    profile = Keyword.get(options, :profile, Keyword.get(options, :http3_profile, :ordered))
    endpoint = Keyword.get(options, :endpoint)
    connect_port = Keyword.get(options, :http3_connect_port)

    with :ok <- compatible_route(options),
         :ok <- valid_connect_port(connect_port),
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
          :limits,
          :extension_policy
        ])
        |> Map.new()

      resumption = resumption(request, options)

      identity =
        {String.downcase(host), port || 443, tls, compiled, endpoint, policy}
        |> with_connect_port(connect_port)
        |> with_resumption(resumption)

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
        Keyword.merge(connect,
          host: host,
          port: connect_port || port || 443,
          tls: tls_options,
          profile: profile,
          exclusive?: reuse == false
        )

      connect = if endpoint, do: Keyword.put(connect, :endpoint, endpoint), else: connect
      connect = if resumption, do: Keyword.put(connect, :resumption, resumption), else: connect
      {:ok, key, connect}
    end
  end

  def build(_, _), do: {:error, :http3_requires_https}

  defp compatible_route(options) do
    cond do
      options[:unix_socket] != nil ->
        {:error, :unix_socket_not_supported_for_quic}

      options[:socket_opts] not in [nil, []] ->
        {:error, :socket_opts_not_supported_for_quic}

      options[:http2_profile] != nil ->
        {:error, :http2_profile_not_supported_for_quic}

      options[:proxy] != nil ->
        {:error, :proxy_not_supported_for_quic}

      options[:http3_reuse] not in [nil, true, false] ->
        {:error, :invalid_http3_reuse}

      options[:http3_resumption] not in [nil, true, false] ->
        {:error, :invalid_http3_resumption}

      options[:early_data] not in [nil, true, false] ->
        {:error, :invalid_early_data}

      options[:http3_resumption] == true and options[:endpoint] != nil ->
        {:error, :http3_resumption_endpoint_conflict}

      true ->
        :ok
    end
  end

  defp valid_connect_port(nil), do: :ok
  defp valid_connect_port(port) when port in 1..65_535, do: :ok
  defp valid_connect_port(_port), do: {:error, :invalid_http3_connect_port}

  defp with_connect_port(identity, nil), do: identity
  defp with_connect_port(identity, port), do: Tuple.insert_at(identity, 6, {:connect_port, port})

  defp resumption(request, options) do
    if options[:http3_resumption] == true,
      do: %{early: options[:early_data] == true and early_request?(request)}
  end

  defp early_request?(%Request{method: method, body: body}) do
    method |> Request.method_token() |> String.upcase() |> Kernel.in(@early_methods) and
      body in [nil, ""]
  end

  defp with_resumption(identity, nil), do: identity

  defp with_resumption(identity, %{early: early?}),
    do: Tuple.insert_at(identity, tuple_size(identity), {:resumption, early?})

  defp safe?(value) when is_function(value), do: false
  defp safe?(value) when is_list(value), do: Enum.all?(value, &safe?/1)
  defp safe?(value) when is_tuple(value), do: value |> Tuple.to_list() |> Enum.all?(&safe?/1)

  defp safe?(value) when is_map(value),
    do: Enum.all?(value, fn {key, item} -> safe?(key) and safe?(item) end)

  defp safe?(_), do: true
end

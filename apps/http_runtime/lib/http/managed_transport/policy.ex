defmodule HTTP.ManagedTransport.Policy do
  @moduledoc false

  @max_policy_bytes 1_048_576
  @max_request_bytes 65_536
  @max_input_nodes 65_536
  @max_input_depth 32
  @tls_options [
    :verify,
    :depth,
    :versions,
    :ciphers,
    :cacerts,
    :cert,
    :key,
    :server_name_indication,
    :signature_algs,
    :signature_algs_cert,
    :supported_groups,
    :honor_cipher_order,
    :reuse_sessions,
    :session_tickets,
    :middlebox_comp_mode
  ]
  @socket_options [
    :nodelay,
    :keepalive,
    :send_timeout,
    :send_timeout_close,
    :recbuf,
    :sndbuf,
    :buffer,
    :tos,
    :tclass,
    :priority
  ]
  @open_options [
    :origin,
    :connect_address,
    :http_version,
    :tls_backend,
    :ssl,
    :socket_opts,
    :max_requests,
    :max_connections,
    :max_pending,
    :idle_timeout,
    :http2_profile
  ]

  def freeze(opts) when is_list(opts) do
    with true <- Keyword.keyword?(opts),
         true <- Enum.all?(Keyword.keys(opts), &(&1 in @open_options)),
         true <- length(opts) == length(Enum.uniq(Keyword.keys(opts))),
         {:ok, origin} <- origin(Keyword.get(opts, :origin)),
         true <- byte_size(origin.host) <= 253,
         true <- HTTP.Transport.valid_connect_address?(opts[:connect_address]),
         version when version in [:http1, :http2, :h2c] <- opts[:http_version],
         true <- version != :h2c or origin.scheme == "http",
         true <- version != :http2 or origin.scheme == "https",
         true <- Keyword.get(opts, :tls_backend, :ssl) == :ssl,
         true <- Keyword.get(opts, :http2_profile, :native_v1) == :native_v1,
         true <- Keyword.get(opts, :max_pending, 0) == 0,
         {:ok, requests} <- limit(opts, :max_requests, 100, 2_048),
         {:ok, connections} <- limit(opts, :max_connections, 2, 256),
         {:ok, idle} <- limit(opts, :idle_timeout, 30_000, 60_000),
         {:ok, ssl} <- freeze_ssl(origin, Keyword.get(opts, :ssl, [])),
         {:ok, sockets} <- freeze_sockets(Keyword.get(opts, :socket_opts, [])),
         true <- bounded_term?({ssl, sockets}, 16),
         true <- :erlang.external_size({ssl, sockets}) <= @max_policy_bytes do
      transport =
        [
          http_version: version,
          connect_address: opts[:connect_address],
          tls_backend: :ssl,
          ssl: ssl,
          socket_opts: sockets
        ] ++
          if(version == :http1,
            do: [
              http1_reuse: true,
              http1_pool_size: min(connections, 16),
              http1_idle_timeout: idle
            ],
            else: [http2_reuse: true, http2_profile: :native_v1]
          )

      identity =
        :crypto.hash(:sha256, :erlang.term_to_binary({origin, transport}, [:deterministic]))

      {:ok,
       %{
         origin: origin,
         transport: transport,
         identity: identity,
         limits: %{
           max_requests: requests,
           max_connections: connections,
           max_pending: 0,
           idle_timeout: idle
         }
       }}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_transport_scope_policy}
    end
  rescue
    _ -> {:error, :invalid_transport_scope_policy}
  end

  def freeze(_), do: {:error, :invalid_transport_scope_policy}

  def prepare(policy, %HTTP.Request{} = request, supplied) do
    supplied = if is_map(supplied), do: Map.to_list(supplied), else: supplied
    supplied = Enum.map(supplied, fn {key, value} -> {normalize_key(key), value} end)
    options = request.transport_options

    cond do
      origin(request.url) != {:ok, policy.origin} ->
        {:error, :transport_scope_origin_mismatch}

      Keyword.get(options, :redirect) not in [:manual, :error] or
        Keyword.get(options, :decode_body, true) != false or
          Keyword.get(options, :stream_response, false) != true ->
        {:error, :transport_scope_requires_raw_stream}

      Enum.any?([:proxy, :unix_socket], &(Keyword.get(supplied, &1) != nil)) ->
        {:error, :transport_scope_policy_mismatch}

      Enum.any?(policy.transport, fn {key, value} ->
        Keyword.has_key?(supplied, key) and supplied[key] != value
      end) or
          Enum.any?(
            [:http1_scope, :http2_scope, :http2_priority, :http3_profile, :http3_reuse],
            &Keyword.has_key?(supplied, &1)
          ) ->
        {:error, :transport_scope_policy_mismatch}

      not valid_deadline?(Keyword.get(options, :timeout, 30_000)) or
          not valid_deadline?(Keyword.get(options, :connect_timeout, 30_000)) ->
        {:error, :transport_scope_invalid_deadline}

      true ->
        normalize_request(%{
          request
          | transport_options: Keyword.merge(options, policy.transport)
        })
    end
  end

  defp normalize_request(%HTTP.Request{} = request) do
    fields = request.headers |> HTTP.Headers.to_list() |> Enum.take(257)

    with true <- length(fields) <= 256,
         true <- fields_bytes(fields) <= @max_request_bytes,
         {:ok, url} <- normalize_url(request.url),
         {:ok, body} <- normalize_body(request.body),
         {:ok, content_type} <- normalize_content_type(request.content_type),
         true <-
           fields_bytes(fields) + byte_size(content_type || "") +
             url_bytes(url.scheme, url.host, url.path, url.query) <=
             @max_request_bytes do
      headers = HTTP.Headers.new(Enum.map(fields, fn {key, value} -> {own(key), own(value)} end))
      request = %{request | url: url, headers: headers, body: body, content_type: content_type}
      {effective, target_bytes} = effective_fields(request)

      if length(effective) <= 256 and
           fields_bytes(effective) + target_bytes <= @max_request_bytes do
        {:ok, request}
      else
        {:error, :transport_scope_request_limit}
      end
    else
      _ -> {:error, :transport_scope_request_limit}
    end
  rescue
    _ -> {:error, :transport_scope_request_limit}
  end

  @spec normalize_url(URI.t()) :: {:ok, URI.t()} | {:error, :transport_scope_request_limit}
  defp normalize_url(url) do
    path = if url.path in [nil, ""], do: "/", else: url.path

    # Preserve the parser-owned opaque authority while discarding unused URI metadata.
    normalized = %{
      URI.parse("")
      | scheme: url.scheme,
        host: url.host,
        port: url.port,
        path: path,
        query: url.query
    }

    if byte_size(url.host) <= 253 and
         url_bytes(normalized.scheme, normalized.host, normalized.path, normalized.query) <=
           @max_request_bytes do
      {:ok,
       %{
         normalized
         | scheme: own(url.scheme),
           host: own(url.host),
           path: own(path),
           query: own(url.query)
       }}
    else
      {:error, :transport_scope_request_limit}
    end
  end

  defp url_bytes(scheme, host, path, query),
    do: byte_size(scheme) + byte_size(host) + byte_size(path) + byte_size(query || "")

  defp normalize_body(body) when is_nil(body) or is_pid(body), do: {:ok, body}

  defp normalize_body(body) do
    with {:ok, _, _} <- scan_input(body, @max_input_depth, @max_input_nodes, 0, 255) do
      {:ok, body |> IO.iodata_to_binary() |> own()}
    end
  end

  defp normalize_content_type(nil), do: {:ok, nil}

  defp normalize_content_type(value) do
    with {:ok, _, _} <- scan_input(value, @max_input_depth, @max_input_nodes, 0, 0x10FFFF),
         value <- to_string(value),
         true <- byte_size(value) <= @max_request_bytes do
      {:ok, own(value)}
    end
  end

  # Count cons cells and leaves before flattening; tails do not increase nesting.
  defp scan_input(_, depth, nodes, bytes, _)
       when depth < 0 or nodes <= 0 or bytes > @max_policy_bytes,
       do: {:error, :transport_scope_request_limit}

  defp scan_input([], _, nodes, bytes, _), do: {:ok, nodes - 1, bytes}

  defp scan_input([head | tail], depth, nodes, bytes, max_char) do
    with {:ok, nodes, bytes} <- scan_input(head, depth - 1, nodes - 1, bytes, max_char) do
      scan_input(tail, depth, nodes, bytes, max_char)
    end
  end

  defp scan_input(value, _, nodes, bytes, _) when is_binary(value) do
    bytes = bytes + byte_size(value)

    if bytes <= @max_policy_bytes,
      do: {:ok, nodes - 1, bytes},
      else: {:error, :transport_scope_request_limit}
  end

  defp scan_input(value, _, nodes, bytes, max_char)
       when is_integer(value) and value >= 0 and value <= max_char,
       do: {:ok, nodes - 1, bytes + 1}

  defp scan_input(_, _, _, _, _), do: {:error, :transport_scope_request_limit}

  defp effective_fields(%HTTP.Request{transport_options: options} = request) do
    # Accounting must not replace upload attachment or the later duplex validation.
    request = if is_pid(request.body), do: %{request | duplex: :half}, else: request

    if options[:http_version] == :http1 do
      headers =
        request.headers
        |> HTTP.Headers.set_default("User-Agent", HTTP.Headers.user_agent())
        |> HTTP.Headers.set_default("Host", HTTP.Request.authority(request.url))
        |> HTTP.Headers.set("Connection", "keep-alive")

      {headers, _} = HTTP.Request.put_body_headers(headers, request)
      {HTTP.Headers.to_list(headers), byte_size(HTTP.Request.origin_form(request.url))}
    else
      {:ok, headers, _} = HTTP.HTTP2.request_headers(request, :native_v1)
      {headers, 0}
    end
  end

  defp fields_bytes(fields),
    do:
      Enum.reduce(fields, 0, fn {key, value}, sum ->
        sum + byte_size(key) + byte_size(value) + 32
      end)

  defp own(nil), do: nil
  defp own(value), do: :binary.copy(value)

  defp valid_deadline?(value), do: is_integer(value) and value > 0 and value <= 86_400_000

  defp origin(value) when is_binary(value), do: origin(URI.parse(value))

  defp origin(%URI{scheme: scheme, host: host, port: port, userinfo: nil, fragment: nil})
       when scheme in ["http", "https"] and is_binary(host) and host != "" and
              is_integer(port) and port > 0 and port <= 65_535,
       do: {:ok, %{scheme: scheme, host: String.downcase(host), port: port}}

  defp origin(_), do: {:error, :invalid_transport_scope_origin}

  defp limit(opts, key, default, max) do
    value = Keyword.get(opts, key, default)

    if is_integer(value) and value >= 1 and value <= max,
      do: {:ok, value},
      else: {:error, {:invalid_transport_scope_limit, key}}
  end

  defp freeze_ssl(%{scheme: "http"}, []), do: {:ok, []}
  defp freeze_ssl(%{scheme: "http"}, _), do: {:error, :transport_scope_tls_requires_https}

  defp freeze_ssl(origin, opts) do
    with true <- Keyword.keyword?(opts),
         true <- length(opts) == length(Enum.uniq(Keyword.keys(opts))),
         true <-
           Enum.all?(
             Keyword.keys(opts),
             &(&1 in (@tls_options ++ [:cacertfile, :certfile, :keyfile]))
           ),
         true <- bounded_term?(opts, 16),
         {:ok, opts} <- materialize(opts, :cacertfile, :cacerts),
         {:ok, opts} <- materialize(opts, :certfile, :cert),
         {:ok, opts} <- materialize(opts, :keyfile, :key),
         true <- Enum.all?(opts, &valid_tls_option?/1),
         true <-
           Keyword.get(opts, :server_name_indication, String.to_charlist(origin.host)) ==
             String.to_charlist(origin.host) do
      {:ok,
       opts
       |> Keyword.put_new(:cacerts, :public_key.cacerts_get())
       |> Keyword.put_new(:verify, :verify_peer)
       |> Keyword.put_new(:versions, [:"tlsv1.3", :"tlsv1.2"])
       |> Keyword.put_new(:depth, 4)
       |> Keyword.put(:server_name_indication, String.to_charlist(origin.host))}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_transport_scope_tls_policy}
    end
  end

  defp materialize(opts, file_key, value_key) do
    case Keyword.fetch(opts, file_key) do
      :error ->
        {:ok, opts}

      {:ok, path} ->
        with false <- Keyword.has_key?(opts, value_key),
             {:ok, bytes} <- read_file(path),
             {:ok, value} <- pem_value(:public_key.pem_decode(bytes), value_key) do
          {:ok, opts |> Keyword.delete(file_key) |> Keyword.put(value_key, value)}
        else
          _ -> {:error, {:invalid_transport_scope_tls_file, file_key}}
        end
    end
  end

  defp read_file(path) when is_binary(path) or is_list(path) do
    with {:ok, file} <- File.open(path, [:read, :binary]) do
      try do
        case IO.binread(file, @max_policy_bytes + 1) do
          bytes when is_binary(bytes) and byte_size(bytes) <= @max_policy_bytes -> {:ok, bytes}
          _ -> {:error, :tls_file_limit}
        end
      after
        File.close(file)
      end
    end
  end

  defp read_file(_), do: {:error, :invalid_tls_file}

  defp pem_value(entries, :cacerts) do
    certs = for {:Certificate, der, :not_encrypted} <- entries, do: der
    if certs == [], do: {:error, :empty_ca_file}, else: {:ok, certs}
  end

  defp pem_value([{:Certificate, der, :not_encrypted}], :cert), do: {:ok, der}

  defp pem_value([{type, der, :not_encrypted}], :key)
       when type in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo],
       do: {:ok, {type, der}}

  defp pem_value(_, _), do: {:error, :unsupported_pem}

  defp freeze_sockets(opts) do
    if Keyword.keyword?(opts) and length(opts) == length(Enum.uniq(Keyword.keys(opts))) and
         Enum.all?(opts, &valid_socket_option?/1) and
         Keyword.get(opts, :send_timeout_close, true) == true do
      {:ok,
       opts
       |> Keyword.put_new(:send_timeout, 30_000)
       |> Keyword.put_new(:buffer, 65_536)
       |> Keyword.put_new(:recbuf, 65_536)
       |> Keyword.put_new(:sndbuf, 65_536)
       |> Keyword.put_new(:send_timeout_close, true)}
    else
      {:error, :invalid_transport_scope_socket_policy}
    end
  end

  defp valid_socket_option?({key, value}) when key in [:nodelay, :keepalive, :send_timeout_close],
    do: is_boolean(value)

  defp valid_socket_option?({key, value}),
    do: key in @socket_options and is_integer(value) and value > 0 and value <= 1_048_576

  defp valid_tls_option?({:verify, value}), do: value in [:verify_peer, :verify_none]
  defp valid_tls_option?({:depth, value}), do: is_integer(value) and value >= 0 and value <= 100

  defp valid_tls_option?({:versions, value}),
    do: is_list(value) and value != [] and Enum.all?(value, &(&1 in [:"tlsv1.2", :"tlsv1.3"]))

  defp valid_tls_option?({:cacerts, value}), do: is_list(value) and Enum.all?(value, &is_binary/1)
  defp valid_tls_option?({:cert, value}), do: is_binary(value)

  defp valid_tls_option?({:key, {type, value}}),
    do: type in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo] and is_binary(value)

  defp valid_tls_option?({:server_name_indication, value}),
    do: is_list(value) and Enum.all?(value, &is_integer/1)

  defp valid_tls_option?({key, value})
       when key in [:honor_cipher_order, :reuse_sessions, :middlebox_comp_mode],
       do: is_boolean(value)

  defp valid_tls_option?({:session_tickets, value}), do: value in [:disabled, :manual, :auto]

  defp valid_tls_option?({key, value})
       when key in [:ciphers, :signature_algs, :signature_algs_cert, :supported_groups],
       do: is_list(value) and value != []

  defp valid_tls_option?(_), do: false

  defp bounded_term?(_, 0), do: false

  defp bounded_term?(value, _)
       when is_function(value) or is_pid(value) or is_port(value) or is_reference(value),
       do: false

  defp bounded_term?(value, depth) when is_list(value),
    do: length(value) <= 4_096 and Enum.all?(value, &bounded_term?(&1, depth - 1))

  defp bounded_term?(value, depth) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&bounded_term?(&1, depth - 1))

  defp bounded_term?(value, _) when is_binary(value), do: byte_size(value) <= @max_policy_bytes
  defp bounded_term?(value, _), do: is_atom(value) or is_number(value)

  defp normalize_key("transport_scope"), do: :transport_scope
  defp normalize_key("transportScope"), do: :transport_scope

  defp normalize_key(key) when is_binary(key) do
    key = key |> then(&Regex.replace(~r/([a-z0-9])([A-Z])/, &1, "\\1_\\2")) |> String.downcase()

    case Enum.find(
           @open_options ++
             [
               :http1_reuse,
               :http1_pool_size,
               :http1_idle_timeout,
               :http2_reuse,
               :redirect,
               :decode_body,
               :stream_response,
               :proxy,
               :unix_socket,
               :http1_scope,
               :http2_scope,
               :http2_priority,
               :http3_profile,
               :http3_reuse
             ],
           &(Atom.to_string(&1) == key)
         ) do
      nil -> key
      atom -> atom
    end
  end

  defp normalize_key(key), do: key
end

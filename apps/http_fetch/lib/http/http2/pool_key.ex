defmodule HTTP.HTTP2.PoolKey do
  @moduledoc """
  Builds a safe, comparable identity for a reusable HTTP/2 connection.

  The returned key contains only normalized values and digests. In particular,
  TLS files are identified by their contents and metadata, never by path alone,
  and callback or opaque option values are conservatively marked non-reusable.
  """

  alias HTTP.HTTP2.WireProfile
  alias HTTP.Request

  @type key :: map()
  @type result :: {:ok, key()} | {:ok, :non_reusable, key()} | {:error, term()}

  @doc """
  Builds a pool identity from a request, compiled (or compilable) profile and
  the protocol actually negotiated by the transport.

  `opts` may provide transport routing values such as `:unix_socket` and is
  merged over the request transport options. Supported protocols are `:h2` and
  `:h2c`; unsupported route/proxy options are rejected explicitly.
  """
  @spec build(
          Request.t(),
          WireProfile.t() | map() | atom() | binary(),
          atom() | binary(),
          keyword()
        ) ::
          result()
  def build(request, profile, actual_protocol, opts \\ [])

  def build(%Request{} = request, profile, actual_protocol, opts) when is_list(opts) do
    with {:ok, protocol} <- normalize_protocol(actual_protocol),
         {:ok, profile} <- WireProfile.compile(profile),
         {:ok, profile_digest} <- WireProfile.digest(profile),
         {:ok, origin} <- origin(request.url, protocol),
         transport_options = Keyword.merge(request.transport_options, opts),
         :ok <- validate_route(transport_options),
         {:ok, tls_identity, tls_reusable?} <- tls_identity(transport_options, origin),
         {:ok, socket_identity, socket_reusable?} <-
           option_identity(Keyword.get(transport_options, :socket_opts, []), :socket_opts),
         {:ok, connect_identity, connect_reusable?} <-
           option_identity(connection_options(transport_options), :connection_options),
         {:ok, scope, scope_reusable?} <- scope_identity(transport_options),
         {:ok, route, route_reusable?} <- route_identity(transport_options),
         {:ok, reuse} <- reuse_marker(transport_options) do
      key = %{
        version: 1,
        scheme: origin.scheme,
        host: origin.host,
        port: origin.port,
        protocol: protocol,
        route: route,
        unix_socket: digest_optional(Keyword.get(transport_options, :unix_socket)),
        proxy: digest_optional(Keyword.get(transport_options, :proxy)),
        tls: tls_identity,
        socket_options: socket_identity,
        connection_options: connect_identity,
        wire_profile: profile_digest,
        http2_scope: scope,
        reuse: reuse
      }

      reusable? =
        tls_reusable? and socket_reusable? and connect_reusable? and
          scope_reusable? and route_reusable? and reuse == :shared

      if reusable?, do: {:ok, key}, else: {:ok, :non_reusable, key}
    end
  end

  def build(_request, _profile, _actual_protocol, _opts),
    do: {:error, :invalid_pool_key_arguments}

  defp normalize_protocol(protocol) when protocol in [:h2, "h2", :http2], do: {:ok, :h2}
  defp normalize_protocol(protocol) when protocol in [:h2c, "h2c"], do: {:ok, :h2c}
  defp normalize_protocol(_protocol), do: {:error, :unsupported_http2_protocol}

  defp origin(%URI{scheme: scheme, host: host, port: port}, protocol)
       when is_binary(scheme) and is_binary(host) do
    scheme = String.downcase(scheme)
    host = normalize_host(host)
    port = port || default_port(scheme)

    cond do
      host == "" -> {:error, :missing_origin_host}
      protocol == :h2 and scheme != "https" -> {:error, :h2_requires_https}
      protocol == :h2c and scheme != "http" -> {:error, :h2c_requires_http}
      not is_integer(port) or port < 1 or port > 65_535 -> {:error, :invalid_origin_port}
      true -> {:ok, %{scheme: scheme, host: host, port: port}}
    end
  end

  defp origin(_url, _protocol), do: {:error, :invalid_request_url}

  defp normalize_host(host) do
    host
    |> String.trim()
    |> String.downcase()
    |> String.trim_trailing(".")
  end

  defp default_port("https"), do: 443
  defp default_port("http"), do: 80
  defp default_port(_), do: nil

  defp validate_route(options) do
    unsupported = [:proxy, :proxy_url, :proxy_opts]

    bad_proxy =
      Enum.find(unsupported, fn key ->
        Keyword.has_key?(options, key) and not is_nil(options[key])
      end)

    case bad_proxy do
      nil ->
        case Keyword.get(options, :route, :direct) do
          :direct -> :ok
          nil -> :ok
          _ -> {:error, {:unsupported_route, :route}}
        end

      key ->
        {:error, {:unsupported_route, key}}
    end
  end

  defp route_identity(options) do
    route = Keyword.get(options, :route, :direct)
    safe_identity(route, :route)
  end

  defp tls_identity(options, origin) do
    backend = Keyword.get(options, :tls_backend, :ssl)
    ssl_options = Keyword.get(options, :ssl, [])

    with {:ok, backend} <- normalize_backend(backend),
         {:ok, identity, reusable?} <- ssl_identity(ssl_options, origin) do
      {:ok, %{backend: backend, options: identity}, reusable?}
    end
  end

  defp normalize_backend(backend) when backend in [:ssl, "ssl"], do: {:ok, :ssl}
  defp normalize_backend(backend) when backend in [:ex_ssl, "ex_ssl"], do: {:ok, :ex_ssl}
  defp normalize_backend(_backend), do: {:error, :invalid_tls_backend}

  defp ssl_identity(options, origin) when is_list(options) do
    if Keyword.keyword?(options) do
      Enum.reduce_while(options, {:ok, %{}, true}, fn {name, value}, {:ok, acc, reusable?} ->
        case tls_option_identity(name, value, origin) do
          {:ok, identity, value_reusable?} ->
            {:cont, {:ok, Map.put(acc, name, identity), reusable? and value_reusable?}}

          {:error, reason} ->
            {:halt, {:error, reason}}
        end
      end)
    else
      {:error, {:invalid_tls_options, :not_a_keyword}}
    end
  end

  defp ssl_identity(_options, _origin), do: {:error, {:invalid_tls_options, :not_a_keyword}}

  defp tls_option_identity(name, value, _origin)
       when name in [:cacertfile, :certfile, :keyfile, :dhfile, :crlfile] do
    file_identity(value, name)
  end

  defp tls_option_identity(name, value, _origin) when name in [:cert, :key, :cacerts] do
    binary_identity(value, name)
  end

  defp tls_option_identity(:server_name_indication, value, _origin),
    do: safe_identity(value, :sni)

  defp tls_option_identity(:verify, value, _origin), do: safe_identity(value, :verify)

  defp tls_option_identity(:alpn_advertised_protocols, value, _origin),
    do: safe_identity(value, :alpn)

  defp tls_option_identity(:alpn_preferred_protocols, value, _origin),
    do: safe_identity(value, :alpn)

  defp tls_option_identity(name, value, _origin)
       when name in [:verify_fun, :customize_hostname_check],
       do: non_reusable_identity(name, value)

  defp tls_option_identity(:ex_ssl, value, _origin), do: safe_identity(value, :ex_ssl_profile)
  defp tls_option_identity(name, value, _origin), do: safe_identity(value, name)

  defp file_identity(path, name) when is_binary(path) do
    case File.stat(path, time: :posix) do
      {:ok, stat} ->
        with {:ok, contents} <- File.read(path) do
          {:ok, %{kind: name, digest: digest({stat.size, stat.mtime, stat.mode, contents})}, true}
        else
          {:error, reason} -> {:error, {:tls_file_unreadable, name, reason}}
        end

      {:error, reason} ->
        {:error, {:tls_file_unavailable, name, reason}}
    end
  end

  defp file_identity(_path, name), do: {:error, {:invalid_tls_file, name}}

  defp binary_identity(value, name) when is_binary(value),
    do: {:ok, %{kind: name, digest: digest(value)}, true}

  defp binary_identity(value, name) when is_list(value) do
    if Enum.all?(value, &is_binary/1),
      do: {:ok, %{kind: name, digest: digest(value)}, true},
      else: {:error, {:invalid_tls_value, name}}
  end

  defp binary_identity(_value, name), do: {:error, {:invalid_tls_value, name}}

  defp option_identity(value, name), do: safe_identity(value, name)

  defp connection_options(options) do
    Keyword.take(options, [:connect_timeout, :tls_backend, :http_version])
  end

  defp scope_identity(options) do
    case Keyword.fetch(options, :http2_scope) do
      :error -> {:ok, :default, true}
      {:ok, nil} -> {:ok, :default, true}
      {:ok, value} -> safe_identity(value, :http2_scope)
    end
  end

  defp reuse_marker(options) do
    case Keyword.get(options, :http2_reuse, true) do
      true -> {:ok, :shared}
      false -> {:ok, {:isolated, :crypto.strong_rand_bytes(16)}}
      value -> {:error, {:invalid_http2_reuse, value}}
    end
  end

  defp safe_identity(value, name) do
    if safe_term?(value) do
      {:ok, %{kind: name, digest: digest(value)}, true}
    else
      non_reusable_identity(name, value)
    end
  end

  defp non_reusable_identity(name, value) do
    {:ok, %{kind: name, digest: digest_safe_term(value)}, false}
  end

  defp safe_term?(value)
       when is_function(value) or is_pid(value) or is_port(value) or is_reference(value),
       do: false

  defp safe_term?(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.all?(&safe_term?/1)

  defp safe_term?(value) when is_list(value), do: Enum.all?(value, &safe_term?/1)

  defp safe_term?(value) when is_map(value),
    do: Enum.all?(value, fn {k, v} -> safe_term?(k) and safe_term?(v) end)

  defp safe_term?(_value), do: true

  defp digest_safe_term(value), do: digest(:erlang.term_to_binary(value, [:deterministic]))

  defp digest(value),
    do:
      Base.encode16(:crypto.hash(:sha256, :erlang.term_to_binary(value, [:deterministic])),
        case: :lower
      )

  defp digest_optional(nil), do: nil
  defp digest_optional(value), do: digest_safe_term(value)
end

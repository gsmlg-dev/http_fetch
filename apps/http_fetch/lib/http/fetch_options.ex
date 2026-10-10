defmodule HTTP.FetchOptions do
  @moduledoc """
  Options processing for `HTTP.fetch/2` requests.

  `HTTP.fetch/2` accepts a flat init keyword list or map, mirroring the browser
  `fetch(input, init)` shape. Supported fetch-style options are:

  - `method` - HTTP method, defaulting to `GET`
  - `headers` - request headers as a list, map, or `HTTP.Headers`
  - `body` - request body
  - `duplex` - request streaming mode; `:half` or `"half"` for streaming bodies
  - `signal` - `HTTP.AbortController` PID
  - `redirect` - `:follow`, `:manual`, or `:error`; defaults to `:follow`

  The socket transport also accepts Elixir-specific extensions:

  - `telemetry` - emit request and stream telemetry; defaults to `true`. Shared
    pool/connection counters require the global opt-out in `HTTP.Telemetry`.
  - `decode_body` - decode response Content-Encoding; defaults to `true`. Set
    `false` to preserve stored entity bytes for buffered and streamed HTTP/1,
    HTTP/2, and HTTP/3 responses without changing headers.
  - `stream_response` - set `true` to resolve at final response headers and
    expose an acknowledged body stream, even for small Content-Length bodies.
    Defaults to `false` (automatic size/framing policy). HEAD and bodyless
    statuses remain buffered empty responses. The request timeout still bounds
    the entire response; callers can observe headers before applying a body deadline.
  - `request_mode` - `:fetch` (default) or `:proxy`; proxy mode retains request
    entities for all admitted methods, including GET, DELETE, and HEAD
  - `content_type` - convenience Content-Type value for request bodies
  - `timeout` - request timeout in milliseconds
  - `connect_timeout` - connection timeout in milliseconds
  - `connect_address` - caller-validated literal IPv4/IPv6 tuple to dial instead
    of resolving the URL hostname. Keeps original HTTP authority, TLS SNI and
    certificate hostname verification. No DNS/address fallback or request replay.
    Requires `redirect: :manual` or `:error`; validate every permitted redirect
    hop independently and provide that hop's pin. HTTP/3, Unix sockets and
    proxies are unsupported. Pools isolate each pin from DNS and other targets.
    Cancellation and request/connect deadlines cover establishment. Conflicting
    TLS SNI rejects before I/O; native verification and trust defaults remain.
    With `:ex_ssl`, a literal-IP HTTPS URL must match the pin, since a distinct
    original IP verification identity is currently unsupported.
  - `http_version` - protocol selection, one of `:http1`, `:http2`, `:http3`,
    `:h2c`, or `:auto`; defaults to `:http1`
  - `tls_backend` - TLS implementation, `:ssl` or `:ex_ssl`; defaults to the
    shared `:http_core, :tls_backend` configuration
  - `ssl` - TLS options passed to the selected TLS backend
  - `socket_opts` - socket options passed to the underlying transport
  - `unix_socket` - Unix Domain Socket path
  - `http1_reuse` - opt in to HTTP/1 keep-alive; requires `http_version: :http1`.
    Only fully consumed, self-delimited responses are reusable. Failed or
    cancelled requests are closed, and requests are never retried on stale peers.
  - `http1_scope` - optional atom or string separating caller routes sharing an origin.
  - `http1_pool_size` - retained idle sockets per route/policy, 1..16 (default 2).
  - `http1_idle_timeout` - idle retention in milliseconds, 1..60,000 (default 30,000).
    All callers share a maximum of 256 idle sockets. TLS identities, socket
    options, isolation scope and route policies are part of the reuse key;
    opaque callbacks disable reuse. HTTP/1 reuse defaults to `false`.

  - `proxy` - explicit proxy `{:http, host, port, opts}` or
    `{:https, host, port, opts}`. Options are
    `headers: [{"Proxy-Authorization", value}]` and a finite positive `timeout`.
    HTTP/1 cleartext uses absolute-form forwarding; HTTPS uses CONNECT and then
    origin TLS/ALPN. H2 over HTTPS is supported. H2c, HTTP/3, Unix socket routes,
    and ExSSL IP-origin tunnels are rejected explicitly. Environment/NO_PROXY
    selection belongs to the caller.
    HTTPS proxies support HTTP origins only, using TLS to the proxy and
    absolute-form HTTP/1 forwarding. `ssl` and `tls_backend` apply to the proxy;
    its hostname is the certificate/SNI identity. TLS-over-TLS origins are
    rejected. Proxy scheme, endpoint, credentials, and TLS policy isolate pools.
  - `http2_profile` - versioned HTTP/2 wire profile (only used by HTTP/2)
  - `http2_reuse` - whether an HTTP/2 connection may be reused; defaults to `true`
  - `http3_profile` - QUIC wire profile; defaults to `:ordered`
  - `http3_reuse` - whether an HTTP/3 connection may be reused; defaults to `true`
  - `http2_scope` - non-sensitive caller isolation scope
  - `http2_priority` - per-request HTTP/2 priority metadata
  """

  @string_keys %{
    "body" => :body,
    "request_mode" => :request_mode,
    "requestMode" => :request_mode,
    "connect_address" => :connect_address,
    "connectAddress" => :connect_address,
    "connect_timeout" => :connect_timeout,
    "connectTimeout" => :connect_timeout,
    "content_type" => :content_type,
    "contentType" => :content_type,
    "duplex" => :duplex,
    "decode_body" => :decode_body,
    "decodeBody" => :decode_body,
    "stream_response" => :stream_response,
    "streamResponse" => :stream_response,
    "headers" => :headers,
    "http_version" => :http_version,
    "httpVersion" => :http_version,
    "http1_reuse" => :http1_reuse,
    "http1Reuse" => :http1_reuse,
    "http1_scope" => :http1_scope,
    "http1Scope" => :http1_scope,
    "http1_pool_size" => :http1_pool_size,
    "http1PoolSize" => :http1_pool_size,
    "http1_idle_timeout" => :http1_idle_timeout,
    "http1IdleTimeout" => :http1_idle_timeout,
    "http2_profile" => :http2_profile,
    "http2Profile" => :http2_profile,
    "http2_reuse" => :http2_reuse,
    "http2Reuse" => :http2_reuse,
    "http3_profile" => :http3_profile,
    "http3Profile" => :http3_profile,
    "http3_reuse" => :http3_reuse,
    "http3Reuse" => :http3_reuse,
    "http2_scope" => :http2_scope,
    "http2Scope" => :http2_scope,
    "http2_priority" => :http2_priority,
    "http2Priority" => :http2_priority,
    "proxy" => :proxy,
    "method" => :method,
    "redirect" => :redirect,
    "signal" => :signal,
    "socket_opts" => :socket_opts,
    "socketOpts" => :socket_opts,
    "ssl" => :ssl,
    "tls_backend" => :tls_backend,
    "tlsBackend" => :tls_backend,
    "timeout" => :timeout,
    "telemetry" => :telemetry,
    "unix_socket" => :unix_socket,
    "unixSocket" => :unix_socket
  }

  defstruct method: :get,
            request_mode: :fetch,
            headers: %HTTP.Headers{},
            content_type: nil,
            body: nil,
            duplex: nil,
            decode_body: true,
            stream_response: false,
            telemetry: true,
            signal: nil,
            unix_socket: nil,
            redirect: :follow,
            http_version: :http1,
            tls_backend: nil,
            timeout: nil,
            connect_timeout: nil,
            connect_address: nil,
            ssl: nil,
            socket_opts: nil,
            proxy: nil,
            http1_reuse: false,
            http1_scope: nil,
            http1_pool_size: 2,
            http1_idle_timeout: 30_000,
            http2_profile: nil,
            http2_reuse: true,
            http3_profile: nil,
            http3_reuse: true,
            http2_scope: nil,
            http2_priority: nil

  @type redirect :: :follow | :manual | :error
  @type http_version :: :http1 | :http2 | :http3 | :h2c | :auto
  @type tls_backend :: term()

  @type t :: %__MODULE__{
          method: atom(),
          request_mode: HTTP.Request.request_mode(),
          headers: HTTP.Headers.t(),
          content_type: String.t() | nil,
          body: any(),
          duplex: :half | nil,
          decode_body: boolean(),
          stream_response: boolean(),
          telemetry: boolean(),
          signal: any() | nil,
          unix_socket: String.t() | nil,
          redirect: redirect(),
          http_version: http_version(),
          tls_backend: tls_backend(),
          timeout: integer() | nil,
          connect_timeout: integer() | nil,
          connect_address: :inet.ip_address() | nil,
          ssl: list() | nil,
          socket_opts: list() | nil,
          http1_reuse: boolean(),
          http1_scope: atom() | String.t() | nil,
          http1_pool_size: pos_integer(),
          http1_idle_timeout: pos_integer(),
          proxy: {:http | :https, String.t(), :inet.port_number(), keyword()} | nil,
          http2_profile: atom() | String.t() | map() | nil,
          http2_reuse: boolean(),
          http3_profile: atom() | map() | nil,
          http3_reuse: boolean(),
          http2_scope: atom() | String.t() | nil,
          http2_priority: map() | keyword() | nil
        }

  @doc """
  Creates a new FetchOptions struct from a flat map, keyword list, or existing
  FetchOptions struct.
  """
  @spec new(map() | keyword() | t()) :: t()
  def new(%__MODULE__{} = options), do: normalize_options(options)

  def new(options) when is_map(options) do
    options
    |> Enum.map(fn {key, value} -> {normalize_key(key), value} end)
    |> new()
  end

  def new(options) when is_list(options) do
    %__MODULE__{}
    |> merge_options(options)
    |> normalize_options()
  end

  @doc """
  Converts fetch init options to the internal socket transport option list.
  """
  @spec to_transport_options(t()) :: keyword()
  def to_transport_options(%__MODULE__{} = options) do
    []
    |> maybe_add(:telemetry, options.telemetry)
    |> maybe_add(:decode_body, options.decode_body)
    |> maybe_add(:stream_response, options.stream_response)
    |> maybe_add(:timeout, options.timeout)
    |> maybe_add(:connect_timeout, options.connect_timeout)
    |> maybe_add(:connect_address, options.connect_address)
    |> maybe_add(:ssl, options.ssl)
    |> maybe_add(:socket_opts, options.socket_opts)
    |> maybe_add(:proxy, options.proxy)
    |> maybe_add(:redirect, options.redirect)
    |> maybe_add(:http_version, options.http_version)
    |> maybe_add(:tls_backend, options.tls_backend)
    |> maybe_add(:http1_reuse, if(options.http1_reuse, do: true, else: nil))
    |> maybe_add(:http1_scope, options.http1_scope)
    |> maybe_add(:http1_pool_size, if(options.http1_reuse, do: options.http1_pool_size))
    |> maybe_add(:http1_idle_timeout, if(options.http1_reuse, do: options.http1_idle_timeout))
    |> maybe_add(:http2_profile, options.http2_profile)
    |> maybe_add(:http2_reuse, if(options.http2_reuse, do: nil, else: false))
    |> maybe_add(:http3_profile, options.http3_profile)
    |> maybe_add(:http3_reuse, if(options.http3_reuse, do: nil, else: false))
    |> maybe_add(:http2_scope, options.http2_scope)
    |> maybe_add(:http2_priority, options.http2_priority)
  end

  @doc """
  Extracts the HTTP method from options.
  """
  @spec get_method(t()) :: atom()
  def get_method(%__MODULE__{method: method}), do: method

  @doc """
  Extracts headers from options.
  """
  @spec get_headers(t()) :: HTTP.Headers.t()
  def get_headers(%__MODULE__{headers: headers}), do: headers

  @doc """
  Extracts body from options.
  """
  @spec get_body(t()) :: any()
  def get_body(%__MODULE__{body: body}), do: body

  @doc """
  Extracts the request body streaming mode from options.
  """
  @spec get_duplex(t()) :: :half | nil
  def get_duplex(%__MODULE__{duplex: duplex}), do: duplex

  @doc """
  Extracts content type from options.
  """
  @spec get_content_type(t()) :: String.t() | nil
  def get_content_type(%__MODULE__{content_type: content_type}), do: content_type

  defp merge_options(%__MODULE__{} = struct, options) do
    Enum.reduce(options, struct, fn
      {:method, method}, acc ->
        %{acc | method: normalize_method(method)}

      {:request_mode, mode}, acc ->
        %{acc | request_mode: mode}

      {:headers, headers}, acc ->
        %{acc | headers: normalize_headers(headers)}

      {:content_type, content_type}, acc ->
        %{acc | content_type: content_type}

      {:body, body}, acc ->
        %{acc | body: body}

      {:duplex, duplex}, acc ->
        %{acc | duplex: normalize_duplex(duplex)}

      {:telemetry, telemetry}, acc ->
        %{acc | telemetry: telemetry}

      {:stream_response, stream_response}, acc ->
        %{acc | stream_response: stream_response}

      {:decode_body, decode_body}, acc ->
        %{acc | decode_body: decode_body}

      {:signal, signal}, acc ->
        %{acc | signal: signal}

      {:unix_socket, unix_socket}, acc ->
        %{acc | unix_socket: unix_socket}

      {:redirect, redirect}, acc ->
        %{acc | redirect: redirect}

      {:http_version, http_version}, acc ->
        %{acc | http_version: http_version}

      {:tls_backend, tls_backend}, acc ->
        %{acc | tls_backend: tls_backend}

      {:timeout, timeout}, acc ->
        %{acc | timeout: timeout}

      {:connect_timeout, connect_timeout}, acc ->
        %{acc | connect_timeout: connect_timeout}

      {:connect_address, connect_address}, acc ->
        %{acc | connect_address: connect_address}

      {:ssl, ssl}, acc ->
        %{acc | ssl: ssl}

      {:proxy, proxy}, acc ->
        %{acc | proxy: proxy}

      {:socket_opts, socket_opts}, acc ->
        %{acc | socket_opts: socket_opts}

      {:http1_reuse, reuse}, acc ->
        %{acc | http1_reuse: reuse}

      {:http1_scope, scope}, acc ->
        %{acc | http1_scope: scope}

      {:http1_pool_size, size}, acc ->
        %{acc | http1_pool_size: size}

      {:http1_idle_timeout, timeout}, acc ->
        %{acc | http1_idle_timeout: timeout}

      {:http2_profile, profile}, acc ->
        %{acc | http2_profile: profile}

      {:http2_reuse, reuse}, acc ->
        %{acc | http2_reuse: reuse}

      {:http3_profile, profile}, acc ->
        %{acc | http3_profile: profile}

      {:http3_reuse, reuse}, acc ->
        %{acc | http3_reuse: reuse}

      {:http2_scope, scope}, acc ->
        %{acc | http2_scope: scope}

      {:http2_priority, priority}, acc ->
        %{acc | http2_priority: priority}

      {key, _value}, acc when is_atom(key) or is_binary(key) ->
        if http2_option_key?(key) do
          raise ArgumentError, "unsupported HTTP/2 option: #{inspect(key)}"
        else
          acc
        end
    end)
  end

  defp normalize_key(key) when is_binary(key), do: Map.get(@string_keys, key, key)
  defp normalize_key(key), do: key

  defp normalize_headers(%HTTP.Headers{} = headers), do: headers
  defp normalize_headers(headers) when is_list(headers), do: HTTP.Headers.new(headers)
  defp normalize_headers(headers) when is_map(headers), do: HTTP.Headers.from_map(headers)
  defp normalize_headers(_), do: HTTP.Headers.new()

  defp normalize_options(%__MODULE__{} = options) do
    http_version = normalize_http_version(options.http_version)

    %{
      options
      | method: normalize_method(options.method),
        request_mode: normalize_request_mode(options.request_mode),
        redirect: normalize_redirect(options.redirect),
        duplex: normalize_duplex(options.duplex),
        decode_body: normalize_decode_body(options.decode_body),
        stream_response: normalize_stream_response(options.stream_response),
        telemetry: normalize_telemetry(options.telemetry),
        http_version: http_version,
        tls_backend: normalize_tls_backend(options.tls_backend, http_version),
        http1_reuse: normalize_http1_reuse(options.http1_reuse, http_version),
        http1_scope: normalize_http2_scope(options.http1_scope),
        http1_pool_size: normalize_http1_limit(options.http1_pool_size, 16, :http1_pool_size),
        http1_idle_timeout:
          normalize_http1_limit(options.http1_idle_timeout, 60_000, :http1_idle_timeout),
        http2_profile: normalize_http2_profile(options.http2_profile),
        http2_reuse: normalize_http2_reuse(options.http2_reuse),
        http3_reuse: normalize_http3_reuse(options.http3_reuse),
        http2_scope: normalize_http2_scope(options.http2_scope),
        http2_priority: normalize_http2_priority(options.http2_priority)
    }
    |> validate_connect_address()
  end

  defp validate_connect_address(%{connect_address: nil} = options), do: options

  defp validate_connect_address(options) do
    cond do
      not HTTP.Transport.valid_connect_address?(options.connect_address) ->
        raise ArgumentError, "invalid connect_address: expected a literal IPv4 or IPv6 tuple"

      options.redirect == :follow ->
        raise ArgumentError,
              "connect_address requires redirect: :manual or :error; validate each hop"

      options.http_version == :http3 or options.unix_socket != nil or options.proxy != nil ->
        raise ArgumentError, "connect_address is unsupported with HTTP/3, Unix sockets or proxies"

      true ->
        options
    end
  end

  defp normalize_request_mode(mode) when mode in [:fetch, :proxy], do: mode
  defp normalize_request_mode("fetch"), do: :fetch
  defp normalize_request_mode("proxy"), do: :proxy

  defp normalize_request_mode(mode),
    do:
      raise(
        ArgumentError,
        "unsupported request_mode: #{inspect(mode)}; expected :fetch or :proxy"
      )

  defp normalize_http1_reuse(false, _version), do: false
  defp normalize_http1_reuse(true, :http1), do: true

  defp normalize_http1_reuse(value, version),
    do: raise(ArgumentError, "invalid http1_reuse: #{inspect(value)} for #{inspect(version)}")

  defp normalize_http1_limit(value, limit, _key)
       when is_integer(value) and value >= 1 and value <= limit,
       do: value

  defp normalize_http1_limit(value, _limit, key),
    do: raise(ArgumentError, "invalid #{key}: #{inspect(value)}")

  defp normalize_telemetry(value) when is_boolean(value), do: value

  defp normalize_telemetry(value),
    do: raise(ArgumentError, "invalid telemetry: #{inspect(value)}; expected boolean")

  defp normalize_stream_response(value) when is_boolean(value), do: value

  defp normalize_stream_response(value),
    do: raise(ArgumentError, "invalid stream_response: #{inspect(value)}; expected boolean")

  defp normalize_decode_body(value) when is_boolean(value), do: value

  defp normalize_decode_body(value),
    do: raise(ArgumentError, "invalid decode_body: #{inspect(value)}; expected boolean")

  defp normalize_method(method) when is_binary(method) do
    method |> String.downcase() |> String.to_atom()
  end

  defp normalize_method(method) when is_atom(method), do: method

  defp normalize_redirect(nil), do: :follow
  defp normalize_redirect(:follow), do: :follow
  defp normalize_redirect(:manual), do: :manual
  defp normalize_redirect(:error), do: :error

  defp normalize_redirect(redirect) when is_binary(redirect) do
    case String.downcase(redirect) do
      "follow" -> :follow
      "manual" -> :manual
      "error" -> :error
      _ -> raise ArgumentError, redirect_error_message(redirect)
    end
  end

  defp normalize_redirect(redirect), do: raise(ArgumentError, redirect_error_message(redirect))

  defp redirect_error_message(redirect),
    do: "unsupported redirect mode: #{inspect(redirect)}; expected :follow, :manual, or :error"

  defp normalize_duplex(nil), do: nil
  defp normalize_duplex(:half), do: :half

  defp normalize_duplex(duplex) when is_binary(duplex) do
    case String.downcase(duplex) do
      "half" -> :half
      _ -> raise ArgumentError, duplex_error_message(duplex)
    end
  end

  defp normalize_duplex(duplex), do: raise(ArgumentError, duplex_error_message(duplex))

  defp duplex_error_message(duplex),
    do: "unsupported duplex mode: #{inspect(duplex)}; expected :half or \"half\""

  defp normalize_http_version(nil), do: :http1
  defp normalize_http_version(:http1), do: :http1
  defp normalize_http_version(:http2), do: :http2
  defp normalize_http_version(:http3), do: :http3
  defp normalize_http_version(:h2c), do: :h2c
  defp normalize_http_version(:auto), do: :auto

  defp normalize_http_version(http_version) when is_binary(http_version) do
    case String.downcase(http_version) do
      "http1" -> :http1
      "http/1.1" -> :http1
      "http2" -> :http2
      "h2" -> :http2
      "http3" -> :http3
      "h3" -> :http3
      "h2c" -> :h2c
      "auto" -> :auto
      _ -> raise ArgumentError, http_version_error_message(http_version)
    end
  end

  defp normalize_http_version(http_version),
    do: raise(ArgumentError, http_version_error_message(http_version))

  defp http_version_error_message(http_version) do
    "unsupported http_version: #{inspect(http_version)}; expected :http1, :http2, :http3, :h2c, or :auto"
  end

  defp normalize_tls_backend(nil, :http3), do: nil
  defp normalize_tls_backend(tls_backend, :http3), do: tls_backend
  defp normalize_tls_backend(tls_backend, _http_version), do: resolve_tls_backend(tls_backend)

  defp normalize_http2_profile(nil), do: nil
  defp normalize_http2_profile(profile) when is_atom(profile) or is_binary(profile), do: profile

  defp normalize_http2_profile(profile) when is_map(profile) do
    allowed = [:id, :version, :synthetic]
    allowed_strings = Enum.map(allowed, &Atom.to_string/1)

    if Enum.all?(
         Map.keys(profile),
         &(&1 in allowed or (is_binary(&1) and &1 in allowed_strings))
       ) do
      profile
    else
      raise ArgumentError, "invalid http2_profile: unsupported profile field"
    end
  end

  defp normalize_http2_profile(profile),
    do: raise(ArgumentError, "invalid http2_profile: #{inspect(profile)}")

  defp normalize_http3_reuse(nil), do: true
  defp normalize_http3_reuse(value) when is_boolean(value), do: value

  defp normalize_http3_reuse(value),
    do: raise(ArgumentError, "invalid http3_reuse: #{inspect(value)}; expected boolean")

  defp normalize_http2_reuse(nil), do: true
  defp normalize_http2_reuse(value) when is_boolean(value), do: value

  defp normalize_http2_reuse(value),
    do: raise(ArgumentError, "invalid http2_reuse: #{inspect(value)}; expected boolean")

  defp normalize_http2_scope(nil), do: nil
  defp normalize_http2_scope(value) when is_atom(value) or is_binary(value), do: value

  defp normalize_http2_scope(value),
    do: raise(ArgumentError, "invalid http2_scope: #{inspect(value)}; expected atom or string")

  defp normalize_http2_priority(nil), do: nil
  defp normalize_http2_priority(value) when is_map(value) or is_list(value), do: value

  defp normalize_http2_priority(value),
    do:
      raise(
        ArgumentError,
        "invalid http2_priority: #{inspect(value)}; expected map or keyword list"
      )

  defp http2_option_key?(key) when is_atom(key),
    do: key |> Atom.to_string() |> http2_option_key?()

  defp http2_option_key?(key) when is_binary(key),
    do: String.starts_with?(key, "http2_") or String.starts_with?(key, "http2")

  defp resolve_tls_backend(tls_backend) do
    case HTTP.TLSBackend.resolve(tls_backend) do
      {:ok, backend} ->
        backend

      {:error, :invalid_tls_backend} ->
        raise ArgumentError, tls_backend_error_message(tls_backend)
    end
  end

  defp tls_backend_error_message(tls_backend) do
    "unsupported tls_backend: #{inspect(tls_backend)}; expected :ssl or :ex_ssl"
  end

  defp maybe_add(list, _key, nil), do: list
  defp maybe_add(list, key, value), do: Keyword.put(list, key, value)
end

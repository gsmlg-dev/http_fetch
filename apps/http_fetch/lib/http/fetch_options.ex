defmodule HTTP.FetchOptions do
  @moduledoc """
  Options processing for `HTTP.fetch/2` requests.

  `HTTP.fetch/2` accepts a flat init keyword list or map, mirroring the browser
  `fetch(input, init)` shape. Supported fetch-style options are:

  - `method` - nonempty ASCII HTTP method token, defaulting to `GET`. Common
    methods normalize to their conventional atoms; other binary methods retain
    their case, and atom methods are uppercased on the wire. DAV methods such as
    `:propfind` and `:report` carry bodies normally. Invalid token bytes reject
    before network I/O; extension strings are never converted into new atoms.
  - `headers` - request headers as a list, map, or `HTTP.Headers`
  - `body` - request body
  - `duplex` - request streaming mode; `:half` or `"half"` for streaming bodies
  - `signal` - `HTTP.AbortController` PID (`nil` for none); any other value raises `ArgumentError`
  - `redirect` - `:follow`, `:manual`, or `:error`; defaults to `:follow`

  Unknown option keys raise `ArgumentError`.

  The socket transport also accepts Elixir-specific extensions:

  - `telemetry` - emit request and stream telemetry; defaults to `true`. Shared
    pool/connection counters require the global opt-out in `HTTP.Telemetry`.
  - `decode_body` - decode response Content-Encoding; defaults to `true`. Set
    `false` to preserve stored entity bytes for buffered and streamed HTTP/1,
    HTTP/2, and HTTP/3 responses without changing headers.
  - `max_decoded_body_size` - maximum decoded size in bytes of a response body
    whose Content-Encoding is decoded, as a positive integer or `:infinity`.
    Defaults to `HTTP.Config.max_decoded_body_size/0` (50,000,000 bytes).
    Inflation is incremental, so a compression bomb fails with
    `{:error, :decoded_body_too_large}` (buffered) or a stream error with that
    reason (streamed) before the expansion is held in memory. Bodies that are
    not decoded (`decode_body: false`, identity or unknown encodings) are not limited.
  - `stream_response` - set `true` to resolve at final response headers and
    expose an acknowledged body stream, even for small Content-Length bodies.
    Defaults to `false` (automatic size/framing policy). HEAD and bodyless
    statuses remain buffered empty responses. The request timeout still bounds
    the entire response; callers can observe headers before applying a body deadline.
  - `request_mode` - `:fetch` (default) or `:proxy`; proxy mode retains request
    entities for all admitted methods, including GET, DELETE, and HEAD, and
    adds no default `User-Agent` (a caller-supplied one is sent unchanged)
  - `content_type` - convenience Content-Type value for request bodies
  - `timeout` - request timeout in non-negative milliseconds or `:infinity`
    (HTTP/1, HTTP/2 and HTTP/3); other values raise `ArgumentError`
  - `error_mode` - `:raw` (default) or `:structured`; structured failures return
    `HTTP.RequestError` with conservative pre-send evidence. Retry
    classification uses the raw reason; only the final failure is wrapped.
  - `retry` - `false` (default, one attempt), `:transient`, `:safe_transient`
    or a 2-arity function `(request, response_or_error) -> boolean`; string
    values `"transient"` and `"safe_transient"` are also accepted. See "Retries"
    in `HTTP.fetch/2`. Rejected with `transport_scope`.
  - `max_retries` - additional attempts as a non-negative integer; defaults to 3
  - `retry_delay` - non-negative milliseconds, or a 1-arity function of the
    1-based number of the attempt being retried; defaults to exponential
    500 ms doubling up to 10,000 ms. `Retry-After` on 429/503 takes precedence.
  - `read_idle_timeout` - positive milliseconds (1..4,294,967,295), or `nil`
    to disable (default). Bounds each pending HTTP/1 transport read, including
    headers; nonempty transport data resets the clock. Consumer acknowledgement
    backpressure pauses reads and this clock. Writes do not reset it.
  - `write_idle_timeout` - positive milliseconds (same range), or `nil` to disable
    (default). Bounds each at-most-16KiB HTTP/1 transport write; each successful
    nonempty send starts a fresh write budget. This is transport acceptance,
    not peer acknowledgement or a partial-syscall progress guarantee. Waiting
    for an upload source does not consume a write budget. Shorter existing
    `socket_opts[:send_timeout]` and overall request limits still apply.
    Both idle options support ordinary HTTP/1 TCP and ExSSL TLS, including
    HTTP/1 reuse. They require `http_version: :http1` (the default); automatic/H2/H3
    protocols and managed `transport_scope` are rejected. Timeouts report
    `:read_idle_timeout` / `:write_idle_timeout` (or `HTTP.RequestError` in
    structured mode before response headers). Neither changes connection or
    overall request deadlines or the cleanup completion contract.
  - `connect_timeout` - connection timeout in non-negative milliseconds or
    `:infinity`; other values raise `ArgumentError`
  - `response_stream_idle_timeout` - ordinary HTTP/1 response-stream inactivity
    in positive milliseconds (1..4,294,967,295), or `:infinity` to disable the
    network-wait clock. `nil` (default) retains the global streaming timeout.
    Consumer acknowledgement waits use the separate ACK policy below.
    Convenience body readers use the same stream policy. Other protocols and
    managed `transport_scope` reject explicit policies.
  - `response_stream_ack_timeout` - ordinary HTTP/1 response chunk delivery and
    consumer acknowledgement budget in positive milliseconds (1..4,294,967,295),
    or `:infinity`. `nil` (default) retains the global streaming timeout.
    This covers a buffered chunk awaiting a reader and a delivered chunk awaiting
    acknowledgement. It does not change network idle, overall request deadlines,
    cancellation or reader-death cleanup. Other protocols and managed
    `transport_scope` reject explicit policies.
  - `adapter` - a module or `{module, config}` implementing `HTTP.Adapter`.
    Context is prepared in the caller and executed in the Promise worker.
  - `pool` - a named `HTTP.Runtime.Pool` family or opaque `HTTP.Pool` reference.
    Explicit selection binds one generation and rejects incompatible reuse/protocol options.
  - `transport_scope` - opaque `HTTP.ManagedTransport` generation selecting
    private reusable HTTP/1 or HTTP/2 transports. Requires raw streamed responses,
    manual/error redirects, and the origin/policy frozen by `open/1`.
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
  - `alt_svc` - opt in to RFC 7838 Alt-Svc HTTP/3 discovery; defaults to `false`
    and requires `http_version: :auto` (other versions raise `ArgumentError`).
    Final `https` responses carrying `Alt-Svc` update a bounded per-origin cache
    of same-host `h3` alternatives (`ma` defaults to 86,400 s; `clear` removes
    the origin). A later eligible `https` request with a fresh entry uses HTTP/3
    on the alternative UDP port, keeping the origin authority, SNI and
    certificate identity. Requests with a proxy, Unix socket, `connect_address`,
    `socket_opts`, `http2_profile`, `transport_scope` or
    explicit `pool` never use the alternative. If the QUIC connection is never
    established (`{:http3_not_established, _}` or `:opening_timeout`), the
    request runs on the normal `:auto` H2/HTTP/1.1 path within the original
    deadline and the origin is marked broken for five minutes. Failures after
    the connection is established are returned without replay. Redirect hops
    re-select per origin; `response.http_version` reports the actual protocol.
  - `prefer_ipv6` - Prefer IPv6 with IPv4 fallback only during TCP establishment.
    Explicit `connect_address` pins and `:inet`/`:inet6` socket options remain strict.
    For a proxy route this policy selects the proxy endpoint address family.
  - `response_header_limits` - Request-local HTTP/1 and CONNECT budgets; see
    `HTTP.ResponseHeaderLimits`. Also applies to informational and redirect heads.
  - `ssl` - TLS options passed to the `ex_ssl` TLS engine
  - `socket_opts` - socket options passed to the underlying transport
  - `unix_socket` - Unix Domain Socket path
  - `http1_reuse` - opt in to HTTP/1 keep-alive; requires `http_version: :http1`.
    Only fully consumed, self-delimited responses are reusable. Failed or
    cancelled requests are closed, and requests are never retried on stale peers
    unless the `retry` policy classifies the failure as retryable.
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
    origin TLS/ALPN. H2 over HTTPS and ExSSL IP-origin tunnels are supported;
    H2c, HTTP/3 and Unix socket proxy routes are rejected explicitly. Environment/NO_PROXY
    selection belongs to the caller.
    HTTPS proxies support HTTP/1 forwarding to HTTP origins and CONNECT tunnels
    to HTTPS origins. Proxy `ssl` settings verify the proxy independently from
    origin `ssl` settings.
    Proxy scheme, endpoint, credentials and both TLS policies isolate pools.
  - `http2_profile` - versioned HTTP/2 wire profile (only used by HTTP/2)
  - `http2_reuse` - whether an HTTP/2 connection may be reused; defaults to `true`
  - `http2_unprocessed_retry` - whether a non-streamed HTTP/2 request the server
    provably did not process is replayed; defaults to `true`. RFC 9113 §8.7
    treats a stream above a GOAWAY last-stream-id, a stream reset with
    `REFUSED_STREAM`, and an open refused by a draining pooled connection as
    unprocessed. By default such a request moves to another connection under
    the same deadline, at most three connections per redirect hop, and each
    move emits `[:http_fetch, :request, :retry]` with `source:
    :http2_unprocessed` (see `HTTP.Telemetry`). With `false` the first such
    failure is returned exactly as when those attempts are exhausted:
    `{:goaway, last_stream_id, error_code, :unprocessed}`, `{:stream_reset,
    :refused_stream}` or `:draining` (wrapped by `error_mode: :structured`).
    Applies to pooled and exclusive (`http2_reuse: false`) HTTP/2 connections,
    `:auto`-negotiated h2, explicit `pool:` and `transport_scope` requests.
    Streamed (`duplex: "half"`) bodies are never replayed either way. It has no
    effect on HTTP/1.1, on HTTP/3 (whose transfer rule is separate), or with an
    `adapter:`. It is independent of `retry:`, which may still retry the
    returned failure under its own policy.
  - `http3_profile` - QUIC wire profile; defaults to `:ordered`
  - `http3_reuse` - whether an HTTP/3 connection may be reused; defaults to `true`
  - `http3_resumption` - beta opt-in QUIC session resumption for HTTP/3; defaults
    to `false`. New connections dial through a runtime-owned endpoint whose
    bounded ticket store is partitioned by origin, dialed port, TLS trust and
    reference identity, QUIC profile and 0-RTT policy. HTTP/3 responses then
    carry `response.http3 == %{resumed: boolean, early_data: boolean}`.
  - `early_data` - beta per-request QUIC 0-RTT; defaults to `false`. Only GET,
    HEAD and OPTIONS without a body may set it (others raise `ArgumentError`).
    It takes effect only with `http3_resumption: true`, a ticket that allows
    0-RTT and remembered peer HTTP/3 SETTINGS; otherwise the request is sent
    after the handshake. A request whose 0-RTT is rejected is re-sent once after
    the handshake, and a `425 Too Early` response to a request carried in 0-RTT
    is retried once after the handshake (RFC 8470). See
    `docs/http3-fetch-contract.md`.
  - `http2_scope` - non-sensitive caller isolation scope
  - `http2_priority` - per-request HTTP/2 priority metadata
  """

  @string_keys %{
    "body" => :body,
    "adapter" => :adapter,
    "pool" => :pool,
    "transport_scope" => :transport_scope,
    "transportScope" => :transport_scope,
    "request_mode" => :request_mode,
    "requestMode" => :request_mode,
    "error_mode" => :error_mode,
    "errorMode" => :error_mode,
    "connect_address" => :connect_address,
    "connectAddress" => :connect_address,
    "connect_timeout" => :connect_timeout,
    "connectTimeout" => :connect_timeout,
    "read_idle_timeout" => :read_idle_timeout,
    "readIdleTimeout" => :read_idle_timeout,
    "write_idle_timeout" => :write_idle_timeout,
    "writeIdleTimeout" => :write_idle_timeout,
    "response_stream_ack_timeout" => :response_stream_ack_timeout,
    "responseStreamAckTimeout" => :response_stream_ack_timeout,
    "response_stream_idle_timeout" => :response_stream_idle_timeout,
    "responseStreamIdleTimeout" => :response_stream_idle_timeout,
    "content_type" => :content_type,
    "contentType" => :content_type,
    "duplex" => :duplex,
    "decode_body" => :decode_body,
    "decodeBody" => :decode_body,
    "max_decoded_body_size" => :max_decoded_body_size,
    "maxDecodedBodySize" => :max_decoded_body_size,
    "stream_response" => :stream_response,
    "streamResponse" => :stream_response,
    "headers" => :headers,
    "http_version" => :http_version,
    "httpVersion" => :http_version,
    "alt_svc" => :alt_svc,
    "altSvc" => :alt_svc,
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
    "http2_unprocessed_retry" => :http2_unprocessed_retry,
    "http2UnprocessedRetry" => :http2_unprocessed_retry,
    "http3_profile" => :http3_profile,
    "http3Profile" => :http3_profile,
    "http3_reuse" => :http3_reuse,
    "http3Reuse" => :http3_reuse,
    "http3_resumption" => :http3_resumption,
    "http3Resumption" => :http3_resumption,
    "early_data" => :early_data,
    "earlyData" => :early_data,
    "http2_scope" => :http2_scope,
    "http2Scope" => :http2_scope,
    "http2_priority" => :http2_priority,
    "http2Priority" => :http2_priority,
    "proxy" => :proxy,
    "retry" => :retry,
    "max_retries" => :max_retries,
    "maxRetries" => :max_retries,
    "retry_delay" => :retry_delay,
    "retryDelay" => :retry_delay,
    "method" => :method,
    "redirect" => :redirect,
    "signal" => :signal,
    "response_header_limits" => :response_header_limits,
    "responseHeaderLimits" => :response_header_limits,
    "prefer_ipv6" => :prefer_ipv6,
    "preferIpv6" => :prefer_ipv6,
    "preferIPv6" => :prefer_ipv6,
    "socket_opts" => :socket_opts,
    "socketOpts" => :socket_opts,
    "ssl" => :ssl,
    "timeout" => :timeout,
    "telemetry" => :telemetry,
    "unix_socket" => :unix_socket,
    "unixSocket" => :unix_socket
  }

  defstruct method: :get,
            adapter: nil,
            pool: nil,
            transport_scope: nil,
            request_mode: :fetch,
            headers: %HTTP.Headers{},
            content_type: nil,
            body: nil,
            duplex: nil,
            decode_body: true,
            max_decoded_body_size: nil,
            stream_response: false,
            telemetry: true,
            signal: nil,
            unix_socket: nil,
            redirect: :follow,
            http_version: :http1,
            alt_svc: false,
            timeout: nil,
            error_mode: :raw,
            connect_timeout: nil,
            read_idle_timeout: nil,
            write_idle_timeout: nil,
            response_stream_idle_timeout: nil,
            response_stream_ack_timeout: nil,
            connect_address: nil,
            prefer_ipv6: false,
            ssl: nil,
            socket_opts: nil,
            response_header_limits: nil,
            proxy: nil,
            http1_reuse: false,
            http1_scope: nil,
            http1_pool_size: 2,
            http1_idle_timeout: 30_000,
            http2_profile: nil,
            http2_reuse: true,
            http2_unprocessed_retry: true,
            http3_profile: nil,
            http3_reuse: true,
            http3_resumption: false,
            early_data: false,
            http2_scope: nil,
            http2_priority: nil,
            retry: false,
            max_retries: 3,
            retry_delay: nil

  @type redirect :: :follow | :manual | :error
  @type http_version :: :http1 | :http2 | :http3 | :h2c | :auto

  @type t :: %__MODULE__{
          adapter: module() | {module(), term()} | nil,
          pool: term(),
          method: HTTP.Request.method(),
          request_mode: HTTP.Request.request_mode(),
          headers: HTTP.Headers.t(),
          content_type: String.t() | nil,
          body: any(),
          duplex: :half | nil,
          decode_body: boolean(),
          max_decoded_body_size: pos_integer() | :infinity | nil,
          stream_response: boolean(),
          telemetry: boolean(),
          signal: any() | nil,
          unix_socket: String.t() | nil,
          redirect: redirect(),
          http_version: http_version(),
          alt_svc: boolean(),
          timeout: timeout() | nil,
          error_mode: :raw | :structured,
          connect_timeout: timeout() | nil,
          read_idle_timeout: pos_integer() | nil,
          write_idle_timeout: pos_integer() | nil,
          response_stream_idle_timeout: pos_integer() | :infinity | nil,
          response_stream_ack_timeout: pos_integer() | :infinity | nil,
          connect_address: :inet.ip_address() | nil,
          prefer_ipv6: boolean(),
          ssl: list() | nil,
          socket_opts: list() | nil,
          response_header_limits: map() | nil,
          http1_reuse: boolean(),
          http1_scope: atom() | String.t() | nil,
          http1_pool_size: pos_integer(),
          http1_idle_timeout: pos_integer(),
          proxy: {:http | :https, String.t(), :inet.port_number(), keyword()} | nil,
          http2_profile: atom() | String.t() | map() | nil,
          http2_reuse: boolean(),
          http2_unprocessed_retry: boolean(),
          http3_profile: atom() | map() | nil,
          http3_reuse: boolean(),
          http3_resumption: boolean(),
          early_data: boolean(),
          http2_scope: atom() | String.t() | nil,
          http2_priority: map() | keyword() | nil,
          retry: false | HTTP.Retry.mode(),
          max_retries: non_neg_integer(),
          retry_delay: non_neg_integer() | (pos_integer() -> non_neg_integer()) | nil
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
    |> maybe_add(:pool, options.pool)
    |> maybe_add(:transport_scope, options.transport_scope)
    |> maybe_add(:telemetry, options.telemetry)
    |> maybe_add(:decode_body, options.decode_body)
    |> maybe_add(:max_decoded_body_size, options.max_decoded_body_size)
    |> maybe_add(:stream_response, options.stream_response)
    |> maybe_add(:timeout, options.timeout)
    |> maybe_add(:error_mode, options.error_mode)
    |> maybe_add(:connect_timeout, options.connect_timeout)
    |> maybe_add(:read_idle_timeout, options.read_idle_timeout)
    |> maybe_add(:write_idle_timeout, options.write_idle_timeout)
    |> maybe_add(:response_stream_idle_timeout, options.response_stream_idle_timeout)
    |> maybe_add(:response_stream_ack_timeout, options.response_stream_ack_timeout)
    |> maybe_add(:connect_address, options.connect_address)
    |> maybe_add(:prefer_ipv6, if(options.prefer_ipv6, do: true, else: nil))
    |> maybe_add(:ssl, options.ssl)
    |> maybe_add(:socket_opts, options.socket_opts)
    |> maybe_add(:response_header_limits, options.response_header_limits)
    |> maybe_add(:proxy, options.proxy)
    |> maybe_add(:redirect, options.redirect)
    |> maybe_add(:http_version, options.http_version)
    |> maybe_add(:alt_svc, if(options.alt_svc, do: true))
    |> maybe_add(:http1_reuse, if(options.http1_reuse, do: true, else: nil))
    |> maybe_add(:http1_scope, options.http1_scope)
    |> maybe_add(:http1_pool_size, if(options.http1_reuse, do: options.http1_pool_size))
    |> maybe_add(:http1_idle_timeout, if(options.http1_reuse, do: options.http1_idle_timeout))
    |> maybe_add(:http2_profile, options.http2_profile)
    |> maybe_add(:http2_reuse, if(options.http2_reuse, do: nil, else: false))
    |> maybe_add(
      :http2_unprocessed_retry,
      if(options.http2_unprocessed_retry, do: nil, else: false)
    )
    |> maybe_add(:http3_profile, options.http3_profile)
    |> maybe_add(:http3_reuse, if(options.http3_reuse, do: nil, else: false))
    |> maybe_add(:http3_resumption, if(options.http3_resumption, do: true))
    |> maybe_add(:early_data, if(options.early_data, do: true))
    |> maybe_add(:http2_scope, options.http2_scope)
    |> maybe_add(:http2_priority, options.http2_priority)
  end

  @doc """
  Extracts the HTTP method from options.
  """
  @spec get_method(t()) :: HTTP.Request.method()
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
      {:adapter, adapter}, acc ->
        %{acc | adapter: adapter}

      {:pool, pool}, acc ->
        %{acc | pool: pool}

      {:transport_scope, scope}, acc ->
        %{acc | transport_scope: scope}

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

      {:max_decoded_body_size, limit}, acc ->
        %{acc | max_decoded_body_size: limit}

      {:signal, signal}, acc ->
        %{acc | signal: signal}

      {:unix_socket, unix_socket}, acc ->
        %{acc | unix_socket: unix_socket}

      {:redirect, redirect}, acc ->
        %{acc | redirect: redirect}

      {:http_version, http_version}, acc ->
        %{acc | http_version: http_version}

      {:alt_svc, alt_svc}, acc ->
        %{acc | alt_svc: alt_svc}

      {:timeout, timeout}, acc ->
        %{acc | timeout: timeout}

      {:error_mode, mode}, acc ->
        %{acc | error_mode: mode}

      {:connect_timeout, connect_timeout}, acc ->
        %{acc | connect_timeout: connect_timeout}

      {:read_idle_timeout, timeout}, acc ->
        %{acc | read_idle_timeout: timeout}

      {:write_idle_timeout, timeout}, acc ->
        %{acc | write_idle_timeout: timeout}

      {:response_stream_ack_timeout, timeout}, acc ->
        %{acc | response_stream_ack_timeout: timeout}

      {:response_stream_idle_timeout, timeout}, acc ->
        %{acc | response_stream_idle_timeout: timeout}

      {:prefer_ipv6, value}, acc ->
        %{acc | prefer_ipv6: value}

      {:connect_address, connect_address}, acc ->
        %{acc | connect_address: connect_address}

      {:ssl, ssl}, acc ->
        %{acc | ssl: ssl}

      {:proxy, proxy}, acc ->
        %{acc | proxy: proxy}

      {:response_header_limits, limits}, acc ->
        %{acc | response_header_limits: limits}

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

      {:http2_unprocessed_retry, retry}, acc ->
        %{acc | http2_unprocessed_retry: retry}

      {:http3_profile, profile}, acc ->
        %{acc | http3_profile: profile}

      {:http3_reuse, reuse}, acc ->
        %{acc | http3_reuse: reuse}

      {:http3_resumption, resumption}, acc ->
        %{acc | http3_resumption: resumption}

      {:early_data, early_data}, acc ->
        %{acc | early_data: early_data}

      {:http2_scope, scope}, acc ->
        %{acc | http2_scope: scope}

      {:http2_priority, priority}, acc ->
        %{acc | http2_priority: priority}

      {:retry, retry}, acc ->
        %{acc | retry: retry}

      {:max_retries, max_retries}, acc ->
        %{acc | max_retries: max_retries}

      {:retry_delay, delay}, acc ->
        %{acc | retry_delay: delay}

      {key, _value}, _acc when is_atom(key) or is_binary(key) ->
        if http2_option_key?(key) do
          raise ArgumentError, "unsupported HTTP/2 option: #{inspect(key)}"
        else
          raise ArgumentError, "unknown fetch option: #{inspect(key)}"
        end

      other, _acc ->
        raise ArgumentError,
              "fetch options must be {key, value} pairs with atom or string keys, got: #{inspect(other)}"
    end)
  end

  defp normalize_signal(signal) when signal == nil or is_pid(signal), do: signal

  defp normalize_signal(signal),
    do:
      raise(
        ArgumentError,
        "invalid signal: #{inspect(signal)}; expected an HTTP.AbortController pid"
      )

  defp normalize_prefer_ipv6(value) when is_boolean(value), do: value
  defp normalize_prefer_ipv6(_value), do: raise(ArgumentError, "prefer_ipv6 must be a boolean")

  defp validate_response_header_protocol(%{response_header_limits: nil} = options), do: options
  defp validate_response_header_protocol(%{http_version: :http1} = options), do: options

  defp validate_response_header_protocol(_options),
    do: raise(ArgumentError, "response_header_limits requires explicit http_version: :http1")

  defp normalize_key(key) when is_binary(key), do: Map.get(@string_keys, key, key)
  defp normalize_key(key), do: key

  defp normalize_headers(%HTTP.Headers{} = headers), do: headers
  defp normalize_headers(headers) when is_list(headers), do: HTTP.Headers.new(headers)
  defp normalize_headers(headers) when is_map(headers), do: HTTP.Headers.from_map(headers)
  defp normalize_headers(_), do: HTTP.Headers.new()

  defp normalize_options(%__MODULE__{} = options) do
    http_version = normalize_http_version(options.http_version)
    alt_svc = normalize_alt_svc(options.alt_svc, http_version)
    retry = HTTP.Retry.normalize(options.retry, options.max_retries, options.retry_delay)

    %{
      options
      | method: normalize_method(options.method),
        request_mode: normalize_request_mode(options.request_mode),
        redirect: normalize_redirect(options.redirect),
        signal: normalize_signal(options.signal),
        duplex: normalize_duplex(options.duplex),
        decode_body: normalize_decode_body(options.decode_body),
        max_decoded_body_size: normalize_max_decoded_body_size(options.max_decoded_body_size),
        stream_response: normalize_stream_response(options.stream_response),
        telemetry: normalize_telemetry(options.telemetry),
        error_mode: normalize_error_mode(options.error_mode),
        http_version: http_version,
        alt_svc: alt_svc,
        prefer_ipv6: normalize_prefer_ipv6(options.prefer_ipv6),
        timeout: normalize_timeout(options.timeout, :timeout),
        connect_timeout: normalize_timeout(options.connect_timeout, :connect_timeout),
        response_header_limits:
          HTTP.ResponseHeaderLimits.normalize(options.response_header_limits),
        read_idle_timeout: normalize_idle_timeout(options.read_idle_timeout, :read_idle_timeout),
        write_idle_timeout:
          normalize_idle_timeout(options.write_idle_timeout, :write_idle_timeout),
        response_stream_idle_timeout:
          normalize_response_stream_idle_timeout(options.response_stream_idle_timeout),
        response_stream_ack_timeout:
          normalize_response_stream_ack_timeout(options.response_stream_ack_timeout),
        http1_reuse: normalize_http1_reuse(options.http1_reuse, http_version),
        http1_scope: normalize_http2_scope(options.http1_scope),
        http1_pool_size: normalize_http1_limit(options.http1_pool_size, 16, :http1_pool_size),
        http1_idle_timeout:
          normalize_http1_limit(options.http1_idle_timeout, 60_000, :http1_idle_timeout),
        http2_profile: normalize_http2_profile(options.http2_profile),
        http2_reuse: normalize_http2_reuse(options.http2_reuse),
        http2_unprocessed_retry:
          normalize_http2_unprocessed_retry(options.http2_unprocessed_retry),
        http3_reuse: normalize_http3_reuse(options.http3_reuse),
        http3_resumption: normalize_boolean(options.http3_resumption, :http3_resumption),
        early_data: normalize_boolean(options.early_data, :early_data),
        http2_scope: normalize_http2_scope(options.http2_scope),
        http2_priority: normalize_http2_priority(options.http2_priority),
        retry: if(retry, do: retry.mode, else: false),
        max_retries: HTTP.Retry.normalize_max_retries(options.max_retries),
        retry_delay: options.retry_delay
    }
    |> validate_response_header_protocol()
    |> validate_connect_address()
    |> validate_idle_protocol()
    |> validate_response_stream_idle_protocol()
    |> validate_response_stream_ack_protocol()
    |> validate_early_data()
    |> validate_retry()
  end

  @doc false
  @spec retry_policy(t()) :: HTTP.Retry.t() | nil
  def retry_policy(%__MODULE__{retry: false}), do: nil

  def retry_policy(%__MODULE__{} = options),
    do: HTTP.Retry.normalize(options.retry, options.max_retries, options.retry_delay)

  # A managed admission covers exactly one attempt.
  defp validate_retry(%{retry: retry, transport_scope: scope})
       when retry != false and scope != nil,
       do: raise(ArgumentError, "retry is unsupported with transport_scope")

  defp validate_retry(options), do: options

  defp normalize_boolean(nil, _name), do: false
  defp normalize_boolean(value, _name) when is_boolean(value), do: value

  defp normalize_boolean(value, name),
    do: raise(ArgumentError, "invalid #{name}: #{inspect(value)}; expected boolean")

  # 0-RTT data is replayable, so only safe methods without a body may opt in.
  defp validate_early_data(%{early_data: true} = options) do
    cond do
      options.method not in [:get, :head, :options] ->
        raise ArgumentError,
              "early_data requires GET, HEAD or OPTIONS, got: #{inspect(options.method)}"

      options.body not in [nil, ""] ->
        raise ArgumentError, "early_data requires a request without a body"

      true ->
        options
    end
  end

  defp validate_early_data(options), do: options

  defp normalize_response_stream_idle_timeout(timeout) when timeout in [nil, :infinity],
    do: timeout

  defp normalize_response_stream_idle_timeout(timeout),
    do: normalize_idle_timeout(timeout, :response_stream_idle_timeout)

  defp validate_response_stream_idle_protocol(%{response_stream_idle_timeout: nil} = options),
    do: options

  defp validate_response_stream_idle_protocol(%{transport_scope: scope}) when scope != nil,
    do: raise(ArgumentError, "response_stream_idle_timeout is unsupported with transport_scope")

  defp validate_response_stream_idle_protocol(%{http_version: :http1} = options), do: options

  defp validate_response_stream_idle_protocol(_options),
    do: raise(ArgumentError, "response_stream_idle_timeout requires http_version: :http1")

  defp normalize_response_stream_ack_timeout(timeout) when timeout in [nil, :infinity],
    do: timeout

  defp normalize_response_stream_ack_timeout(timeout),
    do: normalize_idle_timeout(timeout, :response_stream_ack_timeout)

  defp validate_response_stream_ack_protocol(%{response_stream_ack_timeout: nil} = options),
    do: options

  defp validate_response_stream_ack_protocol(%{transport_scope: scope}) when scope != nil,
    do: raise(ArgumentError, "response_stream_ack_timeout is unsupported with transport_scope")

  defp validate_response_stream_ack_protocol(%{http_version: :http1} = options), do: options

  defp validate_response_stream_ack_protocol(_options),
    do: raise(ArgumentError, "response_stream_ack_timeout requires http_version: :http1")

  defp normalize_timeout(timeout, _key)
       when timeout in [nil, :infinity] or (is_integer(timeout) and timeout >= 0),
       do: timeout

  defp normalize_timeout(_timeout, key),
    do: raise(ArgumentError, "#{key} must be non-negative milliseconds or :infinity")

  defp normalize_idle_timeout(nil, _key), do: nil

  defp normalize_idle_timeout(timeout, _key)
       when is_integer(timeout) and timeout > 0 and timeout <= 4_294_967_295,
       do: timeout

  defp normalize_idle_timeout(_timeout, key),
    do: raise(ArgumentError, "#{key} must be positive milliseconds in 1..4294967295 or nil")

  defp validate_idle_protocol(%{read_idle_timeout: nil, write_idle_timeout: nil} = options),
    do: options

  defp validate_idle_protocol(%{transport_scope: scope}) when scope != nil,
    do: raise(ArgumentError, "idle deadlines are unsupported with transport_scope")

  defp validate_idle_protocol(%{http_version: :http1} = options), do: options

  defp validate_idle_protocol(_options),
    do: raise(ArgumentError, "idle deadlines require http_version: :http1")

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

  defp normalize_error_mode(mode) when mode in [:raw, :structured], do: mode

  defp normalize_error_mode(mode),
    do: raise(ArgumentError, "invalid error_mode: #{inspect(mode)}; expected :raw or :structured")

  defp normalize_telemetry(value) when is_boolean(value), do: value

  defp normalize_telemetry(value),
    do: raise(ArgumentError, "invalid telemetry: #{inspect(value)}; expected boolean")

  defp normalize_stream_response(value) when is_boolean(value), do: value

  defp normalize_stream_response(value),
    do: raise(ArgumentError, "invalid stream_response: #{inspect(value)}; expected boolean")

  defp normalize_decode_body(value) when is_boolean(value), do: value

  defp normalize_decode_body(value),
    do: raise(ArgumentError, "invalid decode_body: #{inspect(value)}; expected boolean")

  defp normalize_max_decoded_body_size(limit)
       when limit in [nil, :infinity] or (is_integer(limit) and limit > 0),
       do: limit

  defp normalize_max_decoded_body_size(_limit),
    do: raise(ArgumentError, "max_decoded_body_size must be positive bytes or :infinity")

  defp normalize_method(method) do
    case method |> HTTP.Request.method_token() |> String.upcase() do
      "DELETE" -> :delete
      "GET" -> :get
      "HEAD" -> :head
      "OPTIONS" -> :options
      "PATCH" -> :patch
      "POST" -> :post
      "PUT" -> :put
      _ -> method
    end
  end

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

  defp normalize_alt_svc(value, _http_version) when value in [nil, false], do: false
  defp normalize_alt_svc(true, :auto), do: true

  defp normalize_alt_svc(true, http_version),
    do:
      raise(
        ArgumentError,
        "alt_svc requires http_version: :auto, got: #{inspect(http_version)}"
      )

  defp normalize_alt_svc(value, _http_version),
    do: raise(ArgumentError, "invalid alt_svc: #{inspect(value)}; expected boolean")

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

  defp normalize_http2_unprocessed_retry(nil), do: true
  defp normalize_http2_unprocessed_retry(value) when is_boolean(value), do: value

  defp normalize_http2_unprocessed_retry(value),
    do:
      raise(
        ArgumentError,
        "invalid http2_unprocessed_retry: #{inspect(value)}; expected boolean"
      )

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

  defp maybe_add(list, _key, nil), do: list
  defp maybe_add(list, key, value), do: Keyword.put(list, key, value)
end

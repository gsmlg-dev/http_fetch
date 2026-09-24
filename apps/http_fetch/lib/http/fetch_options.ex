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

  - `content_type` - convenience Content-Type value for request bodies
  - `timeout` - request timeout in milliseconds
  - `connect_timeout` - connection timeout in milliseconds
  - `http_version` - protocol selection, one of `:http1`, `:http2`, `:http3`,
    `:h2c`, or `:auto`; defaults to `:http1`
  - `tls_backend` - TLS implementation, `:ssl` or `:ex_ssl`; defaults to the
    shared `:http_core, :tls_backend` configuration
  - `ssl` - TLS options passed to the selected TLS backend
  - `socket_opts` - socket options passed to the underlying transport
  - `unix_socket` - Unix Domain Socket path
  - `http2_profile` - versioned HTTP/2 wire profile (only used by HTTP/2)
  - `http2_reuse` - whether an HTTP/2 connection may be reused; defaults to `true`
  - `http2_scope` - non-sensitive caller isolation scope
  - `http2_priority` - per-request HTTP/2 priority metadata
  """

  @string_keys %{
    "body" => :body,
    "connect_timeout" => :connect_timeout,
    "connectTimeout" => :connect_timeout,
    "content_type" => :content_type,
    "contentType" => :content_type,
    "duplex" => :duplex,
    "headers" => :headers,
    "http_version" => :http_version,
    "httpVersion" => :http_version,
    "http2_profile" => :http2_profile,
    "http2Profile" => :http2_profile,
    "http2_reuse" => :http2_reuse,
    "http2Reuse" => :http2_reuse,
    "http2_scope" => :http2_scope,
    "http2Scope" => :http2_scope,
    "http2_priority" => :http2_priority,
    "http2Priority" => :http2_priority,
    "method" => :method,
    "redirect" => :redirect,
    "signal" => :signal,
    "socket_opts" => :socket_opts,
    "socketOpts" => :socket_opts,
    "ssl" => :ssl,
    "tls_backend" => :tls_backend,
    "tlsBackend" => :tls_backend,
    "timeout" => :timeout,
    "unix_socket" => :unix_socket,
    "unixSocket" => :unix_socket
  }

  defstruct method: :get,
            headers: %HTTP.Headers{},
            content_type: nil,
            body: nil,
            duplex: nil,
            signal: nil,
            unix_socket: nil,
            redirect: :follow,
            http_version: :http1,
            tls_backend: nil,
            timeout: nil,
            connect_timeout: nil,
            ssl: nil,
            socket_opts: nil,
            http2_profile: nil,
            http2_reuse: true,
            http2_scope: nil,
            http2_priority: nil

  @type redirect :: :follow | :manual | :error
  @type http_version :: :http1 | :http2 | :http3 | :h2c | :auto
  @type tls_backend :: term()

  @type t :: %__MODULE__{
          method: atom(),
          headers: HTTP.Headers.t(),
          content_type: String.t() | nil,
          body: any(),
          duplex: :half | nil,
          signal: any() | nil,
          unix_socket: String.t() | nil,
          redirect: redirect(),
          http_version: http_version(),
          tls_backend: tls_backend(),
          timeout: integer() | nil,
          connect_timeout: integer() | nil,
          ssl: list() | nil,
          socket_opts: list() | nil,
          http2_profile: atom() | String.t() | map() | nil,
          http2_reuse: boolean(),
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
    |> maybe_add(:timeout, options.timeout)
    |> maybe_add(:connect_timeout, options.connect_timeout)
    |> maybe_add(:ssl, options.ssl)
    |> maybe_add(:socket_opts, options.socket_opts)
    |> maybe_add(:redirect, options.redirect)
    |> maybe_add(:http_version, options.http_version)
    |> maybe_add(:tls_backend, options.tls_backend)
    |> maybe_add(:http2_profile, options.http2_profile)
    |> maybe_add(:http2_reuse, if(options.http2_reuse, do: nil, else: false))
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

      {:headers, headers}, acc ->
        %{acc | headers: normalize_headers(headers)}

      {:content_type, content_type}, acc ->
        %{acc | content_type: content_type}

      {:body, body}, acc ->
        %{acc | body: body}

      {:duplex, duplex}, acc ->
        %{acc | duplex: normalize_duplex(duplex)}

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

      {:ssl, ssl}, acc ->
        %{acc | ssl: ssl}

      {:socket_opts, socket_opts}, acc ->
        %{acc | socket_opts: socket_opts}

      {:http2_profile, profile}, acc ->
        %{acc | http2_profile: profile}

      {:http2_reuse, reuse}, acc ->
        %{acc | http2_reuse: reuse}

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
        redirect: normalize_redirect(options.redirect),
        duplex: normalize_duplex(options.duplex),
        http_version: http_version,
        tls_backend: normalize_tls_backend(options.tls_backend, http_version),
        http2_profile: normalize_http2_profile(options.http2_profile),
        http2_reuse: normalize_http2_reuse(options.http2_reuse),
        http2_scope: normalize_http2_scope(options.http2_scope),
        http2_priority: normalize_http2_priority(options.http2_priority)
    }
  end

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

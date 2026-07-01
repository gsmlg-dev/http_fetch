defmodule HTTP.FetchOptions do
  @moduledoc """
  Options processing for `HTTP.fetch/2` requests.

  `HTTP.fetch/2` accepts a flat init keyword list or map, mirroring the browser
  `fetch(input, init)` shape. Supported fetch-style options are:

  - `method` - HTTP method, defaulting to `GET`
  - `headers` - request headers as a list, map, or `HTTP.Headers`
  - `body` - request body
  - `signal` - `HTTP.AbortController` PID
  - `redirect` - `:follow`, `:manual`, or `:error`; defaults to `:follow`

  The socket transport also accepts Elixir-specific extensions:

  - `content_type` - convenience Content-Type value for request bodies
  - `timeout` - request timeout in milliseconds
  - `connect_timeout` - connection timeout in milliseconds
  - `http_version` - protocol selection, one of `:http1`, `:http2`, `:h2c`,
    or `:auto`; defaults to `:http1`
  - `ssl` - TLS options passed to `:ssl`
  - `socket_opts` - socket options passed to the underlying transport
  - `unix_socket` - Unix Domain Socket path
  """

  @string_keys %{
    "body" => :body,
    "connect_timeout" => :connect_timeout,
    "connectTimeout" => :connect_timeout,
    "content_type" => :content_type,
    "contentType" => :content_type,
    "headers" => :headers,
    "http_version" => :http_version,
    "httpVersion" => :http_version,
    "method" => :method,
    "redirect" => :redirect,
    "signal" => :signal,
    "socket_opts" => :socket_opts,
    "socketOpts" => :socket_opts,
    "ssl" => :ssl,
    "timeout" => :timeout,
    "unix_socket" => :unix_socket,
    "unixSocket" => :unix_socket
  }

  defstruct method: :get,
            headers: %HTTP.Headers{},
            content_type: nil,
            body: nil,
            signal: nil,
            unix_socket: nil,
            redirect: :follow,
            http_version: :http1,
            timeout: nil,
            connect_timeout: nil,
            ssl: nil,
            socket_opts: nil

  @type redirect :: :follow | :manual | :error
  @type http_version :: :http1 | :http2 | :h2c | :auto

  @type t :: %__MODULE__{
          method: atom(),
          headers: HTTP.Headers.t(),
          content_type: String.t() | nil,
          body: any(),
          signal: any() | nil,
          unix_socket: String.t() | nil,
          redirect: redirect(),
          http_version: http_version(),
          timeout: integer() | nil,
          connect_timeout: integer() | nil,
          ssl: list() | nil,
          socket_opts: list() | nil
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

      {:signal, signal}, acc ->
        %{acc | signal: signal}

      {:unix_socket, unix_socket}, acc ->
        %{acc | unix_socket: unix_socket}

      {:redirect, redirect}, acc ->
        %{acc | redirect: redirect}

      {:http_version, http_version}, acc ->
        %{acc | http_version: http_version}

      {:timeout, timeout}, acc ->
        %{acc | timeout: timeout}

      {:connect_timeout, connect_timeout}, acc ->
        %{acc | connect_timeout: connect_timeout}

      {:ssl, ssl}, acc ->
        %{acc | ssl: ssl}

      {:socket_opts, socket_opts}, acc ->
        %{acc | socket_opts: socket_opts}

      {_key, _value}, acc ->
        acc
    end)
  end

  defp normalize_key(key) when is_binary(key), do: Map.get(@string_keys, key, key)
  defp normalize_key(key), do: key

  defp normalize_headers(%HTTP.Headers{} = headers), do: headers
  defp normalize_headers(headers) when is_list(headers), do: HTTP.Headers.new(headers)
  defp normalize_headers(headers) when is_map(headers), do: HTTP.Headers.from_map(headers)
  defp normalize_headers(_), do: HTTP.Headers.new()

  defp normalize_options(%__MODULE__{} = options) do
    %{
      options
      | method: normalize_method(options.method),
        redirect: normalize_redirect(options.redirect),
        http_version: normalize_http_version(options.http_version)
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

  defp normalize_http_version(nil), do: :http1
  defp normalize_http_version(:http1), do: :http1
  defp normalize_http_version(:http2), do: :http2
  defp normalize_http_version(:h2c), do: :h2c
  defp normalize_http_version(:auto), do: :auto

  defp normalize_http_version(http_version) when is_binary(http_version) do
    case String.downcase(http_version) do
      "http1" -> :http1
      "http/1.1" -> :http1
      "http2" -> :http2
      "h2" -> :http2
      "h2c" -> :h2c
      "auto" -> :auto
      _ -> raise ArgumentError, http_version_error_message(http_version)
    end
  end

  defp normalize_http_version(http_version),
    do: raise(ArgumentError, http_version_error_message(http_version))

  defp http_version_error_message(http_version) do
    "unsupported http_version: #{inspect(http_version)}; expected :http1, :http2, :h2c, or :auto"
  end

  defp maybe_add(list, _key, nil), do: list
  defp maybe_add(list, key, value), do: Keyword.put(list, key, value)
end

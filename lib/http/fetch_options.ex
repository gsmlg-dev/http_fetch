defmodule HTTP.FetchOptions do
  @moduledoc """
  Processes fetch options for HTTP requests, supporting flat map, keyword list,
  and HTTP.FetchOptions struct formats. Handles conversion to :httpc.request arguments.
  """

  defstruct method: :get,
            headers: %HTTP.Headers{},
            content_type: nil,
            body: nil,
            options: [],
            opts: [sync: false],
            signal: nil,
            timeout: nil,
            connect_timeout: nil,
            ssl: nil,
            autoredirect: nil,
            proxy_auth: nil,
            version: nil,
            relaxed: nil,
            stream: nil,
            body_format: nil,
            full_result: nil,
            headers_as_is: nil,
            socket_opts: nil,
            receiver: nil,
            ipv6_host_with_brackets: nil

  @type t :: %__MODULE__{
          method: atom(),
          headers: HTTP.Headers.t(),
          content_type: String.t() | nil,
          body: any(),
          options: keyword(),
          opts: keyword(),
          signal: any() | nil,
          timeout: integer() | nil,
          connect_timeout: integer() | nil,
          ssl: list() | nil,
          autoredirect: boolean() | nil,
          proxy_auth: tuple() | nil,
          version: String.t() | nil,
          relaxed: boolean() | nil,
          stream: atom() | tuple() | nil,
          body_format: atom() | nil,
          full_result: boolean() | nil,
          headers_as_is: boolean() | nil,
          socket_opts: list() | nil,
          receiver: pid() | function() | tuple() | nil,
          ipv6_host_with_brackets: boolean() | nil
        }

  @doc """
  Creates a new FetchOptions struct from various input formats.
  Supports flat map, keyword list, or existing FetchOptions struct.
  """
  @spec new(map() | keyword() | t()) :: t()
  def new(options) when is_map(options) do
    options
    |> Map.to_list()
    |> new()
  end

  def new(options) when is_list(options) do
    %__MODULE__{}
    |> merge_options(options)
    |> normalize_options()
  end

  def new(%__MODULE__{} = options) do
    options
    |> normalize_options()
  end

  @doc """
  Converts FetchOptions to HTTP options for :httpc.request 3rd argument.
  Returns keyword list of HttpOptions.
  """
  @spec to_http_options(t()) :: keyword()
  def to_http_options(%__MODULE__{} = options) do
    []
    |> maybe_add(:timeout, options.timeout)
    |> maybe_add(:connect_timeout, options.connect_timeout)
    |> maybe_add(:ssl, options.ssl)
    |> maybe_add(:autoredirect, options.autoredirect)
    |> maybe_add(:proxy_auth, options.proxy_auth)
    |> maybe_add(:version, options.version)
    |> maybe_add(:relaxed, options.relaxed)
  end

  @doc """
  Converts FetchOptions to options for :httpc.request 4th argument.
  Returns keyword list of Options.
  """
  @spec to_options(t()) :: keyword()
  def to_options(%__MODULE__{} = options) do
    options.opts
    |> Keyword.put_new(:sync, false)
    |> maybe_add(:stream, options.stream)
    |> maybe_add(:body_format, options.body_format)
    |> maybe_add(:full_result, options.full_result)
    |> maybe_add(:headers_as_is, options.headers_as_is)
    |> maybe_add(:socket_opts, options.socket_opts)
    |> maybe_add(:receiver, options.receiver)
    |> maybe_add(:ipv6_host_with_brackets, options.ipv6_host_with_brackets)
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

      {:options, options}, acc ->
        %{acc | options: Keyword.merge(acc.options, List.wrap(options))}

      {:opts, opts}, acc ->
        %{acc | opts: Keyword.merge(acc.opts, List.wrap(opts))}

      {:signal, signal}, acc ->
        %{acc | signal: signal}

      {:timeout, timeout}, acc ->
        %{acc | timeout: timeout}

      {:connect_timeout, connect_timeout}, acc ->
        %{acc | connect_timeout: connect_timeout}

      {:ssl, ssl}, acc ->
        %{acc | ssl: ssl}

      {:autoredirect, autoredirect}, acc ->
        %{acc | autoredirect: autoredirect}

      {:proxy_auth, proxy_auth}, acc ->
        %{acc | proxy_auth: proxy_auth}

      {:version, version}, acc ->
        %{acc | version: version}

      {:relaxed, relaxed}, acc ->
        %{acc | relaxed: relaxed}

      {:stream, stream}, acc ->
        %{acc | stream: stream}

      {:body_format, body_format}, acc ->
        %{acc | body_format: body_format}

      {:full_result, full_result}, acc ->
        %{acc | full_result: full_result}

      {:headers_as_is, headers_as_is}, acc ->
        %{acc | headers_as_is: headers_as_is}

      {:socket_opts, socket_opts}, acc ->
        %{acc | socket_opts: socket_opts}

      {:receiver, receiver}, acc ->
        %{acc | receiver: receiver}

      {:ipv6_host_with_brackets, ipv6_host_with_brackets}, acc ->
        %{acc | ipv6_host_with_brackets: ipv6_host_with_brackets}

      {key, value}, acc ->
        handle_unknown_option(key, value, acc)
    end)
  end

  defp normalize_headers(%HTTP.Headers{} = headers), do: headers
  defp normalize_headers(headers) when is_list(headers), do: HTTP.Headers.new(headers)
  defp normalize_headers(headers) when is_map(headers), do: HTTP.Headers.from_map(headers)
  defp normalize_headers(_), do: HTTP.Headers.new()

  defp normalize_options(%__MODULE__{} = options) do
    %{options | method: normalize_method(options.method)}
  end

  defp normalize_method(method) when is_binary(method) do
    method |> String.downcase() |> String.to_atom()
  end

  defp normalize_method(method) when is_atom(method) do
    method
  end

  defp handle_unknown_option(key, value, acc) do
    if Keyword.keyword?(acc.options) do
      %{acc | options: Keyword.put(acc.options, key, value)}
    else
      acc
    end
  end

  defp maybe_add(list, _key, nil), do: list
  defp maybe_add(list, key, value), do: Keyword.put(list, key, value)
end

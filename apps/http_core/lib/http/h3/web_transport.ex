defmodule HTTP.H3.WebTransport do
  @moduledoc false

  alias HTTP.H3.Settings

  @protocol "webtransport-h3"
  @required_connect_pseudo_headers [":method", ":protocol", ":scheme", ":authority", ":path"]

  @type headers :: [{String.t(), String.t()}] | map()

  @spec protocol() :: String.t()
  def protocol, do: @protocol

  @spec client_settings(keyword()) :: Settings.settings()
  def client_settings(opts \\ []) do
    [
      {Settings.wt_enabled(), 1},
      {Settings.h3_datagram(), 1}
    ]
    |> maybe_setting(
      Settings.wt_initial_max_streams_uni(),
      Keyword.get(opts, :initial_max_streams_uni, 0)
    )
    |> maybe_setting(
      Settings.wt_initial_max_streams_bidi(),
      Keyword.get(opts, :initial_max_streams_bidi, 0)
    )
    |> maybe_setting(Settings.wt_initial_max_data(), Keyword.get(opts, :initial_max_data, 0))
  end

  @spec validate_client_settings(Settings.settings()) :: :ok | {:error, term()}
  def validate_client_settings(settings) do
    with :ok <- Settings.validate(settings),
         {:ok, normalized} <- Settings.normalize(settings),
         :ok <-
           require_setting(
             normalized,
             Settings.wt_enabled(),
             &(&1 == 1),
             :webtransport_not_enabled
           ) do
      require_setting(normalized, Settings.h3_datagram(), &(&1 == 1), :h3_datagram_disabled)
    end
  end

  @spec validate_server_settings(Settings.settings()) :: :ok | {:error, term()}
  def validate_server_settings(settings) do
    with :ok <- Settings.validate(settings),
         {:ok, normalized} <- Settings.normalize(settings),
         :ok <-
           require_setting(
             normalized,
             Settings.wt_enabled(),
             &(&1 == 1),
             :webtransport_not_enabled
           ),
         :ok <-
           require_setting(
             normalized,
             Settings.enable_connect_protocol(),
             &(&1 == 1),
             :extended_connect_disabled
           ) do
      require_setting(normalized, Settings.h3_datagram(), &(&1 == 1), :h3_datagram_disabled)
    end
  end

  @spec connect_pseudo_headers(String.t() | URI.t()) ::
          {:ok, [{String.t(), String.t()}]} | {:error, term()}
  def connect_pseudo_headers(url) do
    with {:ok, uri} <- normalize_uri(url),
         {:ok, authority} <- authority(uri),
         {:ok, path} <- request_path(uri) do
      {:ok,
       [
         {":method", "CONNECT"},
         {":protocol", @protocol},
         {":scheme", "https"},
         {":authority", authority},
         {":path", path}
       ]}
    end
  end

  @spec validate_connect_pseudo_headers(headers()) :: {:ok, map()} | {:error, term()}
  def validate_connect_pseudo_headers(headers) do
    with {:ok, headers} <- normalize_headers(headers),
         :ok <- validate_pseudo_header_order(headers),
         {:ok, pseudo_headers} <- collect_pseudo_headers(headers),
         :ok <- require_connect_pseudo_headers(pseudo_headers),
         :ok <- validate_connect_pseudo_header_values(pseudo_headers) do
      {:ok, pseudo_headers}
    end
  end

  defp maybe_setting(settings, _setting_id, 0), do: settings
  defp maybe_setting(settings, setting_id, value), do: settings ++ [{setting_id, value}]

  defp require_setting(settings, setting_id, predicate, reason) do
    case List.keyfind(settings, setting_id, 0) do
      {^setting_id, value} ->
        if predicate.(value), do: :ok, else: {:error, reason}

      nil ->
        {:error, reason}
    end
  end

  defp normalize_uri(%URI{} = uri), do: validate_uri(uri)

  defp normalize_uri(url) when is_binary(url) do
    url
    |> URI.parse()
    |> validate_uri()
  end

  defp normalize_uri(_url), do: {:error, :invalid_url}

  defp validate_uri(%URI{fragment: fragment}) when is_binary(fragment),
    do: {:error, :fragment_not_allowed}

  defp validate_uri(%URI{scheme: "https", host: host} = uri) when is_binary(host),
    do: {:ok, uri}

  defp validate_uri(%URI{scheme: scheme}), do: {:error, {:unsupported_scheme, scheme}}

  defp authority(%URI{host: host, port: port}) do
    authority =
      host
      |> bracket_ipv6_host()
      |> maybe_append_port(port)

    validate_header_value(authority, :invalid_authority)
  end

  defp bracket_ipv6_host(host) do
    if String.contains?(host, ":") and not String.starts_with?(host, "[") do
      "[" <> host <> "]"
    else
      host
    end
  end

  defp maybe_append_port(host, nil), do: host
  defp maybe_append_port(host, 443), do: host
  defp maybe_append_port(host, port), do: host <> ":" <> Integer.to_string(port)

  defp request_path(%URI{path: path, query: query}) do
    path =
      case path do
        nil -> "/"
        "" -> "/"
        path -> path
      end

    path =
      if is_binary(query) do
        path <> "?" <> query
      else
        path
      end

    with {:ok, path} <- validate_header_value(path, :invalid_path) do
      if String.starts_with?(path, "/") do
        {:ok, path}
      else
        {:error, :invalid_path}
      end
    end
  end

  defp normalize_headers(%HTTP.Headers{headers: headers}), do: normalize_headers(headers)

  defp normalize_headers(headers) when is_map(headers),
    do: headers |> Map.to_list() |> normalize_headers()

  defp normalize_headers(headers) when is_list(headers) do
    if Enum.all?(headers, &valid_header?/1) do
      {:ok, headers}
    else
      {:error, :invalid_headers}
    end
  end

  defp normalize_headers(_headers), do: {:error, :invalid_headers}

  defp valid_header?({name, value}), do: is_binary(name) and is_binary(value)
  defp valid_header?(_header), do: false

  defp validate_pseudo_header_order(headers) do
    headers
    |> Enum.reduce_while(false, fn {name, _value}, seen_regular_header? ->
      cond do
        pseudo_header?(name) and seen_regular_header? ->
          {:halt, {:error, :pseudo_header_after_regular_header}}

        pseudo_header?(name) ->
          {:cont, false}

        true ->
          {:cont, true}
      end
    end)
    |> case do
      {:error, reason} -> {:error, reason}
      _seen_regular_header? -> :ok
    end
  end

  defp collect_pseudo_headers(headers) do
    Enum.reduce_while(headers, {:ok, %{}}, fn {name, value}, {:ok, acc} ->
      if pseudo_header?(name) do
        cond do
          name not in @required_connect_pseudo_headers ->
            {:halt, {:error, {:unknown_pseudo_header, name}}}

          Map.has_key?(acc, name) ->
            {:halt, {:error, {:duplicate_pseudo_header, name}}}

          true ->
            {:cont, {:ok, Map.put(acc, name, value)}}
        end
      else
        {:cont, {:ok, acc}}
      end
    end)
  end

  defp require_connect_pseudo_headers(pseudo_headers) do
    case Enum.find(@required_connect_pseudo_headers, &(not Map.has_key?(pseudo_headers, &1))) do
      nil -> :ok
      missing -> {:error, {:missing_pseudo_header, missing}}
    end
  end

  defp validate_connect_pseudo_header_values(pseudo_headers) do
    with :ok <-
           validate_exact_pseudo_header(
             pseudo_headers,
             ":method",
             "CONNECT",
             :invalid_connect_method
           ),
         :ok <-
           validate_exact_pseudo_header(
             pseudo_headers,
             ":protocol",
             @protocol,
             :invalid_connect_protocol
           ),
         :ok <-
           validate_exact_pseudo_header(
             pseudo_headers,
             ":scheme",
             "https",
             :invalid_connect_scheme
           ),
         {:ok, _authority} <-
           validate_header_value(Map.fetch!(pseudo_headers, ":authority"), :invalid_authority),
         {:ok, path} <- validate_header_value(Map.fetch!(pseudo_headers, ":path"), :invalid_path) do
      if String.starts_with?(path, "/") do
        :ok
      else
        {:error, :invalid_path}
      end
    end
  end

  defp validate_exact_pseudo_header(pseudo_headers, name, value, error) do
    if Map.fetch!(pseudo_headers, name) == value do
      :ok
    else
      {:error, error}
    end
  end

  defp validate_header_value("", reason), do: {:error, reason}

  defp validate_header_value(value, reason) when is_binary(value) do
    if String.match?(value, ~r/[\x00-\x20\x7f]/) do
      {:error, reason}
    else
      {:ok, value}
    end
  end

  defp pseudo_header?(name), do: String.starts_with?(name, ":")
end

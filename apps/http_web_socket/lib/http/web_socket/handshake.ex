defmodule HTTP.WebSocket.Handshake do
  @moduledoc false

  @guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  @max_head_bytes 64 * 1024
  @required_headers ~w(host upgrade connection sec-websocket-key sec-websocket-version)

  @spec build_request(URI.t(), [String.t()], [{String.t(), String.t()}], String.t()) ::
          {:ok, binary()}
  def build_request(%URI{} = uri, protocols, headers, key) when is_binary(key) do
    headers =
      headers
      |> reject_required_headers()
      |> Kernel.++(required_headers(uri, key))
      |> maybe_add_protocols(protocols)

    request =
      [
        "GET ",
        request_target(uri),
        " HTTP/1.1\r\n",
        Enum.map(headers, fn {name, value} -> [name, ": ", value, "\r\n"] end),
        "\r\n"
      ]
      |> IO.iodata_to_binary()

    {:ok, request}
  end

  @spec parse_response(binary()) ::
          {:ok, non_neg_integer(), HTTP.Headers.t(), binary()}
          | {:more, binary()}
          | {:error, term()}
  def parse_response(buffer) when is_binary(buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {index, 4} when index <= @max_head_bytes ->
        head = binary_part(buffer, 0, index)
        rest = binary_part(buffer, index + 4, byte_size(buffer) - index - 4)

        with {:ok, status, headers} <- parse_head(head) do
          {:ok, status, headers, rest}
        end

      {index, 4} when index > @max_head_bytes ->
        {:error, :headers_too_large}

      :nomatch when byte_size(buffer) > @max_head_bytes ->
        {:error, :headers_too_large}

      :nomatch ->
        {:more, buffer}
    end
  end

  @spec accept_key(String.t()) :: String.t()
  def accept_key(key) when is_binary(key) do
    :sha
    |> :crypto.hash(key <> @guid)
    |> Base.encode64()
  end

  @spec validate_response(
          non_neg_integer(),
          HTTP.Headers.t() | [{String.t(), String.t()}],
          String.t(),
          [
            String.t()
          ]
        ) ::
          {:ok, %{protocol: String.t(), extensions: String.t()}} | {:error, term()}
  def validate_response(status, headers, key, requested_protocols) do
    headers = to_headers(headers)

    with :ok <- validate_status(status),
         :ok <- validate_header_token(headers, "upgrade", "websocket"),
         :ok <- validate_header_token(headers, "connection", "upgrade"),
         :ok <- validate_accept(headers, key),
         {:ok, protocol} <- validate_protocol(headers, requested_protocols),
         {:ok, extensions} <- validate_extensions(headers) do
      {:ok, %{protocol: protocol, extensions: extensions}}
    end
  end

  defp request_target(%URI{path: path, query: nil}), do: path_or_root(path)
  defp request_target(%URI{path: path, query: query}), do: path_or_root(path) <> "?" <> query

  defp path_or_root(nil), do: "/"
  defp path_or_root(""), do: "/"
  defp path_or_root(path), do: path

  defp required_headers(uri, key) do
    [
      {"Host", host_header(uri)},
      {"Upgrade", "websocket"},
      {"Connection", "Upgrade"},
      {"Sec-WebSocket-Key", key},
      {"Sec-WebSocket-Version", "13"}
    ]
  end

  defp host_header(%URI{host: host, port: nil}), do: host

  defp host_header(%URI{host: host, port: port, scheme: scheme}) do
    if default_port?(scheme, port), do: host, else: host <> ":" <> Integer.to_string(port)
  end

  defp default_port?("ws", 80), do: true
  defp default_port?("wss", 443), do: true
  defp default_port?(_scheme, _port), do: false

  defp reject_required_headers(headers) do
    Enum.reject(headers, fn {name, _value} ->
      String.downcase(name) in @required_headers
    end)
  end

  defp maybe_add_protocols(headers, []), do: headers

  defp maybe_add_protocols(headers, protocols) do
    headers ++ [{"Sec-WebSocket-Protocol", Enum.join(protocols, ", ")}]
  end

  defp parse_head(head) do
    case String.split(head, "\r\n") do
      [status_line | header_lines] ->
        with {:ok, status} <- parse_status_line(status_line),
             {:ok, headers} <- parse_headers(header_lines) do
          {:ok, status, headers}
        end

      _ ->
        {:error, :invalid_http_response}
    end
  end

  defp parse_status_line(line) do
    case String.split(line, " ", parts: 3) do
      ["HTTP/" <> _version, status_code | _reason] ->
        case Integer.parse(status_code) do
          {status, ""} -> {:ok, status}
          _ -> {:error, :invalid_status_line}
        end

      _ ->
        {:error, :invalid_status_line}
    end
  end

  defp parse_headers(lines) do
    lines
    |> Enum.reduce_while({:ok, []}, fn line, {:ok, acc} ->
      case String.split(line, ":", parts: 2) do
        [name, value] -> {:cont, {:ok, [{String.trim(name), String.trim(value)} | acc]}}
        _ -> {:halt, {:error, :invalid_header}}
      end
    end)
    |> case do
      {:ok, headers} -> {:ok, headers |> Enum.reverse() |> HTTP.Headers.new()}
      {:error, _reason} = error -> error
    end
  end

  defp validate_status(101), do: :ok
  defp validate_status(status), do: {:error, {:unexpected_status, status}}

  defp validate_header_token(headers, name, expected) do
    values =
      headers
      |> HTTP.Headers.get_all(name)
      |> Enum.flat_map(&split_header_tokens/1)

    if expected in values do
      :ok
    else
      {:error, {:missing_header_token, name, expected}}
    end
  end

  defp split_header_tokens(value) do
    value
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&String.downcase/1)
  end

  defp validate_accept(headers, key) do
    case HTTP.Headers.get(headers, "sec-websocket-accept") do
      nil -> {:error, :missing_accept}
      value -> if value == accept_key(key), do: :ok, else: {:error, :invalid_accept}
    end
  end

  defp validate_protocol(headers, requested_protocols) do
    selected = HTTP.Headers.get(headers, "sec-websocket-protocol")

    cond do
      is_nil(selected) ->
        {:ok, ""}

      selected in requested_protocols ->
        {:ok, selected}

      true ->
        {:error, {:unexpected_protocol, selected}}
    end
  end

  defp validate_extensions(headers) do
    case HTTP.Headers.get(headers, "sec-websocket-extensions") do
      nil -> {:ok, ""}
      "" -> {:ok, ""}
      value -> {:error, {:unsupported_extensions, value}}
    end
  end

  defp to_headers(%HTTP.Headers{} = headers), do: headers
  defp to_headers(headers) when is_list(headers), do: HTTP.Headers.new(headers)
end

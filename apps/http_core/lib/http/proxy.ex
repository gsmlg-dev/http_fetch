defmodule HTTP.Proxy do
  @moduledoc false

  alias HTTP.{Headers, Request}

  @max_head_bytes 16_384
  @max_auth_bytes 8_192

  def normalize(nil), do: {:ok, nil}

  def normalize({scheme, host, port, opts}) when scheme in [:http, :https] and is_list(opts) do
    if valid_host?(host) and is_integer(port) and port in 1..65_535 and
         Keyword.keyword?(opts) and
         length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) and
         Enum.all?(Keyword.keys(opts), &(&1 in [:headers, :timeout])) do
      headers = Keyword.get(opts, :headers, [])
      timeout = Keyword.get(opts, :timeout, 30_000)

      if valid_auth?(headers) and is_integer(timeout) and timeout > 0 do
        {:ok,
         %{
           scheme: scheme,
           host: String.downcase(host),
           port: port,
           headers: headers,
           timeout: timeout
         }}
      else
        {:error, :invalid_proxy_configuration}
      end
    else
      {:error, :invalid_proxy_configuration}
    end
  end

  def normalize(_), do: {:error, :invalid_proxy_configuration}

  def route(%Request{} = request, unix_socket \\ nil) do
    with {:ok, proxy} <- normalize(Keyword.get(request.transport_options, :proxy)),
         :ok <- compatible(request, proxy, unix_socket) do
      {:ok, proxy}
    end
  end

  defp compatible(_request, nil, _unix_socket), do: :ok

  defp compatible(request, proxy, unix_socket) do
    cond do
      unix_socket != nil ->
        {:error, :proxy_not_supported_for_unix_socket}

      request.url.scheme not in ["http", "https"] ->
        {:error, :unsupported_proxy_scheme}

      proxy.scheme == :https and request.url.scheme != "http" ->
        {:error, :https_proxy_requires_http_origin}

      not is_integer(request.url.port) or request.url.port not in 1..65_535 ->
        {:error, :invalid_proxy_origin}

      not valid_host?(request.url.host) ->
        {:error, :invalid_proxy_origin}

      Keyword.get(request.transport_options, :http_version) in [:h2c, :http3] ->
        {:error, :unsupported_proxy_http_version}

      true ->
        :ok
    end
  end

  def target(%Request{url: url} = request) do
    case route(request) do
      {:ok, proxy} when proxy != nil and url.scheme == "http" ->
        "http://" <> Request.authority(url) <> Request.origin_form(url)

      {:ok, _} ->
        Request.origin_form(url)

      {:error, reason} ->
        raise ArgumentError, "invalid proxy route: #{reason}"
    end
  end

  def request_headers(%Request{headers: headers, url: url} = request) do
    case route(request) do
      {:ok, nil} ->
        headers

      {:ok, proxy} ->
        headers = Headers.delete(headers, "Proxy-Authorization")

        if url.scheme == "http" do
          Enum.reduce(proxy.headers, headers, fn {_name, value}, acc ->
            Headers.set(acc, "Proxy-Authorization", value)
          end)
        else
          headers
        end

      {:error, reason} ->
        raise ArgumentError, "invalid proxy route: #{reason}"
    end
  end

  def connect(transport, _host, _port, opts, timeout, %{scheme: :https} = proxy) do
    ssl = opts |> Keyword.get(:ssl, []) |> Keyword.put(:alpn_advertised_protocols, ["http/1.1"])
    opts = opts |> Keyword.put(:ssl, ssl) |> Keyword.put(:cancellable, true)
    transport.connect(proxy.host, proxy.port, opts, min(timeout, proxy.timeout))
  end

  def connect(transport, host, port, opts, timeout, proxy) do
    deadline = System.monotonic_time(:millisecond) + min(timeout, proxy.timeout)

    socket_opts =
      opts |> Keyword.get(:socket_opts, []) |> Keyword.delete(:active) |> Keyword.delete(:packet)

    tcp_opts =
      opts
      |> Keyword.take([:request_lifecycle])
      |> Keyword.put(:socket_opts, socket_opts)

    with {:ok, tcp} <-
           HTTP.Transport.TCP.connect(proxy.host, proxy.port, tcp_opts, remaining(deadline)) do
      result =
        if transport == HTTP.Transport.TCP do
          {:ok, tcp}
        else
          upgrade_opts = Keyword.put_new(opts, :cancellable, true)

          with :ok <- establish_tunnel(tcp, host, port, proxy, deadline),
               do: transport.upgrade(tcp, host, upgrade_opts, remaining(deadline))
        end

      case result do
        {:ok, _} ->
          result

        {:error, _} ->
          :gen_tcp.close(tcp)
          result
      end
    end
  end

  defp establish_tunnel(tcp, host, port, proxy, deadline) do
    host = if String.contains?(host, ":"), do: "[#{host}]", else: host
    authority = host <> ":" <> to_string(port)

    headers =
      Enum.map(proxy.headers, fn {_name, value} -> ["Proxy-Authorization: ", value, "\r\n"] end)

    with :ok <-
           :gen_tcp.send(tcp, [
             "CONNECT ",
             authority,
             " HTTP/1.1\r\nHost: ",
             authority,
             "\r\n",
             headers,
             "\r\n"
           ]),
         {:ok, head} <- read_head(tcp, "", deadline),
         :ok <- validate_head(head),
         do: plaintext_boundary(tcp)
  end

  defp read_head(_tcp, bytes, _deadline) when byte_size(bytes) > @max_head_bytes,
    do: {:error, :proxy_response_too_large}

  defp read_head(tcp, bytes, deadline) do
    case :binary.match(bytes, "\r\n\r\n") do
      {index, 4} when byte_size(bytes) == index + 4 ->
        {:ok, binary_part(bytes, 0, index)}

      {_index, 4} ->
        {:error, :proxy_buffered_plaintext}

      :nomatch ->
        case :gen_tcp.recv(tcp, 0, remaining(deadline)) do
          {:ok, chunk} -> read_head(tcp, bytes <> chunk, deadline)
          {:error, :timeout} -> {:error, :proxy_tunnel_timeout}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp validate_head(head) do
    [status | fields] = String.split(head, "\r\n")

    case Regex.run(~r/\AHTTP\/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?\z/, status) do
      [_, code] ->
        code = String.to_integer(code)

        cond do
          code not in 200..299 -> {:error, {:proxy_connect_status, code}}
          Enum.all?(fields, &valid_response_field?/1) -> :ok
          true -> {:error, :invalid_proxy_response}
        end

      _ ->
        {:error, :invalid_proxy_response}
    end
  end

  defp valid_response_field?(line) do
    case String.split(line, ":", parts: 2) do
      [name, value] ->
        valid_name?(name) and safe_value?(value) and
          String.downcase(name) != "transfer-encoding" and
          (String.downcase(name) != "content-length" or String.trim(value) == "0")

      _ ->
        false
    end
  end

  defp plaintext_boundary(tcp) do
    case :gen_tcp.recv(tcp, 0, 0) do
      {:error, :timeout} -> :ok
      {:ok, _} -> {:error, :proxy_buffered_plaintext}
      {:error, reason} -> {:error, reason}
    end
  end

  defp valid_auth?([]), do: true

  defp valid_auth?([{name, value}]) when is_binary(name) and is_binary(value),
    do:
      String.downcase(name) == "proxy-authorization" and byte_size(value) <= @max_auth_bytes and
        safe_value?(value)

  defp valid_auth?(_), do: false

  defp valid_name?(name), do: Regex.match?(~r/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/, name)
  defp safe_value?(value), do: Enum.all?(:binary.bin_to_list(value), &(&1 == 9 or &1 in 32..126))

  defp valid_host?(host) when is_binary(host),
    do: byte_size(host) in 1..253 and Regex.match?(~r/\A[A-Za-z0-9._:-]+\z/, host)

  defp valid_host?(_), do: false
  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)
end

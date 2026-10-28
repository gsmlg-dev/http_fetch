defmodule HTTP.Proxy do
  @moduledoc false

  alias HTTP.{Headers, Request}
  alias HTTP.Transport.{ExSSL, TCP}
  alias HTTP.Transport.SSL, as: OTPTLS

  @max_auth_bytes 8_192

  def normalize(nil), do: {:ok, nil}

  def normalize({scheme, host, port, opts}) when scheme in [:http, :https] and is_list(opts) do
    if valid_host?(host) and is_integer(port) and port in 1..65_535 and
         Keyword.keyword?(opts) and
         length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) and
         Enum.all?(Keyword.keys(opts), &(&1 in [:headers, :timeout, :ssl])) do
      headers = Keyword.get(opts, :headers, [])
      timeout = Keyword.get(opts, :timeout, 30_000)

      ssl = Keyword.get(opts, :ssl)

      if valid_auth?(headers) and is_integer(timeout) and timeout > 0 and
           (is_nil(ssl) or (scheme == :https and Keyword.keyword?(ssl))) do
        {:ok,
         %{
           scheme: scheme,
           host: String.downcase(host),
           port: port,
           headers: headers,
           timeout: timeout,
           ssl: ssl
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
      {:ok, if(proxy, do: Map.put(proxy, :origin_scheme, request.url.scheme))}
    end
  end

  defp compatible(_request, nil, _unix_socket), do: :ok

  defp compatible(request, _proxy, unix_socket) do
    cond do
      unix_socket != nil ->
        {:error, :proxy_not_supported_for_unix_socket}

      request.url.scheme not in ["http", "https"] ->
        {:error, :unsupported_proxy_scheme}

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

  def connect(ExSSL, host, port, opts, timeout, %{scheme: :https, origin_scheme: "https"} = proxy) do
    deadline = System.monotonic_time(:millisecond) + min(timeout, proxy.timeout)

    ssl =
      (Map.get(proxy, :ssl) || Keyword.get(opts, :ssl, []))
      |> Keyword.put(:alpn_advertised_protocols, ["http/1.1"])

    proxy_opts = Keyword.put(opts, :ssl, ssl)

    with {:ok, attempt} <- ExSSL.prepare_nested(proxy.host, proxy_opts, host, opts, deadline),
         {:ok, tcp} <- connect_proxy_tcp_attempt(proxy, opts, deadline, {:ex_ssl_nested, attempt}) do
      result =
        with {:ok, outer} <- ExSSL.upgrade_nested(tcp, attempt, :outer, proxy_opts),
             do: nested_ex_ssl_connect(outer, attempt, host, port, opts, proxy, deadline)

      if match?({:error, _}, result) do
        ExSSL.cancel_nested(attempt)
        close_owned_tcp(tcp)
      end

      result
    end
  end

  def connect(transport, host, port, opts, timeout, %{scheme: :https} = proxy) do
    deadline = System.monotonic_time(:millisecond) + min(timeout, proxy.timeout)

    ssl =
      (Map.get(proxy, :ssl) || Keyword.get(opts, :ssl, []))
      |> Keyword.put(:alpn_advertised_protocols, ["http/1.1"])

    proxy_opts = opts |> Keyword.put(:ssl, ssl) |> Keyword.put(:cancellable, true)

    with {:ok, outer} <-
           transport.connect(proxy.host, proxy.port, proxy_opts, remaining(deadline)) do
      if Map.get(proxy, :origin_scheme) == "https" do
        nested_connect(transport, outer, host, port, opts, proxy, deadline)
      else
        {:ok, outer}
      end
    else
      # The outer TLS result can arrive before the dialer's connect timer.
      {:error, :timeout} -> {:error, :connect_timeout}
      error -> error
    end
  end

  def connect(transport, host, port, opts, timeout, proxy) do
    deadline = System.monotonic_time(:millisecond) + min(timeout, proxy.timeout)

    with {:ok, upgrade} <- prepare_tunnel_upgrade(transport, host, opts, deadline),
         {:ok, tcp} <- connect_proxy_tcp_attempt(proxy, opts, deadline, upgrade) do
      result =
        if transport == TCP do
          {:ok, tcp}
        else
          with :ok <-
                 establish_tunnel(
                   tcp,
                   host,
                   port,
                   proxy,
                   deadline,
                   Keyword.get(opts, :response_header_limits)
                 ),
               do: upgrade_tunnel(upgrade, tcp, remaining(deadline))
        end

      case result do
        {:ok, _} ->
          result

        {:error, _} ->
          cancel_upgrade(upgrade)
          close_owned_tcp(tcp)
          result
      end
    end
  end

  defp nested_connect(OTPTLS, outer, host, port, opts, proxy, deadline) do
    result =
      with :ok <-
             establish_tunnel(
               outer,
               host,
               port,
               proxy,
               deadline,
               Keyword.get(opts, :response_header_limits),
               OTPTLS
             ),
           do: HTTP.Transport.NestedTLS.upgrade(outer, host, opts, remaining(deadline))

    if match?({:error, _}, result), do: OTPTLS.abort(outer)
    result
  end

  defp nested_connect(transport, outer, _host, _port, _opts, _proxy, _deadline) do
    transport.close(outer)
    {:error, :nested_tls_requires_otp_ssl}
  end

  defp nested_ex_ssl_connect(outer, attempt, host, port, opts, proxy, deadline) do
    result =
      with :ok <-
             establish_tunnel(
               outer,
               host,
               port,
               proxy,
               deadline,
               Keyword.get(opts, :response_header_limits),
               ExSSL
             ),
           do: ExSSL.upgrade_nested(outer, attempt, :inner, opts)

    if match?({:error, _}, result), do: ExSSL.close(outer)
    result
  end

  defp prepare_tunnel_upgrade(ExSSL, host, opts, deadline) do
    with {:ok, prepared} <- ExSSL.prepare_upgrade(host, opts, deadline),
         do: {:ok, {:ex_ssl, prepared}}
  end

  defp prepare_tunnel_upgrade(transport, host, opts, _deadline),
    do: {:ok, {:legacy, transport, host, opts}}

  defp upgrade_tunnel({:ex_ssl, prepared}, tcp, timeout),
    do: ExSSL.upgrade_prepared(tcp, prepared, timeout)

  defp upgrade_tunnel({:legacy, transport, host, opts}, tcp, timeout),
    do: transport.upgrade(tcp, host, opts, timeout)

  defp cancel_upgrade({:ex_ssl, attempt}), do: ExSSL.cancel_prepared(attempt)
  defp cancel_upgrade({:ex_ssl_nested, attempt}), do: ExSSL.cancel_nested(attempt)
  defp cancel_upgrade(_upgrade), do: :ok

  defp connect_proxy_tcp_attempt(proxy, opts, deadline, upgrade) do
    case connect_proxy_tcp(proxy, opts, deadline) do
      {:ok, _} = result ->
        result

      error ->
        cancel_upgrade(upgrade)
        error
    end
  end

  defp close_owned_tcp(tcp) do
    if Port.info(tcp, :connected) == {:connected, self()}, do: :gen_tcp.close(tcp)
  end

  defp connect_proxy_tcp(proxy, opts, deadline) do
    tcp_opts = proxy_tcp_options(opts)

    case remaining(deadline) do
      0 -> {:error, :timeout}
      timeout -> TCP.connect(proxy.host, proxy.port, tcp_opts, timeout)
    end
  end

  defp proxy_tcp_options(opts) do
    socket_opts =
      opts |> Keyword.get(:socket_opts, []) |> Keyword.delete(:active) |> Keyword.delete(:packet)

    [
      socket_opts: socket_opts,
      request_lifecycle: Keyword.get(opts, :request_lifecycle),
      prefer_ipv6: Keyword.get(opts, :prefer_ipv6, false)
    ]
  end

  defp establish_tunnel(tcp, host, port, proxy, deadline, limits, transport \\ TCP) do
    host = if String.contains?(host, ":"), do: "[#{host}]", else: host
    authority = host <> ":" <> to_string(port)

    headers =
      Enum.map(proxy.headers, fn {_name, value} -> ["Proxy-Authorization: ", value, "\r\n"] end)

    with :ok <-
           send_tunnel(
             transport,
             tcp,
             [
               "CONNECT ",
               authority,
               " HTTP/1.1\r\nHost: ",
               authority,
               "\r\n",
               headers,
               "\r\n"
             ],
             deadline
           ),
         {:ok, head} <- read_head(tcp, "", deadline, limits, 0, 0, transport),
         :ok <- validate_head(head),
         do: plaintext_boundary(tcp, transport)
  end

  defp send_tunnel(ExSSL, socket, bytes, deadline),
    do: ExSSL.send(socket, bytes, {:abs_ms, deadline})

  defp send_tunnel(transport, socket, bytes, _deadline), do: transport.send(socket, bytes)

  defp read_head(tcp, bytes, deadline, limits, info_count, info_bytes, transport) do
    case :binary.match(bytes, "\r\n\r\n") do
      {index, 4} ->
        with :ok <- HTTP.ResponseHeaderLimits.check(limits, bytes, :connect, index) do
          head = binary_part(bytes, 0, index)
          rest = binary_part(bytes, index + 4, byte_size(bytes) - index - 4)
          next_proxy_head(tcp, head, rest, deadline, limits, info_count, info_bytes, transport)
        end

      :nomatch ->
        with :ok <- HTTP.ResponseHeaderLimits.check(limits, bytes, :connect) do
          case transport.recv(tcp, 0, remaining(deadline)) do
            {:ok, chunk} ->
              read_head(tcp, bytes <> chunk, deadline, limits, info_count, info_bytes, transport)

            {:error, :timeout} ->
              {:error, :proxy_tunnel_timeout}

            {:error, reason} ->
              {:error, reason}
          end
        end
    end
  end

  defp next_proxy_head(tcp, head, rest, deadline, limits, info_count, info_bytes, transport) do
    case validate_head(head) do
      {:informational, _status} ->
        count = info_count + 1
        size = info_bytes + byte_size(head) + 4

        with :ok <- HTTP.ResponseHeaderLimits.informational(limits, :connect, count, size),
             do: read_head(tcp, rest, deadline, limits, count, size, transport)

      :ok when rest == "" ->
        {:ok, head}

      :ok ->
        {:error, :proxy_buffered_plaintext}

      error ->
        error
    end
  end

  defp validate_head(head) do
    [status | fields] = String.split(head, "\r\n")

    case Regex.run(~r/\AHTTP\/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?\z/, status) do
      [_, code] ->
        code = String.to_integer(code)

        cond do
          not Enum.all?(fields, &valid_response_field?/1) -> {:error, :invalid_proxy_response}
          code in 100..199 and code != 101 -> {:informational, code}
          code in 200..299 -> :ok
          true -> {:error, {:proxy_connect_status, code}}
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

  defp plaintext_boundary(tcp, transport) do
    case transport.recv(tcp, 0, 0) do
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

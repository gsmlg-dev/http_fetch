defmodule HTTP.Transport.ExSSL do
  @moduledoc false

  @behaviour HTTP.Transport

  @impl true
  def connect(host, port, opts, timeout) do
    with {:ok, ssl_opts} <- tls_options(opts) do
      route = if Keyword.get(opts, :connect_address) != nil, do: :pinned, else: :direct
      ssl_opts = origin_identity(host, ssl_opts, route)

      SSL.connect(
        Keyword.get(opts, :connect_address, connect_host(host)),
        port,
        ssl_opts,
        timeout
      )
    end
  end

  @doc false
  def upgrade(tcp, host, opts, timeout) do
    with {:ok, ssl_opts} <- tls_options(opts),
         do: SSL.connect(tcp, origin_identity(host, ssl_opts, :upgrade), timeout)
  end

  @impl true
  def controlling_process(socket, pid), do: SSL.controlling_process(socket, pid)

  @impl true
  def send(socket, iodata), do: SSL.send(socket, iodata)

  @doc false
  def enable_duplex_reads(socket, timeout) do
    with :ok <- SSL.setopts(socket, send_timeout: timeout),
         do: SSL.enable_duplex_reads(socket)
  end

  @doc false
  def abandon_send(socket), do: SSL.abandon_send(socket)

  @impl true
  def recv(socket, length, timeout), do: SSL.recv(socket, length, timeout)

  @impl true
  def setopts(socket, opts), do: SSL.setopts(socket, opts)

  @impl true
  def close(socket), do: SSL.close(socket)

  @impl true
  def negotiated_protocol(socket) do
    case SSL.negotiated_protocol(socket) do
      {:error, :protocol_not_negotiated} -> {:ok, nil}
      result -> result
    end
  end

  @impl true
  def normalize_message({:ssl, socket, data}, socket), do: {:data, data}
  def normalize_message({:ssl_closed, socket}, socket), do: :closed
  def normalize_message({:ssl_error, socket, reason}, socket), do: {:error, reason}
  def normalize_message(_, _), do: :unknown

  defp tls_options(opts) do
    ssl_opts = Keyword.get(opts, :ssl, [])
    socket_opts = Keyword.get(opts, :socket_opts, [])

    with :ok <- validate_keyword(ssl_opts),
         :ok <- validate_keyword(socket_opts),
         :ok <- validate_socket_options(socket_opts) do
      # SSL supplies system trust only when neither caller CA option is present,
      # and infers DNS SNI or IP identity from the connection host.
      defaults = [
        mode: :binary,
        packet: :raw,
        active: false,
        verify: :verify_peer,
        versions: Keyword.get_lazy(ssl_opts, :versions, fn -> default_versions(ssl_opts) end),
        depth: 4,
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]

      {:ok, defaults |> Keyword.merge(ssl_opts) |> Keyword.merge(socket_opts)}
    end
  end

  # Concrete profiles retain their ordered version policy. Auto tickets and an
  # explicit cipher policy retain the previous TLS 1.3 context unless versions
  # are explicit. This does not infer protocol versions from cipher spellings.
  # Ordinary HTTP with no concrete policy offers both supported versions.
  defp default_versions(ssl_opts) do
    ex_ssl = Keyword.get(ssl_opts, :ex_ssl, [])
    profile = if Keyword.keyword?(ex_ssl), do: Keyword.get(ex_ssl, :profile)

    case profile do
      %SSL.ClientHello.WireProfile{extensions: extensions} when is_list(extensions) ->
        profile_versions(extensions)

      _ ->
        if Keyword.get(ssl_opts, :session_tickets) == :auto or
             Keyword.has_key?(ssl_opts, :ciphers),
           do: [:"tlsv1.3"],
           else: [:"tlsv1.3", :"tlsv1.2"]
    end
  end

  defp profile_versions(extensions) do
    case List.keyfind(extensions, :supported_versions, 0) do
      {:supported_versions, versions} when is_list(versions) ->
        Enum.flat_map(versions, fn
          {:grease, _slot} -> []
          version when version in [0x0304, :tlsv1_3] -> [:"tlsv1.3"]
          version when version in [0x0303, :tlsv1_2] -> [:"tlsv1.2"]
          version -> [version]
        end)

      _ ->
        [:"tlsv1.3"]
    end
  end

  defp validate_keyword(opts) do
    if Keyword.keyword?(opts) and
         length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) do
      :ok
    else
      {:error, {:options, :invalid_options}}
    end
  end

  defp validate_socket_options(opts) do
    allowed = [
      :send_timeout,
      :send_timeout_close,
      :nodelay,
      :keepalive,
      :sndbuf,
      :recbuf,
      :buffer,
      :tos,
      :tclass,
      :priority,
      :ip,
      :port
    ]

    case Enum.find(opts, fn {key, _} -> key not in allowed end) do
      nil -> :ok
      {key, _} -> {:error, {:options, {key, :unsupported_or_invalid}}}
    end
  end

  defp origin_identity(host, ssl_opts, route) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} ->
        ex_ssl = Keyword.get(ssl_opts, :ex_ssl, [])

        valid_options? =
          not Keyword.has_key?(ssl_opts, :ex_ssl) or
            (Keyword.keyword?(ex_ssl) and ex_ssl != [])

        ip_reference? =
          route == :pinned or Keyword.get(ssl_opts, :server_name_indication) in [nil, :disable]

        if valid_options? and ip_reference? do
          ssl_opts
          |> Keyword.put(:ex_ssl, Keyword.put_new(ex_ssl, :reference_identity, {:ip, address}))
          |> Keyword.put_new(:server_name_indication, :disable)
        else
          ssl_opts
        end

      {:error, _} ->
        if route != :direct,
          do: Keyword.put_new(ssl_opts, :server_name_indication, String.to_charlist(host)),
          else: ssl_opts
    end
  end

  defp connect_host(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> address
      {:error, :einval} -> host
    end
  end
end

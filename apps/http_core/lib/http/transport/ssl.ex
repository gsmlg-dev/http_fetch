defmodule HTTP.Transport.SSL do
  @moduledoc false

  @behaviour HTTP.Transport

  @type cancellable_socket :: {:cancellable_ssl, :ssl.sslsocket(), port()}

  # Temporary OTP-only accounting. Other providers supply public lifecycle proof.
  @doc false
  def lifecycle_resources({:sslsocket, {:gen_tcp, tcp, _, _}, [receiver, sender]})
      when is_port(tcp) and is_pid(receiver) and is_pid(sender),
      do: {:ok, tcp, [receiver, sender]}

  def lifecycle_resources({:sslsocket, tcp, receiver, sender, :gen_tcp, _, _, _})
      when is_port(tcp) and is_pid(receiver) and is_pid(sender),
      do: {:ok, tcp, [receiver, sender]}

  def lifecycle_resources(
        {:sslsocket, outer, receiver, sender, HTTP.Transport.NestedTLS, _, _, _}
      )
      when is_pid(receiver) and is_pid(sender) do
    with {:ok, tcp, outer_pids} <- lifecycle_resources(outer),
         do: {:ok, tcp, [receiver, sender | outer_pids]}
  end

  def lifecycle_resources(
        {:sslsocket, {HTTP.Transport.NestedTLS, outer, _, _}, [receiver, sender]}
      )
      when is_pid(receiver) and is_pid(sender) do
    with {:ok, tcp, outer_pids} <- lifecycle_resources(outer),
         do: {:ok, tcp, [receiver, sender | outer_pids]}
  end

  def lifecycle_resources(_socket), do: :error

  # Retain the TCP handle through the public TLS upgrade API. OTP's graceful
  # close can wait on its sender even with a zero close timeout.
  @spec connect_cancellable(String.t(), non_neg_integer(), keyword(), timeout()) ::
          {:ok, cancellable_socket()} | {:error, term()}
  def connect_cancellable(host, port, opts, timeout) do
    deadline = if timeout == :infinity, do: :infinity, else: now() + timeout
    socket_opts = [:binary, packet: :raw, active: false] ++ Keyword.get(opts, :socket_opts, [])
    ssl_opts = ssl_options(host, Keyword.get(opts, :ssl, []))

    case HTTP.Transport.AddressFamily.connect(host, port, socket_opts, opts, timeout) do
      {:ok, tcp} ->
        HTTP.RequestLifecycle.track_socket(opts, tcp)
        remaining = if deadline == :infinity, do: :infinity, else: max(deadline - now(), 0)

        tls_opts =
          [:binary, packet: :raw, active: false] ++
            ssl_opts ++ Keyword.get(opts, :socket_opts, [])

        case connect_tls(tcp, tls_opts, opts, deadline, remaining) do
          {:ok, socket} ->
            case HTTP.RequestLifecycle.track_tls(opts, socket) do
              :ok ->
                {:ok, {:cancellable_ssl, socket, tcp}}

              {:error, _} = error ->
                abort_tcp(tcp)
                error
            end

          {:error, _} = error ->
            if not Keyword.get(opts, :tls_setup_evidence, false), do: unconfirmed_setup(opts)
            abort_tcp(tcp)
            error
        end

      {:error, reason} ->
        HTTP.Transport.connect_error(opts, reason)
    end
  end

  # Public hello pause exposes the exact TLS receiver/sender before certificate
  # validation. No HTTP bytes can be sent before this continuation returns.
  defp connect_tls(tcp, tls_opts, opts, deadline, remaining) do
    if Keyword.get(opts, :tls_setup_evidence, false) do
      case :ssl.connect(tcp, Keyword.put(tls_opts, :handshake, :hello), remaining) do
        {:ok, socket, _extensions} ->
          with :ok <- HTTP.RequestLifecycle.track_tls(opts, socket) do
            socket
            |> :ssl.handshake_continue([], remaining(deadline))
            |> setup_result(opts, deadline)
          end

        {:error, _} = error ->
          unconfirmed_setup(opts)
          error
      end
    else
      :ssl.connect(tcp, tls_opts, remaining)
    end
  end

  defp setup_result({:error, {:tls_alert, {alert, _}} = reason}, opts, deadline)
       when alert in [
              :handshake_failure,
              :bad_certificate,
              :unsupported_certificate,
              :certificate_revoked,
              :certificate_expired,
              :certificate_unknown,
              :unknown_ca,
              :access_denied,
              :certificate_required,
              :no_application_protocol
            ] do
    if remaining(deadline) > 0,
      do: HTTP.Transport.tls_setup_error(opts, reason),
      else: {:error, reason}
  end

  defp setup_result(result, _opts, _deadline), do: result

  defp remaining(:infinity), do: :infinity
  defp remaining(deadline), do: max(deadline - now(), 0)

  @doc false
  def upgrade(tcp, host, opts, timeout) do
    HTTP.RequestLifecycle.track_socket(opts, tcp)

    tls_opts =
      [:binary, packet: :raw, active: false] ++
        ssl_options(host, Keyword.get(opts, :ssl, [])) ++ Keyword.get(opts, :socket_opts, [])

    case :ssl.connect(tcp, tls_opts, timeout) do
      {:ok, socket} ->
        case HTTP.RequestLifecycle.track_tls(opts, socket) do
          :ok ->
            if Keyword.get(opts, :cancellable, false),
              do: {:ok, {:cancellable_ssl, socket, tcp}},
              else: {:ok, socket}

          {:error, _} = error ->
            abort_tcp(tcp)
            error
        end

      {:error, _} = error ->
        unconfirmed_setup(opts)
        abort_tcp(tcp)
        error
    end
  end

  @doc false
  def cancellable?({:cancellable_ssl, _socket, _tcp}), do: true
  def cancellable?(_socket), do: false

  @spec abort(cancellable_socket()) :: :ok
  def abort({:cancellable_ssl, _socket, tcp}), do: abort_tcp(tcp)

  defp abort_tcp(tcp) do
    _ = :inet.setopts(tcp, linger: {true, 0})
    :gen_tcp.close(tcp)
  end

  # A failed public connect returns no TLS socket. OTP may reply before its
  # receiver/sender terminate, so there is no proven DOWN barrier.
  defp unconfirmed_setup(opts) do
    HTTP.RequestLifecycle.unconfirmed_tls(Keyword.get(opts, :request_lifecycle))
  end

  defp now, do: System.monotonic_time(:millisecond)

  @impl true
  def connect(host, port, [{:cancellable, true} | opts], timeout),
    do: connect_cancellable(host, port, opts, timeout)

  def connect(host, port, opts, timeout) do
    if Keyword.get(opts, :request_lifecycle) do
      connect_cancellable(host, port, opts, timeout)
    else
      connect_unmanaged(host, port, opts, timeout)
    end
  end

  defp connect_unmanaged(host, port, opts, timeout) do
    if HTTP.Transport.AddressFamily.preferred?(opts),
      do: connect_unmanaged_preferred(host, port, opts, timeout),
      else: connect_unmanaged_direct(host, port, opts, timeout)
  end

  defp connect_unmanaged_preferred(host, port, opts, timeout) do
    deadline = if timeout == :infinity, do: :infinity, else: now() + timeout
    socket_opts = [:binary, packet: :raw, active: false] ++ Keyword.get(opts, :socket_opts, [])

    with {:ok, tcp} <-
           HTTP.Transport.AddressFamily.connect(host, port, socket_opts, opts, timeout) do
      case :ssl.connect(
             tcp,
             [:binary, packet: :raw, active: false] ++
               ssl_options(host, Keyword.get(opts, :ssl, [])) ++
               Keyword.get(opts, :socket_opts, []),
             remaining(deadline)
           ) do
        {:ok, _socket} = connected ->
          connected

        error ->
          :gen_tcp.close(tcp)
          error
      end
    end
  end

  defp connect_unmanaged_direct(host, port, opts, timeout) do
    ssl_opts = ssl_options(host, Keyword.get(opts, :ssl, []))

    socket_opts =
      [
        :binary,
        packet: :raw,
        active: false
      ] ++ ssl_opts ++ Keyword.get(opts, :socket_opts, [])

    :ssl.connect(
      Keyword.get(opts, :connect_address, String.to_charlist(host)),
      port,
      socket_opts,
      timeout
    )
  end

  @impl true
  def controlling_process({:cancellable_ssl, socket, _tcp}, pid),
    do: controlling_process(socket, pid)

  def controlling_process(socket, pid), do: :ssl.controlling_process(socket, pid)

  @impl true
  def send({:cancellable_ssl, socket, _tcp}, iodata), do: :ssl.send(socket, iodata)
  def send(socket, iodata), do: :ssl.send(socket, iodata)

  @impl true
  def recv({:cancellable_ssl, socket, _tcp}, length, timeout), do: recv(socket, length, timeout)
  def recv(socket, length, timeout), do: :ssl.recv(socket, length, timeout)

  @impl true
  def setopts({:cancellable_ssl, socket, _tcp}, opts), do: setopts(socket, opts)
  def setopts(socket, opts), do: :ssl.setopts(socket, opts)

  @impl true
  def close({:cancellable_ssl, socket, _tcp}), do: close(socket)
  def close(socket), do: :ssl.close(socket)

  @impl true
  @spec negotiated_protocol(:ssl.sslsocket() | cancellable_socket()) ::
          {:ok, binary() | nil} | {:error, :closed}
  def negotiated_protocol({:cancellable_ssl, socket, _tcp}), do: negotiated_protocol(socket)

  def negotiated_protocol(socket) do
    case :ssl.negotiated_protocol(socket) do
      {:ok, protocol} -> {:ok, protocol}
      {:error, :protocol_not_negotiated} -> {:ok, nil}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def normalize_message(message, {:cancellable_ssl, socket, _tcp}),
    do: normalize_message(message, socket)

  def normalize_message({:ssl, socket, data}, socket), do: {:data, data}
  def normalize_message({:ssl_closed, socket}, socket), do: :closed
  def normalize_message({:ssl_error, socket, reason}, socket), do: {:error, reason}
  def normalize_message(_, _), do: :unknown

  defp default_ssl_options(host) do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      server_name_indication: String.to_charlist(host),
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ],
      versions: [:"tlsv1.3", :"tlsv1.2"],
      depth: 4
    ]
  end

  @doc false
  def ssl_options(host, user_ssl_opts) do
    user_ssl_opts = normalize_user_ssl_options(user_ssl_opts)

    host
    |> default_ssl_options()
    |> maybe_drop_default_cacerts(user_ssl_opts)
    |> Keyword.merge(user_ssl_opts)
  end

  defp normalize_user_ssl_options(user_ssl_opts) do
    Enum.map(user_ssl_opts, fn
      {key, value} when key in [:cacertfile, :certfile, :keyfile] and is_binary(value) ->
        {key, String.to_charlist(value)}

      option ->
        option
    end)
  end

  defp maybe_drop_default_cacerts(defaults, user_ssl_opts) do
    if Keyword.has_key?(user_ssl_opts, :cacertfile) or Keyword.has_key?(user_ssl_opts, :cacerts) do
      Keyword.delete(defaults, :cacerts)
    else
      defaults
    end
  end
end

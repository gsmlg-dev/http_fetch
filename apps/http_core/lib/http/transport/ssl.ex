defmodule HTTP.Transport.SSL do
  @moduledoc false

  @behaviour HTTP.Transport

  @type cancellable_socket :: {:cancellable_ssl, :ssl.sslsocket(), port()}

  # Retain the TCP handle through the public TLS upgrade API. OTP's graceful
  # close can wait on its sender even with a zero close timeout.
  @spec connect_cancellable(String.t(), non_neg_integer(), keyword(), timeout()) ::
          {:ok, cancellable_socket()} | {:error, term()}
  def connect_cancellable(host, port, opts, timeout) do
    deadline = if timeout == :infinity, do: :infinity, else: now() + timeout
    socket_opts = [:binary, packet: :raw, active: false] ++ Keyword.get(opts, :socket_opts, [])
    ssl_opts = ssl_options(host, Keyword.get(opts, :ssl, []))

    with {:ok, tcp} <- :gen_tcp.connect(String.to_charlist(host), port, socket_opts, timeout) do
      remaining = if deadline == :infinity, do: :infinity, else: max(deadline - now(), 0)

      tls_opts =
        [:binary, packet: :raw, active: false] ++ ssl_opts ++ Keyword.get(opts, :socket_opts, [])

      case :ssl.connect(tcp, tls_opts, remaining) do
        {:ok, socket} ->
          {:ok, {:cancellable_ssl, socket, tcp}}

        {:error, _} = error ->
          abort_tcp(tcp)
          error
      end
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

  defp now, do: System.monotonic_time(:millisecond)

  @impl true
  def connect(host, port, [{:cancellable, true} | opts], timeout),
    do: connect_cancellable(host, port, opts, timeout)

  def connect(host, port, opts, timeout) do
    ssl_opts = ssl_options(host, Keyword.get(opts, :ssl, []))

    socket_opts =
      [
        :binary,
        packet: :raw,
        active: false
      ] ++ ssl_opts ++ Keyword.get(opts, :socket_opts, [])

    :ssl.connect(String.to_charlist(host), port, socket_opts, timeout)
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

  defp ssl_options(host, user_ssl_opts) do
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

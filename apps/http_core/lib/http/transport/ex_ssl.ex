defmodule HTTP.Transport.ExSSL do
  @moduledoc false

  @behaviour HTTP.Transport

  @impl true
  def connect(host, port, opts, timeout) do
    with {:ok, ssl_opts} <- tls_options(opts) do
      SSL.connect(connect_host(host), port, ssl_opts, timeout)
    end
  end

  @impl true
  def controlling_process(socket, pid), do: SSL.controlling_process(socket, pid)

  @impl true
  def send(socket, iodata), do: SSL.send(socket, iodata)

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
        versions: [:"tlsv1.3"],
        depth: 4,
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]

      {:ok, defaults |> Keyword.merge(ssl_opts) |> Keyword.merge(socket_opts)}
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
      :ip,
      :port
    ]

    case Enum.find(opts, fn {key, _} -> key not in allowed end) do
      nil -> :ok
      {key, _} -> {:error, {:options, {key, :unsupported_or_invalid}}}
    end
  end

  defp connect_host(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> address
      {:error, :einval} -> host
    end
  end
end

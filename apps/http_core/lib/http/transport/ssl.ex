defmodule HTTP.Transport.SSL do
  @moduledoc false

  @behaviour HTTP.Transport

  @impl true
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
  def controlling_process(socket, pid), do: :ssl.controlling_process(socket, pid)

  @impl true
  def send(socket, iodata), do: :ssl.send(socket, iodata)

  @impl true
  def setopts(socket, opts), do: :ssl.setopts(socket, opts)

  @impl true
  def close(socket), do: :ssl.close(socket)

  @spec negotiated_protocol(:ssl.sslsocket()) :: {:ok, binary() | nil} | {:error, term()}
  def negotiated_protocol(socket) do
    case :ssl.negotiated_protocol(socket) do
      {:ok, protocol} -> {:ok, protocol}
      {:error, :protocol_not_negotiated} -> {:ok, nil}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
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

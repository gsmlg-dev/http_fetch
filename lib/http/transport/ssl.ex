defmodule HTTP.Transport.SSL do
  @moduledoc false

  @behaviour HTTP.Transport

  @impl true
  def connect(host, port, opts, timeout) do
    ssl_opts =
      host
      |> default_ssl_options()
      |> Keyword.merge(Keyword.get(opts, :ssl, []))

    socket_opts =
      [
        :binary,
        packet: :raw,
        active: false
      ] ++ ssl_opts ++ Keyword.get(opts, :socket_opts, [])

    :ssl.connect(String.to_charlist(host), port, socket_opts, timeout)
  end

  @impl true
  def send(socket, iodata), do: :ssl.send(socket, iodata)

  @impl true
  def setopts(socket, opts), do: :ssl.setopts(socket, opts)

  @impl true
  def close(socket), do: :ssl.close(socket)

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
end

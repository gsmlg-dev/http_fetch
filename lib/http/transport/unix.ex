defmodule HTTP.Transport.Unix do
  @moduledoc false

  @behaviour HTTP.Transport

  @impl true
  def connect(socket_path, _port, opts, timeout) do
    socket_opts =
      [
        :binary,
        packet: :raw,
        active: false
      ] ++ Keyword.get(opts, :socket_opts, [])

    :gen_tcp.connect({:local, String.to_charlist(socket_path)}, 0, socket_opts, timeout)
  end

  @impl true
  def send(socket, iodata), do: :gen_tcp.send(socket, iodata)

  @impl true
  def setopts(socket, opts), do: :inet.setopts(socket, opts)

  @impl true
  def close(socket), do: :gen_tcp.close(socket)

  @impl true
  def normalize_message({:tcp, socket, data}, socket), do: {:data, data}
  def normalize_message({:tcp_closed, socket}, socket), do: :closed
  def normalize_message({:tcp_error, socket, reason}, socket), do: {:error, reason}
  def normalize_message(_, _), do: :unknown
end

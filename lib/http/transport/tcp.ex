defmodule HTTP.Transport.TCP do
  @moduledoc false

  @behaviour HTTP.Transport

  @impl true
  def connect(host, port, opts, timeout) do
    socket_opts =
      [
        :binary,
        packet: :raw,
        active: false
      ] ++ Keyword.get(opts, :socket_opts, [])

    :gen_tcp.connect(String.to_charlist(host), port, socket_opts, timeout)
  end

  @impl true
  def controlling_process(socket, pid), do: :gen_tcp.controlling_process(socket, pid)

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

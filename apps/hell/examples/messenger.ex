defmodule Messenger do
  @moduledoc """
  A sample Handler implementation that allows for simultaneous bidirectional sending
  of messages to demonstrate that the Handler process is just a GenServer under the
  hood
  """

  use Hell.Handler

  def send_message(pid, msg) do
    GenServer.cast(pid, {:send, msg})
  end

  @impl Hell.Handler
  def handle_connection(socket, state) do
    {:ok, {remote_address, _port}} = Hell.Socket.peername(socket)
    IO.puts("#{inspect(self())} received connection from #{remote_address}")
    {:continue, state}
  end

  @impl Hell.Handler
  def handle_data(msg, _socket, state) do
    IO.puts("Received #{msg}")
    {:continue, state}
  end

  @impl GenServer
  def handle_cast({:send, msg}, {socket, state}) do
    Hell.Socket.send(socket, msg)
    {:noreply, {socket, state}, socket.read_timeout}
  end
end

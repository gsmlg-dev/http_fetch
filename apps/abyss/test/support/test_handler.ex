defmodule Abyss.TestHandler do
  @moduledoc """
  Test handler module for testing Abyss.Handler behaviour
  """
  require Abyss.Handler
  Abyss.Handler.__implement__([])

  @impl true
  def handle_data({ip, port, data}, state) do
    send(self(), {:packet_received, data, {ip, port}})
    {:continue, state}
  end

  @impl true
  def handle_info({:packet_received, _data, {_ip, _port}}, state) do
    # Handle the packet received message sent by handle_data
    {:noreply, state}
  end
end

defmodule Abyss.TestEchoHandler do
  @moduledoc """
  Test echo handler for integration testing
  """
  require Abyss.Handler
  Abyss.Handler.__implement__([])

  @impl true
  def handle_data({ip, port, data}, state) do
    :ok = Abyss.Transport.UDP.send(state.socket, ip, port, data)
    {:continue, state}
  end
end

defmodule Echo do
  @moduledoc """
  A sample Handler implementation of the Echo protocol

  https://en.wikipedia.org/wiki/Echo_Protocol
  """

  use Hell.Handler

  @impl Hell.Handler
  def handle_data(data, socket, state) do
    Hell.Socket.send(socket, data)
    {:continue, state}
  end
end

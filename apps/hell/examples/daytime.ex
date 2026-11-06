defmodule Daytime do
  @moduledoc """
  A sample Handler implementation of the Daytime protocol

  https://en.wikipedia.org/wiki/Daytime_Protocol
  """

  use Hell.Handler

  @impl Hell.Handler
  def handle_connection(socket, state) do
    time = DateTime.utc_now() |> to_string()
    Hell.Socket.send(socket, time)
    {:close, state}
  end
end

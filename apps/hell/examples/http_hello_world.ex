defmodule HTTPHelloWorld do
  @moduledoc """
  A sample Handler implementation of a simple HTTP Server. Intended to be the
  simplest thing that can answer a browser request and nothing more. Not even
  remotely strictly HTTP compliant.
  """

  use Hell.Handler

  @impl Hell.Handler
  def handle_data(_data, socket, state) do
    Hell.Socket.send(socket, "HTTP/1.0 200 OK\r\n\r\nHello, World")
    {:close, state}
  end
end

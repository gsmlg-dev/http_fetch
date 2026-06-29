defmodule HTTPWebSocket.Application do
  @moduledoc """
  Supervision tree for WebSocket connection processes.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: HTTP.WebSocket.ConnectionSupervisor},
      {Registry, keys: :unique, name: HTTP.WebSocket.Registry}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__)
  end
end

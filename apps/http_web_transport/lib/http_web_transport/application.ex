defmodule HTTPWebTransport.Application do
  @moduledoc """
  Supervision tree for WebTransport session processes.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: HTTP.WebTransport.SessionSupervisor},
      {Registry, keys: :unique, name: HTTP.WebTransport.Registry}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__)
  end
end

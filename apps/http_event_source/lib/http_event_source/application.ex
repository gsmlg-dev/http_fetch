defmodule HTTPEventSource.Application do
  @moduledoc """
  Supervision tree for EventSource connection processes.
  """

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: HTTP.EventSource.ConnectionSupervisor},
      {Registry, keys: :unique, name: HTTP.EventSource.Registry}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: __MODULE__)
  end
end

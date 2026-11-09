defmodule SSL.ConnectionSupervisor do
  @moduledoc false

  use DynamicSupervisor

  def start_link(opts \\ []) do
    DynamicSupervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc false
  # Client connections start through SSL's handoff; TCP TLS servers start here.
  def start_server(args),
    do: DynamicSupervisor.start_child(__MODULE__, {SSL.ServerConnection, args})

  @impl true
  def init(_opts), do: DynamicSupervisor.init(strategy: :one_for_one)
end

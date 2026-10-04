defmodule SSL.Supervisor do
  @moduledoc false

  use Supervisor

  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Supervisor.init([SSL.TicketCache, SSL.ConnectionSupervisor], strategy: :one_for_one)
  end
end

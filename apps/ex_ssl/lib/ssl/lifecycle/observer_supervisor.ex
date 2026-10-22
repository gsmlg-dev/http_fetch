defmodule SSL.Lifecycle.ObserverSupervisor do
  @moduledoc false
  use DynamicSupervisor

  alias SSL.Lifecycle.{Authority, Bootstrap, Handoff, Observer, Reader, Receipt, ResourceLedger}

  @control_modules [
    :atomics,
    :timer,
    Authority,
    Bootstrap,
    Handoff,
    Observer,
    Reader,
    Receipt,
    ResourceLedger
  ]

  def start_link(options \\ []),
    do: DynamicSupervisor.start_link(__MODULE__, options, name: __MODULE__)

  @impl true
  def init(_options) do
    # Load control code before timed admission and receipt reads. Load errors fail startup.
    Enum.each(@control_modules, &Code.ensure_loaded!/1)
    DynamicSupervisor.init(strategy: :one_for_one)
  end
end

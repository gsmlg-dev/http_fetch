defmodule SSL.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args), do: SSL.Supervisor.start_link()
end

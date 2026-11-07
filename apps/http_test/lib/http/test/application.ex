defmodule HTTP.Test.Application do
  @moduledoc false
  use Application

  def start(_type, _args) do
    Supervisor.start_link([HTTP.Test.Registry],
      strategy: :one_for_one,
      name: HTTP.Test.Supervisor
    )
  end
end

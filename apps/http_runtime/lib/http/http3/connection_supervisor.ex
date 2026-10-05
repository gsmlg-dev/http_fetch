defmodule HTTP.HTTP3.ConnectionSupervisor do
  @moduledoc "Supervises temporary HTTP/3 owners independently of request callers."
  use DynamicSupervisor

  def start_link(opts \\ []),
    do: DynamicSupervisor.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @impl true
  def init(_opts), do: DynamicSupervisor.init(strategy: :one_for_one)

  def start_connection(opts, supervisor \\ :http_fetch_http3_connection_supervisor) do
    DynamicSupervisor.start_child(supervisor, %{
      id: HTTP.HTTP3.ConnectionOwner,
      start: {HTTP.HTTP3.ConnectionOwner, :start_link, [opts]},
      restart: :temporary
    })
  end
end

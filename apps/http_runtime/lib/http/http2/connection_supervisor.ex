defmodule HTTP.HTTP2.ConnectionSupervisor do
  @moduledoc "Supervises HTTP/2 socket owners independently of request callers."
  use DynamicSupervisor

  def start_link(opts \\ []),
    do: DynamicSupervisor.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))

  @impl true
  def init(_opts), do: DynamicSupervisor.init(strategy: :one_for_one)

  def start_connection(opts, supervisor \\ :http_fetch_http2_connection_supervisor) do
    child = %{
      id: HTTP.HTTP2.ConnectionOwner,
      start: {HTTP.HTTP2.ConnectionOwner, :start_link, [opts]},
      restart: :temporary,
      type: :worker
    }

    DynamicSupervisor.start_child(supervisor, child)
  end
end

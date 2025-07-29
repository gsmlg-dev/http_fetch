defmodule HTTPFetch.Application do
  @moduledoc false
  use Application

  def start(_type, _args) do
    children = [
      {Task.Supervisor, name: :http_fetch_task_supervisor},
      {Registry, keys: :unique, name: HTTP.AbortController}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: HTTPFetch.Application)
  end
end

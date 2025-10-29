defmodule HTTPFetch.Application do
  @moduledoc """
  OTP application for HTTP fetch library.

  This application supervises the core infrastructure required for HTTP operations:

  - **Task.Supervisor** (`:http_fetch_task_supervisor`) - Supervises all async HTTP request tasks
  - **Registry** (`HTTP.AbortController`) - Tracks AbortController agents for request cancellation

  The application starts automatically when the `:http_fetch` application is loaded.
  No manual configuration is required.
  """
  use Application

  def start(_type, _args) do
    children = [
      {Task.Supervisor, name: :http_fetch_task_supervisor},
      {Registry, keys: :unique, name: HTTP.AbortController}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: HTTPFetch.Application)
  end
end

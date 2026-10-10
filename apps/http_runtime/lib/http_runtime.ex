defmodule HTTPRuntime.Application do
  @moduledoc "Supervises the shared HTTP/2 runtime once for all protocol clients."
  use Application

  def start(_type, _args) do
    children = [
      {Task.Supervisor, name: :http_runtime_task_supervisor, max_children: 2_048},
      {DynamicSupervisor,
       name: :http_managed_transport_supervisor, strategy: :one_for_one, max_children: 2_048},
      {HTTP.HTTP1.Pool, []},
      {HTTP.HTTP2.ConnectionSupervisor, name: :http_fetch_http2_connection_supervisor},
      {HTTP.HTTP2.Pool, name: :http_fetch_http2_pool},
      {HTTP.HTTP3.ConnectionSupervisor, name: :http_fetch_http3_connection_supervisor},
      {HTTP.HTTP3.Pool, name: :http_fetch_http3_pool}
    ]

    Supervisor.start_link(children, strategy: :one_for_all, name: HTTPRuntime.Application)
  end
end

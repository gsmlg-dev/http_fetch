defmodule TelemetryHelpers do
  @moduledoc false

  @events [
    [:hell, :listener, :start],
    [:hell, :listener, :stop],
    [:hell, :acceptor, :start],
    [:hell, :acceptor, :stop],
    [:hell, :acceptor, :spawn_error],
    [:hell, :acceptor, :econnaborted],
    [:hell, :acceptor, :accept_error],
    [:hell, :acceptor, :emfile],
    [:hell, :connection, :start],
    [:hell, :connection, :stop],
    [:hell, :connection, :exception],
    [:hell, :connection, :ready],
    [:hell, :connection, :async_recv],
    [:hell, :connection, :recv],
    [:hell, :connection, :recv_error],
    [:hell, :connection, :send],
    [:hell, :connection, :send_error],
    [:hell, :connection, :sendfile],
    [:hell, :connection, :sendfile_error],
    [:hell, :connection, :socket_shutdown]
  ]

  def attach_all_events(handler) do
    ref = make_ref()
    _ = :telemetry.attach_many(ref, @events, &__MODULE__.handle_event/4, {self(), handler})
    fn -> :telemetry.detach(ref) end
  end

  def handle_event(event, measurements, %{handler: handler} = metadata, {pid, handler}),
    do: send(pid, {:telemetry, event, measurements, metadata})

  def handle_event(_event, _measurements, _metadata, {_pid, _handler}), do: :ok
end

ExUnit.start(exclude: [:integration, :e2e])
Application.ensure_all_started(:http_event_source)

defmodule HTTP.EventSource.TestStop do
  @moduledoc false

  # Stops a test-owned process; it may be linked to the exiting test process
  # and already shutting down when on_exit runs, which is fine.
  def quietly(pid) do
    if Process.alive?(pid), do: GenServer.stop(pid)
    :ok
  catch
    :exit, _reason -> :ok
  end
end

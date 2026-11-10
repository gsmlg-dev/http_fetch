ExUnit.start(exclude: [:integration, :e2e])
# Positive message waits need room on loaded CI runners; refutes keep their default.
ExUnit.configure(assert_receive_timeout: 1_000)

defmodule HTTP.Runtime.TestStop do
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

defmodule HTTP.Pool.Telemetry do
  @moduledoc false

  # Keep the established event and global opt-outs after extracting the emitter.
  def http2_pool(event, outcome, measurements) do
    if Application.get_env(:http_pool, :telemetry, true) != false and
         Application.get_env(:http_runtime, :telemetry, true) != false and
         Application.get_env(:http_fetch, :telemetry, true) != false do
      :telemetry.execute([:http_fetch, :http2, :pool], measurements, %{
        event: event,
        outcome: outcome
      })
    else
      :ok
    end
  end
end

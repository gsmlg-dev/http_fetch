defmodule HTTP.Runtime.Telemetry do
  @moduledoc """
  Shared HTTP/2 runtime telemetry emission.

  The established `[:http_fetch, :http2, ...]` event prefixes are retained for
  compatibility. Emission does not require the Fetch application to be started.
  """

  @doc false
  def http2_connection(event, lifecycle, measurements) do
    :telemetry.execute([:http_fetch, :http2, :connection], measurements, %{
      event: event,
      lifecycle: lifecycle
    })
  end

  @doc false
  def http2_pool(event, outcome, measurements) do
    :telemetry.execute([:http_fetch, :http2, :pool], measurements, %{
      event: event,
      outcome: outcome
    })
  end

  @doc false
  def http2_runtime(event, outcome, measurements) do
    :telemetry.execute([:http_fetch, :http2, :runtime], measurements, %{
      event: event,
      outcome: outcome
    })
  end
end

defmodule HTTP.Runtime.TelemetryTest do
  use ExUnit.Case, async: true

  alias HTTP.Runtime.Telemetry

  def handle_event(name, measurements, metadata, parent),
    do: send(parent, {:runtime_telemetry, self(), name, measurements, metadata})

  setup do
    handler = "shared-http2-runtime-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach_many(
        handler,
        [
          [:http_fetch, :http2, :connection],
          [:http_fetch, :http2, :pool],
          [:http_fetch, :http2, :runtime]
        ],
        &__MODULE__.handle_event/4,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler) end)
    :ok
  end

  test "shared connection emission retains the established event contract" do
    caller = self()
    assert :ok = Telemetry.http2_connection(:opened, :ready, %{active_streams: 1})

    assert_receive {:runtime_telemetry, ^caller, [:http_fetch, :http2, :connection],
                    %{active_streams: 1}, %{event: :opened, lifecycle: :ready}}
  end

  test "shared pool emission retains the established event contract" do
    caller = self()
    assert :ok = Telemetry.http2_pool(:release, :ok, %{reservations: 0})

    assert_receive {:runtime_telemetry, ^caller, [:http_fetch, :http2, :pool], %{reservations: 0},
                    %{event: :release, outcome: :ok}}
  end

  test "shared runtime emission retains numeric peer error measurements" do
    caller = self()
    assert :ok = Telemetry.http2_runtime(:peer_reset, :received, %{error_code: 123})

    assert_receive {:runtime_telemetry, ^caller, [:http_fetch, :http2, :runtime],
                    %{error_code: 123}, %{event: :peer_reset, outcome: :received}}
  end
end

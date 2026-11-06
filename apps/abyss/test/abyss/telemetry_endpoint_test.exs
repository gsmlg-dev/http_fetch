defmodule Abyss.TelemetryEndpointTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Telemetry

  setup do
    Telemetry.reset_metrics()
    on_exit(fn -> Telemetry.reset_metrics() end)
    :ok
  end

  test "same handler endpoints have independent counters and a legacy aggregate" do
    first = make_ref()
    second = make_ref()
    Telemetry.register_scope(first, SharedHandler)
    Telemetry.register_scope(second, SharedHandler)
    Telemetry.track_connection_accepted(first)
    Telemetry.track_connection_accepted(second)
    Telemetry.track_connection_closed(first)
    Telemetry.track_send_result(first, :ok, 4)
    Telemetry.track_send_result(second, {:error, :closed}, 8)
    assert Telemetry.get_metrics(first).connections_active == 0
    assert Telemetry.get_metrics(second).connections_active == 1
    assert Telemetry.get_metrics(first).responses_total == 1
    assert Telemetry.get_metrics(second).responses_total == 0
    assert Telemetry.get_metrics(second).send_errors_total == 1
    assert Telemetry.get_metrics(SharedHandler).connections_total == 2
    assert Telemetry.get_metrics().connections_total == 2
  end

  test "endpoint send attribution works from arbitrary callers and cleanup removes socket rows" do
    scope = make_ref()
    socket = make_ref()
    Telemetry.register_scope(scope, SharedHandler)
    Telemetry.register_socket(scope, socket)
    assert Telemetry.socket_scope(socket) == scope
    Telemetry.track_datagram_received(scope, 0)
    Telemetry.track_datagram_dropped(scope, :capacity, 0)
    Telemetry.track_work_finished(scope, :killed)
    metrics = Telemetry.get_metrics(scope)
    assert metrics.datagrams_received == 1
    assert metrics.datagrams_dropped == 1
    assert metrics.work_failed == 1
    assert metrics.bytes_received == 0
    Telemetry.clear_scope(scope)
    assert Telemetry.socket_scope(socket) == :unscoped
    assert Telemetry.get_metrics(scope).datagrams_received == 0
    assert Telemetry.get_metrics(SharedHandler).datagrams_received == 0
  end

  test "work completion is independent of sends and inactive rates expire" do
    scope = make_ref()
    Telemetry.track_connection_accepted(scope)
    Telemetry.track_connection_closed(scope)
    Telemetry.track_work_finished(scope, {:shutdown, :local_closed})
    metrics = Telemetry.get_metrics(scope)
    assert metrics.work_completed == 1
    assert metrics.responses_total == 0
    table = :abyss_telemetry_metrics

    :ets.insert(
      table,
      {{scope, :accept_rate_window_start}, System.monotonic_time(:millisecond) - 1001}
    )

    assert Telemetry.get_metrics(scope).accepts_per_second == 0
  end
end

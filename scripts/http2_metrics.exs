# Bounded aggregate evidence; never retain per-request identifiers or bodies.
defmodule HTTP2GateMetrics do
  @measurements ~w(duration queue_wait_us reservations waiters connecting connections active_streams protocol_streams error_code duration_us)a
  @bounds [0, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000]

  def start do
    table = :ets.new(__MODULE__, [:public, :set, write_concurrency: true])

    events =
      [[:http_fetch, :request, :stop], [:http_fetch, :request, :exception]] ++
        for kind <- [:pool, :connection, :runtime], do: [:http_fetch, :http2, kind]

    :ok = :telemetry.attach_many({__MODULE__, table}, events, &__MODULE__.record/4, table)
    table
  end

  def record(event, measurements, metadata, table) do
    outcome = Map.get(metadata, :outcome, Map.get(metadata, :lifecycle, :observed))
    action = Map.get(metadata, :event, :observed)
    protocol = Map.get(metadata, :http_version, :unspecified)
    label = {Enum.join(event, "."), action, outcome, protocol}
    :ets.update_counter(table, {:events, label}, {2, 1}, {{:events, label}, 0})

    for name <- @measurements, value = Map.get(measurements, name), is_integer(value) do
      bound = Enum.find(@bounds, :above_10_000_000, &(value <= &1))
      key = {label, name, bound}
      :ets.update_counter(table, key, [{2, 1}, {3, value}], {key, 0, 0})
    end
  end

  def snapshot(table) do
    records =
      for {{label, measurement, bound}, count, total} <- :ets.tab2list(table) do
        {event, action, outcome, protocol} = label

        %{
          event: event,
          action: action,
          outcome: outcome,
          protocol: protocol,
          measurement: measurement,
          upper_bound: bound,
          count: count,
          total: total
        }
      end

    events =
      for {{:events, {event, action, outcome, protocol}}, count} <- :ets.tab2list(table),
          do: %{event: event, action: action, outcome: outcome, protocol: protocol, count: count}

    %{
      kind: "telemetry_aggregates",
      units: "duration, duration_us and queue_wait_us are microseconds",
      events: events,
      buckets: records
    }
  end
end

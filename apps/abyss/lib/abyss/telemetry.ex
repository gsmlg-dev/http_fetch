defmodule Abyss.Telemetry do
  @moduledoc """
  Telemetry spans and metrics emitted by Abyss.

  ## Telemetry Metrics

  Abyss tracks counters per logical endpoint, keyed by its server pid. Handler
  module queries aggregate registered endpoints for legacy callers. Runtime
  socket generations share the logical endpoint scope; closing an endpoint
  removes its socket registrations and counter rows. Raw socket operations
  bypass the supported transport send instrumentation. Supported GenUDP and
  native sends record each actual local socket outcome once, independently of
  connection-span sampling. Success increments `responses_total` and payload
  `bytes_sent`; empty datagrams count as one success and zero bytes. Definite
  socket-send failures increment `send_errors_total`. Validation/admission
  rejection, waits and repeated receipt reads do not count as sends. Local
  completion is not evidence of peer delivery.

  `datagrams_dropped` and `bytes_dropped` count definitive network-input
  rejection, with observed payload bytes. Rejected managed events use fixed
  `timer_events_rejected` and `send_outcome_events_rejected` counters instead.
  Public endpoint drop counters retain the current generation through drain;
  telemetry retains the logical-server lifetime across generations. Callback
  failure, send failure, teardown discard and unknown kernel loss are separate.

  - `connections_active`: Number of currently active connections
  - `connections_total`: Total number of connections since server start
  - `accepts_total`: Total number of accepted connections
  - `responses_total`: Total number of responses sent
  - `accepts_per_second`: Current accepts per second rate
  - `responses_per_second`: Current responses per second rate

  ### Using Metrics

  ```elixir
  # Aggregate metrics across all Abyss server instances in this node
  Abyss.Telemetry.get_metrics()
  # => %{connections_active: 15, connections_total: 1250, ...}

  # Metrics for a single server instance, identified by handler module
  Abyss.Telemetry.get_metrics(MyApp.DnsHandler)

  # Reset all metrics
  Abyss.Telemetry.reset_metrics()
  ```

  ## Telemetry Spans

  ### `[:abyss, :listener, *]`

  Represents an Abyss listener bound to a port. Started by
  `[:abyss, :listener, :start]` and ended by `[:abyss, :listener, :stop]`
  (measurements: `monotonic_time`, and `duration` on stop; metadata:
  `telemetry_span_context`, `listener_id`, `handler`, `local_address`,
  `local_port`, `broadcast`, `transport_options`).

  Events emitted within this span:

  - `[:abyss, :listener, :ready]` - the listener began accepting packets
  - `[:abyss, :listener, :waiting]` - the listener is blocked waiting to
    receive (passive mode only)
  - `[:abyss, :listener, :receiving]` - a packet was received (passive mode
    only)
  - `[:abyss, :listener, :packet_too_large]` - a packet exceeding
    `max_packet_size` was rejected (measurements: `remote_address`,
    `remote_port`, `packet_size`, `max_size`)
  - `[:abyss, :listener, :recv_error]` - receiving failed (measurements:
    `reason`)

  ### `[:abyss, :connection, *]`

  Represents the handling of a single packet/connection. Started by
  `[:abyss, :connection, :start]` and ended by
  `[:abyss, :connection, :stop]` (metadata includes
  `parent_telemetry_span_context` referencing the listener span,
  `remote_address`, `remote_port`, and `accept_start_time`).

  Events emitted within this span:

  - `[:abyss, :connection, :ready]` - the handler process received the packet

  Connection spans are sampled according to the
  `connection_telemetry_sample_rate` server option (default `0.05`);
  unsampled spans emit no events. Metrics tracking is not affected by
  sampling.

  ## Other Events

  - `[:abyss, :datagram, :send]` - actual instrumented local send result
    (measurements: payload `bytes`; metadata: `server_id`, `result`, `socket`).
  - `[:abyss, :datagram, :dropped]` - definitive network-input rejection
    (measurements: observed payload `bytes`; metadata: `server_id`, `reason`).
  - `[:abyss, :datagram, :event_rejected]` - rejected timer/send-outcome event
    (measurements: serialized event `bytes`; metadata: `server_id`, `event_type`,
    `reason`).

  - `[:abyss, :metrics, :response_time]` - emitted for every tracked
    response (measurements: `response_time` in ms; metadata: `handler`)
  - `[:abyss, :connection, :limit_exceeded]` - connection retries exhausted
    while the connection supervisor was at capacity
  - `[:abyss, :handler, :memory_warning]` - a handler process exceeded the
    `handler_memory_warning_threshold`
  - `[:abyss, :listener_pool, :scale_up]` / `[:abyss, :listener_pool,
    :scale_down]` - emitted by `Abyss.ListenerPoolScaler`
  - `[:abyss, :client, :send | :send_recv | :subscribe, :start | :stop |
    :exception]` - emitted by `Abyss.Client` operations
  """

  @enforce_keys [:span_name, :telemetry_span_context, :start_time, :start_metadata]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          span_name: span_name(),
          telemetry_span_context: reference(),
          start_time: integer(),
          start_metadata: metadata()
        }

  @type span_name :: :listener | :connection
  @type metadata :: :telemetry.event_metadata()

  @typedoc "Metrics scope - a logical server pid, legacy handler module, or :unscoped"
  @type scope :: term()

  @type metrics :: %{
          required(:accepts_per_second) => integer(),
          required(:responses_per_second) => integer(),
          optional(atom()) => term()
        }

  @typedoc false
  @type measurements :: :telemetry.event_measurements()

  @typedoc false
  @type event_name :: atom()

  @typedoc false
  @type untimed_event_name :: :stop | :waiting | :receiving

  @app_name :abyss

  # Default sampling rates for different span types.
  # Matches the ServerConfig connection_telemetry_sample_rate default.
  @default_connection_sample_rate 0.05
  # 100% sampling for listeners (they're few)
  @default_listener_sample_rate 1.0

  # Counter rows use {{scope, counter_name}, value}; registry rows have
  # distinct three-part keys so they cannot contribute to counter aggregation.
  @metrics_table :abyss_telemetry_metrics

  @doc """
  Initialize telemetry metrics tracking
  """
  @spec init_metrics() :: :ok
  def init_metrics do
    case :ets.whereis(@metrics_table) do
      :undefined ->
        # Creation is routed through Abyss.TableOwner so the table is owned
        # by a long-lived process regardless of which process first needs it.
        Abyss.TableOwner.ensure_table(@metrics_table, [
          :set,
          :public,
          :named_table,
          {:read_concurrency, true},
          {:write_concurrency, true}
        ])

      _ ->
        :ok
    end

    :ok
  end

  # Helper function to get ETS table
  defp get_metrics_table do
    case :ets.whereis(@metrics_table) do
      :undefined ->
        init_metrics()
        :ets.whereis(@metrics_table)

      table_id ->
        table_id
    end
  end

  @doc false
  def register_scope(scope, handler) do
    :ets.insert(get_metrics_table(), {{:scope_handler, scope, handler}, true})
    Abyss.TableOwner.track_scope(scope)
    :ok
  end

  @doc false
  def register_socket(scope, socket) do
    :ets.insert(get_metrics_table(), {{:socket_scope, socket, scope}, true})
    :ok
  end

  @doc false
  def unregister_socket(socket) do
    :ets.match_delete(get_metrics_table(), {{:socket_scope, socket, :_}, :_})
    :ok
  end

  @doc false
  def socket_scope(socket) do
    case :ets.match_object(get_metrics_table(), {{:socket_scope, socket, :_}, :_}) do
      [{{:socket_scope, ^socket, scope}, _}] -> scope
      _ -> :unscoped
    end
  end

  @doc false
  def clear_scope(scope) do
    table = get_metrics_table()
    :ets.match_delete(table, {{scope, :_}, :_})
    :ets.match_delete(table, {{:scope_handler, scope, :_}, :_})
    :ets.match_delete(table, {{:socket_scope, :_, scope}, :_})
    :ok
  end

  @doc false
  def track_datagram_received(scope, bytes) do
    table = get_metrics_table()
    _ = bump(table, scope, :datagrams_received)
    _ = add(table, scope, :bytes_received, bytes)
    :ok
  end

  @doc false
  def track_datagram_dropped(scope, reason, bytes) do
    table = get_metrics_table()
    _ = bump(table, scope, :datagrams_dropped)
    _ = add(table, scope, :bytes_dropped, bytes)

    :telemetry.execute([:abyss, :datagram, :dropped], %{bytes: bytes}, %{
      server_id: scope,
      reason: reason
    })

    :ok
  end

  @doc false
  def track_event_rejected(scope, type, reason, bytes) when type in [:timer, :send_outcomes] do
    counter =
      case type do
        :timer -> :timer_events_rejected
        :send_outcomes -> :send_outcome_events_rejected
      end

    _ = bump(get_metrics_table(), scope, counter)

    :telemetry.execute([:abyss, :datagram, :event_rejected], %{bytes: bytes}, %{
      server_id: scope,
      event_type: type,
      reason: reason
    })

    :ok
  end

  @doc false
  def track_work_finished(scope, reason) do
    completed? =
      reason in [:normal, :shutdown, {:shutdown, :local_closed}, {:shutdown, :broadcast}]

    _ = bump(get_metrics_table(), scope, if(completed?, do: :work_completed, else: :work_failed))
    :ok
  end

  @doc false
  def track_send_result(scope, result, bytes, metadata \\ %{}) do
    table = get_metrics_table()
    metadata = Map.put(metadata, :server_id, scope)

    _ =
      case result do
        :ok ->
          _ = bump(table, scope, :responses_total)
          _ = add(table, scope, :bytes_sent, bytes)
          update_rate_window(table, scope, :response_rate_window_start, :responses_in_window)

        {:error, _reason} ->
          _ = bump(table, scope, :send_errors_total)
      end

    :telemetry.execute(
      [:abyss, :datagram, :send],
      %{bytes: bytes},
      Map.put(metadata, :result, result)
    )

    :ok
  end

  @doc """
  Track a new connection being accepted.

  `scope` identifies the server instance (its handler module).
  """
  @spec track_connection_accepted(scope()) :: :ok
  def track_connection_accepted(scope \\ :unscoped) do
    table = get_metrics_table()

    _ = bump(table, scope, :accepts_total)
    _ = bump(table, scope, :connections_active)
    _ = bump(table, scope, :connections_total)
    update_rate_window(table, scope, :accept_rate_window_start, :accepts_in_window)

    :ok
  end

  @doc """
  Track a connection being closed.

  `scope` identifies the server instance (its handler module).
  """
  @spec track_connection_closed(scope()) :: :ok
  def track_connection_closed(scope \\ :unscoped) do
    table = get_metrics_table()

    # Atomically decrement, but never below zero
    _ =
      :ets.update_counter(
        table,
        {scope, :connections_active},
        {2, -1, 0, 0},
        {{scope, :connections_active}, 0}
      )

    :ok
  end

  @doc """
  Track a response being sent.

  `metadata` is included in the emitted `[:abyss, :metrics, :response_time]`
  event; Abyss handlers pass `%{handler: handler_module}`, which is also used
  as the metrics scope.
  """
  @spec track_response_sent(response_time :: integer(), metadata()) :: :ok
  def track_response_sent(response_time, metadata \\ %{}) when is_integer(response_time) do
    table = get_metrics_table()

    scope =
      Map.get(
        metadata,
        :server_id,
        Map.get(metadata, :server_pid, Map.get(metadata, :handler, :unscoped))
      )

    _ = bump(table, scope, :responses_total)
    update_rate_window(table, scope, :response_rate_window_start, :responses_in_window)

    # Emit response time event
    :telemetry.execute(
      [:abyss, :metrics, :response_time],
      %{response_time: response_time},
      metadata
    )

    :ok
  end

  @doc """
  Get telemetry metrics aggregated across all server instances.
  """
  @spec get_metrics() :: metrics()
  def get_metrics do
    table = get_metrics_table()
    scopes = list_scopes(table)

    metrics_for_scopes(table, scopes)
  end

  @doc """
  Returns counters for an endpoint scope. A handler module query aggregates
  endpoints registered with that module and any legacy directly keyed rows.
  """
  @spec get_metrics(scope()) :: metrics()
  def get_metrics(scope) do
    table = get_metrics_table()
    registered = :ets.match_object(table, {{:scope_handler, :_, scope}, :_})
    scopes = Enum.map(registered, fn {{:scope_handler, endpoint, _}, _} -> endpoint end)
    metrics_for_scopes(table, Enum.uniq([scope | scopes]))
  end

  defp metrics_for_scopes(table, scopes) do
    counters = [
      :connections_active,
      :connections_total,
      :accepts_total,
      :responses_total,
      :datagrams_received,
      :datagrams_dropped,
      :timer_events_rejected,
      :send_outcome_events_rejected,
      :bytes_received,
      :bytes_dropped,
      :bytes_sent,
      :send_errors_total,
      :work_completed,
      :work_failed
    ]

    metrics =
      Map.new(counters, fn key ->
        {key, Enum.reduce(scopes, 0, &(counter(table, &1, key) + &2))}
      end)

    Map.merge(metrics, %{
      accepts_per_second:
        Enum.reduce(
          scopes,
          0,
          &(get_rate(table, &1, :accept_rate_window_start, :accepts_in_window) + &2)
        ),
      responses_per_second:
        Enum.reduce(
          scopes,
          0,
          &(get_rate(table, &1, :response_rate_window_start, :responses_in_window) + &2)
        )
    })
  end

  @doc """
  Reset telemetry metrics
  """
  @spec reset_metrics() :: :ok
  def reset_metrics do
    case :ets.whereis(@metrics_table) do
      :undefined ->
        init_metrics()

      _table_id ->
        :ets.delete_all_objects(@metrics_table)
    end

    :ok
  end

  # Private metrics functions

  defp bump(table, scope, counter), do: add(table, scope, counter, 1)

  defp add(table, scope, counter, amount) do
    :ets.update_counter(table, {scope, counter}, amount, {{scope, counter}, 0})
  end

  defp counter(table, scope, counter) do
    case :ets.lookup(table, {scope, counter}) do
      [{_key, value}] -> value
      [] -> 0
    end
  end

  defp list_scopes(table) do
    table
    |> :ets.select([{{{:"$1", :_}, :_}, [], [:"$1"]}])
    |> Enum.uniq()
  end

  defp update_rate_window(table, scope, window_key, counter_key) do
    current_time = System.monotonic_time(:millisecond)
    _ = bump(table, scope, counter_key)

    case :ets.lookup(table, {scope, window_key}) do
      [{_key, window_start}] ->
        if current_time - window_start >= 1000 do
          :ets.insert(table, {{scope, window_key}, current_time})
          :ets.insert(table, {{scope, counter_key}, 1})
        end

      [] ->
        :ets.insert(table, {{scope, window_key}, current_time})
    end

    :ok
  end

  defp get_rate(table, scope, window_key, counter_key) do
    current_time = System.monotonic_time(:millisecond)

    case :ets.lookup(table, {scope, window_key}) do
      [{_key, window_start}] ->
        time_diff = current_time - window_start

        if time_diff > 0 and time_diff < 1000 do
          round(counter(table, scope, counter_key) * 1000 / time_diff)
        else
          0
        end

      [] ->
        0
    end
  end

  @doc false
  @spec start_span(span_name(), measurements(), metadata()) :: t()
  def start_span(span_name, measurements, metadata) do
    start_span_with_sampling(span_name, measurements, metadata)
  end

  @doc false
  @spec start_span_with_sampling(span_name(), measurements(), metadata(), keyword()) :: t()
  def start_span_with_sampling(span_name, measurements, metadata, opts \\ []) do
    sample_rate = get_sample_rate(span_name, opts)

    if should_sample?(sample_rate) do
      measurements = Map.put_new_lazy(measurements, :monotonic_time, &monotonic_time/0)
      telemetry_span_context = make_ref()
      metadata = Map.put(metadata, :telemetry_span_context, telemetry_span_context)
      metadata = Map.put(metadata, :sampled, true)
      _ = event([span_name, :start], measurements, metadata)

      %__MODULE__{
        span_name: span_name,
        telemetry_span_context: telemetry_span_context,
        start_time: measurements[:monotonic_time],
        start_metadata: metadata
      }
    else
      # Create unsampled span
      measurements = Map.put_new_lazy(measurements, :monotonic_time, &monotonic_time/0)
      telemetry_span_context = make_ref()
      metadata = Map.put(metadata, :telemetry_span_context, telemetry_span_context)
      metadata = Map.put(metadata, :sampled, false)

      %__MODULE__{
        span_name: span_name,
        telemetry_span_context: telemetry_span_context,
        start_time: measurements[:monotonic_time],
        start_metadata: metadata
      }
    end
  end

  @doc false
  @spec start_child_span(t(), span_name(), measurements(), metadata()) :: t()
  def start_child_span(parent_span, span_name, measurements \\ %{}, metadata \\ %{}) do
    metadata =
      parent_span.start_metadata
      |> Map.take([:handler, :server_pid, :server_id, :endpoint_id, :generation])
      |> Map.merge(metadata)
      |> Map.put(:parent_telemetry_span_context, parent_span.telemetry_span_context)

    start_span(span_name, measurements, metadata)
  end

  @doc false
  @spec start_child_span_with_sampling(t(), span_name(), measurements(), metadata(), keyword()) ::
          t()
  def start_child_span_with_sampling(
        parent_span,
        span_name,
        measurements \\ %{},
        metadata \\ %{},
        opts \\ []
      ) do
    metadata =
      parent_span.start_metadata
      |> Map.take([:handler, :server_pid, :server_id, :endpoint_id, :generation])
      |> Map.merge(metadata)
      |> Map.put(:parent_telemetry_span_context, parent_span.telemetry_span_context)

    start_span_with_sampling(span_name, measurements, metadata, opts)
  end

  # Private helper functions

  defp get_sample_rate(:connection, opts) do
    Keyword.get(opts, :sample_rate, @default_connection_sample_rate)
  end

  defp get_sample_rate(:listener, _opts) do
    @default_listener_sample_rate
  end

  defp get_sample_rate(_span_name, opts) do
    # Default to no sampling for unknown spans
    Keyword.get(opts, :sample_rate, 1.0)
  end

  defp should_sample?(sample_rate) when sample_rate >= 1.0, do: true
  defp should_sample?(sample_rate) when sample_rate <= 0.0, do: false
  defp should_sample?(sample_rate), do: :rand.uniform() <= sample_rate

  @doc false
  @spec stop_span(t(), measurements(), metadata()) :: :ok
  def stop_span(span, measurements \\ %{}, metadata \\ %{}) do
    # Only emit events if this span was sampled
    if span.start_metadata[:sampled] != false do
      measurements = Map.put_new_lazy(measurements, :monotonic_time, &monotonic_time/0)

      measurements =
        Map.put(measurements, :duration, measurements[:monotonic_time] - span.start_time)

      metadata = Map.merge(span.start_metadata, metadata)

      untimed_span_event(span, :stop, measurements, metadata)
    else
      :ok
    end
  end

  @doc false
  @spec span_event(t(), event_name(), measurements(), metadata()) :: :ok
  def span_event(span, name, measurements \\ %{}, metadata \\ %{}) do
    # Only emit events if this span was sampled
    if span.start_metadata[:sampled] != false do
      measurements = Map.put_new_lazy(measurements, :monotonic_time, &monotonic_time/0)
      untimed_span_event(span, name, measurements, metadata)
    else
      :ok
    end
  end

  @doc false
  @spec untimed_span_event(t(), event_name() | untimed_event_name(), measurements(), metadata()) ::
          :ok
  def untimed_span_event(span, name, measurements \\ %{}, metadata \\ %{}) do
    # Only emit events if this span was sampled
    if span.start_metadata[:sampled] != false do
      metadata =
        span.start_metadata
        |> Map.merge(metadata)
        |> Map.put(:telemetry_span_context, span.telemetry_span_context)
        |> Map.put_new(:handler, span.start_metadata[:handler] || :unknown)

      event([span.span_name, name], measurements, metadata)
    else
      :ok
    end
  end

  @spec monotonic_time() :: integer
  defdelegate monotonic_time, to: System

  defp event(suffix, measurements, metadata) do
    :telemetry.execute([@app_name | suffix], measurements, metadata)
  end
end

defmodule Abyss.ServerConfig do
  @moduledoc """
  Encapsulates the configuration of a Abyss server instance

  This is used internally by `Abyss.Handler`. Datagram `runtime_options` have
  finite bounds; `idle_timeout` controls only keyed worker eviction. Endpoint
  application state persists through ordinary idleness within its generation.
  """

  require Logger

  @typedoc "A set of configuration parameters for a Abyss server instance"
  @type t :: %__MODULE__{
          port: :inet.port_number(),
          transport_module: module(),
          transport_options: Abyss.transport_options(),
          handler_module: module() | nil,
          datagram_options: map(),
          handler_options: term(),
          genserver_options: GenServer.options(),
          supervisor_options: [Supervisor.option()],
          broadcast: boolean(),
          num_listeners: pos_integer(),
          num_connections: non_neg_integer() | :infinity,
          max_connections_retry_count: non_neg_integer(),
          max_connections_retry_wait: timeout(),
          read_timeout: timeout(),
          shutdown_timeout: timeout(),
          udp_buffer_size: pos_integer(),
          dynamic_listeners: boolean(),
          min_listeners: pos_integer(),
          max_listeners: pos_integer(),
          listener_scale_threshold: float(),
          silent_terminate_on_error: boolean(),
          max_packet_size: pos_integer(),
          connection_telemetry_sample_rate: float(),
          handler_memory_check_interval: pos_integer(),
          handler_memory_warning_threshold: pos_integer(),
          handler_memory_hard_limit: pos_integer(),
          datagram_dispatcher: nil | module() | {module(), keyword()},
          dispatcher_options: keyword(),
          dispatcher_max_queue: pos_integer(),
          dispatcher_max_queue_bytes: pos_integer(),
          admission_start_timeout: pos_integer()
        }

  @connections_per_listener 100
  @processing_time_baseline_ms 100
  @min_processing_factor 0.5

  @datagram_defaults %{
    datagram_handler: nil,
    execution: :per_datagram,
    route_key: nil,
    io_backend: :gen_udp,
    runtime_options: [],
    required_capabilities: [],
    required_metadata: []
  }

  defstruct port: 4000,
            transport_module: Abyss.Transport.UDP,
            transport_options: [],
            handler_module: nil,
            datagram_options: @datagram_defaults,
            handler_options: [],
            genserver_options: [],
            supervisor_options: [],
            broadcast: false,
            num_listeners: 100,
            num_connections: 16_384,
            max_connections_retry_count: 5,
            max_connections_retry_wait: 1000,
            read_timeout: 60_000,
            shutdown_timeout: 15_000,
            udp_buffer_size: 64 * 1024,
            dynamic_listeners: false,
            min_listeners: 10,
            max_listeners: 1000,
            listener_scale_threshold: 0.8,
            silent_terminate_on_error: false,
            max_packet_size: 8192,
            connection_telemetry_sample_rate: 0.05,
            handler_memory_check_interval: 10_000,
            handler_memory_warning_threshold: 100,
            handler_memory_hard_limit: 150,
            datagram_dispatcher: nil,
            dispatcher_options: [],
            dispatcher_max_queue: 128,
            dispatcher_max_queue_bytes: 1_048_576,
            admission_start_timeout: 1000

  @spec new(Abyss.options()) :: t()
  def new(opts \\ []) do
    unless Keyword.keyword?(opts) do
      raise ArgumentError, "configuration must be a keyword list"
    end

    validate_handler_selection!(opts)

    # num_acceptors is deprecated but documented; map it to num_listeners
    # rather than crashing in struct!/2 (it is not a struct field).
    {num_acceptors, opts} = Keyword.pop(opts, :num_acceptors)

    opts =
      if num_acceptors do
        Logger.warning("Option :num_acceptors is deprecated. Use :num_listeners instead.")
        Keyword.put_new(opts, :num_listeners, num_acceptors)
      else
        opts
      end

    # Determine broadcast mode from transport module
    transport_module = Keyword.get(opts, :transport_module, Abyss.Transport.UDP)
    is_broadcast = transport_module == Abyss.Transport.UDP.Broadcast

    opts =
      if is_broadcast do
        Keyword.put(opts, :broadcast, true)
      else
        opts
      end

    opts =
      if Keyword.get(opts, :datagram_handler) do
        Keyword.put_new(opts, :num_listeners, 1)
      else
        opts
      end

    opts =
      if Keyword.get(opts, :io_backend, :gen_udp) == :socket_native do
        Keyword.put(opts, :transport_module, Abyss.Transport.UDP.Native)
      else
        opts
      end

    datagram_options =
      Map.new(@datagram_defaults, fn {key, default} -> {key, Keyword.get(opts, key, default)} end)

    legacy_options = Keyword.drop(opts, Map.keys(@datagram_defaults))
    config = struct!(__MODULE__, Keyword.put(legacy_options, :datagram_options, datagram_options))

    # Validate numeric ranges for new configuration options
    validate_config!(config)

    config
  end

  defp validate_handler_selection!(opts) do
    handler = Keyword.get(opts, :datagram_handler)
    dispatcher = Keyword.get(opts, :datagram_dispatcher)

    case {handler, dispatcher, Keyword.has_key?(opts, :handler_module)} do
      {nil, nil, false} ->
        raise ArgumentError, "No handler_module defined in server configuration"

      _ ->
        :ok
    end

    validate_legacy_handler!(opts)
    validate_datagram_handler!(handler)
    validate_handler_conflict!(handler, Keyword.get(opts, :handler_module), dispatcher)
  end

  defp validate_legacy_handler!(opts) do
    case Keyword.fetch(opts, :handler_module) do
      {:ok, module} when is_atom(module) -> :ok
      :error -> :ok
      _ -> raise ArgumentError, "handler_module must be a module"
    end
  end

  defp validate_datagram_handler!(nil), do: :ok

  defp validate_datagram_handler!(handler) do
    unless is_atom(handler) and Code.ensure_loaded?(handler) and
             function_exported?(handler, :init, 2) and
             function_exported?(handler, :handle_datagram, 2),
           do: raise(ArgumentError, "datagram_handler must export init/2 and handle_datagram/2")
  end

  defp validate_handler_conflict!(nil, _legacy, _dispatcher), do: :ok

  defp validate_handler_conflict!(_handler, legacy, dispatcher) do
    if legacy || dispatcher,
      do:
        raise(
          ArgumentError,
          "datagram_handler cannot be combined with handler_module or datagram_dispatcher"
        )
  end

  @runtime_defaults [
    max_queue: 128,
    max_queue_bytes: 1_048_576,
    max_keys: 128,
    max_key_bytes: 1024,
    max_key_queue: 32,
    max_key_queue_bytes: 262_144,
    max_timers: 128,
    max_actions: 32,
    max_action_bytes: 1_048_576,
    init_timeout: 1000,
    callback_timeout: 1000,
    route_timeout: 1000,
    terminate_timeout: 100,
    idle_timeout: 60_000,
    send_timeout: 100
  ]

  @doc "Finite bounds used by the datagram runtime, merged with endpoint options."
  def runtime_options(%__MODULE__{datagram_options: %{runtime_options: options}}),
    do: Keyword.merge(@runtime_defaults, options)

  defp validate_runtime!(config) do
    validate_backend!(config)
    validate_requirements!(config)

    unless config.datagram_options.execution in [:per_datagram, :endpoint, :keyed],
      do: raise(ArgumentError, "execution must be :per_datagram, :endpoint or :keyed")

    _ = validate_runtime_limits!(config.datagram_options.runtime_options)
    validate_datagram_topology!(config)
    if config.datagram_options.datagram_handler, do: validate_dispatcher_limits!(config)
  end

  defp validate_requirements!(config) do
    capabilities = [
      :destination,
      :interface_index,
      :local_address,
      :scoped_send,
      :source_control,
      :memberships,
      :strict_group_filter,
      :strict_interface_filter
    ]

    metadata = [:destination, :interface_index, :local_address, :hop_limit, :traffic_class]

    _ =
      for {name, values, allowed} <- [
            {:required_capabilities, config.datagram_options.required_capabilities, capabilities},
            {:required_metadata, config.datagram_options.required_metadata, metadata}
          ] do
        unless is_list(values) and Enum.all?(values, &(&1 in allowed)),
          do: raise(ArgumentError, "#{name} must contain supported requirement names")
      end

    if is_nil(config.datagram_options.datagram_handler) and
         (config.datagram_options.required_capabilities != [] or
            config.datagram_options.required_metadata != []),
       do: raise(ArgumentError, "metadata requirements need datagram_handler")
  end

  defp validate_backend!(config) do
    unless config.datagram_options.io_backend in [:gen_udp, :socket_native],
      do: raise(ArgumentError, "io_backend must be :gen_udp or :socket_native")

    if config.transport_module == Abyss.Transport.UDP.Native and
         config.datagram_options.io_backend != :socket_native,
       do: raise(ArgumentError, "native transport requires io_backend: :socket_native")

    validate_native_selection!(config)
  end

  defp validate_native_selection!(%{
         datagram_options: %{io_backend: :socket_native, datagram_handler: nil}
       }),
       do:
         raise(
           ArgumentError,
           "socket_native requires datagram_handler; legacy handlers and dispatchers are unsupported"
         )

  defp validate_native_selection!(%{datagram_options: %{io_backend: :socket_native}} = config) do
    if Enum.any?(config.transport_options, &match?({:inet_backend, _}, &1)),
      do: raise(ArgumentError, "inet_backend cannot be combined with socket_native")
  end

  defp validate_native_selection!(_config), do: :ok

  defp validate_runtime_limits!(options) do
    unless Keyword.keyword?(options),
      do: raise(ArgumentError, "runtime_options must be a keyword list")

    for {key, value} <- options do
      unless Keyword.has_key?(@runtime_defaults, key),
        do: raise(ArgumentError, "unknown runtime option #{inspect(key)}")

      unless is_integer(value) and value > 0,
        do: raise(ArgumentError, "runtime option #{key} must be a finite positive integer")
    end
  end

  defp validate_datagram_topology!(%{datagram_options: %{datagram_handler: nil}}), do: :ok

  defp validate_datagram_topology!(%{num_listeners: 1, dynamic_listeners: false} = config),
    do: validate_route_key!(config.datagram_options.execution, config.datagram_options.route_key)

  defp validate_datagram_topology!(_config),
    do: raise(ArgumentError, "datagram_handler requires one listener without dynamic scaling")

  defp validate_route_key!(:keyed, route_key) do
    unless valid_route_key?(route_key),
      do:
        raise(
          ArgumentError,
          "keyed execution requires an explicit route_key function or {module, function}"
        )
  end

  defp validate_route_key!(_execution, nil), do: :ok

  defp validate_route_key!(_execution, _route_key),
    do: raise(ArgumentError, "route_key is only supported with keyed execution")

  defp valid_route_key?(function) when is_function(function, 1), do: true
  defp valid_route_key?({module, function}) when is_atom(module) and is_atom(function), do: true
  defp valid_route_key?(_route_key), do: false

  # Private validation function
  defp validate_config!(config) do
    validate_runtime!(config)
    _ = validate_limits!(config)
    _ = validate_timeouts!(config)
    validate_socket_options!(config)
    validate_scaling!(config)
    validate_resources!(config)
    validate_dispatcher!(config)
    :ok
  end

  defp validate_limits!(config) do
    for {name, value} <- [
          num_listeners: config.num_listeners,
          num_connections: config.num_connections,
          max_packet_size: config.max_packet_size,
          udp_buffer_size: config.udp_buffer_size,
          admission_start_timeout: config.admission_start_timeout
        ] do
      unless is_integer(value) and value > 0,
        do: raise(ArgumentError, "#{name} must be a positive integer")
    end

    unless is_integer(config.port) and config.port in 0..65_535,
      do: raise(ArgumentError, "port must be between 0 and 65535")
  end

  defp validate_timeouts!(config) do
    for {name, value} <- [
          read_timeout: config.read_timeout,
          shutdown_timeout: config.shutdown_timeout
        ] do
      unless value == :infinity or (is_integer(value) and value >= 0),
        do: raise(ArgumentError, "#{name} must be a non-negative timeout or :infinity")
    end
  end

  defp validate_socket_options!(config) do
    for key <- [:broadcast, :dynamic_listeners, :silent_terminate_on_error] do
      unless is_boolean(Map.fetch!(config, key)),
        do: raise(ArgumentError, "#{key} must be boolean")
    end

    unless is_list(config.transport_options),
      do: raise(ArgumentError, "transport_options must be a list")

    for option <- config.transport_options do
      case option do
        {:active, value} when value not in [false, :once] ->
          raise ArgumentError, "host owns receive activation; active must be false or :once"

        :list ->
          raise ArgumentError, "host requires binary datagrams"

        {:mode, :list} ->
          raise ArgumentError, "host requires binary datagrams"

        _ ->
          :ok
      end
    end

    validate_dynamic_endpoint!(config)
  end

  defp validate_dynamic_endpoint!(config) do
    membership? = Enum.any?(config.transport_options, &match?({:add_membership, _}, &1))

    if config.dynamic_listeners and
         (config.broadcast or config.port == 0 or membership? or
            config.transport_module == Abyss.Transport.UDP.Multicast),
       do:
         raise(
           ArgumentError,
           "dynamic receive-socket scaling is incompatible with ephemeral, broadcast or multicast endpoints"
         )
  end

  defp validate_scaling!(config) do
    # Validate listener scaling configuration
    unless is_integer(config.min_listeners) and is_integer(config.max_listeners) and
             config.min_listeners > 0 and config.min_listeners <= config.max_listeners do
      raise ArgumentError,
            "min_listeners must be positive and <= max_listeners (got min: #{config.min_listeners}, max: #{config.max_listeners})"
    end

    unless is_number(config.listener_scale_threshold) and config.listener_scale_threshold > 0.0 and
             config.listener_scale_threshold <= 1.0 do
      raise ArgumentError,
            "listener_scale_threshold must be between 0.0 and 1.0 (got #{config.listener_scale_threshold})"
    end
  end

  defp validate_resources!(config) do
    # Validate telemetry sampling rate
    unless is_number(config.connection_telemetry_sample_rate) and
             config.connection_telemetry_sample_rate >= 0.0 and
             config.connection_telemetry_sample_rate <= 1.0 do
      raise ArgumentError,
            "connection_telemetry_sample_rate must be between 0.0 and 1.0 (got #{config.connection_telemetry_sample_rate})"
    end

    validate_memory!(config)
  end

  defp validate_memory!(config) do
    # Validate memory thresholds
    unless is_integer(config.handler_memory_check_interval) and
             config.handler_memory_check_interval > 0 do
      raise ArgumentError,
            "handler_memory_check_interval must be positive (got #{config.handler_memory_check_interval})"
    end

    unless is_number(config.handler_memory_warning_threshold) and
             is_number(config.handler_memory_hard_limit) and
             config.handler_memory_warning_threshold > 0 and
             config.handler_memory_warning_threshold < config.handler_memory_hard_limit do
      raise ArgumentError,
            "handler_memory_warning_threshold must be positive and < handler_memory_hard_limit (got warning: #{config.handler_memory_warning_threshold}, hard limit: #{config.handler_memory_hard_limit})"
    end

    :ok
  end

  defp validate_dispatcher!(%__MODULE__{datagram_dispatcher: nil}), do: :ok

  defp validate_dispatcher!(%__MODULE__{broadcast: true, datagram_dispatcher: dispatcher})
       when not is_nil(dispatcher),
       do: raise(ArgumentError, "datagram_dispatcher is only supported for unicast listeners")

  defp validate_dispatcher!(%__MODULE__{} = config) do
    dispatcher_module =
      case config.datagram_dispatcher do
        module when is_atom(module) -> module
        {module, opts} when is_atom(module) and is_list(opts) -> module
        _ -> nil
      end

    loaded? = not is_nil(dispatcher_module) and Code.ensure_loaded?(dispatcher_module)

    unless loaded? and function_exported?(dispatcher_module, :init, 2) and
             function_exported?(dispatcher_module, :handle_datagram, 4) do
      raise ArgumentError,
            "datagram_dispatcher must be a module exporting init/2 and handle_datagram/4"
    end

    validate_dispatcher_limits!(config)
  end

  defp validate_dispatcher_limits!(config) do
    unless Keyword.keyword?(config.dispatcher_options) do
      raise ArgumentError, "dispatcher_options must be a keyword list"
    end

    unless is_integer(config.dispatcher_max_queue) and config.dispatcher_max_queue > 0 do
      raise ArgumentError, "dispatcher_max_queue must be positive"
    end

    unless is_integer(config.dispatcher_max_queue_bytes) and config.dispatcher_max_queue_bytes > 0 do
      raise ArgumentError, "dispatcher_max_queue_bytes must be positive"
    end
  end

  @doc """
  Calculate optimal number of listeners based on current load and processing characteristics

  Uses a more granular scaling approach:
  - 1 listener per 100 connections (instead of 1000)
  - Adjusts for processing time with a lower bound of 0.5x
  - Ensures minimum of 1 listener

  ## Examples

      iex> Abyss.ServerConfig.calculate_optimal_listeners(50, 100.0)
      1

      iex> Abyss.ServerConfig.calculate_optimal_listeners(500, 100.0)
      5

      iex> Abyss.ServerConfig.calculate_optimal_listeners(500, 200.0)
      10
  """
  @spec calculate_optimal_listeners(pos_integer(), float()) :: pos_integer()
  def calculate_optimal_listeners(current_connections, avg_processing_time_ms) do
    # Start with at least 1 listener per @connections_per_listener connections
    base_listeners = max(div(current_connections, @connections_per_listener), 1)

    # Adjust for processing time (slower processing = more listeners needed)
    # Normalize to @processing_time_baseline_ms baseline
    processing_factor =
      max(avg_processing_time_ms / @processing_time_baseline_ms, @min_processing_factor)

    optimal = round(base_listeners * processing_factor)

    # Ensure reasonable bounds
    max(optimal, 1)
  end
end

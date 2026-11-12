defmodule Hell.ServerConfig do
  @moduledoc """
  Encapsulates the configuration of a Hell server instance

  This is used internally by `Hell.Handler`
  """

  @typedoc "A set of configuration parameters for a Hell server instance"
  @type t :: %__MODULE__{
          port: :inet.port_number(),
          transport_module: Hell.transport_module(),
          transport_options: Hell.transport_options(),
          handler_module: module(),
          handler_options: term(),
          genserver_options: GenServer.options(),
          supervisor_options: [Supervisor.option()],
          num_acceptors: pos_integer(),
          num_listen_sockets: pos_integer(),
          num_connections: non_neg_integer() | :infinity,
          max_connections_retry_count: non_neg_integer(),
          max_connections_retry_wait: timeout(),
          read_timeout: timeout(),
          handshake_timeout: timeout(),
          shutdown_timeout: timeout(),
          silent_terminate_on_error: boolean()
        }

  defstruct port: 4000,
            transport_module: Hell.Transports.TCP,
            transport_options: [],
            handler_module: nil,
            handler_options: [],
            genserver_options: [],
            supervisor_options: [],
            num_acceptors: 100,
            num_listen_sockets: 1,
            num_connections: 16_384,
            max_connections_retry_count: 5,
            max_connections_retry_wait: 1000,
            read_timeout: 60_000,
            handshake_timeout: 5_000,
            shutdown_timeout: 15_000,
            silent_terminate_on_error: false

  @spec new(Hell.options()) :: t()
  def new(opts \\ []) do
    validate_keys!(opts)
    config = struct!(__MODULE__, opts)
    validate_handler_module!(config)
    validate_num_sockets!(config)
    validate_reuseport_options!(config)
    config
  end

  defp validate_keys!(opts) do
    unless Keyword.keyword?(opts) do
      raise ArgumentError, "configuration must be a keyword list"
    end

    known = Map.keys(%__MODULE__{})

    case opts |> Keyword.keys() |> Enum.reject(&(&1 in known)) do
      [] -> :ok
      unknown -> raise ArgumentError, "unknown Hell option(s): #{inspect(Enum.uniq(unknown))}"
    end
  end

  defp validate_handler_module!(config) do
    if !config.handler_module do
      raise ArgumentError, "No handler_module defined in server configuration"
    end
  end

  defp validate_num_sockets!(config) do
    if config.num_listen_sockets > config.num_acceptors do
      raise ArgumentError,
            "num_listen_sockets (#{config.num_listen_sockets}) must be less than or equal to num_acceptors (#{config.num_acceptors})"
    end
  end

  @secret_keys [:password, :key, :sni_fun]

  @doc """
  Returns `transport_options` with secret-bearing TLS options redacted

  `password`, `key` and `sni_fun` values, the `key` and `password` of every
  `certs_keys` entry and the options of every `sni_hosts` entry are replaced by
  `:redacted`. Listener telemetry metadata and `inspect/2` of a server
  configuration use this form so that private key material never reaches
  telemetry handlers or crash reports.
  """
  @spec redact_transport_options(Hell.transport_options()) :: Hell.transport_options()
  def redact_transport_options(options) when is_list(options),
    do: Enum.map(options, &redact_option/1)

  def redact_transport_options(options), do: options

  defp redact_option({key, _value}) when key in @secret_keys, do: {key, :redacted}

  defp redact_option({:certs_keys, entries}) when is_list(entries),
    do: {:certs_keys, Enum.map(entries, &redact_certs_key/1)}

  defp redact_option({:sni_hosts, hosts}) when is_list(hosts),
    do: {:sni_hosts, Enum.map(hosts, &redact_sni_host/1)}

  defp redact_option({key, _value}) when key in [:certs_keys, :sni_hosts], do: {key, :redacted}
  defp redact_option(option), do: option

  defp redact_certs_key(entry) when is_map(entry) do
    Enum.reduce([:key, :password], entry, fn key, entry ->
      if Map.has_key?(entry, key), do: Map.put(entry, key, :redacted), else: entry
    end)
  end

  defp redact_certs_key(_entry), do: :redacted

  defp redact_sni_host({host, options}) when is_list(options),
    do: {host, redact_transport_options(options)}

  defp redact_sni_host({host, _options}), do: {host, :redacted}
  defp redact_sni_host(_entry), do: :redacted

  defp validate_reuseport_options!(config) do
    num_listen_sockets = config.num_listen_sockets
    transport_options = config.transport_options
    has_reuseport = :proplists.get_value(:reuseport, transport_options, false)
    has_reuseport_lb = :proplists.get_value(:reuseport_lb, transport_options, false)

    unless num_listen_sockets <= 1 or has_reuseport or has_reuseport_lb do
      raise ArgumentError,
            "reuseport: true or reuseport_lb: true must be set in transport_options when using num_listen_sockets > 1"
    end
  end
end

defimpl Inspect, for: Hell.ServerConfig do
  # Supervisor and crash reports inspect start arguments; keep TLS secrets out of them
  def inspect(config, opts) do
    redacted = %{
      config
      | transport_options: Hell.ServerConfig.redact_transport_options(config.transport_options)
    }

    Inspect.Any.inspect(redacted, opts)
  end
end

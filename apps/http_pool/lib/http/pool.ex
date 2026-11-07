defmodule HTTP.Pool do
  @moduledoc """
  Policy validation and opaque references for HTTP/1 idle and HTTP/2 stream pools.

  Runtime composes usable families with `HTTP.Runtime.Pool`. This application
  starts no default pools. References bind to process identities for one family
  generation: restarting the same name never redirects an old request.

  H1 counts describe retained idle sockets and pending handoffs. Active HTTP/1
  requests are owned by their callers and are deliberately absent from snapshots.
  H2 counts include connecting and provider handoff capacity. Draining connections
  remain in the total connection count.
  """
  @enforce_keys [:instance, :generation, :http1, :http2, :policy]
  defstruct [:instance, :generation, :http1, :http2, :policy]

  @opaque t :: %__MODULE__{
            instance: pid(),
            generation: reference(),
            http1: pid(),
            http2: pid(),
            policy: map()
          }

  @h1 [max_idle_per_key: 2, max_idle: 256, idle_timeout: 30_000]
  @h2 [
    max_connections: 2,
    max_total_connections: 20,
    max_keys: 100,
    max_streams: 100,
    max_pending: 100,
    idle_timeout: 30_000
  ]

  @doc "Validates immutable family policy; unknown options fail without exposing values."
  def policy(opts \\ []) do
    with :ok <- options(opts, [:http1, :http2]),
         {:ok, h1} <- protocol_policy(Keyword.get(opts, :http1, []), @h1, :http1),
         {:ok, h2} <- protocol_policy(Keyword.get(opts, :http2, []), @h2, :http2) do
      {:ok, %{http1: h1, http2: h2}}
    end
  end

  @doc "Low-level child specs. Runtime supplies protocol owner callbacks at handoff."
  def child_specs(policy) do
    [{HTTP.HTTP1.Pool, [name: nil] ++ policy.http1}, {HTTP.HTTP2.Pool, policy.http2}]
  end

  @doc "Checks that all processes belonging to the bound generation are still alive."
  def validate(%__MODULE__{} = ref) do
    if Enum.all?([ref.instance, ref.http1, ref.http2], &(is_pid(&1) and Process.alive?(&1))),
      do: :ok,
      else: {:error, :stale_pool}
  end

  def validate(_), do: {:error, :invalid_pool}

  @doc false
  def validate_binding(request) do
    case request.transport_options[:pool_binding] do
      nil -> :ok
      reference -> validate(reference)
    end
  end

  @doc "Returns aggregate counts without route identities, request data or TLS material."
  def snapshot(%__MODULE__{} = ref) do
    with :ok <- validate(ref) do
      h1 = GenServer.call(ref.http1, :stats)
      entries = HTTP.HTTP2.Pool.stats(ref.http2)

      h2 =
        Enum.reduce(
          Map.values(entries),
          %{
            keys: map_size(entries),
            connections: 0,
            draining: 0,
            pending: 0,
            connecting: 0,
            provider_pending: 0,
            streams: 0
          },
          fn entry, counts ->
            Map.new(counts, fn
              {:keys, count} -> {:keys, count}
              {key, count} -> {key, count + Map.get(entry, key, 0)}
            end)
          end
        )

      {:ok, %{http1: h1, http2: h2}}
    end
  catch
    :exit, _ -> {:error, :stale_pool}
  end

  def snapshot(_), do: {:error, :invalid_pool}

  defp protocol_policy(opts, defaults, protocol) do
    with :ok <- options(opts, Keyword.keys(defaults)) do
      merged = Keyword.merge(defaults, opts)

      case Enum.find(merged, fn {key, value} -> not valid_limit?(protocol, key, value) end) do
        nil -> {:ok, merged}
        {key, _} -> {:error, {:invalid_pool_option, key, :out_of_range}}
      end
    end
  end

  defp options(opts, keys) when is_list(opts) do
    if Keyword.keyword?(opts) and
         length(Keyword.keys(opts)) == length(Enum.uniq(Keyword.keys(opts))) do
      case Enum.find(Keyword.keys(opts), &(&1 not in keys)) do
        nil -> :ok
        key -> {:error, {:invalid_pool_option, key, :unknown}}
      end
    else
      {:error, {:invalid_pool_option, :options, :expected_keyword}}
    end
  end

  defp options(_, _), do: {:error, {:invalid_pool_option, :options, :expected_keyword}}
  defp valid_limit?(:http1, :max_idle_per_key, value), do: is_integer(value) and value in 1..16
  defp valid_limit?(:http1, :idle_timeout, value), do: is_integer(value) and value in 1..60_000

  defp valid_limit?(:http2, :idle_timeout, value),
    do: is_integer(value) and value in 1..4_294_967_295

  defp valid_limit?(:http2, :max_pending, value), do: is_integer(value) and value >= 0
  defp valid_limit?(_, _, value), do: is_integer(value) and value > 0
end

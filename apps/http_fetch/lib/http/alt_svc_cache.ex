defmodule HTTP.AltSvc.Cache do
  @moduledoc """
  Bounded per-origin cache of RFC 7838 HTTP/3 alternatives for `HTTP.fetch/2`.

  Origins are `{downcased_host, port}` tuples for `https` URLs. Only `h3`
  alternatives on the same host (empty or equal alternative host) are kept.
  A broken origin is neither routed nor re-learned until its mark expires.
  Times are monotonic seconds and may be passed explicitly for testing. Reads
  use a protected ETS table; writes are serialized through the owner process.
  """

  use GenServer

  alias HTTP.AltSvc

  @table __MODULE__
  @max_entries 1_024
  @broken_seconds 300

  @type origin :: {String.t(), :inet.port_number()}

  @doc false
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Returns the cache origin for an `https` URI, or `nil`."
  @spec origin(URI.t()) :: origin() | nil
  def origin(%URI{scheme: "https", host: host, port: port}) when is_binary(host) and host != "",
    do: {String.downcase(host), port || 443}

  def origin(_uri), do: nil

  @doc "Applies an `Alt-Svc` field value received from `origin`; malformed values are ignored."
  @spec put(origin(), String.t(), integer()) :: :ok
  def put({host, _port} = origin, value, now \\ now()) when is_binary(value) do
    case decision(host, AltSvc.parse(value)) do
      :ignore -> :ok
      decision -> call({:put, origin, decision, now})
    end
  end

  @doc "Returns the fresh alternative port for `origin`, or `:none`."
  @spec lookup(origin(), integer()) :: {:ok, :inet.port_number()} | :none
  def lookup(origin, now \\ now()) do
    case :ets.lookup(@table, origin) do
      [{^origin, {:alt, port}, expires_at}] when expires_at > now -> {:ok, port}
      _ -> :none
    end
  rescue
    ArgumentError -> :none
  end

  @doc "Marks `origin` broken for five minutes, removing any alternative."
  @spec mark_broken(origin(), integer()) :: :ok
  def mark_broken(origin, now \\ now()), do: call({:broken, origin, now + @broken_seconds, now})

  @doc false
  @spec clear() :: :ok
  def clear, do: call(:clear)

  @doc false
  def max_entries, do: @max_entries

  @impl true
  def init(_opts) do
    _ = :ets.new(@table, [:named_table, :protected, :set, read_concurrency: true])
    {:ok, nil}
  end

  @impl true
  def handle_call({:put, origin, decision, now}, _from, state) do
    unless broken?(origin, now), do: apply_decision(origin, decision, now)
    {:reply, :ok, state}
  end

  def handle_call({:broken, origin, until, now}, _from, state) do
    insert(origin, :broken, until, now)
    {:reply, :ok, state}
  end

  def handle_call(:clear, _from, state) do
    :ets.delete_all_objects(@table)
    {:reply, :ok, state}
  end

  defp decision(_host, :clear), do: :delete
  defp decision(_host, {:error, _reason}), do: :ignore

  defp decision(host, alternatives) when is_list(alternatives) do
    case Enum.find(alternatives, &(&1.alpn == "h3" and &1.host in ["", host])) do
      %{max_age: max_age, port: port} when max_age > 0 -> {:alt, port, max_age}
      _ -> :delete
    end
  end

  defp apply_decision(origin, :delete, _now), do: :ets.delete(@table, origin)

  defp apply_decision(origin, {:alt, port, max_age}, now),
    do: insert(origin, {:alt, port}, now + max_age, now)

  defp broken?(origin, now) do
    match?([{_, :broken, until}] when until > now, :ets.lookup(@table, origin))
  end

  defp insert(origin, value, expires_at, now) do
    unless :ets.member(@table, origin), do: make_room(now)
    :ets.insert(@table, {origin, value, expires_at})
  end

  defp make_room(now) do
    if :ets.info(@table, :size) >= @max_entries do
      :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:"=<", :"$1", now}], [true]}])
      evict_soonest()
    end
  end

  defp evict_soonest do
    if :ets.info(@table, :size) >= @max_entries do
      {origin, _value, _expires_at} = @table |> :ets.tab2list() |> Enum.min_by(&elem(&1, 2))
      :ets.delete(@table, origin)
    end
  end

  defp call(message) do
    GenServer.call(__MODULE__, message)
  catch
    :exit, _reason -> :ok
  end

  defp now, do: System.monotonic_time(:second)
end

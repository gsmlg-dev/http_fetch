defmodule HTTP.HTTP3.Resumption do
  @moduledoc """
  Runtime-owned QUIC session-ticket authority for opt-in HTTP/3 resumption (beta).

  Each partition owns one shared client endpoint whose engine-local store keeps
  the session tickets. A partition is the exact endpoint configuration (origin
  host, TLS trust and reference identity, QUIC profile, stream and datagram
  limits), the dialed UDP port and the 0-RTT policy; the engine additionally
  binds tickets to the remote address, trust and application profile. Early
  partitions also remember the peer HTTP/3 SETTINGS last received on that
  partition, which bound requests sent in 0-RTT (RFC 9114 Section 7.2.4.2).

  State is bounded: at most `max_partitions` (default 64) endpoints with at most
  32 remembered SETTINGS each. When full, the least recently used endpoint with
  no live connection is stopped; when none is idle, checkout fails and the
  caller connects without resumption. Nothing is persisted.
  """
  use GenServer

  alias QuicHttp3.Transport.Quic, as: QuicTransport

  @profile "http3-fetch-r1-v1"
  @early_profile "http3-fetch-0rtt-v1"
  @max_settings 32

  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))

  @doc """
  Returns the shared endpoint for `client_opts` dialing `port`, its partition and
  the remembered peer SETTINGS (`nil` until a connection received them).
  """
  def checkout(server \\ __MODULE__, client_opts, port, early?)
      when is_list(client_opts) and is_boolean(early?) do
    GenServer.call(server, {:checkout, client_opts, port, early?}, 10_000)
  catch
    :exit, reason -> {:error, {:resumption_unavailable, reason}}
  end

  @doc "Remembers the peer SETTINGS received on a connection of `partition`."
  def remember(server \\ __MODULE__, partition, settings),
    do: GenServer.cast(server, {:remember, partition, settings})

  def status(server \\ __MODULE__), do: GenServer.call(server, :status)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    {:ok,
     %{
       entries: %{},
       pids: %{},
       clock: 0,
       max_partitions: Keyword.get(opts, :max_partitions, 64)
     }}
  end

  @impl true
  def handle_call({:checkout, client_opts, port, early?}, _from, state) do
    partition = :crypto.hash(:sha256, :erlang.term_to_binary({client_opts, port, early?}))
    state = %{state | clock: state.clock + 1}

    case state.entries[partition] do
      %{endpoint: endpoint} = entry ->
        entries = Map.put(state.entries, partition, %{entry | used: state.clock})
        {:reply, {:ok, endpoint, partition, entry.settings}, %{state | entries: entries}}

      nil ->
        with {:ok, state} <- make_room(state),
             {:ok, endpoint} <- QuicTransport.client(client_opts ++ policy(early?)) do
          entry = %{
            endpoint: endpoint,
            port: port,
            early: early?,
            settings: nil,
            used: state.clock
          }

          {:reply, {:ok, endpoint, partition, nil},
           %{
             state
             | entries: Map.put(state.entries, partition, entry),
               pids: Map.put(state.pids, endpoint.pid, partition)
           }}
        else
          {:error, reason} -> {:reply, {:error, reason}, state}
          other -> {:reply, {:error, other}, state}
        end
    end
  end

  def handle_call(:status, _from, state) do
    {:reply,
     %{
       partitions: map_size(state.entries),
       remembered: Enum.count(state.entries, fn {_, entry} -> entry.settings != nil end)
     }, state}
  end

  @impl true
  def handle_cast({:remember, partition, settings}, state) do
    if Map.has_key?(state.entries, partition) and valid_settings?(settings),
      do: {:noreply, put_in(state.entries[partition].settings, settings)},
      else: {:noreply, state}
  end

  @impl true
  def handle_info({:EXIT, pid, _reason}, state) do
    case Map.pop(state.pids, pid) do
      {nil, _} ->
        {:noreply, state}

      {partition, pids} ->
        {:noreply, %{state | pids: pids, entries: Map.delete(state.entries, partition)}}
    end
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    for {_, %{endpoint: endpoint}} <- state.entries, do: _ = QuicTransport.stop_endpoint(endpoint)
    :ok
  end

  defp policy(false), do: [resumption: [enabled: true, application_profile: @profile]]

  defp policy(true),
    do: [
      resumption: [enabled: true, application_profile: @early_profile],
      early_data: [enabled: true, application_profile: @early_profile]
    ]

  defp make_room(state) do
    if map_size(state.entries) < state.max_partitions do
      {:ok, state}
    else
      idle =
        state.entries
        |> Enum.sort_by(fn {_, entry} -> entry.used end)
        |> Enum.find(fn {_, entry} -> idle?(entry.endpoint) end)

      case idle do
        {partition, entry} ->
          _ = QuicTransport.stop_endpoint(entry.endpoint)

          {:ok,
           %{
             state
             | entries: Map.delete(state.entries, partition),
               pids: Map.delete(state.pids, entry.endpoint.pid)
           }}

        nil ->
          {:error, :resumption_capacity}
      end
    end
  end

  defp idle?(endpoint) do
    Quic.Endpoint.connections(endpoint.pid) == []
  catch
    _, _ -> false
  end

  defp valid_settings?(settings) do
    is_list(settings) and length(settings) <= @max_settings and
      Enum.all?(settings, fn
        {id, value} -> is_integer(id) and id >= 0 and is_integer(value) and value >= 0
        _ -> false
      end)
  end
end

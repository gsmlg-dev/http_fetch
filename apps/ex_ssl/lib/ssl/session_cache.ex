defmodule SSL.SessionCache do
  @moduledoc "Bounded, reusable, memory-only TLS 1.2 EMS session cache."
  use GenServer

  alias SSL.TLS12Session

  @max_entries 128
  @max_bytes 4_194_304
  @cleanup_interval 60_000
  @call_timeout 25

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, Keyword.put_new(opts, :name, __MODULE__))
  end

  @spec put(binary(), TLS12Session.t(), GenServer.server()) :: :ok | {:error, atom()}
  def put(key, session, server \\ __MODULE__)

  def put(key, session, server) when is_binary(key) and byte_size(key) == 32 do
    with :ok <- TLS12Session.validate(session),
         true <- session.expires_at > System.monotonic_time(:millisecond) do
      safe_call(server, {:put, key, session}, {:error, :cache_unavailable})
    else
      false -> {:error, :expired}
      {:error, _} = error -> error
    end
  end

  def put(_key, _session, _server), do: {:error, :invalid_key}

  @spec lookup(binary(), :auto | binary() | {binary(), binary()}, GenServer.server()) ::
          {:ok, TLS12Session.t()} | :miss
  def lookup(key, reference, server \\ __MODULE__)

  def lookup(key, reference, server) when is_binary(key) and byte_size(key) == 32 do
    if reference == :auto or TLS12Session.valid_reference?(reference),
      do: safe_call(server, {:lookup, key, reference}, :miss),
      else: :miss
  end

  def lookup(_key, _reference, _server), do: :miss

  @spec stats(GenServer.server()) ::
          %{count: non_neg_integer(), bytes: non_neg_integer()} | {:error, atom()}
  def stats(server \\ __MODULE__),
    do: safe_call(server, :stats, {:error, :cache_unavailable})

  @impl true
  def init(:ok) do
    Process.flag(:sensitive, true)
    {:ok, schedule_cleanup(%{entries: %{}, bytes: 0, order: 0, timer_ref: nil, timer_token: nil})}
  end

  @impl true
  def handle_call({:put, key, session}, _from, state) do
    now = System.monotonic_time(:millisecond)
    key = {:binary.copy(key), :binary.copy(session.id)}
    state = state |> prune(now) |> remove(key)
    session = own_material(session)
    size = :erlang.external_size({key, session})

    if session.expires_at <= now or size > @max_bytes do
      {:reply, {:error, :expired}, state}
    else
      state = evict_until_fit(state, size)
      order = state.order + 1
      entries = Map.put(state.entries, key, {session, size, order})
      {:reply, :ok, %{state | entries: entries, bytes: state.bytes + size, order: order}}
    end
  end

  def handle_call({:lookup, key, reference}, _from, state) do
    state = prune(state, System.monotonic_time(:millisecond))

    selected =
      state.entries
      |> Enum.filter(fn {{partition, id}, {session, _, _}} ->
        partition == key and matches?(reference, id, session)
      end)
      |> Enum.max_by(fn {_, {_, _, order}} -> order end, fn -> nil end)

    case selected do
      {_, {session, _, _}} -> {:reply, {:ok, session}, state}
      nil -> {:reply, :miss, state}
    end
  end

  def handle_call(:stats, _from, state) do
    state = prune(state, System.monotonic_time(:millisecond))
    {:reply, %{count: map_size(state.entries), bytes: state.bytes}, state}
  end

  @impl true
  def handle_info({:cleanup, token}, %{timer_token: token} = state) do
    {:noreply, state |> prune(System.monotonic_time(:millisecond)) |> schedule_cleanup()}
  end

  def handle_info({:cleanup, _stale_token}, state), do: {:noreply, state}
  def handle_info(:cleanup, state), do: {:noreply, state}

  @impl true
  def format_status(status) do
    Map.merge(status, %{state: :redacted, message: :redacted, reason: :redacted, log: []})
  end

  defp schedule_cleanup(state) do
    _ = if state.timer_ref, do: Process.cancel_timer(state.timer_ref)
    token = make_ref()

    %{
      state
      | timer_ref: Process.send_after(self(), {:cleanup, token}, @cleanup_interval),
        timer_token: token
    }
  end

  # Wire parsers return subbinaries. Retain only owned session/DER bytes so a
  # small cache entry cannot pin a much larger handshake or certificate flight.
  # Decoded PKIX material is reconstructed under current policy on checkout.
  defp own_material(session) do
    %{
      session
      | id: :binary.copy(session.id),
        master_secret: :binary.copy(session.master_secret),
        data: if(session.data, do: :binary.copy(session.data), else: nil),
        alpn: if(session.alpn, do: :binary.copy(session.alpn), else: nil),
        peer: %{chain: Enum.map(session.peer.chain, &:binary.copy/1)}
    }
  end

  defp matches?(:auto, _id, session), do: session.auto

  defp matches?({id, data}, id, %{data: retained}) when is_binary(retained),
    do: :crypto.hash_equals(data, retained)

  defp matches?(id, id, _session) when is_binary(id), do: true
  defp matches?(_, _, _), do: false

  defp prune(state, now) do
    Enum.reduce(state.entries, state, fn {key, {session, _, _}}, acc ->
      if session.expires_at <= now, do: remove(acc, key), else: acc
    end)
  end

  defp remove(state, key) do
    case Map.pop(state.entries, key) do
      {nil, _} ->
        state

      {{_session, size, _order}, entries} ->
        %{state | entries: entries, bytes: state.bytes - size}
    end
  end

  defp evict_until_fit(state, new_size) do
    if map_size(state.entries) < @max_entries and state.bytes + new_size <= @max_bytes do
      state
    else
      {oldest, _} = Enum.min_by(state.entries, fn {_key, {_session, _size, order}} -> order end)
      state |> remove(oldest) |> evict_until_fit(new_size)
    end
  end

  defp safe_call(server, message, fallback) do
    GenServer.call(server, message, @call_timeout)
  catch
    :exit, _ -> fallback
  end
end

defmodule SSL.TicketCache do
  @moduledoc "Bounded, one-use, in-memory TLS 1.3 ticket cache."
  use GenServer

  alias SSL.SessionTicket

  @max_entries 128
  @max_bytes 4_194_304
  @cleanup_interval 60_000
  @call_timeout 25

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, Keyword.put_new(opts, :name, __MODULE__))
  end

  @spec put(binary(), SessionTicket.t(), GenServer.server()) :: :ok | {:error, atom()}
  def put(key, ticket, server \\ __MODULE__)

  def put(key, ticket, server) when is_binary(key) and byte_size(key) == 32 do
    with :ok <- SessionTicket.validate(ticket),
         true <- ticket.expires_at > System.monotonic_time(:millisecond) do
      safe_call(server, {:put, key, ticket}, {:error, :cache_unavailable})
    else
      false -> {:error, :expired}
      {:error, _} = error -> error
    end
  end

  def put(_key, _ticket, _server), do: {:error, :invalid_key}

  @spec checkout(binary(), GenServer.server()) :: {:ok, SessionTicket.t()} | :miss
  def checkout(key, server \\ __MODULE__)

  def checkout(key, server) when is_binary(key) and byte_size(key) == 32,
    do: safe_call(server, {:checkout, key}, :miss)

  def checkout(_key, _server), do: :miss

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
  def handle_call({:put, key, ticket}, _from, state) do
    now = System.monotonic_time(:millisecond)
    state = state |> prune(now) |> remove(key)
    key = :binary.copy(key)
    ticket = own_material(ticket)
    size = :erlang.external_size({key, ticket})

    if ticket.expires_at <= now or size > @max_bytes do
      {:reply, {:error, :expired}, state}
    else
      state = evict_until_fit(state, size)
      order = state.order + 1
      entries = Map.put(state.entries, key, {ticket, size, order})
      {:reply, :ok, %{state | entries: entries, bytes: state.bytes + size, order: order}}
    end
  end

  def handle_call({:checkout, key}, _from, state) do
    now = System.monotonic_time(:millisecond)

    case Map.get(state.entries, key) do
      {ticket, _size, _order} ->
        state = remove(state, key)

        if ticket.expires_at > now,
          do: {:reply, {:ok, ticket}, state},
          else: {:reply, :miss, state}

      nil ->
        {:reply, :miss, state}
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

  # Wire parsers return subbinaries. Retain only owned ticket/DER bytes so a
  # small cache entry cannot pin a much larger handshake or certificate flight.
  # Decoded PKIX material is reconstructed under current policy on checkout.
  defp own_material(ticket) do
    %{
      ticket
      | ticket: :binary.copy(ticket.ticket),
        psk: :binary.copy(ticket.psk),
        alpn: if(ticket.alpn, do: :binary.copy(ticket.alpn), else: nil),
        peer: %{chain: Enum.map(ticket.peer.chain, &:binary.copy/1)}
    }
  end

  defp prune(state, now) do
    Enum.reduce(state.entries, state, fn {key, {ticket, _, _}}, acc ->
      if ticket.expires_at <= now, do: remove(acc, key), else: acc
    end)
  end

  defp remove(state, key) do
    case Map.pop(state.entries, key) do
      {nil, _} -> state
      {{_ticket, size, _order}, entries} -> %{state | entries: entries, bytes: state.bytes - size}
    end
  end

  defp evict_until_fit(state, new_size) do
    if map_size(state.entries) < @max_entries and state.bytes + new_size <= @max_bytes do
      state
    else
      {oldest, _} = Enum.min_by(state.entries, fn {_key, {_ticket, _size, order}} -> order end)
      state |> remove(oldest) |> evict_until_fit(new_size)
    end
  end

  defp safe_call(server, message, fallback) do
    GenServer.call(server, message, @call_timeout)
  catch
    :exit, _ -> fallback
  end
end

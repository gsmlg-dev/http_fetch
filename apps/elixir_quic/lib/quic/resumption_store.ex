defmodule Quic.ResumptionStore do
  @moduledoc "Endpoint-local, bounded single-use ticket authority. No persistence or IO."
  alias SSL.QUIC.Session
  @derive {Inspect, only: [:max_entries, :max_bytes, :bytes]}
  defstruct entries: %{}, bytes: 0, max_entries: 256, max_bytes: 1_048_576

  def new(opts \\ []) do
    entries = Keyword.get(opts, :max_entries, 256)
    bytes = Keyword.get(opts, :max_bytes, 1_048_576)

    if is_integer(entries) and entries in 1..4096 and is_integer(bytes) and
         bytes in 1024..16_777_216,
       do: {:ok, %__MODULE__{max_entries: entries, max_bytes: bytes}},
       else: {:error, :invalid_resumption_store_limits}
  end

  def store(state, partition, %Session{} = session, now) do
    state = expire(state, now)
    size = :erlang.external_size(session)
    key = {partition, session.identity}

    cond do
      Session.validate(session) != :ok or session.context != partition or
        session.expires_at <= now or session.issued_at > now ->
        {:error, :ineligible_session, state}

      size > state.max_bytes ->
        {:error, :ticket_too_large, state}

      Map.has_key?(state.entries, key) ->
        {:error, :duplicate_ticket, state}

      true ->
        state = make_room(state, size)
        entry = %{session: session, size: size, lease: nil, lease_until: nil, inserted: now}
        {:ok, %{state | entries: Map.put(state.entries, key, entry), bytes: state.bytes + size}}
    end
  end

  def lookup(state, partition, identity, now, deadline) do
    state = expire(state, now)
    key = {partition, identity}

    case state.entries[key] do
      %{lease: lease, lease_until: until} when not is_nil(lease) and until > now ->
        {:miss, state}

      nil ->
        {:miss, state}

      entry when deadline > now ->
        lease = make_ref()
        entry = %{entry | lease: lease, lease_until: min(deadline, now + 100)}
        {:ok, entry.session, lease, %{state | entries: Map.put(state.entries, key, entry)}}

      _ ->
        {:miss, state}
    end
  end

  def commit(state, partition, identity, lease, now) do
    state = expire(state, now)
    key = {partition, identity}

    case state.entries[key] do
      %{lease: ^lease, lease_until: until} = entry when is_reference(lease) and until > now ->
        {:ok, delete(state, key, entry)}

      _ ->
        {:miss, state}
    end
  end

  def claim_client(state, partition, now) do
    state = expire(state, now)

    eligible =
      Enum.filter(state.entries, fn {{context, _}, entry} ->
        context == partition and entry.lease == nil
      end)

    case Enum.max_by(eligible, fn {_, entry} -> entry.inserted end, fn -> nil end) do
      nil -> {nil, state}
      {key, entry} -> {entry.session, delete(state, key, entry)}
    end
  end

  def expire(state, now) do
    Enum.reduce(state.entries, state, fn {key, entry}, state ->
      if entry.session.expires_at <= now, do: delete(state, key, entry), else: state
    end)
  end

  defp delete(state, key, entry),
    do: %{state | entries: Map.delete(state.entries, key), bytes: state.bytes - entry.size}

  defp make_room(state, size) do
    if map_size(state.entries) < state.max_entries and state.bytes + size <= state.max_bytes do
      state
    else
      {key, entry} = Enum.min_by(state.entries, fn {_, entry} -> entry.inserted end)
      make_room(delete(state, key, entry), size)
    end
  end
end

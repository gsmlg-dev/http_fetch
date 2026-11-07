defmodule Quic.PeerCIDs do
  @moduledoc """
  Bounded peer CID issuance, destination bindings, and retirement watermark.

  Used CIDs cannot move to another destination. Contiguous unbound spent entries
  are retired through the watermark; lower live bindings or unseen sequence gaps
  defer retirement. Such gaps can exhaust the finite active map until the peer
  advances its retirement watermark or the lower bindings are released.
  """
  defstruct ids: %{}, bindings: %{default: 0}, current: 0, retired_before: 0, limit: 2

  def new(initial, limit \\ 2),
    do: %__MODULE__{ids: %{0 => %{cid: initial, token: nil, used: true}}, limit: limit}

  def current(state) do
    case state.ids[state.current] do
      nil -> nil
      entry -> entry.cid
    end
  end

  def current(state, path) do
    case state.ids[state.bindings[path]] do
      nil -> nil
      entry -> entry.cid
    end
  end

  def bind_path(state, path, previous, same_incoming_dcid) do
    cond do
      Map.has_key?(state.bindings, path) ->
        {:ok, state}

      map_size(state.bindings) >= 2 ->
        {:error, :path_limit}

      not Map.has_key?(state.bindings, previous) ->
        {:error, :unknown_path}

      same_incoming_dcid ->
        case state.bindings[previous] do
          sequence when is_integer(sequence) ->
            {:ok, %{state | bindings: Map.put(state.bindings, path, sequence)}}

          _ ->
            {:error, :no_unused_connection_id}
        end

      true ->
        case unused(state.ids) do
          nil ->
            {:error, :no_unused_connection_id}

          sequence ->
            ids = Map.update!(state.ids, sequence, &%{&1 | used: true})
            {:ok, %{state | ids: ids, bindings: Map.put(state.bindings, path, sequence)}}
        end
    end
  end

  # Usage remains recorded in the bounded active map after a path disappears.
  def drop_path(state, path), do: %{state | bindings: Map.delete(state.bindings, path)}

  def retire_unused(state), do: retire_unused(state, [])

  def receive_id(state, frame, selected_path \\ :default)

  def receive_id(
        state,
        %{sequence: sequence, retire_prior_to: prior, cid: cid, token: token},
        selected_path
      ) do
    entry = %{cid: cid, token: token}
    existing = state.ids[sequence]

    cond do
      prior > sequence ->
        {:error, :invalid_retire_prior_to}

      sequence < state.retired_before ->
        {:ok, state, [sequence]}

      existing != nil and Map.take(existing, [:cid, :token]) != entry ->
        {:error, :connection_id_conflict}

      Enum.any?(state.ids, fn {n, e} -> n != sequence and e.cid == cid end) ->
        {:error, :connection_id_conflict}

      true ->
        watermark = max(prior, state.retired_before)
        entry = existing || Map.put(entry, :used, false)

        {retired, active} =
          Map.put(state.ids, sequence, entry) |> Enum.split_with(fn {n, _} -> n < watermark end)

        ids = Map.new(active)

        if map_size(ids) > state.limit do
          {:error, :connection_id_limit}
        else
          current =
            if Map.has_key?(ids, state.current), do: state.current, else: Enum.min(Map.keys(ids))

          next = %{state | ids: ids, current: current, retired_before: watermark}
          {next, spent} = next |> rebind_retired(selected_path) |> retire_unused()
          retired = (Enum.map(retired, &elem(&1, 0)) ++ spent) |> Enum.uniq() |> Enum.sort()

          {:ok, next, retired}
        end
    end
  end

  defp retire_unused(state, retired) do
    sequence = state.retired_before

    case state.ids[sequence] do
      %{used: true, cid: cid} when cid != <<>> ->
        if sequence in Map.values(state.bindings) do
          finish_retirement(state, retired)
        else
          retire_unused(
            %{state | ids: Map.delete(state.ids, sequence), retired_before: sequence + 1},
            [sequence | retired]
          )
        end

      _ ->
        finish_retirement(state, retired)
    end
  end

  defp finish_retirement(state, retired) do
    current =
      if Map.has_key?(state.ids, state.current),
        do: state.current,
        else: Enum.min(Map.keys(state.ids), fn -> nil end)

    {%{state | current: current}, Enum.reverse(retired)}
  end

  defp unused(ids) do
    ids
    |> Enum.flat_map(fn {sequence, entry} -> if entry.used, do: [], else: [sequence] end)
    |> Enum.min(fn -> nil end)
  end

  defp rebind_retired(state, selected_path) do
    bindings =
      Map.new(state.bindings, fn
        {path, sequence} when is_integer(sequence) ->
          binding =
            if Map.has_key?(state.ids, sequence), do: sequence, else: {:unavailable, sequence}

          {path, binding}

        entry ->
          entry
      end)

    groups =
      bindings
      |> Map.values()
      |> Enum.filter(&match?({:unavailable, _}, &1))
      |> Enum.uniq()
      |> Enum.sort_by(&{if(&1 == bindings[selected_path], do: 0, else: 1), &1})

    Enum.reduce(groups, %{state | bindings: bindings}, fn group, state ->
      case unused(state.ids) do
        nil ->
          state

        sequence ->
          bindings =
            Map.new(state.bindings, fn {path, binding} ->
              {path, if(binding == group, do: sequence, else: binding)}
            end)

          ids = Map.update!(state.ids, sequence, &%{&1 | used: true})
          %{state | ids: ids, bindings: bindings}
      end
    end)
  end
end

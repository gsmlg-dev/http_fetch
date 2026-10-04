defmodule Quic.PeerCIDs do
  @moduledoc "Bounded peer connection-ID state and retirement watermark."
  defstruct ids: %{}, current: 0, retired_before: 0, limit: 2

  def new(initial), do: %__MODULE__{ids: %{0 => %{cid: initial, token: nil}}}
  def current(state), do: state.ids[state.current].cid

  def receive_id(state, %{sequence: sequence, retire_prior_to: prior, cid: cid, token: token}) do
    entry = %{cid: cid, token: token}
    existing = state.ids[sequence]

    cond do
      prior > sequence ->
        {:error, :invalid_retire_prior_to}

      sequence < state.retired_before ->
        {:ok, state, [sequence]}

      existing != nil and existing != entry ->
        {:error, :connection_id_conflict}

      Enum.any?(state.ids, fn {n, e} -> n != sequence and e.cid == cid end) ->
        {:error, :connection_id_conflict}

      true ->
        watermark = max(prior, state.retired_before)

        {retired, active} =
          Map.put(state.ids, sequence, entry) |> Enum.split_with(fn {n, _} -> n < watermark end)

        ids = Map.new(active)

        if map_size(ids) > state.limit do
          {:error, :connection_id_limit}
        else
          current =
            if Map.has_key?(ids, state.current), do: state.current, else: Enum.min(Map.keys(ids))

          {:ok, %{state | ids: ids, current: current, retired_before: watermark},
           Enum.map(retired, &elem(&1, 0)) |> Enum.sort()}
        end
    end
  end
end

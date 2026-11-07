defmodule Quic.LocalCIDs do
  @moduledoc """
  Bounded local connection-ID issuance, registration, and retirement.

  The caller supplies CID material and a registration identity scoped to its
  connection generation. Registration acknowledgment makes an issuance ready;
  only publication after a successful local send advances the sent watermark.
  Retired entries are removed rather than retained as connection history.
  """

  @max_sequence 4_611_686_018_427_387_903
  @target 4
  @capacity 8

  defstruct ids: %{}, highest_sent: 0, pending: nil, target: 2, limit: 2

  @type entry :: %{cid: binary(), token: binary() | nil}
  @type registration :: %{
          sequence: non_neg_integer(),
          cid: binary(),
          token: binary(),
          registration_id: term()
        }
  @type pending :: %{
          sequence: non_neg_integer(),
          cid: binary(),
          token: binary(),
          registration_id: term(),
          status: :registering | :ready
        }
  @type frame :: %{
          type: :new_connection_id,
          sequence: non_neg_integer(),
          retire_prior_to: 0,
          cid: binary(),
          token: binary()
        }
  @opaque t :: %__MODULE__{
            ids: %{non_neg_integer() => entry()},
            highest_sent: non_neg_integer(),
            pending: pending() | nil,
            target: 2..4,
            limit: 2..8
          }

  @spec new(binary(), integer()) :: {:ok, t()} | {:error, atom()}
  def new(initial, peer_limit \\ 2) do
    if is_binary(initial) and byte_size(initial) <= 20 do
      configure(%__MODULE__{ids: %{0 => %{cid: :binary.copy(initial), token: nil}}}, peer_limit)
    else
      {:error, :invalid_connection_id}
    end
  end

  @spec configure(t(), integer()) :: {:ok, t()} | {:error, atom()}
  def configure(state, peer_limit)
      when is_integer(peer_limit) and peer_limit >= 2 and peer_limit <= @max_sequence do
    limit = min(@capacity, peer_limit)

    if map_size(state.ids) + pending_count(state) <= limit,
      do: {:ok, %{state | target: min(@target, peer_limit), limit: limit}},
      else: {:error, :connection_id_capacity}
  end

  def configure(_state, _peer_limit), do: {:error, :invalid_active_connection_id_limit}

  @doc "Whether one refill can be reserved without duplicating pending work."
  @spec refill?(t()) :: boolean()
  def refill?(state),
    do: state.pending == nil and not zero_length?(state) and map_size(state.ids) < state.target

  @spec active?(t(), binary()) :: boolean()
  def active?(state, cid), do: Enum.any?(state.ids, fn {_, entry} -> entry.cid == cid end)

  @doc "Reserve one route registration; this does not authorize advertisement."
  @spec reserve(t(), binary(), binary(), term()) ::
          {:ok, t(), registration()} | {:error, atom()}
  def reserve(state, cid, token, registration_id) do
    cond do
      zero_length?(state) ->
        {:error, :zero_length_connection_id}

      state.pending != nil ->
        {:error, :issuance_pending}

      map_size(state.ids) >= state.limit ->
        {:error, :connection_id_capacity}

      state.highest_sent == @max_sequence ->
        {:error, :connection_id_sequence_exhausted}

      not is_binary(cid) or byte_size(cid) not in 1..20 ->
        {:error, :invalid_connection_id}

      not is_binary(token) or byte_size(token) != 16 ->
        {:error, :invalid_reset_token}

      Enum.any?(state.ids, fn {_, entry} -> entry.cid == cid or entry.token == token end) ->
        {:error, :connection_id_conflict}

      true ->
        registration = %{
          sequence: state.highest_sent + 1,
          cid: :binary.copy(cid),
          token: :binary.copy(token),
          registration_id: registration_id
        }

        pending = Map.put(registration, :status, :registering)
        {:ok, %{state | pending: pending}, registration}
    end
  end

  @doc "Acknowledge the exact route registration and return its ready frame."
  @spec registered(t(), term()) :: {:ok, t(), frame()} | {:error, :stale_registration}
  def registered(%{pending: %{registration_id: identity} = pending} = state, identity) do
    frame = %{
      type: :new_connection_id,
      sequence: pending.sequence,
      retire_prior_to: 0,
      cid: pending.cid,
      token: pending.token
    }

    {:ok, %{state | pending: %{pending | status: :ready}}, frame}
  end

  def registered(_state, _identity), do: {:error, :stale_registration}

  @doc "Commit first transmission after successful registration and local send."
  @spec published(t(), non_neg_integer()) :: {:ok, t()} | {:error, atom()}
  def published(%{pending: %{sequence: sequence, status: :ready} = pending} = state, sequence) do
    entry = Map.take(pending, [:cid, :token])

    {:ok,
     %{state | ids: Map.put(state.ids, sequence, entry), highest_sent: sequence, pending: nil}}
  end

  def published(%{pending: %{sequence: sequence}} = _state, sequence),
    do: {:error, :registration_pending}

  def published(state, sequence)
      when is_integer(sequence) and sequence >= 0 and sequence <= state.highest_sent,
      do: {:ok, state}

  def published(_state, _sequence), do: {:error, :stale_issuance}

  @doc "Retire once, returning the route to remove without retaining its token."
  @spec retire(t(), non_neg_integer(), binary()) ::
          {:ok, t(), binary() | nil} | {:error, :invalid_connection_id_retirement}
  def retire(state, sequence, containing_dcid) do
    entry = state.ids[sequence]

    cond do
      zero_length?(state) or not is_integer(sequence) or sequence < 0 or
          sequence > state.highest_sent ->
        {:error, :invalid_connection_id_retirement}

      entry == nil ->
        {:ok, state, nil}

      entry.cid == containing_dcid ->
        {:error, :invalid_connection_id_retirement}

      true ->
        {:ok, %{state | ids: Map.delete(state.ids, sequence)}, entry.cid}
    end
  end

  defp pending_count(%{pending: nil}), do: 0
  defp pending_count(_state), do: 1
  defp zero_length?(state), do: match?(%{cid: <<>>}, state.ids[0])
end

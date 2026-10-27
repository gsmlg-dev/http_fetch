defmodule SSL.Lifecycle.Authority do
  @moduledoc false

  # Pure authority transitions. The runtime supplies fresh references, real
  # controller monitors and an authenticated connection-owner acknowledgment.
  # Nothing here establishes liveness, transfers a socket or proves cleanup.
  @derive {Inspect, only: [:epoch, :phase, :bound?]}
  defstruct [
    :attempt,
    :controller,
    :controller_monitor,
    :owner,
    :capability,
    :offer,
    epoch: 0,
    phase: :open,
    bound?: false
  ]

  @max_epoch 0x7FFFFFFFFFFFFFFF
  @type lease :: {reference(), non_neg_integer(), reference()}
  @type ticket :: {reference(), non_neg_integer(), reference()}
  @type acceptance_context :: %{
          caller: pid(),
          owner_ack: {reference(), pid()} | nil,
          monitor: reference(),
          capability: reference(),
          now: integer(),
          deadline: integer()
        }
  @opaque t :: %__MODULE__{}

  @spec new(reference(), pid(), reference(), reference()) :: t()
  def new(attempt, controller, monitor, capability)
      when is_reference(attempt) and is_pid(controller) and is_reference(monitor) and
             is_reference(capability) do
    %__MODULE__{
      attempt: attempt,
      controller: controller,
      controller_monitor: monitor,
      capability: capability
    }
  end

  @spec lease(t()) :: lease()
  def lease(%__MODULE__{} = state), do: {state.attempt, state.epoch, state.capability}

  @spec bind(t(), lease(), pid()) :: {:ok, t()} | {:error, atom()}
  def bind(%__MODULE__{} = state, lease, owner) do
    cond do
      not authorized?(state, lease) -> {:error, :stale_lease}
      state.phase != :open -> {:error, :cancelled}
      state.bound? -> {:error, :already_bound}
      not is_pid(owner) -> {:error, :invalid_owner}
      true -> {:ok, %{state | owner: owner, bound?: true}}
    end
  end

  @spec cancel(t(), lease(), integer(), integer()) :: {:ok, t()} | {:error, atom()}
  def cancel(%__MODULE__{} = state, lease, now, deadline) do
    cond do
      not within_deadline?(now, deadline) -> {:error, :deadline_exceeded}
      not authorized?(state, lease) -> {:error, :stale_lease}
      true -> {:ok, close(state)}
    end
  end

  @spec offer(t(), lease(), %{controller: pid(), owner: pid()}, reference(), integer(), integer()) ::
          {:ok, t(), ticket()} | {:error, atom()}
  def offer(%__MODULE__{} = state, lease, target, nonce, now, deadline) do
    cond do
      not within_deadline?(now, deadline) -> {:error, :deadline_exceeded}
      not authorized?(state, lease) -> {:error, :stale_lease}
      state.phase != :open -> {:error, :cancelled}
      not state.bound? -> {:error, :not_bound}
      not valid_target?(target) -> {:error, :invalid_target}
      not is_reference(nonce) or same_nonce?(state.offer, nonce) -> {:error, :invalid_nonce}
      true -> make_offer(state, target, nonce, deadline)
    end
  end

  @doc false
  @spec recover(t(), ticket(), pid(), integer(), integer()) ::
          {:ok, t(), lease()}
          | {:error,
             :deadline_exceeded | :stale_transfer | :not_recipient | :acceptance_unconfirmed}
  def recover(state, ticket, caller, now, deadline) do
    cond do
      not within_deadline?(now, deadline) -> {:error, :deadline_exceeded}
      is_nil(state.offer) or state.offer.ticket !== ticket -> {:error, :stale_transfer}
      caller != state.offer.controller -> {:error, :not_recipient}
      state.offer.status == :accepted -> {:ok, state, lease(state)}
      true -> {:error, :acceptance_unconfirmed}
    end
  end

  # Context is provider-internal, never a caller-supplied public acceptance DTO.
  # A replay recovers the committed lease without changing state or authority.
  @spec accept(t(), ticket(), acceptance_context()) :: {:ok, t(), lease()} | {:error, atom()}
  def accept(%__MODULE__{} = state, ticket, context) do
    cond do
      not within_deadline?(context.now, context.deadline) ->
        {:error, :deadline_exceeded}

      is_nil(state.offer) or state.offer.ticket !== ticket ->
        {:error, :stale_transfer}

      context.caller != state.offer.controller ->
        {:error, :not_recipient}

      state.offer.status == :accepted ->
        {:ok, state, lease(state)}

      state.phase != :open ->
        {:error, :cancelled}

      context.now >= state.offer.expires ->
        {:error, :offer_expired}

      context.owner_ack != {elem(ticket, 2), state.offer.owner} ->
        {:error, :owner_not_acknowledged}

      not fresh_monitor?(state, context.monitor) ->
        {:error, :invalid_controller_monitor}

      not fresh_capability?(state, context.capability) ->
        {:error, :invalid_capability}

      state.epoch == @max_epoch ->
        {:error, :authority_exhausted}

      true ->
        commit(state, context)
    end
  end

  @spec controller_down(t(), {:DOWN, reference(), :process, pid(), term()}) :: t()
  def controller_down(%__MODULE__{} = state, {:DOWN, ref, type, object, _reason}) do
    if {ref, type, object} == {state.controller_monitor, :process, state.controller},
      do: close(state),
      else: state
  end

  @spec snapshot(t(), integer()) :: map()
  def snapshot(%__MODULE__{} = state, now) do
    transfer =
      case state.offer do
        nil -> :none
        %{status: :pending, expires: expiry} when now >= expiry -> :expired
        %{status: status} -> status
      end

    %{
      epoch: state.epoch,
      phase: state.phase,
      bound?: state.bound?,
      transfer: transfer,
      transfer_nonce: if(state.offer, do: elem(state.offer.ticket, 2), else: :none)
    }
  end

  defp make_offer(state, target, nonce, deadline) do
    ticket = {state.attempt, state.epoch, nonce}

    offer = %{
      ticket: ticket,
      controller: target.controller,
      owner: target.owner,
      expires: deadline,
      status: :pending
    }

    {:ok, %{state | offer: offer}, ticket}
  end

  defp commit(state, context) do
    next = %{
      state
      | epoch: state.epoch + 1,
        capability: context.capability,
        controller_monitor: context.monitor,
        controller: state.offer.controller,
        owner: state.offer.owner,
        offer: %{state.offer | status: :accepted}
    }

    {:ok, next, lease(next)}
  end

  defp close(state) do
    offer =
      case state.offer do
        %{status: :pending} = offer -> %{offer | status: :cancelled}
        other -> other
      end

    %{state | phase: :cancelled, offer: offer}
  end

  defp authorized?(state, lease), do: lease === lease(state)

  defp within_deadline?(now, deadline),
    do: is_integer(now) and is_integer(deadline) and now < deadline

  defp valid_target?(%{controller: controller, owner: owner}),
    do: is_pid(controller) and is_pid(owner)

  defp valid_target?(_), do: false
  defp same_nonce?(nil, _nonce), do: false
  defp same_nonce?(offer, nonce), do: elem(offer.ticket, 2) == nonce
  defp fresh_monitor?(state, ref), do: is_reference(ref) and ref != state.controller_monitor
  defp fresh_capability?(state, ref), do: is_reference(ref) and ref != state.capability
end

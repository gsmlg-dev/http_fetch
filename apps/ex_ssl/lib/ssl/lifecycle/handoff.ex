defmodule SSL.Lifecycle.Handoff do
  @moduledoc false

  # Pure, bounded bookkeeping for cooperative private ownership acknowledgments.
  # The original Observer supplies authenticated facts, never role-mask inference.
  alias SSL.Lifecycle.ResourceLedger

  @ready_roles [:setup, :connection, :writer, :owner, :controller]
  @handoff_roles @ready_roles ++ [:allocator, :tcp]

  @derive {Inspect, only: [:phase]}
  defstruct observer: nil,
            phase: :idle,
            deadline: nil,
            identities: %{},
            ready_nonce: nil,
            grant_nonce: nil

  @type identities :: %{atom() => ResourceLedger.identity()}
  @type context :: %{
          observer: pid(),
          identities: identities(),
          deadline: integer(),
          now: integer()
        }
  @opaque t :: %__MODULE__{}

  @spec new(pid()) :: t()
  def new(observer), do: %__MODULE__{observer: observer}

  @spec writer_ready(t(), context(), reference()) :: {:ok, t()} | {:error, atom()}
  def writer_ready(
        %__MODULE__{phase: :idle, observer: observer} = handoff,
        %{observer: observer, deadline: deadline, now: now} = context,
        nonce
      )
      when is_integer(deadline) and now < deadline and is_reference(nonce) do
    {:ok,
     %{
       handoff
       | phase: :writer_ready,
         deadline: deadline,
         identities: Map.take(context.identities, @ready_roles),
         ready_nonce: nonce
     }}
  end

  def writer_ready(_handoff, _context, _nonce), do: {:error, :handoff_not_idle}

  @spec connection_ready(t(), context(), reference()) :: {:ok, t()} | {:error, atom()}
  def connection_ready(
        %__MODULE__{phase: :writer_ready, ready_nonce: nonce} = handoff,
        context,
        nonce
      )
      when is_reference(nonce) do
    with :ok <- current(handoff, context),
         do: {:ok, %{handoff | phase: :ready, ready_nonce: nil}}
  end

  def connection_ready(_handoff, _context, _nonce), do: {:error, :invalid_readiness}

  @spec prepare(t(), context(), reference()) :: {:ok, t()} | {:error, atom()}
  def prepare(%__MODULE__{phase: :ready} = handoff, context, nonce) when is_reference(nonce) do
    with :ok <- current(handoff, context),
         do:
           {:ok,
            %{
              handoff
              | phase: :prepared,
                identities: Map.take(context.identities, @handoff_roles),
                grant_nonce: nonce
            }}
  end

  def prepare(_handoff, _context, _nonce), do: {:error, :handoff_not_ready}

  @spec commit(t(), context(), reference()) :: {:ok, t()} | {:error, atom()}
  def commit(%__MODULE__{phase: :prepared, grant_nonce: nonce} = handoff, context, nonce)
      when is_reference(nonce) do
    with :ok <- current(handoff, context),
         do: {:ok, %{handoff | phase: :committed, grant_nonce: nil}}
  end

  def commit(_handoff, _context, _nonce), do: {:error, :invalid_handoff_grant}

  @spec pending?(t()) :: boolean()
  def pending?(%__MODULE__{phase: phase}), do: phase in [:writer_ready, :ready, :prepared]

  @spec deadline(t()) :: integer() | nil
  def deadline(%__MODULE__{deadline: deadline}), do: deadline

  @spec expired?(t(), integer()) :: boolean()
  def expired?(%__MODULE__{} = handoff, now),
    do: pending?(handoff) and now >= handoff.deadline

  @spec involves?(t(), ResourceLedger.identity()) :: boolean()
  def involves?(%__MODULE__{} = handoff, identity),
    do: pending?(handoff) and identity in Map.values(handoff.identities)

  @spec invalidate(t()) :: t()
  def invalidate(%__MODULE__{} = handoff),
    do: %{handoff | phase: :invalid, ready_nonce: nil, grant_nonce: nil}

  defp current(handoff, context) do
    cond do
      context.observer != handoff.observer ->
        {:error, :foreign_observer}

      # A tighter RPC budget is allowed; the first protocol deadline never moves.
      context.now >= min(handoff.deadline, context.deadline) ->
        {:error, :deadline_exceeded}

      not Enum.all?(handoff.identities, fn {role, identity} ->
        Map.get(context.identities, role) == identity
      end) ->
        {:error, :stale_handoff_identity}

      true ->
        :ok
    end
  end
end

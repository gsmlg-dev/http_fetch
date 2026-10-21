defmodule SSL.Lifecycle.Receipt do
  @moduledoc false

  # Provider-internal storage, not an independently established cleanup proof.
  # Only the creating observer publishes. Readers trust payload words after seal.
  alias SSL.Lifecycle.ResourceLedger

  @words 8
  @max_epoch 0x7FFFFFFFFFFFFFFF
  @setups %{not_started: 1, connected: 2, failed: 3, cancelled: 4}
  @failures %{
    none: 1,
    options: 2,
    connect: 3,
    tls: 4,
    timeout: 5,
    cancelled: 6,
    owner_down: 7,
    internal: 8
  }
  @scopes %{dial: 1, upgrade: 2}
  @enforce_keys [:cell, :observer]
  @derive {Inspect, only: []}
  defstruct [:cell, :observer]

  @type setup :: :not_started | :connected | :failed | :cancelled
  @type failure ::
          :none | :options | :connect | :tls | :timeout | :cancelled | :owner_down | :internal
  @type metadata :: %{setup: setup(), failure: failure(), epoch: 0..0x7FFFFFFFFFFFFFFF}
  @type terminal :: %{
          version: 1,
          scope: ResourceLedger.scope(),
          setup: setup(),
          setup_failure: failure(),
          logical: :closed,
          cleanup: :confirmed | :unconfirmed,
          roles: ResourceLedger.role_mask(),
          observed_down: ResourceLedger.role_mask(),
          losses: ResourceLedger.role_mask(),
          epoch: 0..0x7FFFFFFFFFFFFFFF
        }
  @opaque t :: %__MODULE__{cell: :atomics.atomics_ref(), observer: pid()}

  @spec new() :: t()
  def new, do: %__MODULE__{cell: :atomics.new(@words, signed: false), observer: self()}

  @spec observer(t()) :: pid()
  def observer(%__MODULE__{observer: observer}), do: observer

  @spec seal(t(), ResourceLedger.t(), metadata()) :: :ok | {:error, atom()}
  def seal(%__MODULE__{observer: observer} = receipt, ledger, metadata) do
    if self() == observer do
      with {:ok, proof} <- settled(ledger),
           {:ok, words} <- encode(proof, metadata),
           :ok <- claim(receipt.cell) do
        Enum.each(Enum.with_index(words, 2), fn {word, index} ->
          :atomics.put(receipt.cell, index, word)
        end)

        # Atomic publication follows every payload write. A dying publisher in
        # state 1 leaves unsealed evidence, even if some/all payload is present.
        :atomics.put(receipt.cell, 1, 2)
        :ok
      end
    else
      {:error, :not_observer}
    end
  end

  @spec read(t()) :: :unsealed | {:sealed, terminal()} | {:error, :invalid_evidence}
  def read(%__MODULE__{cell: cell}) do
    case :atomics.get(cell, 1) do
      state when state in [0, 1] -> :unsealed
      2 -> decode(cell)
      _ -> {:error, :invalid_evidence}
    end
  catch
    :error, :badarg -> {:error, :invalid_evidence}
  end

  defp settled(ledger) do
    case ResourceLedger.proof(ledger) do
      {:ok, proof} -> {:ok, proof}
      {:pending, _} -> {:error, :resources_pending}
    end
  end

  defp claim(cell) do
    case :atomics.compare_exchange(cell, 1, 0, 1) do
      :ok -> :ok
      _ -> {:error, :already_sealing_or_sealed}
    end
  end

  defp encode(proof, %{setup: setup, failure: failure, epoch: epoch} = metadata)
       when map_size(metadata) == 3 and is_integer(epoch) and epoch >= 0 and epoch <= @max_epoch do
    with true <- valid_outcome?(setup, failure),
         {:ok, setup_code} <- Map.fetch(@setups, setup),
         {:ok, failure_code} <- Map.fetch(@failures, failure),
         {:ok, scope_code} <- Map.fetch(@scopes, proof.scope) do
      {:ok,
       [
         setup_code,
         scope_code,
         proof.roles,
         proof.observed_down,
         proof.losses,
         epoch,
         failure_code
       ]}
    else
      _ -> {:error, :invalid_metadata}
    end
  end

  defp encode(_, _), do: {:error, :invalid_metadata}

  defp decode(cell) do
    [setup, scope, roles, down, losses, epoch, failure] =
      Enum.map(2..@words, &:atomics.get(cell, &1))

    with {:ok, setup} <- decode_enum(@setups, setup),
         {:ok, scope} <- decode_enum(@scopes, scope),
         {:ok, failure} <- decode_enum(@failures, failure),
         true <- valid_outcome?(setup, failure),
         true <- roles in 0..31 and down == roles and losses in 0..31 and epoch <= @max_epoch do
      {:sealed,
       %{
         version: 1,
         scope: scope,
         setup: setup,
         setup_failure: failure,
         logical: :closed,
         cleanup: if(losses == 0, do: :confirmed, else: :unconfirmed),
         roles: roles,
         observed_down: down,
         losses: losses,
         epoch: epoch
       }}
    else
      _ -> {:error, :invalid_evidence}
    end
  end

  defp decode_enum(values, encoded) do
    case Enum.find(values, fn {_name, code} -> code == encoded end) do
      {name, _} -> {:ok, name}
      nil -> {:error, :invalid_evidence}
    end
  end

  defp valid_outcome?(:connected, :none), do: true
  defp valid_outcome?(:not_started, :none), do: true

  defp valid_outcome?(:failed, failure),
    do: failure in [:options, :connect, :tls, :timeout, :internal]

  defp valid_outcome?(:cancelled, failure), do: failure in [:cancelled, :timeout, :owner_down]
  defp valid_outcome?(_, _), do: false
end

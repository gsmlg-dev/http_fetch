defmodule SSL.Lifecycle.Receipt do
  @moduledoc false

  # Provider-internal storage, not an independently established cleanup proof.
  # Only the creating observer publishes. Readers trust payload words after seal.
  alias SSL.Lifecycle.{AuxiliaryLedger, ResourceLedger}

  @words 8
  @auxiliary_words 4
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
  @scopes %{dial: 1, upgrade: 2, layer: 3}
  @enforce_keys [:cell, :observer]
  @derive {Inspect, only: []}
  defstruct [:cell, :observer, :setup_phase, :auxiliary_cell]

  @type setup :: :not_started | :connected | :failed | :cancelled
  @type failure ::
          :none | :options | :connect | :tls | :timeout | :cancelled | :owner_down | :internal
  @type metadata :: %{setup: setup(), failure: failure(), epoch: 0..0x7FFFFFFFFFFFFFFF}
  @type primary_terminal :: %{
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
  @type extended_terminal :: %{
          version: 2,
          scope: ResourceLedger.scope(),
          setup: setup(),
          setup_failure: failure(),
          logical: :closed,
          cleanup: :confirmed | :unconfirmed,
          roles: ResourceLedger.role_mask(),
          observed_down: ResourceLedger.role_mask(),
          losses: ResourceLedger.role_mask(),
          epoch: 0..0x7FFFFFFFFFFFFFFF,
          auxiliary: %{roles: 0..3, observed_down: 0..3, losses: 0..7}
        }
  @type terminal :: primary_terminal() | extended_terminal()
  @opaque t :: %__MODULE__{
            cell: :atomics.atomics_ref(),
            observer: pid(),
            setup_phase: :atomics.atomics_ref(),
            auxiliary_cell: :atomics.atomics_ref() | nil
          }

  @spec new() :: t()
  def new do
    %__MODULE__{
      cell: :atomics.new(@words, signed: false),
      setup_phase: :atomics.new(1, signed: false),
      auxiliary_cell: :atomics.new(@auxiliary_words, signed: false),
      observer: self()
    }
  end

  @doc false
  def seal_setup_failure(%__MODULE__{observer: observer, setup_phase: cell})
      when observer == self() do
    case :atomics.compare_exchange(cell, 1, 0, 1) do
      :ok ->
        :atomics.put(cell, 1, 2)
        :ok

      _ ->
        {:error, :already_sealed}
    end
  end

  def seal_setup_failure(_), do: {:error, :not_observer}

  @doc false
  def setup_failure(%__MODULE__{setup_phase: cell}) do
    if :atomics.get(cell, 1) == 2, do: {:ok, %{phase: :tls_setup}}, else: :unknown
  catch
    :error, :badarg -> :unknown
  end

  def setup_failure(_), do: :unknown

  @doc false
  def seal_connect_failure(%__MODULE__{observer: observer, setup_phase: cell})
      when observer == self() do
    case :atomics.compare_exchange(cell, 1, 0, 3) do
      :ok ->
        :atomics.put(cell, 1, 4)
        :ok

      _ ->
        {:error, :already_sealed}
    end
  end

  def seal_connect_failure(_), do: {:error, :not_observer}

  @doc false
  def connect_failure(%__MODULE__{setup_phase: cell}) do
    if :atomics.get(cell, 1) == 4, do: {:ok, %{phase: :connect}}, else: :unknown
  catch
    :error, :badarg -> :unknown
  end

  def connect_failure(_), do: :unknown

  @doc false
  def valid?(%__MODULE__{observer: observer, cell: cell}),
    do: is_pid(observer) and is_reference(cell)

  def valid?(_), do: false

  @doc false
  @spec failure_tag(t()) :: reference()
  def failure_tag(%__MODULE__{cell: cell}), do: cell

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

  # The runtime must call this overload whenever the auxiliary reducer exists.
  # Both proofs settle before claiming publication, even with no admitted effect.
  # Never publish primary-only proof for an attempt that admitted auxiliary work.
  @spec seal(t(), ResourceLedger.t(), AuxiliaryLedger.t(), metadata()) ::
          :ok | {:error, atom()}
  def seal(%__MODULE__{observer: observer} = receipt, ledger, auxiliary, metadata) do
    if self() == observer do
      seal_combined(receipt, ledger, auxiliary, metadata)
    else
      {:error, :not_observer}
    end
  end

  # Existing eight-word handles can predate the optional sidecar fields.
  @type legacy_t :: %{
          required(:__struct__) => __MODULE__,
          required(:cell) => :atomics.atomics_ref(),
          required(:observer) => pid(),
          optional(:setup_phase) => :atomics.atomics_ref() | nil
        }

  @spec read(t() | legacy_t()) ::
          :unsealed | {:sealed, terminal()} | {:error, :invalid_evidence}
  def read(%{__struct__: __MODULE__, cell: cell} = receipt) do
    case :atomics.get(cell, 1) do
      state when state in [0, 1] -> :unsealed
      2 -> decode(cell)
      3 -> decode_extended(cell, Map.get(receipt, :auxiliary_cell))
      _ -> {:error, :invalid_evidence}
    end
  catch
    :error, :badarg -> {:error, :invalid_evidence}
  end

  defp seal_combined(receipt, ledger, auxiliary, metadata) do
    with {:ok, proof} <- settled(ledger),
         {:ok, auxiliary_proof} <- settled_auxiliary(auxiliary),
         {:ok, words} <- encode(proof, metadata) do
      if AuxiliaryLedger.admitted?(auxiliary) do
        publish_extended(receipt, words, auxiliary_proof)
      else
        seal(receipt, ledger, metadata)
      end
    end
  end

  defp settled_auxiliary(auxiliary) do
    case AuxiliaryLedger.proof(auxiliary) do
      {:ok, proof} -> {:ok, proof}
      {:pending, _} -> {:error, :auxiliary_pending}
    end
  end

  defp publish_extended(receipt, words, proof) do
    with :ok <- auxiliary_capacity(Map.get(receipt, :auxiliary_cell)),
         :ok <- claim(receipt.cell) do
      Enum.each(Enum.with_index(words, 2), fn {word, index} ->
        :atomics.put(receipt.cell, index, word)
      end)

      # The last extension word attests that no operation/close obligation is
      # unfinished. All extension words precede the sole final publication.
      payload = [proof.roles, proof.observed_down, proof.losses, 1]

      Enum.each(Enum.with_index(payload, 1), fn {word, index} ->
        :atomics.put(receipt.auxiliary_cell, index, word)
      end)

      # The old v1 reader rejects 3, rather than confirming clean primary bits.
      :atomics.put(receipt.cell, 1, 3)
      :ok
    end
  end

  defp auxiliary_capacity(cell) do
    if :atomics.info(cell).size == @auxiliary_words,
      do: :ok,
      else: {:error, :auxiliary_capacity_missing}
  catch
    :error, :badarg -> {:error, :auxiliary_capacity_missing}
  end

  defp decode_extended(cell, auxiliary_cell) do
    with :ok <- auxiliary_capacity(auxiliary_cell),
         {:sealed, primary} <- decode(cell),
         [roles, down, losses, 1] <-
           Enum.map(1..@auxiliary_words, &:atomics.get(auxiliary_cell, &1)),
         true <- roles in 0..3 and down == roles and losses in 0..7,
         true <- :erlang.band(losses, 3) == :erlang.band(losses, roles),
         true <- losses < 4 or roles in [2, 3] do
      cleanup =
        if primary.cleanup == :confirmed and losses == 0, do: :confirmed, else: :unconfirmed

      {:sealed,
       Map.merge(primary, %{
         version: 2,
         cleanup: cleanup,
         auxiliary: %{roles: roles, observed_down: down, losses: losses}
       })}
    else
      _ -> {:error, :invalid_evidence}
    end
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
         true <- roles in 0..31 and down == roles and losses in 0..31 and epoch <= @max_epoch,
         true <- scope != :layer or :erlang.band(:erlang.bor(roles, losses), 17) == 0 do
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

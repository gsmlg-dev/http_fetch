defmodule SSL.Lifecycle.Reader do
  @moduledoc false

  # Only receipt publication / observer absence are read here. Live setup and
  # authority snapshots belong to the future observer, not this internal reader.
  alias SSL.Lifecycle.Receipt

  @max_receive_timeout 0xFFFFFFFF
  @type pending :: %{receipt: :unsealed | :sealed, observer: :alive}
  @type loss :: :observer_unsealed | :invalid_evidence | :resource_evidence_lost

  @spec status(Receipt.t()) ::
          {:pending, pending()} | {:terminal, Receipt.terminal()} | {:unconfirmed, loss()}
  def status(receipt) do
    if Process.alive?(Receipt.observer(receipt)) do
      live_status(Receipt.read(receipt))
    else
      # Read AFTER observing absence. A pre-exit unsealed read can race the
      # observer's final publication and must not mask its completed seal.
      absent_status(Receipt.read(receipt))
    end
  catch
    :error, :badarg -> {:unconfirmed, :invalid_evidence}
  end

  @spec await(Receipt.t(), {:abs_ms, integer()}) ::
          {:ok, Receipt.terminal()}
          | {:pending, pending()}
          | {:unconfirmed, loss()}
          | {:error, :invalid_deadline}
  def await(receipt, {:abs_ms, deadline}) when is_integer(deadline) do
    observer = Receipt.observer(receipt)
    monitor = Process.monitor(observer)

    try do
      wait(receipt, observer, monitor, deadline)
    after
      Process.demonitor(monitor, [:flush])
    end
  catch
    :error, :badarg -> {:unconfirmed, :invalid_evidence}
  end

  def await(_, _), do: {:error, :invalid_deadline}

  defp wait(receipt, observer, monitor, deadline) do
    case status(receipt) do
      {:terminal, %{cleanup: :confirmed} = terminal} -> {:ok, terminal}
      {:terminal, %{cleanup: :unconfirmed}} -> {:unconfirmed, :resource_evidence_lost}
      {:unconfirmed, _} = result -> result
      {:pending, snapshot} -> wait_pending(receipt, observer, monitor, deadline, snapshot)
    end
  end

  defp wait_pending(receipt, observer, monitor, deadline, snapshot) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      {:pending, snapshot}
    else
      receive do
        {:DOWN, ^monitor, :process, ^observer, _reason} ->
          wait(receipt, observer, monitor, deadline)
      after
        min(remaining, @max_receive_timeout) -> wait(receipt, observer, monitor, deadline)
      end
    end
  end

  defp live_status(:unsealed), do: {:pending, %{receipt: :unsealed, observer: :alive}}
  defp live_status({:sealed, _}), do: {:pending, %{receipt: :sealed, observer: :alive}}
  defp live_status({:error, _}), do: {:unconfirmed, :invalid_evidence}

  defp absent_status(:unsealed), do: {:unconfirmed, :observer_unsealed}
  defp absent_status({:sealed, terminal}), do: {:terminal, terminal}
  defp absent_status({:error, _}), do: {:unconfirmed, :invalid_evidence}
end

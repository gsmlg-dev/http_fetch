defmodule HTTP.ClientCompletion do
  @moduledoc """
  Durable cleanup receipt returned by EventSource and WebSocket `completion/1`.

  A finite wait confirms tracked request resources have terminated or been
  handed off to their retained HTTP/2 owner. Healthy shared connections stay
  open. Logical close, protocol acknowledgements and process death alone do not
  establish cleanup. Receipts remain readable after the client exits; repeated
  and concurrent waits are safe. Lost evidence is reported as unconfirmed.

  This barrier does not certify native allocator or kernel memory reclamation,
  or remote receipt of application bytes. HTTP/3 retains its separate QUIC
  cleanup contract and is explicitly unsupported by this receipt.
  """
  @opaque t :: %__MODULE__{
            tracker: pid() | nil,
            latch: reference() | nil,
            unsupported: atom() | nil
          }
  defstruct [:tracker, :latch, :unsupported]

  @type result ::
          :ok
          | {:error, :cleanup_pending | :cleanup_unconfirmed | {:unsupported_completion, atom()}}

  @doc false
  def new(mode \\ :request) do
    {tracker, latch} = HTTP.RequestLifecycle.start(mode)
    %__MODULE__{tracker: tracker, latch: latch}
  end

  @doc false
  def unsupported(reason), do: %__MODULE__{unsupported: reason}

  @doc "Waits for cleanup using one finite timeout in milliseconds."
  @spec await(t(), non_neg_integer()) :: result()
  def await(receipt, timeout \\ 5_000)

  def await(%__MODULE__{unsupported: reason}, timeout)
      when reason != nil and is_integer(timeout) and timeout >= 0,
      do: {:error, {:unsupported_completion, reason}}

  def await(%__MODULE__{} = receipt, timeout) when is_integer(timeout) and timeout >= 0 do
    monitor = Process.monitor(receipt.tracker)
    deadline = System.monotonic_time(:millisecond) + timeout

    try do
      wait(receipt, monitor, deadline)
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp wait(receipt, monitor, deadline) do
    case {:atomics.get(receipt.latch, 1), Process.alive?(receipt.tracker)} do
      {2, false} ->
        :ok

      {3, _} ->
        {:error, :cleanup_unconfirmed}

      {_, false} ->
        # The tracker may seal between the latch read and the liveness check.
        if :atomics.get(receipt.latch, 1) == 2, do: :ok, else: {:error, :cleanup_unconfirmed}

      {_, true} ->
        wait_down(receipt, monitor, deadline)
    end
  end

  defp wait_down(receipt, monitor, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    if remaining == 0 do
      {:error, :cleanup_pending}
    else
      receive do
        {:DOWN, ^monitor, :process, _, _} -> wait(receipt, monitor, deadline)
      after
        min(remaining, 10) -> wait(receipt, monitor, deadline)
      end
    end
  end
end

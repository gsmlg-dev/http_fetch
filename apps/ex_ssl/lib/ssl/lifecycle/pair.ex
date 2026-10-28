defmodule SSL.Lifecycle.Pair do
  @moduledoc false
  alias SSL.Lifecycle

  defmodule Handle do
    @moduledoc false
    @derive {Inspect, only: []}
    @enforce_keys [:outer, :inner]
    defstruct [:outer, :inner]
    @opaque t :: %__MODULE__{outer: SSL.Lifecycle.Handle.t(), inner: SSL.Lifecycle.Handle.t()}
  end

  defmodule Lease do
    @moduledoc false
    @derive {Inspect, only: []}
    @enforce_keys [:handle, :outer, :inner]
    defstruct [:handle, :outer, :inner]

    @opaque t :: %__MODULE__{
              handle: Handle.t(),
              outer: SSL.Lifecycle.Lease.t(),
              inner: SSL.Lifecycle.Lease.t()
            }
  end

  defmodule Transfer do
    @moduledoc false
    @derive {Inspect, only: []}
    @enforce_keys [:handle, :outer, :inner]
    defstruct [:handle, :outer, :inner]

    @opaque t :: %__MODULE__{
              handle: Handle.t(),
              outer: SSL.Lifecycle.Transfer.t(),
              inner: SSL.Lifecycle.Transfer.t()
            }
  end

  def new(options) do
    with {:ok, outer, outer_lease} <- Lifecycle.new(options) do
      case Lifecycle.new(options) do
        {:ok, inner, inner_lease} ->
          handle = %Handle{outer: outer, inner: inner}
          {:ok, handle, %Lease{handle: handle, outer: outer_lease, inner: inner_lease}}

        error ->
          deadline = Keyword.fetch!(options, :deadline)
          deadline = if deadline == :infinity, do: control(), else: deadline
          _ = Lifecycle.cancel(outer_lease, deadline)
          _ = Lifecycle.await(outer, deadline)
          error
      end
    end
  end

  def layers({%Handle{} = handle, %Lease{handle: same} = lease}) when handle === same do
    with {:ok, outer, outer_lease} <- Lifecycle.descriptor({handle.outer, lease.outer}),
         {:ok, inner, inner_lease} <- Lifecycle.descriptor({handle.inner, lease.inner}),
         true <- outer !== inner do
      {:ok, %{outer: {outer, outer_lease}, inner: {inner, inner_lease}}}
    else
      _ -> {:error, :invalid_lifecycle}
    end
  end

  def layers(_), do: {:error, :invalid_lifecycle}

  def status(handle), do: status(handle, control())

  def status(%Handle{} = handle, {:abs_ms, expiry} = deadline) when is_integer(expiry) do
    outer = Lifecycle.status(handle.outer, deadline)
    inner = Lifecycle.status(handle.inner, deadline)
    aggregate(outer, inner, true)
  end

  def status(_handle, _deadline), do: {:error, :invalid_deadline}

  def await(%Handle{} = handle, {:abs_ms, expiry} = deadline) when is_integer(expiry) do
    outer = await_status(Lifecycle.await(handle.outer, deadline))
    inner = await_status(Lifecycle.await(handle.inner, deadline))

    case aggregate(outer, inner, false) do
      {:terminal, receipt} -> {:ok, receipt}
      result -> result
    end
  end

  def await(_handle, _deadline), do: {:error, :invalid_deadline}

  def cancel(%Lease{} = lease, {:abs_ms, expiry} = deadline) when is_integer(expiry) do
    # Always retain and attempt both obligations, including after partial transfer.
    outer = Lifecycle.cancel(lease.outer, deadline)
    inner = Lifecycle.cancel(lease.inner, deadline)

    case {outer, inner} do
      {:ok, :ok} -> :ok
      {{:error, reason}, _} -> {:error, {:outer, reason}}
      {_, {:error, reason}} -> {:error, {:inner, reason}}
    end
  end

  def cancel(_lease, _deadline), do: {:error, :invalid_deadline}

  def offer(%Lease{} = lease, %{controller: controller} = target, deadline) do
    with {:ok, outer} <- Lifecycle.offer_controller(lease.outer, controller, deadline),
         {:ok, inner} <- Lifecycle.offer(lease.inner, target, deadline) do
      {:ok, %Transfer{handle: lease.handle, outer: outer, inner: inner}}
    end
  end

  def offer(_lease, _target, _deadline), do: {:error, :invalid_target}

  def accept(%Transfer{} = transfer, deadline) do
    # Accept the outer controller first. Until BOTH ACKs commit, the source still
    # holds the inner lease; retiring it also kills the outer application owner.
    with {:ok, outer} <- accept_layer(:outer, transfer.outer, deadline),
         {:ok, inner} <- accept_layer(:inner, transfer.inner, deadline) do
      {:ok, %Lease{handle: transfer.handle, outer: outer, inner: inner}}
    end
  end

  defp accept_layer(layer, transfer, deadline) do
    case Lifecycle.accept(transfer, deadline) do
      {:error, reason} -> {:error, {layer, reason}}
      accepted -> accepted
    end
  end

  defp aggregate({:unconfirmed, reason}, _inner, _numeric),
    do: {:unconfirmed, {:outer, reason}}

  defp aggregate(_outer, {:unconfirmed, reason}, _numeric),
    do: {:unconfirmed, {:inner, reason}}

  defp aggregate({outer_state, outer}, {inner_state, inner}, numeric)
       when outer_state in [:pending, :terminal] and inner_state in [:pending, :terminal] do
    terminal? = outer_state == :terminal and inner_state == :terminal
    layers = %{outer: outer, inner: inner}

    evidence = %{
      scope: :pair,
      cleanup: if(terminal?, do: :confirmed, else: :pending),
      layers: layers,
      setup: setup(Map.get(outer, :setup, :pending), Map.get(inner, :setup, :pending)),
      epoch: {outer[:epoch], inner[:epoch]},
      transfer_nonce: {outer[:transfer_nonce], inner[:transfer_nonce]},
      transfer: transfer_state(outer[:transfer], inner[:transfer]),
      bound?: outer[:bound?] == true and inner[:bound?] == true
    }

    evidence =
      if numeric and not terminal?,
        do:
          Map.put(evidence, :provider_resources, counts(outer_state, outer, inner_state, inner)),
        else: evidence

    {if(terminal?, do: :terminal, else: :pending), evidence}
  end

  defp aggregate(_outer, _inner, _numeric), do: {:unconfirmed, :invalid_evidence}

  defp counts(outer_state, outer, inner_state, inner) do
    with outer when is_map(outer) <- counts(outer_state, outer),
         inner when is_map(inner) <- counts(inner_state, inner),
         do: Map.new(outer, fn {key, value} -> {key, value + Map.fetch!(inner, key)} end)
  end

  defp counts(:terminal, _receipt),
    do: %{processes: 0, observers: 0, tcp_sockets: 0, data_resources: 0}

  defp counts(:pending, evidence), do: evidence[:provider_resources]

  defp setup(same, same), do: same
  defp setup(:failed, _), do: :failed
  defp setup(_, :failed), do: :failed
  defp setup(:cancelled, _), do: :cancelled
  defp setup(_, :cancelled), do: :cancelled
  defp setup(_, _), do: :pending

  defp transfer_state(same, same), do: same
  defp transfer_state(:cancelled, _), do: :cancelled
  defp transfer_state(_, :cancelled), do: :cancelled
  defp transfer_state(:expired, _), do: :expired
  defp transfer_state(_, :expired), do: :expired
  defp transfer_state(:unknown, _), do: :unknown
  defp transfer_state(_, :unknown), do: :unknown
  defp transfer_state(_, _), do: :pending

  defp await_status({:ok, evidence}), do: {:terminal, evidence}
  defp await_status(result), do: result
  defp control, do: {:abs_ms, System.monotonic_time(:millisecond) + 250}
end

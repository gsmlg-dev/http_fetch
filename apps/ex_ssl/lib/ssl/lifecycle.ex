defmodule SSL.Lifecycle do
  @moduledoc """
  Provider lifecycle evidence and transferable cancellation authority.

  Create a handle before connecting and pass `{handle, lease}` under
  `ex_ssl: [lifecycle: ...]`. A successful cancel accepts retirement; only a
  confirmed await receipt establishes local resource cleanup. Control deadlines
  are finite absolute monotonic milliseconds. Handles contain no cancellation
  authority and remain readable after the provider exits.
  """
  alias SSL.Lifecycle.{Observer, Reader, Receipt}

  defmodule Handle do
    @moduledoc false
    @derive {Inspect, only: []}
    @enforce_keys [:receipt]
    defstruct [:receipt]
    @opaque t :: %__MODULE__{receipt: Receipt.t()}
  end

  defmodule Lease do
    @moduledoc false
    @derive {Inspect, only: []}
    @enforce_keys [:handle, :authority]
    defstruct [:handle, :authority]
    @opaque t :: %__MODULE__{handle: Handle.t(), authority: tuple()}
  end

  defmodule Transfer do
    @moduledoc false
    @derive {Inspect, only: []}
    @enforce_keys [:handle, :ticket]
    defstruct [:handle, :ticket]
    @opaque t :: %__MODULE__{handle: Handle.t(), ticket: tuple()}
  end

  @spec new(keyword()) :: {:ok, Handle.t(), Lease.t()} | {:error, atom()}
  def new(options) do
    with true <- Keyword.keyword?(options),
         true <- Enum.sort(Keyword.keys(options)) == [:controller, :deadline],
         controller when is_pid(controller) <- options[:controller],
         true <- node(controller) == node(),
         :ok <- setup_deadline(options[:deadline]),
         {:ok, receipt, authority} <- start(controller, options[:deadline]) do
      handle = %Handle{receipt: receipt}
      {:ok, handle, %Lease{handle: handle, authority: authority}}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_options}
    end
  end

  @doc """
  Reads authenticated fatal setup-phase evidence separately from resource cleanup.

  A proven result means the original Connection accepted ServerHello and committed
  a fatal setup failure within its original deadline. The fixed result survives
  provider exit. Missing or uncommitted evidence returns `:unknown`; cancellation,
  timeout, and a successful handshake alone do not establish this phase.
  Use `await/2` separately to establish local resource cleanup.
  """
  @spec setup_failure(Handle.t()) :: {:ok, %{phase: :tls_setup}} | :unknown
  def setup_failure(%Handle{receipt: receipt}), do: Receipt.setup_failure(receipt)
  def setup_failure(_), do: :unknown

  @spec status(Handle.t()) :: {:pending, map()} | {:terminal, map()} | {:unconfirmed, atom()}
  def status(%Handle{receipt: receipt}) do
    case Reader.status(receipt) do
      {:pending, evidence} ->
        case Observer.snapshot(receipt, control()) do
          {:ok, snapshot} -> {:pending, Map.merge(evidence, snapshot)}
          _ -> reconcile(receipt, evidence)
        end

      result ->
        result
    end
  end

  def status(_), do: {:unconfirmed, :invalid_evidence}

  @doc "Observes exact live resource counts within one finite absolute deadline."
  @spec status(Handle.t(), {:abs_ms, integer()}) :: term()
  def status(%Handle{receipt: receipt}, {:abs_ms, expiry} = deadline) when is_integer(expiry) do
    case Reader.status(receipt) do
      {:pending, evidence} ->
        case Observer.snapshot_resources(receipt, deadline) do
          {:ok, snapshot} -> {:pending, Map.merge(evidence, snapshot)}
          _ -> reconcile_resources(receipt, evidence)
        end

      result ->
        result
    end
  end

  def status(%Handle{}, _), do: {:error, :invalid_deadline}
  def status(_, _), do: {:unconfirmed, :invalid_evidence}

  @spec await(Handle.t(), {:abs_ms, integer()}) :: term()
  def await(%Handle{receipt: receipt}, deadline) do
    case Reader.await(receipt, deadline) do
      {:pending, evidence} ->
        case Observer.snapshot(receipt, deadline) do
          {:ok, snapshot} -> {:pending, Map.merge(evidence, snapshot)}
          _ -> {:pending, evidence}
        end

      result ->
        result
    end
  end

  def await(_, _), do: {:unconfirmed, :invalid_evidence}

  @spec cancel(Lease.t(), {:abs_ms, integer()}) :: :ok | {:error, atom()}
  def cancel(%Lease{handle: %Handle{receipt: receipt}, authority: authority}, deadline),
    do: Observer.cancel(receipt, authority, deadline)

  def cancel(_, _), do: {:error, :invalid_lease}

  @spec offer(Lease.t(), %{controller: pid(), owner: pid()}, {:abs_ms, integer()}) :: term()
  def offer(
        %Lease{handle: %Handle{receipt: receipt} = handle, authority: authority},
        target,
        deadline
      ) do
    case Observer.offer(receipt, authority, target, deadline) do
      {:ok, ticket} -> {:ok, %Transfer{handle: handle, ticket: ticket}}
      error -> error
    end
  end

  def offer(_, _, _), do: {:error, :invalid_lease}

  @spec accept(Transfer.t(), {:abs_ms, integer()}) :: term()
  def accept(%Transfer{handle: %Handle{receipt: receipt} = handle, ticket: ticket}, deadline) do
    case Observer.accept(receipt, ticket, deadline) do
      {:ok, authority} -> {:ok, %Lease{handle: handle, authority: authority}}
      error -> error
    end
  end

  def accept(_, _), do: {:error, :invalid_transfer}

  @doc false
  def descriptor({%Handle{} = handle, %Lease{handle: same} = lease}) when handle === same,
    do: {:ok, handle, lease}

  def descriptor(_), do: {:error, :invalid_lifecycle}

  defp reconcile(receipt, evidence) do
    case Reader.status(receipt) do
      {:pending, _} -> {:pending, Map.put(evidence, :snapshot, :unavailable)}
      result -> result
    end
  end

  defp reconcile_resources(receipt, evidence) do
    case reconcile(receipt, evidence) do
      {:pending, evidence} -> {:pending, Map.put(evidence, :provider_resources, nil)}
      result -> result
    end
  end

  defp setup_deadline(:infinity), do: :ok

  defp setup_deadline({:abs_ms, deadline}) when is_integer(deadline) do
    if deadline > now(), do: :ok, else: {:error, :deadline_exceeded}
  end

  defp setup_deadline(_), do: {:error, :invalid_deadline}

  # Application/supervisor admission is control work only. Bound it before any
  # data permit exists; the observer always monitors the actual controller.
  defp start(controller, deadline) do
    expiry =
      if deadline == :infinity, do: now() + 1_000, else: min(now() + 1_000, elem(deadline, 1))

    reply = :erlang.alias()

    {worker, monitor} =
      spawn_monitor(fn ->
        {:ok, timer} = :timer.kill_after(max(1, expiry - now()), self())

        try do
          result =
            with {:ok, _} <- Application.ensure_all_started(:ex_ssl),
                 do: Observer.start(controller, deadline)

          send(reply, {reply, result})
        after
          :timer.cancel(timer)
        end
      end)

    try do
      receive do
        {^reply, result} -> result
        {:DOWN, ^monitor, :process, ^worker, _} -> {:error, :acceptance_unconfirmed}
      after
        max(0, expiry - now()) -> {:error, :acceptance_unconfirmed}
      end
    after
      Process.exit(worker, :kill)
      Process.demonitor(monitor, [:flush])
      :erlang.unalias(reply)
    end
  end

  defp control, do: {:abs_ms, now() + 250}
  defp now, do: System.monotonic_time(:millisecond)
end

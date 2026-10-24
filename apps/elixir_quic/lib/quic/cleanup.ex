defmodule Quic.Cleanup do
  @moduledoc """
  Retained cleanup evidence for one exclusive standalone client endpoint.

  Construct this scope before calling `Quic.client/1` with its birth lease. A
  successful receipt joins every enrolled actor and the actual UDP Port. It
  does not establish peer delivery or resolve an unknown operation outcome.
  Handles remain readable after the observer exits, within the same VM.
  """
  alias Quic.Cleanup.Observer

  @observation_cap 5_000

  defmodule Handle do
    @moduledoc false
    @enforce_keys [:observer, :scope, :receipt]
    defstruct [:observer, :scope, :receipt]
    @opaque t :: %__MODULE__{}
  end

  defmodule Lease do
    @moduledoc false
    @enforce_keys [:handle, :secret, :retirement]
    defstruct [:handle, :secret, :retirement]
    @opaque t :: %__MODULE__{}
  end

  defmodule Permit do
    @moduledoc false
    @enforce_keys [:lease, :ref, :deadline]
    defstruct [:lease, :ref, :deadline]
    @opaque t :: %__MODULE__{}
  end

  @type deadline :: {:abs_ms, integer()}

  @spec new(keyword()) :: {:ok, Handle.t(), Lease.t()} | {:error, term()}
  def new(opts \\ []) do
    owner = Keyword.get(opts, :owner, self())

    if is_pid(owner) and node(owner) == node() do
      receipt = :atomics.new(13, signed: true)
      scope = make_ref()
      secret = make_ref()

      case GenServer.start(Observer, {owner, scope, secret, receipt}) do
        {:ok, observer} ->
          handle = %Handle{observer: observer, scope: scope, receipt: receipt}
          # Only the write lease retains this authenticated mutation capability.
          # A read handle contains neither the secret nor the closure.
          retirement = fn
            ^handle, ^secret -> fence(receipt)
            _, _ -> {:error, :invalid_lease}
          end

          {:ok, handle, %Lease{handle: handle, secret: secret, retirement: retirement}}

        {:error, _} = error ->
          error
      end
    else
      {:error, :invalid_owner}
    end
  end

  @spec status(Handle.t()) :: tuple()
  def status(%Handle{} = handle) do
    if Process.alive?(handle.observer) do
      {:pending, snapshot(handle)}
    else
      # The observer is joined before reading its immutable payload and seal.
      seal = :atomics.get(handle.receipt, 1)
      snapshot = snapshot(handle)

      case seal do
        1 -> {:ok, Map.put(snapshot, :cleanup, :confirmed)}
        2 -> unconfirmed(snapshot, reason(:atomics.get(handle.receipt, 9)))
        0 -> unconfirmed(snapshot, :observer_lost)
      end
    end
  end

  @spec await(Handle.t(), deadline()) :: tuple()
  def await(%Handle{} = handle, {:abs_ms, deadline}) when is_integer(deadline) do
    case status(handle) do
      {:pending, _} = pending ->
        remaining = deadline - now()

        if remaining <= 0 do
          pending
        else
          monitor = Process.monitor(handle.observer)

          receive do
            {:DOWN, ^monitor, :process, _, _} -> status(handle)
          after
            remaining ->
              Process.demonitor(monitor, [:flush])
              status(handle)
          end
        end

      terminal ->
        terminal
    end
  end

  @spec retire(Lease.t(), deadline()) :: tuple()
  def retire(%Lease{handle: handle} = lease, {:abs_ms, deadline} = bound)
      when is_integer(deadline) do
    # The authenticated latch closes admission before returning, even when the
    # observer is paused. Its first trigger also fixes the observation cap.
    if lease.retirement.(handle, lease.secret) == :ok,
      do: send(handle.observer, {:retire, lease.secret})

    await(handle, bound)
  end

  @doc false
  def reserve(%Lease{} = lease, role, {:abs_ms, deadline} = bound)
      when role in [:endpoint, :io, :connection, :port] and is_integer(deadline) do
    call(lease, {:reserve, role, deadline}, bound)
  end

  @doc false
  def enroll(%Permit{lease: lease, ref: ref}, resource) do
    # Late identities must still join the graph, but receive no effect grant.
    call(lease, {:enroll, ref, resource}, {:abs_ms, now() + 1_000})
  end

  @doc false
  def no_birth(%Permit{lease: lease, ref: ref}) do
    call(lease, {:no_birth, ref}, {:abs_ms, now() + 1_000})
  end

  @doc false
  def authorize(nil), do: :ok
  def authorize(%Lease{} = lease), do: call(lease, :authorize, {:abs_ms, now() + 1_000})

  @doc false
  def monitor(nil), do: nil
  def monitor(%Lease{handle: handle}), do: Process.monitor(handle.observer)

  @doc false
  def lease(nil), do: nil
  def lease(%Permit{lease: lease}), do: lease

  @doc "Retain an operation intent before its native call; never replay an unknown call."
  def operation(%Lease{} = lease, target, ref, kind, {:abs_ms, deadline} = bound)
      when is_reference(ref) and is_integer(deadline) do
    call(lease, {:operation, target, ref, kind, deadline}, bound)
  end

  @doc "Record a known return from the original operation producer."
  def resolved(%Permit{lease: lease, ref: ref}) do
    call(lease, {:operation_result, ref, :resolved}, {:abs_ms, now() + 1_000})
  end

  @doc "Retain that the original operation's result is unknown, independently of cleanup."
  def indeterminate(%Permit{lease: lease, ref: ref}) do
    call(lease, {:operation_result, ref, :indeterminate}, {:abs_ms, now() + 1_000})
  end

  @doc false
  def deadline(opts) do
    case Keyword.get(opts, :deadline) do
      {:abs_ms, deadline} when is_integer(deadline) -> {:abs_ms, deadline}
      _ -> {:abs_ms, now() + Keyword.get(opts, :timeout, 5_000)}
    end
  end

  defp call(%Lease{handle: handle, secret: secret} = lease, request, {:abs_ms, deadline}) do
    remaining = deadline - now()

    if remaining <= 0 do
      {:error, :deadline_expired}
    else
      try do
        case GenServer.call(handle.observer, {secret, request}, remaining) do
          {:permit, ref} -> {:ok, %Permit{lease: lease, ref: ref, deadline: deadline}}
          result -> result
        end
      catch
        :exit, _ -> {:error, :cleanup_unavailable}
      end
    end
  end

  @doc false
  def fence(receipt) do
    :atomics.compare_exchange(receipt, 8, 0, elapsed() + @observation_cap)
    :ok
  end

  @doc false
  def fenced?(receipt), do: :atomics.get(receipt, 8) != 0

  @doc false
  def cap_remaining(receipt), do: :atomics.get(receipt, 8) - elapsed()

  # Normalize signed VM monotonic time so zero remains an unambiguous latch
  # sentinel; the stored cap still uses only the VM's monotonic clock.
  defp elapsed do
    now() - System.convert_time_unit(:erlang.system_info(:start_time), :native, :millisecond)
  end

  defp snapshot(handle) do
    %{
      version: 1,
      scope: :exclusive_endpoint,
      generation: handle.scope,
      admission:
        if(:atomics.get(handle.receipt, 2) == 0 and :atomics.get(handle.receipt, 8) == 0,
          do: :open,
          else: :closed
        ),
      enrolled: :atomics.get(handle.receipt, 3),
      down: :atomics.get(handle.receipt, 4),
      unresolved_births: :atomics.get(handle.receipt, 5),
      unresolved_operations: :atomics.get(handle.receipt, 6),
      native_outcome:
        if(:atomics.get(handle.receipt, 7) == 0, do: :resolved, else: :indeterminate),
      roles: %{
        endpoint: :atomics.get(handle.receipt, 10),
        io: :atomics.get(handle.receipt, 11),
        port: :atomics.get(handle.receipt, 12),
        connection: :atomics.get(handle.receipt, 13)
      }
    }
  end

  defp unconfirmed(snapshot, reason),
    do: {:error, {:cleanup_unconfirmed, reason}, Map.put(snapshot, :cleanup, :unconfirmed)}

  defp reason(1), do: :birth_unresolved
  defp reason(2), do: :observation_cap
  defp reason(3), do: :unsupported_native_socket
  defp reason(_), do: :observer_lost
  defp now, do: System.monotonic_time(:millisecond)
end

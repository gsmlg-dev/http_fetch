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
    @type t :: Quic.Cleanup.handle()
  end

  defmodule Lease do
    @moduledoc false
    @enforce_keys [:handle, :secret, :retirement]
    defstruct [:handle, :secret, :retirement]
    @type t :: Quic.Cleanup.lease()
  end

  defmodule Permit do
    @moduledoc false
    @enforce_keys [:lease, :ref, :deadline]
    defstruct [:lease, :ref, :deadline]
    @type t :: Quic.Cleanup.permit()
  end

  # The facade constructs and interprets these values; callers retain opaque aliases.
  @opaque handle :: %Handle{observer: pid(), scope: reference(), receipt: :atomics.atomics_ref()}
  @opaque lease :: %Lease{
            handle: handle(),
            secret: reference(),
            retirement: (handle(), reference() -> :ok | {:error, :invalid_lease})
          }
  @opaque permit :: %Permit{lease: lease(), ref: reference(), deadline: integer()}
  @type snapshot :: %{
          version: 1,
          scope: :exclusive_endpoint,
          generation: reference(),
          admission: :open | :closed,
          enrolled: integer(),
          down: integer(),
          unresolved_births: integer(),
          unresolved_operations: integer(),
          native_outcome: :resolved | :indeterminate,
          roles: %{endpoint: integer(), io: integer(), port: integer(), connection: integer()}
        }
  @type terminal_snapshot(cleanup) :: %{
          version: 1,
          scope: :exclusive_endpoint,
          generation: reference(),
          admission: :open | :closed,
          enrolled: integer(),
          down: integer(),
          unresolved_births: integer(),
          unresolved_operations: integer(),
          native_outcome: :resolved | :indeterminate,
          roles: %{endpoint: integer(), io: integer(), port: integer(), connection: integer()},
          cleanup: cleanup
        }
  @type result ::
          {:pending, snapshot()}
          | {:ok, terminal_snapshot(:confirmed)}
          | {:error,
             {:cleanup_unconfirmed,
              :birth_unresolved | :observation_cap | :observer_lost | :unsupported_native_socket},
             terminal_snapshot(:unconfirmed)}

  @doc false
  @spec observer(Handle.t()) :: pid()
  def observer(%Handle{observer: observer}), do: observer

  @type deadline :: {:abs_ms, integer()}
  @type descriptor :: %{handle: handle(), lease: lease()}

  @doc false
  @spec descriptor(term()) :: {:ok, descriptor()} | {:error, :invalid_cleanup_descriptor}
  def descriptor(%{handle: %Handle{} = handle, lease: %Lease{handle: handle} = lease}),
    do: {:ok, %{handle: handle, lease: lease}}

  def descriptor(_), do: {:error, :invalid_cleanup_descriptor}

  @doc false
  @spec retire_descriptor(term(), deadline()) :: result() | :ok
  def retire_descriptor(%{lease: %Lease{} = lease}, bound), do: retire(lease, bound)
  def retire_descriptor(_, _), do: :ok

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

  @spec status(Handle.t()) :: result()
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

  @spec await(Handle.t(), deadline()) :: result()
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

  @spec retire(Lease.t(), deadline()) :: result()
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
    _ = :atomics.compare_exchange(receipt, 8, 0, elapsed() + @observation_cap)
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

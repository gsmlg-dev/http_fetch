defmodule Quic.Runtime do
  @moduledoc """
  Small data contracts separating pure transitions from runtime IO.
  """

  defmodule Datagram do
    @moduledoc false
    @enforce_keys [:bytes, :remote, :received_at, :generation]
    defstruct [:bytes, :remote, :local, :received_at, :generation]

    @type t :: %__MODULE__{
            bytes: binary(),
            remote: term(),
            local: term() | nil,
            received_at: integer(),
            generation: non_neg_integer()
          }
  end

  defmodule Generation do
    @moduledoc false
    @enforce_keys [:value]
    defstruct [:value]
    @type t :: %__MODULE__{value: non_neg_integer()}
  end

  defmodule SendReceipt do
    @moduledoc false
    @enforce_keys [:ref, :generation, :status]
    defstruct [:ref, :generation, :status, :completed_at, :error]
    @type status :: :queued | :sent | :failed | :stale
  end

  defmodule TimerToken do
    @moduledoc false
    @enforce_keys [:ref, :generation, :deadline]
    defstruct [:ref, :generation, :deadline]
  end

  defmodule ConnectionHandle do
    @moduledoc false
    @enforce_keys [:id, :generation]
    defstruct [:id, :generation]
    @type t :: %__MODULE__{id: pid(), generation: reference()}
  end

  defmodule StreamHandle do
    @moduledoc false
    @enforce_keys [:connection, :id]
    defstruct [:connection, :id]
    @type t :: %__MODULE__{connection: Quic.Runtime.ConnectionHandle.t(), id: non_neg_integer()}
  end

  defmodule VirtualClock do
    @moduledoc """
    Deterministic monotonic clock for pure engine tests.
    """
    def new(now \\ 0), do: %{now: now}
    def now(%{now: now}), do: now

    def advance(clock, delta) when is_integer(delta) and delta >= 0,
      do: %{clock | now: clock.now + delta}
  end

  defmodule IO do
    @moduledoc """
    Legacy behaviour for externally owned sockets and deterministic tests.
    Successful sends return actual completion time in monotonic microseconds,
    matching `Quic.IO`.
    """
    @callback send(term(), binary(), term()) :: {:ok, integer()} | {:error, term()}
    @callback monotonic_time() :: integer()
  end
end

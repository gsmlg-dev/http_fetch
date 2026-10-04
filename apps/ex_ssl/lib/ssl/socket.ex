defmodule SSL.Socket do
  @moduledoc "An opaque handle to one ex_ssl connection. Contains no TLS key material."
  @derive {Inspect, only: [:pid, :ref]}
  @enforce_keys [:pid, :ref, :status]
  defstruct [:pid, :ref, :status]
  @opaque t :: %__MODULE__{pid: pid(), ref: reference(), status: reference()}

  @doc false
  def terminal_error(%__MODULE__{status: status}) do
    if :atomics.get(status, 1) == 1, do: :closed, else: :econnreset
  end

  @doc false
  def mark_terminal(%__MODULE__{status: status}, orderly?) do
    _ = :atomics.compare_exchange(status, 1, 0, if(orderly?, do: 1, else: 2))
    :ok
  end
end

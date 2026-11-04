defmodule SSL.Socket do
  @moduledoc "An opaque handle to one ex_ssl connection. Contains no TLS key material."
  @derive {Inspect, only: [:pid, :ref]}
  @enforce_keys [:pid, :ref, :status]
  defstruct [:pid, :ref, :status]
  @opaque t :: %__MODULE__{pid: pid(), ref: reference(), status: :atomics.atomics_ref()}

  @doc false
  @spec new(pid(), reference(), :atomics.atomics_ref()) :: t()
  def new(pid, ref, status) when is_pid(pid) and is_reference(ref) do
    _ = :atomics.get(status, 1)
    %__MODULE__{pid: pid, ref: ref, status: status}
  end

  @doc false
  # Shape validation does not authenticate a handle; the connection checks its reference.
  @spec fetch(term()) :: {:ok, t()} | {:error, :badarg}
  def fetch(%__MODULE__{pid: pid, ref: ref, status: status} = socket)
      when is_pid(pid) and is_reference(ref) do
    _ = :atomics.get(status, 1)
    {:ok, socket}
  rescue
    ArgumentError -> {:error, :badarg}
  end

  def fetch(_), do: {:error, :badarg}

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

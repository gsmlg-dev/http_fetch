defmodule HTTP.WebTransport.Promise do
  @moduledoc """
  Promise-like handle for WebTransport lifecycle states.

  The promise is resolved by the owning `HTTP.WebTransport.Session` process.
  Use `await/2` to block until the value is resolved or rejected.
  """

  defstruct [:pid, :kind]

  @type kind :: :ready | :closed | :draining
  @type t :: %__MODULE__{pid: pid(), kind: kind()}

  @spec await(t(), timeout()) :: :ok | {:ok, term()} | {:error, term()}
  def await(%__MODULE__{pid: pid, kind: kind}, timeout \\ :infinity) when is_pid(pid) do
    GenServer.call(pid, {:await, kind}, timeout)
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, _reason -> {:error, :closed}
  end
end

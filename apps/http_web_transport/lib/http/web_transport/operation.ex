defmodule HTTP.WebTransport.Operation do
  @moduledoc false

  def call(pid, request, timeout \\ 5_000) do
    ref = make_ref()
    deadline = System.monotonic_time(:millisecond) + timeout

    try do
      GenServer.call(pid, {:operation, ref, deadline, request}, timeout)
    catch
      :exit, {:timeout, _} -> {:error, {:indeterminate_operation, ref}}
      :exit, {:noproc, _} -> {:error, :closed}
      :exit, _ -> {:error, {:indeterminate_operation, ref}}
    end
  end
end

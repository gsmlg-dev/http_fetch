defmodule SSL.Lifecycle.Bootstrap do
  @moduledoc false

  # Control-only proxy: the public supervisor API has an infinite admission wait.
  # No TLS/data work may occur before the resulting reservation is bound. The
  # independent kill timer also bounds this proxy if its caller dies while waiting.
  @spec start(pid(), :infinity | {:abs_ms, integer()}, :dial | :upgrade, integer()) ::
          {:ok, pid()} | {:error, atom()}
  def start(controller, deadline, scope, expiry) do
    reply = :erlang.alias()

    {worker, monitor} =
      spawn_monitor(fn ->
        {:ok, timer} = :timer.kill_after(max(1, expiry - now()), self())

        try do
          result = launch(controller, deadline, scope)
          send(reply, {reply, result})
        after
          :timer.cancel(timer)
        end
      end)

    try do
      await(worker, monitor, reply, expiry)
    after
      Process.exit(worker, :kill)
      Process.demonitor(monitor, [:flush])
      :erlang.unalias(reply)

      receive do
        {^reply, _result} -> :ok
      after
        0 -> :ok
      end
    end
  end

  defp launch(controller, deadline, scope) do
    case DynamicSupervisor.start_child(
           SSL.Lifecycle.ObserverSupervisor,
           {SSL.Lifecycle.Observer, {controller, deadline, scope}}
         ) do
      {:ok, pid} -> {:ok, pid}
      {:error, _} -> {:error, :observer_start_failed}
    end
  catch
    :exit, _ -> {:error, :observer_start_failed}
  end

  defp await(worker, monitor, reply, expiry) do
    receive do
      {^reply, result} -> await_down(worker, monitor, result, expiry)
      {:DOWN, ^monitor, :process, ^worker, _} -> {:error, :acceptance_unconfirmed}
    after
      max(0, expiry - now()) -> {:error, :acceptance_unconfirmed}
    end
  end

  defp await_down(worker, monitor, result, expiry) do
    receive do
      {:DOWN, ^monitor, :process, ^worker, :normal} -> result
      {:DOWN, ^monitor, :process, ^worker, _} -> {:error, :acceptance_unconfirmed}
    after
      max(0, expiry - now()) -> {:error, :acceptance_unconfirmed}
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end

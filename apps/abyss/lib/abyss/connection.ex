defmodule Abyss.Connection do
  @moduledoc """
  Starts one execution process per admitted datagram under the connection
  supervisor. Capacity failures drop new work immediately; no retry process,
  delayed admission, or resend is created. Socket ownership stays with the
  listener. Acceptance and termination accounting are owned by its monitor.
  """

  @doc """
  Starts a handler and returns its actual pid. The internal `:deferred`
  packet sentinel starts without delivery; the listener sends the reserved
  packet only after checking its generation and admission deadline.
  """
  @spec start(
          Supervisor.supervisor(),
          pid(),
          Abyss.Transport.socket(),
          term(),
          Abyss.ServerConfig.t(),
          Abyss.Telemetry.t()
        ) ::
          {:ok, pid()} | :ignore | {:error, term()}
  def start(sup_pid, listener_pid, socket, recv_data, config, span) do
    args = {span, config, listener_pid, socket}

    child_spec =
      {config.handler_module, args}
      |> Supervisor.child_spec(shutdown: config.shutdown_timeout)
      |> Map.put(
        :start,
        {__MODULE__, :guarded_start, [config.handler_module, args, listener_pid, self()]}
      )

    case DynamicSupervisor.start_child(Abyss.Server.connection_sup_pid(sup_pid), child_spec) do
      {:ok, pid} ->
        deliver(pid, socket, recv_data)

      {:ok, pid, _info} ->
        deliver(pid, socket, recv_data)

      {:error, :max_children} ->
        :telemetry.execute([:abyss, :connection, :limit_exceeded], %{retries_attempted: 0}, %{
          listener_pid: listener_pid,
          socket: socket
        })

        {:error, :too_many_connections}

      other ->
        other
    end
  end

  @doc false
  def guarded_start(module, args, listener_pid, starter_pid) do
    case module.start_link(args) do
      {:ok, pid} = result -> validate_generation(result, pid, listener_pid, starter_pid)
      {:ok, pid, _info} = result -> validate_generation(result, pid, listener_pid, starter_pid)
      other -> other
    end
  end

  defp validate_generation(result, pid, listener_pid, starter_pid) do
    if Process.alive?(listener_pid) and Process.alive?(starter_pid) do
      result
    else
      monitor = Process.monitor(pid)
      Process.unlink(pid)
      Process.exit(pid, :kill)

      receive do
        {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
      end

      {:error, :stale_generation}
    end
  end

  defp deliver(pid, _socket, :deferred), do: {:ok, pid}

  defp deliver(pid, socket, recv_data) do
    send(pid, {:new_connection, socket, recv_data})
    {:ok, pid}
  end
end

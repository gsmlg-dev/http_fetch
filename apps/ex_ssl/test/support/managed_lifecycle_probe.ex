defmodule ExSSL.TestSupport.ManagedLifecycleProbe do
  @moduledoc false

  # Provider-owned fault instrumentation. Consumers receive only bounded test
  # controls; production HTTP never extracts opaque lifecycle/provider state.
  def handles(%{coordinator: coordinator}) do
    state = :sys.get_state(coordinator, 1_000)

    state.slots
    |> Map.values()
    |> Enum.map(& &1.provider)
    |> Enum.filter(&match?(%SSL.Lifecycle.Handle{}, &1))
    |> Enum.uniq()
  end

  def graph(scope) do
    [handle | _] = handles(scope)
    graph_handle(handle)
  end

  def graph_handle(%SSL.Lifecycle.Handle{} = handle) do
    observer = handle.receipt.observer
    %{resources: resources} = :sys.get_state(observer, 1_000)
    %{identity: {_, :process, connection}, live: true} = resources.connection
    %{identity: {_, :process, writer}, live: true} = resources.writer
    %{identity: {_, :socket, tcp}, live: true} = resources.tcp

    %{
      handle: handle,
      observer: observer,
      connection: connection,
      writer: writer,
      tcp: tcp,
      monitors: %{
        observer: Process.monitor(observer),
        connection: Process.monitor(connection),
        writer: Process.monitor(writer),
        tcp: :socket.monitor(tcp)
      }
    }
  end

  def observer_control(scope) do
    [handle | _] = handles(scope)
    %{observer: handle.receipt.observer}
  end

  def suspend(graph, role) when role in [:observer, :writer, :connection],
    do: :erlang.suspend_process(Map.fetch!(graph, role))

  def resume(graph, role) when role in [:observer, :writer, :connection] do
    pid = Map.fetch!(graph, role)
    if Process.alive?(pid), do: :erlang.resume_process(pid)
    :ok
  end

  def alive?(graph, role), do: Process.alive?(Map.fetch!(graph, role))
  def close_tcp(graph), do: :socket.close(graph.tcp)
  def kill_connection(graph), do: Process.exit(graph.connection, :kill)
  def kill_observer(graph), do: Process.exit(graph.observer, :kill)

  def await_down(graph, roles, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    Enum.each(roles, fn role ->
      ref = Map.fetch!(graph.monitors, role)
      object = Map.fetch!(graph, role)
      type = if role == :tcp, do: :socket, else: :process

      receive do
        {:DOWN, ^ref, ^type, ^object, _} -> :ok
      after
        max(deadline - System.monotonic_time(:millisecond), 0) ->
          raise "managed provider #{role} did not terminate within original deadline"
      end
    end)
  end

  def release_monitors(graph) do
    Enum.each(graph.monitors, fn
      {:tcp, ref} -> :socket.cancel_monitor(ref)
      {_, ref} -> Process.demonitor(ref, [:flush])
    end)
  end

  # Match the public provider boundary's native blocked-output predicate. The
  # original absolute deadline covers both samples and every retry.
  def await_native_blocked(graph, deadline) do
    timeout = native_remaining!(deadline)
    {:connected, state} = :sys.get_state(graph.connection, timeout)
    before = :socket.info(graph.tcp)

    if match?(%{output: %{kind: :application}}, state) and
         native_waiting?(graph.writer, before) do
      receive do
      after
        min(50, native_remaining!(deadline)) -> :ok
      end

      after_wait = :socket.info(graph.tcp)
      {:connected, current} = :sys.get_state(graph.connection, native_remaining!(deadline))
      counters = [:write_byte, :write_pkg, :write_tries, :write_waits]

      if native_waiting?(graph.writer, after_wait) and current.output == state.output and
           Map.take(before.counters, counters) == Map.take(after_wait.counters, counters) do
        :ok
      else
        await_native_blocked(graph, deadline)
      end
    else
      receive do
      after
        1 -> await_native_blocked(graph, deadline)
      end
    end
  end

  defp native_waiting?(writer, %{counters: %{write_waits: waits}, num_writers: 1, wstates: states})
       when waits > 0 do
    :selected in states and
      match?(
        [status: :waiting, current_function: {:socket, _function, _arity}],
        Process.info(writer, [:status, :current_function])
      )
  end

  defp native_waiting?(_writer, _info), do: false

  defp native_remaining!(deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    if remaining <= 0, do: raise("native encrypted output did not block within original deadline")
    remaining
  end
end

defmodule HTTP.RequestLifecycle do
  @moduledoc false
  use GenServer

  # The latch outlives the coordinator. No request process owns the evidence.
  def start do
    latch = :atomics.new(1, [])
    :atomics.put(latch, 1, 1)
    {:ok, pid} = GenServer.start(__MODULE__, {self(), latch})
    {pid, latch}
  end

  def launch(tracker, fun) do
    fun.()
  catch
    kind, reason ->
      if tracker, do: send(tracker, :launch_failed)
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  def current, do: Process.get(__MODULE__)

  def bind_scope(tracker, scope, deadline),
    do: deadline_call(tracker, {:bind_scope, scope, deadline}, deadline)

  def bind_connector(tracker, token, deadline),
    do: deadline_call(tracker, {:bind_connector, token}, deadline)

  def track_tls(opts, {:sslsocket, _, processes}) when is_list(processes) do
    tracker = Keyword.get(opts, :request_lifecycle)

    if tracker do
      Enum.each(processes, fn
        pid when is_pid(pid) -> GenServer.call(tracker, {:track_independent, pid, :tls})
        _ -> :ok
      end)
    end

    :ok
  end

  def track_tls(_opts, _socket), do: :ok

  def enter(nil, _kind), do: :ok

  def enter(tracker, kind) do
    Process.put(__MODULE__, tracker)
    register(tracker, self(), kind)
  end

  def register(nil, _resource, _kind), do: :ok

  def register(tracker, resource, kind) do
    GenServer.call(tracker, {:register, resource, kind}, :infinity)
  end

  def complete(nil), do: :ok
  def complete(tracker), do: GenServer.call(tracker, {:complete, self()}, :infinity)

  def complete(tracker, nil), do: complete(tracker)

  # The task's completion signal precedes its DOWN signal even if the tracker
  # is suspended. Recording it must not extend the managed request deadline.
  def complete(tracker, _deadline), do: GenServer.cast(tracker, {:complete, self()})

  def abort(nil), do: :ok
  def abort(tracker), do: send(tracker, :abort)

  def unconfirmed(nil), do: :ok
  def unconfirmed(tracker), do: GenServer.cast(tracker, :unconfirmed)

  def track_socket(opts, socket) do
    register(Keyword.get(opts, :request_lifecycle), socket_resource(socket), :socket)
    socket
  end

  # Called at the ownership boundary, before a pool makes the connection
  # available to another request. Cancellation must never close a handed-off socket.
  def handoff_socket(nil, _socket), do: :ok

  def handoff_socket(tracker, socket), do: handoff(tracker, [socket_resource(socket)])

  def handoff_connection(nil, _socket, _owner), do: :ok

  def handoff_connection(tracker, socket, owner),
    do: handoff(tracker, [socket_resource(socket), owner])

  defp handoff(tracker, resources) do
    GenServer.call(tracker, {:handoff, resources}, :infinity)
  catch
    # A lost coordinator already makes its handle unconfirmed. It must not
    # crash the pool, which may own unrelated idle connections.
    :exit, _ -> :ok
  end

  defp socket_resource({:cancellable_ssl, _ssl, tcp}), do: tcp
  defp socket_resource(socket), do: socket

  def attach_stream(nil, _stream), do: :ok

  def attach_stream(tracker, stream) do
    register(tracker, stream, :stream_starting)
    ref = make_ref()
    monitor = Process.monitor(stream)
    send(stream, {:request_lifecycle, tracker, self(), ref})

    receive do
      {:request_lifecycle_attached, ^ref} ->
        Process.demonitor(monitor, [:flush])
        GenServer.call(tracker, {:stream_ready, stream}, :infinity)

      {:DOWN, ^monitor, :process, ^stream, _reason} ->
        unconfirmed(tracker)
    end

    :ok
  end

  def attach_stream(tracker, stream, nil), do: attach_stream(tracker, stream)

  def attach_stream(tracker, stream, deadline) do
    case deadline_call(tracker, {:register, stream, :managed_stream_starting}, deadline) do
      :ok ->
        ref = make_ref()
        monitor = Process.monitor(stream)
        send(stream, {:request_lifecycle, tracker, self(), ref})

        result =
          receive do
            {:request_lifecycle_attached, ^ref} ->
              deadline_call(tracker, {:stream_ready, stream}, deadline)

            {:DOWN, ^monitor, :process, ^stream, _reason} ->
              unconfirmed(tracker)
              {:error, :body_stream_closed}
          after
            remaining(deadline) -> {:error, :request_timeout}
          end

        Process.demonitor(monitor, [:flush])
        if result != :ok, do: send(stream, {:request_lifecycle_stop, :request_timeout})
        result

      error ->
        send(stream, {:request_lifecycle_stop, :request_timeout})
        error
    end
  end

  defp deadline_call(tracker, message, deadline) do
    case remaining(deadline) do
      0 -> {:error, :request_timeout}
      timeout -> GenServer.call(tracker, message, timeout)
    end
  catch
    :exit, {:timeout, _} ->
      abort(tracker)
      {:error, :request_timeout}

    :exit, _ ->
      {:error, :transport_scope_retired}
  end

  defp remaining(deadline), do: max(deadline - System.monotonic_time(:millisecond), 0)

  @impl true
  def init({starter, latch}) do
    {:ok,
     %{
       latch: latch,
       resources: %{Process.monitor(starter) => {starter, :starter}},
       completed: MapSet.new(),
       aborted?: false,
       sealed?: false,
       uncertain?: false,
       scope: nil,
       scope_monitor: nil,
       deadline: nil,
       connector: nil
     }}
  end

  @impl true
  def handle_call({:bind_scope, scope, deadline}, _, state),
    do:
      {:reply, :ok,
       %{state | scope: scope, scope_monitor: Process.monitor(scope), deadline: deadline}}

  def handle_call({:bind_connector, token}, _, state),
    do: {:reply, :ok, %{state | connector: token}}

  def handle_call({:track_independent, resource, kind}, _, state),
    do: {:reply, :ok, track_scope(state, resource, kind)}

  def handle_call({:register, resource, kind}, _from, state) do
    state = track_scope(state, resource, kind)
    state = if kind in [:task, :owner], do: release_starter(state), else: state
    monitor = if is_port(resource), do: Port.monitor(resource), else: Process.monitor(resource)
    state = %{state | resources: Map.put(state.resources, monitor, {resource, kind})}
    if state.aborted?, do: cancel(resource, kind)
    {:reply, :ok, state}
  end

  def handle_call({:handoff, handed_off}, _from, state) do
    resources =
      Enum.reduce(state.resources, state.resources, fn {ref, {resource, kind}}, acc ->
        if kind in [:socket, :connection] and resource in handed_off do
          Process.demonitor(ref, [:flush])
          Map.delete(acc, ref)
        else
          acc
        end
      end)

    {:reply, :ok, %{state | resources: resources}}
  end

  def handle_call({:stream_ready, stream}, _from, state) do
    resources =
      Map.new(state.resources, fn
        {ref, {^stream, kind}} when kind in [:stream_starting, :managed_stream_starting] ->
          {ref, {stream, :stream}}

        entry ->
          entry
      end)

    if state.aborted?, do: cancel(stream, :stream)
    {:reply, :ok, %{state | resources: resources}}
  end

  def handle_call({:complete, pid}, _from, state) do
    {:reply, :ok, mark_complete(state, pid)}
  end

  @impl true
  def handle_cast(:unconfirmed, state), do: {:noreply, %{state | uncertain?: true}}

  def handle_cast({:complete, pid}, state), do: {:noreply, mark_complete(state, pid)}

  defp mark_complete(state, pid) do
    state = %{state | completed: MapSet.put(state.completed, pid)}
    if resource_kind(state, pid) in [:owner, :task], do: %{state | sealed?: true}, else: state
  end

  @impl true
  def handle_info(:launch_failed, state) do
    state = release_starter(state)
    settle(%{state | sealed?: true, uncertain?: true})
  end

  def handle_info(:abort, state) do
    Enum.each(state.resources, fn {_ref, {pid, kind}} -> cancel(pid, kind) end)
    {:noreply, %{state | aborted?: true}}
  end

  def handle_info({:DOWN, ref, :process, _, _}, %{scope_monitor: ref} = state) do
    Enum.each(state.resources, fn {_ref, {pid, kind}} -> cancel(pid, kind) end)
    {:noreply, %{state | aborted?: true, uncertain?: true}}
  end

  def handle_info({:DOWN, ref, _type, resource, _reason}, state) do
    case Map.pop(state.resources, ref) do
      {nil, _} ->
        {:noreply, state}

      {{_, kind}, resources} ->
        incomplete? =
          kind in [:owner, :task, :dial, :starter] and
            not MapSet.member?(state.completed, resource)

        state = %{state | resources: resources, uncertain?: state.uncertain? or incomplete?}

        state =
          if kind == :owner or (kind in [:task, :starter] and incomplete?),
            do: %{state | sealed?: true},
            else: state

        if incomplete? do
          Enum.each(resources, fn {_ref, {pid, resource_kind}} ->
            cancel(pid, resource_kind)
          end)
        end

        settle(state)
    end
  end

  defp settle(%{sealed?: true, resources: resources} = state) when map_size(resources) == 0 do
    :atomics.put(state.latch, 1, if(state.uncertain?, do: 3, else: 2))
    {:stop, :normal, state}
  end

  defp settle(state), do: {:noreply, state}

  defp release_starter(state) do
    resources =
      Enum.reduce(state.resources, state.resources, fn
        {ref, {_pid, :starter}}, acc ->
          Process.demonitor(ref, [:flush])
          Map.delete(acc, ref)

        _, acc ->
          acc
      end)

    %{state | resources: resources}
  end

  defp resource_kind(state, pid) do
    Enum.find_value(state.resources, fn {_ref, {resource, kind}} ->
      if resource == pid, do: kind
    end)
  end

  defp track_scope(%{scope: nil} = state, _resource, _kind), do: state

  defp track_scope(state, resource, kind) do
    timeout = if state.deadline, do: max(remaining(state.deadline), 1), else: 5_000
    :ok = GenServer.call(state.scope, {:track, resource, kind, state.connector}, timeout)
    state
  catch
    :exit, _ ->
      cancel(resource, kind)
      %{state | uncertain?: true, aborted?: true}
  end

  defp cancel(pid, :owner), do: send(pid, :abort)
  defp cancel(pid, :dial), do: send(pid, :abort)
  # Upload workers are linked to the owner, which unlinks before stopping them.
  defp cancel(pid, :upload), do: send(pid, :abort)
  defp cancel(pid, :body_bridge), do: GenServer.cast(pid, :stop)
  defp cancel(pid, :connection), do: send(pid, :http2_shutdown_exclusive)
  defp cancel(_pid, :starter), do: :ok
  defp cancel(_pid, :task), do: :ok
  defp cancel(_pid, :stream_starting), do: :ok

  defp cancel(pid, :managed_stream_starting),
    do: send(pid, {:request_lifecycle_stop, :aborted})

  defp cancel(pid, :stream), do: send(pid, {:request_lifecycle_stop, :aborted})

  defp cancel(port, :socket) do
    _ = :inet.setopts(port, linger: {true, 0})
    :gen_tcp.close(port)
  end

  defp cancel(pid, _kind), do: Process.exit(pid, :kill)
end

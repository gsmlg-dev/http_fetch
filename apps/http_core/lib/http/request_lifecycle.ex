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

  def abort(nil), do: :ok
  def abort(tracker), do: send(tracker, :abort)

  def unconfirmed(tracker), do: GenServer.cast(tracker, :unconfirmed)

  def track_socket(opts, socket) do
    register(Keyword.get(opts, :request_lifecycle), socket, :socket)
    socket
  end

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

  @impl true
  def init({starter, latch}) do
    {:ok,
     %{
       latch: latch,
       resources: %{Process.monitor(starter) => {starter, :starter}},
       completed: MapSet.new(),
       aborted?: false,
       sealed?: false,
       uncertain?: false
     }}
  end

  @impl true
  def handle_call({:register, resource, kind}, _from, state) do
    state = if kind in [:task, :owner], do: release_starter(state), else: state
    monitor = if is_port(resource), do: Port.monitor(resource), else: Process.monitor(resource)
    state = %{state | resources: Map.put(state.resources, monitor, {resource, kind})}
    if state.aborted?, do: cancel(resource, kind)
    {:reply, :ok, state}
  end

  def handle_call({:stream_ready, stream}, _from, state) do
    resources =
      Map.new(state.resources, fn
        {ref, {^stream, :stream_starting}} -> {ref, {stream, :stream}}
        entry -> entry
      end)

    if state.aborted?, do: cancel(stream, :stream)
    {:reply, :ok, %{state | resources: resources}}
  end

  def handle_call({:complete, pid}, _from, state) do
    state = %{state | completed: MapSet.put(state.completed, pid)}

    state =
      if resource_kind(state, pid) in [:owner, :task], do: %{state | sealed?: true}, else: state

    {:reply, :ok, state}
  end

  @impl true
  def handle_cast(:unconfirmed, state), do: {:noreply, %{state | uncertain?: true}}

  @impl true
  def handle_info(:launch_failed, state) do
    state = release_starter(state)
    settle(%{state | sealed?: true, uncertain?: true})
  end

  def handle_info(:abort, state) do
    Enum.each(state.resources, fn {_ref, {pid, kind}} -> cancel(pid, kind) end)
    {:noreply, %{state | aborted?: true}}
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

  defp cancel(pid, :owner), do: send(pid, :abort)
  defp cancel(pid, :dial), do: send(pid, :abort)
  # Upload workers are linked to the owner, which unlinks before stopping them.
  defp cancel(pid, :upload), do: send(pid, :abort)
  defp cancel(_pid, :starter), do: :ok
  defp cancel(_pid, :task), do: :ok
  defp cancel(_pid, :stream_starting), do: :ok
  defp cancel(pid, :stream), do: send(pid, {:request_lifecycle_stop, :aborted})

  defp cancel(port, :socket) do
    _ = :inet.setopts(port, linger: {true, 0})
    :gen_tcp.close(port)
  end

  defp cancel(pid, _kind), do: Process.exit(pid, :kill)
end

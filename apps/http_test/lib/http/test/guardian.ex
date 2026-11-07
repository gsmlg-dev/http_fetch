defmodule HTTP.Test.Guardian do
  @moduledoc false
  use GenServer

  def start(context, worker, tracker, timeout),
    do: GenServer.start(__MODULE__, {context, worker, tracker, timeout})

  def track(pid, resource, kind), do: GenServer.call(pid, {:track, resource, kind})
  def cancellation(pid), do: GenServer.call(pid, :cancellation)

  def cancel_and_await(pid, timeout) do
    monitor = Process.monitor(pid)
    send(pid, :abort)

    receive do
      {:DOWN, ^monitor, :process, ^pid, _} -> :ok
    after
      timeout ->
        Process.demonitor(monitor, [:flush])
        {:error, :cleanup_pending}
    end
  end

  @impl true
  def init({context, worker, tracker, timeout}) do
    :ok = HTTP.RequestLifecycle.register(tracker, self(), :owner)
    worker_monitor = Process.monitor(worker)
    caller_monitor = Process.monitor(context.caller)
    timer = if timeout == :infinity, do: nil, else: Process.send_after(self(), :deadline, timeout)

    {:ok,
     %{
       token: context.token,
       worker: worker,
       tracker: tracker,
       caller_monitor: caller_monitor,
       timer: timer,
       aborted: false,
       reason: nil,
       resources: %{worker_monitor => {worker, :worker}}
     }}
  end

  @impl true
  def handle_call({:track, resource, kind}, _, state) do
    monitor = Process.monitor(resource)
    state = put_in(state.resources[monitor], {resource, kind})
    if state.aborted, do: stop_resource(resource, kind, state.reason)
    {:reply, :ok, state}
  end

  def handle_call(:cancellation, _, state), do: {:reply, state.reason, state}

  @impl true
  def handle_info(event, %{aborted: true} = state) when event in [:abort, :deadline],
    do: {:noreply, state}

  def handle_info(event, state) when event in [:abort, :deadline] do
    :ok = HTTP.Test.Registry.canceled(state.token, state.worker)
    HTTP.RequestLifecycle.abort(state.tracker)
    reason = if event == :deadline, do: :request_timeout, else: :aborted

    Enum.each(state.resources, fn {_, {resource, kind}} ->
      stop_resource(resource, kind, reason)
    end)

    _force_timer = Process.send_after(self(), :force_stop, 100)
    {:noreply, %{state | aborted: true, reason: reason}}
  end

  def handle_info(:force_stop, state) do
    Enum.each(state.resources, fn {_, {resource, _}} ->
      if Process.alive?(resource), do: Process.exit(resource, :kill)
    end)

    {:noreply, state}
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, %{caller_monitor: monitor} = state) do
    send(self(), :abort)
    {:noreply, state}
  end

  def handle_info({:DOWN, monitor, :process, pid, reason}, state) do
    if pid == state.worker, do: HTTP.Test.Registry.worker_down(state.token, pid, reason)
    state = %{state | resources: Map.delete(state.resources, monitor)}

    if map_size(state.resources) == 0 do
      :ok = HTTP.Test.Registry.guardian_completed(state.token, self())
      HTTP.RequestLifecycle.complete(state.tracker)
      {:stop, :normal, state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def terminate(_reason, state) do
    _ = if state.timer, do: Process.cancel_timer(state.timer)
    :ok
  end

  defp stop_resource(resource, :stream, reason), do: HTTP.Stream.stop(resource, reason)
  defp stop_resource(resource, _kind, :request_timeout), do: send(resource, :deadline)
  defp stop_resource(resource, _kind, _reason), do: send(resource, :abort)
end

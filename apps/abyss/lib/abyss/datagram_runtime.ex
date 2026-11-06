defmodule Abyss.DatagramRuntime do
  @moduledoc false
  use GenServer
  alias Abyss.{DatagramActions, DatagramWorker, UDPAdmission}
  alias Abyss.Dispatcher.{Admission, SendCapability, Writer}

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)
  def admit(pid, datagram), do: GenServer.call(pid, {:admit, datagram})
  def info(pid), do: GenServer.call(pid, :info)
  def drain(pid, deadline), do: GenServer.cast(pid, {:drain, deadline})

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    config = opts.config
    limits = Map.new(Abyss.ServerConfig.runtime_options(config))

    with {:ok, admission} <-
           Admission.start_link(
             generation: opts.generation,
             max_queue: config.dispatcher_max_queue,
             max_bytes: config.dispatcher_max_queue_bytes
           ),
         {:ok, writer} <-
           Writer.start_link(
             socket: opts.socket,
             transport: opts.transport,
             owner: self(),
             generation: opts.generation,
             admission: admission,
             max_queue: config.dispatcher_max_queue,
             max_bytes: config.dispatcher_max_queue_bytes
           ) do
      :ok = Abyss.TableOwner.monitor_runtime(self(), opts.owner, opts.server, writer, admission)

      capability = %SendCapability{
        writer: writer,
        admission: admission,
        generation: opts.generation,
        io_backend: config.datagram_options.io_backend
      }

      context = %{endpoint_id: opts.endpoint_id, generation: opts.generation, send: capability}

      {:ok,
       %{
         owner: opts.owner,
         server: opts.server,
         config: config,
         limits: limits,
         context: context,
         writer: writer,
         admission: admission,
         workers: %{},
         inputs: %{},
         bytes: 0,
         high_bytes: 0,
         high_items: 0,
         dropped: 0,
         internal_events_rejected: %{timer: 0, send_outcomes: 0},
         route_queue: :queue.new(),
         routing: nil,
         timers: %{},
         receipts: %{},
         draining: nil,
         drain_timer: nil,
         poll: nil
       }}
    end
  end

  @impl true
  def handle_call(:info, _from, state) do
    egress = Admission.status(state.admission)

    info = %{
      send: state.context.send,
      retained_bytes: state.bytes,
      input_count: map_size(state.inputs),
      key_count: map_size(state.workers),
      timer_count: map_size(state.timers),
      dropped: state.dropped,
      internal_events_rejected: state.internal_events_rejected,
      high_bytes: state.high_bytes,
      high_items: state.high_items,
      egress: egress,
      receipts: state.receipts
    }

    {:reply, info, state}
  end

  def handle_call({:admit, datagram}, _from, %{draining: deadline} = state)
      when not is_nil(deadline),
      do: {:reply, {:error, :draining}, dropped(state, :draining, {:datagram, datagram})}

  def handle_call({:admit, datagram}, _from, state) do
    case reserve({:datagram, datagram}, state) do
      {:ok, token, state} -> {:reply, :ok, route(token, state)}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  defp reserve(event, state) do
    bytes = event_bytes(event)
    limit = min(state.limits.max_queue, state.config.num_connections)

    if map_size(state.inputs) >= limit do
      {:error, :input_limit, dropped(state, :input_limit, event)}
    else
      reserve_input(event, bytes, state)
    end
  end

  defp reserve_input(event, bytes, state) do
    case UDPAdmission.reserve_runtime(
           state.server,
           state.owner,
           state.config.num_connections,
           bytes,
           state.limits.max_queue_bytes,
           self()
         ) do
      {:ok, slot} ->
        token = make_ref()
        input = %{event: event, bytes: bytes, slot: slot}

        state = %{
          state
          | inputs: Map.put(state.inputs, token, input),
            bytes: state.bytes + bytes,
            high_bytes: max(state.high_bytes, state.bytes + bytes),
            high_items: max(state.high_items, map_size(state.inputs) + 1)
        }

        {:ok, token, state}

      {:error, reason} ->
        {:error, reason, dropped(state, reason, event)}
    end
  end

  defp event_bytes({:datagram, datagram}), do: :erlang.external_size(datagram)
  defp event_bytes({:event, value}), do: :erlang.external_size(value)

  defp route(token, %{config: %{datagram_options: %{execution: :keyed}}} = state),
    do: start_route(%{state | route_queue: :queue.in(token, state.route_queue)})

  defp route(token, %{config: %{datagram_options: %{execution: :endpoint}}} = state),
    do: enqueue(:endpoint, token, state)

  defp route(token, state), do: enqueue(token, token, state)

  defp start_route(%{routing: routing} = state) when not is_nil(routing), do: state

  defp start_route(state) do
    case :queue.out(state.route_queue) do
      {{:value, token}, queue} ->
        {pid, monitor} = start_route_helper(token, state)

        timer = Process.send_after(self(), {:route_expired, token}, state.limits.route_timeout)

        %{
          state
          | route_queue: queue,
            routing: %{token: token, pid: pid, monitor: monitor, timer: timer, expired: false}
        }

      {:empty, _} ->
        state
    end
  end

  defp start_route_helper(token, state) do
    {:datagram, datagram} = state.inputs[token].event
    runtime = self()
    route = state.config.datagram_options.route_key

    spawn_input(token, state, fn ->
      result = protected(fn -> route_key(route, datagram) end)
      _ = send(runtime, {:route_result, token, result})
    end)
  end

  @impl true
  def handle_info(
        {:route_result, token, result},
        %{routing: %{token: token, expired: false} = routing} = state
      ) do
    {:noreply, %{state | routing: Map.put(routing, :result, result)}}
  end

  def handle_info({:route_expired, token}, %{routing: %{token: token} = routing} = state) do
    Process.exit(routing.pid, :kill)
    {:noreply, %{state | routing: %{routing | expired: true}}}
  end

  def handle_info({:initialized, key, token}, state) do
    case state.workers[key] do
      %{current: ^token, phase: :init} = worker ->
        worker = arm_watchdog(worker, key, token, :callback, state.limits.callback_timeout, state)
        {:noreply, put_worker(state, key, worker)}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:invocation_result, key, token, result}, state) do
    case state.workers[key] do
      %{current: ^token, phase: phase} = worker when phase in [:init, :callback] ->
        cancel(worker.watchdog)
        _ = GenServer.cast(worker.pid, {:settled, token})
        state = put_worker(state, key, %{worker | initialized: true, watchdog: nil})

        case result do
          {:ok, actions} -> effects(key, token, actions, nil, state)
          {:stop, reason, actions} -> effects(key, token, actions, reason, state)
          {:error, reason} -> {:noreply, remove_worker(key, reason, state)}
          {:init_error, reason} -> {:noreply, remove_worker(key, {:init_error, reason}, state)}
        end

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:effects_result, key, token, outcomes, stop_reason}, state) do
    case state.workers[key] do
      %{current: ^token, phase: :effects} = worker ->
        result = {outcomes, stop_reason}
        {:noreply, put_worker(state, key, %{worker | effect_result: result})}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:invocation_settled, key, token}, state) do
    case state.workers[key] do
      %{current: ^token, phase: :effects} = worker ->
        state = put_worker(state, key, %{worker | callback_settled: true})
        {:noreply, finish_effects(key, state)}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:work_expired, key, token, pid, phase, identity, generation}, state)
      when generation == state.context.generation do
    case state.workers[key] do
      %{
        pid: ^pid,
        current: ^token,
        phase: ^phase,
        watchdog: %{identity: ^identity, phase: ^phase, deadline: deadline}
      } ->
        {:noreply, expire_watchdog(key, pid, phase, deadline, state)}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:idle_expired, key, idle_token}, state) do
    case state.workers[key] do
      %{current: nil, idle_token: ^idle_token} ->
        {:noreply, remove_worker(key, :idle_timeout, state)}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:managed_timer, key, token, generation}, state) do
    case state.timers[{key, token}] do
      %{generation: ^generation, value: value} ->
        state = %{state | timers: Map.delete(state.timers, {key, token})}

        {:noreply, timer_event(key, token, value, state)}

      _ ->
        {:noreply, state}
    end
  end

  def handle_info({:abyss_dispatcher_send, generation, ref, result, _at}, state)
      when generation == state.context.generation do
    receipts =
      Map.new(state.receipts, fn {token, receipt} ->
        {token,
         %{
           receipt
           | outcomes:
               Enum.map(receipt.outcomes, fn
                 {:unknown, ^ref} -> {ref, result}
                 other -> other
               end)
         }}
      end)

    {:noreply, %{state | receipts: receipts}}
  end

  def handle_info({:receipt_expired, token}, state),
    do: {:noreply, %{state | receipts: Map.delete(state.receipts, token)}}

  def handle_info(:drain_poll, state), do: check_drain(%{state | poll: nil})
  def handle_info(:drain_expired, state), do: {:stop, :normal, state}

  def handle_info({:DOWN, monitor, :process, pid, reason}, state) do
    {:noreply, process_down(monitor, pid, reason, state)}
  end

  def handle_info({:EXIT, pid, reason}, state)
      when pid == state.owner or pid == state.writer or pid == state.admission,
      do: {:stop, {:component_down, reason}, state}

  def handle_info(_, state), do: {:noreply, state}

  @impl true
  def handle_cast({:drain, deadline}, state) do
    timer =
      if deadline == :infinity,
        do: nil,
        else: Process.send_after(self(), :drain_expired, max(deadline - now(), 0))

    Enum.each(state.timers, fn {_, timer} -> cancel(timer.ref) end)
    check_drain(%{state | draining: deadline, drain_timer: timer, timers: %{}})
  end

  defp enqueue(key, token, state) do
    worker = state.workers[key]

    cond do
      not is_nil(worker) and worker.phase == :closing ->
        reject(token, :key_closing, state)

      state.inputs[token].bytes > state.limits.max_key_queue_bytes ->
        reject(token, :key_queue_bytes_limit, state)

      is_nil(worker) and map_size(state.workers) >= state.limits.max_keys ->
        reject(token, :key_limit, state)

      key_queue_full?(worker, state.inputs[token].bytes, state.limits) ->
        reject(token, :key_queue_limit, state)

      true ->
        state = if worker, do: state, else: new_worker(key, state)
        worker = state.workers[key]
        cancel(worker.idle_timer)

        worker = %{
          worker
          | queue: :queue.in(token, worker.queue),
            items: worker.items + 1,
            bytes: worker.bytes + state.inputs[token].bytes,
            idle_timer: nil,
            idle_token: nil
        }

        start_next(key, put_worker(state, key, worker))
    end
  end

  defp key_queue_full?(nil, _, _), do: false

  defp key_queue_full?(worker, bytes, limits),
    do: worker.items >= limits.max_key_queue or worker.bytes + bytes > limits.max_key_queue_bytes

  defp new_worker(key, state) do
    {:ok, pid} = DatagramWorker.start_link(self(), key, state.config, state.context)

    worker = %{
      pid: pid,
      monitor: Process.monitor(pid),
      queue: :queue.new(),
      items: 0,
      bytes: 0,
      current: nil,
      initialized: false,
      phase: :init,
      watchdog: nil,
      idle_timer: nil,
      idle_token: nil,
      effect_pid: nil,
      effect_monitor: nil,
      effect_result: nil,
      callback_settled: false
    }

    put_worker(state, key, worker)
  end

  defp start_next(key, state) do
    case state.workers[key] do
      %{current: nil} = worker ->
        case :queue.out(worker.queue) do
          {{:value, token}, queue} ->
            {phase, timeout} = invocation_phase(worker, state.limits)
            worker = arm_watchdog(worker, key, token, phase, timeout, state)
            :ok = UDPAdmission.protect(state.inputs[token].slot, worker.pid)
            _ = GenServer.cast(worker.pid, {:invoke, token, state.inputs[token].event})

            put_worker(state, key, %{
              worker
              | queue: queue,
                current: token
            })

          {:empty, _} when state.config.datagram_options.execution == :endpoint ->
            state

          {:empty, _} ->
            idle_token = make_ref()

            timer =
              Process.send_after(
                self(),
                {:idle_expired, key, idle_token},
                state.limits.idle_timeout
              )

            put_worker(state, key, %{worker | idle_token: idle_token, idle_timer: timer})
        end

      _ ->
        state
    end
  end

  defp effects(key, token, actions, stop_reason, state) do
    persistent = state.config.datagram_options.execution != :per_datagram

    case DatagramActions.validate(actions, state.limits, persistent) do
      :ok -> validated_effects(key, token, actions, stop_reason, state)
      {:error, reason} -> {:noreply, remove_worker(key, reason, state)}
    end
  end

  defp validated_effects(key, token, actions, stop_reason, state) do
    {timer_actions, sends} = Enum.split_with(actions, &timer_action?/1)

    case timers(key, timer_actions, state) do
      {:ok, state} -> start_effects(key, token, sends, stop_reason, state)
      {:error, reason} -> {:noreply, remove_worker(key, reason, state)}
    end
  end

  defp start_effects(key, token, sends, stop_reason, state) do
    runtime = self()
    capability = state.context.send
    event = state.inputs[token].event
    timeout = state.limits.send_timeout

    {pid, monitor} =
      spawn_input(token, state, fn ->
        outcomes = Enum.map(sends, &submit_action(&1, event, capability, timeout))
        _ = send(runtime, {:effects_result, key, token, outcomes, stop_reason})
      end)

    worker =
      arm_watchdog(
        state.workers[key],
        key,
        token,
        :effects,
        min(max(1, length(sends)) * (2 * timeout + 10), 0xFFFFFFFF),
        state
      )

    worker = %{
      worker
      | effect_pid: pid,
        effect_monitor: monitor,
        effect_result: nil,
        callback_settled: false
    }

    {:noreply, put_worker(state, key, worker)}
  end

  defp finish_effects(key, state) do
    case state.workers[key] do
      %{
        phase: :effects,
        effect_pid: nil,
        callback_settled: true,
        effect_result: {outcomes, stop_reason}
      } = worker ->
        complete_effects(key, worker, outcomes, stop_reason, state)

      _ ->
        state
    end
  end

  defp complete_effects(key, worker, outcomes, stop_reason, state) do
    cancel(worker.watchdog)
    token = worker.current
    state = record_receipts(state, token, outcomes)
    persistent = is_nil(stop_reason) and state.config.datagram_options.execution != :per_datagram
    original_event = state.inputs[token].event
    state = if persistent, do: release(token, state), else: state
    worker = state.workers[key]

    state =
      put_worker(state, key, %{
        worker
        | current: if(persistent, do: nil, else: token),
          effect_result: nil,
          watchdog: nil
      })

    if persistent do
      state = start_next(key, state)
      outcome_event(key, token, original_event, outcomes, state)
    else
      remove_worker(key, stop_reason || :normal, state)
    end
  end

  defp spawn_input(token, state, fun) do
    {:ok, pid} = UDPAdmission.spawn_protected(state.inputs[token].slot, fun)
    monitor = Process.monitor(pid)
    _ = send(pid, :run)
    {pid, monitor}
  end

  defp route_key(fun, datagram) when is_function(fun, 1), do: fun.(datagram)
  defp route_key({module, function}, datagram), do: apply(module, function, [datagram])

  defp timer_event(key, token, value, %{draining: nil} = state) do
    if state.workers[key] do
      case reserve({:event, {:timer, token, value}}, state) do
        {:ok, input, state} -> enqueue(key, input, state)
        {:error, _, state} -> state
      end
    else
      state
    end
  end

  defp timer_event(_, _, _, state), do: state

  defp process_down(monitor, pid, reason, state) do
    worker = Enum.find(state.workers, fn {_, w} -> w.monitor == monitor and w.pid == pid end)
    process_down(worker, monitor, pid, reason, state)
  end

  defp process_down({key, %{phase: :closing} = worker}, _, _, _, state) do
    finish_closed(key, put_worker(state, key, Map.put(worker, :worker_dead, true)))
  end

  defp process_down({key, _}, _, _, reason, state),
    do: remove_worker(key, {:worker_down, reason}, state)

  defp process_down(nil, monitor, pid, reason, state) do
    case state.routing do
      %{monitor: ^monitor, pid: ^pid} = routing -> route_down(routing, reason, state)
      _ -> effect_down(monitor, pid, reason, state)
    end
  end

  defp route_down(routing, reason, state) do
    cancel(routing.timer)

    result =
      if routing.expired,
        do: {:error, :route_timeout},
        else: Map.get(routing, :result, {:error, {:route_down, reason}})

    state = %{state | routing: nil}
    start_route(route_result(result, routing.token, state))
  end

  defp route_result({:ok, key}, token, state) do
    if :erlang.external_size(key) <= state.limits.max_key_bytes,
      do: enqueue(key, token, state),
      else: reject(token, :key_size_limit, state)
  end

  defp route_result({:error, reason}, token, state), do: reject(token, reason, state)

  defp effect_down(monitor, pid, reason, state) do
    worker =
      Enum.find(state.workers, fn {_, w} ->
        w.effect_monitor == monitor and w.effect_pid == pid
      end)

    effect_down(worker, reason, state)
  end

  defp effect_down(nil, _, state), do: state

  defp effect_down({key, worker}, reason, state) do
    worker = %{worker | effect_pid: nil, effect_monitor: nil}
    state = put_worker(state, key, worker)

    case {worker.phase, worker.effect_result, reason} do
      {:closing, _, _} ->
        finish_closed(key, state)

      {:effects, {_outcomes, _stop_reason}, :normal} ->
        cancel(worker.watchdog)
        finish_effects(key, put_worker(state, key, %{worker | watchdog: nil}))

      _ ->
        remove_worker(key, {:effect_down, reason}, state)
    end
  end

  defp submit_action({:send, destination, data}, _, capability, timeout),
    do: send_action(capability, destination, data, timeout)

  defp submit_action({:reply, data}, {:datagram, datagram}, capability, timeout),
    do: send_action(capability, datagram.peer, data, timeout)

  defp submit_action({:reply, data, :strict}, {:datagram, datagram}, capability, timeout) do
    with {:ok, ref} <- Abyss.Endpoint.reply(capability, datagram, data, :strict, timeout),
         do: await_action(capability, ref, timeout)
  end

  defp submit_action(_, _, _, _), do: {:error, :reply_without_datagram}

  defp send_action(capability, destination, data, timeout) do
    case Abyss.Endpoint.send(capability, destination, data, timeout) do
      {:ok, ref} -> await_action(capability, ref, timeout)
      error -> error
    end
  end

  defp await_action(capability, ref, timeout) do
    case Writer.await(capability.writer, capability, ref, timeout) do
      {:unknown, _} = unknown -> unknown
      result -> {ref, result}
    end
  end

  defp timer_action?({:timer, _, _, _}), do: true
  defp timer_action?({:cancel_timer, _}), do: true
  defp timer_action?(_), do: false

  defp timers(key, actions, state) do
    desired =
      Enum.reduce(actions, MapSet.new(Map.keys(state.timers)), fn
        {:timer, token, _, _}, set -> MapSet.put(set, {key, token})
        {:cancel_timer, token}, set -> MapSet.delete(set, {key, token})
      end)

    if MapSet.size(desired) > state.limits.max_timers do
      {:error, :timer_limit}
    else
      {:ok, Enum.reduce(actions, state, fn action, state -> apply_timer(key, action, state) end)}
    end
  end

  defp apply_timer(key, {:cancel_timer, token}, state), do: cancel_managed(key, token, state)

  defp apply_timer(key, {:timer, token, delay, value}, state) do
    state = cancel_managed(key, token, state)
    generation = make_ref()
    ref = Process.send_after(self(), {:managed_timer, key, token, generation}, delay)

    %{
      state
      | timers:
          Map.put(state.timers, {key, token}, %{ref: ref, generation: generation, value: value})
    }
  end

  defp cancel_managed(key, token, state) do
    case Map.pop(state.timers, {key, token}) do
      {nil, _} ->
        state

      {%{ref: ref}, timers} ->
        cancel(ref)
        %{state | timers: timers}
    end
  end

  defp remove_worker(key, reason, state) do
    case state.workers[key] do
      nil ->
        state

      %{phase: :closing} ->
        state

      worker ->
        cancel(worker.watchdog)
        cancel(worker.idle_timer)
        if worker.effect_pid, do: Process.exit(worker.effect_pid, :kill)
        state = Enum.reduce(:queue.to_list(worker.queue), state, &release/2)

        state =
          Enum.reduce(Map.keys(state.timers), state, fn
            {^key, token}, state -> cancel_managed(key, token, state)
            _, state -> state
          end)

        dead = match?({:worker_down, _}, reason)
        forced = dead or reason == :callback_timeout or match?({:effect_down, _}, reason)

        if forced,
          do: Process.exit(worker.pid, :kill),
          else: _ = GenServer.cast(worker.pid, {:finish, {:shutdown, reason}})

        worker =
          worker
          |> arm_watchdog(key, worker.current, :closing, state.limits.terminate_timeout, state)
          |> Map.put(:worker_dead, dead)
          |> Map.put(:queue, :queue.new())

        state = put_worker(state, key, worker)
        finish_closed(key, state)
    end
  end

  defp finish_closed(key, state) do
    worker = state.workers[key]

    if worker.worker_dead and is_nil(worker.effect_pid),
      do: finalize_worker(key, state),
      else: state
  end

  defp finalize_worker(key, state) do
    case Map.pop(state.workers, key) do
      {nil, _} ->
        state

      {worker, workers} ->
        cancel(worker.watchdog)
        Process.demonitor(worker.monitor, [:flush])
        state = %{state | workers: workers}
        if worker.current, do: release(worker.current, state), else: state
    end
  end

  defp put_worker(state, key, worker), do: %{state | workers: Map.put(state.workers, key, worker)}

  defp release(token, state) do
    case Map.pop(state.inputs, token) do
      {nil, _} ->
        state

      {input, inputs} ->
        :ok = UDPAdmission.complete(input.slot)

        workers =
          Map.new(state.workers, fn {key, worker} ->
            {key, release_worker_input(worker, token, input.bytes)}
          end)

        %{state | inputs: inputs, bytes: state.bytes - input.bytes, workers: workers}
    end
  end

  defp release_worker_input(%{current: token} = worker, token, bytes),
    do: %{worker | items: worker.items - 1, bytes: worker.bytes - bytes}

  defp release_worker_input(worker, _, _), do: worker

  defp reject(token, reason, state),
    do: release(token, dropped(state, reason, state.inputs[token].event))

  defp dropped(state, reason, {:datagram, datagram}) do
    state = %{state | dropped: state.dropped + 1}
    publish_drop_counters(state)
    Abyss.Telemetry.track_datagram_dropped(state.server, reason, byte_size(datagram.payload))
    state
  end

  defp dropped(state, reason, {:event, {:timer, _, _} = event}),
    do: event_rejected(state, :timer, reason, event)

  defp dropped(state, reason, {:event, {:send_outcomes, _, _, _} = event}),
    do: event_rejected(state, :send_outcomes, reason, event)

  defp event_rejected(state, type, reason, event) do
    counters = Map.update!(state.internal_events_rejected, type, &(&1 + 1))
    state = %{state | internal_events_rejected: counters}
    publish_drop_counters(state)
    Abyss.Telemetry.track_event_rejected(state.server, type, reason, :erlang.external_size(event))
    state
  end

  defp publish_drop_counters(state) do
    counters = Map.take(state, [:dropped, :internal_events_rejected])
    _ = send(state.owner, {:runtime_drop_counters, self(), state.context.generation, counters})
    :ok
  end

  defp record_receipts(state, token, outcomes) do
    if map_size(state.receipts) >= 256 do
      {oldest, receipt} = Enum.min_by(state.receipts, fn {_, receipt} -> receipt.at end)
      cancel(receipt.timer)
      record_receipts(%{state | receipts: Map.delete(state.receipts, oldest)}, token, outcomes)
    else
      timer = Process.send_after(self(), {:receipt_expired, token}, 5000)

      %{
        state
        | receipts: Map.put(state.receipts, token, %{at: now(), outcomes: outcomes, timer: timer})
      }
    end
  end

  defp check_drain(%{draining: nil} = state), do: {:noreply, state}

  defp check_drain(state) do
    state =
      if map_size(state.inputs) == 0 do
        Enum.reduce(Map.keys(state.workers), state, &remove_worker(&1, :normal, &2))
      else
        state
      end

    if map_size(state.inputs) == 0 and map_size(state.workers) == 0 and
         Admission.status(state.admission).entries == 0 do
      {:stop, :normal, state}
    else
      poll = Process.send_after(self(), :drain_poll, 5)
      {:noreply, %{state | poll: poll}}
    end
  end

  defp outcome_event(_key, _token, {:event, {:send_outcomes, _, _, _}}, _outcomes, state),
    do: state

  defp outcome_event(key, token, _event, outcomes, state) do
    if outcomes != [] and
         function_exported?(state.config.datagram_options.datagram_handler, :handle_event, 2) and
         is_nil(state.draining) do
      event = {:event, {:send_outcomes, state.context.generation, token, outcomes}}

      case reserve(event, state) do
        {:ok, input, state} -> enqueue(key, input, state)
        {:error, _, state} -> state
      end
    else
      state
    end
  end

  defp protected(fun) do
    {:ok, fun.()}
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp invocation_phase(%{initialized: true}, limits),
    do: {:callback, limits.callback_timeout}

  defp invocation_phase(_worker, limits), do: {:init, limits.init_timeout}

  defp expire_watchdog(key, pid, phase, deadline, state) do
    cond do
      now() < deadline ->
        state

      phase == :closing ->
        Process.exit(pid, :kill)
        state

      true ->
        remove_worker(key, :callback_timeout, state)
    end
  end

  defp arm_watchdog(worker, key, token, phase, timeout, state) do
    cancel(worker.watchdog)
    identity = make_ref()
    deadline = now() + timeout
    message = {:work_expired, key, token, worker.pid, phase, identity, state.context.generation}
    ref = Process.send_after(self(), message, deadline, abs: true)
    watchdog = %{ref: ref, identity: identity, phase: phase, deadline: deadline}
    %{worker | watchdog: watchdog, phase: phase}
  end

  defp cancel(%{ref: ref}), do: cancel(ref)
  defp cancel(nil), do: :ok

  defp cancel(timer) do
    _ = Process.cancel_timer(timer)
    :ok
  end

  defp now, do: System.monotonic_time(:millisecond)

  @impl true
  def terminate(_reason, state) do
    if state.routing, do: Process.exit(state.routing.pid, :kill)

    Enum.each(state.workers, fn {_, worker} ->
      if worker.effect_pid, do: Process.exit(worker.effect_pid, :kill)
      Process.exit(worker.pid, :kill)
    end)

    Enum.each(state.inputs, fn {_, input} -> UDPAdmission.release(input.slot) end)
    Enum.each(state.timers, fn {_, timer} -> cancel(timer.ref) end)
    Process.exit(state.writer, :kill)
    Process.exit(state.admission, :kill)
    _ = send(state.owner, {:runtime_drained, self()})
    :ok
  end
end

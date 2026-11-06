defmodule Abyss.DatagramDispatcher do
  @moduledoc """
  Behaviour for an opt-in persistent datagram dispatcher.

  The callback owns protocol state (for example a QUIC endpoint), while
  `Abyss.Dispatcher` owns admission, route generations and the shared socket
  writer. The callback must never close the socket or call back into the
  blocked listener.
  """

  @callback init(context :: map(), opts :: keyword()) :: {:ok, state :: term()} | {:error, term()}

  @callback handle_datagram(
              remote :: {term(), non_neg_integer()},
              bytes :: binary(),
              received_at :: integer(),
              context :: map()
            ) ::
              {:ok, state :: term()}
              | {:drop, reason :: term(), state :: term()}
              | {:new, keys :: [term()], pid(), state :: term()}
              | {:route, keys :: [term()], pid(), state :: term()}

  @callback terminate(reason :: term(), state :: term()) :: term()
  @optional_callbacks terminate: 2
end

defmodule Abyss.Dispatcher do
  @moduledoc """
  Persistent bounded dispatcher used before Abyss's legacy handler path.

  One dispatcher is created per listener. Calls are serialized in this process,
  and connection processes are monitored so all CID routes are removed on
  death. Egress uses a separate bounded writer because the listener may be
  blocked in `recv(:infinity)`.
  """

  use GenServer

  defmodule SendCapability do
    @enforce_keys [:writer, :generation]
    defstruct [:writer, :generation, :admission, io_backend: :gen_udp]
  end

  defmodule Admission do
    @moduledoc false
    use GenServer

    def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

    def size({kind, _} = remote, bytes) when kind in [:native, :native_reply, :scoped],
      do: byte_size(bytes) + :erlang.external_size(remote)

    def size(_, bytes), do: byte_size(bytes)

    def reserve(_pid, %SendCapability{generation: generation} = capability, bytes, timeout)
        when is_integer(bytes) and bytes >= 0 do
      with {:ok, admission} <- admission(capability) do
        ref = make_ref()

        try do
          GenServer.call(admission, {:reserve, generation, ref, bytes, self()}, timeout)
        catch
          :exit, {:timeout, _} ->
            GenServer.cast(admission, {:cancel_reservation, generation, ref, self()})
            {:error, :writer_timeout}

          :exit, _ ->
            {:error, :writer_down}
        end
      end
    end

    def reserve(_pid, _capability, _bytes, _timeout), do: {:error, :stale_generation}

    def submit(%SendCapability{generation: generation} = capability, ref, remote, bytes, timeout)
        when is_reference(ref) and is_tuple(remote) and is_binary(bytes) do
      with {:ok, admission} <- admission(capability) do
        call(admission, {:submitted, generation, ref, remote, bytes}, timeout, ref)
      end
    end

    def submit(_capability, _ref, _remote, _bytes, _timeout), do: {:error, :stale_generation}

    def await(%SendCapability{generation: generation} = capability, ref, timeout)
        when is_reference(ref) do
      with {:ok, admission} <- admission(capability) do
        deadline = System.monotonic_time(:millisecond) + timeout
        call(admission, {:await, generation, ref, deadline}, timeout, ref)
      end
    end

    def await(_capability, _ref, _timeout), do: {:error, :stale_generation}

    def status(pid), do: GenServer.call(pid, :status)

    def complete(pid, generation, ref, result),
      do: GenServer.cast(pid, {:complete, generation, ref, result})

    def bind(pid, writer, owner \\ nil) when is_pid(writer),
      do: GenServer.call(pid, {:bind, writer, owner})

    @impl true
    def init(opts) do
      {:ok,
       %{
         generation: Keyword.fetch!(opts, :generation),
         max_queue: Keyword.fetch!(opts, :max_queue),
         max_bytes: Keyword.fetch!(opts, :max_bytes),
         max_results: Keyword.get(opts, :max_results, 256),
         result_ttl: Keyword.get(opts, :result_ttl, 5_000),
         writer: nil,
         writer_monitor: nil,
         owner: nil,
         owner_monitor: nil,
         entries: %{},
         reserved_bytes: 0,
         waiters: %{},
         results: %{}
       }}
    end

    @impl true
    def handle_call(:status, _from, state),
      do: {:reply, %{entries: map_size(state.entries), bytes: state.reserved_bytes}, state}

    def handle_call({:reserve, generation, ref, bytes, caller}, _from, state)
        when generation == state.generation and is_reference(ref) and is_pid(caller) do
      state = prune_results(state)

      cond do
        not is_pid(state.writer) ->
          {:reply, {:error, :writer_down}, state}

        state.reserved_bytes + bytes > state.max_bytes ->
          {:reply, {:error, :queue_bytes_limit}, state}

        map_size(state.entries) >= state.max_queue ->
          {:reply, {:error, :queue_limit}, state}

        true ->
          monitor = Process.monitor(caller)
          entry = %{bytes: bytes, status: :reserved, caller: caller, monitor: monitor}

          {:reply, {:ok, ref},
           %{
             state
             | entries: Map.put(state.entries, ref, entry),
               reserved_bytes: state.reserved_bytes + bytes
           }}
      end
    end

    def handle_call({:reserve, _generation, _ref, _bytes, _caller}, _from, state),
      do: {:reply, {:error, :stale_generation}, state}

    def handle_call({:await, generation, ref, deadline}, from, state)
        when generation == state.generation do
      state = prune_results(state)

      case Map.get(state.results, ref) do
        %{result: result} ->
          {:reply, result, state}

        nil when is_map_key(state.entries, ref) and not is_map_key(state.waiters, ref) ->
          monitor = Process.monitor(elem(from, 0))

          timer =
            Process.send_after(
              self(),
              {:await_expired, ref, monitor},
              max(deadline - System.monotonic_time(:millisecond), 0)
            )

          waiter = %{from: from, timer: timer, monitor: monitor}
          {:noreply, %{state | waiters: Map.put(state.waiters, ref, waiter)}}

        nil when is_map_key(state.entries, ref) ->
          {:reply, {:error, :already_awaiting}, state}

        nil ->
          {:reply, {:error, :unknown_send}, state}
      end
    end

    def handle_call({:await, _generation, _ref, _deadline}, _from, state),
      do: {:reply, {:error, :stale_generation}, state}

    def handle_call({:bind, writer, owner}, _from, state) when is_pid(writer) do
      if is_reference(state.writer_monitor), do: Process.demonitor(state.writer_monitor, [:flush])
      if is_reference(state.owner_monitor), do: Process.demonitor(state.owner_monitor, [:flush])

      :persistent_term.put({Abyss.Dispatcher.Writer, writer}, self())

      {:reply, :ok,
       %{
         state
         | writer: writer,
           writer_monitor: Process.monitor(writer),
           owner: owner,
           owner_monitor: if(is_pid(owner), do: Process.monitor(owner))
       }}
    end

    def handle_call({:submitted, generation, ref, remote, bytes}, _from, state)
        when generation == state.generation do
      expected_size = size(remote, bytes)

      case Map.get(state.entries, ref) do
        %{status: :reserved, monitor: monitor, bytes: size} = entry
        when size == expected_size and is_pid(state.writer) ->
          Process.demonitor(monitor, [:flush])
          GenServer.cast(state.writer, {:submit, generation, ref, remote, bytes})

          {:reply, :ok,
           %{state | entries: Map.put(state.entries, ref, %{entry | status: :submitted})}}

        %{status: :submitted, bytes: size} when size == expected_size ->
          {:reply, :ok, state}

        nil ->
          {:reply, {:error, :unknown_send}, state}

        _entry ->
          {:reply, {:error, :invalid_send}, state}
      end
    end

    def handle_call({:submitted, _generation, _ref, _remote, _bytes}, _from, state),
      do: {:reply, {:error, :stale_generation}, state}

    @impl true
    def handle_cast({:complete, generation, ref, result}, state)
        when generation == state.generation do
      case Map.pop(state.entries, ref) do
        {nil, _entries} ->
          {:noreply, state}

        {%{bytes: bytes, monitor: monitor}, entries} ->
          if is_reference(monitor), do: Process.demonitor(monitor, [:flush])
          state = %{state | entries: entries, reserved_bytes: state.reserved_bytes - bytes}
          {:noreply, complete(state, ref, result)}
      end
    end

    def handle_cast({:complete, _generation, _ref, _result}, state), do: {:noreply, state}

    def handle_cast({:cancel_reservation, generation, ref, caller}, state)
        when generation == state.generation do
      case Map.get(state.entries, ref) do
        %{status: :reserved, caller: ^caller} -> {:noreply, release_entry(state, ref)}
        _ -> {:noreply, state}
      end
    end

    def handle_cast({:cancel_reservation, _generation, _ref, _caller}, state),
      do: {:noreply, state}

    @impl true
    def handle_info(
          {:DOWN, monitor, :process, owner, _reason},
          %{owner: owner, owner_monitor: monitor} = state
        ) do
      if is_pid(state.writer), do: Process.exit(state.writer, :kill)
      {:noreply, %{state | owner: nil, owner_monitor: nil}}
    end

    def handle_info(
          {:DOWN, monitor, :process, writer, _reason},
          %{writer: writer, writer_monitor: monitor} = state
        ) do
      :persistent_term.erase({Abyss.Dispatcher.Writer, writer})

      state =
        Enum.reduce(Map.keys(state.entries), state, fn ref, acc ->
          acc
          |> release_entry(ref)
          |> complete(ref, {:error, :writer_down})
        end)

      {:stop, :normal, %{state | writer: nil, writer_monitor: nil}}
    end

    def handle_info({:DOWN, monitor, :process, _caller, _reason}, state) do
      case Enum.find(state.entries, fn {_ref, entry} -> entry.monitor == monitor end) do
        {ref, %{status: :reserved}} ->
          {:noreply, release_entry(state, ref)}

        _ ->
          case Enum.find(state.waiters, fn {_ref, waiter} -> waiter.monitor == monitor end) do
            {ref, waiter} ->
              _ = Process.cancel_timer(waiter.timer)
              {:noreply, %{state | waiters: Map.delete(state.waiters, ref)}}

            nil ->
              {:noreply, state}
          end
      end
    end

    def handle_info({:await_expired, ref, monitor}, state) do
      case Map.get(state.waiters, ref) do
        %{from: from, monitor: ^monitor, timer: timer} ->
          _ = Process.cancel_timer(timer)
          Process.demonitor(monitor, [:flush])
          GenServer.reply(from, {:unknown, ref})
          {:noreply, %{state | waiters: Map.delete(state.waiters, ref)}}

        _ ->
          {:noreply, state}
      end
    end

    def handle_info({:result_expired, ref}, state),
      do: {:noreply, %{state | results: Map.delete(state.results, ref)}}

    defp complete(state, ref, result) do
      state =
        case Map.pop(state.waiters, ref) do
          {nil, waiters} ->
            %{state | waiters: waiters}

          {%{from: from, timer: timer, monitor: monitor}, waiters} ->
            _ = Process.cancel_timer(timer)
            Process.demonitor(monitor, [:flush])
            GenServer.reply(from, result)
            %{state | waiters: waiters}
        end

      expires_at = System.monotonic_time(:millisecond) + state.result_ttl
      timer = Process.send_after(self(), {:result_expired, ref}, state.result_ttl)

      results =
        state.results
        |> prune_results_map()
        |> limit_results(state.max_results)
        |> Map.put(ref, %{
          result: result,
          expires_at: expires_at,
          timer: timer
        })

      %{state | results: results}
    end

    defp prune_results(state), do: %{state | results: prune_results_map(state.results)}

    defp prune_results_map(results) do
      now = System.monotonic_time(:millisecond)
      Map.filter(results, fn {_ref, %{expires_at: expires_at}} -> expires_at > now end)
    end

    defp limit_results(results, max) when map_size(results) < max, do: results

    defp limit_results(results, _max) do
      {ref, result} = Enum.min_by(results, fn {_ref, result} -> result.expires_at end)
      _ = Process.cancel_timer(result.timer)
      Map.delete(results, ref)
    end

    defp release_entry(state, ref) do
      case Map.pop(state.entries, ref) do
        {nil, _entries} ->
          state

        {%{bytes: bytes, monitor: monitor}, entries} ->
          if is_reference(monitor), do: Process.demonitor(monitor, [:flush])
          %{state | entries: entries, reserved_bytes: state.reserved_bytes - bytes}
      end
    end

    defp call(pid, request, timeout, unknown_ref) do
      try do
        GenServer.call(pid, request, timeout)
      catch
        :exit, {:timeout, _} when is_reference(unknown_ref) -> {:unknown, unknown_ref}
        :exit, {:timeout, _} -> {:error, :writer_timeout}
        :exit, _ -> {:error, :writer_down}
      end
    end

    defp admission(%SendCapability{admission: admission}) when is_pid(admission),
      do: {:ok, admission}

    defp admission(%SendCapability{writer: writer}) when is_pid(writer) do
      case :persistent_term.get({Abyss.Dispatcher.Writer, writer}, nil) do
        admission when is_pid(admission) -> {:ok, admission}
        nil -> {:error, :writer_down}
      end
    end

    defp admission(_capability), do: {:error, :writer_down}

    @impl true
    def terminate(_reason, state) do
      if is_pid(state.writer), do: :persistent_term.erase({Abyss.Dispatcher.Writer, state.writer})
      :ok
    end
  end

  defmodule Writer do
    use GenServer

    def start_link(opts) do
      case Keyword.fetch(opts, :admission) do
        {:ok, _admission} ->
          GenServer.start_link(__MODULE__, opts)

        :error ->
          with {:ok, admission} <-
                 Admission.start_link(
                   generation: Keyword.fetch!(opts, :generation),
                   max_queue: Keyword.fetch!(opts, :max_queue),
                   max_bytes: Keyword.fetch!(opts, :max_bytes)
                 ) do
            GenServer.start_link(
              __MODULE__,
              opts |> Keyword.put(:admission, admission) |> Keyword.put(:owns_admission, true)
            )
          end
      end
    end

    def enqueue(pid, capability, remote, bytes, timeout \\ 100) do
      with {:ok, ref} <-
             Admission.reserve(pid, capability, Admission.size(remote, bytes), timeout) do
        Admission.submit(capability, ref, remote, bytes, timeout)
        |> case do
          :ok -> {:ok, ref}
          error -> error
        end
      end
    end

    def await(_pid, capability, ref, timeout \\ 100)
        when is_reference(ref) do
      Admission.await(capability, ref, timeout)
    end

    @impl true
    def init(opts) do
      Process.flag(:trap_exit, true)

      :ok =
        Admission.bind(
          Keyword.fetch!(opts, :admission),
          self(),
          Keyword.fetch!(opts, :owner)
        )

      {:ok,
       %{
         socket: Keyword.fetch!(opts, :socket),
         transport: Keyword.fetch!(opts, :transport),
         owner: Keyword.fetch!(opts, :owner),
         owner_monitor: Process.monitor(Keyword.fetch!(opts, :owner)),
         owns_admission: Keyword.get(opts, :owns_admission, false),
         generation: Keyword.fetch!(opts, :generation),
         max_queue: Keyword.fetch!(opts, :max_queue),
         max_bytes: Keyword.fetch!(opts, :max_bytes),
         admission: Keyword.fetch!(opts, :admission),
         queue: :queue.new(),
         queue_bytes: 0,
         sending: false
       }}
    end

    @impl true
    def handle_cast({:submit, generation, ref, remote, bytes}, state)
        when generation == state.generation and is_tuple(remote) and is_binary(bytes) and
               byte_size(bytes) >= 0 do
      {:noreply,
       maybe_send(%{
         state
         | queue: :queue.in({ref, remote, bytes}, state.queue),
           queue_bytes: state.queue_bytes + byte_size(bytes)
       })}
    end

    def handle_cast({:submit, _generation, _ref, _remote, _bytes}, state), do: {:noreply, state}

    @impl true
    def handle_info({:send_result, ref, result}, state) do
      completed = normalize_result(result)

      Admission.complete(state.admission, state.generation, ref, completed)

      send(
        state.owner,
        {:abyss_dispatcher_send, state.generation, ref, completed, monotonic_time()}
      )

      {:noreply, maybe_send(%{state | sending: false})}
    end

    def handle_info(
          {:DOWN, monitor, :process, owner, reason},
          %{owner: owner, owner_monitor: monitor} = state
        ),
        do: {:stop, owner_down_reason(reason), state}

    def handle_info({:EXIT, owner, reason}, %{owner: owner} = state),
      do: {:stop, owner_down_reason(reason), state}

    defp maybe_send(%{sending: true} = state), do: state

    defp maybe_send(state) do
      case :queue.out(state.queue) do
        {{:value, {ref, remote, bytes}}, queue} ->
          result =
            try do
              send_target(state, remote, bytes)
            rescue
              error -> {:error, error}
            catch
              kind, reason -> {:error, {kind, reason}}
            end

          send(self(), {:send_result, ref, result})

          %{
            state
            | queue: queue,
              queue_bytes: state.queue_bytes - byte_size(bytes),
              sending: true
          }

        {:empty, _} ->
          state
      end
    end

    defp send_target(state, {kind, _} = operation, bytes)
         when kind in [:native, :native_reply],
         do: state.transport.send(state.socket, operation, bytes)

    defp send_target(state, {:scoped, destination}, bytes),
      do: state.transport.send(state.socket, destination, bytes)

    defp send_target(state, {ip, port}, bytes),
      do: state.transport.send(state.socket, ip, port, bytes)

    defp monotonic_time, do: System.monotonic_time(:microsecond)
    defp owner_down_reason(:normal), do: :normal
    defp owner_down_reason(reason), do: {:owner_down, reason}
    defp normalize_result(:ok), do: {:ok, monotonic_time()}
    defp normalize_result({:ok, at}) when is_integer(at), do: {:ok, at}
    defp normalize_result({:error, _} = error), do: error
    defp normalize_result(other), do: {:error, {:invalid_send_result, other}}

    @impl true
    def terminate(_reason, state) do
      :persistent_term.erase({__MODULE__, self()})

      if state.owns_admission and Process.alive?(state.admission),
        do: GenServer.stop(state.admission, :normal, 1_000)

      :ok
    end
  end

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  def dispatch(pid, remote, bytes, received_at, timeout \\ 100) do
    try do
      GenServer.call(pid, {:datagram, remote, bytes, received_at}, timeout)
    catch
      :exit, {:timeout, _} -> {:error, :dispatcher_overloaded}
      :exit, reason -> {:error, reason}
    end
  end

  @doc false
  def dispatch_with_metadata(pid, remote, bytes, received_at, metadata, timeout) do
    GenServer.call(pid, {:datagram, remote, bytes, received_at, metadata}, timeout)
  catch
    :exit, reason -> {:error, reason}
  end

  def send(capability, remote, bytes, timeout \\ 100)
      when is_struct(capability, SendCapability) and is_tuple(remote) and is_binary(bytes) and
             byte_size(bytes) >= 0 do
    Writer.enqueue(capability.writer, capability, remote, bytes, timeout)
  end

  def send_receipt(capability, remote, bytes, timeout \\ 100)
      when is_struct(capability, SendCapability) and is_tuple(remote) and is_binary(bytes) and
             byte_size(bytes) >= 0 do
    with {:ok, ref} <- send(capability, remote, bytes, timeout) do
      Writer.await(capability.writer, capability, ref, timeout)
    end
  end

  def routes(pid), do: GenServer.call(pid, :routes)

  @impl true
  def init(opts) do
    module = Keyword.fetch!(opts, :module)
    module_opts = Keyword.get(opts, :module_options, [])
    generation = make_ref()

    Process.flag(:trap_exit, true)

    with {:ok, admission} <-
           Admission.start_link(
             generation: generation,
             max_queue: Keyword.fetch!(opts, :max_queue),
             max_bytes: Keyword.fetch!(opts, :max_bytes)
           ),
         {:ok, writer} <-
           Writer.start_link(
             socket: Keyword.fetch!(opts, :socket),
             transport: Keyword.fetch!(opts, :transport),
             owner: self(),
             generation: generation,
             max_queue: Keyword.fetch!(opts, :max_queue),
             max_bytes: Keyword.fetch!(opts, :max_bytes),
             admission: admission
           ),
         {:ok, callback_state} <-
           init_callback(
             module,
             %{
               local_info: Keyword.fetch!(opts, :local_info),
               generation: generation,
               send: %SendCapability{writer: writer, generation: generation, admission: admission},
               send_fun: fn remote, bytes ->
                 send_receipt(
                   %SendCapability{writer: writer, generation: generation, admission: admission},
                   remote,
                   bytes
                 )
               end
             },
             module_opts,
             writer,
             admission
           ) do
      {:ok,
       %{
         module: module,
         callback_state: callback_state,
         listener: Keyword.get(opts, :listener),
         writer: writer,
         admission: admission,
         generation: generation,
         send: %SendCapability{writer: writer, generation: generation, admission: admission},
         routes: %{},
         monitors: %{}
       }}
    end
  end

  @impl true
  def handle_call(:routes, _from, state), do: {:reply, state.routes, state}

  def handle_call({:datagram, remote, bytes, received_at}, from, state),
    do: handle_call({:datagram, remote, bytes, received_at, %{}}, from, state)

  def handle_call({:datagram, remote, bytes, received_at, metadata}, _from, state)
      when is_tuple(remote) and is_binary(bytes) do
    context = %{
      local: self(),
      generation: state.generation,
      send: state.send,
      send_fun: fn remote, bytes -> send_receipt(state.send, remote, bytes) end,
      routes: state.routes,
      state: state.callback_state
    }

    context = Map.merge(context, Map.take(metadata, [:ancillary, :local_info]))

    result =
      try do
        state.module.handle_datagram(remote, bytes, received_at, context)
      rescue
        error -> {:drop, {:callback_error, error}, state.callback_state}
      catch
        kind, reason -> {:drop, {:callback_error, {kind, reason}}, state.callback_state}
      end

    case result do
      {:ok, callback_state} ->
        {:reply, :ok, %{state | callback_state: callback_state}}

      {:drop, reason, callback_state} ->
        {:reply, {:dropped, reason}, %{state | callback_state: callback_state}}

      {:new, keys, pid, callback_state} ->
        {:reply, :ok, register(state, keys, pid, remote, callback_state)}

      {:route, keys, pid, callback_state} ->
        {:reply, :ok, register(state, keys, pid, remote, callback_state)}

      _ ->
        {:reply, {:error, :invalid_dispatch_result}, state}
    end
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, _pid, _reason}, state) do
    {keys, monitors} =
      Enum.reduce(state.routes, {[], state.monitors}, fn {key, route}, {removed, mons} ->
        if route.monitor == monitor,
          do: {[key | removed], Map.delete(mons, monitor)},
          else: {removed, mons}
      end)

    {:noreply, %{state | routes: Map.drop(state.routes, keys), monitors: monitors}}
  end

  def handle_info({:abyss_dispatcher_send, _generation, _ref, _result, _at}, state),
    do: {:noreply, state}

  def handle_info({:EXIT, writer, reason}, %{writer: writer} = state) do
    if is_pid(state.listener), do: send(state.listener, {:abyss_dispatcher_writer_error, reason})

    {:stop, {:writer_exit, reason}, state}
  end

  def handle_info({:EXIT, admission, reason}, %{admission: admission} = state),
    do: {:stop, {:admission_exit, reason}, state}

  def handle_info({:abyss_dispatcher_writer_error, _reason}, state), do: {:noreply, state}

  @impl true
  def terminate(reason, state) do
    if function_exported?(state.module, :terminate, 2),
      do: state.module.terminate(reason, state.callback_state)

    if is_pid(state.writer), do: stop_child(state.writer)
    if is_pid(state.admission), do: stop_child(state.admission)

    :ok
  end

  defp register(state, [], _pid, _remote, callback_state),
    do: %{state | callback_state: callback_state}

  defp register(state, keys, pid, remote, callback_state) when is_pid(pid) and is_list(keys) do
    monitor =
      Enum.find_value(state.routes, fn {_key, route} ->
        case route do
          %{pid: ^pid, monitor: existing} -> existing
          _ -> nil
        end
      end) || Process.monitor(pid)

    route = %{pid: pid, remote: remote, generation: state.generation, monitor: monitor}
    routes = Enum.reduce(keys, state.routes, &Map.put(&2, &1, route))
    monitors = rebuild_monitors(state.monitors, routes)

    %{
      state
      | routes: routes,
        monitors: monitors,
        callback_state: callback_state
    }
  end

  defp register(state, _keys, _pid, _remote, callback_state),
    do: %{state | callback_state: callback_state}

  defp rebuild_monitors(existing, routes) do
    monitors =
      Enum.reduce(routes, %{}, fn {key, route}, acc ->
        Map.update(acc, route.monitor, [key], &[key | &1])
      end)

    existing
    |> Map.keys()
    |> Enum.reject(&Map.has_key?(monitors, &1))
    |> Enum.each(&Process.demonitor(&1, [:flush]))

    monitors
  end

  defp init_callback(module, context, module_opts, writer, admission) do
    case module.init(context, module_opts) do
      {:ok, _callback_state} = ok ->
        ok

      {:error, _reason} = error ->
        stop_blocked_child(writer)
        stop_child(admission)
        error
    end
  end

  defp stop_blocked_child(pid) do
    monitor = Process.monitor(pid)
    Process.unlink(pid)
    Process.exit(pid, :kill)

    receive do
      {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
    after
      100 -> :ok
    end
  end

  defp stop_child(pid) do
    try do
      GenServer.stop(pid, :normal, 100)
    catch
      :exit, _reason -> stop_blocked_child(pid)
    end
  end
end

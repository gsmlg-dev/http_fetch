defmodule Abyss.Listener do
  @moduledoc """
  Supervised owner of a UDP endpoint. Reception uses one active credit, with
  a finite handler ceiling and no user-space pending queue. A fixed starter
  process isolates custom handler startup from socket control operations.

  Pause discards newly received packets while retaining the socket and existing
  handlers. Drain stops admission and waits for admitted handlers, then closes
  I/O. Dispatcher drain is host cleanup, not application-session completion.
  """
  use GenServer, restart: :transient
  alias Abyss.Transport.UDP.{Core, Multicast}

  @listener_info_table :abyss_listener_info
  @membership_table :abyss_udp_memberships
  @owner_table :abyss_udp_owners
  @type state :: map()

  def start_link({id, server, config}), do: GenServer.start_link(__MODULE__, {id, server, config})
  def stop(server), do: GenServer.stop(server, :normal)
  def pause(server), do: GenServer.call(server, :pause)
  def resume(server), do: GenServer.call(server, :resume)
  def status(server), do: GenServer.call(server, :status)
  def drain(server, deadline), do: GenServer.call(server, {:drain, deadline}, :infinity)
  def join(server, membership), do: GenServer.call(server, {:membership, :join, membership})
  def leave(server, membership), do: GenServer.call(server, {:membership, :leave, membership})
  def memberships(server), do: GenServer.call(server, :memberships)
  def listener_info(server), do: GenServer.call(server, :listener_info)
  def socket_info(server), do: GenServer.call(server, :socket_info)

  def listener_info_cached(pid) when is_pid(pid) do
    ensure_info_table_exists()

    case :ets.lookup(@listener_info_table, pid) do
      [{^pid, local, _}] -> {:ok, local}
      [] -> :error
    end
  end

  def ensure_info_table_exists do
    Abyss.TableOwner.ensure_table(@listener_info_table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true
    ])
  end

  def clear_desired(server) do
    ensure_membership_table()
    :ets.match_delete(@membership_table, {{server, :_}, :_})
    Abyss.TableOwner.ensure_table(@owner_table, [:named_table, :public, :set])
    :ets.match_delete(@owner_table, {:_, server})
    Abyss.UDPAdmission.release_server(server)
    :ok
  end

  def cleanup_owner(pid) do
    ensure_info_table_exists()

    case :ets.take(@listener_info_table, pid) do
      [{^pid, _local, socket}] -> Abyss.Telemetry.unregister_socket(socket)
      [] -> :ok
    end

    Abyss.TableOwner.ensure_table(@owner_table, [:named_table, :public, :set])
    :ets.delete(@owner_table, pid)
    Abyss.UDPAdmission.release_owner(pid)
  end

  def for_server(server) do
    Abyss.TableOwner.ensure_table(@owner_table, [:named_table, :public, :set])

    for {pid, ^server} <- :ets.match_object(@owner_table, {:_, server}),
        Process.alive?(pid),
        do: pid
  end

  @impl true
  def init({id, server, config}) do
    Process.flag(:trap_exit, true)
    ensure_info_table_exists()
    ensure_membership_table()
    desired_key = {server, id}

    options =
      case normalize_transport_options(config) do
        {:ok, normalized} -> normalized
        {:error, reason} -> raise ArgumentError, "invalid transport options: #{inspect(reason)}"
      end

    initial =
      Enum.reduce(options, [], fn
        {:add_membership, membership}, desired -> Enum.uniq(desired ++ [membership])
        {:drop_membership, membership}, desired -> List.delete(desired, membership)
        _, desired -> desired
      end)

    desired =
      case :ets.lookup(@membership_table, desired_key) do
        [{^desired_key, saved}] -> saved
        [] -> Enum.uniq(initial)
      end

    desired = normalize_desired(desired)

    user_options =
      Enum.reject(options, fn
        {operation, _} when operation in [:add_membership, :drop_membership] -> true
        _ -> false
      end)

    transport_options =
      Core.merge_options(
        user_options ++ Enum.map(desired, &{:add_membership, &1}),
        active: false,
        mode: :binary,
        recbuf: config.udp_buffer_size,
        sndbuf: config.udp_buffer_size,
        buffer: 65_536
      )

    transport_options =
      if config.broadcast, do: transport_options ++ [broadcast: true], else: transport_options

    transport = config.transport_module

    case transport.listen(config.port, transport_options) do
      {:ok, socket} ->
        initialize_socket(socket, transport, id, server, config, desired_key, desired)

      {:error, reason} ->
        {:stop, reason}
    end
  end

  defp normalize_transport_options(%{
         datagram_options: %{io_backend: :socket_native},
         transport_options: options
       }),
       do: {:ok, options}

  defp normalize_transport_options(config),
    do: Core.normalize_options([], config.transport_options)

  defp normalize_desired(memberships) do
    desired =
      Enum.map(memberships, fn membership ->
        case Multicast.normalize_membership(membership) do
          {:ok, normalized} -> normalized
          {:error, reason} -> raise ArgumentError, "invalid membership: #{inspect(reason)}"
        end
      end)
      |> Enum.uniq()

    if length(desired) > 64, do: raise(ArgumentError, "at most 64 memberships per endpoint")
    desired
  end

  defp initialize_socket(socket, transport, id, server, config, key, desired) do
    generation = make_ref()

    with {:ok, local} <- transport.sockname(socket),
         :ok <- validate_capabilities(socket, transport, config, local, desired),
         {:ok, dispatcher} <- start_dispatcher(config, socket, transport, local),
         {:ok, starter} <- Abyss.ListenerStarter.start_link(self()),
         {:ok, runtime} <-
           start_runtime(config, socket, transport, local, {server, id}, generation, server) do
      span =
        Abyss.Telemetry.start_span(:listener, %{}, %{
          server_pid: server,
          listener_id: id,
          listener_socket: socket,
          handler: config.handler_module,
          local_info: local,
          broadcast: config.broadcast
        })

      Abyss.Telemetry.register_scope(server, config.handler_module)
      Abyss.Telemetry.register_socket(server, socket)
      Abyss.TableOwner.ensure_table(@owner_table, [:named_table, :public, :set])
      :ets.insert(@owner_table, {self(), server})
      Abyss.TableOwner.monitor_listener(self())
      :ets.insert(@listener_info_table, {self(), local, socket})
      :ets.insert(@membership_table, {key, desired})
      send(self(), :start_listening)

      {:ok,
       %{
         server_pid: server,
         server_config: config,
         listener_id: id,
         listener_socket: socket,
         listener_span: span,
         transport: transport,
         local_info: local,
         dispatcher: dispatcher,
         runtime: runtime,
         runtime_counter_source: runtime,
         runtime_drop_counters: %{
           dropped: 0,
           internal_events_rejected: %{timer: 0, send_outcomes: 0}
         },
         runtime_send:
           if(is_pid(runtime), do: Abyss.DatagramRuntime.info(runtime).send, else: nil),
         generation: generation,
         native_select: nil,
         starter: starter,
         mode: :running,
         armed: false,
         handlers: %{},
         reservation: nil,
         desired_key: key,
         memberships: desired,
         drain_waiter: nil,
         received: 0,
         dropped: 0,
         active_high_water: 0,
         retained_high_water: 0
       }}
    else
      {:error, reason} ->
        transport.close(socket)
        {:stop, reason}
    end
  end

  @impl true
  def handle_info(:start_listening, %{mode: :running} = state), do: rearm(state)
  def handle_info(:start_listening, state), do: {:noreply, state}

  def handle_info({:udp, socket, ip, port, data}, %{listener_socket: socket} = state),
    do: receive_packet({ip, port, data}, [], %{state | armed: false})

  def handle_info({:udp, socket, ip, port, ancillary, data}, %{listener_socket: socket} = state),
    do: receive_packet({ip, port, data}, ancillary, %{state | armed: false})

  def handle_info(
        {:"$socket", socket, :select, reference},
        %{
          listener_socket: socket,
          native_select: {_generation, {:select_info, :recvmsg, reference}}
        } = state
      ),
      do: rearm(%{state | armed: false, native_select: nil})

  def handle_info(
        {:"$socket", socket, :abort, {reference, reason}},
        %{
          listener_socket: socket,
          native_select: {_generation, {:select_info, :recvmsg, reference}}
        } = state
      ),
      do: {:stop, {:native_receive_abort, reason}, state}

  def handle_info({:native_datagram, generation, message}, %{generation: generation} = state) do
    state = %{state | armed: false}

    context = %{
      endpoint_id: {state.server_pid, state.listener_id},
      generation: generation,
      local_endpoint: state.local_info
    }

    case state.transport.datagram(message, context) do
      {:ok, datagram} ->
        receive_datagram(datagram, state)

      {:error, reason} ->
        bytes = IO.iodata_length(message.iov)
        Abyss.Telemetry.track_datagram_received(state.server_pid, bytes)
        state = %{state | received: state.received + 1}
        rearm(drop(state, reason, bytes))
    end
  end

  def handle_info({:runtime_drained, runtime}, %{runtime: runtime, mode: :draining} = state),
    do: complete_drain(%{state | runtime: nil})

  def handle_info(
        {:runtime_drop_counters, runtime, generation, counters},
        %{runtime_counter_source: runtime, generation: generation} = state
      ),
      do: {:noreply, %{state | runtime_drop_counters: counters}}

  def handle_info({:EXIT, runtime, reason}, %{runtime: runtime, mode: :draining} = state)
      when reason in [:normal, :killed],
      do: complete_drain(%{state | runtime: nil})

  def handle_info({:EXIT, runtime, reason}, %{runtime: runtime} = state),
    do: {:stop, {:runtime_exit, reason}, state}

  def handle_info({:udp_error, socket, reason}, %{listener_socket: socket} = state),
    do: {:stop, {:udp_error, reason}, state}

  def handle_info({:udp_passive, socket}, %{listener_socket: socket} = state),
    do: rearm(%{state | armed: false})

  def handle_info({:dispatch_result, token, result}, %{reservation: %{token: token}} = state) do
    state =
      case result do
        {:error, reason} -> drop(state, reason, byte_size(elem(state.reservation.packet, 2)))
        {:dropped, reason} -> drop(state, reason, byte_size(elem(state.reservation.packet, 2)))
        _ -> state
      end

    state = %{state | reservation: nil}
    if state.mode == :draining, do: finish_drain(state), else: rearm(state)
  end

  def handle_info(
        {:handler_started, token, result},
        %{reservation: %{token: token} = reservation} = state
      ) do
    _ = Process.cancel_timer(reservation.timer)
    valid? = state.mode == :running and not reservation.expired and now() <= reservation.deadline

    case {valid?, result} do
      {true, {:ok, pid}} ->
        ref = Process.monitor(pid)
        :ok = Abyss.UDPAdmission.admitted(reservation.slot, pid)
        send(pid, {:new_connection, state.listener_socket, reservation.packet})
        handlers = Map.put(state.handlers, ref, {pid, reservation.slot})

        rearm(%{
          state
          | handlers: handlers,
            reservation: nil,
            active_high_water: max(state.active_high_water, map_size(handlers))
        })

      {_, {:ok, pid}} ->
        Process.exit(pid, :kill)
        finish_reservation(state, :stale_admission)

      {_, error} ->
        finish_reservation(state, {:start_failed, error})
    end
  end

  def handle_info({:start_expired, token}, %{reservation: %{token: token}} = state) do
    # Keep the sole reservation until the fixed starter returns. This prevents
    # an unresponsive custom start_link from creating an unbounded start queue.
    {:noreply, expire_reservation(state, :start_deadline)}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, state) do
    case Map.pop(state.handlers, ref) do
      {nil, _} ->
        {:noreply, state}

      {{_pid, slot}, handlers} ->
        Abyss.UDPAdmission.release(slot)
        Abyss.Telemetry.track_work_finished(state.server_pid, reason)
        finish_drain(%{state | handlers: handlers})
    end
  end

  def handle_info(:drain_expired, state) do
    Enum.each(state.handlers, fn {_ref, {pid, _slot}} -> Process.exit(pid, :kill) end)
    complete_drain(state)
  end

  def handle_info({:EXIT, pid, reason}, %{starter: pid} = state),
    do: {:stop, {:starter_exit, reason}, state}

  def handle_info({:EXIT, pid, reason}, %{dispatcher: pid} = state),
    do: {:stop, {:dispatcher_exit, reason}, state}

  def handle_info({:abyss_dispatcher_writer_error, reason}, state) do
    Abyss.Telemetry.span_event(state.listener_span, :dispatcher_writer_error, %{reason: reason})
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def handle_call(:endpoint_info, _from, state) do
    runtime = endpoint_runtime_info(state)
    capabilities = capabilities(state)
    drops = endpoint_drops(state, runtime)

    info =
      Map.merge(runtime, %{
        local_endpoint: state.local_info,
        endpoint_id: {state.server_pid, state.listener_id},
        generation: state.generation,
        capabilities: capabilities,
        mode: state.mode,
        received: state.received
      })
      |> Map.merge(drops)

    {:reply, {:ok, info}, state}
  end

  def handle_call(:listener_info, _from, state), do: {:reply, state.local_info, state}

  def handle_call(:socket_info, _from, state),
    do: {:reply, {state.listener_socket, state.listener_span}, state}

  def handle_call(:memberships, _from, state), do: {:reply, state.memberships, state}

  def handle_call(:status, _from, state) do
    status = %{
      mode: state.mode,
      active_handlers: map_size(state.handlers),
      pending_count: 0,
      pending_bytes: 0,
      starting: if(state.reservation, do: 1, else: 0),
      retained_bytes:
        if(state.reservation, do: byte_size(elem(state.reservation.packet, 2)), else: 0),
      receive_credit: if(state.armed, do: 1, else: 0),
      received: state.received,
      dropped: state.dropped,
      active_high_water: state.active_high_water,
      retained_high_water: state.retained_high_water,
      local: state.local_info
    }

    {:reply, status, state}
  end

  def handle_call(:pause, _from, %{mode: :stopped} = state), do: {:reply, :ok, state}

  def handle_call(:resume, _from, %{mode: :stopped} = state),
    do: {:reply, {:error, :stopped}, state}

  def handle_call(:pause, _from, %{mode: :draining} = state),
    do: {:reply, {:error, :draining}, state}

  def handle_call(:pause, _from, state) do
    state = expire_reservation(state, :suspended)
    {:reply, :ok, %{state | mode: :suspended}}
  end

  def handle_call(:resume, _from, %{mode: :draining} = state),
    do: {:reply, {:error, :draining}, state}

  def handle_call(:resume, _from, state) do
    case arm(%{state | mode: :running}) do
      {:ok, state} -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:drain, _deadline}, _from, %{mode: :stopped} = state), do: {:reply, :ok, state}

  def handle_call({:drain, _deadline}, _from, %{drain_waiter: waiter} = state)
      when not is_nil(waiter),
      do: {:reply, {:error, :already_draining}, state}

  def handle_call({:drain, deadline}, from, state) do
    timer =
      if deadline == :infinity,
        do: nil,
        else: Process.send_after(self(), :drain_expired, max(deadline - now(), 0))

    state = %{state | mode: :draining, drain_waiter: {from, timer}}
    if is_pid(state.runtime), do: Abyss.DatagramRuntime.drain(state.runtime, deadline)
    finish_drain(state)
  end

  def handle_call({:membership, _operation, _membership}, _from, %{mode: mode} = state)
      when mode in [:draining, :stopped],
      do: {:reply, {:error, mode}, state}

  def handle_call({:membership, operation, membership}, _from, state) do
    with :ok <- membership_topology(state),
         {:ok, normalized} <- Multicast.normalize_membership(membership),
         :ok <- membership_family(normalized, state),
         :ok <- membership_operation(operation, normalized, state) do
      desired =
        case operation do
          :join -> Enum.uniq(state.memberships ++ [normalized])
          :leave -> List.delete(state.memberships, normalized)
        end

      :ets.insert(@membership_table, {state.desired_key, desired})
      {:reply, :ok, %{state | memberships: desired}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp membership_topology(state) do
    if length(for_server(state.server_pid)) > 1 or state.server_config.dynamic_listeners,
      do: {:error, :multiple_receive_endpoints},
      else: :ok
  end

  defp membership_family({group, _interface}, state) do
    with {:ok, {local, _port}} <- state.transport.sockname(state.listener_socket) do
      expected = Multicast.family(local)
      actual = Multicast.family(group)

      if expected == actual,
        do: :ok,
        else: {:error, {:membership_family_mismatch, expected, actual}}
    end
  end

  defp membership_operation(:join, membership, state) do
    cond do
      membership in state.memberships -> :ok
      length(state.memberships) >= 64 -> {:error, :membership_limit}
      true -> state.transport.setopts(state.listener_socket, add_membership: membership)
    end
  end

  defp membership_operation(:leave, membership, state) do
    if membership in state.memberships,
      do: state.transport.setopts(state.listener_socket, drop_membership: membership),
      else: :ok
  end

  defp endpoint_runtime_info(%{runtime: runtime}) when is_pid(runtime),
    do: Abyss.DatagramRuntime.info(runtime)

  defp endpoint_runtime_info(%{runtime_counter_source: runtime, runtime_drop_counters: counters})
       when is_pid(runtime),
       do: counters

  defp endpoint_runtime_info(_state), do: %{}

  defp endpoint_drops(%{runtime_counter_source: runtime, dropped: ingress}, info)
       when is_pid(runtime) do
    %{
      dropped: ingress + info.dropped,
      drop_counts: %{ingress: ingress, runtime: info.dropped}
    }
  end

  defp endpoint_drops(state, _info), do: %{dropped: state.dropped}

  defp receive_datagram(datagram, state) do
    bytes = byte_size(datagram.payload)
    Abyss.Telemetry.track_datagram_received(state.server_pid, bytes)
    state = %{state | received: state.received + 1}

    cond do
      state.mode != :running ->
        rearm(drop(state, state.mode, bytes))

      bytes > state.server_config.max_packet_size ->
        rearm(drop(state, :packet_too_large, bytes))

      true ->
        admit_datagram(datagram, state)
    end
  end

  defp admit_datagram(datagram, state) do
    missing =
      Enum.filter(
        state.server_config.datagram_options.required_metadata,
        &is_nil(Map.get(datagram, &1))
      )

    case missing do
      [] ->
        case Abyss.DatagramRuntime.admit(state.runtime, datagram) do
          :ok -> rearm(state)
          {:error, _} -> rearm(state)
        end

      fields ->
        rearm(drop(state, {:missing_metadata, fields}, byte_size(datagram.payload)))
    end
  end

  defp receive_packet({_ip, _port, data} = packet, ancillary, state) do
    bytes = byte_size(data)
    Abyss.Telemetry.track_datagram_received(state.server_pid, bytes)
    state = %{state | received: state.received + 1}

    cond do
      state.mode != :running ->
        rearm(drop(state, state.mode, bytes))

      bytes > state.server_config.max_packet_size ->
        Abyss.Telemetry.span_event(state.listener_span, :packet_too_large, %{
          packet_size: bytes,
          max_size: state.server_config.max_packet_size
        })

        rearm(drop(state, :packet_too_large, bytes))

      is_pid(state.runtime) ->
        admit_gen_udp(packet, ancillary, state)

      true ->
        receive_legacy_packet(packet, ancillary, bytes, state)
    end
  end

  defp receive_legacy_packet(packet, ancillary, bytes, state) do
    cond do
      is_pid(state.dispatcher) ->
        token = make_ref()
        reservation = %{token: token, packet: packet, timer: nil, slot: nil, expired: false}

        Abyss.ListenerStarter.dispatch(
          state.starter,
          {token, state.dispatcher, packet, Abyss.Telemetry.monotonic_time(),
           %{ancillary: ancillary, local_info: state.local_info}}
        )

        {:noreply,
         %{
           state
           | reservation: reservation,
             retained_high_water: max(bytes, state.retained_high_water)
         }}

      map_size(state.handlers) >= state.server_config.num_connections ->
        rearm(drop(state, :handler_limit, bytes))

      state.reservation != nil ->
        rearm(drop(state, :starting_limit, bytes))

      true ->
        case Abyss.UDPAdmission.reserve(
               state.server_pid,
               self(),
               state.server_config.num_connections
             ) do
          {:ok, slot} -> start_reservation(packet, ancillary, bytes, slot, state)
          {:error, reason} -> rearm(drop(state, reason, bytes))
        end
    end
  end

  defp admit_gen_udp({ip, port, data}, ancillary, state) do
    datagram =
      Abyss.Datagram.from_gen_udp({ip, port, ancillary, data}, %{
        endpoint_id: {state.server_pid, state.listener_id},
        generation: state.generation,
        local_endpoint: state.local_info
      })

    admit_datagram(datagram, state)
  end

  defp start_reservation({ip, port, _data} = packet, ancillary, bytes, slot, state) do
    token = make_ref()
    deadline = now() + state.server_config.admission_start_timeout

    timer =
      Process.send_after(
        self(),
        {:start_expired, token},
        state.server_config.admission_start_timeout
      )

    span =
      Abyss.Telemetry.start_child_span_with_sampling(
        state.listener_span,
        :connection,
        %{monotonic_time: Abyss.Telemetry.monotonic_time()},
        %{
          server_pid: state.server_pid,
          remote_address: ip,
          remote_port: port,
          ancillary: ancillary,
          local_info: state.local_info
        },
        sample_rate: state.server_config.connection_telemetry_sample_rate
      )

    reservation = %{
      slot: slot,
      token: token,
      deadline: deadline,
      timer: timer,
      expired: false,
      packet: packet
    }

    Abyss.ListenerStarter.start(
      state.starter,
      {token, state.server_pid, state.listener_socket, state.server_config, span}
    )

    {:noreply,
     %{
       state
       | reservation: reservation,
         retained_high_water: max(bytes, state.retained_high_water)
     }}
  end

  defp expire_reservation(%{reservation: nil} = state, _reason), do: state
  defp expire_reservation(%{reservation: %{expired: true}} = state, _reason), do: state

  defp expire_reservation(state, reason) do
    {ip, port, data} = state.reservation.packet
    state = drop(state, reason, byte_size(data))
    %{state | reservation: %{state.reservation | expired: true, packet: {ip, port, <<>>}}}
  end

  defp finish_reservation(state, reason) do
    Abyss.UDPAdmission.release(state.reservation.slot)

    state =
      if state.reservation.expired,
        do: state,
        else: drop(state, reason, byte_size(elem(state.reservation.packet, 2)))

    state = %{state | reservation: nil}
    if state.mode == :draining, do: finish_drain(state), else: rearm(state)
  end

  defp drop(state, reason, bytes) do
    Abyss.Telemetry.track_datagram_dropped(state.server_pid, reason, bytes)
    %{state | dropped: state.dropped + 1}
  end

  defp rearm(state) do
    case arm(state) do
      {:ok, state} -> {:noreply, state}
      {:error, reason} -> {:stop, {:arm_failed, reason}, state}
    end
  end

  defp arm(%{armed: true} = state), do: {:ok, state}
  defp arm(%{reservation: reservation} = state) when not is_nil(reservation), do: {:ok, state}
  defp arm(%{mode: :draining} = state), do: {:ok, state}
  defp arm(%{mode: :stopped} = state), do: {:ok, state}

  defp arm(%{server_config: %{datagram_options: %{io_backend: :socket_native}}} = state) do
    operation = make_ref()

    case state.transport.arm(state.listener_socket, operation) do
      {:ok, message} ->
        send(self(), {:native_datagram, state.generation, message})
        {:ok, %{state | armed: true, native_select: nil}}

      {:select, select_info} ->
        {:ok, %{state | armed: true, native_select: {state.generation, select_info}}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp arm(state) do
    case state.transport.setopts(state.listener_socket, active: :once) do
      :ok -> {:ok, %{state | armed: true}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp finish_drain(%{runtime: runtime} = state) when is_pid(runtime), do: {:noreply, state}

  defp finish_drain(%{mode: :draining, handlers: handlers, reservation: nil} = state)
       when map_size(handlers) == 0,
       do: complete_drain(state)

  defp finish_drain(state), do: {:noreply, state}

  defp complete_drain(%{drain_waiter: {from, timer}} = state) do
    _ = if timer, do: Process.cancel_timer(timer)
    if is_pid(state.starter), do: Process.exit(state.starter, :shutdown)

    Enum.each(state.handlers, fn {ref, {pid, slot}} ->
      Process.demonitor(ref, [:flush])
      Process.exit(pid, :kill)
      Abyss.UDPAdmission.release(slot)
      Abyss.Telemetry.track_work_finished(state.server_pid, :drain_deadline)
    end)

    if state.reservation do
      _ = if state.reservation.timer, do: Process.cancel_timer(state.reservation.timer)
      if state.reservation.slot, do: Abyss.UDPAdmission.release(state.reservation.slot)
    end

    Abyss.Telemetry.unregister_socket(state.listener_socket)
    force_runtime_cleanup(state)
    if is_pid(state.dispatcher), do: Process.exit(state.dispatcher, :kill)
    cancel_native_receive(state)
    state.transport.close(state.listener_socket)
    GenServer.reply(from, :ok)

    {:noreply,
     %{
       state
       | mode: :stopped,
         armed: false,
         drain_waiter: nil,
         dispatcher: nil,
         runtime: nil,
         starter: nil,
         handlers: %{},
         reservation: nil
     }}
  end

  defp complete_drain(state), do: {:noreply, state}

  defp force_runtime_cleanup(%{runtime_send: %{writer: writer, admission: admission}} = state) do
    # Kill blocked components directly: a trapped EXIT cannot interrupt a socket send.
    :persistent_term.erase({Abyss.Dispatcher.Writer, writer})
    Process.exit(writer, :kill)
    Process.exit(admission, :kill)
    if is_pid(state.runtime), do: Process.exit(state.runtime, :kill)
  end

  defp force_runtime_cleanup(state) do
    if is_pid(state.runtime), do: Process.exit(state.runtime, :kill)
  end

  defp cancel_native_receive(%{native_select: {_, select_info}} = state),
    do: state.transport.cancel(state.listener_socket, select_info)

  defp cancel_native_receive(_state), do: :ok

  defp now, do: System.monotonic_time(:millisecond)

  defp ensure_membership_table do
    Abyss.TableOwner.ensure_table(@membership_table, [:named_table, :public, :set])
  end

  @impl true
  def terminate(_reason, state) do
    :ets.delete(@listener_info_table, self())
    :ets.delete(@owner_table, self())
    Abyss.Telemetry.unregister_socket(state.listener_socket)
    if is_pid(state.starter), do: Process.exit(state.starter, :shutdown)

    Enum.each(state.handlers, fn {ref, {pid, slot}} ->
      Process.demonitor(ref, [:flush])
      Process.exit(pid, :kill)
      Abyss.UDPAdmission.release(slot)
    end)

    if state.reservation do
      _ = if state.reservation.timer, do: Process.cancel_timer(state.reservation.timer)
      if state.reservation.slot, do: Abyss.UDPAdmission.release(state.reservation.slot)
    end

    force_runtime_cleanup(state)
    if is_pid(state.dispatcher), do: Process.exit(state.dispatcher, :kill)

    cancel_native_receive(state)
    state.transport.close(state.listener_socket)
    Abyss.Telemetry.stop_span(state.listener_span)
    :ok
  end

  defp start_runtime(%{datagram_options: %{datagram_handler: nil}}, _, _, _, _, _, _),
    do: {:ok, nil}

  defp start_runtime(config, socket, transport, _local, endpoint_id, generation, server) do
    Abyss.DatagramRuntime.start_link(%{
      config: config,
      socket: socket,
      transport: transport,
      owner: self(),
      endpoint_id: endpoint_id,
      generation: generation,
      server: server
    })
  end

  defp validate_capabilities(socket, transport, config, local, desired) do
    available =
      capabilities(%{
        server_config: config,
        transport: transport,
        listener_socket: socket,
        local_info: local,
        memberships: desired
      })

    case Enum.find(config.datagram_options.required_capabilities, fn name ->
           not Map.fetch!(available, name).enabled
         end) do
      nil ->
        :ok

      name ->
        {:error, {:required_capability_unavailable, name, Map.fetch!(available, name).reason}}
    end
  end

  defp capabilities(state) do
    if state.server_config.datagram_options.io_backend == :socket_native do
      state.transport.capabilities(state.listener_socket)
    else
      gen_udp_capabilities(state)
    end
  end

  defp gen_udp_capabilities(%{transport: transport} = state)
       when transport in [
              Abyss.Transport.UDP,
              Abyss.Transport.UDP.Unicast,
              Abyss.Transport.UDP.Broadcast,
              Abyss.Transport.UDP.Multicast
            ] do
    unavailable = %{supported: false, enabled: false, reason: :gen_udp_metadata_unavailable}
    family = Multicast.family(elem(state.local_info, 0))

    %{
      adapter: :gen_udp,
      driver: if(is_port(state.listener_socket), do: :inet, else: :socket),
      family: Multicast.family(elem(state.local_info, 0)),
      platform: :os.type(),
      runtime: %{otp: :erlang.system_info(:otp_release), erts: :erlang.system_info(:version)},
      destination: unavailable,
      interface_index: unavailable,
      local_address: unavailable,
      source_control: unavailable,
      strict_group_filter: %{
        supported:
          :os.type() == {:unix, :linux} and is_port(state.listener_socket) and
            Multicast.family(elem(state.local_info, 0)) == :inet,
        enabled: gen_udp_group_filter_enabled?(state.listener_socket),
        reason: if(gen_udp_group_filter_enabled?(state.listener_socket), do: nil, else: :disabled)
      },
      strict_interface_filter: unavailable,
      memberships: %{supported: true, enabled: true, reason: nil},
      scoped_send: gen_udp_scoped_send(state.listener_socket, family)
    }
  end

  defp gen_udp_capabilities(state) do
    unavailable = %{supported: false, enabled: false, reason: :custom_transport_unverified}

    Map.new(
      [
        :destination,
        :interface_index,
        :local_address,
        :source_control,
        :strict_group_filter,
        :strict_interface_filter,
        :memberships,
        :scoped_send
      ],
      &{&1, unavailable}
    )
    |> Map.merge(%{
      adapter: :custom,
      driver: nil,
      transport: state.transport,
      family: Multicast.family(elem(state.local_info, 0)),
      platform: :os.type()
    })
  end

  defp gen_udp_scoped_send(socket, :inet6) when is_port(socket),
    do: %{supported: true, enabled: true, reason: nil}

  defp gen_udp_scoped_send(_socket, :inet6),
    do: %{supported: false, enabled: false, reason: :scoped_sockaddr_send}

  defp gen_udp_scoped_send(_socket, _family),
    do: %{supported: false, enabled: false, reason: :family_unsupported}

  defp gen_udp_group_filter_enabled?(socket) when is_port(socket) do
    case :inet.getopts(socket, [{:raw, 0, 49, 4}]) do
      {:ok, [{:raw, 0, 49, <<0::native-signed-32>>}]} -> true
      _ -> false
    end
  end

  defp gen_udp_group_filter_enabled?(_socket), do: false

  defp start_dispatcher(
         %Abyss.ServerConfig{datagram_dispatcher: nil},
         _socket,
         _transport,
         _local
       ),
       do: {:ok, nil}

  defp start_dispatcher(config, socket, transport, local_info) do
    {module, options} =
      case config.datagram_dispatcher do
        module when is_atom(module) -> {module, config.dispatcher_options}
        {module, options} -> {module, Keyword.merge(config.dispatcher_options, options)}
      end

    Abyss.Dispatcher.start_link(
      module: module,
      module_options: options,
      socket: socket,
      transport: transport,
      local_info: local_info,
      listener: self(),
      max_queue: config.dispatcher_max_queue,
      max_bytes: config.dispatcher_max_queue_bytes
    )
  end
end

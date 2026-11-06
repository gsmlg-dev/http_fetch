defmodule Abyss.RuntimeTestHandler do
  @behaviour Abyss.DatagramHandler
  def init(opts, context) do
    send(opts[:owner], {:initialized, self(), context})
    if opts[:block_init], do: receive(do: (:continue -> :ok))
    {:ok, %{owner: opts[:owner], count: 0, opts: opts}}
  end

  def handle_datagram(datagram, state) do
    send(state.owner, {:invoked, self(), datagram, state.count})
    if datagram.payload == "block", do: receive(do: (:continue -> :ok))
    state = %{state | count: state.count + 1}

    actions_for(datagram, state)
  end

  defp actions_for(%{payload: "error"}, state), do: {:error, :returned_error, state}

  defp actions_for(datagram, state) do
    case datagram.payload do
      "invalid" ->
        {:ok, state, [{:reply, "should-not-send"}, :invalid]}

      "invalid-scope" ->
        {:ok, state,
         [{:reply, "partial"}, {:send, Map.put(datagram.peer, :scope_id, "bad"), "bad"}]}

      "huge-timer" ->
        {:ok, state, [{:reply, "partial"}, {:timer, :bad, Integer.pow(2, 128), nil}]}

      "improper" ->
        {:ok, state, [{:reply, "partial"} | :bad]}

      "many-actions" ->
        {:ok, state, List.duplicate({:reply, "partial"}, 33)}

      "timer" ->
        {:ok, state, [{:timer, :reply, 5, datagram.peer}]}

      "stop" ->
        {:stop, :done, state, [{:reply, "accepted"}]}

      _ ->
        {:ok, state, [{:reply, <<state.count::32>>, datagram.payload |> strict()}] |> actions()}
    end
  end

  defp strict("strict"), do: :strict
  defp strict(_), do: :route
  defp actions([{:reply, data, :route}]), do: [{:reply, data}]
  defp actions(actions), do: actions

  def handle_event({:timer, :reply, peer}, state),
    do: {:ok, state, [{:send, peer, "delayed"}]}

  def handle_event({:send_outcomes, generation, token, outcomes}, state) do
    send(state.owner, {:outcomes, generation, token, outcomes})
    {:ok, state, []}
  end

  def terminate(reason, state) do
    send(state.owner, {:terminated, self(), reason, state.count})
    if state.opts[:block_terminate], do: receive(do: (:continue -> :ok))
  end
end

defmodule Abyss.RuntimeIdleTestHandler do
  @behaviour Abyss.DatagramHandler
  defdelegate init(opts, context), to: Abyss.RuntimeTestHandler
  defdelegate handle_event(event, state), to: Abyss.RuntimeTestHandler
  defdelegate terminate(reason, state), to: Abyss.RuntimeTestHandler

  def handle_datagram(%{payload: "a"} = datagram, state) do
    send(state.owner, {:idle_callback, self()})
    receive do: (:continue -> :ok)
    Abyss.RuntimeTestHandler.handle_datagram(datagram, state)
  end

  defdelegate handle_datagram(datagram, state), to: Abyss.RuntimeTestHandler
end

defmodule Abyss.RuntimeBlockingTransport do
  alias Abyss.Transport.UDP
  defdelegate listen(port, options), to: UDP
  defdelegate sockname(socket), to: UDP
  defdelegate setopts(socket, options), to: UDP
  defdelegate close(socket), to: UDP

  def send(socket, ip, port, data) do
    owner = :persistent_term.get({__MODULE__, :owner})
    send(owner, {:writer_blocked, self()})

    receive do
      :continue -> :ok
    end

    UDP.send(socket, ip, port, data)
  end
end

defmodule Abyss.DatagramRuntimeTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Endpoint

  defp endpoint(opts \\ []) do
    config =
      Keyword.merge(
        [
          datagram_handler: Abyss.RuntimeTestHandler,
          handler_options: [owner: self()],
          port: 0,
          transport_options: [ip: {127, 0, 0, 1}]
        ],
        opts
      )

    {:ok, server} = Endpoint.start_link(config)
    Process.unlink(server)
    on_exit(fn -> if Process.alive?(server), do: Endpoint.stop(server, 100) end)
    {:ok, {_ip, port}} = Endpoint.local_endpoint(server)
    {:ok, client} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(client) end)
    {server, client, port}
  end

  defp packet(client, port, payload), do: :gen_udp.send(client, {127, 0, 0, 1}, port, payload)
  defp response(client), do: :gen_udp.recv(client, 0, 1000)

  test "new per-datagram consumer preserves empty datagrams and finishes returned state" do
    {server, client, port} = endpoint()

    for payload <- ["one", ""] do
      :ok = packet(client, port, payload)
      assert {:ok, {_, ^port, <<1::32>>}} = response(client)
      assert_receive {:invoked, _, %Abyss.Datagram{payload: ^payload, destination: nil}, 0}
      assert_receive {:terminated, _, {:shutdown, :normal}, 1}
    end

    assert {:ok, %{local_endpoint: {{127, 0, 0, 1}, ^port}}} = Endpoint.info(server)
  end

  test "endpoint state serializes datagrams independently of broadcast permission" do
    {_server, client, port} = endpoint(execution: :endpoint, broadcast: true)

    for n <- 1..3 do
      :ok = packet(client, port, "state")
      assert {:ok, {_, ^port, <<^n::32>>}} = response(client)
    end

    assert_receive {:invoked, first, _, 0}
    assert_receive {:invoked, ^first, _, 1}
    assert_receive {:invoked, ^first, _, 2}
  end

  test "keyed state serializes same key while another key makes progress" do
    {_server, client, port} =
      endpoint(
        execution: :keyed,
        route_key: fn d -> if d.payload == "other", do: :b, else: :a end
      )

    :ok = packet(client, port, "block")
    assert_receive {:invoked, blocked, _, 0}
    :ok = packet(client, port, "same")
    :ok = packet(client, port, "other")
    assert {:ok, {_, ^port, <<1::32>>}} = response(client)
    assert_receive {:invoked, other, %{payload: "other"}, 0}
    refute blocked == other
    send(blocked, :continue)
    assert {:ok, {_, ^port, <<1::32>>}} = response(client)
    assert {:ok, {_, ^port, <<2::32>>}} = response(client)
    assert_receive {:invoked, ^blocked, %{payload: "same"}, 1}
  end

  test "blocked callback and init do not block control or absolute stop" do
    for options <- [[handler_options: [owner: self(), block_init: true]], []] do
      {server, client, port} = endpoint(options)
      :ok = packet(client, port, "block")
      assert_receive {:initialized, _, _}
      start = System.monotonic_time(:millisecond)
      assert :ok = Endpoint.pause(server)
      assert {:ok, %{mode: :suspended}} = Endpoint.info(server)
      assert :ok = Endpoint.stop(server, 20)
      assert System.monotonic_time(:millisecond) - start < 500
    end
  end

  test "absolute stop completes when runtime deadline retires protected input first" do
    owner = self()
    {server, client, port} = endpoint(handler_options: [owner: owner, block_init: true])
    :ok = packet(client, port, "block")
    assert_receive {:initialized, worker, _}
    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    runtime = :sys.get_state(listener).runtime
    %{writer: writer, admission: admission} = :sys.get_state(runtime)

    monitors =
      Enum.map([server, listener, runtime, worker, writer, admission], &{&1, Process.monitor(&1)})

    :ok =
      :sys.install(
        listener,
        {fn observed, event, _name ->
           case event do
             {:in, {:"$gen_call", _, {:drain, deadline}}} ->
               monitor = Process.monitor(runtime)
               Abyss.DatagramRuntime.drain(runtime, deadline)

               receive do
                 {:DOWN, ^monitor, :process, ^runtime, reason} ->
                   send(owner, {:runtime_deadline_down, reason})
                   :done
               end

             _ ->
               observed
           end
         end, false}
      )

    started = System.monotonic_time(:millisecond)
    assert :ok = Endpoint.stop(server, 30)
    assert System.monotonic_time(:millisecond) - started < 500
    assert_receive {:runtime_deadline_down, :killed}

    Enum.each(monitors, fn {pid, monitor} ->
      assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1000
    end)
  end

  test "invalid collection emits no partial packet and termination retains returned state" do
    {_server, client, port} = endpoint()
    :ok = packet(client, port, "invalid")
    assert_receive {:terminated, _, {:shutdown, :invalid_action}, 1}
    assert {:error, :timeout} = :gen_udp.recv(client, 0, 50)
  end

  test "managed persistent timer sends delayed reply and strict GenUDP reply rejects" do
    {server, client, port} = endpoint(execution: :endpoint)
    :ok = packet(client, port, "timer")
    assert {:ok, {_, ^port, "delayed"}} = response(client)
    :ok = packet(client, port, "strict")
    assert_receive {:invoked, _, %{payload: "strict"}, _}
    assert {:error, :timeout} = :gen_udp.recv(client, 0, 50)
    assert {:ok, %{receipts: receipts}} = Endpoint.info(server)
    assert Enum.any?(receipts, fn {_, r} -> {:error, :strict_reply_unsupported} in r.outcomes end)
  end

  test "overload reserves queued and in-flight work, cleanup releases exactly once" do
    {server, client, port} =
      endpoint(
        execution: :endpoint,
        num_connections: 2,
        runtime_options: [max_queue: 2, max_key_queue: 2, callback_timeout: 80]
      )

    :ok = packet(client, port, "block")
    assert_receive {:invoked, blocked, _, 0}
    :ok = packet(client, port, "queued")
    for _ <- 1..100, do: packet(client, port, "drop")
    assert :ok = Endpoint.pause(server)
    assert {:ok, info} = Endpoint.info(server)
    assert info.input_count <= 2
    assert info.high_items <= 2
    assert info.retained_bytes <= 2 * 1024
    monitor = Process.monitor(blocked)
    assert_receive {:DOWN, ^monitor, :process, ^blocked, :killed}, 1000
    assert :ok = Endpoint.stop(server, 100)
  end

  test "blocked route is isolated and watchdog drops without callback replay" do
    owner = self()

    {server, client, port} =
      endpoint(
        execution: :keyed,
        route_key: fn _ ->
          send(owner, {:routing, self()})

          receive do
            :continue -> :key
          end
        end,
        runtime_options: [route_timeout: 30]
      )

    :ok = packet(client, port, "route")
    assert_receive {:routing, route_pid}
    monitor = Process.monitor(route_pid)
    assert {:ok, %{input_count: 1}} = Endpoint.info(server)
    assert :ok = Endpoint.pause(server)
    assert_receive {:DOWN, ^monitor, :process, ^route_pid, :killed}, 1000
    refute_receive {:invoked, _, _, _}, 20
    assert {:ok, %{input_count: 0, retained_bytes: 0}} = Endpoint.info(server)
  end

  test "idle expiry and maximum keys bound persistent state without status extending lifetime" do
    owner = self()

    {server, client, port} =
      endpoint(
        datagram_handler: Abyss.RuntimeIdleTestHandler,
        execution: :keyed,
        route_key: fn datagram ->
          send(owner, {:routed, self(), datagram.payload})
          datagram.payload
        end,
        runtime_options: [max_keys: 1, idle_timeout: 40]
      )

    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    runtime = :sys.get_state(listener).runtime

    :ok =
      :sys.install(
        runtime,
        {fn observed, event, _name ->
           observe_idle_status(observed, event, owner)
         end, false}
      )

    :erlang.trace(runtime, true, [:receive])

    try do
      :ok = packet(client, port, "a")
      assert_receive {:initialized, first, %{endpoint_id: _}}
      assert_receive {:idle_callback, ^first}
      monitor = Process.monitor(first)
      :ok = packet(client, port, "b")
      assert_receive {:routed, route, "b"}
      assert_receive {:trace, ^runtime, :receive, {:DOWN, _, :process, ^route, :normal}}
      assert {:error, :timeout} = :gen_udp.recv(client, 0, 15)
      assert {:ok, %{key_count: 1}} = Endpoint.info(server)
      assert %{dropped: 1} = Abyss.DatagramRuntime.info(runtime)
      send(first, :continue)
      assert {:ok, {_, ^port, <<1::32>>}} = response(client)
      assert_receive {:invoked, ^first, _, 0}
      assert_receive {:idle_status, token, timer, status_token, status_timer}
      assert status_token == token
      assert status_timer == timer
      assert_receive {:terminated, ^first, {:shutdown, :idle_timeout}, 1}, 1000
      assert_receive {:DOWN, ^monitor, :process, ^first, _}
      assert_receive {:trace, ^runtime, :receive, {:DOWN, _, :process, ^first, _}}
    after
      :erlang.trace(runtime, false, [:receive])
    end

    :ok = packet(client, port, "b")
    assert {:ok, {_, ^port, <<1::32>>}} = response(client)
    assert_receive {:initialized, second, %{endpoint_id: _}}
    assert is_pid(owner) and is_pid(second)
  end

  defp observe_idle_status(
         false,
         {:noreply,
          %{workers: %{"a" => %{current: nil, idle_token: token, idle_timer: timer}}} = state},
         owner
       )
       when is_reference(token) do
    {:reply, _, state} = Abyss.DatagramRuntime.handle_call(:info, nil, state)
    {:reply, _, state} = Abyss.DatagramRuntime.handle_call(:info, nil, state)
    worker = state.workers["a"]
    send(owner, {:idle_status, token, timer, worker.idle_token, worker.idle_timer})
    true
  end

  defp observe_idle_status(observed, _event, _owner), do: observed

  test "termination hook is watchdog bounded and retains its reservation" do
    {server, client, port} =
      endpoint(
        handler_options: [owner: self(), block_terminate: true],
        num_connections: 1,
        runtime_options: [terminate_timeout: 60]
      )

    :ok = packet(client, port, "stop")
    assert {:ok, {_, ^port, "accepted"}} = response(client)
    assert_receive {:terminated, pid, {:shutdown, :done}, 1}
    monitor = Process.monitor(pid)
    assert {:ok, %{input_count: 1, key_count: 1}} = Endpoint.info(server)
    :ok = packet(client, port, "rejected")
    assert {:error, :timeout} = :gen_udp.recv(client, 0, 10)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}, 1000
    :ok = packet(client, port, "new")
    assert {:ok, {_, ^port, <<1::32>>}} = response(client)
  end

  test "telemetry sampling does not alter delivered metadata" do
    values =
      for rate <- [0.0, 1.0] do
        {server, client, port} = endpoint(connection_telemetry_sample_rate: rate)
        :ok = packet(client, port, "metadata")
        assert_receive {:invoked, _, datagram, 0}
        assert {:ok, {_, ^port, <<1::32>>}} = response(client)
        assert {:ok, %{generation: generation}} = Endpoint.info(server)
        assert datagram.generation == generation

        Map.take(datagram, [
          :destination,
          :interface_index,
          :local_address,
          :hop_limit,
          :ancillary,
          :flags
        ])
      end

    assert Enum.uniq(values) |> length() == 1
  end

  test "socket restart invalidates old capabilities and preserves logical endpoint" do
    {server, client, port} = endpoint(execution: :endpoint)
    {:ok, old_info} = Endpoint.info(server)
    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    monitor = Process.monitor(listener)
    Process.exit(listener, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^listener, :killed}
    # The supervisor answers only after processing the owner death and restart.
    pool = Abyss.Server.listener_pool_pid(server)
    [replacement] = Abyss.ListenerPool.listener_pids(pool)
    assert replacement != listener
    {:ok, info} = Endpoint.info(server)
    assert info.endpoint_id == old_info.endpoint_id
    assert info.generation != old_info.generation

    assert Endpoint.send(
             old_info.send,
             %{family: :inet, addr: {127, 0, 0, 1}, port: port},
             "stale"
           ) == {:error, :writer_down}

    {_ip, new_port} = info.local_endpoint
    :ok = packet(client, new_port, "new-generation")
    assert {:ok, {_, ^new_port, <<1::32>>}} = response(client)
    assert_receive {:invoked, _, %{generation: generation}, 0}
    assert generation == info.generation
  end

  defp completed_effect_fixture(server, client, port, payload) do
    owner = self()
    gate = make_ref()
    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    runtime = :sys.get_state(listener).runtime

    :ok =
      :sys.install(
        runtime,
        {fn held, event, _name ->
           case event do
             {:noreply, state} when not held ->
               case Map.to_list(state.workers) do
                 [
                   {key,
                    %{
                      phase: :effects,
                      current: token,
                      effect_pid: helper,
                      effect_monitor: monitor
                    }}
                 ] ->
                   fixture = %{
                     runtime: runtime,
                     admission: state.admission,
                     slot: state.inputs[token].slot
                   }

                   send(owner, {gate, key, token, helper, monitor, fixture})

                   # These fixtures require completed effects. Preserve the real
                   # deadline, but process its actual expiry after matching DOWN.
                   receive do
                     {:work_expired, ^key, ^token, _, :effects, _, _} = expired ->
                       receive do: ({^gate, :continue} -> send(self(), expired))
                   end

                   true

                 _ ->
                   held
               end

             _ ->
               held
           end
         end, false}
      )

    :erlang.trace(runtime, true, [:receive])

    try do
      :ok = packet(client, port, payload)
      assert_receive {^gate, key, token, helper, monitor, fixture}

      assert_receive {:trace, ^runtime, :receive,
                      {:effects_result, ^key, ^token, [{:unknown, _}], nil}}

      assert_receive {:trace, ^runtime, :receive, {:DOWN, ^monitor, :process, ^helper, :normal}}

      # Observe the real watchdog expiry with a separate scheduling budget;
      # the fixture keeps the production send deadline and exact trace match.
      assert_receive {:trace, ^runtime, :receive,
                      {:work_expired, ^key, ^token, _, :effects, _, _}},
                     1000

      fixture
    after
      send(runtime, {gate, :continue})
      :erlang.trace(runtime, false, [:receive])
    end
  end

  test "blocked writer retains output credit when invocation finishes and caller dies" do
    :persistent_term.put({Abyss.RuntimeBlockingTransport, :owner}, self())
    on_exit(fn -> :persistent_term.erase({Abyss.RuntimeBlockingTransport, :owner}) end)

    {server, client, port} =
      endpoint(
        transport_module: Abyss.RuntimeBlockingTransport,
        runtime_options: [send_timeout: 10],
        dispatcher_max_queue: 1
      )

    completed_effect_fixture(server, client, port, "blocked-send")
    assert_receive {:writer_blocked, writer}
    assert_receive {:terminated, _, {:shutdown, :normal}, 1}, 1000
    assert {:ok, %{send: capability, egress: %{entries: 1}}} = Endpoint.info(server)
    destination = %{family: :inet, addr: {127, 0, 0, 1}, port: port}
    assert {:error, :queue_limit} = Endpoint.send(capability, destination, "overload")
    assert :ok = Endpoint.pause(server)
    {:ok, %{receipts: receipts}} = Endpoint.info(server)
    [{_, %{outcomes: [{:unknown, ref}]}}] = Map.to_list(receipts)
    send(writer, :continue)
    assert {:ok, {_, ^port, <<1::32>>}} = response(client)
    assert {:ok, _} = Endpoint.await(capability, ref, 1000)
    assert :ok = Endpoint.stop(server, 100)
  end

  test "completed effects retain credit through settlement despite queued watchdog expiry" do
    owner = self()
    :persistent_term.put({Abyss.RuntimeBlockingTransport, :owner}, owner)
    on_exit(fn -> :persistent_term.erase({Abyss.RuntimeBlockingTransport, :owner}) end)

    {server, client, port} =
      endpoint(
        transport_module: Abyss.RuntimeBlockingTransport,
        runtime_options: [send_timeout: 10],
        dispatcher_max_queue: 1
      )

    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    runtime = :sys.get_state(listener).runtime
    :ok = packet(client, port, "block")
    assert_receive {:invoked, worker, %{payload: "block"}, 0}
    monitor = Process.monitor(worker)

    :ok =
      :sys.install(
        runtime,
        {fn held, event, _name ->
           case event do
             {:in, {:invocation_result, _, _, _}} when not held ->
               true = :erlang.suspend_process(worker)
               send(owner, {:settlement_held, worker})
               true

             {:noreply, %{workers: workers}} when held == true ->
               [{key, %{phase: :effects, current: token, effect_pid: helper}}] =
                 Map.to_list(workers)

               send(owner, {:effects_queue_held, helper})

               # Queue the actual expired timer after the actual helper DOWN,
               # independently of how quickly the helper gets scheduled.
               receive do
                 {:work_expired, ^key, ^token, _, :effects, _, _} = expired ->
                   receive do: (:continue_effect_queue -> send(self(), expired))
               end

               :effects_queued

             {:in, {:DOWN, _, :process, helper, :normal}} when helper != worker ->
               send(owner, {:effect_down_held, helper})
               receive do: (:continue_effect_down -> held)

             {:in, :continue_worker_settlement} ->
               true = :erlang.resume_process(worker)
               send(owner, {:worker_resumed, worker})
               :done

             _ ->
               held
           end
         end, false}
      )

    :erlang.trace(runtime, true, [:receive])

    try do
      send(worker, :continue)
      assert_receive {:settlement_held, ^worker}
      assert_receive {:effects_queue_held, helper}
      assert_receive {:writer_blocked, writer}
      assert_receive {:trace, ^runtime, :receive, {:effects_result, _, _, [{:unknown, ref}], nil}}
      assert_receive {:trace, ^runtime, :receive, {:DOWN, _, :process, ^helper, :normal}}
      assert_receive {:trace, ^runtime, :receive, {:work_expired, _, _, _, :effects, _, _}}
      send(runtime, :continue_effect_queue)
      assert_receive {:effect_down_held, ^helper}
      send(runtime, :continue_effect_down)

      assert %{input_count: 1, key_count: 1, egress: %{entries: 1}} =
               Abyss.DatagramRuntime.info(runtime)

      assert Process.alive?(worker)
      send(runtime, :continue_worker_settlement)
      assert_receive {:worker_resumed, ^worker}
      assert_receive {:terminated, ^worker, {:shutdown, :normal}, 1}, 1000
      assert_receive {:DOWN, ^monitor, :process, ^worker, {:shutdown, :normal}}

      assert_receive {:trace, ^runtime, :receive,
                      {:DOWN, _, :process, ^worker, {:shutdown, :normal}}}

      assert {:ok, %{send: capability, input_count: 0, egress: %{entries: 1}}} =
               Endpoint.info(server)

      send(writer, :continue)
      assert {:ok, {_, ^port, <<1::32>>}} = response(client)
      assert {:ok, _} = Endpoint.await(capability, ref, 1000)
    after
      send(runtime, :continue_effect_queue)
      send(runtime, :continue_effect_down)
      send(runtime, :continue_worker_settlement)
      :erlang.trace(runtime, false, [:receive])
    end
  end

  test "stop during accepted blocked egress uses original deadline" do
    :persistent_term.put({Abyss.RuntimeBlockingTransport, :owner}, self())
    on_exit(fn -> :persistent_term.erase({Abyss.RuntimeBlockingTransport, :owner}) end)

    {server, client, port} =
      endpoint(
        transport_module: Abyss.RuntimeBlockingTransport,
        runtime_options: [send_timeout: 10]
      )

    :ok = packet(client, port, "blocked-stop")
    assert_receive {:writer_blocked, writer}
    monitor = Process.monitor(writer)
    started = System.monotonic_time(:millisecond)
    assert :ok = Endpoint.stop(server, 30)
    assert System.monotonic_time(:millisecond) - started < 500
    assert_receive {:DOWN, ^monitor, :process, ^writer, :killed}, 1000
  end

  test "scope, timer overflow, improper and excessive action collections reject before effects" do
    for payload <- ["invalid-scope", "huge-timer", "improper", "many-actions"] do
      {_server, client, port} = endpoint(execution: :endpoint)
      :ok = packet(client, port, payload)
      assert_receive {:terminated, _, _, 1}, 1000
      assert {:error, :timeout} = :gen_udp.recv(client, 0, 20)
    end
  end

  test "unexpected worker death retires queued credit without replay and permits fresh work" do
    {server, client, port} = endpoint(execution: :endpoint, num_connections: 2)
    :ok = packet(client, port, "block")
    assert_receive {:invoked, worker, _, 0}
    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    runtime = :sys.get_state(listener).runtime
    :erlang.trace(runtime, true, [:receive])

    try do
      :ok = packet(client, port, "queued")

      assert_receive {:trace, ^runtime, :receive,
                      {:"$gen_call", _, {:admit, %{payload: "queued"}}}}

      assert %{inputs: inputs, workers: %{endpoint: %{queue: queue}}} = :sys.get_state(runtime)
      assert map_size(inputs) == 2
      assert :queue.len(queue) == 1
      assert :ok = Endpoint.pause(server)
      monitor = Process.monitor(worker)
      Process.exit(worker, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}
      assert_receive {:trace, ^runtime, :receive, {:DOWN, _, :process, ^worker, :killed}}
    after
      :erlang.trace(runtime, false, [:receive])
    end

    assert {:ok, %{input_count: 0, retained_bytes: 0}} = Endpoint.info(server)
    assert :ok = Endpoint.resume(server)
    :ok = packet(client, port, "fresh")
    assert {:ok, {_, ^port, <<1::32>>}} = response(client)
    refute_receive {:invoked, _, %{payload: "queued"}, _}, 20
  end

  test "effect results retain input credit until the matching helper DOWN" do
    :persistent_term.put({Abyss.RuntimeBlockingTransport, :owner}, self())
    on_exit(fn -> :persistent_term.erase({Abyss.RuntimeBlockingTransport, :owner}) end)

    {server, client, port} =
      endpoint(
        execution: :endpoint,
        transport_module: Abyss.RuntimeBlockingTransport,
        num_connections: 1,
        runtime_options: [send_timeout: 5000]
      )

    :ok = packet(client, port, "blocked-effect")
    assert_receive {:writer_blocked, writer}
    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    runtime = :sys.get_state(listener).runtime
    %{workers: %{endpoint: %{effect_pid: helper, current: token}}} = :sys.get_state(runtime)
    true = :erlang.suspend_process(helper)
    on_exit(fn -> if Process.alive?(helper), do: :erlang.resume_process(helper) end)
    monitor = Process.monitor(helper)
    send(runtime, {:effects_result, :endpoint, token, [], nil})
    send(runtime, {:DOWN, make_ref(), :process, helper, :normal})

    assert %{input_count: 1, retained_bytes: bytes} = Abyss.DatagramRuntime.info(runtime)
    assert bytes > 0
    assert [{_, 1}] = :ets.lookup(:abyss_udp_admission, {:count, server})
    true = :erlang.resume_process(helper)
    send(writer, :continue)
    assert {:ok, {_, ^port, <<1::32>>}} = response(client)
    assert_receive {:DOWN, ^monitor, :process, ^helper, :normal}
    assert_receive {:outcomes, _, _, _}
    assert :ok = Endpoint.stop(server, 100)
  end

  test "forced owner and server cleanup keep global credits until protected DOWN" do
    for cleanup <- [:release_owner, :release_server] do
      server = spawn(fn -> receive do: (:stop -> :ok) end)
      root = spawn(fn -> receive do: (:stop -> :ok) end)
      replacement = spawn(fn -> receive do: (:stop -> :ok) end)
      on_exit(fn -> Enum.each([server, root, replacement], &Process.exit(&1, :kill)) end)
      Abyss.Telemetry.register_scope(server, __MODULE__)
      assert {:ok, token} = Abyss.UDPAdmission.reserve_runtime(server, self(), 1, 400, 400, root)
      owner = self()

      assert {:ok, helper} =
               Abyss.UDPAdmission.spawn_protected(token, fn ->
                 send(owner, {:protected_helper, self()})
                 receive do: (:stop -> :ok)
               end)

      send(helper, :run)
      assert_receive {:protected_helper, ^helper}
      helper_monitor = Process.monitor(helper)
      root_monitor = Process.monitor(root)
      ledger = Process.whereis(Abyss.TableOwner)
      :ok = :sys.suspend(ledger)
      cleanup_ref = make_ref()
      reserve_ref = make_ref()
      scope = if cleanup == :release_owner, do: self(), else: server

      try do
        # Both calls precede the DOWN signals generated by cleanup's kills.
        send(ledger, {:"$gen_call", {self(), cleanup_ref}, {:admission, {cleanup, scope}}})
        operation = {:reserve_runtime, server, self(), 1, 1, 400, replacement}
        send(ledger, {:"$gen_call", {self(), reserve_ref}, {:admission, operation}})
      after
        :ok = :sys.resume(ledger)
      end

      assert_receive {^cleanup_ref, :ok}
      assert_receive {^reserve_ref, {:error, :handler_limit}}
      assert_receive {:DOWN, ^helper_monitor, :process, ^helper, :killed}
      assert_receive {:DOWN, ^root_monitor, :process, ^root, :killed}
      wait_for_retirement(ledger, token)

      assert {:ok, fresh} =
               Abyss.UDPAdmission.reserve_runtime(server, self(), 1, 400, 400, replacement)

      assert :ok = Abyss.UDPAdmission.complete(fresh)
      assert [{_, 0}] = :ets.lookup(:abyss_udp_admission, {:count, server})
      assert [{_, 0}] = :ets.lookup(:abyss_udp_admission, {:bytes, server})
    end
  end

  defp wait_for_retirement(ledger, token, attempts \\ 100) do
    state = :sys.get_state(ledger)

    if Map.has_key?(state.reservations, token) do
      assert attempts > 0, "protected process DOWN was not processed"
      wait_for_retirement(ledger, token, attempts - 1)
    end
  end

  test "listener replacement reclaims blocked route, callback and effect generations" do
    owner = self()
    :persistent_term.put({Abyss.RuntimeBlockingTransport, :owner}, owner)
    on_exit(fn -> :persistent_term.erase({Abyss.RuntimeBlockingTransport, :owner}) end)

    modes = [
      {:route,
       [
         execution: :keyed,
         route_key: fn _ ->
           send(owner, {:route_generation, self()})
           receive do: (:continue -> :key)
         end
       ]},
      {:callback, [execution: :endpoint]},
      {:effect, [execution: :endpoint, transport_module: Abyss.RuntimeBlockingTransport]}
    ]

    for {mode, options} <- modes do
      {server, client, port} = endpoint(options ++ [num_connections: 1])

      [listener] =
        server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

      runtime = :sys.get_state(listener).runtime
      {:ok, %{generation: generation}} = Endpoint.info(server)
      payload = if mode == :callback, do: "block", else: "generation"
      :ok = packet(client, port, payload)
      descendants = generation_descendants(mode, runtime)
      monitors = Enum.map([listener, runtime | descendants], &{&1, Process.monitor(&1)})
      token = :sys.get_state(runtime).inputs |> Map.values() |> hd() |> Map.fetch!(:slot)
      Process.exit(listener, :kill)

      Enum.each(monitors, fn {pid, monitor} ->
        assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1000
      end)

      wait_for_retirement(Process.whereis(Abyss.TableOwner), token)

      [replacement] =
        server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

      assert replacement != listener
      {:ok, info} = Endpoint.info(server)
      assert info.generation != generation
      assert info.input_count == 0
      assert [{_, 0}] = :ets.lookup(:abyss_udp_admission, {:count, server})
      assert [{_, 0}] = :ets.lookup(:abyss_udp_admission, {:bytes, server})
      assert :ok = Endpoint.stop(server, 100)
    end
  end

  defp generation_descendants(:route, _runtime) do
    assert_receive {:route_generation, helper}
    [helper]
  end

  defp generation_descendants(:callback, _runtime) do
    assert_receive {:invoked, worker, %{payload: "block"}, _}
    [worker]
  end

  defp generation_descendants(:effect, runtime) do
    assert_receive {:writer_blocked, writer}
    %{workers: %{endpoint: %{pid: worker, effect_pid: helper}}} = :sys.get_state(runtime)
    [worker, helper, writer]
  end

  test "zero-input runtime death kills blocked output components and erases lookup" do
    :persistent_term.put({Abyss.RuntimeBlockingTransport, :owner}, self())
    on_exit(fn -> :persistent_term.erase({Abyss.RuntimeBlockingTransport, :owner}) end)

    {server, client, port} =
      endpoint(
        transport_module: Abyss.RuntimeBlockingTransport,
        runtime_options: [send_timeout: 10]
      )

    %{runtime: runtime, admission: admission, slot: token} =
      completed_effect_fixture(server, client, port, "unknown-send")

    assert_receive {:writer_blocked, writer}
    assert_receive {:terminated, worker, _, 1}, 1000
    worker_monitor = Process.monitor(worker)
    assert_receive {:DOWN, ^worker_monitor, :process, ^worker, _}, 1000
    ledger = Process.whereis(Abyss.TableOwner)
    wait_for_retirement(ledger, token)
    assert %{input_count: 0, egress: %{entries: 1}} = Abyss.DatagramRuntime.info(runtime)
    writer_monitor = Process.monitor(writer)
    admission_monitor = Process.monitor(admission)
    runtime_monitor = Process.monitor(runtime)
    Process.exit(runtime, :kill)
    assert_receive {:DOWN, ^runtime_monitor, :process, ^runtime, :killed}, 1000
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, :killed}, 1000
    assert_receive {:DOWN, ^admission_monitor, :process, ^admission, _}, 1000
    wait_for_runtime_retirement(ledger, runtime)
    assert :persistent_term.get({Abyss.Dispatcher.Writer, writer}, :missing) == :missing
  end

  defp wait_for_runtime_retirement(ledger, runtime, attempts \\ 100) do
    if Map.has_key?(:sys.get_state(ledger).runtimes, runtime) do
      assert attempts > 0, "runtime component DOWN was not processed"
      wait_for_runtime_retirement(ledger, runtime, attempts - 1)
    end
  end

  test "forced runtime death kills blocked route helper and erases writer lookup" do
    owner = self()

    {server, client, port} =
      endpoint(
        execution: :keyed,
        route_key: fn _ ->
          send(owner, {:route_helper, self()})

          receive do
            :continue -> :key
          end
        end
      )

    {:ok, %{send: capability}} = Endpoint.info(server)
    :ok = packet(client, port, "blocked-route")
    assert_receive {:route_helper, helper}
    monitor = Process.monitor(helper)
    assert :ok = Endpoint.stop(server, 10)
    assert_receive {:DOWN, ^monitor, :process, ^helper, :killed}, 1000

    assert :persistent_term.get({Abyss.Dispatcher.Writer, capability.writer}, :missing) ==
             :missing
  end
end

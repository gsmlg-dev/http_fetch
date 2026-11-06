defmodule Abyss.WatchdogTestHandler do
  @behaviour Abyss.DatagramHandler

  def init(options, context) do
    send(options[:owner], {:watchdog_init, self(), context.generation})
    receive do: (:finish_init -> :ok)
    {:ok, options[:owner]}
  end

  def handle_datagram(datagram, owner) do
    send(owner, {:watchdog_callback, self(), datagram.payload})
    receive do: ({:finish_callback, actions} -> {:ok, owner, actions})
  end
end

defmodule Abyss.WatchdogBlockingTransport do
  alias Abyss.Transport.UDP
  defdelegate listen(port, options), to: UDP
  defdelegate sockname(socket), to: UDP
  defdelegate setopts(socket, options), to: UDP
  defdelegate close(socket), to: UDP

  def send(socket, ip, port, payload) do
    owner = :persistent_term.get({__MODULE__, :owner})
    send(owner, {:watchdog_writer, self()})
    receive do: (:finish_send -> UDP.send(socket, ip, port, payload))
  end
end

defmodule Abyss.DatagramWatchdogTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Endpoint

  defp endpoint(options) do
    {:ok, endpoint} =
      Endpoint.start_link(
        Keyword.merge(
          [
            datagram_handler: Abyss.WatchdogTestHandler,
            handler_options: [owner: self()],
            execution: :endpoint,
            port: 0,
            transport_options: [ip: {127, 0, 0, 1}]
          ],
          options
        )
      )

    Process.unlink(endpoint)
    on_exit(fn -> if Process.alive?(endpoint), do: Endpoint.stop(endpoint, 100) end)
    {:ok, {_, port}} = Endpoint.local_endpoint(endpoint)
    {:ok, client} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(client) end)

    [listener] =
      endpoint |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

    {endpoint, client, port, :sys.get_state(listener).runtime}
  end

  # Hold delivery, not the timer: receive the previous arm's actual expiry while
  # the phase transition is waiting, then deliver it after the next arm exists.
  # The old and corrected message shapes both preserve key/token as elements 1/2.
  defp hold_previous_expiry(runtime, transition, next_phase) do
    owner = self()
    gate = make_ref()

    :ok =
      :sys.install(
        runtime,
        {fn held, event, _name ->
           case {held, event} do
             {nil, {:out, :ok, _, %{workers: %{endpoint: %{phase: :init, current: token}}}}}
             when transition == :initialized ->
               hold_transition(owner, gate, transition, :endpoint, token)

             {nil, {:noreply, %{workers: %{endpoint: %{phase: :callback, current: token}}}}}
             when transition == :invocation_result ->
               hold_transition(owner, gate, transition, :endpoint, token)

             {{key, token, expired}, {:noreply, state}} ->
               %{current: ^token, phase: ^next_phase} = worker = state.workers[key]
               send(self(), expired)
               send(owner, {gate, :installed, worker})
               :done

             _ ->
               held
           end
         end, nil}
      )

    gate
  end

  defp hold_transition(owner, gate, transition, key, token) do
    # The runtime is held immediately after arming the previous phase, before
    # its next receive. Both real messages may arrive in either order.
    receive do
      message
      when elem(message, 0) == transition and elem(message, 1) == key and
             elem(message, 2) == token ->
        receive do
          expired
          when elem(expired, 0) == :work_expired and elem(expired, 1) == key and
                 elem(expired, 2) == token ->
            send(owner, {gate, :expired, expired})
            send(self(), message)
            {key, token, expired}
        end
    end
  end

  test "an actual init expiry delivered after callback arm cannot kill that callback" do
    {endpoint, client, port, runtime} =
      endpoint(runtime_options: [init_timeout: 80, callback_timeout: 5000])

    gate = hold_previous_expiry(runtime, :initialized, :callback)
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "init-race")
    assert_receive {:watchdog_init, worker, _}
    send(worker, :finish_init)
    assert_receive {:watchdog_callback, ^worker, "init-race"}
    assert_receive {^gate, :expired, expired}, 2000
    assert_receive {^gate, :installed, %{pid: ^worker} = installed}, 2000
    _ = Abyss.DatagramRuntime.info(runtime)
    assert Process.alive?(worker), "stale init expiry killed the active callback"
    assert_new_arm(installed, expired, :callback)
    send(worker, {:finish_callback, [{:reply, "init-survived"}]})
    assert {:ok, {_, ^port, "init-survived"}} = :gen_udp.recv(client, 0, 1000)
    assert {:ok, _} = Endpoint.info(endpoint)
    wait_idle(runtime)
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "later-invocation")
    assert_receive {:watchdog_callback, ^worker, "later-invocation"}
    send(runtime, expired)
    _ = Abyss.DatagramRuntime.info(runtime)
    assert Process.alive?(worker)
    send(worker, {:finish_callback, [{:reply, "later-survived"}]})
    assert {:ok, {_, ^port, "later-survived"}} = :gen_udp.recv(client, 0, 1000)
  end

  test "an actual callback expiry delivered after effects arm cannot kill those effects" do
    :persistent_term.put({Abyss.WatchdogBlockingTransport, :owner}, self())
    on_exit(fn -> :persistent_term.erase({Abyss.WatchdogBlockingTransport, :owner}) end)

    {endpoint, client, port, runtime} =
      endpoint(
        transport_module: Abyss.WatchdogBlockingTransport,
        runtime_options: [init_timeout: 5000, callback_timeout: 80, send_timeout: 1000]
      )

    gate = hold_previous_expiry(runtime, :invocation_result, :effects)
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "callback-race")
    assert_receive {:watchdog_init, worker, _}
    send(worker, :finish_init)
    assert_receive {:watchdog_callback, ^worker, "callback-race"}
    send(worker, {:finish_callback, [{:reply, "effects-survived"}]})
    assert_receive {^gate, :expired, expired}, 2000
    assert_receive {^gate, :installed, %{pid: ^worker} = installed}, 2000
    _ = Abyss.DatagramRuntime.info(runtime)
    assert Process.alive?(worker), "stale callback expiry killed active effects"
    assert_new_arm(installed, expired, :effects)
    assert_receive {:watchdog_writer, writer}
    send(writer, :finish_send)
    assert {:ok, {_, ^port, "effects-survived"}} = :gen_udp.recv(client, 0, 1000)
    assert {:ok, _} = Endpoint.info(endpoint)
  end

  test "current init, callback and effects arms still enforce their real deadlines" do
    :persistent_term.put({Abyss.WatchdogBlockingTransport, :owner}, self())
    on_exit(fn -> :persistent_term.erase({Abyss.WatchdogBlockingTransport, :owner}) end)

    for phase <- [:init, :callback, :effects] do
      limits = [init_timeout: 80, callback_timeout: 80, send_timeout: 500]

      transport =
        if phase == :effects, do: Abyss.WatchdogBlockingTransport, else: Abyss.Transport.UDP

      {endpoint, client, port, runtime} =
        endpoint(transport_module: transport, runtime_options: limits)

      :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "deadline")
      assert_receive {:watchdog_init, worker, _}
      monitor = Process.monitor(worker)

      case phase do
        :init ->
          nil

        :callback ->
          send(worker, :finish_init)
          assert_receive {:watchdog_callback, ^worker, "deadline"}
          nil

        :effects ->
          send(worker, :finish_init)
          assert_receive {:watchdog_callback, ^worker, "deadline"}
          # The effects helper times out before its watchdog under normal
          # scheduling, so hold the genuine helper to exercise the active arm.
          gate = make_ref()
          owner = self()

          :ok =
            :sys.install(
              runtime,
              {fn held, event, _ ->
                 case event do
                   {:noreply, %{workers: %{endpoint: %{phase: :effects, effect_pid: helper}}}}
                   when not held ->
                     true = :erlang.suspend_process(helper)
                     send(owner, {gate, helper})
                     true

                   _ ->
                     held
                 end
               end, false}
            )

          send(worker, {:finish_callback, [{:reply, "expired"}]})
          assert_receive {^gate, _helper}
          # The helper may be suspended before it submits the send. Current
          # effects expiry must kill it and the callback worker regardless.
          nil
      end

      assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 2000
      wait_empty(runtime)
      assert {:ok, %{input_count: 0}} = Endpoint.info(endpoint)
      :ok = Endpoint.stop(endpoint, 100)
    end
  end

  test "an expired arm cannot target a replacement keyed worker or endpoint generation" do
    for replacement <- [:key, :generation] do
      {endpoint, client, port, runtime} =
        endpoint(
          execution: :keyed,
          route_key: fn _ -> :same end,
          runtime_options: [init_timeout: 80, callback_timeout: 5000]
        )

      :erlang.trace(runtime, true, [:receive])
      :ok = :gen_udp.send(client, {127, 0, 0, 1}, port, "old")
      assert_receive {:watchdog_init, old_worker, old_generation}
      old_monitor = Process.monitor(old_worker)

      assert_receive {:trace, ^runtime, :receive, expired}
                     when elem(expired, 0) == :work_expired,
                     2000

      assert_receive {:DOWN, ^old_monitor, :process, ^old_worker, :killed}, 2000
      wait_empty(runtime)
      :erlang.trace(runtime, false, [:receive])

      {new_runtime, new_port} =
        if replacement == :generation do
          [listener] =
            endpoint |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

          monitor = Process.monitor(runtime)
          Process.exit(listener, :kill)
          assert_receive {:DOWN, ^monitor, :process, ^runtime, _}, 1000

          %{local_endpoint: {_, new_port}} = wait_replacement(endpoint, old_generation)

          [new_listener] =
            endpoint |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

          {:sys.get_state(new_listener).runtime, new_port}
        else
          {runtime, port}
        end

      :ok = :gen_udp.send(client, {127, 0, 0, 1}, new_port, "replacement")
      assert_receive {:watchdog_init, new_worker, new_generation}
      refute new_worker == old_worker
      if replacement == :generation, do: refute(new_generation == old_generation)
      send(new_runtime, expired)
      _ = Abyss.DatagramRuntime.info(new_runtime)
      assert Process.alive?(new_worker)
      send(new_worker, :finish_init)
      assert_receive {:watchdog_callback, ^new_worker, "replacement"}
      send(new_worker, {:finish_callback, [{:reply, "replacement-survived"}]})
      assert {:ok, {_, ^new_port, "replacement-survived"}} = :gen_udp.recv(client, 0, 1000)
    end
  end

  defp wait_replacement(endpoint, old_generation) do
    deadline = System.monotonic_time(:millisecond) + 1000
    wait_replacement(endpoint, old_generation, deadline)
  end

  defp wait_replacement(endpoint, old_generation, deadline) do
    case Endpoint.info(endpoint) do
      {:ok, %{generation: generation} = info} when generation != old_generation ->
        info

      _ ->
        assert System.monotonic_time(:millisecond) < deadline,
               "replacement endpoint did not become ready"

        wait_replacement(endpoint, old_generation, deadline)
    end
  end

  defp assert_new_arm(worker, expired, phase) do
    assert %{identity: identity, phase: ^phase, deadline: deadline, ref: timer} = worker.watchdog
    assert is_reference(identity)
    refute identity == worker.current
    refute identity == elem(expired, 5)
    assert is_integer(deadline)
    assert deadline > System.monotonic_time(:millisecond)
    assert Process.read_timer(timer) > 0
  end

  defp wait_idle(runtime),
    do: wait_state(runtime, &match?(%{workers: %{endpoint: %{current: nil}}}, &1))

  defp wait_empty(runtime), do: wait_state(runtime, &(map_size(&1.workers) == 0))

  defp wait_state(runtime, predicate) do
    deadline = System.monotonic_time(:millisecond) + 1000
    wait_state(runtime, predicate, deadline)
  end

  defp wait_state(runtime, predicate, deadline) do
    state = :sys.get_state(runtime)

    unless predicate.(state) do
      assert System.monotonic_time(:millisecond) < deadline,
             "runtime did not reach observed settlement"

      wait_state(runtime, predicate, deadline)
    end
  end
end

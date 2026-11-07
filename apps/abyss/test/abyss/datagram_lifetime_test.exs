defmodule Abyss.LifetimeTestHandler do
  @behaviour Abyss.DatagramHandler

  def init(options, context) do
    send(options[:owner], {:lifetime_initialized, self(), context.generation})

    {:ok,
     %{
       owner: options[:owner],
       generation: context.generation,
       count: 0,
       timer_delay: options[:timer_delay] || 150
     }}
  end

  def handle_datagram(datagram, state) do
    state = %{state | count: state.count + 1}
    send(state.owner, {:lifetime_datagram, self(), datagram.payload, state.count})
    actions = [{:reply, <<state.count::32>>}]

    actions =
      if datagram.payload == "timer",
        do: actions ++ [{:timer, :tick, state.timer_delay, datagram.peer}],
        else: actions

    {:ok, state, actions}
  end

  def handle_event({:timer, :tick, peer}, state) do
    state = %{state | count: state.count + 1}
    send(state.owner, {:lifetime_timer, self(), state.generation, state.count})
    {:ok, state, [{:send, peer, <<state.count::32>>}]}
  end

  def handle_event(_, state), do: {:ok, state, []}

  def terminate(reason, state), do: send(state.owner, {:lifetime_terminated, self(), reason})
end

defmodule Abyss.DatagramLifetimeTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.Endpoint

  defp endpoint(options \\ []) do
    {:ok, endpoint} =
      Endpoint.start_link(
        Keyword.merge(
          [
            datagram_handler: Abyss.LifetimeTestHandler,
            handler_options: [owner: self()],
            execution: :endpoint,
            port: 0,
            transport_options: [ip: {127, 0, 0, 1}],
            runtime_options: [idle_timeout: 30]
          ],
          options
        )
      )

    Process.unlink(endpoint)
    on_exit(fn -> if Process.alive?(endpoint), do: Endpoint.stop(endpoint, 100) end)
    {:ok, {_, port}} = Endpoint.local_endpoint(endpoint)
    {:ok, client} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(client) end)
    {endpoint, client, port}
  end

  defp packet(client, port, payload), do: :gen_udp.send(client, {127, 0, 0, 1}, port, payload)

  defp response(client, port, count),
    do: assert({:ok, {_, ^port, <<^count::32>>}} = :gen_udp.recv(client, 0, 1000))

  defp runtime(endpoint) do
    [listener] =
      endpoint |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

    {listener, :sys.get_state(listener).runtime}
  end

  defp elapsed_barrier(milliseconds) do
    marker = make_ref()
    start = System.monotonic_time(:millisecond)
    Process.send_after(self(), marker, milliseconds)
    assert_receive ^marker, 1000
    assert System.monotonic_time(:millisecond) - start >= milliseconds
  end

  defp wait_info(endpoint, predicate) do
    wait_info(endpoint, predicate, System.monotonic_time(:millisecond) + 1000)
  end

  defp wait_info(endpoint, predicate, deadline) do
    case Endpoint.info(endpoint) do
      {:ok, info} ->
        if predicate.(info), do: info, else: retry_info(endpoint, predicate, deadline)

      _ ->
        retry_info(endpoint, predicate, deadline)
    end
  end

  defp retry_info(endpoint, predicate, deadline) do
    assert System.monotonic_time(:millisecond) < deadline, "endpoint did not reach observed state"
    wait_info(endpoint, predicate, deadline)
  end

  defp settled(endpoint),
    do: wait_info(endpoint, &(&1.input_count == 0 and &1.egress.entries == 0))

  test "endpoint preserves state beyond keyed idle interval without retaining completed credit" do
    {endpoint, client, port} = endpoint()
    :ok = packet(client, port, "first")
    response(client, port, 1)
    assert_receive {:lifetime_initialized, worker, generation}
    assert_receive {:lifetime_datagram, ^worker, "first", 1}
    assert %{retained_bytes: 0, timer_count: 0} = settled(endpoint)
    elapsed_barrier(90)

    assert {:ok, %{generation: ^generation, input_count: 0, retained_bytes: 0}} =
             Endpoint.status(endpoint)

    :ok = packet(client, port, "second")
    response(client, port, 2)
    assert_receive {:lifetime_datagram, ^worker, "second", 2}
    refute_receive {:lifetime_initialized, _, _}, 0
    {_listener, runtime} = runtime(endpoint)

    assert %{workers: %{endpoint: %{pid: ^worker, idle_timer: nil, idle_token: nil}}} =
             :sys.get_state(runtime)
  end

  test "endpoint timer survives inactivity and pause while resume preserves accumulated state" do
    {endpoint, client, port} = endpoint()
    :ok = packet(client, port, "timer")
    response(client, port, 1)
    assert_receive {:lifetime_initialized, worker, generation}
    assert %{timer_count: 1, retained_bytes: 0} = settled(endpoint)
    assert :ok = Endpoint.pause(endpoint)

    # The timer's actual callback and UDP reply establish progress beyond the
    # idle interval; its input credit may still be live while that work runs.
    assert_receive {:lifetime_timer, ^worker, ^generation, 2}, 1000
    response(client, port, 2)

    assert %{
             mode: :suspended,
             generation: ^generation,
             input_count: 0,
             timer_count: 0,
             retained_bytes: 0
           } = settled(endpoint)

    assert :ok = Endpoint.resume(endpoint)
    :ok = packet(client, port, "resumed")
    response(client, port, 3)
    assert_receive {:lifetime_datagram, ^worker, "resumed", 3}
    refute_receive {:lifetime_initialized, _, _}, 0
    refute_receive {:lifetime_timer, _, _, _}, 0
  end

  test "stop and generation replacement cancel old endpoint timers without delivering into new state" do
    for replacement <- [:stop, :generation] do
      {endpoint, client, port} = endpoint(runtime_options: [idle_timeout: 1000])
      :ok = packet(client, port, "timer")
      response(client, port, 1)
      assert_receive {:lifetime_initialized, worker, generation}
      assert %{timer_count: 1} = settled(endpoint)
      {listener, old_runtime} = runtime(endpoint)
      %{timers: %{{:endpoint, :tick} => %{ref: old_timer}}} = :sys.get_state(old_runtime)
      worker_monitor = Process.monitor(worker)
      runtime_monitor = Process.monitor(old_runtime)

      {new_endpoint, new_client, new_port} =
        if replacement == :stop do
          assert :ok = Endpoint.stop(endpoint, 100)
          endpoint(runtime_options: [idle_timeout: 1000])
        else
          Process.exit(listener, :kill)
          %{local_endpoint: {_, new_port}} = wait_info(endpoint, &(&1.generation != generation))
          {endpoint, client, new_port}
        end

      assert_receive {:DOWN, ^runtime_monitor, :process, ^old_runtime, _}, 1000
      assert_receive {:DOWN, ^worker_monitor, :process, ^worker, _}, 1000
      assert Process.read_timer(old_timer) == false
      :ok = packet(new_client, new_port, "timer")
      response(new_client, new_port, 1)
      assert_receive {:lifetime_initialized, new_worker, new_generation}
      refute new_worker == worker
      refute new_generation == generation
      # The new timer was armed after teardown. Its actual callback/reply is an
      # observable milestone beyond the old timer's earlier deadline.
      assert_receive {:lifetime_timer, ^new_worker, ^new_generation, 2}, 1000
      response(new_client, new_port, 2)
      assert %{timer_count: 0} = settled(new_endpoint)
      refute_receive {:lifetime_timer, ^worker, ^generation, _}, 0
    end
  end

  test "keyed idle eviction cancels managed timers and public status cannot refresh lifetime" do
    {endpoint, client, port} =
      endpoint(
        execution: :keyed,
        route_key: fn _ -> :key end,
        handler_options: [owner: self(), timer_delay: 600],
        runtime_options: [idle_timeout: 200]
      )

    :ok = packet(client, port, "timer")
    response(client, port, 1)
    assert_receive {:lifetime_initialized, worker, generation}
    assert %{timer_count: 1} = settled(endpoint)
    {_listener, runtime} = runtime(endpoint)

    %{
      timers: %{{:key, :tick} => %{ref: managed_timer}},
      workers: %{key: %{idle_timer: idle_timer, idle_token: idle_token}}
    } = :sys.get_state(runtime)

    monitor = Process.monitor(worker)
    for _ <- 1..10, do: assert({:ok, _} = Endpoint.status(endpoint))

    %{workers: %{key: %{idle_timer: ^idle_timer, idle_token: ^idle_token}}} =
      :sys.get_state(runtime)

    assert_receive {:lifetime_terminated, ^worker, {:shutdown, :idle_timeout}}, 1000
    assert_receive {:DOWN, ^monitor, :process, ^worker, _}, 1000

    assert %{key_count: 0, timer_count: 0, retained_bytes: 0} =
             wait_info(endpoint, &(&1.key_count == 0))

    assert Process.read_timer(managed_timer) == false
    :ok = packet(client, port, "fresh")
    response(client, port, 1)
    assert_receive {:lifetime_initialized, new_worker, ^generation}
    refute new_worker == worker
    elapsed_barrier(660)
    assert {:ok, %{key_count: 0, timer_count: 0, input_count: 0}} = Endpoint.status(endpoint)
    refute_receive {:lifetime_initialized, _, _}, 0
    refute_receive {:lifetime_timer, _, _, _}, 0
  end
end

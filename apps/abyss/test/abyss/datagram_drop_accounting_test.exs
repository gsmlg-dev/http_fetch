defmodule Abyss.DatagramDropAccountingTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  alias Abyss.{Endpoint, Telemetry, UDPAdmission}

  setup do
    id = make_ref()

    :ok =
      :telemetry.attach_many(
        id,
        [[:abyss, :datagram, :dropped], [:abyss, :datagram, :event_rejected]],
        &__MODULE__.event/4,
        self()
      )

    on_exit(fn -> :telemetry.detach(id) end)
    :ok
  end

  def event(event, measurements, metadata, owner),
    do: send(owner, {:drop_decision, event, metadata.server_id, measurements, metadata})

  defp endpoint(options \\ []) do
    {:ok, server} =
      Endpoint.start_link(
        Keyword.merge(
          [
            datagram_handler: Abyss.Test.DropAccountingHandler,
            handler_options: [owner: self()],
            execution: :endpoint,
            port: 0,
            transport_options: [ip: {127, 0, 0, 1}]
          ],
          options
        )
      )

    Process.unlink(server)
    on_exit(fn -> if Process.alive?(server), do: Endpoint.stop(server, 100) end)
    {:ok, {_, port}} = Endpoint.local_endpoint(server)
    {:ok, client} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(client) end)
    {server, client, port}
  end

  defp packet(client, port, payload), do: :gen_udp.send(client, {127, 0, 0, 1}, port, payload)

  defp wait_info(server, predicate, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 1000

    case Endpoint.info(server) do
      {:ok, info} -> if predicate.(info), do: info, else: retry_info(server, predicate, deadline)
      {:error, :not_running} -> retry_info(server, predicate, deadline)
    end
  end

  defp retry_info(server, predicate, deadline) do
    assert System.monotonic_time(:millisecond) < deadline
    wait_info(server, predicate, deadline)
  end

  defp settled(server), do: wait_info(server, &(&1.input_count == 0))

  defp assert_drop(server, reason, bytes) do
    assert_receive {:drop_decision, [:abyss, :datagram, :dropped], ^server, %{bytes: ^bytes},
                    metadata},
                   1000

    assert metadata.reason == reason
  end

  defp assert_totals(server, received, ingress, runtime) do
    {:ok, info} = Endpoint.info(server)
    assert info.received == received
    assert info.dropped == ingress + runtime
    assert info.drop_counts == %{ingress: ingress, runtime: runtime}
    assert {:ok, status} = Endpoint.status(server)
    fields = [:received, :dropped, :drop_counts, :internal_events_rejected, :generation]
    assert Map.take(status, fields) == Map.take(info, fields)
    metrics = Telemetry.get_metrics(server)
    assert metrics.datagrams_received == received
    assert metrics.datagrams_dropped == info.dropped
    info
  end

  test "deferred key count rejection remains visible after successful initial admission" do
    {server, client, port} =
      endpoint(execution: :keyed, route_key: & &1.payload, runtime_options: [max_keys: 1])

    :ok = packet(client, port, "first")
    assert_receive {:drop_callback, _, "first"}
    settled(server)
    :ok = packet(client, port, "second")

    assert_receive {:drop_decision, [:abyss, :datagram, :dropped], ^server, %{bytes: bytes},
                    %{reason: :key_limit}},
                   1000

    assert {:ok, %{dropped: 1}} = Endpoint.status(server)
    assert bytes == 6
    assert_totals(server, 2, 0, 1)
    assert Telemetry.get_metrics(server).bytes_dropped == 6
    assert %{input_count: 0, key_count: 1} = settled(server)
  end

  test "per-key item rejection releases the rejected input once while retaining active work" do
    {server, client, port} =
      endpoint(
        execution: :keyed,
        route_key: fn _ -> :same end,
        runtime_options: [max_key_queue: 1]
      )

    :ok = packet(client, port, "block")
    assert_receive {:drop_callback, worker, "block"}
    :ok = packet(client, port, "second")
    assert_drop(server, :key_queue_limit, 6)
    assert %{input_count: 1} = assert_totals(server, 2, 0, 1)
    send(worker, :finish_callback)
    assert %{input_count: 0, retained_bytes: 0} = settled(server)
    assert_totals(server, 2, 0, 1)
  end

  test "per-key single and aggregate byte limits account only network payload bytes" do
    for {limit, blocked, reason} <- [
          {128, false, :key_queue_bytes_limit},
          {800, true, :key_queue_limit}
        ] do
      {server, client, port} =
        endpoint(
          execution: :keyed,
          route_key: fn _ -> :same end,
          runtime_options: [max_key_queue_bytes: limit]
        )

      worker =
        if blocked do
          :ok = packet(client, port, "block")
          assert_receive {:drop_callback, worker, "block"}
          worker
        end

      payload = :binary.copy(<<1>>, 256)
      :ok = packet(client, port, payload)
      assert_drop(server, reason, 256)
      assert_totals(server, if(blocked, do: 2, else: 1), 0, 1)
      assert Telemetry.get_metrics(server).bytes_dropped == 256
      if worker, do: send(worker, :finish_callback)
      settled(server)
    end
  end

  test "over-large opaque routing key is one deferred network drop" do
    {server, client, port} =
      endpoint(
        execution: :keyed,
        route_key: fn _ -> :binary.copy(<<1>>, 256) end,
        runtime_options: [max_key_bytes: 8]
      )

    :ok = packet(client, port, "key")
    assert_drop(server, :key_size_limit, 3)
    assert_totals(server, 1, 0, 1)
    assert %{key_count: 0, input_count: 0} = settled(server)
    refute_receive {:drop_callback, _, _}, 0
  end

  test "blocked route expiry and failed routing are definitive deferred rejections" do
    owner = self()

    for mode <- [:blocked, :failed] do
      route = fn _ ->
        send(owner, {:route_entered, self(), mode})

        case mode do
          :blocked -> receive do: (:finish_route -> :key)
          :failed -> throw(:controlled_route_failure)
        end
      end

      {server, client, port} =
        endpoint(execution: :keyed, route_key: route, runtime_options: [route_timeout: 100])

      :ok = packet(client, port, "route")
      assert_receive {:route_entered, route_pid, ^mode}

      if mode == :blocked do
        assert {:ok, %{dropped: 0, input_count: 1}} = Endpoint.info(server)
        monitor = Process.monitor(route_pid)
        assert_drop(server, :route_timeout, 5)
        assert_receive {:DOWN, ^monitor, :process, ^route_pid, :killed}
      else
        assert_drop(server, {:throw, :controlled_route_failure}, 5)
      end

      assert_totals(server, 1, 0, 1)
      assert %{input_count: 0, key_count: 0} = settled(server)
    end
  end

  test "synchronous global item and byte admission rejection appears exactly once" do
    for kind <- [:item, :byte] do
      limits = if kind == :item, do: [max_queue: 1], else: [max_queue_bytes: 800]
      {server, client, port} = endpoint(runtime_options: limits)
      :ok = packet(client, port, "block")
      assert_receive {:drop_callback, worker, "block"}
      payload = :binary.copy(<<1>>, 256)
      :ok = packet(client, port, payload)
      reason = if kind == :item, do: :input_limit, else: :input_bytes_limit
      assert_drop(server, reason, 256)
      assert %{input_count: 1} = assert_totals(server, 2, 0, 1)
      for _ <- 1..5, do: assert_totals(server, 2, 0, 1)
      send(worker, :finish_callback)
      assert %{retained_bytes: 0} = settled(server)
    end
  end

  test "shared service admission exhaustion rejects one network input without duplicate counters" do
    {server, client, port} = endpoint(num_connections: 1)
    {:ok, slot} = UDPAdmission.reserve(server, self(), 1)
    :ok = packet(client, port, "capacity")
    assert_drop(server, :handler_limit, 8)
    assert_totals(server, 1, 0, 1)
    assert :ok = UDPAdmission.release(slot)
    assert :ok = UDPAdmission.release(slot)
    :ok = packet(client, port, "accepted")
    assert_receive {:drop_callback, _, "accepted"}
    settled(server)
    assert_totals(server, 2, 0, 1)
  end

  test "packet size, required metadata and paused ingress rejection have disjoint ingress accounting" do
    for kind <- [:size, :metadata, :paused] do
      opts =
        case kind do
          :size -> [max_packet_size: 2]
          :metadata -> [required_metadata: [:destination]]
          :paused -> []
        end

      {server, client, port} = endpoint(opts)
      if kind == :paused, do: assert(:ok = Endpoint.pause(server))
      :ok = packet(client, port, "ingress")

      reason =
        case kind do
          :size -> :packet_too_large
          :metadata -> {:missing_metadata, [:destination]}
          :paused -> :suspended
        end

      assert_drop(server, reason, 7)
      assert %{input_count: 0} = assert_totals(server, 1, 1, 0)
      refute_receive {:drop_callback, _, _}, 0
    end
  end

  test "actual managed timer admission rejection is internal event loss, not a network drop" do
    {server, client, port} = endpoint(runtime_options: [max_queue_bytes: 1000])
    :ok = packet(client, port, "timer")
    assert_receive {:drop_callback, _, "timer"}

    assert_receive {:drop_decision, [:abyss, :datagram, :event_rejected], ^server,
                    %{bytes: bytes}, %{event_type: :timer, reason: :input_bytes_limit}},
                   1000

    assert bytes == :erlang.external_size({:timer, :large_event, :binary.copy(<<1>>, 2048)})
    assert Telemetry.get_metrics(server).datagrams_dropped == 0

    assert %{internal_events_rejected: %{timer: 1, send_outcomes: 0}} =
             assert_totals(server, 1, 0, 0)

    assert Telemetry.get_metrics(server).timer_events_rejected == 1
    assert %{input_count: 0, timer_count: 0} = settled(server)
    refute_receive {:drop_decision, [:abyss, :datagram, :dropped], ^server, _, _}, 0
  end

  test "send-outcome deferred byte rejection is internal event loss after actual sends" do
    {server, client, port} = endpoint(runtime_options: [max_key_queue_bytes: 1000])
    :ok = packet(client, port, "outcomes")
    assert_receive {:drop_callback, _, "outcomes"}
    for i <- 1..32, do: assert({:ok, {_, ^port, <<^i>>}} = :gen_udp.recv(client, 0, 1000))

    assert_receive {:drop_decision, [:abyss, :datagram, :event_rejected], ^server,
                    %{bytes: bytes},
                    %{event_type: :send_outcomes, reason: :key_queue_bytes_limit}},
                   1000

    assert bytes > 1000
    assert Telemetry.get_metrics(server).datagrams_dropped == 0

    assert %{internal_events_rejected: %{timer: 0, send_outcomes: 1}} =
             assert_totals(server, 1, 0, 0)

    metrics = Telemetry.get_metrics(server)
    assert metrics.send_outcome_events_rejected == 1
    assert metrics.responses_total == 32
    assert metrics.bytes_sent == 32
    settled(server)
    refute_receive {:drop_decision, [:abyss, :datagram, :dropped], ^server, _, _}, 0
  end

  test "same-handler endpoints isolate drops and status reads do not change statistics" do
    {first, client, first_port} = endpoint(runtime_options: [max_key_queue_bytes: 128])
    {second, _, second_port} = endpoint()
    :ok = packet(client, first_port, "dropped")
    assert_drop(first, :key_queue_bytes_limit, 7)
    :ok = packet(client, second_port, <<>>)
    assert_receive {:drop_callback, _, <<>>}
    settled(second)

    for _ <- 1..5 do
      assert_totals(first, 1, 0, 1)
      assert_totals(second, 1, 0, 0)
    end
  end

  @tag :capture_log
  test "generation replacement resets public counts while logical-server telemetry persists" do
    {server, client, port} = endpoint(runtime_options: [max_key_queue_bytes: 128])
    :ok = packet(client, port, "old")
    assert_drop(server, :key_queue_bytes_limit, 3)
    info = assert_totals(server, 1, 0, 1)
    [listener] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
    monitor = Process.monitor(listener)
    Process.exit(listener, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^listener, :killed}
    replacement = wait_info(server, &(&1.generation != info.generation))
    assert replacement.received == 0
    assert replacement.dropped == 0
    assert replacement.drop_counts == %{ingress: 0, runtime: 0}
    assert replacement.internal_events_rejected == %{timer: 0, send_outcomes: 0}
    assert Telemetry.get_metrics(server).datagrams_received == 1
    assert Telemetry.get_metrics(server).datagrams_dropped == 1
    {_, new_port} = replacement.local_endpoint
    :ok = packet(client, new_port, "new")
    assert_drop(server, :key_queue_bytes_limit, 3)

    assert {:ok, %{received: 1, dropped: 1, drop_counts: %{ingress: 0, runtime: 1}}} =
             Endpoint.status(server)

    assert Telemetry.get_metrics(server).datagrams_received == 2
    assert Telemetry.get_metrics(server).datagrams_dropped == 2
  end

  test "callback failure, local send failure and teardown-discarded queue are not admission drops" do
    for payload <- ["fail", "failed-send", "block-fail"] do
      {server, client, port} = endpoint()
      :ok = packet(client, port, payload)
      assert_receive {:drop_callback, worker, ^payload}

      received =
        if payload == "block-fail" do
          :ok = packet(client, port, "queued")
          wait_info(server, &(&1.input_count == 2))
          send(worker, :finish_callback)
          2
        else
          1
        end

      settled(server)
      assert_totals(server, received, 0, 0)

      if payload == "failed-send",
        do: assert(Telemetry.get_metrics(server).send_errors_total == 1)

      refute_receive {:drop_decision, [:abyss, :datagram, :dropped], ^server, _, _}, 0
    end
  end

  @tag :capture_log
  test "runtime draining rejection has authoritative accounting even before listener barrier" do
    {server, client, port} = endpoint()
    :ok = packet(client, port, "block")
    assert_receive {:drop_callback, _, "block"}
    [listener] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
    runtime = :sys.get_state(listener).runtime
    Abyss.DatagramRuntime.drain(runtime, System.monotonic_time(:millisecond) + 5000)
    Abyss.DatagramRuntime.info(runtime)
    :ok = packet(client, port, "draining")
    assert_drop(server, :draining, 8)
    assert_totals(server, 2, 0, 1)
  end

  @tag :stopped_window
  test "normal and deadline-forced drain retain known counters through the stopped generation" do
    for mode <- [:normal, :forced] do
      route = fn datagram ->
        if datagram.payload == "drop", do: :binary.copy(<<1>>, 256), else: :same
      end

      {server, client, port} =
        endpoint(
          execution: :keyed,
          route_key: route,
          runtime_options: [max_key_bytes: 16, max_queue_bytes: 1000]
        )

      :ok = packet(client, port, "drop")
      assert_drop(server, :key_size_limit, 4)
      :ok = packet(client, port, "timer")
      assert_receive {:drop_callback, _, "timer"}

      assert_receive {:drop_decision, [:abyss, :datagram, :event_rejected], ^server, _,
                      %{event_type: :timer}},
                     1000

      settled(server)
      info = assert_totals(server, 2, 0, 1)
      assert info.internal_events_rejected == %{timer: 1, send_outcomes: 0}

      [listener] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
      runtime = :sys.get_state(listener).runtime
      generation = info.generation

      received =
        if mode == :forced do
          :ok = packet(client, port, "block")
          assert_receive {:drop_callback, _, "block"}
          3
        else
          2
        end

      started = System.monotonic_time(:millisecond)
      assert :ok = Abyss.Listener.drain(listener, started + 20)
      assert System.monotonic_time(:millisecond) - started < 500

      assert %{
               mode: :stopped,
               generation: ^generation,
               internal_events_rejected: %{timer: 1, send_outcomes: 0}
             } =
               assert_totals(server, received, 0, 1)

      # Fixed absolute snapshots are accepted only from this runtime/generation.
      # Sender ordering makes the subsequent public call a delivery barrier.
      bogus = %{dropped: 99, internal_events_rejected: %{timer: 99, send_outcomes: 99}}
      send(listener, {:runtime_drop_counters, runtime, make_ref(), bogus})
      send(listener, {:runtime_drop_counters, self(), generation, bogus})

      assert %{internal_events_rejected: %{timer: 1, send_outcomes: 0}} =
               assert_totals(server, received, 0, 1)
    end
  end
end

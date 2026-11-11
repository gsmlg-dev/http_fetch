defmodule Abyss.UDPHostHardeningTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  defmodule Controlled do
    require Abyss.Handler
    Abyss.Handler.__implement__([])

    def handle_data({ip, port, data}, state) do
      send(state.server_config.handler_options[:owner], {:admitted, self(), data})

      receive do
        :reply -> :ok = state.server_config.transport_module.send(state.socket, ip, port, data)
      end

      {:close, state}
    end
  end

  defmodule SlowStart do
    def child_spec(args),
      do: %{id: __MODULE__, start: {__MODULE__, :start_link, [args]}, restart: :temporary}

    def start_link({_span, config, _listener, _socket} = args) do
      send(config.handler_options[:owner], {:start_entered, self()})

      receive do
        :finish_start -> Controlled.start_link(args)
      end
    end
  end

  defmodule SlowDispatcher do
    @behaviour Abyss.DatagramDispatcher
    def init(_context, opts), do: {:ok, %{owner: opts[:owner]}}

    def handle_datagram(_peer, _data, _at, context) do
      send(context.state.owner, {:dispatcher_entered, self(), context})

      receive do
        :finish_dispatch -> :ok
      end

      {:ok, context.state}
    end
  end

  defp endpoint(opts \\ []) do
    server =
      start_supervised!(
        {Abyss,
         Keyword.merge(
           [
             handler_module: Controlled,
             handler_options: [owner: self()],
             port: 0,
             num_listeners: 4,
             num_connections: 2
           ],
           opts
         )}
      )

    [listener] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
    {_, port} = Abyss.Listener.listener_info(listener)
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false])
    on_exit(fn -> :gen_udp.close(socket) end)
    {server, listener, socket, port}
  end

  test "one ephemeral endpoint is responsive without packets" do
    {_, listener, _, port} = endpoint()
    assert port > 0
    assert %{mode: :running, pending_count: 0, pending_bytes: 0} = Abyss.Listener.status(listener)
  end

  test "pause keeps admitted replies and port; paused packets are discarded" do
    {server, listener, socket, port} = endpoint()
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "before")
    assert_receive {:admitted, handler, "before"}
    assert :ok = Abyss.suspend(server)
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "paused")
    send(handler, :reply)
    assert {:ok, {{127, 0, 0, 1}, ^port, "before"}} = :gen_udp.recv(socket, 0, 1000)
    refute_receive {:admitted, _, "paused"}, 50
    assert :ok = Abyss.resume(server)
    assert {_, ^port} = Abyss.Listener.listener_info(listener)
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "after")
    assert_receive {:admitted, next, "after"}
    send(next, :reply)
    assert {:ok, {_, ^port, "after"}} = :gen_udp.recv(socket, 0, 1000)
  end

  test "drain retains socket until the admitted response completes" do
    {server, listener, socket, port} = endpoint()
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "drain")
    assert_receive {:admitted, handler, "drain"}
    task = Task.async(fn -> Abyss.stop(server, 1000) end)
    assert %{mode: :draining} = wait_draining(listener)
    send(handler, :reply)
    assert {:ok, {_, ^port, "drain"}} = :gen_udp.recv(socket, 0, 1000)
    assert :ok = Task.await(task)
    refute Process.alive?(server)
  end

  test "empty datagrams count toward concurrency and overload is bounded" do
    {server, listener, socket, port} = endpoint(num_connections: 1)
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "")
    assert_receive {:admitted, handler, ""}
    for n <- 1..200, do: :gen_udp.send(socket, {127, 0, 0, 1}, port, <<n::32>>)

    assert %{active_handlers: 1, pending_count: 0, pending_bytes: 0} =
             Abyss.Listener.status(listener)

    assert DynamicSupervisor.count_children(Abyss.Server.connection_sup_pid(server)).active == 1
    refute_receive {:admitted, _, _}, 50
    send(handler, :reply)
    assert {:ok, {_, ^port, ""}} = :gen_udp.recv(socket, 0, 1000)
  end

  test "oversized datagram is rejected whole and stale socket messages are ignored" do
    {_, listener, socket, port} = endpoint(max_packet_size: 64)
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, :binary.copy("x", 9000))
    send(listener, {:udp, make_ref(), {127, 0, 0, 1}, port, "fake"})
    refute_receive {:admitted, _, _}, 50
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, :binary.copy("x", 64))
    assert_receive {:admitted, handler, data}
    assert byte_size(data) == 64
    send(handler, :reply)
  end

  test "one absolute drain deadline bounds many stalled callbacks" do
    {server, _listener, socket, port} = endpoint(num_connections: 3)

    for id <- 1..3 do
      :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, <<id>>)
      assert_receive {:admitted, _, <<^id>>}
    end

    before = System.monotonic_time(:millisecond)
    assert :ok = Abyss.stop(server, 40)
    elapsed = System.monotonic_time(:millisecond) - before
    assert elapsed < 250
  end

  test "forced listener death releases handler leases and cached generation" do
    {server, listener, socket, port} = endpoint(num_connections: 1)
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "generation")
    assert_receive {:admitted, handler, "generation"}
    monitor = Process.monitor(handler)
    Process.exit(listener, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^handler, :killed}
    assert :error = Abyss.Listener.listener_info_cached(listener)
    assert %{connections_active: 0} = Abyss.Telemetry.get_metrics(server)
    [next] = Abyss.ListenerPool.listener_pids(Abyss.Server.listener_pool_pid(server))
    refute next == listener
    {_, next_port} = Abyss.Listener.listener_info(next)
    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, next_port, "new")
    assert_receive {:admitted, next_handler, "new"}
    send(next_handler, :reply)
  end

  test "two instances using one handler keep counters isolated" do
    {first, _, socket, port} = endpoint()

    second =
      start_supervised!(
        {Abyss,
         [
           handler_module: Controlled,
           handler_options: [owner: self()],
           port: 0,
           num_connections: 1
         ]}
      )

    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "isolation")
    assert_receive {:admitted, handler, "isolation"}

    assert %{connections_active: 1, accepts_total: 1, responses_total: 0} =
             Abyss.Telemetry.get_metrics(first)

    assert %{connections_active: 0, accepts_total: 0, responses_total: 0} =
             Abyss.Telemetry.get_metrics(second)

    monitor = Process.monitor(handler)
    send(handler, :reply)
    assert {:ok, {_, ^port, "isolation"}} = :gen_udp.recv(socket, 0, 1000)
    # Wire arrival can precede send accounting; handler completion orders it.
    assert_receive {:DOWN, ^monitor, :process, ^handler, _}
    assert %{responses_total: 1, bytes_sent: 9} = Abyss.Telemetry.get_metrics(first)
  end

  @tag skip: Abyss.TestHost.linux_only()
  test "mixed loopback delivery modes isolate a saturated and crashing endpoint" do
    group = {239, 255, 72, 3}
    {unicast, _, _, unicast_port} = endpoint(num_connections: 1)

    {broadcast, _, _, broadcast_port} =
      endpoint(transport_module: Abyss.Transport.UDP.Broadcast)

    {multicast, _, _, multicast_port} =
      endpoint(
        transport_module: Abyss.Transport.UDP.Multicast,
        transport_options: [add_membership: {group, {127, 0, 0, 1}}]
      )

    {:ok, sender} =
      :gen_udp.open(0, [
        :binary,
        {:active, false},
        {:ip, {127, 0, 0, 1}},
        {:broadcast, true},
        {:multicast_if, {127, 0, 0, 1}}
      ])

    on_exit(fn -> :gen_udp.close(sender) end)
    assert :ok = :gen_udp.send(sender, {127, 0, 0, 1}, unicast_port, "held")
    assert_receive {:admitted, held, "held"}
    assert :ok = :gen_udp.send(sender, {127, 255, 255, 255}, broadcast_port, "broadcast")
    assert :ok = :gen_udp.send(sender, group, multicast_port, "multicast")
    assert_receive {:admitted, broadcast_handler, "broadcast"}
    assert_receive {:admitted, multicast_handler, "multicast"}

    for server <- [unicast, broadcast, multicast] do
      assert %{connections_active: 1, accepts_total: 1, responses_total: 0} =
               Abyss.Telemetry.get_metrics(server)
    end

    Process.exit(held, :kill)
    assert :ok = Abyss.stop(unicast, 100)
    broadcast_monitor = Process.monitor(broadcast_handler)
    multicast_monitor = Process.monitor(multicast_handler)
    send(broadcast_handler, :reply)
    send(multicast_handler, :reply)

    replies = for _ <- 1..2, do: :gen_udp.recv(sender, 0, 1000)
    assert {:ok, {{127, 0, 0, 1}, broadcast_port, "broadcast"}} in replies
    assert {:ok, {{127, 0, 0, 1}, multicast_port, "multicast"}} in replies
    # Wire arrival precedes the sender's telemetry update. Handler completion
    # orders the accounting assertions after both transport calls returned.
    assert_receive {:DOWN, ^broadcast_monitor, :process, ^broadcast_handler, _}
    assert_receive {:DOWN, ^multicast_monitor, :process, ^multicast_handler, _}
    assert %{responses_total: 1, bytes_sent: 9} = Abyss.Telemetry.get_metrics(broadcast)
    assert %{responses_total: 1, bytes_sent: 9} = Abyss.Telemetry.get_metrics(multicast)
  end

  test "expired custom startup releases payload, rejects late delivery, and drops once" do
    owner = self()
    attachment = "start-deadline-#{inspect(self())}"

    :telemetry.attach(
      attachment,
      [:abyss, :datagram, :dropped],
      fn _, _, metadata, _ -> send(owner, {:drop, metadata.reason}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(attachment) end)

    {server, listener, socket, port} =
      endpoint(handler_module: SlowStart, admission_start_timeout: 30)

    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "late")
    assert_receive {:start_entered, starter}
    on_exit(fn -> send(starter, :finish_start) end)
    assert_receive {:drop, :start_deadline}, 1000
    assert %{starting: 1, retained_bytes: 0, dropped: 1} = Abyss.Listener.status(listener)
    send(starter, :finish_start)
    assert :ok = Abyss.stop(server, 100)
    refute_receive {:admitted, _, "late"}
  end

  test "stalled custom startup cannot extend the total shutdown deadline" do
    {server, _listener, socket, port} =
      endpoint(handler_module: SlowStart, admission_start_timeout: 1000)

    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, port, "stalled")
    assert_receive {:start_entered, starter}
    on_exit(fn -> send(starter, :finish_start) end)
    before = System.monotonic_time(:millisecond)
    assert :ok = Abyss.stop(server, 40)
    assert System.monotonic_time(:millisecond) - before < 250
    refute Process.alive?(starter)
    refute_receive {:admitted, _, "stalled"}
  end

  test "dispatcher callbacks preserve ancillary metadata while owner stays responsive" do
    {server, listener, _socket, port} =
      endpoint(datagram_dispatcher: {SlowDispatcher, [owner: self()]})

    {socket, _span} = Abyss.Listener.socket_info(listener)
    send(listener, {:udp, socket, {127, 0, 0, 1}, port, [tos: 16], "ancillary"})
    assert_receive {:dispatcher_entered, dispatcher, %{ancillary: [tos: 16], local_info: local}}
    assert {_, ^port} = local
    assert %{starting: 1} = Abyss.Listener.status(listener)
    send(dispatcher, :finish_dispatch)
    assert :ok = Abyss.stop(server, 100)
  end

  test "a stuck dispatcher callback is dropped after the admission bound and reception resumes" do
    {server, listener, _socket, port} =
      endpoint(
        datagram_dispatcher: {SlowDispatcher, [owner: self()]},
        admission_start_timeout: 50
      )

    test_pid = self()
    handler_id = {:dispatcher_timeout, make_ref()}

    :ok =
      :telemetry.attach(
        handler_id,
        [:abyss, :datagram, :dropped],
        fn _event, _measurements, %{server_id: ^server, reason: reason}, _ ->
          send(test_pid, {:dropped, reason})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    {socket, _span} = Abyss.Listener.socket_info(listener)
    send(listener, {:udp, socket, {127, 0, 0, 1}, port, [], "stuck"})
    assert_receive {:dispatcher_entered, dispatcher, _context}
    assert %{starting: 1} = Abyss.Listener.status(listener)

    status = wait_status(listener, &match?(%{starting: 0}, &1))
    assert status.dropped == 1
    assert status.mode == :running
    assert_receive {:dropped, :dispatcher_timeout}

    # The listener is armed again: a later datagram reaches the dispatcher
    # once its stuck callback returns.
    send(listener, {:udp, socket, {127, 0, 0, 1}, port, [], "next"})
    assert %{starting: 1} = Abyss.Listener.status(listener)
    send(dispatcher, :finish_dispatch)
    assert_receive {:dispatcher_entered, ^dispatcher, _context}, 1_000
    send(dispatcher, :finish_dispatch)
    wait_status(listener, &match?(%{starting: 0}, &1))
    assert :ok = Abyss.stop(server, 100)
  end

  defp wait_status(listener, fun, tries \\ 200)
  defp wait_status(_listener, _fun, 0), do: flunk("listener status not reached")

  defp wait_status(listener, fun, tries) do
    status = Abyss.Listener.status(listener)

    if fun.(status) do
      status
    else
      Process.sleep(5)
      wait_status(listener, fun, tries - 1)
    end
  end

  defp wait_draining(listener, tries \\ 100)
  defp wait_draining(_listener, 0), do: flunk("drain barrier not reached")

  defp wait_draining(listener, tries) do
    case Abyss.Listener.status(listener) do
      %{mode: :draining} = state ->
        state

      _ ->
        :erlang.yield()
        wait_draining(listener, tries - 1)
    end
  end
end

defmodule Quic.CleanupIntegrationTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  alias Quic.{Cleanup, Connection, Endpoint}
  alias Quic.IO.GenUDP

  defmodule InitialTLS do
    def new(:client, _), do: {:ok, :client, [{:emit, :initial, <<1, 2>>}]}
    def info(_), do: %{receive_level: :initial}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  test "returned retirement from real UDP credit preserves the linked caller" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {caller, caller_down, endpoint} = receive_client(cleanup: lease)
    {port, io} = native_socket(Quic.local(endpoint))
    endpoint_down = Process.monitor(endpoint)
    io_down = Process.monitor(io)
    port_down = :erlang.monitor(:port, port)
    parent = self()
    tag = make_ref()

    gate = fn
      state, {:in, {:"$gen_call", _, {:consumed, generation, credit}}}, _ ->
        send(parent, {:credit_return_gate, tag, generation, credit})

        receive do
          {:release_credit, ^tag} -> state
        after
          2_000 -> exit(:credit_return_gate_timeout)
        end

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(io, {gate, nil})
    on_exit(fn -> send(io, {:release_credit, tag}) end)
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(peer) end)
    {ip, number} = Quic.local(endpoint)
    assert :ok = :gen_udp.send(peer, ip, number, <<0>>)
    assert_receive {:credit_return_gate, ^tag, generation, credit}, 1_000
    assert is_reference(generation) and is_reference(credit)
    assert {:pending, %{enrolled: 3, admission: :closed}} = Cleanup.retire(lease, bound(0))
    send(io, {:release_credit, tag})
    assert_receive {:DOWN, ^io_down, :process, ^io, :normal}, 1_000
    assert_receive {:DOWN, ^port_down, :port, ^port, :normal}, 1_000
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, :normal}, 1_000
    assert Process.alive?(caller)
    assert {:ok, %{cleanup: :confirmed, enrolled: 3, down: 3}} = Cleanup.await(handle, bound())
    send(caller, :stop_receive_client)
    assert_receive {:DOWN, ^caller_down, :process, ^caller, :normal}, 1_000
  end

  for tracked? <- [true, false] do
    test "returned stale real UDP credit remains an error with tracked=#{tracked?}" do
      tracked? = unquote(tracked?)
      {:ok, handle, lease} = Cleanup.new(owner: self())
      options = if tracked?, do: [cleanup: lease], else: []
      {caller, caller_down, endpoint} = receive_client(options)
      {port, io} = native_socket(Quic.local(endpoint))
      endpoint_down = Process.monitor(endpoint)
      io_down = Process.monitor(io)
      port_down = :erlang.monitor(:port, port)
      parent = self()
      tag = make_ref()

      capture = fn
        state, {:in, {:quic_udp, _, _, _, <<0>>, _} = message}, _ ->
          send(parent, {:credit_message, tag, message})
          state

        state, _, _ ->
          state
      end

      assert :ok = :sys.install(endpoint, {capture, nil})
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_udp.close(peer) end)
      {ip, number} = Quic.local(endpoint)
      assert :ok = :gen_udp.send(peer, ip, number, <<0>>)
      assert_receive {:credit_message, ^tag, message}, 1_000
      assert {^ip, ^number} = Quic.local(endpoint)
      assert {:pending, %{admission: :open}} = Cleanup.status(handle)
      send(endpoint, message)

      assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint,
                      {:socket_receive, :stale_credit}},
                     1_000

      assert_receive {:DOWN, ^caller_down, :process, ^caller, {:socket_receive, :stale_credit}},
                     1_000

      assert_receive {:DOWN, ^io_down, :process, ^io, :normal}, 1_000
      assert_receive {:DOWN, ^port_down, :port, ^port, :normal}, 1_000
      assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
    end
  end

  for tracked? <- [true, false] do
    test "a returned retiring fault with live authority stays abnormal with tracked=#{tracked?}" do
      tracked? = unquote(tracked?)
      {:ok, handle, lease} = Cleanup.new(owner: self())
      options = if tracked?, do: [cleanup: lease], else: []
      {caller, caller_down, endpoint} = receive_client(options)
      {port, io} = native_socket(Quic.local(endpoint))
      endpoint_down = Process.monitor(endpoint)
      io_down = Process.monitor(io)
      port_down = :erlang.monitor(:port, port)
      parent = self()
      tag = make_ref()

      reply_fault = fn
        state, {:in, {:"$gen_call", from, {:consumed, _, _}}}, _ ->
          GenServer.reply(from, {:error, :retiring})
          send(parent, {:live_retiring_reply, tag})
          state

        state, _, _ ->
          state
      end

      assert :ok = :sys.install(io, {reply_fault, nil})
      assert {:pending, %{admission: :open}} = Cleanup.status(handle)
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_udp.close(peer) end)
      {ip, number} = Quic.local(endpoint)
      assert :ok = :gen_udp.send(peer, ip, number, <<0>>)
      assert_receive {:live_retiring_reply, ^tag}, 1_000

      assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, {:socket_receive, :retiring}},
                     1_000

      assert_receive {:DOWN, ^caller_down, :process, ^caller, {:socket_receive, :retiring}}, 1_000
      assert_receive {:DOWN, ^io_down, :process, ^io, :normal}, 1_000
      assert_receive {:DOWN, ^port_down, :port, ^port, :normal}, 1_000
      assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
    end
  end

  test "retirement with queued real UDP credit preserves the linked caller" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    parent = self()
    tag = make_ref()

    observe = fn
      count, {:in, {:"$gen_call", _, {_, {:enroll, _, resource}}}}, _ ->
        send(parent, {:receive_resource, tag, count + 1, resource})
        count + 1

      count, _, _ ->
        count
    end

    assert :ok = :sys.install(handle.observer, {observe, 0})
    {caller, caller_down, endpoint} = receive_client(cleanup: lease)
    assert_receive {:receive_resource, ^tag, 1, ^endpoint}
    assert_receive {:receive_resource, ^tag, 2, io}
    assert_receive {:receive_resource, ^tag, 3, port}
    endpoint_down = Process.monitor(endpoint)
    io_down = Process.monitor(io)
    port_down = :erlang.monitor(:port, port)
    observe_cleanup_down(handle, tag, [io, port])
    gate_udp(endpoint, tag)
    observation_deadline = System.monotonic_time(:millisecond) + 1_000
    assert {:pending, %{enrolled: 3}} = Cleanup.retire(lease, bound(0))
    assert_receive {:DOWN, ^io_down, :process, ^io, :normal}, 1_000
    assert_receive {:DOWN, ^port_down, :port, ^port, :normal}, 1_000

    assert_receive {:cleanup_observed_down, ^tag},
                   max(observation_deadline - System.monotonic_time(:millisecond), 0)

    assert {:pending, %{enrolled: 3, down: 2}} = Cleanup.status(handle)
    send(endpoint, {:release_receive, tag})
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, :normal}, 1_000
    assert Process.alive?(caller)
    assert {:ok, %{cleanup: :confirmed, enrolled: 3, down: 3}} = Cleanup.await(handle, bound())
    send(caller, :stop_receive_client)
    assert_receive {:DOWN, ^caller_down, :process, ^caller, :normal}, 1_000
  end

  test "retirement after real UDP routing starts joins credit without killing its caller" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {caller, caller_down, endpoint} = receive_client(cleanup: lease, tls: [adapter: InitialTLS])
    {port, io} = native_socket(Quic.local(endpoint))
    endpoint_down = Process.monitor(endpoint)
    io_down = Process.monitor(io)
    port_down = :erlang.monitor(:port, port)
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, remote} = :inet.sockname(peer)
    on_exit(fn -> :gen_udp.close(peer) end)
    {:ok, connection} = Quic.connect(endpoint, remote)
    connection_down = Process.monitor(connection.id)
    assert {:ok, {_, _, initial}} = :gen_udp.recv(peer, 0, 1_000)
    assert {:ok, %{scid: scid}} = Quic.Codec.parse_initial(initial)
    parent = self()
    tag = make_ref()
    observe_cleanup_down(handle, tag, [io, port])

    pause = fn
      state, {:in, {{:call, _}, {:datagram, _, _, _}}, _}, _ ->
        send(parent, {:route_paused, tag})

        receive do
          {:release_route, ^tag} -> state
        after
          2_000 -> exit(:route_gate_timeout)
        end

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(connection.id, {pause, nil})
    on_exit(fn -> send(connection.id, {:release_route, tag}) end)
    {ip, number} = Quic.local(endpoint)
    assert :ok = :gen_udp.send(peer, ip, number, <<0x40, scid::binary>>)
    assert_receive {:route_paused, ^tag}, 1_000
    observation_deadline = System.monotonic_time(:millisecond) + 1_000
    assert {:pending, %{enrolled: 4}} = Cleanup.retire(lease, bound(0))
    assert_receive {:DOWN, ^io_down, :process, ^io, :normal}, 1_000
    assert_receive {:DOWN, ^port_down, :port, ^port, :normal}, 1_000

    assert_receive {:cleanup_observed_down, ^tag},
                   max(observation_deadline - System.monotonic_time(:millisecond), 0)

    assert {:pending, %{enrolled: 4, down: 2}} = Cleanup.status(handle)
    send(connection.id, {:release_route, tag})
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, :normal}, 1_000
    assert_receive {:DOWN, ^connection_down, :process, _, :normal}, 1_000
    assert Process.alive?(caller)
    assert {:ok, %{cleanup: :confirmed, enrolled: 4, down: 4}} = Cleanup.await(handle, bound())
    send(caller, :stop_receive_client)
    assert_receive {:DOWN, ^caller_down, :process, ^caller, :normal}, 1_000
  end

  for tracked? <- [true, false] do
    test "unexpected IO loss during queued UDP remains an error with tracked=#{tracked?}" do
      tracked? = unquote(tracked?)
      {:ok, handle, lease} = Cleanup.new(owner: self())
      options = if tracked?, do: [cleanup: lease], else: []
      {caller, caller_down, endpoint} = receive_client(options)
      {port, io} = native_socket(Quic.local(endpoint))
      endpoint_down = Process.monitor(endpoint)
      port_down = :erlang.monitor(:port, port)
      tag = make_ref()
      gate_udp(endpoint, tag)
      assert :ok = GenServer.stop(io, :normal)
      assert_receive {:DOWN, ^port_down, :port, ^port, :normal}, 1_000
      assert {:pending, %{admission: :open}} = Cleanup.status(handle)
      send(endpoint, {:release_receive, tag})
      assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, reason}, 1_000
      assert {:noproc, {GenServer, :call, [^io, {:consumed, _, _}, _]}} = reason
      assert_receive {:DOWN, ^caller_down, :process, ^caller, ^reason}, 1_000
      assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
    end
  end

  # Independent monitors can deliver DOWN before the observer publishes it.
  # The sys noreply event follows handle_info and its receipt update.
  defp observe_cleanup_down(handle, tag, resources) do
    parent = self()

    observe = fn
      state, {:in, {:DOWN, _, _, resource, _}}, _ ->
        %{state | current: resource}

      %{pending: pending, current: resource} = state, {:noreply, _}, _
      when resource != nil ->
        case List.delete(pending, resource) do
          [] ->
            send(parent, {:cleanup_observed_down, tag})
            :done

          pending ->
            %{state | pending: pending, current: nil}
        end

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(handle.observer, {observe, %{pending: resources, current: nil}})
  end

  defp receive_client(options) do
    parent = self()
    tag = make_ref()

    {caller, monitor} =
      spawn_monitor(fn ->
        {:ok, endpoint} = Quic.client(options)
        send(parent, {:receive_client, tag, endpoint})

        receive do
          :stop_receive_client ->
            if Process.alive?(endpoint), do: GenServer.stop(endpoint)
        after
          3_000 -> exit(:receive_client_timeout)
        end
      end)

    on_exit(fn -> send(caller, :stop_receive_client) end)
    assert_receive {:receive_client, ^tag, endpoint}, 1_000
    {caller, monitor, endpoint}
  end

  defp gate_udp(endpoint, tag) do
    parent = self()

    pause = fn
      state, {:in, {:quic_udp, _, _, _, <<0>>, _}}, _ ->
        send(parent, {:receive_paused, tag})

        receive do
          {:release_receive, ^tag} -> state
        after
          2_000 -> exit(:receive_gate_timeout)
        end

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(endpoint, {pause, nil})
    on_exit(fn -> send(endpoint, {:release_receive, tag}) end)
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(peer) end)
    {ip, port} = Quic.local(endpoint)
    assert :ok = :gen_udp.send(peer, ip, port, <<0>>)
    assert_receive {:receive_paused, ^tag}, 1_000
  end

  test "actual standalone client joins its Endpoint, GenUDP actor and concrete UDP Port" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, endpoint} = Quic.client(cleanup: lease)
    {port, io} = native_socket(Quic.local(endpoint))
    endpoint_down = Process.monitor(endpoint)
    io_down = Process.monitor(io)
    port_down = :erlang.monitor(:port, port)

    assert {:pending, %{enrolled: 3, roles: %{endpoint: 1, io: 1, port: 1}}} =
             Cleanup.status(handle)

    assert {:ok, %{cleanup: :confirmed, enrolled: 3, down: 3}} = Cleanup.retire(lease, bound())
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, _}
    assert_receive {:DOWN, ^io_down, :process, ^io, _}
    assert_receive {:DOWN, ^port_down, :port, ^port, _}
    assert :erlang.port_info(port) == :undefined
    assert {:error, :closed} = Quic.local(endpoint)
  end

  test "endpoint kill cannot confirm while an enrolled native connection is suspended" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, remote} = :inet.sockname(peer)
    on_exit(fn -> :gen_udp.close(peer) end)
    {:ok, endpoint} = Quic.client(cleanup: lease, tls: [adapter: InitialTLS])
    {port, io} = native_socket(Quic.local(endpoint))
    {:ok, connection} = Quic.connect(endpoint, remote)
    assert {:ok, {_, _, packet}} = :gen_udp.recv(peer, 0, 1_000)
    assert byte_size(packet) >= 1_200
    assert :erlang.suspend_process(connection.id)
    on_exit(fn -> if Process.alive?(connection.id), do: :erlang.resume_process(connection.id) end)
    Process.unlink(endpoint)
    endpoint_down = Process.monitor(endpoint)
    connection_down = Process.monitor(connection.id)
    port_down = :erlang.monitor(:port, port)
    Process.exit(endpoint, :kill)
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, :killed}
    assert {:pending, %{enrolled: 4}} = Cleanup.retire(lease, bound(0))
    assert Process.alive?(connection.id)
    assert :erlang.resume_process(connection.id)
    assert {:ok, %{cleanup: :confirmed, enrolled: 4, down: 4}} = Cleanup.await(handle, bound())
    assert_receive {:DOWN, ^connection_down, :process, _, _}
    assert_receive {:DOWN, ^port_down, :port, ^port, _}
    refute Process.alive?(io)
  end

  test "retiring one exclusive endpoint preserves its sibling's real UDP capability" do
    {:ok, first_handle, first_lease} = Cleanup.new(owner: self())
    {:ok, second_handle, second_lease} = Cleanup.new(owner: self())
    {:ok, first} = Quic.client(cleanup: first_lease)
    {:ok, second} = Quic.client(cleanup: second_lease, tls: [adapter: InitialTLS])
    assert Quic.local(first) != Quic.local(second)
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(first_lease, bound())
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, remote} = :inet.sockname(peer)
    on_exit(fn -> :gen_udp.close(peer) end)
    assert {:ok, _} = Quic.connect(second, remote)
    assert {:ok, {_, _, packet}} = :gen_udp.recv(peer, 0, 1_000)
    assert byte_size(packet) >= 1_200
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.status(first_handle)
    assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(second_lease, bound())
    assert {:ok, %{down: 4}} = Cleanup.status(second_handle)
  end

  test "a lease admits at most one endpoint before allocating a second native socket" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, endpoint} = Quic.client(cleanup: lease)
    assert {:error, :endpoint_already_reserved} = Quic.client(cleanup: lease)
    assert {:pending, %{enrolled: 3}} = Cleanup.status(handle)
    assert {:ok, %{cleanup: :confirmed, enrolled: 3}} = Cleanup.retire(lease, bound())
    refute Process.alive?(endpoint)
    assert {:error, :cleanup_unavailable} = Quic.client(cleanup: lease)
  end

  test "native operation results stay indeterminate after their graph is confirmed retired" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, _endpoint} = Quic.client(cleanup: lease)
    ref = make_ref()
    deadline = bound()
    assert {:ok, operation} = Cleanup.operation(lease, make_ref(), ref, :send, deadline)
    assert :ok = Cleanup.indeterminate(operation)
    assert {:pending, %{native_outcome: :indeterminate}} = Cleanup.status(handle)

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate}} =
             Cleanup.retire(lease, deadline)
  end

  test "expired construction allocates no endpoint or UDP Port" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    assert {:error, :deadline_expired} = Quic.client(cleanup: lease, deadline: bound(-1))
    assert {:pending, %{enrolled: 0, unresolved_births: 0}} = Cleanup.status(handle)
    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.retire(lease, bound())
  end

  test "allocation publication pause remains pending and late real Port is joined before confirmation" do
    {handle, lease, endpoint, io, port, allocation} = paused_allocation()
    port_down = :erlang.monitor(:port, port)
    io_down = Process.monitor(io)
    endpoint_down = Process.monitor(endpoint)
    assert {:pending, %{enrolled: 2, unresolved_births: 1}} = Cleanup.status(handle)
    assert :erlang.port_info(port) != :undefined
    assert {:pending, %{unresolved_births: 1}} = Cleanup.retire(lease, bound(0))
    send(io, {:publish, allocation})
    assert_receive {:publication, ^io, {:error, :retiring}}
    assert {:ok, %{cleanup: :confirmed, enrolled: 3, down: 3}} = Cleanup.await(handle, bound())
    assert_receive {:DOWN, ^port_down, :port, ^port, _}
    assert_receive {:DOWN, ^io_down, :process, ^io, _}
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, _}
  end

  test "death between real UDP allocation and publication preserves lost-birth integrity" do
    {handle, _lease, endpoint, io, port, _allocation} = paused_allocation()
    port_down = :erlang.monitor(:port, port)
    io_down = Process.monitor(io)
    endpoint_down = Process.monitor(endpoint)
    Process.exit(io, :kill)
    assert_receive {:DOWN, ^port_down, :port, ^port, _}
    assert_receive {:DOWN, ^io_down, :process, ^io, :killed}
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, _}

    assert {:error, {:cleanup_unconfirmed, :birth_unresolved}, %{unresolved_births: 1}} =
             Cleanup.await(handle, bound())

    # Independent Port DOWN cannot fill the provider's missing publication.
    assert :erlang.port_info(port) == :undefined
  end

  test "observer loss retires actual native actors but never fabricates their receipt" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, endpoint} = Quic.client(cleanup: lease)
    {port, io} = native_socket(Quic.local(endpoint))
    endpoint_down = Process.monitor(endpoint)
    io_down = Process.monitor(io)
    port_down = :erlang.monitor(:port, port)
    # Internal provider fault injection, independent from receipt evidence.
    Process.exit(handle.observer, :kill)
    assert {:error, {:cleanup_unconfirmed, :observer_lost}, _} = Cleanup.await(handle, bound())
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, _}, 1_000
    assert_receive {:DOWN, ^io_down, :process, ^io, _}, 1_000
    assert_receive {:DOWN, ^port_down, :port, ^port, _}, 1_000
    assert {:error, {:cleanup_unconfirmed, :observer_lost}, _} = Cleanup.status(handle)
  end

  test "a timed-out native connect is not replayed and cache eviction cannot resolve its receipt" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(peer) end)
    {:ok, remote} = :inet.sockname(peer)
    {:ok, endpoint} = Quic.client(cleanup: lease, operation_limit: 1, tls: [adapter: InitialTLS])
    assert :erlang.suspend_process(endpoint)
    on_exit(fn -> if Process.alive?(endpoint), do: :erlang.resume_process(endpoint) end)
    parent = self()
    ref = make_ref()
    deadline = bound(50)

    spawn(fn ->
      {:ok, operation} = Cleanup.operation(lease, make_ref(), ref, :connect, deadline)
      result = Quic.connect(endpoint, remote, ref: ref, deadline: deadline, timeout: 10)
      :ok = Cleanup.indeterminate(operation)
      send(parent, {:native_result, result})
    end)

    assert_receive {:native_result, {:unknown, ^ref}}

    receive do
    after
      60 -> :ok
    end

    assert :erlang.resume_process(endpoint)

    assert %{status: :rejected, result: {:error, :deadline_expired}} =
             Quic.operation_status(endpoint, ref)

    assert {:error, :would_block} = Quic.accept(endpoint, ref: make_ref())
    assert :unknown = Quic.operation_status(endpoint, ref)
    assert {:error, :timeout} = :gen_udp.recv(peer, 0, 30)

    assert {:ok, %{cleanup: :confirmed, enrolled: 3, native_outcome: :indeterminate}} =
             Cleanup.retire(lease, bound())

    assert {:ok, %{native_outcome: :indeterminate}} = Cleanup.status(handle)
  end

  test "ordinary untracked endpoint shutdown preserves its linked caller and joins real UDP" do
    {:ok, endpoint} = Quic.client([])
    {port, io} = native_socket(Quic.local(endpoint))
    endpoint_down = Process.monitor(endpoint)
    io_down = Process.monitor(io)
    port_down = :erlang.monitor(:port, port)
    assert :ok = GenServer.stop(endpoint)
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, :normal}
    assert_receive {:DOWN, ^io_down, :process, ^io, :normal}
    assert_receive {:DOWN, ^port_down, :port, ^port, _}
    assert :erlang.port_info(port) == :undefined
  end

  test "already-closed untracked IO cannot crash the endpoint's linked caller during retirement" do
    {:ok, endpoint} = Quic.client([])
    {port, io} = native_socket(Quic.local(endpoint))
    endpoint_down = Process.monitor(endpoint)
    port_down = :erlang.monitor(:port, port)
    assert :ok = GenUDP.close(io)
    assert_receive {:DOWN, ^endpoint_down, :process, ^endpoint, :normal}, 1_000
    assert_receive {:DOWN, ^port_down, :port, ^port, _}
    assert :erlang.port_info(port) == :undefined
  end

  test "queued attach keeps the original absolute deadline and cannot replace the consumer late" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, endpoint} = Quic.client(cleanup: lease, tls: [adapter: InitialTLS])
    {:ok, connection} = Quic.connect(endpoint, {{127, 0, 0, 1}, 9})
    assert :ok = Quic.attach(connection, self())
    assert :erlang.suspend_process(connection.id)
    on_exit(fn -> if Process.alive?(connection.id), do: :erlang.resume_process(connection.id) end)
    parent = self()
    consumer = spawn(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> send(consumer, :stop) end)
    deadline = bound(40)
    ref = make_ref()

    spawn(fn ->
      {:ok, operation} = Cleanup.operation(lease, connection.generation, ref, :attach, deadline)
      result = Quic.attach(connection, consumer, deadline: deadline, timeout: 10)
      :ok = Cleanup.indeterminate(operation)
      send(parent, {:attach_result, result})
    end)

    assert_receive {:attach_result, {:error, :timeout}}

    receive do
    after
      50 -> :ok
    end

    assert :erlang.resume_process(connection.id)
    assert {:ok, []} = Quic.events(connection)

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate}} =
             Cleanup.retire(lease, bound())

    assert {:ok, %{native_outcome: :indeterminate}} = Cleanup.status(handle)
  end

  test "public client rejected after the immediate fence returns without starting a linked endpoint" do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    assert :erlang.suspend_process(handle.observer)

    on_exit(fn ->
      if Process.alive?(handle.observer), do: :erlang.resume_process(handle.observer)
    end)

    parent = self()

    {caller, monitor} =
      spawn_monitor(fn ->
        send(parent, {:public_constructor, Quic.client(cleanup: lease, deadline: bound())})
      end)

    assert queued_constructor?(handle.observer, bound())
    assert {:pending, %{admission: :closed}} = Cleanup.retire(lease, bound(0))
    assert :erlang.resume_process(handle.observer)
    assert_receive {:public_constructor, {:error, :retiring}}
    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}
    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.await(handle, bound())
  end

  for {role, position} <- [endpoint: 1, io: 2, port: 3, connection: 4] do
    test "public client retirement at actual #{role} enrollment joins every native birth" do
      position = unquote(position)
      {handle, lease, caller, caller_down, peer, tag, resources} = public_gate(position)
      expected = position - 1
      assert {:pending, %{enrolled: ^expected, unresolved_births: 1}} = Cleanup.status(handle)
      assert {:error, :timeout} = :gen_udp.recv(peer, 0, 10)

      if position == 3 do
        port = List.last(resources)
        assert is_port(port)
        assert {:ok, [active: false]} = :inet.getopts(port, [:active])
        assert :erlang.port_info(port) != :undefined
      end

      joins = monitor_resources(resources)
      assert {:pending, %{admission: :closed}} = Cleanup.retire(lease, bound(0))
      send(handle.observer, {:release_public_gate, tag})
      assert_receive {:DOWN, ^caller_down, :process, ^caller, _}, 1_000
      refute_receive {:public_gate_result, ^tag, {:ok, _}}, 10

      assert {:ok, %{cleanup: :confirmed, enrolled: ^position, down: ^position}} =
               Cleanup.await(handle, bound())

      assert_resource_joins(joins)
      assert {:error, :timeout} = :gen_udp.recv(peer, 0, 30)
    end
  end

  test "public constructor caller loss during real Port publication joins the late native birth" do
    {handle, _lease, caller, caller_down, peer, tag, resources} = public_gate(3)
    port = List.last(resources)
    assert {:ok, [active: false]} = :inet.getopts(port, [:active])
    assert {:pending, %{enrolled: 2, unresolved_births: 1}} = Cleanup.status(handle)
    joins = monitor_resources(resources)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^caller_down, :process, ^caller, :killed}, 1_000
    assert {:pending, %{unresolved_births: 1}} = Cleanup.status(handle)
    send(handle.observer, {:release_public_gate, tag})
    assert {:ok, %{cleanup: :confirmed, enrolled: 3, down: 3}} = Cleanup.await(handle, bound())
    assert_resource_joins(joins)
    assert :erlang.port_info(port) == :undefined
    assert {:error, :timeout} = :gen_udp.recv(peer, 0, 30)
    refute_receive {:public_gate_result, ^tag, {:ok, _}}, 10
  end

  # The documented sys debug callback blocks only this observer's incoming
  # enrollment. Quic.client and every native constructor remain unchanged.
  # A Port enrollment event is the real passive allocation's publication;
  # this does not pause inside the runtime's native open instruction.
  defp public_gate(position) do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, remote} = :inet.sockname(peer)
    parent = self()
    tag = make_ref()

    debug = fn
      count, {:in, {:"$gen_call", _, {_, {:enroll, _, resource}}}}, _ ->
        next = count + 1
        send(parent, {:public_gate_birth, tag, next, resource})

        if next == position do
          receive do
            {:release_public_gate, ^tag} -> :ok
          after
            2_000 -> exit(:public_gate_timeout)
          end
        end

        next

      count, _, _ ->
        count
    end

    assert :ok = :sys.install(handle.observer, {debug, 0})

    {caller, monitor} =
      spawn_monitor(fn ->
        result = Quic.client(cleanup: lease, remote: remote, tls: [adapter: InitialTLS])
        send(parent, {:public_gate_result, tag, result})
      end)

    on_exit(fn ->
      send(handle.observer, {:release_public_gate, tag})
      Cleanup.retire(lease, bound())
      :gen_udp.close(peer)
    end)

    resources =
      for index <- 1..position do
        assert_receive {:public_gate_birth, ^tag, ^index, resource}, 1_000
        resource
      end

    {handle, lease, caller, monitor, peer, tag, resources}
  end

  defp monitor_resources(resources) do
    Enum.map(resources, fn resource ->
      type = if is_port(resource), do: :port, else: :process
      {type, resource, :erlang.monitor(type, resource)}
    end)
  end

  defp assert_resource_joins(joins) do
    Enum.each(joins, fn {type, resource, monitor} ->
      assert_receive {:DOWN, ^monitor, ^type, ^resource, _}, 1_000
      if type == :port, do: assert(:erlang.port_info(resource) == :undefined)
    end)
  end

  defp queued_constructor?(observer, {:abs_ms, deadline} = bound) do
    {:messages, messages} = Process.info(observer, :messages)

    queued =
      Enum.any?(messages, fn
        {:"$gen_call", _, {_, {:reserve, :endpoint, _}}} -> true
        _ -> false
      end)

    cond do
      queued ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        receive do
        after
          1 -> queued_constructor?(observer, bound)
        end
    end
  end

  for role <- [:endpoint, :io, :connection] do
    test "actual production #{role} init cannot activate after retirement during enrollment" do
      role = unquote(role)
      {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, remote} = :inet.sockname(peer)
      on_exit(fn -> :gen_udp.close(peer) end)
      {handle, lease, birth, producer, writer} = production_birth(role)
      assert :erlang.suspend_process(handle.observer)

      on_exit(fn ->
        if Process.alive?(handle.observer), do: :erlang.resume_process(handle.observer)
        Cleanup.retire(lease, bound())
      end)

      parent = self()

      spawn(fn ->
        # This constructor coordinator deliberately starts linked actors whose
        # init is rejected. It traps exits like a supervisor; the independent
        # init-caller control records OTP's nonnormal linked-init behavior.
        Process.flag(:trap_exit, true)

        options = [
          cleanup: lease,
          cleanup_birth: birth,
          deadline: bound(),
          owner: producer,
          role: :client
        ]

        result = start_production(role, options, writer, remote)
        send(parent, {:production_start, role, result})
      end)

      actor = queued_enrollment(handle.observer, birth.ref, bound())
      assert is_pid(actor)
      monitor = Process.monitor(actor)
      assert {:pending, %{unresolved_births: 1}} = Cleanup.status(handle)
      assert {:error, :timeout} = :gen_udp.recv(peer, 0, 10)
      assert {:pending, %{admission: :closed}} = Cleanup.retire(lease, bound(0))
      assert :erlang.resume_process(handle.observer)
      assert_receive {:production_start, ^role, {:error, _}}, 1_000
      assert_receive {:DOWN, ^monitor, :process, ^actor, _}, 1_000
      assert {:ok, %{cleanup: :confirmed}} = Cleanup.await(handle, bound())
      assert {:error, :timeout} = :gen_udp.recv(peer, 0, 30)
    end
  end

  defp start_production(:endpoint, options, _writer, _remote),
    do: Endpoint.start_link(options)

  defp start_production(:io, options, _writer, _remote),
    do: GenUDP.open(options)

  defp start_production(:connection, options, writer, remote) do
    Connection.start(
      options ++
        [
          cleanup_deadline: bound(),
          io: {GenUDP, writer},
          remote: remote,
          scheduler: [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: InitialTLS]
        ]
    )
  end

  # Internal constructor gates reserve capabilities explicitly, then start the
  # actual production actors. They supplement the ordinary Quic.client path;
  # they do not claim a pause inside every native allocation instruction.
  defp production_birth(:endpoint) do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, birth} = Cleanup.reserve(lease, :endpoint, bound())
    {handle, lease, birth, self(), nil}
  end

  defp production_birth(role) do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, endpoint_birth} = Cleanup.reserve(lease, :endpoint, bound())
    parent = self()

    producer =
      spawn(fn ->
        :ok = Cleanup.enroll(endpoint_birth, self())

        writer =
          if role == :connection do
            {:ok, io_birth} = Cleanup.reserve(lease, :io, bound())

            {:ok, io} =
              GenUDP.open(cleanup: lease, cleanup_birth: io_birth, deadline: bound())

            io
          end

        {:ok, birth} = Cleanup.reserve(lease, role, bound())
        send(parent, {:production_birth, self(), birth, writer})
        receive do: ({:quic_cleanup_retire, _} -> :ok)
      end)

    assert_receive {:production_birth, ^producer, birth, writer}
    {handle, lease, birth, producer, writer}
  end

  # Own observer protocol scheduling seam, not opaque socket/state inspection.
  defp queued_enrollment(observer, ref, {:abs_ms, deadline} = bound) do
    {:messages, messages} = Process.info(observer, :messages)

    actor =
      Enum.find_value(messages, fn
        {:"$gen_call", _, {_, {:enroll, ^ref, pid}}} when is_pid(pid) -> pid
        _ -> nil
      end)

    cond do
      actor ->
        actor

      System.monotonic_time(:millisecond) >= deadline ->
        nil

      true ->
        receive do
        after
          1 -> queued_enrollment(observer, ref, bound)
        end
    end
  end

  # These controllable birth producers use the same authenticated capability
  # protocol as the native actors. The ordinary standalone-client test above
  # independently exercises actual GenUDP allocation/enrollment/retirement.
  defp paused_allocation do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    {:ok, endpoint_birth} = Cleanup.reserve(lease, :endpoint, bound())
    parent = self()

    endpoint =
      spawn(fn ->
        :ok = Cleanup.enroll(endpoint_birth, self())
        {:ok, io_birth} = Cleanup.reserve(lease, :io, bound())
        send(parent, {:io_birth, self(), io_birth})
        receive do: ({:quic_cleanup_retire, _} -> :ok)
      end)

    assert_receive {:io_birth, ^endpoint, io_birth}

    io =
      spawn(fn ->
        :ok = Cleanup.enroll(io_birth, self())
        {:ok, allocation} = Cleanup.reserve(lease, :port, bound())
        {:ok, port} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
        send(parent, {:allocated, self(), port, allocation})

        receive do
          {:publish, ^allocation} ->
            send(parent, {:publication, self(), Cleanup.enroll(allocation, port)})
            :gen_udp.close(port)
        end
      end)

    assert_receive {:allocated, ^io, port, allocation}

    on_exit(fn ->
      Enum.each([endpoint, io], fn pid ->
        if Process.alive?(pid), do: Process.exit(pid, :kill)
      end)
    end)

    {handle, lease, endpoint, io, port, allocation}
  end

  defp native_socket(address) do
    Enum.find_value(:erlang.ports(), fn port ->
      case :erlang.port_info(port, :name) do
        {:name, ~c"udp_inet"} ->
          case :inet.sockname(port) do
            {:ok, ^address} ->
              {:connected, io} = :erlang.port_info(port, :connected)
              {port, io}

            _ ->
              nil
          end

        _ ->
          nil
      end
    end) || flunk("runtime did not expose the actual standalone UDP Port")
  end

  defp bound(timeout \\ 2_000), do: {:abs_ms, System.monotonic_time(:millisecond) + timeout}
end

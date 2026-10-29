defmodule QuicHttp3.CleanupIntegrationTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  alias Quic.Cleanup
  alias Quic.Runtime.StreamHandle
  alias QuicHttp3.{Frame, Qpack, Session}

  setup do
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, server} = Quic.listen(tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]])
    on_exit(fn -> stop_server(server) end)
    options = [tls: [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]]
    %{server: server, options: options}
  end

  test "Session intent is retained before the actual owned endpoint can be born", context do
    {:ok, handle, lease} = scope()
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {ip, port}} = :inet.sockname(peer)
    on_exit(fn -> :gen_udp.close(peer) end)
    parent = self()
    tag = make_ref()
    absolute = bound()

    debug = fn
      state, {:in, {:"$gen_call", _, {_, {:operation, target, ref, :connect, deadline}}}}, _ ->
        send(parent, {:intent, tag, target, ref, deadline})
        state

      state, {:in, {:"$gen_call", _, {_, {:reserve, :endpoint, _}}}}, _ ->
        send(parent, {:endpoint_birth_gate, tag})
        wait_gate(tag)
        state

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(handle.observer, {debug, nil})
    on_exit(fn -> send(handle.observer, {:release, tag}) end)

    {caller, monitor} =
      spawn_monitor(fn ->
        {:ok, session} = Session.new(cleanup: %{handle: handle, lease: lease})

        result =
          Session.connect(session, ip, port, Keyword.put(context.options, :deadline, absolute))

        send(parent, {:constructor_result, tag, result})
      end)

    {:abs_ms, deadline} = absolute
    assert_receive {:intent, ^tag, target, ref, ^deadline}, 1_000
    assert is_reference(target) and is_reference(ref)
    assert_receive {:endpoint_birth_gate, ^tag}, 1_000
    assert {:pending, %{enrolled: 0, unresolved_operations: 1}} = Cleanup.status(handle)
    assert {:pending, _} = Cleanup.retire(lease, bound(0))
    send(handle.observer, {:release, tag})
    assert_receive {:constructor_result, ^tag, {:error, _, :retiring}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}, 1_000
    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.await(handle, bound())
    assert {:error, :timeout} = :gen_udp.recv(peer, 0, 30)
  end

  test "registration timeout prevents actual endpoint and UDP allocation", context do
    {:ok, handle, lease} = scope()
    assert :erlang.suspend_process(handle.observer)

    on_exit(fn ->
      if Process.alive?(handle.observer), do: :erlang.resume_process(handle.observer)
    end)

    {:ok, session} = Session.new(cleanup: %{handle: handle, lease: lease})
    {ip, port} = Quic.local(context.server)
    options = context.options |> Keyword.put(:deadline, bound(30))
    assert {:error, _, :cleanup_unavailable} = Session.connect(session, ip, port, options)
    assert {:pending, %{enrolled: 0}} = Cleanup.status(handle)
    assert :erlang.resume_process(handle.observer)
    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.retire(lease, bound())
    refute_receive {:quic_accept, _}, 30
  end

  test "unknown actual attach keeps the shorter call wait and cannot be replayed", context do
    {:ok, handle, lease} = scope()
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {ip, port}} = :inet.sockname(peer)
    on_exit(fn -> :gen_udp.close(peer) end)
    parent = self()
    tag = make_ref()
    {:abs_ms, deadline} = absolute = bound()

    debug = fn
      state, {:in, {:"$gen_call", _, {_, {:operation, _, ref, :connect, _}}}}, _ ->
        send(parent, {:connect_intent, tag, ref})
        state

      state, {:in, {:"$gen_call", _, {_, {:reserve, :connection, _}}}}, _ ->
        Map.put(state, :connection_birth?, true)

      %{connection_birth?: true} = state,
      {:in, {:"$gen_call", _, {_, {:enroll, _, connection}}}},
      _ ->
        send(parent, {:connect_gate, tag, connection})
        wait_gate({tag, :connect})
        %{state | connection_birth?: false} |> Map.put(:connection, connection)

      %{connection: connection} = state,
      {:in, {:"$gen_call", _, {_, {:operation, target, ref, :attach, original}}}},
      _ ->
        send(parent, {:attach_gate, tag, connection, target, ref, original})
        wait_gate(tag)
        state

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(handle.observer, {debug, %{connection_birth?: false}})

    {caller, monitor} =
      spawn_monitor(fn ->
        {:ok, session} = Session.new(cleanup: %{handle: handle, lease: lease})
        options = context.options ++ [deadline: absolute, timeout: 20, consumer: parent]
        started = System.monotonic_time(:millisecond)

        {:unknown, %{connection: %{handle: nil}} = pending, connect_ref} =
          Session.connect(session, ip, port, options)

        assert pending.pending.ref == connect_ref
        assert pending.pending.deadline == deadline
        send(parent, {:connect_unknown, tag, connect_ref})

        assert %{status: :admitted} =
                 await_status(pending.connection.endpoint, connect_ref, absolute)

        result = Session.resume(pending)
        elapsed = System.monotonic_time(:millisecond) - started
        send(parent, {:attach_result, tag, result, elapsed})
        receive do: ({:release_caller, ^tag} -> :ok)
      end)

    on_exit(fn ->
      send(handle.observer, {:release, {tag, :connect}})
      send(handle.observer, {:release, tag})
      send(caller, {:release_caller, tag})
    end)

    assert_receive {:connect_intent, ^tag, connect_ref}, 1_000
    assert_receive {:connect_gate, ^tag, connection}, 1_000
    await_connect_timeout(handle.observer, connect_ref, absolute)
    send(handle.observer, {:release, {tag, :connect}})
    assert_receive {:connect_unknown, ^tag, ^connect_ref}, 1_000

    assert_receive {:attach_gate, ^tag, actor, generation, attach_ref, ^deadline}, 1_000
    assert actor == connection
    assert is_reference(attach_ref)
    assert :erlang.suspend_process(actor)
    send(handle.observer, {:release, tag})

    on_exit(fn ->
      try do
        :erlang.resume_process(actor)
      rescue
        ArgumentError -> :ok
      end
    end)

    {result, elapsed, resumed?} =
      receive do
        {:attach_result, ^tag, result, elapsed} -> {result, elapsed, false}
      after
        200 ->
          assert :erlang.resume_process(actor)

          receive do
            {:attach_result, ^tag, result, elapsed} -> {result, elapsed, true}
          after
            1_000 -> flunk("attach caller did not return after releasing its native actor")
          end
      end

    unless resumed?, do: assert(:erlang.resume_process(actor))
    assert {:unknown, session, ref} = result
    assert session.connection.handle.generation == generation
    assert session.pending.deadline == deadline
    assert session.pending.ref == ref

    trace_attach = fn
      state, {:in, {:"$gen_call", _, {:attach, _, _, _, _}}}, _ ->
        send(parent, {:attach_replayed, tag})
        state

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(actor, {trace_attach, nil})
    assert {:unknown, ^session, ^ref} = Session.resume(session)
    refute_receive {:attach_replayed, ^tag}, 30

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate, down: 4}} =
             Cleanup.retire(lease, bound())

    send(caller, {:release_caller, tag})
    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}, 1_000
    assert elapsed < 200
  end

  test "late actual connection enrollment is retired without publishing readiness", context do
    {:ok, handle, lease} = scope()
    {ip, port} = Quic.local(context.server)
    parent = self()
    tag = make_ref()
    {:abs_ms, deadline} = absolute = bound()

    debug = fn
      state, {:in, {:"$gen_call", _, {_, {:reserve, :connection, _}}}}, _ ->
        %{state | connection_birth?: true}

      %{connection_birth?: true} = state,
      {:in, {:"$gen_call", _, {_, {:enroll, _, connection}}}},
      _ ->
        send(parent, {:late_connection_gate, tag, connection})
        wait_gate(tag)
        %{state | connection_birth?: false}

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(handle.observer, {debug, %{connection_birth?: false}})

    {caller, monitor} =
      spawn_monitor(fn ->
        {:ok, session} = Session.new(cleanup: %{handle: handle, lease: lease})

        result =
          Session.connect(
            session,
            ip,
            port,
            context.options ++ [deadline: absolute, timeout: 20, consumer: parent]
          )

        send(parent, {:late_connect_result, tag, result})
        receive do: ({:release_caller, ^tag} -> :ok)
      end)

    on_exit(fn ->
      send(handle.observer, {:release, tag})
      send(caller, {:release_caller, tag})
    end)

    assert_receive {:late_connection_gate, ^tag, actor}, 1_000
    actor_monitor = Process.monitor(actor)

    receive do
    after
      30 -> :ok
    end

    assert {:pending, %{enrolled: 3, unresolved_births: 1}} = Cleanup.status(handle)
    assert {:pending, _} = Cleanup.retire(lease, bound(0))
    send(handle.observer, {:release, tag})
    assert_receive {:late_connect_result, ^tag, {:unknown, session, ref}}, 1_000
    assert session.pending.ref == ref and session.pending.deadline == deadline

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate, down: 4}} =
             Cleanup.await(handle, bound())

    assert_receive {:DOWN, ^actor_monitor, :process, ^actor, _}, 1_000
    refute_receive {:quic_ready, _, _}, 30
    send(caller, {:release_caller, tag})
    assert_receive {:DOWN, ^monitor, :process, ^caller, :normal}, 1_000
  end

  test "closed scope rejects a new Session connect before endpoint allocation", context do
    {:ok, handle, lease} = scope()
    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.retire(lease, bound())
    {:ok, session} = Session.new(cleanup: %{handle: handle, lease: lease})
    {ip, port} = Quic.local(context.server)
    assert {:error, _, :cleanup_unavailable} = Session.connect(session, ip, port, context.options)
    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.status(handle)
    refute_receive {:quic_accept, _}, 30
  end

  test "actual unknown stream open reconciles the original ref without a second stream",
       context do
    {session, accepted, handle, lease} = tracked_session(context)
    connection = session.connection.handle
    assert :erlang.suspend_process(connection.id)
    on_exit(fn -> if Process.alive?(connection.id), do: :erlang.resume_process(connection.id) end)
    {:abs_ms, deadline} = absolute = bound()
    fields = [{":path", "/one-open"}]

    assert {:unknown, session, ref} =
             Session.request(session, fields, "", deadline: absolute, timeout: 20)

    assert session.pending.ref == ref and session.pending.deadline == deadline
    assert session.pending.target_generation == connection.generation
    assert :erlang.resume_process(connection.id)
    assert %{status: :admitted} = await_status(connection, ref, absolute)
    assert {:ok, session, request_ref} = Session.resume(session)
    stream = session.requests[request_ref].stream.handle
    incoming = %StreamHandle{connection: accepted, id: stream.id}
    events = await_events(accepted, incoming, bound(), [])
    assert Enum.count(events, &(&1 == {:stream_open, incoming, :bidi})) == 1
    {:ok, block} = Qpack.encode_header_block(fields)
    expected = Frame.encode!(:headers, block)
    assert await_wire(incoming, byte_size(expected), bound(), <<>>) == expected

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate, down: 4}} =
             Cleanup.retire(lease, bound())

    assert {:ok, %{cleanup: :confirmed}} = Cleanup.status(handle)
  end

  test "native unknown send survives cache eviction and abort without replay", context do
    {session, accepted, handle, lease} = tracked_session(context, operation_limit: 1)
    fields = [{":path", "/one-send"}]
    {:ok, session, request_ref} = Session.request(session, fields, :stream, [])
    stream = session.requests[request_ref].stream.handle
    incoming = %StreamHandle{connection: accepted, id: stream.id}
    _ = await_events(accepted, incoming, bound(), [])
    {:ok, block} = Qpack.encode_header_block(fields)
    headers = Frame.encode!(:headers, block)
    assert await_wire(incoming, byte_size(headers), bound(), <<>>) == headers
    connection = session.connection.handle
    assert :erlang.suspend_process(connection.id)
    on_exit(fn -> if Process.alive?(connection.id), do: :erlang.resume_process(connection.id) end)
    absolute = bound()

    assert {:unknown, session, ref} =
             Session.send_data(session, request_ref, "only once", false,
               deadline: absolute,
               timeout: 20
             )

    assert :erlang.resume_process(connection.id)
    assert %{status: :admitted} = await_status(connection, ref, absolute)
    assert {:ok, _} = Quic.events(connection, 1)
    assert :unknown = Quic.operation_status(connection, ref)
    assert {:unknown, ^session, ^ref} = Session.resume(session)
    expected = Frame.encode!(:data, "only once")
    assert await_wire(incoming, byte_size(expected), bound(), <<>>) == expected
    assert {:ok, []} = Quic.read(incoming, 16_384)
    assert {:ok, aborted} = Session.abort(session)
    assert aborted.aborted_operation == %{ref: ref, kind: :send_stream, status: :unknown}

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate, down: 4}} =
             Cleanup.await(handle, bound())

    assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
  end

  test "expired tracked abort retires the graph without a fresh application permit", context do
    {session, _accepted, handle, lease} = tracked_session(context)
    connection = session.connection.handle
    assert :erlang.suspend_process(connection.id)
    parent = self()
    tag = make_ref()

    trace = fn
      state, {:in, {:"$gen_call", _, {_, {:operation, _, _, :abort, _}}}}, _ ->
        send(parent, {:fresh_abort_permit, tag})
        state

      state, _, _ ->
        state
    end

    assert :ok = :sys.install(handle.observer, {trace, nil})

    assert {:unknown, session, ref} =
             Session.request(session, [{":path", "/expired-abort"}], "",
               deadline: bound(30),
               timeout: 10
             )

    receive do
    after
      50 -> :ok
    end

    assert {:error, aborted, :deadline_expired} = Session.abort(session)
    assert aborted.aborted_operation == %{ref: ref, kind: :open_stream, status: :unknown}
    refute_received {:fresh_abort_permit, ^tag}
    assert {:pending, %{enrolled: 4, admission: :closed}} = Cleanup.status(handle)
    assert :erlang.resume_process(connection.id)

    assert {:ok, %{cleanup: :confirmed, native_outcome: :indeterminate, down: 4}} =
             Cleanup.await(handle, bound())

    assert {:ok, %{cleanup: :confirmed}} = Cleanup.retire(lease, bound())
  end

  test "rejected exclusive claims leave an actual shared endpoint usable", context do
    alias QuicHttp3.Transport.Quic, as: Adapter
    {ip, port} = Quic.local(context.server)
    {:ok, shared} = Adapter.client([host: "127.0.0.1"] ++ context.options)
    on_exit(fn -> Adapter.stop_endpoint(shared.pid) end)
    {:ok, session} = Session.new()
    {:ok, session} = Session.connect(session, ip, port, [endpoint: shared] ++ context.options)
    connection = session.connection.handle
    assert_receive {:quic_ready, ^connection, %{alpn: "h3", peer_authenticated: true}}, 2_000
    assert_receive {:quic_accept, server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    {:ok, handle, lease} = scope()
    descriptor = %{handle: handle, lease: lease}

    assert {:error, :cleanup_requires_owned_endpoint} =
             Adapter.client([host: "127.0.0.1", cleanup: descriptor] ++ context.options)

    for endpoint <- [shared, shared.pid] do
      assert {:error, :cleanup_requires_owned_endpoint} =
               Adapter.connect(
                 ip,
                 port,
                 [endpoint: endpoint, cleanup: descriptor, deadline: bound()] ++ context.options
               )
    end

    assert {:ok, %{cleanup: :confirmed, enrolled: 0}} = Cleanup.retire(lease, bound())
    assert :ready = Session.ready(session)
    assert {:ok, session} = Session.open(session)
    fields = [{":path", "/shared-sibling"}]
    assert {:ok, session, request_ref} = Session.request(session, fields, "", [])
    stream = session.requests[request_ref].stream.handle
    incoming = %StreamHandle{connection: accepted, id: stream.id}
    _ = await_events(accepted, incoming, bound(), [])
    {:ok, block} = Qpack.encode_header_block(fields)
    expected = Frame.encode!(:headers, block)
    assert await_wire(incoming, byte_size(expected), bound(), <<>>) == expected
    assert Process.alive?(shared.pid)
  end

  test "an expired Session deadline still lets abort retire its actual graph", context do
    {:ok, handle, lease} = scope()
    {:abs_ms, deadline} = absolute = bound()
    {:ok, session} = Session.new(cleanup: %{handle: handle, lease: lease}, deadline: absolute)
    {ip, port} = Quic.local(context.server)
    {:ok, session} = Session.connect(session, ip, port, context.options)
    connection = session.connection.handle
    assert_receive {:quic_ready, ^connection, %{alpn: "h3", peer_authenticated: true}}, 2_000
    assert session.work == nil
    assert {:pending, %{admission: :open, enrolled: 4}} = Cleanup.status(handle)

    receive do
    after
      max(0, deadline - System.monotonic_time(:millisecond)) + 1 -> :ok
    end

    assert {:error, _, :deadline_expired} = Session.abort(session)
    assert {:ok, %{cleanup: :confirmed, down: 4}} = Cleanup.await(handle, bound())
  end

  defp scope do
    {:ok, handle, lease} = Cleanup.new(owner: self())
    on_exit(fn -> Cleanup.retire(lease, bound()) end)
    {:ok, handle, lease}
  end

  defp tracked_session(context, connection_options \\ []) do
    {:ok, handle, lease} = scope()
    {:ok, session} = Session.new(cleanup: %{handle: handle, lease: lease}, max_frame: 1_024)
    {ip, port} = Quic.local(context.server)
    {:ok, session} = Session.connect(session, ip, port, context.options ++ connection_options)
    connection = session.connection.handle
    assert_receive {:quic_ready, ^connection, %{alpn: "h3", peer_authenticated: true}}, 2_000
    assert_receive {:quic_accept, server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    {:ok, session} = Session.open(session)
    {session, accepted, handle, lease}
  end

  defp await_status(connection, ref, {:abs_ms, deadline} = absolute) do
    assert System.monotonic_time(:millisecond) < deadline

    case Quic.operation_status(connection, ref) do
      :unknown ->
        receive do
        after
          1 -> await_status(connection, ref, absolute)
        end

      result ->
        result
    end
  end

  defp await_connect_timeout(observer, ref, {:abs_ms, deadline} = absolute) do
    assert System.monotonic_time(:millisecond) < deadline
    {:messages, messages} = Process.info(observer, :messages)

    if Enum.any?(messages, fn
         {:"$gen_call", _, {_, {:operation_result, ^ref, :indeterminate}}} -> true
         _ -> false
       end) do
      :ok
    else
      receive do
      after
        1 -> await_connect_timeout(observer, ref, absolute)
      end
    end
  end

  defp await_events(connection, incoming, {:abs_ms, deadline} = absolute, acc) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(connection)
    events = acc ++ events

    if {:readable, incoming} in events do
      events
    else
      receive do
      after
        1 -> await_events(connection, incoming, absolute, events)
      end
    end
  end

  defp await_wire(stream, size, {:abs_ms, deadline} = absolute, acc) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    bytes = for {:data, _, bytes} <- items, into: acc, do: bytes

    if byte_size(bytes) >= size do
      bytes
    else
      receive do
      after
        1 -> await_wire(stream, size, absolute, bytes)
      end
    end
  end

  defp wait_gate(tag) do
    receive do
      {:release, ^tag} -> :ok
    after
      2_000 -> exit(:cleanup_test_gate_timeout)
    end
  end

  defp stop_server(server) do
    if Process.alive?(server), do: GenServer.stop(server)
  catch
    :exit, {:noproc, _} -> :ok
  end

  defp bound(timeout \\ 2_000), do: {:abs_ms, System.monotonic_time(:millisecond) + timeout}
end

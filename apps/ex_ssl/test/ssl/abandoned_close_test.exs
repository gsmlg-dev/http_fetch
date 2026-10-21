defmodule SSL.AbandonedCloseTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.Protocol.RecordFramer

  @moduletag :integration
  @logical_size 16 * 1_048_576
  @prefix :binary.copy("retained-prefix!", 1_024)
  @response "authenticated-response"
  @fixture_ms 5_000
  @max_tail 65_536

  for {abandon?, expected_terminal} <- [{false, :fin}, {true, :reset}] do
    test "final close after completed retained output abandon=#{abandon?} is #{expected_terminal}" do
      parent = self()
      ref = make_ref()
      peer = start_peer(parent, ref)
      bridge = start_bridge(peer.port, parent, ref)
      options = [:binary | Keyword.merge(tl(Peer.client_options()), send_timeout: @fixture_ms)]
      assert {:ok, socket} = SSL.connect(~c"127.0.0.1", bridge.port, options, @fixture_ms)
      assert_receive {^ref, :peer_ready}, @fixture_ms
      initial = snapshot(socket.pid)
      writer = initial.writer
      connection_monitor = Process.monitor(socket.pid)
      writer_monitor = Process.monitor(writer)

      on_exit(fn ->
        resume_writer(writer)
        if Process.alive?(socket.pid), do: Process.exit(socket.pid, :kill)
        if Process.alive?(bridge.task.pid), do: Process.exit(bridge.task.pid, :kill)
        if Process.alive?(peer.task.pid), do: Process.exit(peer.task.pid, :kill)
        :gen_tcp.close(bridge.listener)
        :ssl.close(peer.listener)
      end)

      assert :ok = SSL.enable_duplex_reads(socket)
      assert :ok = bridge_command(bridge, :observe)
      assert true = :erlang.suspend_process(writer)

      payload =
        if unquote(abandon?),
          do: @prefix <> :binary.copy("d", @logical_size - byte_size(@prefix)),
          else: @prefix

      {sender, sender_monitor} =
        spawn_monitor(fn -> send(parent, {ref, :send_result, SSL.send(socket, payload)}) end)

      held = wait_state(socket.pid, &match?(%{output: %{kind: :application}}, &1))
      assert held.output.size <= 16_406
      assert held.output.size > byte_size(@prefix)
      assert held.write_nil? == false

      if unquote(abandon?) do
        assert :ok = SSL.abandon_send(socket)
        assert_receive {^ref, :send_result, {:error, :write_abandoned}}, 1_000
        assert_receive {:DOWN, ^sender_monitor, :process, ^sender, :normal}, 1_000
        abandoned = snapshot(socket.pid)
        assert abandoned.abandoned?
        assert abandoned.write_nil?
        assert abandoned.output == held.output
        assert {:error, :closed} = SSL.send(socket, "must-not-replay")
      end

      send(peer.task.pid, {ref, :respond})
      assert {:ok, @response} = SSL.recv(socket, byte_size(@response), 1_000)
      assert snapshot(socket.pid).output == held.output
      assert true = :erlang.resume_process(writer)

      unless unquote(abandon?) do
        assert_receive {^ref, :send_result, :ok}, 1_000
        assert_receive {:DOWN, ^sender_monitor, :process, ^sender, :normal}, 1_000
      end

      completed =
        wait_state(socket.pid, fn state ->
          state.output == nil and state.write_nil? and state.driver_pending == 0
        end)

      assert completed.abandoned? == unquote(abandon?)
      assert completed.tcp == held.tcp
      assert_receive {^ref, :record_forwarded, wire_size}, 1_000
      assert wire_size == held.output.size
      # The relay seals only after forwarding exactly the committed record. Its
      # receive loop continues: no assertion forces the client's kernel queue empty.
      assert :ok = bridge_command(bridge, :seal)

      close_deadline = now() + 1_000
      closer = Task.async(fn -> SSL.close(socket) end)
      assert :ok = Task.await(closer, remaining(close_deadline))
      connection = socket.pid

      assert_receive {:DOWN, ^connection_monitor, :process, ^connection, :normal},
                     remaining(close_deadline)

      assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, remaining(close_deadline)
      assert Port.info(completed.tcp) == nil
      assert now() <= close_deadline

      # This is the first terminal event on the CLIENT endpoint, recorded before
      # either relay cleanup or propagation can manufacture a reset at that hop.
      assert_receive {^ref, :client_terminal, actual_terminal}, 1_000

      drain_deadline = now() + 2_000
      send(peer.task.pid, {ref, :drain, drain_deadline})
      assert_receive {^ref, :prefix_received, prefix_size}, remaining(drain_deadline)
      assert prefix_size == byte_size(@prefix)
      assert :ok = bridge_command(bridge, :release_final)
      assert_receive {^ref, :peer_closed, ^prefix_size}, remaining(drain_deadline)
      assert :ok = Peer.stop(peer)
      assert :ok = bridge_command(bridge, :stop)
      assert :ok = Task.await(bridge.task, 1_000)

      # Both FIN and RESET can satisfy an EOF-only drain. This final comparison
      # is the semantic RED on old code, rather than a fixture timeout.
      assert actual_terminal == unquote(expected_terminal)
    end
  end

  defp start_peer(parent, ref) do
    {:ok, peer} =
      Peer.start(
        fn socket ->
          send(parent, {ref, :peer_ready})

          receive do
            {^ref, :respond} -> assert :ok = :ssl.send(socket, @response)
          after
            @fixture_ms -> flunk("peer was not asked to send its authenticated response")
          end

          # Deliberately do not read upload plaintext until local DOWN/port
          # evidence has been collected by the test process.
          receive do
            {^ref, :drain, deadline} ->
              assert {:ok, @prefix} = :ssl.recv(socket, byte_size(@prefix), remaining(deadline))
              send(parent, {ref, :prefix_received, byte_size(@prefix)})
              assert {:error, reason} = :ssl.recv(socket, 0, remaining(deadline))
              refute reason == :timeout
              send(parent, {ref, :peer_closed, byte_size(@prefix)})
          after
            @fixture_ms -> flunk("peer was not permitted to drain after local cleanup")
          end

          :ok
        end,
        ssl_options: [session_tickets: :disabled]
      )

    peer
  end

  defp start_bridge(upstream_port, observer, ref) do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        active: false,
        packet: :raw,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        show_econnreset: true,
        exit_on_close: false
      ])

    {:ok, port} = :inet.port(listener)

    task =
      Task.async(fn ->
        {:ok, client} = :gen_tcp.accept(listener, @fixture_ms)

        {:ok, upstream} =
          :gen_tcp.connect(
            {127, 0, 0, 1},
            upstream_port,
            [:binary, active: false, packet: :raw, exit_on_close: false],
            @fixture_ms
          )

        assert {:ok, [show_econnreset: true]} = :inet.getopts(client, [:show_econnreset])
        :ok = :inet.setopts(client, active: true)
        :ok = :inet.setopts(upstream, active: true)

        state = %{
          client: client,
          upstream: upstream,
          observer: observer,
          ref: ref,
          observing?: false,
          sealed?: false,
          records: RecordFramer.new(),
          record_count: 0,
          tail: :queue.new(),
          tail_size: 0,
          terminal: nil
        }

        try do
          bridge_loop(state)
        after
          :gen_tcp.close(client)
          :gen_tcp.close(upstream)
        end
      end)

    %{task: task, listener: listener, port: port, ref: ref}
  end

  defp bridge_loop(state) do
    %{client: client, upstream: upstream, ref: ref} = state

    receive do
      {^ref, :observe, caller} ->
        send(caller, {ref, :bridge_reply, :observe, :ok})
        bridge_loop(%{state | observing?: true})

      {^ref, :seal, caller} ->
        assert state.record_count == 1
        assert RecordFramer.buffered_size(state.records) == 0
        send(caller, {ref, :bridge_reply, :seal, :ok})
        bridge_loop(%{state | sealed?: true})

      {^ref, :release_final, caller} ->
        assert state.terminal in [:fin, :reset]
        assert :ok = :gen_tcp.send(upstream, :queue.to_list(state.tail))

        case state.terminal do
          :fin ->
            assert :ok = :gen_tcp.shutdown(upstream, :write)

          :reset ->
            assert :ok = :inet.setopts(upstream, linger: {true, 0})
            :gen_tcp.close(upstream)
        end

        send(caller, {ref, :bridge_reply, :release_final, :ok})
        bridge_loop(%{state | tail: :queue.new(), tail_size: 0})

      {^ref, :stop, caller} ->
        send(caller, {ref, :bridge_reply, :stop, :ok})
        :ok

      {:tcp, ^client, bytes} ->
        state = forward_client(state, bytes)
        bridge_loop(state)

      {:tcp, ^upstream, bytes} ->
        # Once the client endpoint is terminal it cannot consume a reciprocal
        # close_notify. Do not let that late reply change its recorded class.
        if state.terminal == nil, do: assert(:ok == :gen_tcp.send(client, bytes))
        bridge_loop(state)

      {:tcp_closed, ^client} ->
        bridge_loop(record_terminal(state, :fin))

      {:tcp_error, ^client, :econnreset} ->
        bridge_loop(record_terminal(state, :reset))

      {:tcp_closed, ^upstream} ->
        bridge_loop(state)

      {:tcp_error, ^upstream, :econnreset} ->
        bridge_loop(state)
    after
      @fixture_ms -> flunk("bounded close-observer relay stalled")
    end
  end

  defp forward_client(%{sealed?: true} = state, bytes) do
    size = state.tail_size + byte_size(bytes)
    assert size <= @max_tail
    %{state | tail: :queue.in(bytes, state.tail), tail_size: size}
  end

  defp forward_client(state, bytes) do
    assert :ok = :gen_tcp.send(state.upstream, bytes)

    if state.observing? do
      {:ok, records, framer} = RecordFramer.feed(state.records, bytes)
      count = state.record_count + length(records)
      assert count <= 1

      for record <- records,
          do: send(state.observer, {state.ref, :record_forwarded, byte_size(record)})

      %{state | records: framer, record_count: count}
    else
      state
    end
  end

  defp record_terminal(%{terminal: nil} = state, terminal) do
    assert state.sealed?
    send(state.observer, {state.ref, :client_terminal, terminal})
    %{state | terminal: terminal}
  end

  defp record_terminal(state, _terminal), do: state

  defp bridge_command(bridge, command) do
    send(bridge.task.pid, {bridge.ref, command, self()})
    ref = bridge.ref
    assert_receive {^ref, :bridge_reply, ^command, result}, 1_000
    result
  end

  # Test-only scalar evidence; no machine, keys, plaintext cursors or OTP private
  # layouts are returned or logged by the precondition observer.
  defp snapshot(pid) do
    {:connected, state} = :sys.get_state(pid)
    {:ok, [{:send_pend, pending}]} = :inet.getstat(state.tcp, [:send_pend])

    %{
      tcp: state.tcp,
      writer: state.writer,
      output: if(state.output, do: Map.take(state.output, [:token, :kind, :size, :timer])),
      write_nil?: state.write == nil,
      abandoned?: state.write_abandoned?,
      driver_pending: pending
    }
  end

  defp wait_state(pid, predicate), do: wait_state(pid, predicate, now() + 1_000)

  defp wait_state(pid, predicate, deadline) do
    state = snapshot(pid)

    if predicate.(state) do
      state
    else
      assert now() < deadline, "close regression precondition did not become ready"

      receive do
      after
        1 -> wait_state(pid, predicate, deadline)
      end
    end
  end

  defp resume_writer(writer) do
    if Process.alive?(writer), do: :erlang.resume_process(writer)
  rescue
    ArgumentError -> :ok
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp remaining(deadline), do: max(0, deadline - now())
end

defmodule SSL.ConnectionLifecycleTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  @moduletag :integration

  test "a peer-requested update at the final sending generation closes without another epoch" do
    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :request_update -> :ok
        end

        assert :ok = :ssl.update_keys(socket, :read_write)
        assert {:error, {:tls_alert, {:internal_error, _}}} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)

    :sys.replace_state(socket.pid, fn {:connected, state} ->
      write = %{state.machine.write_state | generation: 0xFFFFFFFFFFFF}
      {:connected, %{state | machine: %{state.machine | write_state: write}}}
    end)

    monitor = Process.monitor(socket.pid)
    receiver = Task.async(fn -> SSL.recv(socket, 0, 5_000) end)
    wait_for_pending_receiver(socket.pid)
    send(peer.task.pid, :request_update)
    assert {:error, {:tls_alert, {:internal_error, _}}} = Task.await(receiver)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}
    refute MapSet.member?(connection_children(), socket.pid)
    assert {:error, :econnreset} = SSL.send(socket, "never replay")
    Peer.stop(peer)
  end

  test "an exhausted application writer terminates and wakes pending operations" do
    {:ok, peer} = Peer.start(fn socket -> assert {:error, _} = :ssl.recv(socket, 0, 5_000) end)
    socket = connect(peer)

    :sys.replace_state(socket.pid, fn {:connected, state} ->
      write = %{state.machine.write_state | sequence: 23_726_566}
      {:connected, %{state | machine: %{state.machine | write_state: write}}}
    end)

    monitor = Process.monitor(socket.pid)
    receiver = Task.async(fn -> SSL.recv(socket, 0, 5_000) end)
    wait_for_pending_receiver(socket.pid)
    assert {:error, {:tls_alert, {:internal_error, _}}} = SSL.send(socket, "never sent")
    assert {:error, {:tls_alert, {:internal_error, _}}} = Task.await(receiver)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}
    refute MapSet.member?(connection_children(), socket.pid)
    assert {:error, :econnreset} = SSL.recv(socket, 0, 0)
    Peer.stop(peer)
  end

  for {name, ticket} <- [
        {"normal", <<4, 15::24, 60::32, 7::32, 1, 9, 1::16, 1, 0::16>>},
        {"unknown extension",
         <<4, 20::24, 60::32, 7::32, 1, 9, 1::16, 1, 5::16, 0xFEFF::16, 1::16, 9>>},
        {"invalid resumption contents", <<4, 0::24>>}
      ] do
    test "public connection exchanges application data after a ticket with #{name}" do
      {:ok, peer} =
        Peer.start(fn socket ->
          :ok = :ssl.send(socket, "ready")

          receive do
            :send_ticket_slot -> :ok
          end

          # The proxy replaces this single encrypted record with an NST using
          # the same sequence. All subsequent traffic remains the OTP peer's.
          :ok = :ssl.send(socket, "ticket slot")
          :ok = :ssl.send(socket, "after ticket")
          assert {:ok, "client response"} = :ssl.recv(socket, 15, 5_000)
          :ok = :ssl.send(socket, "done")
          assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        end)

      {proxy_port, proxy, listener} = replacing_proxy(peer.port)

      on_exit(fn ->
        :gen_tcp.close(listener)
        Process.exit(proxy.pid, :kill)
      end)

      assert {:ok, socket} = SSL.connect(~c"127.0.0.1", proxy_port, Peer.client_options(), 5_000)
      assert {:ok, "ready"} = SSL.recv(socket, 5, 5_000)
      {:connected, state} = :sys.get_state(socket.pid)

      {:ok, replacement, _} =
        SSL.Protocol.Record.encrypt(state.machine.read_state, :handshake, unquote(ticket))

      send(proxy.pid, {:replace, replacement, self()})
      assert_receive :replacement_armed
      send(peer.task.pid, :send_ticket_slot)
      assert {:ok, "after ticket"} = SSL.recv(socket, 12, 5_000)
      assert :ok = SSL.send(socket, "client response")
      assert {:ok, "done"} = SSL.recv(socket, 4, 5_000)
      assert :ok = SSL.close(socket)
      Peer.stop(peer)
      assert :ok = Task.await(proxy, 5_000)
    end
  end

  test "partial receive timeout preserves plaintext and a later receive succeeds" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        :ok = :ssl.send(socket, "abc")
        send(parent, :first_sent)

        receive do
          :continue -> :ok
        end

        :ok = :ssl.send(socket, "def")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    assert_receive :first_sent
    assert {:error, :timeout} = SSL.recv(socket, 6, 25)
    assert {:error, :timeout} = SSL.recv(socket, 6, 0)
    send(peer.task.pid, :continue)
    assert {:ok, "abcdef"} = SSL.recv(socket, 6, 1_000)
    assert :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "zero and positive lengths preserve unconsumed bytes across records" do
    {:ok, peer} =
      Peer.start(fn socket ->
        :ok = :ssl.send(socket, "abcdef")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    assert {:ok, "ab"} = SSL.recv(socket, 2)
    assert {:ok, "cdef"} = SSL.recv(socket, 0, 0)
    assert {:error, :timeout} = SSL.recv(socket, 0, 0)
    :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "maximum-length receive drains a crossing TLS record and preserves its surplus" do
    prefix = :binary.copy("a", 7)
    remainder = :binary.copy("b", 1_048_576 - byte_size(prefix))
    expected = prefix <> remainder
    surplus = "surplus-after-limit"

    {:ok, peer} =
      Peer.start(fn socket ->
        :ok = :ssl.send(socket, prefix)
        :ok = :ssl.send(socket, remainder <> surplus)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    assert {:ok, ^expected} = SSL.recv(socket, 1_048_576, 5_000)
    assert {:ok, ^surplus} = SSL.recv(socket, byte_size(surplus), 5_000)
    assert :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "dead receiver is cancelled and does not consume subsequent data" do
    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :continue -> :ok
        end

        :ok = :ssl.send(socket, "after-cancel")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    receiver = spawn(fn -> SSL.recv(socket, 0, :infinity) end)
    wait_for_receiver(socket)
    ref = Process.monitor(receiver)
    Process.exit(receiver, :kill)
    assert_receive {:DOWN, ^ref, :process, ^receiver, :killed}
    send(peer.task.pid, :continue)
    assert {:ok, "after-cancel"} = retry_recv(socket)
    :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "owner death terminates temporary connection and closes the peer" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    parent = self()

    owner =
      spawn(fn ->
        socket = connect(peer)
        send(parent, {:connected, socket})

        receive do
          :finish -> :ok
        end
      end)

    assert_receive {:connected, socket}, 5_000
    ref = Process.monitor(socket.pid)
    send(owner, :finish)
    assert_receive {:DOWN, ^ref, :process, _, :normal}
    assert {:error, :closed} = SSL.send(socket, "no replay")

    refute Enum.any?(DynamicSupervisor.which_children(SSL.ConnectionSupervisor), fn {_, pid, _, _} ->
             pid == socket.pid
           end)

    Peer.stop(peer)
  end

  test "concurrent close wakes receiver and already closed operations remain safe" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    receiver = Task.async(fn -> SSL.recv(socket, 5, :infinity) end)
    wait_for_receiver(socket)
    tasks = for _ <- 1..4, do: Task.async(fn -> SSL.close(socket) end)
    assert Enum.all?(tasks, &(Task.await(&1) == :ok))
    assert {:error, :closed} = Task.await(receiver)
    assert {:error, :closed} = SSL.recv(socket, 0, 0)
    assert {:error, :closed} = SSL.send(socket, [])
    assert {:error, :closed} = SSL.setopts(socket, active: :once)
    assert {:error, :closed} = SSL.controlling_process(socket, self())
    assert {:error, :closed} = SSL.negotiated_protocol(socket)
    assert {:error, :badarg} = SSL.setopts(:not_a_socket, active: false)
    assert {:error, :badarg} = SSL.controlling_process(:not_a_socket, self())
    assert {:error, :badarg} = SSL.negotiated_protocol(:not_a_socket)
    Peer.stop(peer)
  end

  test "receive limits and malformed calls do not send or consume application data" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:ok, "valid"} = :ssl.recv(socket, 5, 5_000)
        :ok = :ssl.send(socket, "response")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)

    end_time =
      :erlang.system_info(:end_time)
      |> :erlang.convert_time_unit(:native, :millisecond)

    unrepresentable_timeout = end_time - System.monotonic_time(:millisecond) + 1_000

    assert {:error, :badarg} = SSL.send(socket, [:invalid])
    assert {:error, :badarg} = SSL.recv(socket, -1, 0)
    assert {:error, :badarg} = SSL.recv(socket, 0, -1)
    assert {:error, :badarg} = SSL.recv(socket, 0, unrepresentable_timeout)
    assert Process.alive?(socket.pid)
    assert {:error, :emsgsize} = SSL.recv(socket, 1_048_577, 0)
    assert :ok = SSL.send(socket, "valid")
    assert {:ok, "response"} = SSL.recv(socket, 0, 1_000)
    :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "status and inspection exclude buffered application bytes and traffic keys" do
    {:ok, peer} =
      Peer.start(fn socket ->
        :ok = :ssl.send(socket, "password-unique-secret")
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    assert {:error, :timeout} = SSL.recv(socket, 100, 25)
    status = inspect(:sys.get_status(socket.pid), limit: :infinity)
    refute status =~ "password-unique-secret"
    refute status =~ "write_state"
    refute status =~ "read_state"
    refute inspect(socket) =~ "secret"
    :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "failed handshake times out and leaves no connection process or raw socket" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 1_000)
        assert {:ok, _hello} = :gen_tcp.recv(tcp, 0, 1_000)
        assert {:error, :closed} = :gen_tcp.recv(tcp, 0, 1_000)
      end)

    before = DynamicSupervisor.count_children(SSL.ConnectionSupervisor).active
    assert {:error, :timeout} = SSL.connect(~c"127.0.0.1", port, Peer.client_options(), 50)
    Task.await(task)
    assert DynamicSupervisor.count_children(SSL.ConnectionSupervisor).active == before
    :gen_tcp.close(listener)
  end

  test "unrepresentable connect timeout fails before opening a TCP connection" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    existing = connection_children()

    end_time =
      :erlang.system_info(:end_time)
      |> :erlang.convert_time_unit(:native, :millisecond)

    unrepresentable_timeout = end_time - System.monotonic_time(:millisecond) + 1_000

    assert {:error, :badarg} =
             SSL.connect(~c"127.0.0.1", port, Peer.client_options(), unrepresentable_timeout)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
    assert connection_children() == existing
    :gen_tcp.close(listener)
  end

  test "caller death during a pending handshake closes the raw socket and temporary child" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    server =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 1_000)
        assert {:ok, _hello} = :gen_tcp.recv(tcp, 0, 1_000)
        send(parent, :pending_handshake_observed)
        await_tcp_closed(tcp)
      end)

    existing = connection_children()
    caller = spawn(fn -> SSL.connect(~c"127.0.0.1", port, Peer.client_options(), 5_000) end)
    caller_monitor = Process.monitor(caller)
    assert_receive :pending_handshake_observed, 1_000

    assert [connection] = Enum.reject(connection_children(), &MapSet.member?(existing, &1))
    connection_monitor = Process.monitor(connection)
    Process.exit(caller, :kill)

    assert_receive {:DOWN, ^caller_monitor, :process, ^caller, :killed}
    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, :normal}
    assert :closed = Task.await(server)
    refute connection in connection_children()
    :gen_tcp.close(listener)
  end

  test "application stop cleans up an established connection and pending receive without replay" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer)
    receiver = Task.async(fn -> SSL.recv(socket, 0, :infinity) end)
    wait_for_receiver(socket)
    connection_monitor = Process.monitor(socket.pid)

    on_exit(fn ->
      {:ok, _applications} = Application.ensure_all_started(:ex_ssl)
    end)

    assert :ok = Application.stop(:ex_ssl)
    assert {:error, :econnreset} = Task.await(receiver)
    assert_receive {:DOWN, ^connection_monitor, :process, _, _reason}
    refute Process.whereis(SSL.ConnectionSupervisor)
    assert {:error, :econnreset} = SSL.send(socket, "must-not-replay")
    assert :ok = Peer.stop(peer)
  end

  test "upgrade rejects delivered plaintext without removing its message and closes owned TCP" do
    {tcp, server, listener} = raw_pair()
    send(self(), {:tcp, tcp, "leftover application plaintext"})
    assert {:error, :pending_plaintext} = SSL.connect(tcp, Peer.client_options(), 1_000)
    assert_receive {:tcp, ^tcp, "leftover application plaintext"}
    assert {:error, :closed} = :gen_tcp.recv(server, 0, 1_000)
    :gen_tcp.close(server)
    :gen_tcp.close(listener)
  end

  test "upgrade validates ownership and never closes another process's socket" do
    {tcp, server, listener} = raw_pair()
    task = Task.async(fn -> SSL.connect(tcp, Peer.client_options(), 1_000) end)
    assert {:error, :not_owner} = Task.await(task)
    assert :ok = :gen_tcp.send(tcp, "still owned")
    assert {:ok, "still owned"} = :gen_tcp.recv(server, 0, 1_000)
    :gen_tcp.close(tcp)
    :gen_tcp.close(server)
    :gen_tcp.close(listener)
  end

  test "invalid options before upgrade close owned TCP and prevent plaintext resumption" do
    {tcp, server, listener} = raw_pair()
    assert {:error, {:options, _}} = SSL.connect(tcp, active: true)
    assert {:error, :closed} = :gen_tcp.recv(server, 0, 1_000)
    :gen_tcp.close(server)
    :gen_tcp.close(listener)
  end

  test "upgrade handshake timeout closes the owned raw TCP socket" do
    {tcp, server, listener} = raw_pair()
    existing = connection_children()

    assert {:error, :timeout} = SSL.connect(tcp, Peer.client_options(), 50)
    assert {:ok, _client_hello} = :gen_tcp.recv(server, 0, 1_000)
    assert {:error, :closed} = :gen_tcp.recv(server, 0, 1_000)
    assert {:error, :closed} = :gen_tcp.send(tcp, "plaintext-must-not-resume")
    assert connection_children() == existing

    :gen_tcp.close(server)
    :gen_tcp.close(listener)
  end

  test "fragment arrival never extends the receive deadline or creates stale replies" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        for _ <- 1..10 do
          :ok = :ssl.send(socket, "a")
          Process.sleep(15)
        end

        send(parent, :all_fragments_sent)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    started = System.monotonic_time(:millisecond)
    assert {:error, :timeout} = SSL.recv(socket, 10, 45)
    assert System.monotonic_time(:millisecond) - started < 130
    assert_receive :all_fragments_sent, 1_000
    assert {:ok, "aaaaaaaaaa"} = SSL.recv(socket, 10, 1_000)
    refute_receive {_reference, {:ok, _bytes}}, 20
    :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "an expired pending receive cannot consume data queued ahead of its timer" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :continue -> :ok
        end

        :ok = :ssl.send(socket, "after-deadline")
        send(parent, :data_queued)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    receiver = Task.async(fn -> SSL.recv(socket, 14, 100) end)
    wait_for_receiver(socket)
    :ok = :sys.suspend(socket.pid)
    send(peer.task.pid, :continue)
    assert_receive :data_queued
    Process.sleep(120)
    :ok = :sys.resume(socket.pid)
    assert {:error, :timeout} = Task.await(receiver)
    assert {:ok, "after-deadline"} = SSL.recv(socket, 14, 1_000)
    :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "near-limit overflow preserves state after expiring a pending receive" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do
          :send_crossing_record -> :ok
        end

        :ok = :ssl.send(socket, "xy")
        send(parent, :crossing_record_sent)
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    socket = connect(peer)
    near_limit = :binary.copy("p", 1_048_575)

    :sys.replace_state(socket.pid, fn {:connected, state} ->
      {:connected,
       %{state | buffer: :queue.in(near_limit, state.buffer), size: byte_size(near_limit)}}
    end)

    receiver =
      spawn(fn ->
        send(parent, {:near_limit_recv, SSL.recv(socket, 1_048_576, 50)})

        receive do
          message -> send(parent, {:stale_receiver_message, message})
        after
          100 -> send(parent, :receiver_quiet)
        end
      end)

    receiver_monitor = Process.monitor(receiver)
    wait_for_pending_receiver(socket.pid)
    connection_monitor = Process.monitor(socket.pid)

    try do
      :ok = :sys.suspend(socket.pid)
      send(peer.task.pid, :send_crossing_record)
      assert_receive :crossing_record_sent, 1_000
      Process.sleep(75)
    after
      if Process.alive?(socket.pid), do: :sys.resume(socket.pid)
    end

    assert_receive {:near_limit_recv, {:error, :timeout}}, 1_000
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}
    assert_receive :receiver_quiet, 1_000
    refute_receive {:stale_receiver_message, _message}
    assert_receive {:DOWN, ^receiver_monitor, :process, ^receiver, :normal}
    assert {:error, :econnreset} = SSL.recv(socket, 0, 0)
    assert :ok = Peer.stop(peer)
  end

  test "oversized wire record sends a protocol alert and terminates the temporary child" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 1_000)
        assert {:ok, _hello} = :gen_tcp.recv(tcp, 0, 1_000)
        :ok = :gen_tcp.send(tcp, <<23, 3, 3, 65_535::16>>)
        assert {:ok, <<21, 3, 3, 0, 2, 2, 22>>} = :gen_tcp.recv(tcp, 7, 1_000)
        assert {:error, :closed} = :gen_tcp.recv(tcp, 0, 1_000)
      end)

    assert {:error, {:tls_alert, {:record_overflow, _}}} =
             SSL.connect("127.0.0.1", port, Peer.client_options(), 1_000)

    Task.await(task)
    :gen_tcp.close(listener)
  end

  @tag capture_log: true
  test "unexpected connection process death reports an unclean closure after termination" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
      end)

    socket = connect(peer)
    monitor = Process.monitor(socket.pid)
    Process.exit(socket.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, :killed}
    assert {:error, :econnreset} = SSL.recv(socket, 0, 0)
    assert :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  test "abrupt TCP loss wakes a pending receive and remains unclean after process exit" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, proxy} = Peer.start_fragmenting_proxy(peer.port, self())

    try do
      options = Peer.client_options()
      assert {:ok, socket} = SSL.connect(~c"127.0.0.1", proxy.port, options, 5_000)

      receiver = Task.async(fn -> SSL.recv(socket, 0, :infinity) end)
      wait_for_receiver(socket)
      monitor = Process.monitor(socket.pid)

      _ = Peer.stop_fragmenting_proxy(proxy)

      assert {:error, :econnreset} = Task.await(receiver)
      assert_receive {:DOWN, ^monitor, :process, _, :normal}
      assert {:error, :econnreset} = SSL.recv(socket, 0, 0)
      assert {:error, :econnreset} = SSL.send(socket, "must-not-retry")
      assert :ok = SSL.close(socket)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_fragmenting_proxy(proxy)
      assert :ok = Peer.stop(peer)
    end
  end

  test "authenticated close_notify remains distinguishable after connection termination" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert :ok = :ssl.close(socket)
      end)

    socket = connect(peer)
    monitor = Process.monitor(socket.pid)
    assert {:error, :closed} = SSL.recv(socket, 0, 1_000)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}
    assert {:error, :closed} = SSL.recv(socket, 0, 0)
    assert {:error, :closed} = SSL.send(socket, "after-close-notify")
    assert :ok = SSL.close(socket)
    Peer.stop(peer)
  end

  defp connect(peer) do
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, Peer.client_options(), 5_000)
    socket
  end

  defp raw_pair do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false, packet: :raw])
    {:ok, server} = :gen_tcp.accept(listener, 1_000)
    {tcp, server, listener}
  end

  # Fault injection over real TCP after an authenticated OTP handshake. This
  # proxy changes one server record and never implements a TLS handshake.
  defp replacing_proxy(upstream_port) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    proxy =
      Task.async(fn ->
        {:ok, client} = :gen_tcp.accept(listener, 5_000)

        {:ok, server} =
          :gen_tcp.connect(~c"127.0.0.1", upstream_port, [:binary, active: false], 5_000)

        :ok = :inet.setopts(client, active: :once)
        :ok = :inet.setopts(server, active: :once)

        try do
          replacing_proxy_loop(client, server, SSL.Protocol.RecordFramer.new(), nil)
        after
          :gen_tcp.close(client)
          :gen_tcp.close(server)
        end
      end)

    {port, proxy, listener}
  end

  defp replacing_proxy_loop(client, server, framer, replacement) do
    receive do
      {:replace, record, caller} ->
        assert SSL.Protocol.RecordFramer.buffered_size(framer) == 0
        send(caller, :replacement_armed)
        replacing_proxy_loop(client, server, framer, record)

      {:tcp, ^client, bytes} ->
        :ok = :gen_tcp.send(server, bytes)
        :ok = :inet.setopts(client, active: :once)
        replacing_proxy_loop(client, server, framer, replacement)

      {:tcp, ^server, bytes} ->
        {:ok, records, framer} = SSL.Protocol.RecordFramer.feed(framer, bytes)

        {records, replacement} =
          case {records, replacement} do
            {[_original | rest], record} when is_binary(record) -> {[record | rest], nil}
            _ -> {records, replacement}
          end

        :ok = :gen_tcp.send(client, records)
        :ok = :inet.setopts(server, active: :once)
        replacing_proxy_loop(client, server, framer, replacement)

      {:tcp_closed, _socket} ->
        :ok
    after
      5_000 -> flunk("record replacement proxy timed out")
    end
  end

  defp connection_children do
    SSL.ConnectionSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.map(fn {_, pid, _, _} -> pid end)
    |> MapSet.new()
  end

  defp await_tcp_closed(tcp) do
    case :gen_tcp.recv(tcp, 0, 1_000) do
      {:ok, _bytes} -> await_tcp_closed(tcp)
      {:error, :closed} -> :closed
      {:error, reason} -> {:error, reason}
    end
  end

  defp wait_for_receiver(socket, attempts \\ 100)
  defp wait_for_receiver(_socket, 0), do: flunk("receiver did not become pending")

  defp wait_for_receiver(socket, attempts) do
    case SSL.recv(socket, 0, 0) do
      {:error, :einval} ->
        :ok

      {:error, :timeout} ->
        Process.sleep(1)
        wait_for_receiver(socket, attempts - 1)
    end
  end

  defp wait_for_pending_receiver(pid, attempts \\ 100)
  defp wait_for_pending_receiver(_pid, 0), do: flunk("receiver did not become pending")

  defp wait_for_pending_receiver(pid, attempts) do
    case :sys.get_state(pid) do
      {:connected, %{recv: nil}} ->
        Process.sleep(1)
        wait_for_pending_receiver(pid, attempts - 1)

      {:connected, %{recv: %{} = _receiver}} ->
        :ok
    end
  end

  defp retry_recv(socket, attempts \\ 100)
  defp retry_recv(_socket, 0), do: flunk("dead receiver was not removed")

  defp retry_recv(socket, attempts) do
    case SSL.recv(socket, 0, 1_000) do
      {:error, :einval} ->
        Process.sleep(1)
        retry_recv(socket, attempts - 1)

      result ->
        result
    end
  end
end

defmodule SSL.Lifecycle.SetupTLSFailureTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.{Options, Socket}
  alias SSL.Lifecycle.{Observer, Reader, Receipt, Setup}
  @moduletag :integration

  for original <- [5_000, :infinity] do
    test "real wrong-SNI failure after native E retains TLS classification and alert with #{original}" do
      {:ok, peer} = Peer.start(fn socket -> :ssl.close(socket) end)

      try do
        with_gate(peer, fn proxy ->
          a =
            attempt(
              proxy.port,
              unquote(original),
              [server_name_indication: ~c"wrong.example.test"],
              500
            )

          assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
          ref = proxy.ref
          assert_receive {:tls_record_proxy, ^ref, :queued, _}, 1_000
          wait_until(elem(a.control, 1) + 20)
          alive(a)
          assert Process.alive?(a.setup)
          for _ <- 1..32, do: Peer.release_server_record(proxy)
          failed_tls(a)

          assert {:handshake_error, {:tls_alert, {:certificate_unknown, _}}} =
                   Task.await(peer.task, 5_000)
        end)
      after
        stop_peer(peer)
      end
    end
  end

  test "record ACK closes admission without killing actors and original infinity is forced finite" do
    a = enrolled_attempt() |> committed()
    allocator = a.allocator
    mon = Process.monitor(allocator)
    assert :ok = in_actor(allocator, fn -> Observer.helper_done(a.receipt, deadline()) end)
    send(allocator, :stop)
    assert_receive {:DOWN, ^mon, :process, ^allocator, :normal}, 1_000
    connection = a.connection
    connection_monitor = Process.monitor(connection)
    p = deadline(800)
    assert :ok = in_actor(a.connection, fn -> Observer.record_tls_failure(a.receipt, p) end)
    model_alive(a)

    assert {:ok, %{setup: :failed, setup_failure: :tls, admission: :closed}} =
             Observer.snapshot(a.receipt, deadline())

    assert :unsealed = Receipt.read(a.receipt)
    wait_until(elem(p, 1) - 300)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.record_tls_failure(a.receipt, deadline(1_000))
             end)

    wait_until(elem(p, 1) + 20)
    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, _}, 150
    model_down(a, :tls)
  end

  test "a queued report rejects an already dead unfinished allocator" do
    a = enrolled_attempt() |> committed()
    allocator = a.allocator
    monitor = Process.monitor(allocator)
    assert :ok = :sys.suspend(a.observer)

    try do
      p = deadline(1_000)
      {:abs_ms, r} = deadline(250)

      _ =
        in_actor(a.connection, fn ->
          :gen_server.send_request(a.observer, {{:record_tls_failure, p}, {:abs_ms, r}})
        end)

      # Public metadata only: the call is queued before the allocator DOWN.
      assert {:message_queue_len, 1} = Process.info(a.observer, :message_queue_len)
      send(allocator, :stop)
      assert_receive {:DOWN, ^monitor, :process, ^allocator, :normal}, 1_000
      assert System.monotonic_time(:millisecond) < r
    after
      :sys.resume(a.observer)
    end

    model_down(a, :internal)
  end

  test "the original Root lease cancels an ACKed failure immediately" do
    a = enrolled_attempt() |> committed()

    assert :ok =
             in_actor(a.connection, fn ->
               Observer.record_tls_failure(a.receipt, deadline(1_000))
             end)

    model_alive(a)
    connection = a.connection
    connection_monitor = Process.monitor(connection)
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, _}, 250
    model_down(a, :tls)
  end

  test "only the committed original Connection with its original TCP owner can record" do
    a = enrolled_attempt()

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.record_tls_failure(a.receipt, deadline(1_000))
             end)

    {a, grant} = prepared(a)
    assert Port.info(a.tcp, :connected) == {:connected, a.connection}

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.record_tls_failure(a.receipt, deadline(1_000))
             end)

    assert :ok =
             in_actor(a.connection, fn ->
               Observer.commit_handoff(a.receipt, grant, deadline())
             end)

    assert {:error, _} = Observer.record_tls_failure(a.receipt, deadline(1_000))

    for actor <- [a.setup, a.writer, a.allocator] do
      assert {:error, _} =
               in_actor(actor, fn -> Observer.record_tls_failure(a.receipt, deadline(1_000)) end)
    end

    assert {:error, :deadline_exceeded} =
             in_actor(a.connection, fn ->
               Observer.record_tls_failure(a.receipt, deadline(200))
             end)

    assert :ok = in_actor(a.connection, fn -> :gen_tcp.controlling_process(a.tcp, a.setup) end)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.record_tls_failure(a.receipt, deadline(1_000))
             end)

    assert :ok = in_actor(a.setup, fn -> :gen_tcp.controlling_process(a.tcp, a.connection) end)
    assert {:ok, %{setup: :pending, admission: :open}} = Observer.snapshot(a.receipt, deadline())
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    model_down(a, :cancelled)
  end

  test "an acknowledged connected outcome cannot be downgraded by a Connection report" do
    a = enrolled_attempt() |> committed()

    assert :ok =
             in_actor(a.setup, fn -> Observer.publish_setup(a.receipt, :connected, deadline()) end)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.record_tls_failure(a.receipt, deadline(1_000))
             end)

    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    model_down(a, :none)
  end

  test "unknown recording while the own Observer is suspended still sends the original TLS alert" do
    {:ok, peer} = Peer.start(fn socket -> :ssl.close(socket) end)

    try do
      a = attempt(peer.port, :infinity, server_name_indication: ~c"wrong.example.test")
      assert :ok = :sys.suspend(a.observer)

      try do
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))

        assert {:handshake_error, {:tls_alert, {:certificate_unknown, _}}} =
                 Task.await(peer.task, 1_000)

        tcp = a.tcp
        mon = a.tcp_monitor
        assert_receive {:DOWN, ^mon, :port, ^tcp, _}, 1_000
        refute_receive {:lifecycle_tls_ready, _, _, _, _}, 0
        assert :unsealed = Receipt.read(a.receipt)
      after
        :sys.resume(a.observer)
      end

      assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup_failure: :internal}} =
               Reader.await(a.receipt, deadline())
    after
      stop_peer(peer)
    end
  end

  defp attempt(port, original_ms, overrides, control_ms \\ 1_500) do
    options = Peer.client_options() |> Enum.reject(&(&1 == :binary)) |> Keyword.merge(overrides)
    {:ok, options} = Options.normalize("exssl.test", options)
    original = if original_ms == :infinity, do: :infinity, else: elem(deadline(original_ms), 1)
    observer_d = if original == :infinity, do: :infinity, else: {:abs_ms, original}
    {:ok, receipt, lease} = Observer.start(self(), observer_d)
    observer = Receipt.observer(receipt)
    on_exit(fn -> Process.exit(observer, :kill) end)
    bootstrap = deadline(1_000)
    :ok = Observer.bind(receipt, lease, bootstrap)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :setup, bootstrap)
    {:ok, allocator_permit} = Observer.reserve_root(receipt, lease, :allocator, bootstrap)
    nonce = make_ref()
    classic = {self(), make_ref(), :atomics.new(1, []), options, original}
    requested = elem(deadline(control_ms), 1)
    control = {:abs_ms, if(original == :infinity, do: requested, else: min(requested, original))}

    context = %{
      receipt: receipt,
      permit: permit,
      allocator_permit: allocator_permit,
      endpoint: {{127, 0, 0, 1}, port},
      classic: classic,
      control_deadline: control,
      ready: {self(), nonce}
    }

    {:ok, setup} = Setup.start(context)
    monitor = Process.monitor(setup)
    on_exit(fn -> Process.exit(setup, :kill) end)

    assert_receive {:lifecycle_native_owned, ^setup, ^nonce, ^observer, %Socket{} = socket, tcp},
                   1_000

    tcp_monitor = :erlang.monitor(:port, tcp)
    {:monitors, monitors} = Process.info(socket.pid, :monitors)
    owner = self()
    [writer] = for {:process, pid} <- monitors, pid not in [owner, observer], do: pid

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      setup: setup,
      nonce: nonce,
      socket: socket,
      tcp: tcp,
      tcp_monitor: tcp_monitor,
      writer: writer,
      classic: classic,
      control: control,
      monitor: monitor
    }
  end

  # Cooperative protocol actors below are NOT actual TLS engine actors.
  defp enrolled_attempt do
    enrollment_deadline = deadline(5_000)
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    observer = Receipt.observer(receipt)
    on_exit(fn -> if Process.alive?(observer), do: Process.exit(observer, :kill) end)
    assert :ok = Observer.bind(receipt, lease, enrollment_deadline)

    {:ok, allocator_permit} =
      Observer.reserve_root(receipt, lease, :allocator, enrollment_deadline)

    {:ok, setup_permit} = Observer.reserve_root(receipt, lease, :setup, enrollment_deadline)
    allocator = enrolled_actor(receipt, :allocator, allocator_permit, enrollment_deadline)
    setup = enrolled_actor(receipt, :setup, setup_permit, enrollment_deadline)

    {:ok, connection_permit} =
      in_actor(setup, fn -> Observer.reserve_child(receipt, :connection, enrollment_deadline) end)

    connection = enrolled_actor(receipt, :connection, connection_permit, enrollment_deadline)

    {:ok, writer_permit} =
      in_actor(connection, fn -> Observer.reserve_child(receipt, :writer, enrollment_deadline) end)

    writer = enrolled_actor(receipt, :writer, writer_permit, enrollment_deadline)

    {:ok, tcp_permit} =
      in_actor(allocator, fn -> Observer.reserve_child(receipt, :tcp, enrollment_deadline) end)

    # Listener and peer are test fixtures outside the attempt's resource set.
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :raw, ip: {127, 0, 0, 1}])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port_number}} = :inet.sockname(listener)

    {:ok, tcp} =
      in_actor(allocator, fn ->
        :gen_tcp.connect(
          {127, 0, 0, 1},
          port_number,
          [:binary, active: false, packet: :raw],
          SSL.Options.remaining(elem(enrollment_deadline, 1))
        )
      end)

    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    tcp_monitor = :erlang.monitor(:port, tcp)
    assert Port.info(tcp, :connected) == {:connected, allocator}

    assert :use =
             in_actor(allocator, fn ->
               Observer.enroll_port(receipt, tcp_permit, tcp, enrollment_deadline)
             end)

    assert {:ok, %{roles: 31, allocations: 0, losses: 0, admission: :open}} =
             Observer.snapshot(receipt, enrollment_deadline)

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer,
      tcp: tcp,
      peer: peer,
      tcp_monitor: tcp_monitor
    }
  end

  defp enrolled_actor(receipt, role, permit, budget) do
    pid = spawn(fn -> actor_loop() end)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    assert :use = in_actor(pid, fn -> Observer.enroll_self(receipt, role, permit, budget) end)
    pid
  end

  defp actor_loop do
    receive do
      :stop ->
        :ok

      {:run, caller, token, function} ->
        result =
          try do
            {:returned, function.()}
          catch
            kind, reason -> {:raised, kind, reason, __STACKTRACE__}
          end

        send(caller, {token, result})
        actor_loop()
    end
  end

  defp in_actor(pid, function) do
    token = make_ref()
    send(pid, {:run, self(), token, function})

    receive do
      {^token, {:returned, result}} -> result
      {^token, {:raised, kind, reason, stacktrace}} -> :erlang.raise(kind, reason, stacktrace)
    after
      1_500 -> flunk("enrolled actor did not finish its bounded operation")
    end
  end

  defp committed(a) do
    {a, grant} = prepared(a)
    :ok = in_actor(a.connection, fn -> Observer.commit_handoff(a.receipt, grant, deadline()) end)
    a
  end

  defp prepared(a) do
    d = deadline()
    {:ok, ready} = in_actor(a.writer, fn -> Observer.writer_ready(a.receipt, d) end)
    :ok = in_actor(a.connection, fn -> Observer.connection_ready(a.receipt, ready, d) end)

    {:ok, grant} =
      in_actor(a.allocator, fn -> Observer.prepare_handoff(a.receipt, a.tcp, a.connection, d) end)

    :ok = in_actor(a.allocator, fn -> :gen_tcp.controlling_process(a.tcp, a.connection) end)
    {a, grant}
  end

  defp failed_tls(a) do
    setup = a.setup
    refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0

    assert {:ok,
            %{
              roles: 31,
              observed_down: 31,
              cleanup: :confirmed,
              setup: :failed,
              setup_failure: :tls
            }} = Reader.await(a.receipt, deadline(2_000))

    refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
  end

  defp model_alive(a) do
    for pid <- [a.setup, a.connection, a.writer], do: assert(Process.alive?(pid))
    assert Port.info(a.tcp, :connected) == {:connected, a.connection}
  end

  defp model_down(a, failure) do
    tcp = a.tcp
    mon = a.tcp_monitor
    assert_receive {:DOWN, ^mon, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup_failure: ^failure}} =
             Reader.await(a.receipt, deadline())
  end

  defp alive(a) do
    assert Process.alive?(a.socket.pid) and Process.alive?(a.writer)
    assert Port.info(a.tcp, :connected) == {:connected, a.socket.pid}
  end

  defp stop_peer(peer) do
    :ssl.close(peer.listener)
    if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, 1_000)
  end

  defp with_gate(peer, fun) do
    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self(), initially_gated: true)

    try do
      fun.(proxy)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
    end
  end

  defp wait_until(absolute) do
    timer = :erlang.start_timer(absolute, self(), :boundary, abs: true)
    assert_receive {:timeout, ^timer, :boundary}, 6_000
  end

  defp deadline(ms \\ 2_000), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

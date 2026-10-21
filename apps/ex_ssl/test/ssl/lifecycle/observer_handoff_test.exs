defmodule SSL.Lifecycle.ObserverHandoffTest do
  use ExUnit.Case, async: false

  alias SSL.Lifecycle.{Observer, Reader, Receipt}

  test "cooperatively ready actors commit an enrolled real TCP port after ownership transfer" do
    %{
      receipt: receipt,
      lease: lease,
      allocator: allocator,
      connection: connection,
      writer: writer,
      tcp: tcp,
      peer: peer,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    # This finite private handoff budget does not replace the infinite setup budget.
    handoff_deadline = deadline()

    assert {:ok, ready_nonce} =
             in_actor(writer, fn ->
               Observer.writer_ready(receipt, handoff_deadline)
             end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, handoff_deadline)
             end)

    assert {:ok, grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, handoff_deadline)
             end)

    assert Port.info(tcp, :connected) == {:connected, allocator}
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert :ok =
             in_actor(connection, fn ->
               Observer.commit_handoff(receipt, grant_nonce, handoff_deadline)
             end)

    # No SSL.Connection attach, TLS handshake or setup-success claim occurs here.
    assert Port.info(tcp, :connected) == {:connected, connection}
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: :cancelled}} =
             Reader.await(receipt, deadline())
  end

  test "handoff succeeds only for recorded caller, native owner and unspent grant" do
    %{
      receipt: receipt,
      lease: lease,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer,
      tcp: tcp,
      peer: peer,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    budget = deadline()

    assert {:error, :unauthorized_handoff_caller} =
             in_actor(setup, fn -> Observer.writer_ready(receipt, budget) end)

    assert {:error, :unauthorized_handoff_caller} =
             in_actor(connection, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:error, :foreign_handoff_resource} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, peer, connection, budget)
             end)

    assert {:error, :foreign_handoff_resource} =
             in_actor(allocator, fn -> Observer.prepare_handoff(receipt, tcp, setup, budget) end)

    assert Port.info(peer, :connected) == {:connected, self()}
    assert Port.info(tcp, :connected) == {:connected, allocator}

    assert {:ok, grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert {:error, :handoff_not_ready} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert {:error, :port_not_owned} =
             in_actor(connection, fn -> Observer.commit_handoff(receipt, grant_nonce, budget) end)

    assert {:error, :unauthorized_handoff_caller} =
             in_actor(setup, fn -> Observer.commit_handoff(receipt, grant_nonce, budget) end)

    assert Port.info(tcp, :connected) == {:connected, allocator}
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert {:error, :invalid_handoff_grant} =
             in_actor(connection, fn -> Observer.commit_handoff(receipt, make_ref(), budget) end)

    assert :ok =
             in_actor(connection, fn -> Observer.commit_handoff(receipt, grant_nonce, budget) end)

    assert {:error, :invalid_handoff_grant} =
             in_actor(connection, fn -> Observer.commit_handoff(receipt, grant_nonce, budget) end)

    assert {:error, :handoff_not_idle} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert Port.info(tcp, :connected) == {:connected, connection}
    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: :cancelled}} =
             Reader.await(receipt, deadline())
  end

  test "first readiness deadline retires pending handoff despite later budgets and remint attempts" do
    %{
      receipt: receipt,
      allocator: allocator,
      connection: connection,
      writer: writer,
      tcp: tcp,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    {:abs_ms, original_expiry} = first_budget = deadline(500)

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, first_budget) end)

    {:abs_ms, later_expiry} = later_budget = deadline(3_000)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, later_budget)
             end)

    assert {:ok, _grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, later_budget)
             end)

    assert {:error, :handoff_not_idle} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, later_budget) end)

    assert {:error, :handoff_pending} =
             in_actor(allocator, fn -> Observer.helper_done(receipt, later_budget) end)

    assert Port.info(tcp, :connected) == {:connected, allocator}

    # Await exact native absence at the original deadline, not the later RPC budget.
    remaining = max(1, original_expiry + 1_000 - System.monotonic_time(:millisecond))
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, remaining
    assert System.monotonic_time(:millisecond) < later_expiry

    assert {:ok,
            %{
              roles: 31,
              observed_down: 31,
              cleanup: :confirmed,
              setup: :cancelled,
              setup_failure: :timeout
            }} = Reader.await(receipt, deadline())
  end

  test "committed handoff outlives its private deadline and permits normal allocator completion" do
    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      allocator: allocator,
      connection: connection,
      writer: writer,
      tcp: tcp,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    allocator_monitor = Process.monitor(allocator)
    {:abs_ms, original_expiry} = budget = deadline(500)

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:ok, grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)

    assert :ok =
             in_actor(connection, fn -> Observer.commit_handoff(receipt, grant_nonce, budget) end)

    # Our own elapsed-time fence does not inspect or inject the Observer timer.
    timer =
      :erlang.start_timer(
        max(1, original_expiry + 100 - System.monotonic_time(:millisecond)),
        self(),
        :past_private_deadline
      )

    assert_receive {:timeout, ^timer, :past_private_deadline}, 1_000
    assert System.monotonic_time(:millisecond) > original_expiry
    assert Process.alive?(observer)
    assert Process.alive?(connection)
    assert Process.alive?(writer)
    assert Port.info(tcp, :connected) == {:connected, connection}
    later_budget = deadline()

    assert {:ok, %{admission: :open, roles: 31, observed_down: 0, setup: :pending}} =
             Observer.snapshot(receipt, later_budget)

    assert {:error, :invalid_handoff_grant} =
             in_actor(connection, fn ->
               Observer.commit_handoff(receipt, grant_nonce, later_budget)
             end)

    assert {:error, :handoff_not_idle} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, later_budget) end)

    assert :ok = in_actor(allocator, fn -> Observer.helper_done(receipt, later_budget) end)
    send(allocator, :stop)
    assert_receive {:DOWN, ^allocator_monitor, :process, ^allocator, :normal}, 1_000

    assert %{admission: :open, roles: 31, observed_down: 1, setup: :pending} =
             await_down_mask(receipt, 1, deadline())

    assert Port.info(tcp, :connected) == {:connected, connection}
    assert Process.alive?(connection)
    assert Process.alive?(writer)

    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: :cancelled}} =
             Reader.await(receipt, deadline())
  end

  test "lost commit acknowledgment is unknown and the original queued grant remains consumed" do
    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      allocator: allocator,
      connection: connection,
      writer: writer,
      tcp: tcp,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    {:abs_ms, expiry} = budget = deadline(5_000)

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:ok, grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert :ok = :sys.suspend(observer, 1_000)

    try do
      assert {:error, :acceptance_unconfirmed} =
               in_actor(connection, fn ->
                 Observer.commit_handoff(receipt, grant_nonce, budget)
               end)

      assert Process.alive?(connection)
      assert Port.info(tcp, :connected) == {:connected, connection}
      assert System.monotonic_time(:millisecond) < expiry
    after
      assert :ok = :sys.resume(observer, 1_000)
    end

    # Both public commits originate from the same enrolled Connection actor.
    # Sender FIFO puts the queued first commit before this retry after resume.
    later_budget = deadline()

    assert {:error, :invalid_handoff_grant} =
             in_actor(connection, fn ->
               Observer.commit_handoff(receipt, grant_nonce, later_budget)
             end)

    assert {:ok, %{admission: :open, roles: 31, observed_down: 0, setup: :pending}} =
             Observer.snapshot(receipt, later_budget)

    assert Process.alive?(connection)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: :cancelled}} =
             Reader.await(receipt, deadline())
  end

  test "readiness and grants bind original actors and attempts through independent cancellation" do
    a = enrolled_attempt()
    b = enrolled_attempt()
    %{tcp: tcp_a, tcp_monitor: monitor_a} = a
    %{tcp: tcp_b, tcp_monitor: monitor_b} = b
    budget = deadline()

    assert {:error, :handoff_not_ready} =
             in_actor(a.allocator, fn ->
               Observer.prepare_handoff(a.receipt, tcp_a, a.connection, budget)
             end)

    assert {:ok, ready_a} =
             in_actor(a.writer, fn -> Observer.writer_ready(a.receipt, budget) end)

    assert {:ok, ready_b} =
             in_actor(b.writer, fn -> Observer.writer_ready(b.receipt, budget) end)

    assert {:error, :unauthorized_handoff_caller} =
             in_actor(a.setup, fn -> Observer.connection_ready(a.receipt, ready_a, budget) end)

    assert {:error, :invalid_readiness} =
             in_actor(a.connection, fn ->
               Observer.connection_ready(a.receipt, ready_b, budget)
             end)

    assert {:error, :invalid_readiness} =
             in_actor(b.connection, fn ->
               Observer.connection_ready(b.receipt, ready_a, budget)
             end)

    assert :ok =
             in_actor(a.connection, fn ->
               Observer.connection_ready(a.receipt, ready_a, budget)
             end)

    assert :ok =
             in_actor(b.connection, fn ->
               Observer.connection_ready(b.receipt, ready_b, budget)
             end)

    assert {:error, :invalid_readiness} =
             in_actor(a.connection, fn ->
               Observer.connection_ready(a.receipt, ready_a, budget)
             end)

    assert {:error, :invalid_readiness} =
             in_actor(b.connection, fn ->
               Observer.connection_ready(b.receipt, ready_b, budget)
             end)

    assert {:ok, grant_a} =
             in_actor(a.allocator, fn ->
               Observer.prepare_handoff(a.receipt, tcp_a, a.connection, budget)
             end)

    assert {:ok, grant_b} =
             in_actor(b.allocator, fn ->
               Observer.prepare_handoff(b.receipt, tcp_b, b.connection, budget)
             end)

    assert :ok =
             in_actor(a.allocator, fn -> :gen_tcp.controlling_process(tcp_a, a.connection) end)

    assert :ok =
             in_actor(b.allocator, fn -> :gen_tcp.controlling_process(tcp_b, b.connection) end)

    assert Port.info(tcp_a, :connected) == {:connected, a.connection}
    assert Port.info(tcp_b, :connected) == {:connected, b.connection}

    assert {:error, :invalid_handoff_grant} =
             in_actor(a.connection, fn -> Observer.commit_handoff(a.receipt, grant_b, budget) end)

    assert {:error, :invalid_handoff_grant} =
             in_actor(b.connection, fn -> Observer.commit_handoff(b.receipt, grant_a, budget) end)

    assert :ok =
             in_actor(a.connection, fn -> Observer.commit_handoff(a.receipt, grant_a, budget) end)

    assert :ok =
             in_actor(b.connection, fn -> Observer.commit_handoff(b.receipt, grant_b, budget) end)

    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    assert_receive {:DOWN, ^monitor_a, :port, ^tcp_a, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: :cancelled}} =
             Reader.await(a.receipt, deadline())

    assert Process.alive?(b.observer)
    assert Process.alive?(b.connection)
    assert Port.info(tcp_b, :connected) == {:connected, b.connection}

    assert {:ok, %{admission: :open, roles: 31, observed_down: 0, setup: :pending}} =
             Observer.snapshot(b.receipt, deadline())

    assert :ok = Observer.cancel(b.receipt, b.lease, deadline())
    assert_receive {:DOWN, ^monitor_b, :port, ^tcp_b, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: :cancelled}} =
             Reader.await(b.receipt, deadline())
  end

  test "controller cancellation retires a transferred TCP port before handoff commit" do
    %{
      receipt: receipt,
      lease: lease,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer,
      tcp: tcp,
      peer: peer,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    budget = deadline()

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:ok, _grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)
    assert Port.info(tcp, :connected) == {:connected, connection}

    # Ownership has moved, but no commit, TLS I/O or setup-success claim occurs.
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)

    assert {:ok,
            %{
              admission: :open,
              roles: 31,
              observed_down: 0,
              allocations: 0,
              losses: 0,
              setup: :pending
            }} = Observer.snapshot(receipt, budget)

    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000

    assert {:ok,
            %{
              logical: :closed,
              roles: 31,
              observed_down: 31,
              losses: 0,
              cleanup: :confirmed,
              setup: :cancelled,
              setup_failure: :cancelled
            }} =
             Reader.await(receipt, deadline())

    refute Process.alive?(allocator)
    refute Process.alive?(setup)
    refute Process.alive?(connection)
    refute Process.alive?(writer)
  end

  test "queued original writer DOWN retires a prepared Connection-owned TCP port" do
    %{
      receipt: receipt,
      observer: observer,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer,
      tcp: tcp,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    writer_monitor = Process.monitor(writer)
    {:abs_ms, expiry} = budget = deadline(5_000)

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:ok, _grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert :ok = :sys.suspend(observer, 1_000)

    try do
      assert Process.exit(writer, :kill)
      assert_receive {:DOWN, ^writer_monitor, :process, ^writer, :killed}, 1_000
      refute Process.alive?(writer)
      assert Process.alive?(connection)
      assert Port.info(tcp, :connected) == {:connected, connection}
    after
      assert :ok = :sys.resume(observer, 1_000)
    end

    # Only the resumed Observer consumes its own queued monitor event and retires.
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000
    assert System.monotonic_time(:millisecond) < expiry

    assert {:ok,
            %{
              logical: :closed,
              roles: 31,
              observed_down: 31,
              losses: 0,
              cleanup: :confirmed,
              setup: :failed,
              setup_failure: :internal
            }} =
             Reader.await(receipt, deadline())

    refute Process.alive?(allocator)
    refute Process.alive?(setup)
    refute Process.alive?(connection)
  end

  test "unexpected ownership of the original TCP port rejects commit without consuming its grant" do
    %{
      receipt: receipt,
      lease: lease,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer,
      tcp: tcp,
      peer: peer,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    target = self()
    budget = deadline()

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:ok, grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert :ok = in_actor(connection, fn -> :gen_tcp.controlling_process(tcp, target) end)
    assert Port.info(tcp, :connected) == {:connected, target}

    assert {:error, :port_not_owned} =
             in_actor(connection, fn -> Observer.commit_handoff(receipt, grant_nonce, budget) end)

    assert Port.info(tcp, :connected) == {:connected, target}
    assert Process.alive?(allocator)
    assert Process.alive?(setup)
    assert Process.alive?(connection)
    assert Process.alive?(writer)
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)

    assert {:ok,
            %{
              admission: :open,
              roles: 31,
              observed_down: 0,
              allocations: 0,
              losses: 0,
              setup: :pending
            }} = Observer.snapshot(receipt, budget)

    # Restore the same native port before cancellation; the original grant is intact.
    assert :ok = :gen_tcp.controlling_process(tcp, connection)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert :ok =
             in_actor(connection, fn -> Observer.commit_handoff(receipt, grant_nonce, budget) end)

    assert :ok = Observer.cancel(receipt, lease, deadline())
    assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: :cancelled}} =
             Reader.await(receipt, deadline())
  end

  test "queued original TCP port DOWN retires prepared actors that remained alive after port close" do
    %{
      receipt: receipt,
      observer: observer,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer,
      tcp: tcp,
      tcp_monitor: tcp_monitor
    } = enrolled_attempt()

    {:abs_ms, expiry} = budget = deadline(5_000)

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:ok, _grant_nonce} =
             in_actor(allocator, fn ->
               Observer.prepare_handoff(receipt, tcp, connection, budget)
             end)

    assert :ok = in_actor(allocator, fn -> :gen_tcp.controlling_process(tcp, connection) end)
    assert Port.info(tcp, :connected) == {:connected, connection}

    assert :ok = :sys.suspend(observer, 1_000)

    try do
      assert true == in_actor(connection, fn -> Port.close(tcp) end)
      assert_receive {:DOWN, ^tcp_monitor, :port, ^tcp, _}, 1_000
      assert Port.info(tcp) == nil
      assert Process.alive?(connection)
      assert Process.alive?(writer)
    after
      assert :ok = :sys.resume(observer, 1_000)
    end

    # Native VM port absence was observed independently before actor retirement.
    assert {:ok,
            %{
              logical: :closed,
              roles: 31,
              observed_down: 31,
              losses: 0,
              cleanup: :confirmed,
              setup: :failed,
              setup_failure: :internal
            }} =
             Reader.await(receipt, deadline())

    assert System.monotonic_time(:millisecond) < expiry
    refute Process.alive?(allocator)
    refute Process.alive?(setup)
    refute Process.alive?(connection)
    refute Process.alive?(writer)
  end

  test "pending readiness retains unknown TCP allocation and loss through fixed cancellation grace" do
    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer
    } = unknown_tcp_attempt()

    observer_monitor = Process.monitor(observer)
    budget = deadline(5_000)

    assert {:ok, ready_nonce} =
             in_actor(writer, fn -> Observer.writer_ready(receipt, budget) end)

    assert :ok =
             in_actor(connection, fn ->
               Observer.connection_ready(receipt, ready_nonce, budget)
             end)

    assert {:ok,
            %{
              admission: :open,
              roles: 15,
              observed_down: 0,
              allocations: 16,
              losses: 0,
              setup: :pending
            }} = Observer.snapshot(receipt, budget)

    started = System.monotonic_time(:millisecond)
    assert :ok = Observer.cancel(receipt, lease, deadline())

    assert %{
             admission: :closed,
             roles: 15,
             observed_down: 15,
             allocations: 16,
             losses: 16,
             setup: :cancelled,
             setup_failure: :cancelled
           } =
             await_down_mask(receipt, 15, deadline())

    refute Process.alive?(allocator)
    refute Process.alive?(setup)
    refute Process.alive?(connection)
    refute Process.alive?(writer)

    # No TCP identity was reported, so actor DOWN cannot settle native allocation.
    assert {:unconfirmed, :observer_unsealed} = Reader.await(receipt, deadline(2_000))
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1_000
    elapsed = System.monotonic_time(:millisecond) - started
    assert elapsed >= 1_000
    assert elapsed < 2_000
  end

  defp unknown_tcp_attempt do
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

    {:ok, _tcp_permit} =
      in_actor(allocator, fn -> Observer.reserve_child(receipt, :tcp, enrollment_deadline) end)

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer
    }
  end

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

  # Our monitor can arrive before the Observer consumes its independent DOWN.
  defp await_down_mask(receipt, mask, {:abs_ms, expiry} = budget) do
    assert System.monotonic_time(:millisecond) < expiry
    assert {:ok, snapshot} = Observer.snapshot(receipt, budget)
    if snapshot.observed_down == mask, do: snapshot, else: await_down_mask(receipt, mask, budget)
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

  defp deadline(offset \\ 2_000), do: {:abs_ms, System.monotonic_time(:millisecond) + offset}
end

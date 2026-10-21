defmodule SSL.InertLifecycleBirthTest do
  use ExUnit.Case, async: false

  alias SSL.{Connection, Options}
  alias SSL.Lifecycle.{Observer, Reader, Receipt}

  test "private Connection init returns before observer enrollment and readiness waits for its writer" do
    budget = deadline(2_000)
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, setup_token} = Observer.reserve_root(receipt, lease, :setup, budget)
    parent = self()
    nonce = make_ref()

    setup =
      spawn(fn ->
        :use = Observer.enroll_self(receipt, :setup, setup_token, budget)
        {:ok, token} = Observer.reserve_child(receipt, :connection, budget)
        send(parent, {:connection_permit, token})

        receive do
          {:lifecycle_ready, connection, ^nonce} ->
            send(parent, {:lifecycle_ready, connection, nonce})

            receive do
              :stop -> :ok
            end
        end
      end)

    observer = Receipt.observer(receipt)

    on_exit(fn ->
      if Process.alive?(observer) do
        :sys.resume(observer)
        Process.exit(observer, :kill)
      end

      if Process.alive?(setup), do: Process.exit(setup, :kill)
    end)

    assert_receive {:connection_permit, token}, 1_000
    :ok = :sys.suspend(observer)
    ref = make_ref()
    classic = {self(), ref, :atomics.new(1, []), %Options{}, :infinity}
    context = %{receipt: receipt, permit: token, control_deadline: budget, ready: {setup, nonce}}

    assert {:ok, connection} =
             DynamicSupervisor.start_child(
               SSL.ConnectionSupervisor,
               {Connection, {:inert, classic, context}}
             )

    connection_monitor = Process.monitor(connection)
    assert Process.alive?(connection)
    {:monitors, monitors} = Process.info(connection, :monitors)
    owner = self()
    assert Enum.all?(monitors, fn {:process, pid} -> pid in [owner, observer] end)
    refute_receive {:lifecycle_ready, ^connection, ^nonce}, 20
    assert :ok = :sys.resume(observer)
    assert_receive {:lifecycle_ready, ^connection, ^nonce}, 1_000

    assert {:ok, %{roles: 14, allocations: 0, observed_down: 0}} =
             Observer.snapshot(receipt, budget)

    assert :ok = Observer.cancel(receipt, lease, budget)
    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, _reason}, 1_000

    assert {:ok, %{cleanup: :confirmed, roles: 14, observed_down: 14}} =
             Reader.await(receipt, budget)
  end

  test "queued and ready legacy attach cannot admit a port or emit native bytes" do
    attempt = attempt()
    {tcp, peer} = socket_pair()
    :ok = :sys.suspend(attempt.observer)
    connection = start_connection(attempt)
    request = :gen_statem.send_request(connection, {attempt.ref, {:attach, tcp}})
    assert :timeout = :gen_statem.wait_response(request, 0)
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)
    assert :ok = :sys.resume(attempt.observer)

    assert {:reply, {:error, :lifecycle_attach_not_implemented}} =
             :gen_statem.wait_response(request, 1_000)

    await_ready(attempt, connection)

    assert {:error, :lifecycle_attach_not_implemented} =
             :gen_statem.call(connection, {attempt.ref, {:attach, tcp}})

    assert {:error, :closed} =
             :gen_statem.call(connection, {attempt.ref, {:send, "not admitted"}})

    assert Port.info(tcp, :connected) == {:connected, self()}
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)

    assert {:ok, %{roles: 14, allocations: 0}} =
             Observer.snapshot(attempt.receipt, attempt.budget)

    cancel(attempt)
  end

  test "missing and replayed Connection permits cannot acquire a writer or alter the genuine attempt" do
    attempt = attempt()
    missing = %{attempt | context: %{attempt.context | permit: make_ref()}}
    rejected = start_connection(missing)
    rejected_monitor = Process.monitor(rejected)
    assert_receive {:DOWN, ^rejected_monitor, :process, ^rejected, _}, 1_000
    assert {:ok, %{roles: 2, allocations: 4}} = Observer.snapshot(attempt.receipt, attempt.budget)
    connection = start_connection(attempt)
    await_ready(attempt, connection)
    replay = start_connection(attempt)
    replay_monitor = Process.monitor(replay)
    assert_receive {:DOWN, ^replay_monitor, :process, ^replay, _}, 1_000
    refute_receive {:lifecycle_ready, ^replay, _}, 20
    assert Process.alive?(connection)

    assert {:ok, %{roles: 14, allocations: 0}} =
             Observer.snapshot(attempt.receipt, attempt.budget)

    cancel(attempt)
  end

  test "the private path requires a finite control deadline independent of infinite setup" do
    attempt = attempt()
    context = %{attempt.context | control_deadline: :infinity}

    assert {:error, :invalid_lifecycle_context} =
             DynamicSupervisor.start_child(
               SSL.ConnectionSupervisor,
               {Connection, {:inert, attempt.classic, context}}
             )

    assert {:ok, %{roles: 2, allocations: 4}} = Observer.snapshot(attempt.receipt, attempt.budget)
    connection = start_connection(attempt)
    await_ready(attempt, connection)
    cancel(attempt)
  end

  test "Observer loss before enrollment stops without a writer or ready acknowledgment" do
    attempt = attempt()
    observer_monitor = Process.monitor(attempt.observer)
    Process.exit(attempt.observer, :kill)
    assert_receive {:DOWN, ^observer_monitor, :process, _, :killed}, 1_000
    connection = start_connection(attempt)
    monitor = Process.monitor(connection)
    assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 1_000
    refute_receive {:lifecycle_ready, ^connection, _}, 20
    assert {:unconfirmed, :observer_unsealed} = Reader.await(attempt.receipt, deadline(100))
  end

  test "both enrolled actors independently stop when their original Observer disappears" do
    attempt = attempt()
    connection = start_connection(attempt)
    await_ready(attempt, connection)
    writer = writer(connection, attempt.observer)
    connection_monitor = Process.monitor(connection)
    writer_monitor = Process.monitor(writer)
    Process.exit(attempt.observer, :kill)
    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, _}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000
    assert {:unconfirmed, :observer_unsealed} = Reader.await(attempt.receipt, deadline(100))
  end

  test "Connection death does not stand in for a suspended writer's exact DOWN" do
    attempt = attempt()
    connection = start_connection(attempt)
    await_ready(attempt, connection)
    writer = writer(connection, attempt.observer)
    connection_monitor = Process.monitor(connection)
    writer_monitor = Process.monitor(writer)
    :ok = :sys.suspend(attempt.observer)
    on_exit(fn -> if Process.alive?(writer), do: Process.exit(writer, :kill) end)
    assert true = :erlang.suspend_process(writer)
    Process.exit(connection, :kill)
    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, :killed}, 1_000
    assert Process.alive?(writer)
    refute_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 20
    assert :ok = :sys.resume(attempt.observer)
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000

    assert {:ok, %{roles: 14, observed_down: 14, cleanup: :confirmed}} =
             Reader.await(attempt.receipt, attempt.budget)
  end

  test "an already-born late Connection enrolls and stops after its setup creator is lost" do
    attempt = attempt()
    setup_monitor = Process.monitor(attempt.setup)
    Process.exit(attempt.setup, :kill)
    assert_receive {:DOWN, ^setup_monitor, :process, _, :killed}, 1_000
    assert %{losses: 4, allocations: 4} = snapshot_until(attempt, fn s -> s.losses == 4 end)
    connection = start_connection(attempt)
    monitor = Process.monitor(connection)
    assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 1_000
    refute_receive {:lifecycle_ready, ^connection, _}, 20
    assert {:unconfirmed, :resource_evidence_lost} = Reader.await(attempt.receipt, attempt.budget)
    assert {:terminal, %{roles: 6, observed_down: 6, losses: 4}} = Reader.status(attempt.receipt)
  end

  test "a queued supervisor start cannot refresh the original finite admission deadline" do
    budget = deadline(120)
    attempt = attempt(budget)
    supervisor = SSL.ConnectionSupervisor
    :ok = :sys.suspend(supervisor)
    on_exit(fn -> :sys.resume(supervisor) end)

    request =
      Task.async(fn ->
        DynamicSupervisor.start_child(
          supervisor,
          {Connection, {:inert, attempt.classic, attempt.context}}
        )
      end)

    {:abs_ms, expiry} = budget

    receive do
    after
      max(0, expiry - System.monotonic_time(:millisecond) + 20) -> :ok
    end

    assert :ok = :sys.resume(supervisor)
    assert {:ok, connection} = Task.await(request, 1_000)
    monitor = Process.monitor(connection)
    assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 1_000
    refute_receive {:lifecycle_ready, ^connection, _}, 20

    assert {:ok, %{roles: 2, allocations: 4, observed_down: 0}} =
             Observer.snapshot(attempt.receipt, deadline(500))

    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, deadline(500))
    assert {:unconfirmed, :observer_unsealed} = Reader.await(attempt.receipt, deadline(1_500))
  end

  test "an enrollment call that runs out of the original budget leaves acceptance unknown" do
    budget = deadline(120)
    attempt = attempt(budget)
    :ok = :sys.suspend(attempt.observer)
    connection = start_connection(attempt)
    monitor = Process.monitor(connection)
    assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 500
    refute_receive {:lifecycle_ready, ^connection, _}, 20
    assert :ok = :sys.resume(attempt.observer)
    assert {:ok, %{roles: 2, allocations: 4}} = Observer.snapshot(attempt.receipt, deadline(500))
    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, deadline(500))
    assert {:unconfirmed, :observer_unsealed} = Reader.await(attempt.receipt, deadline(1_500))
  end

  test "Connection enrollment cannot outlive a shorter original setup deadline while Observer stays suspended" do
    setup_deadline = System.monotonic_time(:millisecond) + 150
    attempt = attempt(deadline(2_500), setup_deadline)
    {tcp, peer} = socket_pair()
    :ok = :sys.suspend(attempt.observer)
    connection = start_connection(attempt)
    monitor = Process.monitor(connection)
    request = :gen_statem.send_request(connection, {attempt.ref, {:attach, tcp}})
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)

    assert_receive {:DOWN, ^monitor, :process, ^connection, _},
                   max(1, setup_deadline - System.monotonic_time(:millisecond) + 250)

    assert {:error, _} = :gen_statem.wait_response(request, 100)
    assert Port.info(tcp, :connected) == {:connected, self()}
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)
    refute_receive {:lifecycle_ready, ^connection, _}, 20
    assert :ok = :sys.resume(attempt.observer)
    assert {:ok, %{roles: 2, allocations: 4}} = Observer.snapshot(attempt.receipt, deadline(500))
    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, deadline(500))
    assert {:unconfirmed, :observer_unsealed} = Reader.await(attempt.receipt, deadline(1_500))
  end

  test "standalone writer enrollment cannot outlive its shorter original setup deadline while Observer stays suspended" do
    setup_deadline = System.monotonic_time(:millisecond) + 150
    attempt = attempt(deadline(2_500))
    {connection, permit} = writer_constructor(attempt)
    {tcp, peer} = socket_pair()
    nonce = make_ref()
    context = %{writer_context(attempt, permit, nonce) | setup_deadline: setup_deadline}
    :ok = :sys.suspend(attempt.observer)
    {writer, monitor} = SSL.ConnectionWriter.start(connection, context)
    on_exit(fn -> if Process.alive?(writer), do: Process.exit(writer, :kill) end)
    send(writer, {:lifecycle_send, nonce, make_ref(), tcp, "not authorized", false})
    send(writer, {:lifecycle_writer_release, connection, nonce, attempt.observer})
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)

    assert_receive {:DOWN, ^monitor, :process, ^writer, _},
                   max(1, setup_deadline - System.monotonic_time(:millisecond) + 250)

    assert Port.info(tcp, :connected) == {:connected, self()}
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)
    assert :ok = :sys.resume(attempt.observer)
    assert {:ok, %{roles: 6, allocations: 8}} = Observer.snapshot(attempt.receipt, deadline(500))
    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, deadline(500))
    assert {:unconfirmed, :observer_unsealed} = Reader.await(attempt.receipt, deadline(1_500))
  end

  test "writer readiness arms the original setup deadline without starting a fresh setup budget" do
    setup_deadline = System.monotonic_time(:millisecond) + 500
    attempt = attempt(deadline(2_000), setup_deadline)
    :ok = :sys.suspend(attempt.observer)
    connection = start_connection(attempt)
    monitor = Process.monitor(connection)
    refute_receive {:lifecycle_ready, ^connection, _}, 250
    assert :ok = :sys.resume(attempt.observer)
    await_ready(attempt, connection)
    writer = writer(connection, attempt.observer)
    writer_monitor = Process.monitor(writer)

    assert_receive {:DOWN, ^monitor, :process, ^connection, _},
                   max(1, setup_deadline - System.monotonic_time(:millisecond) + 100)

    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000

    assert {:ok, %{roles: 14, observed_down: 14, cleanup: :confirmed}} =
             Reader.await(attempt.receipt, attempt.budget)
  end

  test "a born writer still enrolls and stops when its Connection parent is already dead" do
    attempt = attempt()
    {connection, token} = writer_constructor(attempt)
    monitor = Process.monitor(connection)
    Process.exit(connection, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^connection, :killed}, 1_000
    assert %{losses: 8, allocations: 8} = snapshot_until(attempt, fn s -> s.losses == 8 end)
    context = writer_context(attempt, token, make_ref())
    {writer, writer_monitor} = SSL.ConnectionWriter.start(connection, context)
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000
    refute_receive {:lifecycle_writer_ready, ^writer, _, _}, 20
    assert {:unconfirmed, :resource_evidence_lost} = Reader.await(attempt.receipt, attempt.budget)

    assert {:terminal, %{roles: 14, observed_down: 14, losses: 8}} =
             Reader.status(attempt.receipt)
  end

  test "writer enrollment alone cannot emit queued bytes before exact PID nonce and Observer release" do
    attempt = attempt()
    {connection, permit} = writer_constructor(attempt)
    {tcp, peer} = socket_pair()
    nonce = make_ref()
    context = writer_context(attempt, permit, nonce)
    :ok = :sys.suspend(attempt.observer)
    send(connection, {:start_writer, context})
    assert_receive {:writer_born, writer}, 1_000
    writer_monitor = Process.monitor(writer)
    job = make_ref()
    send(writer, {:lifecycle_send, nonce, job, tcp, "after both barriers", false})
    send(writer, {:lifecycle_writer_release, connection, permit, attempt.observer})
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)
    assert :ok = :sys.resume(attempt.observer)
    observer = attempt.observer
    assert_receive {:lifecycle_writer_ready, ^writer, ^nonce, ^observer}, 1_000
    send(writer, {:lifecycle_writer_release, self(), nonce, observer})
    send(writer, {:lifecycle_writer_release, connection, nonce, self()})
    send(writer, {:lifecycle_writer_release, connection, make_ref(), observer})
    assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 20)
    send(writer, {:lifecycle_writer_release, connection, nonce, observer})
    assert {:ok, "after both barriers"} = :gen_tcp.recv(peer, 0, 500)
    assert_receive {:writer_result, ^writer, ^job, :ok}, 1_000
    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, attempt.budget)
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000

    assert {:ok, %{cleanup: :confirmed, roles: 14, observed_down: 14}} =
             Reader.await(attempt.receipt, attempt.budget)
  end

  test "a writer with a missing permit cannot become ready or consume the legitimate permit" do
    attempt = attempt()
    {connection, permit} = writer_constructor(attempt)
    context = writer_context(attempt, make_ref(), make_ref())
    {writer, monitor} = SSL.ConnectionWriter.start(connection, context)
    assert_receive {:DOWN, ^monitor, :process, ^writer, _}, 1_000
    refute_receive {:lifecycle_writer_ready, ^writer, _, _}, 20
    assert {:ok, %{roles: 6, allocations: 8}} = Observer.snapshot(attempt.receipt, attempt.budget)
    send(connection, {:start_writer, writer_context(attempt, permit, make_ref())})
    assert_receive {:writer_born, genuine}, 1_000
    assert_receive {:lifecycle_writer_ready, ^genuine, _, _}, 1_000
    cancel(attempt)
  end

  test "writer readiness wait expires at the original control deadline without a fresh release budget" do
    budget = deadline(150)
    attempt = attempt(budget)
    {connection, permit} = writer_constructor(attempt)
    send(connection, {:start_writer, writer_context(attempt, permit, make_ref())})
    assert_receive {:writer_born, writer}, 1_000
    monitor = Process.monitor(writer)
    assert_receive {:lifecycle_writer_ready, ^writer, _, _}, 1_000
    {:abs_ms, expiry} = budget

    assert_receive {:DOWN, ^monitor, :process, ^writer, _},
                   max(1, expiry - System.monotonic_time(:millisecond) + 100)

    assert {:ok, %{cleanup: :confirmed, roles: 14, observed_down: 14}} =
             Reader.await(attempt.receipt, deadline(1_000))
  end

  defp writer_constructor(attempt) do
    parent = self()

    connection =
      actor(fn ->
        :use =
          Observer.enroll_self(
            attempt.receipt,
            :connection,
            attempt.context.permit,
            attempt.budget
          )

        {:ok, token} = Observer.reserve_child(attempt.receipt, :writer, attempt.budget)
        send(parent, {:writer_permit, self(), token})

        receive do
          {:start_writer, context} ->
            {writer, _monitor} = SSL.ConnectionWriter.start(self(), context)
            send(parent, {:writer_born, writer})
            forward(parent)
        end
      end)

    assert_receive {:writer_permit, ^connection, token}, 1_000
    {connection, token}
  end

  defp writer_context(attempt, permit, nonce),
    do: %{
      receipt: attempt.receipt,
      permit: permit,
      control_deadline: attempt.budget,
      setup_deadline: :infinity,
      nonce: nonce
    }

  defp attempt(budget \\ deadline(2_500), setup_deadline \\ :infinity) do
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, setup_token} = Observer.reserve_root(receipt, lease, :setup, budget)
    parent = self()

    setup =
      actor(fn ->
        :use = Observer.enroll_self(receipt, :setup, setup_token, budget)
        {:ok, token} = Observer.reserve_child(receipt, :connection, budget)
        send(parent, {:connection_permit, self(), token})
        forward(parent)
      end)

    observer = Receipt.observer(receipt)

    on_exit(fn ->
      if Process.alive?(observer) do
        :sys.resume(observer)
        Process.exit(observer, :kill)
      end
    end)

    assert_receive {:connection_permit, ^setup, token}, 1_000
    ref = make_ref()
    nonce = make_ref()
    classic = {self(), ref, :atomics.new(1, []), %Options{}, setup_deadline}
    context = %{receipt: receipt, permit: token, control_deadline: budget, ready: {setup, nonce}}

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      setup: setup,
      ref: ref,
      nonce: nonce,
      classic: classic,
      context: context,
      budget: budget
    }
  end

  defp start_connection(attempt) do
    assert {:ok, connection} =
             DynamicSupervisor.start_child(
               SSL.ConnectionSupervisor,
               {Connection, {:inert, attempt.classic, attempt.context}}
             )

    on_exit(fn -> if Process.alive?(connection), do: Process.exit(connection, :kill) end)
    connection
  end

  defp await_ready(attempt, connection) do
    nonce = attempt.nonce
    assert_receive {:lifecycle_ready, ^connection, ^nonce}, 1_000
  end

  defp cancel(attempt) do
    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, attempt.budget)

    assert {:ok, %{cleanup: :confirmed, roles: 14, observed_down: 14}} =
             Reader.await(attempt.receipt, attempt.budget)
  end

  defp writer(connection, observer) do
    {:monitors, monitors} = Process.info(connection, :monitors)
    owner = self()
    assert [writer] = for({:process, pid} <- monitors, pid not in [owner, observer], do: pid)
    writer
  end

  defp snapshot_until(attempt, predicate) do
    {:abs_ms, expiry} = attempt.budget
    assert System.monotonic_time(:millisecond) < expiry
    assert {:ok, snapshot} = Observer.snapshot(attempt.receipt, attempt.budget)

    if predicate.(snapshot),
      do: snapshot,
      else:
        (receive do
         after
           1 -> snapshot_until(attempt, predicate)
         end)
  end

  defp socket_pair do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    {:ok, peer} = :gen_tcp.accept(listener)
    :ok = :gen_tcp.close(listener)
    on_exit(fn -> Enum.each([tcp, peer], &:gen_tcp.close/1) end)
    {tcp, peer}
  end

  defp actor(fun) do
    pid = spawn(fun)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    pid
  end

  defp forward(parent) do
    receive do
      message ->
        send(parent, message)
        forward(parent)
    end
  end

  defp deadline(offset), do: {:abs_ms, System.monotonic_time(:millisecond) + offset}
end

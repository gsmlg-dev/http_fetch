defmodule SSL.Lifecycle.NativeHandoffTest do
  use ExUnit.Case, async: true
  alias SSL.{Connection, Options}
  alias SSL.Lifecycle.{Allocator, Observer, Reader, Receipt}

  test "actual actors commit passive TCP, allocator completes and pending bounds do not cap ownership" do
    a = attempt()
    assert :ok = handoff(a, deadline(200))
    allocator = a.allocator
    monitor = a.allocator_monitor
    assert_receive {:DOWN, ^monitor, :process, ^allocator, :normal}, 1_000
    connection = a.connection
    conn_monitor = a.connection_monitor

    receive do
      {:DOWN, ^conn_monitor, :process, ^connection, _} -> flunk("committed actor expired")
    after
      Options.remaining(a.allocation_deadline) + 1 -> :ok
    end

    assert Port.info(a.tcp, :connected) == {:connected, connection}
    assert Process.alive?(a.writer)
    assert {:ok, [active: false]} = :inet.getopts(a.tcp, [:active])
    assert {:error, :timeout} = :gen_tcp.recv(a.peer, 0, 0)

    assert {:ok, %{roles: 31, admission: :open, setup: :pending}} =
             Observer.snapshot(a.receipt, deadline(1_000))

    assert {:error, :lifecycle_attach_not_implemented} =
             :gen_statem.call(connection, {a.ref, {:attach, :unused}}, 1_000)

    assert {:error, :closed} = :gen_statem.call(connection, {a.ref, :reserve_write}, 1_000)
    cancel(a)
  end

  test "wrong caller and allocation nonce preserve the genuine one-shot handoff" do
    a = attempt()
    wrong = Task.async(fn -> handoff(a, deadline(500)) end)
    assert {:error, :unauthorized_handoff} = Task.await(wrong, 1_000)

    assert {:error, :unauthorized_handoff} =
             Allocator.handoff(
               a.allocator,
               make_ref(),
               {a.connection, a.ref, a.ready_nonce},
               deadline(500)
             )

    assert Port.info(a.tcp, :connected) == {:connected, a.allocator}
    assert :ok = handoff(a, deadline(200))
    cancel(a)
  end

  for field <- [:ref, :ready_nonce] do
    test "authorized wrong #{field} cannot claim native handoff acceptance" do
      a = attempt()
      wrong = Map.put(a, unquote(field), make_ref())
      assert {:error, :acceptance_unconfirmed} = handoff(wrong, deadline(500))
      cleanup(a)
      assert Port.info(a.listener, :connected) == {:connected, self()}
    end
  end

  for {ready_ms, requested_ms} <- [{1_500, 200}, {200, 5_000}] do
    test "asynchronous replay spends once and allocator independently enforces #{ready_ms}/#{requested_ms}" do
      a = attempt(unquote(ready_ms))
      assert :ok = :sys.suspend(a.connection)
      budget = deadline(unquote(requested_ms))

      request =
        :gen_server.send_request(
          a.allocator,
          {:handoff, a.allocation_nonce, {a.connection, a.ref, a.ready_nonce}, elem(budget, 1)}
        )

      try do
        assert {:error, :handoff_spent} = handoff(a, deadline(5_000))
        assert Port.info(a.tcp, :connected) == {:connected, a.connection}
        assert :ok = :sys.suspend(a.observer)
        allocator = a.allocator
        monitor = a.allocator_monitor
        effective = min(elem(budget, 1), a.ready_deadline)
        assert Process.alive?(allocator)
        assert_receive {:DOWN, ^monitor, :process, ^allocator, :normal}, 1_000
        assert System.monotonic_time(:millisecond) >= effective
        assert System.monotonic_time(:millisecond) < a.allocation_deadline
        assert Process.alive?(a.observer) and Process.alive?(a.connection)
        assert Port.info(a.tcp, :connected) == {:connected, a.connection}

        assert {:reply, {:error, :acceptance_unconfirmed}} =
                 :gen_server.receive_response(request, 1_000)
      after
        if Process.alive?(a.connection), do: :sys.resume(a.connection)
        :sys.resume(a.observer)
      end

      cleanup(a)
    end
  end

  # No dropped-ACK hooks: helper_done uncertainty is not claimed as cleanup proof.
  defp attempt(ready_ms \\ 1_500) do
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    observer = Receipt.observer(receipt)
    on_exit(fn -> Process.exit(observer, :kill) end)

    {:ok, listener} =
      :gen_tcp.listen(0, [
        {:inet_backend, :inet},
        :inet,
        :binary,
        active: false,
        packet: :raw,
        ip: {127, 0, 0, 1}
      ])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)
    budget = deadline(2_000)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, setup_permit} = Observer.reserve_root(receipt, lease, :setup, budget)
    {:ok, allocation_permit} = Observer.reserve_root(receipt, lease, :allocator, budget)
    parent = self()

    setup =
      spawn(fn ->
        :use = Observer.enroll_self(receipt, :setup, setup_permit, budget)
        {:ok, permit} = Observer.reserve_child(receipt, :connection, budget)
        send(parent, {:connection_permit, self(), permit})

        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> Process.exit(setup, :kill) end)
    assert_receive {:connection_permit, ^setup, permit}, 1_000
    ref = make_ref()
    ready_nonce = make_ref()
    classic = {self(), ref, :atomics.new(1, []), %Options{}, :infinity}

    context = %{
      receipt: receipt,
      permit: permit,
      control_deadline: budget,
      ready: {self(), ready_nonce}
    }

    {:ok, connection} =
      DynamicSupervisor.start_child(
        SSL.ConnectionSupervisor,
        {Connection, {:inert, classic, context}}
      )

    on_exit(fn -> Process.exit(connection, :kill) end)
    connection_monitor = Process.monitor(connection)
    assert_receive {:lifecycle_ready, ^connection, ^ready_nonce}, 1_000
    {:monitors, monitors} = Process.info(connection, :monitors)
    owner = self()
    [writer] = for {:process, pid} <- monitors, pid not in [owner, observer], do: pid
    allocation_nonce = make_ref()

    allocator_context = %{
      receipt: receipt,
      permit: allocation_permit,
      ip: {127, 0, 0, 1},
      port: port,
      deadline: budget,
      recipient: self(),
      nonce: allocation_nonce
    }

    {:ok, allocator} = Allocator.start(allocator_context)
    on_exit(fn -> Process.exit(allocator, :kill) end)
    allocator_monitor = Process.monitor(allocator)
    assert_receive {:lifecycle_allocated, ^allocator, ^allocation_nonce, ^observer, tcp}, 1_000
    tcp_monitor = :erlang.monitor(:port, tcp)
    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    ready_budget = deadline(ready_ms)

    assert :ok =
             :gen_statem.call(
               connection,
               {ref, {:prepare_handoff, ready_nonce, ready_budget}},
               1_000
             )

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      connection: connection,
      writer: writer,
      connection_monitor: connection_monitor,
      allocator: allocator,
      allocator_monitor: allocator_monitor,
      ref: ref,
      ready_nonce: ready_nonce,
      allocation_nonce: allocation_nonce,
      tcp: tcp,
      tcp_monitor: tcp_monitor,
      peer: peer,
      listener: listener,
      allocation_deadline: elem(budget, 1),
      ready_deadline: elem(ready_budget, 1)
    }
  end

  defp handoff(a, budget),
    do:
      Allocator.handoff(
        a.allocator,
        a.allocation_nonce,
        {a.connection, a.ref, a.ready_nonce},
        budget
      )

  defp cancel(a) do
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline(1_000))
    cleanup(a)
  end

  defp cleanup(a) do
    tcp = a.tcp
    monitor = a.tcp_monitor
    assert_receive {:DOWN, ^monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed}} =
             Reader.await(a.receipt, deadline(2_000))

    refute Process.alive?(a.observer)
  end

  defp deadline(milliseconds),
    do: {:abs_ms, System.monotonic_time(:millisecond) + milliseconds}
end

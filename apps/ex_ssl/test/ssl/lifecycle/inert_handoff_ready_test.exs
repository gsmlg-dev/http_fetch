defmodule SSL.Lifecycle.InertHandoffReadyTest do
  use ExUnit.Case, async: true
  alias SSL.{Connection, Options}
  alias SSL.Lifecycle.{Observer, Reader, Receipt}

  test "actual actors acknowledge preparation and original pending expiry retires typed resources" do
    attempt = attempt()
    assert :ok = prepare(attempt, deadline(200))

    assert {:ok, %{roles: 14, allocations: 0}} =
             Observer.snapshot(attempt.receipt, deadline(1_000))

    assert {:error, :lifecycle_attach_not_implemented} = call(attempt, {:attach, :unused})
    assert {:error, :closed} = call(attempt, :reserve_write)
    cleanup(attempt)
  end

  test "wrong caller, socket reference and ready nonce cannot spend genuine preparation" do
    attempt = attempt()
    request = {:prepare_handoff, attempt.nonce, deadline(500)}
    wrong = Task.async(fn -> call(attempt, request) end)
    assert {:error, :unauthorized_handoff} = Task.await(wrong, 1_000)
    assert {:error, :badarg} = call(attempt, request, make_ref())

    assert {:error, :unauthorized_handoff} =
             call(attempt, {:prepare_handoff, make_ref(), deadline(500)})

    assert :ok = prepare(attempt, deadline(200))
    cleanup(attempt)
  end

  test "preparation after startup expiry spends once and replay cannot extend pending deadline" do
    attempt = attempt(500)
    connection = attempt.connection
    monitor = attempt.connection_monitor

    receive do
      {:DOWN, ^monitor, :process, ^connection, _} -> flunk("birth-ready actor expired")
    after
      Options.remaining(attempt.control) + 1 -> :ok
    end

    assert :ok = prepare(attempt, deadline(200))
    assert {:error, :handoff_spent} = prepare(attempt, deadline(5_000))
    cleanup(attempt)
  end

  test "in-flight replay cannot remint deadline while original Observer is suspended" do
    attempt = attempt()
    observer = attempt.observer
    assert :ok = :sys.suspend(observer)
    budget = deadline(200)

    try do
      request =
        :gen_statem.send_request(
          attempt.connection,
          {attempt.ref, {:prepare_handoff, attempt.nonce, budget}}
        )

      assert {:error, :handoff_spent} = prepare(attempt, deadline(5_000))

      assert {:reply, {:error, :acceptance_unconfirmed}} =
               :gen_statem.receive_response(request, 1_000)

      connection = attempt.connection
      monitor = attempt.connection_monitor
      assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 1_000
      assert System.monotonic_time(:millisecond) >= elem(budget, 1)
    after
      :sys.resume(observer)
    end

    assert {:ok, %{roles: 14, observed_down: 14, cleanup: :confirmed}} =
             Reader.await(attempt.receipt, deadline(2_000))
  end

  test "original setup expiry retires a suspended prepared Connection" do
    attempt = attempt(2_000, System.monotonic_time(:millisecond) + 400)
    assert :ok = prepare(attempt, deadline(5_000))
    assert :ok = :sys.suspend(attempt.connection)
    cleanup(attempt)
  end

  defp attempt(control_ms \\ 2_000, setup_deadline \\ :infinity) do
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    observer = Receipt.observer(receipt)
    on_exit(fn -> Process.exit(observer, :kill) end)
    budget = deadline(control_ms)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, token} = Observer.reserve_root(receipt, lease, :setup, budget)
    parent = self()

    setup =
      spawn(fn ->
        :use = Observer.enroll_self(receipt, :setup, token, budget)
        {:ok, permit} = Observer.reserve_child(receipt, :connection, budget)
        send(parent, {:connection_permit, self(), permit})

        receive do
          :stop -> :ok
        end
      end)

    on_exit(fn -> Process.exit(setup, :kill) end)
    assert_receive {:connection_permit, ^setup, permit}, 1_000
    ref = make_ref()
    nonce = make_ref()
    classic = {self(), ref, :atomics.new(1, []), %Options{}, setup_deadline}

    context = %{
      receipt: receipt,
      permit: permit,
      control_deadline: budget,
      ready: {self(), nonce}
    }

    {:ok, connection} =
      DynamicSupervisor.start_child(
        SSL.ConnectionSupervisor,
        {Connection, {:inert, classic, context}}
      )

    on_exit(fn -> Process.exit(connection, :kill) end)
    monitor = Process.monitor(connection)
    assert_receive {:lifecycle_ready, ^connection, ^nonce}, 1_000
    {:monitors, monitors} = Process.info(connection, :monitors)
    owner = self()
    [writer] = for {:process, pid} <- monitors, pid not in [owner, observer], do: pid

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      connection: connection,
      connection_monitor: monitor,
      writer: writer,
      writer_monitor: Process.monitor(writer),
      ref: ref,
      nonce: nonce,
      control: elem(budget, 1)
    }
  end

  defp prepare(attempt, budget),
    do: call(attempt, {:prepare_handoff, attempt.nonce, budget})

  defp call(attempt, request, ref \\ nil),
    do: :gen_statem.call(attempt.connection, {ref || attempt.ref, request}, 1_000)

  defp cleanup(attempt) do
    connection = attempt.connection
    writer = attempt.writer
    monitor = attempt.connection_monitor
    writer_monitor = attempt.writer_monitor
    assert_receive {:DOWN, ^monitor, :process, ^connection, _}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000

    assert {:ok, %{roles: 14, observed_down: 14, cleanup: :confirmed}} =
             Reader.await(attempt.receipt, deadline(2_000))

    refute Process.alive?(attempt.observer)
  end

  defp deadline(milliseconds),
    do: {:abs_ms, System.monotonic_time(:millisecond) + milliseconds}
end

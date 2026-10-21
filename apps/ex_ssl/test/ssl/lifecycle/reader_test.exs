defmodule SSL.Lifecycle.ReaderTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle.{Reader, Receipt, ResourceLedger}

  test "a seal is pending until observer exit, then survives late noproc monitoring" do
    {pid, monitor, receipt} =
      observer(fn receipt, parent ->
        receive do
          :seal ->
            :ok = Receipt.seal(receipt, closed(), connected())
            send(parent, :sealed)
            receive do: (:exit -> :ok)
        end
      end)

    assert Reader.status(receipt) == {:pending, %{receipt: :unsealed, observer: :alive}}
    send(pid, :seal)
    assert_receive :sealed, 1_000
    assert Reader.status(receipt) == {:pending, %{receipt: :sealed, observer: :alive}}
    assert {:pending, %{receipt: :sealed}} = Reader.await(receipt, deadline(0))
    send(pid, :exit)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    assert {:terminal, %{cleanup: :confirmed}} = Reader.status(receipt)
    assert {:ok, first} = Reader.await(receipt, deadline(0))
    assert_clean_fast_await(receipt, {:ok, first})
  end

  test "normal or killed observer death without a seal is always unconfirmed" do
    for reason <- [:normal, :killed] do
      {pid, monitor, receipt} = observer(fn _, _ -> receive do: (:exit -> :ok) end)
      if reason == :normal, do: send(pid, :exit), else: Process.exit(pid, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^pid, ^reason}, 1_000
      assert Reader.status(receipt) == {:unconfirmed, :observer_unsealed}
      assert_clean_fast_await(receipt, {:unconfirmed, :observer_unsealed})
    end
  end

  test "interrupted publication never becomes a terminal receipt" do
    {pid, monitor, receipt} =
      observer(fn receipt, parent ->
        # Deliberate fault after ALL payload writes, before final seal.
        :atomics.put(receipt.cell, 1, 1)

        Enum.each(Enum.with_index([2, 1, 0, 0, 0, 0, 1], 2), fn {word, index} ->
          :atomics.put(receipt.cell, index, word)
        end)

        send(parent, :partial)
        receive do: (:exit -> :ok)
      end)

    assert_receive :partial, 1_000
    assert {:pending, %{receipt: :unsealed}} = Reader.status(receipt)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}, 1_000
    assert Reader.await(receipt, deadline(100)) == {:unconfirmed, :observer_unsealed}
  end

  test "absolute waits remain bounded, release monitors and leave unrelated messages untouched" do
    {pid, _monitor, receipt} = observer(fn _, _ -> receive do: (:exit -> :ok) end)
    {:monitors, baseline} = Process.info(self(), :monitors)
    marker = make_ref()
    send(self(), {:DOWN, marker, :process, pid, :unrelated})
    started = System.monotonic_time(:millisecond)
    original = deadline(25)
    assert {:pending, _} = Reader.await(receipt, original)
    for _ <- 1..20, do: assert({:pending, _} = Reader.await(receipt, original))
    assert System.monotonic_time(:millisecond) - started < 250
    assert {:monitors, ^baseline} = Process.info(self(), :monitors)
    assert_receive {:DOWN, ^marker, :process, ^pid, :unrelated}

    for invalid <- [:infinity, {:abs_ms, :infinity}, {:abs_ms, 1.0}, 100] do
      assert Reader.await(receipt, invalid) == {:error, :invalid_deadline}
    end
  end

  test "observer exit around monitor registration always rechecks final publication" do
    for _ <- 1..100 do
      {pid, monitor, receipt} =
        observer(fn receipt, _ ->
          receive do
            :finish -> :ok = Receipt.seal(receipt, closed(), connected())
          end
        end)

      send(pid, :finish)

      assert {:ok, %{setup: :connected, cleanup: :confirmed}} =
               Reader.await(receipt, deadline(1_000))

      assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    end
  end

  test "many waiters see one immutable publication without retaining waiter processes" do
    {pid, monitor, receipt} =
      observer(fn receipt, _ ->
        receive do
          :finish -> :ok = Receipt.seal(receipt, closed(), connected())
        end
      end)

    parent = self()

    waiters =
      for _ <- 1..32 do
        spawn_monitor(fn ->
          send(parent, {:result, self(), Reader.await(receipt, deadline(1_000))})
        end)
      end

    send(pid, :finish)

    for {waiter, ref} <- waiters do
      assert_receive {:result, ^waiter, {:ok, %{cleanup: :confirmed}}}, 1_500
      assert_receive {:DOWN, ^ref, :process, ^waiter, :normal}, 1_000
    end

    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    assert {:ok, %{cleanup: :confirmed}} = Reader.await(receipt, deadline(0))
  end

  test "invalid sealed evidence is unconfirmed even with a live observer" do
    {pid, _monitor, receipt} =
      observer(fn receipt, parent ->
        :atomics.put(receipt.cell, 1, 2)
        send(parent, :corrupt)
        receive do: (:exit -> :ok)
      end)

    assert_receive :corrupt, 1_000
    assert Reader.status(receipt) == {:unconfirmed, :invalid_evidence}
    assert_clean_fast_await(receipt, {:unconfirmed, :invalid_evidence})
    send(pid, :exit)
  end

  test "a sealed resource-loss receipt remains unconfirmed after observer exit" do
    {pid, monitor, receipt} =
      observer(fn receipt, _ ->
        {allocator, allocator_monitor} = short_lived_process()
        token = make_ref()
        writer_token = make_ref()
        {:ok, ledger} = ResourceLedger.reserve(ResourceLedger.new(), :allocator, :observer, token)

        {:ok, ledger, :use} =
          ResourceLedger.enroll(
            ledger,
            :allocator,
            token,
            {allocator_monitor, :process, allocator}
          )

        {:ok, ledger} =
          ResourceLedger.reserve(ledger, :writer, {:allocator, allocator_monitor}, writer_token)

        ledger =
          ledger
          |> ResourceLedger.down(kill(allocator, allocator_monitor))
          |> ResourceLedger.close_admission()

        {writer, writer_monitor} = short_lived_process()

        {:ok, ledger, :stop} =
          ResourceLedger.enroll(ledger, :writer, writer_token, {writer_monitor, :process, writer})

        ledger = ResourceLedger.down(ledger, kill(writer, writer_monitor))
        :ok = Receipt.seal(receipt, ledger, %{setup: :failed, failure: :internal, epoch: 0})
      end)

    assert Reader.await(receipt, deadline(1_000)) == {:unconfirmed, :resource_evidence_lost}
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    assert {:terminal, %{cleanup: :unconfirmed, losses: 8}} = Reader.status(receipt)
    assert_clean_fast_await(receipt, {:unconfirmed, :resource_evidence_lost})
  end

  defp assert_clean_fast_await(receipt, expected) do
    baseline = Process.info(self(), [:monitors, :messages])
    for _ <- 1..5, do: assert(Reader.await(receipt, deadline(0)) == expected)
    assert Process.info(self(), [:monitors, :messages]) == baseline
  end

  defp short_lived_process do
    spawn_monitor(fn ->
      receive do
        :stop -> :ok
      after
        1_000 -> :ok
      end
    end)
  end

  defp kill(pid, monitor) do
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed} = down, 1_000
    down
  end

  defp observer(fun) do
    parent = self()

    {pid, monitor} =
      spawn_monitor(fn ->
        receipt = Receipt.new()
        send(parent, {:receipt, self(), receipt})
        fun.(receipt, parent)
      end)

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    assert_receive {:receipt, ^pid, receipt}, 1_000
    {pid, monitor, receipt}
  end

  defp closed, do: ResourceLedger.new() |> ResourceLedger.close_admission()
  defp connected, do: %{setup: :connected, failure: :none, epoch: 0}
  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

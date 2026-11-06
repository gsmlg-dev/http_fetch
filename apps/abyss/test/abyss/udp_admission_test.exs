defmodule Abyss.UDPAdmissionTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  test "reservations and active work share a global ceiling, including zero-byte work" do
    scope =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    Abyss.Telemetry.register_scope(scope, __MODULE__)
    on_exit(fn -> send(scope, :stop) end)
    assert {:ok, first} = Abyss.UDPAdmission.reserve(scope, self(), 2)
    assert {:ok, second} = Abyss.UDPAdmission.reserve(scope, self(), 2)
    assert {:error, :handler_limit} = Abyss.UDPAdmission.reserve(scope, self(), 2)
    assert :ok = Abyss.UDPAdmission.admitted(first, self())
    assert %{connections_active: 1, accepts_total: 1} = Abyss.Telemetry.get_metrics(scope)
    assert :ok = Abyss.UDPAdmission.release(first)
    assert :ok = Abyss.UDPAdmission.release(first)
    assert :ok = Abyss.UDPAdmission.release(second)
    assert %{connections_active: 0} = Abyss.Telemetry.get_metrics(scope)
    assert {:ok, third} = Abyss.UDPAdmission.reserve(scope, self(), 2)
    Abyss.UDPAdmission.release(third)
  end

  test "a caller dying with a queued reservation cannot acquire late capacity" do
    scope =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    Abyss.Telemetry.register_scope(scope, __MODULE__)
    on_exit(fn -> send(scope, :stop) end)
    ledger = Process.whereis(Abyss.TableOwner)
    :ok = :sys.suspend(ledger)
    owner = self()

    caller =
      spawn(fn ->
        send(owner, :reserving)
        Abyss.UDPAdmission.reserve(scope, self(), 1)
      end)

    try do
      assert_receive :reserving
      Process.exit(caller, :kill)
    after
      :ok = :sys.resume(ledger)
    end

    assert {:ok, token} = Abyss.UDPAdmission.reserve(scope, self(), 1)
    assert {:error, :handler_limit} = Abyss.UDPAdmission.reserve(scope, self(), 1)
    Abyss.UDPAdmission.release(token)
  end

  test "concurrent callers cannot oversubscribe reservations" do
    scope =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    Abyss.Telemetry.register_scope(scope, __MODULE__)
    on_exit(fn -> send(scope, :stop) end)
    owner = self()

    tasks =
      for _ <- 1..50 do
        Task.async(fn -> Abyss.UDPAdmission.reserve(scope, owner, 3) end)
      end

    results = Enum.map(tasks, &Task.await/1)
    accepted = for {:ok, token} <- results, do: token
    assert length(accepted) == 3
    Enum.each(accepted, &Abyss.UDPAdmission.release/1)
  end
end

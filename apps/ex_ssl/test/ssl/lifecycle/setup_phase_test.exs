defmodule SSL.Lifecycle.SetupPhaseTest do
  use ExUnit.Case, async: true

  alias SSL.Lifecycle
  alias SSL.Lifecycle.Receipt

  test "public setup phase stays unknown for an untouched and cancelled handle" do
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)
    on_exit(fn -> Lifecycle.cancel(lease, deadline()) end)
    assert :unknown = Lifecycle.setup_failure(handle)
    assert :unknown = Lifecycle.connect_failure(handle)
    assert :ok = Lifecycle.cancel(lease, deadline())
    assert {:ok, terminal} = Lifecycle.await(handle, deadline())
    assert {:terminal, ^terminal} = Lifecycle.status(handle)
    assert :unknown = Lifecycle.setup_failure(handle)
    assert :unknown = Lifecycle.connect_failure(handle)
  end

  test "phase publication leaves all eight legacy cleanup words untouched" do
    receipt = Receipt.new()
    handle = %Lifecycle.Handle{receipt: receipt}
    before = for index <- 1..8, do: :atomics.get(receipt.cell, index)

    assert Task.async(fn -> Receipt.seal_setup_failure(receipt) end) |> Task.await() ==
             {:error, :not_observer}

    assert :unknown = Lifecycle.setup_failure(handle)
    assert :unknown = Lifecycle.connect_failure(handle)
    assert :ok = Receipt.seal_setup_failure(receipt)
    assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
    assert :unknown = Lifecycle.connect_failure(handle)
    assert {:error, :already_sealed} = Receipt.seal_setup_failure(receipt)
    assert :unsealed = Receipt.read(receipt)
    assert for(index <- 1..8, do: :atomics.get(receipt.cell, index)) == before
  end

  test "unsealed, malformed or absent sidecars remain unknown" do
    receipt = Receipt.new()

    for value <- [0, 1, 3] do
      :atomics.put(receipt.setup_phase, 1, value)
      assert :unknown = Lifecycle.setup_failure(%Lifecycle.Handle{receipt: receipt})
    end

    assert :unknown =
             Lifecycle.setup_failure(%Lifecycle.Handle{receipt: %{receipt | setup_phase: nil}})

    assert :unknown = Lifecycle.setup_failure(:invalid)
  end

  test "connect phase is independently sealed without publishing TLS or cleanup proof" do
    receipt = Receipt.new()
    handle = %Lifecycle.Handle{receipt: receipt}
    before = for index <- 1..8, do: :atomics.get(receipt.cell, index)

    assert Task.async(fn -> Receipt.seal_connect_failure(receipt) end) |> Task.await() ==
             {:error, :not_observer}

    assert :unknown = Lifecycle.connect_failure(handle)
    assert :ok = Receipt.seal_connect_failure(receipt)
    assert {:ok, %{phase: :connect}} = Lifecycle.connect_failure(handle)
    assert :unknown = Lifecycle.setup_failure(handle)
    assert {:error, :already_sealed} = Receipt.seal_connect_failure(receipt)
    assert {:error, :already_sealed} = Receipt.seal_setup_failure(receipt)
    assert :unsealed = Receipt.read(receipt)
    assert for(index <- 1..8, do: :atomics.get(receipt.cell, index)) == before
  end

  test "missing, malformed and incomplete connect phase publications remain unknown" do
    receipt = Receipt.new()

    for value <- [0, 1, 2, 3, 5] do
      :atomics.put(receipt.setup_phase, 1, value)
      assert :unknown = Lifecycle.connect_failure(%Lifecycle.Handle{receipt: receipt})
    end

    assert :unknown =
             Lifecycle.connect_failure(%Lifecycle.Handle{receipt: %{receipt | setup_phase: nil}})

    assert :unknown = Lifecycle.connect_failure(:invalid)
  end

  defp deadline, do: {:abs_ms, System.monotonic_time(:millisecond) + 1_000}
end

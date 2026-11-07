defmodule Quic.IO.EndpointPathTest do
  use ExUnit.Case, async: true

  alias Quic.IO.Endpoint

  test "a new peer path starts without another address's amplification credit" do
    {:ok, state} = Endpoint.new()
    {:ok, state} = Endpoint.receive_bytes(state, 1200)
    {:ok, state} = Endpoint.validate_address(state)
    {:ok, state} = Endpoint.add_path(state, 1)
    assert Endpoint.path(state, 1).bytes_received == 0
    assert Endpoint.path(state, 1).bytes_sent == 0
    refute Endpoint.path(state, 1).address_validated
    assert {:error, :anti_amplification} = Endpoint.enqueue(state, <<1>>, :new_peer, 0, 1)
    {:ok, state} = Endpoint.receive_bytes(state, 1, 1)
    {:ok, state, send} = Endpoint.enqueue(state, <<1, 2, 3>>, :new_peer, 0, 1)
    assert send.path_id == 1
    assert {:error, :anti_amplification} = Endpoint.enqueue(state, <<4>>, :new_peer, 0, 1)
    assert Endpoint.path(state, 1).bytes_pending == 3
    assert state.bytes_received == 1201
  end

  test "a late receipt remains charged to the old path after selection changes" do
    {:ok, state} = Endpoint.new()
    {:ok, state} = Endpoint.receive_bytes(state, 1)
    {:ok, state, send} = Endpoint.enqueue(state, <<1, 2, 3>>, :old_peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    {:ok, state} = Endpoint.add_path(state, 1)
    {:ok, state} = Endpoint.select_path(state, 1)
    assert Endpoint.selected_path(state) == 1
    {:ok, state, receipt} = Endpoint.local_send(state, send, :ok, 10)
    assert receipt.path_id == :default
    assert Endpoint.path(state, :default).bytes_sent == 3
    assert Endpoint.path(state, 1).bytes_sent == 0
    assert Endpoint.path(state, 1).bytes_pending == 0
    assert state.bytes_sent == 3
    assert {:error, :anti_amplification} = Endpoint.enqueue(state, <<4>>, :new_peer, 11)
  end

  test "validation is per peer address while item and byte queues stay global" do
    {:ok, state} = Endpoint.new(max_queue: 2, max_queue_bytes: 3)
    {:ok, state} = Endpoint.validate_address(state)
    {:ok, state} = Endpoint.add_path(state, 1)
    {:ok, state} = Endpoint.validate_address(state, 1)
    {:ok, state, _} = Endpoint.enqueue(state, <<1, 2>>, :old_peer, 0)

    assert {:error, :queue_bytes_limit} =
             Endpoint.enqueue(state, <<3, 4>>, :new_peer, 0, 1)

    {:ok, state, _} = Endpoint.enqueue(state, <<3>>, :new_peer, 0, 1)
    assert {:error, :queue_limit} = Endpoint.enqueue(state, <<4>>, :old_peer, 0)
    assert Endpoint.path(state, :default).bytes_pending == 2
    assert Endpoint.path(state, 1).bytes_pending == 1
  end

  test "generation invalidation preserves uncertain spending on its original path" do
    {:ok, state} = Endpoint.new()
    {:ok, state} = Endpoint.receive_bytes(state, 1)
    {:ok, state, send} = Endpoint.enqueue(state, <<1, 2, 3>>, :old_peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    {:ok, state} = Endpoint.add_path(state, 1)
    {:ok, state} = Endpoint.select_path(state, 1)
    {:ok, state} = Endpoint.bump_generation(state)
    assert Endpoint.path(state, :default).bytes_pending == 0
    assert Endpoint.path(state, :default).bytes_sent == 3
    assert Endpoint.path(state, 1).bytes_sent == 0
    assert {:error, :stale_generation} = Endpoint.local_send(state, send, :ok, 1)

    assert {:error, :anti_amplification} =
             Endpoint.enqueue(state, <<4>>, :old_peer, 2, :default)
  end

  test "only two ledgers are live and a pending writer prevents retirement" do
    {:ok, state} = Endpoint.new()
    {:ok, state} = Endpoint.validate_address(state)
    {:ok, state, send} = Endpoint.enqueue(state, <<1>>, :old_peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    {:ok, state} = Endpoint.add_path(state, 1)
    assert {:error, :path_limit} = Endpoint.add_path(state, 2)
    {:ok, state} = Endpoint.select_path(state, 1)
    assert {:error, :path_busy} = Endpoint.drop_path(state, :default)
    {:ok, state, _} = Endpoint.local_send(state, send, {:error, :closed}, 2)
    {:ok, state} = Endpoint.drop_path(state, :default)
    assert Endpoint.path(state, :default) == nil
    assert {:ok, _state} = Endpoint.add_path(state, 2)
  end

  test "unknown paths do not create credit or records" do
    {:ok, state} = Endpoint.new()
    assert {:error, :unknown_path} = Endpoint.receive_bytes(state, 1, :unknown)
    assert {:error, :unknown_path} = Endpoint.validate_address(state, :unknown)
    assert {:error, :unknown_path} = Endpoint.select_path(state, :unknown)
    assert {:error, :unknown_path} = Endpoint.enqueue(state, <<1>>, :peer, 0, :unknown)
    assert {:error, :active_path} = Endpoint.drop_path(state, :default)
  end

  test "validation alias follows only the selected path" do
    {:ok, state} = Endpoint.new(path: 42)
    assert Endpoint.selected_path(state) == 42
    {:ok, state} = Endpoint.validate_address(state)
    {:ok, state} = Endpoint.add_path(state, 1)
    {:ok, state} = Endpoint.select_path(state, 1)
    refute state.address_validated
    {:ok, state} = Endpoint.validate_address(state, 42)
    refute state.address_validated
    {:ok, state} = Endpoint.validate_address(state, 1)
    assert state.address_validated
    assert Endpoint.path(state, 1).bytes_received == 0
    assert {:ok, _, _} = Endpoint.enqueue(state, <<1>>, :established_peer, 0)
  end

  test "the legacy admission arity preserves its invalid-input result" do
    assert {:error, :invalid_datagram} = Endpoint.enqueue(nil, <<1>>, :peer, 0)
  end
end

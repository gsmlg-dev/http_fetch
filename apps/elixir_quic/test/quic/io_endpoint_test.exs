defmodule Quic.IO.EndpointTest do
  use ExUnit.Case, async: true

  alias Quic.IO.Endpoint

  test "successful sends consume amplification credit until more bytes arrive" do
    {:ok, state} = Endpoint.new()
    {:ok, state} = Endpoint.receive_bytes(state, 1)
    {:ok, state, send} = Endpoint.enqueue(state, <<1, 2, 3>>, :peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    {:ok, state, _receipt} = Endpoint.local_send(state, send, :ok, 1)
    assert {:error, :anti_amplification} = Endpoint.enqueue(state, <<4>>, :peer, 2)
    {:ok, state} = Endpoint.receive_bytes(state, 1)
    assert {:ok, _, _} = Endpoint.enqueue(state, <<4, 5, 6>>, :peer, 3)
  end

  test "dequeue does not release outstanding item or byte capacity" do
    {:ok, state} = Endpoint.new(max_queue: 1, max_queue_bytes: 3)
    {:ok, state} = Endpoint.validate_address(state)
    {:ok, state, send} = Endpoint.enqueue(state, <<1, 2, 3>>, :peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    assert {:error, :queue_limit} = Endpoint.enqueue(state, <<4>>, :peer, 1)
    {:ok, state, _} = Endpoint.local_send(state, send, {:error, :closed}, 2)
    assert {:ok, _, _} = Endpoint.enqueue(state, <<4>>, :peer, 3)

    {:ok, state} = Endpoint.new(max_queue: 2, max_queue_bytes: 3)
    {:ok, state} = Endpoint.validate_address(state)
    {:ok, state, send} = Endpoint.enqueue(state, <<1, 2, 3>>, :peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    assert {:error, :queue_bytes_limit} = Endpoint.enqueue(state, <<4>>, :peer, 1)
  end

  test "bounds queue and anti-amplification includes pending egress" do
    {:ok, state} = Endpoint.new(max_queue: 2, max_queue_bytes: 8)
    {:ok, state} = Endpoint.receive_bytes(state, 2)
    {:ok, state, first} = Endpoint.enqueue(state, <<1, 2, 3, 4, 5>>, :peer, 10)
    assert {:error, :anti_amplification} = Endpoint.enqueue(state, <<1, 2>>, :peer, 11)
    {:ok, state} = Endpoint.validate_address(state)

    assert {:error, :queue_bytes_limit} =
             Endpoint.enqueue(state, <<1, 2, 3, 4, 5, 6, 7, 8, 9>>, :peer, 12)

    assert {:ok, state, ^first} = Endpoint.dequeue(state)
    assert state.bytes_pending == 5
  end

  test "admission and actual local receipt are separate" do
    {:ok, state} = Endpoint.new()
    {:ok, state} = Endpoint.receive_bytes(state, 10)
    {:ok, state, send} = Endpoint.enqueue(state, <<1, 2>>, :peer, 0)
    assert state.bytes_sent == 0
    {:ok, state, ^send} = Endpoint.dequeue(state)
    {:ok, state, sent} = Endpoint.local_send(state, send, :ok, 4)
    assert sent.status == :sent
    assert state.bytes_sent == 2
    assert sent.completed_at == 4
    assert sent.error == nil
  end

  test "failed receipt releases pending bytes and does not reuse generation" do
    {:ok, state} = Endpoint.new()
    {:ok, state} = Endpoint.receive_bytes(state, 10)
    {:ok, state, send} = Endpoint.enqueue(state, <<1>>, :peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    {:ok, state, failed} = Endpoint.local_send(state, send, {:error, :closed}, 3)
    assert failed.status == :failed
    assert failed.completed_at == 3
    assert failed.error == :closed
    assert state.bytes_pending == 0
    {:ok, next} = Endpoint.bump_generation(state)
    assert {:error, :stale_generation} = Endpoint.local_send(next, send, :ok, 4)
  end

  test "timers accept signed monotonic time and invalidate only their own kind" do
    {:ok, state} = Endpoint.new()
    {:ok, state, old} = Endpoint.timer(state, :handshake, -10)
    {:ok, state, current} = Endpoint.timer(state, :handshake, -5)
    refute Endpoint.timer_expired?(state, old, 0)
    refute Endpoint.timer_expired?(state, current, -6)
    assert Endpoint.timer_expired?(state, current, -5)
    {:ok, stopped} = Endpoint.shutdown(state)
    refute Endpoint.timer_expired?(stopped, current, 0)
    assert {:error, :closed} = Endpoint.timer(stopped, :idle, 10)
  end

  test "generation replacement releases old work and rejects its receipts" do
    {:ok, state} = Endpoint.new(max_queue: 1)
    {:ok, state} = Endpoint.validate_address(state)
    {:ok, state, send} = Endpoint.enqueue(state, <<1>>, :peer, 0)
    {:ok, state, ^send} = Endpoint.dequeue(state)
    {:ok, state, timer} = Endpoint.timer(state, :handshake, 10)
    {:ok, next} = Endpoint.bump_generation(state)
    refute Endpoint.timer_expired?(next, timer, 20)
    assert {:error, :stale_generation} = Endpoint.local_send(next, send, :ok, 20)
    assert next.in_flight == %{}
    assert next.bytes_pending == 0
    assert {:ok, _, _} = Endpoint.enqueue(next, <<2>>, :peer, 20)
  end

  test "stale timer and shutdown are ignored safely" do
    {:ok, state} = Endpoint.new()
    {:ok, state, old} = Endpoint.timer(state, :handshake, 5)
    {:ok, state, current} = Endpoint.timer(state, :idle, 10)
    assert Endpoint.timer_expired?(state, old, 20)
    assert Endpoint.timer_expired?(state, current, 10)
    {:ok, stopped} = Endpoint.shutdown(state)
    assert stopped.closed
    assert {:error, :closed} = Endpoint.enqueue(stopped, <<1>>, :peer, 0)
  end
end

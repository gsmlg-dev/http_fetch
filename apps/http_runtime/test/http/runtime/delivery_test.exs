defmodule HTTP.Runtime.DeliveryTest do
  use ExUnit.Case, async: true
  alias HTTP.Runtime.Delivery

  test "ACK delivery charges bytes and count, emits one at a time and ignores stale references" do
    state = Delivery.new(delivery: :ack, max_queue_bytes: 7, max_queue_events: 2)
    assert {:ok, state, [{"one", first}]} = Delivery.push(state, "one", 3, self())
    assert {:ok, state, []} = Delivery.push(state, "four", 4, self())
    assert Delivery.status(state) == %{queued_bytes: 7, queued_events: 2, inflight?: true}
    assert {:error, :consumer_overloaded} = Delivery.push(state, "", 0, self())
    assert {:ok, ^state, []} = Delivery.acknowledge(state, make_ref())
    assert {:ok, state, [{"four", second}]} = Delivery.acknowledge(state, first)
    assert first != second
    assert {:ok, ^state, []} = Delivery.acknowledge(state, first)
    assert Delivery.status(state).queued_bytes == 4
    assert {:ok, state, []} = Delivery.acknowledge(state, second)
    assert Delivery.status(state) == %{queued_bytes: 0, queued_events: 0, inflight?: false}
    refute Delivery.paused?(state)
  end

  test "bytes bound catches a single oversized message and clears parked deliveries on close" do
    state = Delivery.new(delivery: :ack, max_queue_bytes: 4)
    assert {:error, :consumer_overloaded} = Delivery.push(state, "large", 5, self())
    assert {:ok, state, [{"four", ref}]} = Delivery.push(state, "four", 4, self())
    assert Delivery.paused?(state)
    state = Delivery.clear(state)
    assert {:ok, ^state, []} = Delivery.acknowledge(state, ref)
    assert Delivery.status(state).queued_bytes == 0
  end

  test "legacy delivery preserves its envelope marker and declares slow-owner overload" do
    state = Delivery.new(delivery: :legacy, max_queue_events: 2)
    assert {:ok, ^state, [{:event, nil}]} = Delivery.push(state, :event, 1, self())
    send(self(), :unrelated_one)
    send(self(), :unrelated_two)
    assert {:error, :consumer_overloaded} = Delivery.push(state, :event, 1, self())
    assert_receive :unrelated_one
    assert_receive :unrelated_two
  end
end

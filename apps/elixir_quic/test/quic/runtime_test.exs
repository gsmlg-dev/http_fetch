defmodule Quic.RuntimeTest do
  use ExUnit.Case, async: true

  alias Quic.Runtime

  test "keeps datagram metadata and generation explicit" do
    datagram = %Runtime.Datagram{
      bytes: <<1, 2>>,
      remote: {{127, 0, 0, 1}, 4433},
      received_at: 10,
      generation: 3
    }

    assert datagram.generation == 3
    assert datagram.local == nil
  end

  test "virtual clock is deterministic" do
    clock = Runtime.VirtualClock.new(100) |> Runtime.VirtualClock.advance(25)
    assert Runtime.VirtualClock.now(clock) == 125
  end

  test "handles and receipts carry generation boundaries" do
    handle = %Runtime.ConnectionHandle{id: make_ref(), generation: 4}
    receipt = %Runtime.SendReceipt{ref: make_ref(), generation: 4, status: :queued}
    assert handle.generation == receipt.generation
  end
end

defmodule Quic.ResumptionStoreTest do
  use ExUnit.Case, async: true
  alias Quic.ResumptionStore, as: Store

  defp ticket(id, context \\ "partition") do
    %SSL.QUIC.Session{
      identity: id,
      psk: <<1::256>>,
      hash: :sha256,
      cipher_suite: 0x1301,
      age_add: 0,
      issued_at: 0,
      expires_at: 1000,
      alpn: "test",
      context: context,
      peer: nil,
      transport_parameters: <<>>
    }
  end

  test "lookup grants a bounded lease; commit is atomic single-use and cannot restore on retry" do
    {:ok, state} = Store.new()
    {:ok, state} = Store.store(state, "partition", ticket("ticket"), 0)
    {:ok, session, lease, state} = Store.lookup(state, "partition", "ticket", 10, 500)
    assert session.identity == "ticket"
    assert {:miss, _} = Store.lookup(state, "partition", "ticket", 11, 500)
    assert {:ok, consumed} = Store.commit(state, "partition", "ticket", lease, 12)
    assert consumed.bytes == 0
    assert {:miss, ^consumed} = Store.commit(consumed, "partition", "ticket", lease, 13)
    assert {:miss, _} = Store.lookup(consumed, "partition", "ticket", 14, 500)
  end

  test "expired leases allow fresh lookup but old/late lease can never consume" do
    {:ok, state} = Store.new()
    {:ok, state} = Store.store(state, "partition", ticket("ticket"), 0)
    {:ok, _, old, state} = Store.lookup(state, "partition", "ticket", 10, 500)
    assert {:miss, state} = Store.commit(state, "partition", "ticket", old, 110)
    {:ok, _, new, state} = Store.lookup(state, "partition", "ticket", 110, 500)
    assert new != old
    assert {:miss, _} = Store.commit(state, "partition", "ticket", old, 111)
    assert {:ok, _} = Store.commit(state, "partition", "ticket", new, 111)
  end

  test "client claim consumes once, partitions isolate, restart/expiry discard and inspection redacts" do
    {:ok, state} = Store.new()
    {:ok, state} = Store.store(state, "partition", ticket("private-ticket"), 0)
    assert {nil, _} = Store.claim_client(state, "changed-trust", 1)
    {session, state} = Store.claim_client(state, "partition", 1)
    assert session.identity == "private-ticket"
    assert {nil, _} = Store.claim_client(state, "partition", 2)
    refute inspect(state) =~ "private-ticket"
    refute inspect(state) =~ "psk"
    {:ok, state} = Store.store(state, "partition", ticket("expiring"), 0)
    assert {nil, %{bytes: 0}} = Store.claim_client(state, "partition", 1000)
  end

  test "entry/byte limits evict old tickets and oversized tickets fail closed" do
    {:ok, state} = Store.new(max_entries: 1, max_bytes: 1024)
    {:ok, state} = Store.store(state, "partition", ticket("old"), 0)
    {:ok, state} = Store.store(state, "partition", ticket("new"), 1)
    assert map_size(state.entries) == 1
    assert {:miss, _} = Store.lookup(state, "partition", "old", 2, 100)

    assert {:error, :ticket_too_large, _} =
             Store.store(state, "partition", ticket(:binary.copy("x", 1024)), 2)
  end
end

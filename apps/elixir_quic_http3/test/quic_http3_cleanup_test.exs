defmodule QuicHttp3.CleanupTest do
  use ExUnit.Case, async: true
  alias QuicHttp3.Session
  alias QuicHttp3.Transport.Quic, as: Adapter

  defmodule BlockedTransport do
    def connect(_, _, options) do
      send(self(), {:transport_connect, options})
      {:blocked, :no_credit}
    end
  end

  test "an expired absolute session deadline prevents transport admission" do
    {:ok, session} = Session.new(transport: BlockedTransport, deadline: bound(-1))
    assert {:error, _, :deadline_expired} = Session.connect(session, {127, 0, 0, 1}, 443, [])
    refute_received {:transport_connect, _}
  end

  test "blocked work retains the exact supplied absolute deadline" do
    {:abs_ms, deadline} = absolute = bound()
    {:ok, session} = Session.new(transport: BlockedTransport)

    assert {:blocked, session, :no_credit} =
             Session.connect(session, {127, 0, 0, 1}, 443, deadline: absolute)

    assert session.pending.deadline == deadline
    assert session.work.deadline == deadline
  end

  test "invalid cleanup input is rejected rather than silently starting untracked" do
    assert {:error, :invalid_cleanup_descriptor} = Session.new(cleanup: :invalid)
  end

  test "an absolute admission deadline preserves a shorter transport call timeout" do
    {:ok, session} = Session.new(transport: BlockedTransport)

    assert {:blocked, _, :no_credit} =
             Session.connect(session, {127, 0, 0, 1}, 443, deadline: bound(), timeout: 20)

    assert_received {:transport_connect, options}
    assert options[:timeout] <= 20
  end

  test "custom transports cannot claim the exclusive production QUIC cleanup scope" do
    {:ok, handle, lease} = Quic.Cleanup.new(owner: self())
    on_exit(fn -> Quic.Cleanup.retire(lease, bound()) end)

    assert {:error, :cleanup_requires_quic_transport} =
             Session.new(transport: BlockedTransport, cleanup: %{handle: handle, lease: lease})
  end

  test "blocked suspend and retry keep the original logical action and deadline" do
    {:abs_ms, deadline} = absolute = bound()
    {:ok, session} = Session.new(transport: BlockedTransport)

    assert {:blocked, session, :no_credit} =
             Session.connect(session, {127, 0, 0, 1}, 443, deadline: absolute, timeout: 20)

    assert_received {:transport_connect, first}
    original = session.pending
    assert {:ok, suspended, continuation} = Session.suspend_blocked(session)
    assert continuation.pending == original
    assert continuation.work.deadline == deadline
    assert {:blocked, resumed, :no_credit} = Session.resume(suspended, continuation)
    assert_received {:transport_connect, second}
    assert resumed.pending.action == original.action
    assert resumed.pending.deadline == deadline
    assert resumed.work.deadline == deadline
    assert second[:ref] != first[:ref]
    assert second[:deadline] == first[:deadline]
    assert second[:timeout] <= 20

    assert {:error, _, :stale_continuation} =
             Session.resume(suspended, %{continuation | id: make_ref()})
  end

  test "expired blocked continuation cannot invoke transport again" do
    {:ok, session} = Session.new(transport: BlockedTransport)

    assert {:blocked, session, :no_credit} =
             Session.connect(session, {127, 0, 0, 1}, 443, deadline: bound(30))

    assert_received {:transport_connect, _}
    assert {:ok, suspended, continuation} = Session.suspend_blocked(session)

    receive do
    after
      50 -> :ok
    end

    assert {:error, _, :deadline_expired} = Session.resume(suspended, continuation)
    refute_received {:transport_connect, _}
  end

  test "a cleanup handle cannot be paired with another scope's write lease" do
    {:ok, first, first_lease} = Quic.Cleanup.new(owner: self())
    {:ok, second, second_lease} = Quic.Cleanup.new(owner: self())

    on_exit(fn ->
      Quic.Cleanup.retire(first_lease, bound())
      Quic.Cleanup.retire(second_lease, bound())
    end)

    descriptor = %{handle: first, lease: second_lease}
    assert {:error, :invalid_cleanup_descriptor} = Session.new(cleanup: descriptor)

    assert {:error, :invalid_cleanup_descriptor} =
             Adapter.connect({127, 0, 0, 1}, 443,
               cleanup: descriptor,
               deadline: bound()
             )

    assert {:pending, %{enrolled: 0}} = Quic.Cleanup.status(first)
    assert {:pending, %{enrolled: 0}} = Quic.Cleanup.status(second)
  end

  defp bound(timeout \\ 2_000), do: {:abs_ms, System.monotonic_time(:millisecond) + timeout}
end

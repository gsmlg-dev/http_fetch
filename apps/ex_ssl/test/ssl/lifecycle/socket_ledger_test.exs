defmodule SSL.Lifecycle.SocketLedgerTest do
  use ExUnit.Case, async: false
  alias SSL.Lifecycle.ResourceLedger, as: Ledger
  @moduletag :integration

  test "actual socket identity enrolls before connect and needs original socket DOWN" do
    native = System.monotonic_time(:millisecond) + 1_000
    parent_deadline = native + 2_000
    {:ok, listener} = :socket.open(:inet, :stream, :tcp)

    {ledger, tcp_permit, owner, owner_monitor, socket, socket_monitor} =
      socket_attempt(native, parent_deadline)

    try do
      :ok = :socket.bind(listener, %{family: :inet, addr: {127, 0, 0, 1}, port: 0})
      :ok = :socket.listen(listener)
      {:ok, address} = :socket.sockname(listener)

      assert {:ok, ledger, :use} =
               Ledger.enroll(ledger, :tcp, tcp_permit, {socket_monitor, :socket, socket})

      send(owner, {:connect, address})
      assert_receive {:connected, ^owner, :ok}, remaining(native)
      ledger = Ledger.close_admission(ledger)
      send(owner, :close)

      assert_receive {:DOWN, ^socket_monitor, :socket, ^socket, _} = socket_down,
                     remaining(parent_deadline)

      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _} = owner_down,
                     remaining(parent_deadline)

      ledger = ledger |> Ledger.down(socket_down) |> Ledger.down(owner_down)

      assert {:ok, %{scope: :dial, roles: 17, observed_down: 17, losses: 0, cleanup: :confirmed}} =
               Ledger.proof(ledger)
    after
      Process.exit(owner, :kill)
      :socket.close(listener)
    end
  end

  test "socket scope and exact monitor identity reject unrelated settlement" do
    native = System.monotonic_time(:millisecond) + 1_000
    parent_deadline = native + 2_000
    {:ok, other} = :socket.open(:inet, :stream, :tcp)

    {ledger, tcp_permit, owner, owner_monitor, socket, socket_monitor} =
      socket_attempt(native, parent_deadline)

    try do
      identity = {socket_monitor, :socket, socket}
      token = make_ref()
      {:ok, process_ledger} = Ledger.reserve(Ledger.new(:dial), :allocator, :observer, token)

      assert {:error, :invalid_monitor_identity} =
               Ledger.enroll(process_ledger, :allocator, token, identity)

      assert {:error, :invalid_monitor_identity} =
               Ledger.adopt_tcp(Ledger.new(:upgrade), identity)

      {upgrade, upgrade_token} = reserved(Ledger.new(:upgrade), owner, owner_monitor)

      assert {:error, :invalid_monitor_identity} =
               Ledger.enroll(upgrade, :tcp, upgrade_token, identity)

      assert {:ok, ledger, :use} = Ledger.enroll(ledger, :tcp, tcp_permit, identity)
      ledger = Ledger.close_admission(ledger)
      # Invalid event data goes only into the pure reducer, never the VM mailbox.
      for wrong <- [
            {:DOWN, make_ref(), :socket, socket, :closed},
            {:DOWN, socket_monitor, :port, socket, :closed},
            {:DOWN, socket_monitor, :socket, other, :closed}
          ],
          do: assert(Ledger.down(ledger, wrong) == ledger)

      assert {:pending, %{roles: 17, observed_down: 0}} = Ledger.proof(ledger)
      send(owner, :close)

      assert_receive {:DOWN, ^socket_monitor, :socket, ^socket, _} = socket_down,
                     remaining(parent_deadline)

      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _} = owner_down,
                     remaining(parent_deadline)

      one_down = Ledger.down(ledger, socket_down)
      assert {:pending, %{roles: 17, observed_down: 16}} = Ledger.proof(one_down)
      assert Ledger.down(one_down, socket_down) == one_down

      assert {:ok, %{cleanup: :confirmed, roles: 17, observed_down: 17, losses: 0}} =
               one_down |> Ledger.down(owner_down) |> Ledger.proof()
    after
      Process.exit(owner, :kill)
      :socket.close(other)
    end
  end

  test "actual owner death keeps unknown TCP and late identity cannot erase loss" do
    native = System.monotonic_time(:millisecond) + 1_000
    parent_deadline = native + 2_000

    {ledger, tcp_permit, owner, owner_monitor, socket, socket_monitor} =
      socket_attempt(native, parent_deadline)

    try do
      Process.exit(owner, :kill)

      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _} = owner_down,
                     remaining(parent_deadline)

      assert_receive {:DOWN, ^socket_monitor, :socket, ^socket, _} = socket_down,
                     remaining(parent_deadline)

      unknown = Ledger.down(ledger, owner_down)

      assert {:pending,
              %{admission: :open, roles: 1, observed_down: 1, allocations: 16, losses: 16}} =
               Ledger.proof(unknown)

      assert Ledger.down(unknown, socket_down) == unknown
      # Admission is still open: sticky loss alone prevents authorizing use.
      assert {:ok, known, :stop} =
               Ledger.enroll(unknown, :tcp, tcp_permit, {socket_monitor, :socket, socket})

      known = Ledger.close_admission(known)

      assert {:pending, %{roles: 17, observed_down: 1, allocations: 0, losses: 16}} =
               Ledger.proof(known)

      settled = Ledger.down(known, socket_down)

      assert {:ok,
              %{scope: :dial, roles: 17, observed_down: 17, losses: 16, cleanup: :unconfirmed}} =
               Ledger.proof(settled)

      assert Ledger.down(settled, socket_down) == settled
      assert Ledger.down(settled, owner_down) == settled
    after
      Process.exit(owner, :kill)
    end
  end

  defp socket_attempt(native, deadline) do
    allocator_permit = make_ref()
    {:ok, ledger} = Ledger.reserve(Ledger.new(:dial), :allocator, :observer, allocator_permit)
    parent = self()
    {owner, monitor} = spawn_monitor(fn -> socket_owner(parent, native, deadline) end)
    on_exit(fn -> Process.exit(owner, :kill) end)

    {:ok, ledger, :use} =
      Ledger.enroll(ledger, :allocator, allocator_permit, {monitor, :process, owner})

    tcp_permit = make_ref()
    {:ok, ledger} = Ledger.reserve(ledger, :tcp, {:allocator, monitor}, tcp_permit)
    send(owner, :open)
    assert_receive {:opened, ^owner, socket}, remaining(native)
    socket_monitor = :socket.monitor(socket)
    {ledger, tcp_permit, owner, monitor, socket, socket_monitor}
  end

  defp remaining(d), do: max(d - System.monotonic_time(:millisecond), 0)

  defp reserved(ledger, owner, monitor) do
    allocator_permit = make_ref()
    tcp_permit = make_ref()
    {:ok, ledger} = Ledger.reserve(ledger, :allocator, :observer, allocator_permit)

    {:ok, ledger, :use} =
      Ledger.enroll(ledger, :allocator, allocator_permit, {monitor, :process, owner})

    {:ok, ledger} = Ledger.reserve(ledger, :tcp, {:allocator, monitor}, tcp_permit)
    {ledger, tcp_permit}
  end

  defp socket_owner(parent, native, deadline) do
    timer = :erlang.start_timer(remaining(deadline), self(), :owner_expiry)

    receive do
      :open ->
        if remaining(native) > 0, do: open_socket(parent, native, timer)

      {:timeout, ^timer, :owner_expiry} ->
        :ok
    end
  end

  defp open_socket(parent, native, timer) do
    {:ok, socket} = :socket.open(:inet, :stream, :tcp)

    try do
      send(parent, {:opened, self(), socket})
      owner_commands(socket, parent, native, timer)
    after
      :socket.close(socket)
    end
  end

  defp owner_commands(socket, parent, native, timer) do
    receive do
      {:connect, address} ->
        send(parent, {:connected, self(), :socket.connect(socket, address, remaining(native))})
        owner_commands(socket, parent, native, timer)

      :close ->
        :ok

      {:timeout, ^timer, :owner_expiry} ->
        :ok
    end
  end
end

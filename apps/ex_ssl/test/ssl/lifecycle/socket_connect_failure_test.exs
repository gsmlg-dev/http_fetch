defmodule SSL.Lifecycle.SocketConnectFailureTest do
  use ExUnit.Case, async: false
  alias SSL.Lifecycle.{Observer, Reader, Receipt}
  @moduletag :integration

  # These are cooperative authentication negatives with real native identities.
  # Actual constructor/refusal attribution belongs to the Allocator integration suite.
  test "a pending permit and an owned but unobserved Socket cannot authorize known failure" do
    attempt = attempt(:socket, false)

    assert {:error, :unauthorized_connect_failure} = report(attempt)
    assert_pending(attempt, 1, 16)
    assert :use = enroll(attempt)
    assert_pending(attempt)
    cancel_and_await(attempt)
  end

  test "the Root and another allocator generation cannot report for the canonical Socket" do
    attempt = attempt()
    other = attempt()

    assert {:error, :unauthorized_connect_failure} =
             Observer.record_socket_connect_failure(
               attempt.receipt,
               attempt.socket,
               :econnrefused,
               budget(attempt.native)
             )

    assert_pending(attempt)

    assert {:error, :unauthorized_connect_failure} =
             in_actor(
               other.allocator,
               fn ->
                 Observer.record_socket_connect_failure(
                   attempt.receipt,
                   attempt.socket,
                   :econnrefused,
                   budget(attempt.native)
                 )
               end,
               attempt.native
             )

    assert_pending(attempt)
    assert_pending(other)
    cancel_and_await(attempt)
    cancel_and_await(other)
  end

  test "another observed Socket and an unobserved same-owner Socket cannot replace the identity" do
    attempt = attempt()
    other = attempt()

    {:ok, replacement} =
      in_actor(attempt.allocator, fn -> :socket.open(:inet, :stream, :tcp) end, attempt.native)

    for socket <- [other.socket, replacement] do
      assert {:error, :unauthorized_connect_failure} = report(attempt, socket)
      assert_pending(attempt)
    end

    assert :ok =
             in_actor(attempt.allocator, fn -> :socket.close(replacement) end, attempt.native)

    assert_pending(other)
    cancel_and_await(attempt)
    cancel_and_await(other)
  end

  test "an enrolled Port is not the known Socket failure resource" do
    attempt = attempt(:port)
    assert {:error, :unauthorized_connect_failure} = report(attempt)
    assert_pending(attempt)
    cancel_and_await(attempt)
  end

  test "the pending-only R29 operation cannot classify an already enrolled Socket" do
    attempt = attempt()

    assert {:error, :unauthorized_connect_failure} =
             in_actor(
               attempt.allocator,
               fn ->
                 Observer.record_connect_failure(
                   attempt.receipt,
                   :econnrefused,
                   budget(attempt.native)
                 )
               end,
               attempt.native
             )

    assert_pending(attempt)
    cancel_and_await(attempt)
  end

  test "the original allocator loses failure authority when the public Socket owner changes" do
    attempt = attempt()
    {holder, _monitor} = start_actor(attempt.parent)

    assert :ok =
             in_actor(
               attempt.allocator,
               fn ->
                 :socket.setopt(attempt.socket, :otp, :controlling_process, holder)
               end,
               attempt.native
             )

    assert {:ok, ^holder} = :socket.getopt(attempt.socket, :otp, :controlling_process)
    assert {:error, :unauthorized_connect_failure} = report(attempt)
    assert_pending(attempt)

    # Cancellation cannot stand in for the original Socket DOWN. Its new owner
    # closes it explicitly; no provider rollback or foreign-owner close is used.
    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, budget(attempt.native))
    assert :ok = in_actor(holder, fn -> :socket.close(attempt.socket) end, attempt.native)
    await_cleanup(attempt)
  end

  test "expired and malformed failure budgets or reasons leave the known resource unchanged" do
    attempt = attempt()

    assert {:error, :deadline_exceeded} =
             in_actor(
               attempt.allocator,
               fn ->
                 Observer.record_socket_connect_failure(
                   attempt.receipt,
                   attempt.socket,
                   :econnrefused,
                   budget(now() - 1)
                 )
               end,
               attempt.native
             )

    assert_pending(attempt)

    for {reason, native} <- [
          {:timeout, budget(attempt.native)},
          {:closed, budget(attempt.native)},
          {:eacces, budget(attempt.native)},
          {:econnrefused, {:abs_ms, :later}}
        ] do
      assert {:error, :invalid_connect_failure} =
               in_actor(
                 attempt.allocator,
                 fn ->
                   Observer.record_socket_connect_failure(
                     attempt.receipt,
                     attempt.socket,
                     reason,
                     native
                   )
                 end,
                 attempt.native
               )

      assert_pending(attempt)
    end

    cancel_and_await(attempt)
  end

  test "the original allocator cannot extend the canonical Socket enrollment deadline" do
    attempt = attempt()

    assert {:error, :unauthorized_connect_failure} =
             in_actor(
               attempt.allocator,
               fn ->
                 Observer.record_socket_connect_failure(
                   attempt.receipt,
                   attempt.socket,
                   :econnrefused,
                   budget(attempt.native + 1_000)
                 )
               end,
               attempt.native
             )

    assert_pending(attempt)
    cancel_and_await(attempt)
  end

  test "an injected internal failure frame cannot replace the canonical outer deadline" do
    attempt = attempt()

    assert {:error, :invalid_connect_failure} =
             in_actor(
               attempt.allocator,
               fn ->
                 requested = min(attempt.native, now() + 200)

                 GenServer.call(
                   Receipt.observer(attempt.receipt),
                   {{:record_socket_connect_failure, attempt.socket, :econnrefused,
                     attempt.native, requested}, {:abs_ms, :later}},
                   left(attempt.native)
                 )
               end,
               attempt.native
             )

    assert_pending(attempt)
    cancel_and_await(attempt)
  end

  test "receiver validation rejects malformed deadlines and an oversized RPC window" do
    attempt = attempt()

    for {existing, requested, expected} <- [
          {{:abs_ms, :later}, budget(now() + 200), :invalid_connect_failure},
          {budget(attempt.native), {:abs_ms, :later}, :invalid_connect_failure},
          {budget(attempt.native), budget(now() + 600), :unauthorized_connect_failure}
        ] do
      assert {:error, ^expected} =
               in_actor(
                 attempt.allocator,
                 fn ->
                   GenServer.call(
                     Receipt.observer(attempt.receipt),
                     {{:record_socket_connect_failure, attempt.socket, :econnrefused, existing},
                      requested},
                     left(attempt.native)
                   )
                 end,
                 attempt.native
               )

      assert_pending(attempt)
    end

    cancel_and_await(attempt)
  end

  defp attempt(kind \\ :socket, enrolled \\ true) do
    native = now() + 1_000
    parent = native + 2_000
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    observer = Receipt.observer(receipt)
    on_exit(fn -> Process.exit(observer, :kill) end)
    assert :ok = Observer.bind(receipt, lease, budget(native))
    {:ok, permit} = Observer.reserve_root(receipt, lease, :allocator, budget(native))
    {allocator, allocator_monitor} = start_actor(parent)

    assert :use =
             in_actor(
               allocator,
               fn ->
                 Observer.enroll_self(receipt, :allocator, permit, budget(native))
               end,
               native
             )

    {:ok, token} =
      in_actor(allocator, fn -> Observer.reserve_child(receipt, :tcp, budget(native)) end, native)

    {:ok, socket} = in_actor(allocator, fn -> open(kind) end, native)
    socket_monitor = monitor(kind, socket)

    attempt = %{
      receipt: receipt,
      lease: lease,
      allocator: allocator,
      allocator_monitor: allocator_monitor,
      socket: socket,
      socket_monitor: socket_monitor,
      kind: kind,
      token: token,
      native: native,
      parent: parent
    }

    if enrolled, do: assert(:use = enroll(attempt))
    attempt
  end

  defp open(:socket), do: :socket.open(:inet, :stream, :tcp)

  defp open(:port),
    do:
      :gen_tcp.listen(0, [
        {:inet_backend, :inet},
        :inet,
        :binary,
        active: false,
        packet: :raw,
        ip: {127, 0, 0, 1}
      ])

  defp monitor(:socket, socket), do: :socket.monitor(socket)
  defp monitor(:port, port), do: :erlang.monitor(:port, port)

  defp enroll(attempt) do
    in_actor(
      attempt.allocator,
      fn ->
        case attempt.kind do
          :socket ->
            Observer.enroll_socket(
              attempt.receipt,
              attempt.token,
              attempt.socket,
              budget(attempt.native)
            )

          :port ->
            Observer.enroll_port(
              attempt.receipt,
              attempt.token,
              attempt.socket,
              budget(attempt.native)
            )
        end
      end,
      attempt.native
    )
  end

  defp report(attempt, socket \\ nil) do
    in_actor(
      attempt.allocator,
      fn ->
        Observer.record_socket_connect_failure(
          attempt.receipt,
          socket || attempt.socket,
          :econnrefused,
          budget(attempt.native)
        )
      end,
      attempt.native
    )
  end

  defp assert_pending(attempt, roles \\ 17, allocations \\ 0) do
    assert {:ok,
            %{
              setup: :pending,
              setup_failure: :none,
              admission: :open,
              phase: :open,
              roles: ^roles,
              observed_down: 0,
              allocations: ^allocations,
              losses: 0
            }} = Observer.snapshot(attempt.receipt, budget(attempt.native))
  end

  defp cancel_and_await(attempt) do
    assert :ok = Observer.cancel(attempt.receipt, attempt.lease, budget(attempt.native))
    await_cleanup(attempt)
  end

  defp await_cleanup(attempt) do
    %{socket_monitor: monitor, socket: socket, kind: kind} = attempt
    %{allocator_monitor: allocator_monitor, allocator: allocator} = attempt
    assert_receive {:DOWN, ^monitor, ^kind, ^socket, _reason}, left(attempt.parent)

    assert_receive {:DOWN, ^allocator_monitor, :process, ^allocator, _reason},
                   left(attempt.parent)

    assert {:ok, %{roles: 17, observed_down: 17, losses: 0, cleanup: :confirmed}} =
             Reader.await(attempt.receipt, budget(attempt.parent))
  end

  defp start_actor(deadline) do
    {pid, monitor} =
      spawn_monitor(fn ->
        timer = :erlang.start_timer(deadline, self(), :expiry, abs: true)
        actor_loop(timer)
      end)

    on_exit(fn -> Process.exit(pid, :kill) end)
    {pid, monitor}
  end

  defp actor_loop(timer) do
    receive do
      {:run, caller, token, function} ->
        result =
          try do
            {:returned, function.()}
          catch
            kind, reason -> {:raised, kind, reason, __STACKTRACE__}
          end

        send(caller, {token, result})
        actor_loop(timer)

      {:timeout, ^timer, :expiry} ->
        :ok
    end
  end

  defp in_actor(pid, function, deadline) do
    token = make_ref()
    send(pid, {:run, self(), token, function})

    receive do
      {^token, {:returned, result}} -> result
      {^token, {:raised, kind, reason, stacktrace}} -> :erlang.raise(kind, reason, stacktrace)
    after
      left(deadline) ->
        flunk("authentication fixture did not finish within its original deadline")
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp left(deadline), do: max(0, deadline - now())
  defp budget(deadline), do: {:abs_ms, deadline}
end

defmodule SSL.Lifecycle.SocketConnectFailureArgumentsTest do
  use ExUnit.Case, async: true
  alias SSL.Lifecycle.Observer

  test "unsupported connect reasons reject before attempting receipt access" do
    for reason <- [:timeout, :closed, :eacces, :acceptance_unconfirmed, nil, "econnrefused"] do
      assert {:error, :invalid_connect_failure} =
               Observer.record_socket_connect_failure(:unused, :unused, reason, deadline())
    end
  end

  test "malformed native deadlines reject before attempting receipt access" do
    for native <- [:infinity, :later, {:abs_ms, :later}, {:abs_ms, 1.5}, {:abs_ms, 1, 2}] do
      assert {:error, :invalid_connect_failure} =
               Observer.record_socket_connect_failure(:unused, :unused, :econnrefused, native)
    end
  end

  test "an already expired integer native deadline rejects before receipt access" do
    assert {:error, :deadline_exceeded} =
             Observer.record_socket_connect_failure(
               :unused,
               :unused,
               :econnrefused,
               {:abs_ms, System.monotonic_time(:millisecond) - 1}
             )
  end

  defp deadline, do: {:abs_ms, System.monotonic_time(:millisecond) + 1_000}
end

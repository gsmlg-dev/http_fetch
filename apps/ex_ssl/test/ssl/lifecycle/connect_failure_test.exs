defmodule SSL.Lifecycle.ConnectFailureTest do
  use ExUnit.Case, async: false
  alias SSL.Options
  alias SSL.Lifecycle.{Allocator, Observer, Reader, Receipt, Setup}
  @moduletag :integration

  test "actual Allocator refusal records connect while retaining unknown TCP" do
    {context, _lease, _observer, listener} = actual_allocator()
    assert :ok = :gen_tcp.close(listener)
    {allocator, monitor} = start_allocator(context)
    assert_receive {:DOWN, ^monitor, :process, ^allocator, _reason}, 1_000
    refute_receive {:lifecycle_allocated, ^allocator, _, _, _}, 0

    assert {:ok,
            %{
              roles: 1,
              allocations: 16,
              setup: :failed,
              setup_failure: :connect,
              admission: :closed
            }} = Observer.snapshot(context.receipt, deadline())

    assert {:unconfirmed, :observer_unsealed} = Reader.await(context.receipt, deadline(2_000))
    assert :unsealed = Receipt.read(context.receipt)
  end

  test "actual Setup refusal records connect without claiming missing child identities" do
    a = setup_attempt()
    assert :ok = :gen_tcp.close(a.listener)
    {:ok, setup} = Setup.start(a.context)
    monitor = Process.monitor(setup)
    on_exit(fn -> Process.exit(setup, :kill) end)
    assert_receive {:DOWN, ^monitor, :process, ^setup, _reason}, 1_000
    refute_receive {:lifecycle_native_owned, ^setup, _, _, _, _}, 0
    refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0

    assert {:ok, %{setup: :failed, setup_failure: :connect, admission: :closed} = view} =
             Observer.snapshot(a.receipt, deadline())

    assert Bitwise.band(view.allocations, 16) == 16
    assert {:unconfirmed, :observer_unsealed} = Reader.await(a.receipt, deadline(2_000))
    assert :unsealed = Receipt.read(a.receipt)
  end

  # Cooperative actors test the private protocol, not real native failure attribution.
  test "cooperative ACK retains unknown TCP and original Root lease cancels every recognized error" do
    for reason <- [:econnrefused, :enetunreach, :ehostunreach] do
      a = cooperative()

      assert :ok =
               in_actor(a.allocator, fn ->
                 Observer.record_connect_failure(a.receipt, reason, deadline(3_000))
               end)

      assert Process.alive?(a.allocator)

      assert {:ok,
              %{
                roles: 1,
                observed_down: 0,
                allocations: 16,
                losses: 0,
                setup: :failed,
                setup_failure: :connect,
                admission: :closed
              }} = Observer.snapshot(a.receipt, deadline())

      assert :unsealed = Receipt.read(a.receipt)
      cancel_actor(a)
    end
  end

  for existing_ms <- [600, 5_000] do
    test "cooperative infinity has fixed expiry with original E #{existing_ms} and replay cannot renew" do
      a = cooperative()
      allocator = a.allocator
      monitor = Process.monitor(allocator)
      existing = deadline(unquote(existing_ms))

      assert :ok =
               in_actor(allocator, fn ->
                 Observer.record_connect_failure(a.receipt, :econnrefused, existing)
               end)

      assert Process.alive?(allocator)
      fence = min(elem(existing, 1), elem(deadline(1_000), 1))
      wait_until(fence - 300)

      assert {:error, _} =
               in_actor(allocator, fn ->
                 Observer.record_connect_failure(a.receipt, :econnrefused, deadline(5_000))
               end)

      wait_until(fence + 20)
      assert_receive {:DOWN, ^monitor, :process, ^allocator, _reason}, 150
      assert {:unconfirmed, :observer_unsealed} = Reader.await(a.receipt, deadline(2_000))
      assert :unsealed = Receipt.read(a.receipt)
    end
  end

  test "cooperative pending TCP and caller generations are required and unsupported reasons do not classify" do
    a = cooperative(false)
    assert {:error, _} = report(a)

    {:ok, token} =
      in_actor(a.allocator, fn -> Observer.reserve_child(a.receipt, :tcp, deadline()) end)

    setup = root_actor(a.receipt, a.lease, :setup)
    b = cooperative()
    assert {:error, _} = Observer.record_connect_failure(a.receipt, :econnrefused, deadline())

    for actor <- [setup, b.allocator] do
      assert {:error, _} =
               in_actor(actor, fn ->
                 Observer.record_connect_failure(a.receipt, :econnrefused, deadline())
               end)
    end

    for reason <- [:timeout, :closed, :eacces, :acceptance_unconfirmed] do
      assert {:error, _} =
               in_actor(a.allocator, fn ->
                 Observer.record_connect_failure(a.receipt, reason, deadline())
               end)
    end

    assert {:error, :deadline_exceeded} =
             in_actor(a.allocator, fn ->
               Observer.record_connect_failure(a.receipt, :econnrefused, deadline(-1))
             end)

    for {reason, existing, request} <- [
          {:timeout, deadline(2_000), deadline(200)},
          {:econnrefused, deadline(2_000), deadline(600)},
          {:econnrefused, deadline(-1), deadline(200)}
        ] do
      assert {:error, _} =
               in_actor(a.allocator, fn -> raw_record(a, reason, existing, request) end)
    end

    assert_pending(a, 16)

    assert :ok =
             in_actor(a.allocator, fn ->
               Observer.reject_before_native(a.receipt, :tcp, token, deadline())
             end)

    assert {:error, _} = report(a)
    assert_pending(a, 0)
    cancel_actor(a)
    cancel_actor(b)
  end

  test "cooperative writer_ready remains eligible before TCP failure" do
    a = cooperative()
    setup = root_actor(a.receipt, a.lease, :setup)
    connection = child_actor(a.receipt, setup, :connection)
    writer = child_actor(a.receipt, connection, :writer)

    assert {:ok, _nonce} =
             in_actor(writer, fn -> Observer.writer_ready(a.receipt, deadline(2_000)) end)

    assert :ok = report(a)
    for pid <- [a.allocator, setup, connection, writer], do: assert(Process.alive?(pid))

    assert {:ok, %{roles: 15, allocations: 16, setup_failure: :connect}} =
             Observer.snapshot(a.receipt, deadline())

    assert :unsealed = Receipt.read(a.receipt)
    cancel_actor(a)
  end

  test "cooperative queued live-R request from a now-dead original Allocator cannot classify" do
    a = cooperative()
    existing = deadline(2_000)
    request = deadline(250)
    assert :ok = :sys.suspend(a.observer)

    try do
      _request_id =
        in_actor(a.allocator, fn ->
          :gen_server.send_request(
            a.observer,
            {{:record_connect_failure, :econnrefused, existing}, request}
          )
        end)

      assert {:message_queue_len, 1} = Process.info(a.observer, :message_queue_len)
      allocator = a.allocator
      monitor = Process.monitor(allocator)
      Process.exit(allocator, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^allocator, :killed}, 150
      assert System.monotonic_time(:millisecond) < elem(request, 1)
    after
      :sys.resume(a.observer)
    end

    assert {:ok, %{setup: :failed, setup_failure: :internal, allocations: 16}} =
             Observer.snapshot(a.receipt, deadline())

    assert :unsealed = Receipt.read(a.receipt)
  end

  test "cooperative queued request past R cannot record while original E is still live" do
    a = cooperative()
    existing = deadline(2_000)
    request = deadline(150)
    assert :ok = :sys.suspend(a.observer)

    try do
      _request_id =
        in_actor(a.allocator, fn ->
          :gen_server.send_request(
            a.observer,
            {{:record_connect_failure, :econnrefused, existing}, request}
          )
        end)

      wait_until(elem(request, 1) + 20)
      assert System.monotonic_time(:millisecond) < elem(existing, 1)
    after
      :sys.resume(a.observer)
    end

    assert_pending(a, 16)
    cancel_actor(a)
  end

  defp actual_allocator do
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    observer = Receipt.observer(receipt)
    on_exit(fn -> if Process.alive?(observer), do: Process.exit(observer, :kill) end)
    budget = deadline(5_000)
    :ok = Observer.bind(receipt, lease, budget)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :allocator, budget)

    {:ok, listener} =
      :gen_tcp.listen(0, [
        {:inet_backend, :inet},
        :inet,
        :binary,
        active: false,
        packet: :raw,
        ip: {127, 0, 0, 1}
      ])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)

    context = %{
      receipt: receipt,
      permit: permit,
      ip: {127, 0, 0, 1},
      port: port,
      deadline: budget,
      recipient: self(),
      nonce: make_ref()
    }

    {context, lease, observer, listener}
  end

  defp start_allocator(context) do
    assert {:ok, allocator} = Allocator.start(context)
    monitor = Process.monitor(allocator)
    on_exit(fn -> Process.exit(allocator, :kill) end)
    {allocator, monitor}
  end

  defp setup_attempt do
    control_ms = 1_500
    original_ms = 5_000

    {:ok, listener} =
      :gen_tcp.listen(0, [
        {:inet_backend, :inet},
        :inet,
        :binary,
        active: false,
        packet: :raw,
        ip: {127, 0, 0, 1}
      ])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)
    original = deadline(original_ms)
    {:ok, receipt, lease} = Observer.start(self(), original)
    observer = Receipt.observer(receipt)
    on_exit(fn -> Process.exit(observer, :kill) end)
    assert :ok = Observer.bind(receipt, lease, original)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :setup, original)
    {:ok, allocation} = Observer.reserve_root(receipt, lease, :allocator, original)
    nonce = make_ref()
    classic = {self(), make_ref(), :atomics.new(1, []), %Options{}, elem(original, 1)}

    # Bootstrap consumes the classic horizon; store the actual clipped control E.
    requested = elem(deadline(control_ms), 1)
    control = {:abs_ms, min(requested, elem(original, 1))}

    context = %{
      receipt: receipt,
      permit: permit,
      allocator_permit: allocation,
      endpoint: {{127, 0, 0, 1}, port},
      classic: classic,
      control_deadline: control,
      ready: {self(), nonce}
    }

    %{
      context: context,
      receipt: receipt,
      lease: lease,
      observer: observer,
      listener: listener,
      nonce: nonce
    }
  end

  defp cooperative(pending \\ true) do
    {:ok, receipt, lease} = Observer.start(self(), :infinity)
    observer = Receipt.observer(receipt)
    on_exit(fn -> if Process.alive?(observer), do: Process.exit(observer, :kill) end)
    assert :ok = Observer.bind(receipt, lease, deadline())
    allocator = root_actor(receipt, lease, :allocator)

    token =
      if pending do
        {:ok, token} =
          in_actor(allocator, fn -> Observer.reserve_child(receipt, :tcp, deadline()) end)

        token
      end

    %{receipt: receipt, lease: lease, observer: observer, allocator: allocator, tcp_permit: token}
  end

  defp root_actor(receipt, lease, role) do
    {:ok, permit} = Observer.reserve_root(receipt, lease, role, deadline())
    enrolled_actor(receipt, role, permit, deadline())
  end

  defp child_actor(receipt, parent, role) do
    {:ok, permit} = in_actor(parent, fn -> Observer.reserve_child(receipt, role, deadline()) end)
    enrolled_actor(receipt, role, permit, deadline())
  end

  defp enrolled_actor(receipt, role, permit, budget) do
    pid = spawn(fn -> actor_loop() end)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    assert :use = in_actor(pid, fn -> Observer.enroll_self(receipt, role, permit, budget) end)
    pid
  end

  defp actor_loop do
    receive do
      :stop ->
        :ok

      {:run, caller, token, function} ->
        result =
          try do
            {:returned, function.()}
          catch
            kind, reason -> {:raised, kind, reason, __STACKTRACE__}
          end

        send(caller, {token, result})
        actor_loop()
    end
  end

  defp in_actor(pid, function) do
    token = make_ref()
    send(pid, {:run, self(), token, function})

    receive do
      {^token, {:returned, result}} -> result
      {^token, {:raised, kind, reason, stacktrace}} -> :erlang.raise(kind, reason, stacktrace)
    after
      1_500 -> flunk("enrolled actor did not finish its bounded operation")
    end
  end

  defp report(a),
    do:
      in_actor(a.allocator, fn ->
        Observer.record_connect_failure(a.receipt, :econnrefused, deadline(2_000))
      end)

  defp raw_record(a, reason, existing, request),
    do: GenServer.call(a.observer, {{:record_connect_failure, reason, existing}, request}, 500)

  defp assert_pending(a, allocations) do
    assert {:ok,
            %{setup: :pending, setup_failure: :none, admission: :open, allocations: ^allocations}} =
             Observer.snapshot(a.receipt, deadline())
  end

  defp cancel_actor(a) do
    allocator = a.allocator
    monitor = Process.monitor(allocator)
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    assert_receive {:DOWN, ^monitor, :process, ^allocator, _reason}, 250
  end

  defp wait_until(absolute) do
    timer = :erlang.start_timer(absolute, self(), :boundary, abs: true)
    assert_receive {:timeout, ^timer, :boundary}, 6_000
  end

  defp deadline(ms \\ 1_000), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

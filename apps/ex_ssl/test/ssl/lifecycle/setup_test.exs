defmodule SSL.Lifecycle.SetupTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  alias SSL.{Connection, Options, Socket}
  alias SSL.Lifecycle.{Observer, Reader, Receipt, Setup}

  test "actual setup orchestrates native ownership without TLS or setup success" do
    a = reserved() |> start() |> native_owned()
    assert Process.alive?(a.setup) and Process.alive?(a.writer)
    assert Port.info(a.tcp, :connected) == {:connected, a.socket.pid}
    assert a.socket.ref == elem(a.context.classic, 1)
    assert a.socket.status == elem(a.context.classic, 2)
    assert {:ok, [active: false]} = :inet.getopts(a.tcp, [:active])
    assert {:error, :timeout} = :gen_tcp.recv(a.peer, 0, 0)

    assert {:ok, %{roles: 31, setup: :pending, admission: :open}} =
             Observer.snapshot(a.receipt, deadline(500))

    assert {:error, :lifecycle_attach_not_implemented} =
             :gen_statem.call(a.socket.pid, {a.socket.ref, {:attach, a.tcp}}, 500)

    cancel(a)
  end

  test "foreign notifications and caller replays cannot spend or repeat the native candidate" do
    a = reserved()
    wrong = Task.async(fn -> Setup.start(a.context) end)
    assert {:error, :invalid_lifecycle_context} = Task.await(wrong, 500)
    assert {:error, :invalid_lifecycle_context} = Connection.start_inert(:invalid)

    expired = %{
      receipt: a.receipt,
      permit: make_ref(),
      control_deadline: deadline(-1),
      ready: {self(), make_ref()}
    }

    assert {:error, :deadline_exceeded} =
             Connection.start_inert({:inert, a.context.classic, expired})

    assert :ok = :sys.suspend(a.observer)

    a =
      try do
        a = start(a)
        send(a.setup, {:lifecycle_ready, self(), a.nonce})
        send(a.setup, {:lifecycle_allocated, self(), a.nonce, a.observer, a.listener})
        send(a.setup, {:timeout, make_ref(), :expiry})
        send(a.setup, {:DOWN, make_ref(), :process, self(), :normal})
        a
      after
        :sys.resume(a.observer)
      end

    a = native_owned(a)
    send(a.setup, {:lifecycle_ready, a.socket.pid, make_ref()})
    assert {:error, :closed} = GenServer.call(a.setup, {:native_owned, a.nonce}, 500)
    setup = a.setup
    nonce = a.nonce
    refute_receive {:lifecycle_native_owned, ^setup, ^nonce, _, _, _}, 0
    cancel(a)
  end

  test "Setup independently expires at original control D while Observer is suspended" do
    a = reserved(200) |> start() |> native_owned()
    assert Port.info(a.tcp, :connected) == {:connected, a.socket.pid}
    assert :ok = :sys.suspend(a.observer)

    try do
      assert Process.alive?(a.setup)
      setup = a.setup
      monitor = a.setup_monitor
      assert_receive {:DOWN, ^monitor, :process, ^setup, :normal}, 1_000
      assert System.monotonic_time(:millisecond) >= elem(a.context.control_deadline, 1)
      assert System.monotonic_time(:millisecond) < elem(a.context.classic, 4)
      assert Process.alive?(a.socket.pid) and Process.alive?(a.writer)
      assert Port.info(a.tcp, :connected) == {:connected, a.socket.pid}
    after
      :sys.resume(a.observer)
    end

    cleanup(a)
  end

  test "cancel before Setup birth keeps the unissued ROOT allocator permit unknown" do
    a = reserved()
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
    a = start(a)
    setup = a.setup
    monitor = a.setup_monitor
    assert_receive {:DOWN, ^monitor, :process, ^setup, _}, 1_000
    refute_receive {:lifecycle_native_owned, ^setup, _, _, _, _}, 0
    assert {:error, :timeout} = :gen_tcp.accept(a.listener, 0)
    assert {:unconfirmed, :observer_unsealed} = Reader.await(a.receipt, deadline(2_000))
    assert :unsealed = Receipt.read(a.receipt)
  end

  test "native refusal retains unresolved TCP identity instead of claiming cleanup" do
    a = reserved()
    assert :ok = :gen_tcp.close(a.listener)
    a = start(a)
    setup = a.setup
    monitor = a.setup_monitor
    assert_receive {:DOWN, ^monitor, :process, ^setup, _}, 1_000
    refute_receive {:lifecycle_native_owned, ^setup, _, _, _, _}, 0
    assert {:unconfirmed, :observer_unsealed} = Reader.await(a.receipt, deadline(2_000))
    assert :unsealed = Receipt.read(a.receipt)
  end

  test "unknown enrollment acceptance holds Setup past the SDK timeout until original D" do
    # A longer classic horizon isolates the unchanged 1500ms control budget and 1s SDK cap.
    a = reserved(1_500, 4_000)
    assert Options.remaining(elem(a.context.control_deadline, 1)) > 1_250
    assert :ok = :sys.suspend(a.observer)

    try do
      a = start(a)

      probe =
        :erlang.start_timer(elem(a.context.control_deadline, 1) - 250, self(), :probe, abs: true)

      assert_receive {:timeout, ^probe, :probe}, 1_500
      assert {:error, :closed} = GenServer.call(a.setup, :probe, 200)
      assert System.monotonic_time(:millisecond) < elem(a.context.control_deadline, 1)
      setup = a.setup
      monitor = a.setup_monitor
      assert_receive {:DOWN, ^monitor, :process, ^setup, :normal}, 1_000
      assert System.monotonic_time(:millisecond) >= elem(a.context.control_deadline, 1)
      assert {:error, :timeout} = :gen_tcp.accept(a.listener, 0)
    after
      :sys.resume(a.observer)
    end

    assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
    assert {:unconfirmed, :observer_unsealed} = Reader.await(a.receipt, deadline(2_000))
  end

  defp reserved(control_ms \\ 1_500, original_ms \\ 2_000) do
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

  defp start(a) do
    assert {:ok, setup} = Setup.start(a.context)
    monitor = Process.monitor(setup)
    on_exit(fn -> Process.exit(setup, :kill) end)
    Map.merge(a, %{setup: setup, setup_monitor: monitor})
  end

  defp native_owned(a) do
    {:ok, peer} = :gen_tcp.accept(a.listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    setup = a.setup
    nonce = a.nonce
    observer = a.observer

    assert_receive {:lifecycle_native_owned, ^setup, ^nonce, ^observer, %Socket{} = socket, tcp},
                   1_000

    tcp_monitor = :erlang.monitor(:port, tcp)
    on_exit(fn -> Process.exit(socket.pid, :kill) end)
    {:monitors, monitors} = Process.info(socket.pid, :monitors)
    owner = self()
    [writer] = for {:process, pid} <- monitors, pid not in [owner, observer], do: pid

    Map.merge(a, %{socket: socket, tcp: tcp, tcp_monitor: tcp_monitor, peer: peer, writer: writer})
  end

  defp cancel(a) do
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
    cleanup(a)
  end

  defp cleanup(a) do
    tcp = a.tcp
    monitor = a.tcp_monitor
    assert_receive {:DOWN, ^monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed}} =
             Reader.await(a.receipt, deadline(2_000))

    refute Process.alive?(a.observer)
  end

  defp deadline(milliseconds),
    do: {:abs_ms, System.monotonic_time(:millisecond) + milliseconds}
end

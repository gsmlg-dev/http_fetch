defmodule SSL.Lifecycle.NativeSocketSetupTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  alias SSL.{Options, Socket}
  alias SSL.Lifecycle.{Observer, Reader, Receipt, Setup}
  @ip {127, 0, 0, 1}

  test "actual Socket Setup owns the native graph without TLS readiness" do
    a = reserved() |> nonpassive() |> start() |> native_owned()
    assert {:ok, a.socket.pid} == :socket.getopt(a.tcp, :otp, :controlling_process)
    assert a.socket.ref == elem(a.context.classic, 1)
    assert a.socket.status == elem(a.context.classic, 2)

    assert {:ok, %{roles: 31, setup: :pending, admission: :open, allocations: 0}} =
             Observer.snapshot(a.receipt, deadline(500))

    assert {:error, :closed} = SSL.recv(a.socket, 0, 500)

    assert {:error, :private_active_mode_not_supported} =
             Setup.attach(a.setup, a.nonce, deadline(500))

    assert {:error, :timeout} = :gen_tcp.recv(a.peer, 0, 0)
    setup = a.setup
    refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
    cancel(a)
  end

  test "raw Setup preserves caller, recipient, nonce and deadline refusal" do
    a = reserved() |> nonpassive()
    wrong = Task.async(fn -> Setup.start_socket(a.context) end)
    assert {:error, :invalid_lifecycle_context} = Task.await(wrong, 500)
    foreign = %{a.context | ready: {a.observer, a.nonce}}
    assert {:error, :invalid_lifecycle_context} = Setup.start_socket(foreign)
    expired = %{a.context | control_deadline: deadline(-1)}
    assert {:error, :deadline_exceeded} = Setup.start_socket(expired)
    a = a |> start() |> native_owned()
    wrong = Task.async(fn -> Setup.attach(a.setup, a.nonce, deadline(500)) end)
    assert {:error, :unauthorized_attach} = Task.await(wrong, 500)
    assert {:error, :unauthorized_attach} = Setup.attach(a.setup, make_ref(), deadline(500))
    assert {:error, :deadline_exceeded} = Setup.attach(a.setup, a.nonce, deadline(-1))

    for _ <- 1..2 do
      assert {:error, :private_active_mode_not_supported} =
               Setup.attach(a.setup, a.nonce, deadline(500))
    end

    assert {:error, :timeout} = :gen_tcp.recv(a.peer, 0, 0)
    cancel(a)
  end

  test "raw pending graph expires under its original control deadline" do
    a = reserved(400) |> start() |> native_owned()
    cleanup(a)
    instant = System.monotonic_time(:millisecond)
    assert instant >= elem(a.context.control_deadline, 1)
    assert instant < elem(a.context.classic, 4)
  end

  test "ready recipient and application owner loss retires the real Socket graph" do
    {listener, port} = listener()
    parent = self()
    {owner, owner_monitor} = spawn_monitor(fn -> owner(parent, port) end)
    on_exit(fn -> Process.exit(owner, :kill) end)
    assert_receive {:reserved, ^owner, a}, 1_000
    a = a |> Map.put(:listener, listener) |> watch_observer()
    send(owner, :start)
    assert_receive {:started, ^owner, setup}, 1_000
    a = a |> watch_setup(setup) |> native_owned()
    send(owner, :stop)
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000
    cleanup(a)
  end

  defp nonpassive(a) do
    {owner, ref, status, options, original} = a.context.classic
    classic = {owner, ref, status, %{options | active: :once}, original}
    %{a | context: %{a.context | classic: classic}}
  end

  defp reserved(control_ms \\ 1_500) do
    {listener, port} = listener()
    reserve(port, control_ms) |> Map.put(:listener, listener) |> watch_observer()
  end

  defp reserve(port, control_ms) do
    original = deadline(5_000)
    {:ok, receipt, lease} = Observer.start(self(), original)
    :ok = Observer.bind(receipt, lease, original)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :setup, original)
    {:ok, allocation} = Observer.reserve_root(receipt, lease, :allocator, original)
    nonce = make_ref()
    classic = {self(), make_ref(), :atomics.new(1, []), %Options{}, elem(original, 1)}
    control = {:abs_ms, min(elem(deadline(control_ms), 1), elem(original, 1))}

    context = %{
      receipt: receipt,
      permit: permit,
      allocator_permit: allocation,
      endpoint: {@ip, port},
      classic: classic,
      control_deadline: control,
      ready: {self(), nonce}
    }

    %{
      context: context,
      receipt: receipt,
      lease: lease,
      observer: Receipt.observer(receipt),
      nonce: nonce
    }
  end

  defp watch_observer(a) do
    observer = a.observer
    monitor = Process.monitor(observer)
    on_exit(fn -> Process.exit(observer, :kill) end)
    Map.put(a, :observer_monitor, monitor)
  end

  defp start(a) do
    assert {:ok, setup} = Setup.start_socket(a.context)
    watch_setup(a, setup)
  end

  defp watch_setup(a, setup) do
    monitor = Process.monitor(setup)
    on_exit(fn -> Process.exit(setup, :kill) end)
    Map.merge(a, %{setup: setup, setup_monitor: monitor})
  end

  defp native_owned(a) do
    setup = a.setup
    nonce = a.nonce
    observer = a.observer

    assert_receive {:lifecycle_native_owned, ^setup, ^nonce, ^observer, %Socket{} = socket, tcp},
                   1_000

    tcp_monitor = :socket.monitor(tcp)
    connection_monitor = Process.monitor(socket.pid)
    on_exit(fn -> Process.exit(socket.pid, :kill) end)
    assert {:ok, socket.pid} == :socket.getopt(tcp, :otp, :controlling_process)
    {:monitors, monitors} = Process.info(socket.pid, :monitors)
    owner = elem(a.context.classic, 0)
    [writer] = for {:process, pid} <- monitors, pid not in [owner, observer, setup], do: pid
    writer_monitor = Process.monitor(writer)
    assert {:ok, peer} = :gen_tcp.accept(a.listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)

    Map.merge(a, %{
      socket: socket,
      tcp: tcp,
      tcp_monitor: tcp_monitor,
      connection_monitor: connection_monitor,
      writer: writer,
      writer_monitor: writer_monitor,
      peer: peer
    })
  end

  defp cancel(a) do
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
    cleanup(a)
  end

  defp cleanup(a) do
    for {pid, monitor} <- [
          {a.setup, a.setup_monitor},
          {a.socket.pid, a.connection_monitor},
          {a.writer, a.writer_monitor}
        ] do
      assert_receive {:DOWN, ^monitor, :process, ^pid, _reason}, 1_000
    end

    tcp = a.tcp
    tcp_monitor = a.tcp_monitor
    assert_receive {:DOWN, ^tcp_monitor, :socket, ^tcp, :closed}, 1_000
    assert {:error, reason} = :gen_tcp.recv(a.peer, 0, 1_000)
    assert reason in [:closed, :econnreset]

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed}} =
             Reader.await(a.receipt, deadline(2_000))

    observer = a.observer
    observer_monitor = a.observer_monitor
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, _reason}, 1_000
  end

  defp owner(parent, port) do
    a = reserve(port, 1_500)
    send(parent, {:reserved, self(), a})

    receive do
      :start ->
        {:ok, setup} = Setup.start_socket(a.context)
        send(parent, {:started, self(), setup})
        relay(parent)
    end
  end

  defp relay(parent) do
    receive do
      {:lifecycle_native_owned, _, _, _, _, _} = notice ->
        send(parent, notice)
        relay(parent)

      :stop ->
        :ok
    end
  end

  defp listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        {:inet_backend, :inet},
        :inet,
        :binary,
        active: false,
        packet: :raw,
        ip: @ip
      ])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {@ip, port}} = :inet.sockname(listener)
    {listener, port}
  end

  defp deadline(milliseconds),
    do: {:abs_ms, System.monotonic_time(:millisecond) + milliseconds}
end

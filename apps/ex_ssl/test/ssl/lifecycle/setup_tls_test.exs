defmodule SSL.Lifecycle.SetupTLSTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.{Options, Socket}
  alias SSL.Lifecycle.{Observer, Reader, Receipt, Setup}
  @moduletag :integration

  test "actual private TLS publishes success then retires Setup without enabling public I/O" do
    with_peer(fn peer ->
      a = attempt(peer.port)
      wrong = Task.async(fn -> Setup.attach(a.setup, a.nonce, deadline(1_000)) end)
      assert {:error, :unauthorized_attach} = Task.await(wrong, 1_000)
      assert {:error, :unauthorized_attach} = Setup.attach(a.setup, make_ref(), deadline(1_000))

      assert {:error, :unauthorized_attach} =
               :gen_statem.call(
                 a.socket.pid,
                 {a.socket.ref,
                  {:lifecycle_attach, make_ref(), a.observer, make_ref(), deadline(500)}},
                 500
               )

      refute_receive {:peer_connected, _}, 0
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      # Former native, publication and classic timers cannot become lifetime caps.
      wait_until(elem(a.classic, 4) + 20)
      alive(a)

      assert {:error, :closed} =
               :gen_statem.call(a.socket.pid, {a.socket.ref, {:recv, 0, :infinity}}, 500)

      refute_receive {:ssl, _, _}, 0
      cancel(a)
    end)
  end

  for original <- [5_000, :infinity] do
    test "authenticated admission lifts native E into original handshake #{original}" do
      with_peer(fn peer ->
        with_gate(peer, fn proxy ->
          a = attempt(proxy.port, unquote(original), [], 500)
          assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
          ref = proxy.ref
          assert_receive {:tls_record_proxy, ^ref, :queued, _}, 1_000
          wait_until(elem(a.control, 1) + 20)
          alive(a)
          send(a.setup, {:timeout, nil, :expiry})
          send(a.setup, {:timeout, make_ref(), :expiry})
          assert {:error, :closed} = GenServer.call(a.setup, :probe, 500)
          assert Process.alive?(a.setup)
          assert {:error, :attach_spent} = Setup.attach(a.setup, a.nonce, deadline(1_000))
          # Finite bounded permits release this owned peer flight; no polling.
          for _ <- 1..32, do: Peer.release_server_record(proxy)
          success(a)
          wait_until(System.monotonic_time(:millisecond) + 1_100)
          alive(a)
          cancel(a)
        end)
      end)
    end
  end

  test "nonpassive private TLS is rejected repeatedly without sending a ClientHello" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])

    try do
      {:ok, {_ip, port}} = :inet.sockname(listener)
      a = attempt(port, 5_000, active: :once)
      {:ok, peer} = :gen_tcp.accept(listener, 1_000)

      try do
        for _ <- 1..2 do
          assert {:error, :private_active_mode_not_supported} =
                   Setup.attach(a.setup, a.nonce, deadline(500))
        end

        assert {:error, :timeout} = :gen_tcp.recv(peer, 0, 0)
        alive(a)
        cancel(a)
      after
        :gen_tcp.close(peer)
      end
    after
      :gen_tcp.close(listener)
    end
  end

  test "real certificate failure has typed cleanup and no successful Root candidate" do
    with_peer(fn peer ->
      a = attempt(peer.port, 5_000, server_name_indication: ~c"wrong.example.test")
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      setup = a.setup
      monitor = a.monitor
      assert_receive {:DOWN, ^monitor, :process, ^setup, _}, 5_000
      refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0

      assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed}} =
               Reader.await(a.receipt, deadline(2_000))
    end)
  end

  test "unknown successful publication holds until its finite completion budget" do
    with_peer(fn peer ->
      a = attempt(peer.port)
      assert :ok = :sys.suspend(a.observer)

      try do
        entered = System.monotonic_time(:millisecond)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        assert_receive {:peer_connected, _}, 2_000
        assert Process.alive?(a.setup)
        setup = a.setup
        monitor = a.monitor
        assert_receive {:DOWN, ^monitor, :process, ^setup, :normal}, 2_000
        assert System.monotonic_time(:millisecond) >= entered + 1_000
        refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
        alive(a)
      after
        :sys.resume(a.observer)
      end

      assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed}} =
               Reader.await(a.receipt, deadline(2_000))
    end)
  end

  test "private TLS success waits for the actual Finished Writer acknowledgement" do
    with_peer(fn peer ->
      with_gate(peer, fn proxy ->
        a = attempt(proxy.port)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        ref = proxy.ref
        assert_receive {:tls_record_proxy, ^ref, :queued, _}, 1_000
        assert true = :erlang.suspend_process(a.writer)

        try do
          for _ <- 1..32, do: Peer.release_server_record(proxy)
          wait_until(System.monotonic_time(:millisecond) + 200)
          setup = a.setup
          refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
          refute_receive {:peer_connected, _}, 0
          assert {:ok, %{setup: :pending}} = Observer.snapshot(a.receipt, deadline(500))
          alive(a)
        after
          if Process.alive?(a.writer), do: :erlang.resume_process(a.writer)
        end

        success(a)
        cancel(a)
      end)
    end)
  end

  test "private actual TLS also interoperates with the existing OpenSSL peer" do
    {:ok, peer} = Peer.start_openssl()

    try do
      a = attempt(peer.port)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      cancel(a)
    after
      Peer.stop_openssl(peer)
    end
  end

  defp attempt(port, original_ms \\ 5_000, overrides \\ [], control_ms \\ 1_500) do
    options = Peer.client_options() |> Enum.reject(&(&1 == :binary)) |> Keyword.merge(overrides)
    {:ok, options} = Options.normalize("exssl.test", options)
    original = if original_ms == :infinity, do: :infinity, else: elem(deadline(original_ms), 1)
    observer_d = if original == :infinity, do: :infinity, else: {:abs_ms, original}
    {:ok, receipt, lease} = Observer.start(self(), observer_d)
    observer = Receipt.observer(receipt)
    on_exit(fn -> Process.exit(observer, :kill) end)
    bootstrap = deadline(1_000)
    :ok = Observer.bind(receipt, lease, bootstrap)
    {:ok, permit} = Observer.reserve_root(receipt, lease, :setup, bootstrap)
    {:ok, allocator_permit} = Observer.reserve_root(receipt, lease, :allocator, bootstrap)
    nonce = make_ref()
    classic = {self(), make_ref(), :atomics.new(1, []), options, original}
    requested = elem(deadline(control_ms), 1)
    control = {:abs_ms, if(original == :infinity, do: requested, else: min(requested, original))}

    context = %{
      receipt: receipt,
      permit: permit,
      allocator_permit: allocator_permit,
      endpoint: {{127, 0, 0, 1}, port},
      classic: classic,
      control_deadline: control,
      ready: {self(), nonce}
    }

    {:ok, setup} = Setup.start(context)
    monitor = Process.monitor(setup)
    on_exit(fn -> Process.exit(setup, :kill) end)

    assert_receive {:lifecycle_native_owned, ^setup, ^nonce, ^observer, %Socket{} = socket, tcp},
                   1_000

    tcp_monitor = :erlang.monitor(:port, tcp)
    {:monitors, monitors} = Process.info(socket.pid, :monitors)
    owner = self()
    [writer] = for {:process, pid} <- monitors, pid not in [owner, observer], do: pid

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      setup: setup,
      nonce: nonce,
      socket: socket,
      tcp: tcp,
      tcp_monitor: tcp_monitor,
      writer: writer,
      classic: classic,
      control: control,
      monitor: monitor
    }
  end

  defp success(a) do
    setup = a.setup
    nonce = a.nonce
    observer = a.observer
    socket = a.socket
    assert_receive {:lifecycle_tls_ready, ^setup, ^nonce, ^observer, ^socket}, 5_000
    monitor = a.monitor
    assert_receive {:DOWN, ^monitor, :process, ^setup, :normal}, 1_000

    assert {:ok, %{setup: :connected, admission: :open}} =
             Observer.snapshot(a.receipt, deadline(500))

    alive(a)
  end

  defp alive(a) do
    assert Process.alive?(a.socket.pid) and Process.alive?(a.writer)
    assert Port.info(a.tcp, :connected) == {:connected, a.socket.pid}
  end

  defp cancel(a) do
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
    tcp = a.tcp
    monitor = a.tcp_monitor
    assert_receive {:DOWN, ^monitor, :port, ^tcp, _}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed}} =
             Reader.await(a.receipt, deadline(2_000))
  end

  defp with_peer(fun) do
    parent = self()
    tag = make_ref()

    {:ok, peer} =
      Peer.start(fn socket ->
        :ok = :ssl.send(socket, "private")
        send(parent, {:peer_connected, tag})

        receive do
          {:finish, ^tag} -> :ssl.close(socket)
        end
      end)

    try do
      fun.(peer)
    after
      send(peer.task.pid, {:finish, tag})
      Peer.stop(peer)
    end
  end

  defp with_gate(peer, fun) do
    {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self(), initially_gated: true)

    try do
      fun.(proxy)
    after
      if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
    end
  end

  defp wait_until(absolute) do
    timer = :erlang.start_timer(absolute, self(), :boundary, abs: true)
    assert_receive {:timeout, ^timer, :boundary}, 6_000
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

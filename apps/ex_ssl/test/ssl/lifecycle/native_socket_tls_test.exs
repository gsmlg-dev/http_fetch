defmodule SSL.Lifecycle.NativeSocketTLSTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @wrong_ca Path.expand("../../fixtures/pkix/wrong_root.pem", __DIR__)
            |> File.read!()
            |> :public_key.pem_decode()
            |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)
  @static_ca Path.expand("../../fixtures/server_flight/root.pem", __DIR__)
             |> File.read!()
             |> :public_key.pem_decode()
             |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)
  @tls12_cipher %{key_exchange: :ecdhe_rsa, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}
  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias SSL.{Options, Socket}
  alias SSL.Lifecycle.{Observer, Reader, Receipt, Setup}

  test "raw Socket authenticates OTP TLS 1.3 and exchanges protected bytes privately" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:ok, "request"} = :ssl.recv(socket, 7, 2_000)
        :ok = :ssl.send(socket, "response")
        send(parent, :exchanged)
        receive do: (:finish -> :ssl.close(socket))
      end)

    try do
      a = attempt(peer.port)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      assert {:error, :closed} = SSL.recv(a.socket, 0, 100)
      assert :ok = private_send(a, "request")
      assert {:ok, "response"} = private_io(a, {:recv, 8, absolute(2_000)})
      assert_receive :exchanged, 1_000
      assert :ok = private_io(a, :close)
      cleanup(a)
    after
      send(peer.task.pid, :finish)
      Peer.stop(peer)
    end
  end

  test "raw Socket rejects the OTP TLS 1.2 peer without required EMS and confirms cleanup" do
    # TLS12MachineTest independently asserts this peer's missing ServerHello
    # extension 23 and the exact :extended_master_secret_required rejection.
    # The supported TLS 1.2 multi-record success case uses OpenSSL below.
    {:ok, peer} =
      Peer.start(
        fn _socket -> flunk("a peer without EMS must not authenticate") end,
        ssl_options: [versions: [:"tlsv1.2"], ciphers: [@tls12_cipher]]
      )

    try do
      a = attempt(peer.port, versions: [:"tlsv1.2"], ciphers: [@tls12_cipher])
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      assert {:error, :closed} = SSL.recv(a.socket, 0, 100)
      setup = a.setup
      monitor = a.setup_monitor
      assert_receive {:DOWN, ^monitor, :process, ^setup, _}, 5_000
      refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
      cleanup(a, :failed)
      assert {:sealed, %{setup_failure: :tls}} = Receipt.read(a.receipt)
    after
      assert {:handshake_error, {:tls_alert, {:handshake_failure, _}}} = Peer.stop(peer)
    end
  end

  test "raw Socket authenticates independent OpenSSL and reads its protected HTTP response" do
    {:ok, peer} = Peer.start_openssl()

    try do
      a = attempt(peer.port)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      assert :ok = private_send(a, "GET / HTTP/1.0\r\nHost: exssl.test\r\n\r\n")
      assert {:ok, <<"HTTP/1.0 200", _::binary>>} = private_io(a, {:recv, 0, absolute(2_000)})
      assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
      cleanup(a)
    after
      Peer.stop_openssl(peer)
    end
  end

  test "raw Socket authenticates independent OpenSSL TLS 1.2 and exchanges protected frames" do
    peer = openssl12()

    try do
      a = attempt(peer.port, static_options())
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)

      assert {:ok, %{"version" => "TLSv1.2"}} =
               ExSSL.TestSupport.OpenSSLPeer.event(peer, "handshake", 2_000)

      payload = :binary.copy("bounded-native-openssl", 8_000)
      frame = <<byte_size(payload)::32, payload::binary>>
      assert :ok = private_send(a, frame)
      assert {:ok, ^frame} = private_io(a, {:recv, byte_size(frame), absolute(3_000)})

      assert {:ok, %{"bytes" => bytes}} =
               ExSSL.TestSupport.OpenSSLPeer.event(peer, "exchange", 2_000)

      assert bytes == byte_size(payload)
      cleanup(a)
    after
      ExSSL.TestSupport.OpenSSLPeer.stop(peer)
    end
  end

  test "independent TCP EOF without close_notify retires the raw TLS graph" do
    peer = openssl12(abrupt_close: true)

    try do
      a = attempt(peer.port, static_options())
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      assert {:ok, _} = ExSSL.TestSupport.OpenSSLPeer.event(peer, "handshake", 2_000)
      assert :ok = private_send(a, <<4::32, "echo">>)
      assert {:ok, <<4::32, "echo">>} = private_io(a, {:recv, 8, absolute(2_000)})
      assert {:ok, _} = ExSSL.TestSupport.OpenSSLPeer.event(peer, "exchange", 2_000)
      assert {:ok, _} = ExSSL.TestSupport.OpenSSLPeer.event(peer, "close_ready", 2_000)
      assert true = Port.command(peer.handle, "close\n")
      cleanup(a)
    after
      ExSSL.TestSupport.OpenSSLPeer.stop(peer)
    end
  end

  test "independent peer fatal alert records failed TLS with original raw Socket evidence" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_ip, port}} = :inet.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
        assert {:ok, <<22, _::binary>>} = :gen_tcp.recv(tcp, 0, 2_000)
        :ok = :gen_tcp.send(tcp, <<21, 3, 3, 0, 2, 2, 40>>)
        result = :gen_tcp.recv(tcp, 0, 2_000)
        :gen_tcp.close(tcp)
        result
      end)

    try do
      a = attempt(port)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      setup = a.setup
      monitor = a.setup_monitor
      assert_receive {:DOWN, ^monitor, :process, ^setup, _}, 5_000
      refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
      cleanup(a, :failed)
      assert {:sealed, %{setup_failure: :tls}} = Receipt.read(a.receipt)
      assert {:error, reason} = Task.await(peer, 2_000)
      assert reason in [:closed, :econnreset]
    after
      :gen_tcp.close(listener)
    end
  end

  for action <- [:drain, :cancel, :close] do
    test "buffered authenticated close_notify retains truthful resources until #{action}" do
      parent = self()

      {:ok, peer} =
        Peer.start(fn socket ->
          :ok = :ssl.send(socket, "retained-plaintext")
          send(parent, :peer_closing)
          :ssl.close(socket)
        end)

      try do
        a = attempt(peer.port)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        success(a)
        assert_receive :peer_closing, 1_000
        await_retained(a)
        assert Process.alive?(a.socket.pid) and Process.alive?(a.writer)
        assert {:ok, a.socket.pid} == :socket.getopt(a.tcp, :otp, :controlling_process)
        assert {:pending, _} = Reader.await(a.receipt, deadline(10))
        assert :unsealed = Receipt.read(a.receipt)
        assert {:error, :closed} = private_io(a, :reserve_write)

        case unquote(action) do
          :drain -> assert {:ok, "retained-plaintext"} = private_io(a, {:recv, 0, absolute(500)})
          :cancel -> assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
          :close -> assert :ok = private_io(a, :close)
        end

        cleanup(a)
      after
        Peer.stop(peer)
      end
    end
  end

  test "actual application-owner death retires a raw TLS socket with retained plaintext" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        :ok = :ssl.send(socket, "retained-plaintext")
        :ssl.close(socket)
      end)

    {owner, owner_monitor} =
      spawn_monitor(fn ->
        a = attempt(peer.port, [], 1_500, fn _ -> :ok end)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        success(a)
        send(parent, {:owned, self(), a})
        receive do: (:stop -> :ok)
      end)

    on_exit(fn -> Process.exit(owner, :kill) end)

    try do
      assert_receive {:owned, ^owner, a}, 5_000
      on_exit(fn -> Process.exit(a.observer, :kill) end)
      on_exit(fn -> Process.exit(a.socket.pid, :kill) end)

      a = %{
        a
        | connection_monitor: Process.monitor(a.socket.pid),
          writer_monitor: Process.monitor(a.writer),
          tcp_monitor: :socket.monitor(a.tcp),
          observer_monitor: Process.monitor(a.observer)
      }

      await_retained(a)
      assert {:pending, _} = Reader.await(a.receipt, deadline(10))
      send(owner, :stop)
      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000
      cleanup(a)
    after
      Peer.stop(peer)
    end
  end

  for {label, overrides} <- [
        {:wrong_name, [server_name_indication: ~c"wrong.example.test"]},
        {:wrong_ca, [cacerts: @wrong_ca]}
      ] do
    test "raw TLS authentication failure #{label} preserves failed TLS evidence" do
      {:ok, peer} = Peer.start(fn socket -> :ssl.close(socket) end)

      try do
        a = attempt(peer.port, unquote(Macro.escape(overrides)))
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        setup = a.setup
        monitor = a.setup_monitor
        assert_receive {:DOWN, ^monitor, :process, ^setup, _}, 5_000
        refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
        cleanup(a, :failed)
        assert {:sealed, %{setup_failure: :tls}} = Receipt.read(a.receipt)
      after
        Peer.stop(peer)
      end
    end
  end

  for original <- [5_000, :infinity] do
    test "raw TLS Finished writer ACK retains original handshake budget #{original}" do
      parent = self()

      {:ok, peer} =
        Peer.start(fn socket ->
          send(parent, :authenticated)
          receive do: (:finish -> :ssl.close(socket))
        end)

      {:ok, proxy} = Peer.start_record_gate_proxy(peer.port, self(), initially_gated: true)

      try do
        a = attempt(proxy.port, [], 500, &on_exit/1, unquote(original))
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        ref = proxy.ref
        assert_receive {:tls_record_proxy, ^ref, :queued, _}, 1_000
        assert true = :erlang.suspend_process(a.writer)

        try do
          for _ <- 1..32, do: Peer.release_server_record(proxy)
          wait_until(elem(a.control, 1) + 20)
          setup = a.setup
          refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
          refute_receive :authenticated, 0
          assert {:ok, %{setup: :pending}} = Observer.snapshot(a.receipt, deadline(500))
        after
          if Process.alive?(a.writer), do: :erlang.resume_process(a.writer)
        end

        success(a)
        assert_receive :authenticated, 1_000
        assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
        cleanup(a)
      after
        send(peer.task.pid, :finish)
        if Process.alive?(proxy.task.pid), do: Peer.stop_record_gate_proxy(proxy)
        Peer.stop(peer)
      end
    end
  end

  test "stale native readiness, abort and writer ACK cannot advance the private stream" do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        send(parent, :waiting)
        receive do: (:finish -> :ssl.close(socket))
      end)

    try do
      a = attempt(peer.port)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      assert_receive :waiting, 1_000

      for _ <- 1..4 do
        send(a.socket.pid, {:"$socket", a.tcp, :select, make_ref()})
        send(a.socket.pid, {:"$socket", a.tcp, :abort, {make_ref(), :closed}})
        send(a.socket.pid, {:writer_result, a.writer, make_ref(), :ok})
      end

      foreign = Task.async(fn -> private_io(a, {:recv, 0, absolute(100)}) end)
      assert {:error, :unauthorized_private_io} = Task.await(foreign, 1_000)
      assert {:error, :timeout} = private_io(a, {:recv, 0, absolute(50)})
      assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
      cleanup(a)
    after
      send(peer.task.pid, :finish)
      Peer.stop(peer)
    end
  end

  for operation <- [:cancel, :timeout] do
    test "raw TLS pending handshake #{operation} terminates every original resource" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
      {:ok, {_ip, port}} = :inet.sockname(listener)
      parent = self()

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 2_000)
          assert {:ok, <<22, _::binary>>} = :gen_tcp.recv(tcp, 0, 2_000)
          send(parent, :client_hello_observed)
          result = :gen_tcp.recv(tcp, 0, 2_000)
          :gen_tcp.close(tcp)
          result
        end)

      try do
        original = if unquote(operation) == :timeout, do: 750, else: 5_000
        a = attempt(port, [], 1_500, &on_exit/1, original)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(500))
        assert_receive :client_hello_observed, 1_000

        if unquote(operation) == :cancel,
          do: assert(:ok = Observer.cancel(a.receipt, a.lease, deadline(500)))

        cleanup(a, :cancelled)
        setup = a.setup
        refute_receive {:lifecycle_tls_ready, ^setup, _, _, _}, 0
        assert {:error, reason} = Task.await(peer, 2_000)
        assert reason in [:closed, :econnreset]
      after
        :gen_tcp.close(listener)
      end
    end
  end

  test "fragmented independent TCP flights preserve native TLS record and application boundaries" do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:ok, "fragmented-request"} = :ssl.recv(socket, 18, 3_000)
        :ok = :ssl.send(socket, "fragmented-response")
        receive do: (:finish -> :ssl.close(socket))
      end)

    {:ok, proxy} = Peer.start_fragmenting_proxy(peer.port, self())

    try do
      a = attempt(proxy.port)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      assert :ok = private_send(a, "fragmented-request")
      assert {:ok, "fragmented-response"} = private_io(a, {:recv, 19, absolute(2_000)})
      assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
      cleanup(a)
    after
      send(peer.task.pid, :finish)
      Peer.stop_fragmenting_proxy(proxy)
      Peer.stop(peer)
    end
  end

  for {timing, payload_size} <- [
        ordinary: 16_384,
        ordinary: 65_536,
        before_abandon: 65_536,
        after_abandon: 65_536
      ] do
    test "raw Socket queues mandatory control #{timing} for #{payload_size} bytes" do
      assert_native_control_case(unquote(timing), unquote(payload_size))
    end
  end

  defp assert_native_control_case(timing, size) do
    expected = if timing == :ordinary, do: size, else: 16_384
    peer = control_peer(expected, timing == :ordinary)

    try do
      a = attempt(peer.port, send_timeout: 2_000)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      assert :ok = private_io(a, :enable_duplex_reads)
      {:connected, initial} = :sys.get_state(a.socket.pid)
      assert true = :erlang.suspend_process(a.writer)
      request = private_send_request(a, :binary.copy("x", size))
      held = native_state(a, &match?(%{output: %{kind: :application}}, &1))

      if timing == :before_abandon do
        assert :ok = private_io(a, :abandon_send)
        assert {:reply, {:error, :write_abandoned}} = :gen_statem.wait_response(request, 1_000)
      end

      send(peer.task.pid, :update)
      queued = native_state(a, &match?(%{pending_control: %{kind: :control}}, &1))
      assert queued.output == held.output
      assert queued.pending_control.size == 27
      assert_control_ciphertext(queued.pending_control, held.machine.write_state)
      assert queued.pending_control.deadline <= held.output.deadline
      assert queued.machine.read_state.generation == initial.machine.read_state.generation + 1
      assert queued.machine.write_state.generation == initial.machine.write_state.generation + 1
      assert queued.machine.write_state.sequence == 0
      assert {:pending, _} = Reader.await(a.receipt, deadline(10))
      assert :unsealed = Receipt.read(a.receipt)
      assert {:ok, a.socket.pid} == :socket.getopt(a.tcp, :otp, :controlling_process)

      if timing == :after_abandon do
        assert :ok = private_io(a, :abandon_send)
        assert {:reply, {:error, :write_abandoned}} = :gen_statem.wait_response(request, 1_000)
      end

      send(a.socket.pid, {:writer_result, a.writer, queued.pending_control.token, :ok})
      send(a.socket.pid, {:writer_result, self(), held.output.token, :ok})
      send(a.socket.pid, {:output_timeout, make_ref()})
      {:connected, unchanged} = :sys.get_state(a.socket.pid)
      assert unchanged.output == held.output
      assert unchanged.pending_control == queued.pending_control
      assert unchanged.machine == queued.machine

      if timing != :ordinary do
        assert unchanged.write == nil
        assert unchanged.write_abandoned?
        assert Process.read_timer(held.write.timer) == false
        assert {:error, :closed} = private_io(a, :reserve_write)
      else
        assert :timeout = :gen_statem.wait_response(request, 0)
      end

      active = native_dispatch_held(a, queued)
      assert active.machine.write_state == queued.machine.write_state
      if timing == :ordinary, do: assert(:timeout == :gen_statem.wait_response(request, 0))
      assert true = :erlang.resume_process(a.writer)

      if timing == :ordinary do
        assert {:reply, :ok} = :gen_statem.wait_response(request, 1_000)
        assert :ok = private_send(a, "client-after-update")
      end

      response = private_io(a, {:recv, 16, absolute(1_000)})
      {:connected, received} = :sys.get_state(a.socket.pid)

      assert {:ok, "control-received"} == response,
             "native response=#{inspect(response)} armed=#{received.armed} " <>
               "buffered=#{received.size} input=#{received.input_size} " <>
               "output=#{inspect(received.output && received.output.kind)}"

      assert :ok = private_io(a, :close)
      cleanup(a)
      send(peer.task.pid, :finish)
      assert :ok = Peer.stop(peer)
    after
      stop_control_peer(peer)
    end
  end

  for abandon? <- [false, true] do
    test "raw Socket pending control keeps original deadline abandon=#{abandon?}" do
      peer = held_control_peer()

      try do
        a = attempt(peer.port, send_timeout: 250)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        success(a)
        assert :ok = private_io(a, :enable_duplex_reads)
        assert true = :erlang.suspend_process(a.writer)
        request = private_send_request(a, :binary.copy("x", 65_536))
        held = native_state(a, &match?(%{output: %{kind: :application}}, &1))
        send(peer.task.pid, :update)
        queued = native_state(a, &match?(%{pending_control: %{kind: :control}}, &1))
        assert queued.output == held.output
        assert queued.pending_control.deadline <= held.write.deadline

        if unquote(abandon?) do
          assert :ok = private_io(a, :abandon_send)
          assert {:reply, {:error, :write_abandoned}} = :gen_statem.wait_response(request, 1_000)
        end

        cleanup(a)

        unless unquote(abandon?),
          do: assert({:reply, {:error, :timeout}} == :gen_statem.wait_response(request, 0))

        assert Process.read_timer(queued.pending_control.timer) == false
        assert Process.read_timer(held.output.timer) == false
      after
        send(peer.task.pid, :finish)
        Peer.stop(peer)
      end
    end
  end

  for operation <- [:cancel, :close, :writer_down] do
    test "raw Socket pending mandatory control #{operation} observes original typed cleanup" do
      peer = held_control_peer()

      try do
        a = attempt(peer.port, send_timeout: 2_000)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        success(a)
        assert :ok = private_io(a, :enable_duplex_reads)
        assert true = :erlang.suspend_process(a.writer)
        request = private_send_request(a, :binary.copy("x", 65_536))
        held = native_state(a, &match?(%{output: %{kind: :application}}, &1))
        send(peer.task.pid, :update)
        queued = native_state(a, &match?(%{pending_control: %{kind: :control}}, &1))
        assert queued.output == held.output
        assert {:pending, _} = Reader.await(a.receipt, deadline(10))
        assert :unsealed = Receipt.read(a.receipt)

        case unquote(operation) do
          :cancel -> assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
          :close -> assert :ok = private_io(a, :close)
          :writer_down -> Process.exit(a.writer, :kill)
        end

        cleanup(a)

        case :gen_statem.wait_response(request, 0) do
          {:reply, {:error, reason}} -> assert reason in [:closed, :econnreset]
          {:error, {reason, _server}} -> assert reason in [:normal, :noproc, :shutdown, :killed]
        end

        assert Process.read_timer(queued.pending_control.timer) == false
      after
        send(peer.task.pid, :finish)
        Peer.stop(peer)
      end
    end
  end

  test "raw Socket owner death aborts pending mandatory control with original identities" do
    parent = self()
    peer = held_control_peer()

    {owner, owner_monitor} =
      spawn_monitor(fn ->
        a = attempt(peer.port, [send_timeout: 2_000], 1_500, fn _ -> :ok end)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        success(a)
        assert :ok = private_io(a, :enable_duplex_reads)
        assert true = :erlang.suspend_process(a.writer)
        _request = private_send_request(a, :binary.copy("x", 65_536))
        native_state(a, &match?(%{output: %{kind: :application}}, &1))
        send(peer.task.pid, :update)
        queued = native_state(a, &match?(%{pending_control: %{kind: :control}}, &1))
        send(parent, {:native_control_owned, a, queued})
        receive do: (:stop -> :ok)
      end)

    on_exit(fn -> Process.exit(owner, :kill) end)

    try do
      assert_receive {:native_control_owned, a, queued}, 5_000

      a = %{
        a
        | connection_monitor: Process.monitor(a.socket.pid),
          writer_monitor: Process.monitor(a.writer),
          tcp_monitor: :socket.monitor(a.tcp),
          observer_monitor: Process.monitor(a.observer)
      }

      assert queued.output.kind == :application
      assert {:pending, _} = Reader.await(a.receipt, deadline(10))
      send(owner, :stop)
      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000
      cleanup(a)
    after
      send(peer.task.pid, :finish)
      Peer.stop(peer)
    end
  end

  for {action, abandon?} <-
        for(
          action <- [:drain, :cancel, :close],
          abandon? <- [false, true],
          do: {action, abandon?}
        ) do
    test "raw Socket queued peer close retains plaintext until #{action} abandon=#{abandon?}" do
      {:ok, peer} =
        Peer.start(fn socket ->
          receive do
            :finish ->
              assert :ok = :ssl.send(socket, "final-data")
              :ssl.close(socket)
          end
        end)

      try do
        a = attempt(peer.port, send_timeout: 2_000)
        assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
        success(a)
        assert :ok = private_io(a, :enable_duplex_reads)
        assert true = :erlang.suspend_process(a.writer)
        request = private_send_request(a, :binary.copy("x", 65_536))
        held = native_state(a, &match?(%{output: %{kind: :application}}, &1))

        if unquote(abandon?) do
          assert :ok = private_io(a, :abandon_send)
          assert {:reply, {:error, :write_abandoned}} = :gen_statem.wait_response(request, 1_000)
        end

        admitted = absolute(0)
        send(peer.task.pid, :finish)

        queued =
          native_state(a, &match?(%{closed: true, pending_control: %{kind: :close_notify}}, &1))

        assert queued.output == held.output
        assert queued.size == 10
        assert queued.write == nil
        assert queued.pending_control.deadline <= held.output.deadline
        assert queued.pending_control.deadline <= admitted + 300

        unless unquote(abandon?),
          do: assert({:reply, {:error, :closed}} == :gen_statem.wait_response(request, 1_000))

        native_state(
          a,
          &match?(%{closed: true, machine: nil, output: nil, pending_control: nil, size: 10}, &1)
        )

        assert Process.alive?(a.socket.pid) and Process.alive?(a.writer)
        assert {:ok, a.socket.pid} == :socket.getopt(a.tcp, :otp, :controlling_process)
        assert {:pending, _} = Reader.await(a.receipt, deadline(10))
        assert :unsealed = Receipt.read(a.receipt)
        assert {:error, :closed} = private_io(a, :reserve_write)
        assert Process.read_timer(queued.pending_control.timer) == false

        case unquote(action) do
          :drain -> assert {:ok, "final-data"} = private_io(a, {:recv, 10, absolute(500)})
          :cancel -> assert :ok = Observer.cancel(a.receipt, a.lease, deadline(500))
          :close -> assert :ok = private_io(a, :close)
        end

        cleanup(a)
      after
        send(peer.task.pid, :finish)
        Peer.stop(peer)
      end
    end
  end

  test "raw Socket genuine native write wait queues requested KeyUpdate without replay" do
    size = 16 * 1_048_576
    peer = control_peer(size, true)
    {:ok, proxy} = Peer.start_backpressure_proxy(peer.port, self())
    ref = proxy.ref

    try do
      a = attempt(proxy.port, send_timeout: 10_000, sndbuf: 4_096)
      assert :ok = Setup.attach(a.setup, a.nonce, deadline(1_000))
      success(a)
      assert :ok = private_io(a, :enable_duplex_reads)
      assert :ok = Peer.pause_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^ref, :paused}, 1_000
      request = private_send_request(a, :binary.copy("x", size))
      assert_receive {:backpressure_proxy, ^ref, :held, count}, 5_000
      assert count > 0
      before_update = native_blocked(a, absolute(2_000))
      assert :timeout = :gen_statem.wait_response(request, 0)
      send(peer.task.pid, :update)
      queued = native_state(a, &match?(%{pending_control: %{kind: :control}}, &1))

      # A transient native wait may complete before KeyUpdate admission. Prove
      # the real send remains blocked with the admitted control, without
      # suspending Writer or confusing an earlier legitimate ACK with replay.
      blocked = native_blocked(a, absolute(1_000))
      assert blocked.output == queued.output
      assert blocked.pending_control == queued.pending_control
      assert blocked.machine == queued.machine
      assert queued.output.deadline == before_update.output.deadline
      assert queued.pending_control.deadline <= before_update.output.deadline
      assert :timeout = :gen_statem.wait_response(request, 0)

      # Only after proving overlapping native wait/control do we hold the
      # controller to observe dispatch of those exact protected bytes.
      assert :ok = :sys.suspend(a.socket.pid)
      assert :ok = Peer.resume_client_to_server(proxy, self())
      assert_receive {:backpressure_proxy, ^ref, :resumed}, 1_000
      assert_receive :native_original_record_received, 1_000
      native_writer_idle(a.writer, absolute(1_000))
      assert true = :erlang.suspend_process(a.writer)
      assert :ok = :sys.resume(a.socket.pid)
      token = queued.pending_control.token
      active = native_state(a, &match?(%{output: %{token: ^token}}, &1))
      assert active.pending_control == nil
      assert active.output == Map.delete(queued.pending_control, :bytes)
      assert active.machine == queued.machine
      assert is_integer(Process.read_timer(active.output.timer))
      assert true = :erlang.resume_process(a.writer)
      assert {:reply, :ok} = :gen_statem.wait_response(request, 10_000)
      assert :ok = private_send(a, "client-after-update")
      assert {:ok, "control-received"} = private_io(a, {:recv, 16, absolute(2_000)})
      assert :ok = private_io(a, :close)
      cleanup(a)
      send(peer.task.pid, :finish)
      assert :ok = Peer.stop(peer)
    after
      stop_control_peer(peer)
      if Process.alive?(proxy.task.pid), do: Peer.stop_backpressure_proxy(proxy)
    end
  end

  defp assert_control_ciphertext(control, write) do
    cipher =
      case write.cipher_suite do
        :tls_aes_128_gcm_sha256 -> :aes_128_gcm
        :tls_aes_256_gcm_sha384 -> :aes_256_gcm
        :tls_chacha20_poly1305_sha256 -> :chacha20_poly1305
      end

    nonce = :crypto.exor(write.iv, <<0::32, write.sequence::64>>)
    header = <<23, 3, 3, 0, 22>>
    # Independently protect the exact RFC KeyUpdate(update_not_requested)
    # handshake and inner content type with the pre-update old write state.
    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        cipher,
        write.key,
        nonce,
        <<24, 0, 0, 1, 0, 22>>,
        header,
        16,
        true
      )

    assert IO.iodata_to_binary(control.bytes) ==
             <<header::binary, ciphertext::binary, tag::binary>>
  end

  defp control_peer(size, marker?) do
    parent = self()

    {:ok, peer} =
      Peer.start(fn socket ->
        receive do: (:update -> :ok)
        assert :ok = :ssl.update_keys(socket, :read_write)
        prefix = :binary.copy("x", 16_384)
        assert {:ok, ^prefix} = :ssl.recv(socket, byte_size(prefix), 12_000)
        send(parent, :native_original_record_received)

        if size > byte_size(prefix) do
          rest = :binary.copy("x", size - byte_size(prefix))
          assert {:ok, ^rest} = :ssl.recv(socket, byte_size(rest), 12_000)
        end

        if marker? do
          assert {:ok, "client-after-update"} = :ssl.recv(socket, 19, 2_000)
        else
          assert {:error, :timeout} = :ssl.recv(socket, 0, 50)
        end

        assert :ok = :ssl.send(socket, "control-received")
        receive do: (:finish -> :ssl.close(socket))
      end)

    peer
  end

  defp stop_control_peer(peer) do
    if Process.alive?(peer.task.pid), do: Task.shutdown(peer.task, :brutal_kill)
    :ssl.close(peer.listener)
  end

  defp held_control_peer do
    {:ok, peer} =
      Peer.start(fn socket ->
        receive do: (:update -> :ok)
        assert :ok = :ssl.update_keys(socket, :read_write)
        receive do: (:finish -> :ssl.close(socket))
      end)

    peer
  end

  defp private_send_request(a, bytes) do
    {:ok, token} = private_io(a, :reserve_write)
    {:ok, cursor, size} = SSL.IodataCursor.new(bytes)

    :gen_statem.send_request(
      a.socket.pid,
      {a.socket.ref, {:lifecycle_io, {:send, token, cursor, size}}}
    )
  end

  defp native_state(a, predicate), do: native_state(a, predicate, absolute(1_000))

  defp native_state(a, predicate, limit) do
    assert absolute(0) < limit
    {:connected, state} = :sys.get_state(a.socket.pid)

    if predicate.(state) do
      state
    else
      receive do
      after
        1 -> native_state(a, predicate, limit)
      end
    end
  end

  defp native_dispatch_held(a, queued) do
    assert :ok = :sys.suspend(a.socket.pid)
    assert true = :erlang.resume_process(a.writer)
    assert_receive :native_original_record_received, 500
    native_writer_idle(a.writer, absolute(500))
    assert true = :erlang.suspend_process(a.writer)
    assert :ok = :sys.resume(a.socket.pid)
    token = queued.pending_control.token
    active = native_state(a, &match?(%{output: %{token: ^token}}, &1))
    assert active.pending_control == nil
    assert active.output == Map.delete(queued.pending_control, :bytes)
    assert is_integer(Process.read_timer(active.output.timer))
    active
  end

  defp native_writer_idle(writer, limit) do
    assert absolute(0) < limit

    case Process.info(writer, [:status, :current_function, :messages]) do
      [
        status: :waiting,
        current_function: {SSL.ConnectionWriter, :enrolled_loop, 6},
        messages: []
      ] ->
        :ok

      _ ->
        receive do
        after
          1 -> native_writer_idle(writer, limit)
        end
    end
  end

  defp native_blocked(a, limit) do
    assert absolute(0) < limit
    held = native_state(a, &match?(%{output: %{kind: :application}}, &1), limit)
    before = :socket.info(a.tcp)

    if native_send_waiting?(a.writer, before) do
      receive do
      after
        50 -> :ok
      end

      after_wait = :socket.info(a.tcp)
      waiting? = native_send_waiting?(a.writer, after_wait)
      {:connected, current} = :sys.get_state(a.socket.pid)
      counters = [:write_byte, :write_pkg, :write_tries, :write_waits]

      # One send may wake and make partial progress without changing its token.
      # Cumulative write_waits and a single process-status sample do not prove
      # sustained backpressure. Require a quiet native send across both samples;
      # transient wakeups retry only the observation under the original limit.
      if waiting? and current.output == held.output and
           Map.take(before.counters, counters) == Map.take(after_wait.counters, counters) do
        current
      else
        native_blocked(a, limit)
      end
    else
      receive do
      after
        1 -> native_blocked(a, limit)
      end
    end
  end

  defp native_send_waiting?(writer, %{
         counters: %{write_waits: waits},
         num_writers: 1,
         wstates: states
       })
       when waits > 0 do
    :selected in states and
      match?(
        [status: :waiting, current_function: {:socket, _function, _arity}],
        Process.info(writer, [:status, :current_function])
      )
  end

  defp native_send_waiting?(_writer, _socket_info), do: false

  defp openssl12(overrides \\ []) do
    {:ok, peer} =
      ExSSL.TestSupport.OpenSSLPeer.start(
        Keyword.merge(
          [
            certfile: Path.expand("../../fixtures/server_flight/leaf-rsa.pem", __DIR__),
            keyfile: Path.expand("../../fixtures/server_flight/leaf-rsa-key.pem", __DIR__),
            min_version: :tls12,
            max_version: :tls12
          ],
          overrides
        )
      )

    peer
  end

  defp static_options do
    [
      cacerts: @static_ca,
      server_name_indication: ~c"example.test",
      versions: [:"tlsv1.2"],
      ciphers: [@tls12_cipher]
    ]
  end

  defp await_retained(a) do
    deadline = absolute(1_000)
    await_retained(a, deadline)
  end

  defp await_retained(a, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    case :sys.get_state(a.socket.pid, 500) do
      {:connected, %{closed: true, machine: nil, size: 18, output: nil, armed: false}} ->
        :ok

      _ ->
        receive do
        after
          5 -> :ok
        end

        await_retained(a, deadline)
    end
  end

  defp wait_until(absolute) do
    timer = :erlang.start_timer(absolute, self(), :boundary, abs: true)
    assert_receive {:timeout, ^timer, :boundary}, 5_000
  end

  defp attempt(
         port,
         overrides \\ [],
         control_ms \\ 1_500,
         cleanup \\ &on_exit/1,
         original_ms \\ 5_000
       ) do
    options = Peer.client_options() |> Enum.reject(&(&1 == :binary)) |> Keyword.merge(overrides)
    {:ok, options} = Options.normalize("exssl.test", options)
    original = if original_ms == :infinity, do: :infinity, else: absolute(original_ms)
    budget = if original == :infinity, do: :infinity, else: {:abs_ms, original}
    {:ok, receipt, lease} = Observer.start(self(), budget)
    observer = Receipt.observer(receipt)
    cleanup.(fn -> Process.exit(observer, :kill) end)
    observer_monitor = Process.monitor(observer)
    :ok = Observer.bind(receipt, lease, deadline(1_000))
    {:ok, permit} = Observer.reserve_root(receipt, lease, :setup, deadline(1_000))
    {:ok, allocator_permit} = Observer.reserve_root(receipt, lease, :allocator, deadline(1_000))
    nonce = make_ref()

    context = %{
      receipt: receipt,
      permit: permit,
      allocator_permit: allocator_permit,
      endpoint: {{127, 0, 0, 1}, port},
      classic: {self(), make_ref(), :atomics.new(1, []), options, original},
      control_deadline: deadline(control_ms),
      ready: {self(), nonce}
    }

    assert {:ok, setup} = Setup.start_socket(context)
    setup_monitor = Process.monitor(setup)
    cleanup.(fn -> Process.exit(setup, :kill) end)

    assert_receive {:lifecycle_native_owned, ^setup, ^nonce, ^observer, %Socket{} = socket, tcp},
                   1_000

    connection_monitor = Process.monitor(socket.pid)
    cleanup.(fn -> Process.exit(socket.pid, :kill) end)
    tcp_monitor = :socket.monitor(tcp)
    {:monitors, monitors} = Process.info(socket.pid, :monitors)
    owner = self()
    [writer] = for {:process, pid} <- monitors, pid not in [owner, observer, setup], do: pid
    writer_monitor = Process.monitor(writer)

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      observer_monitor: observer_monitor,
      setup: setup,
      setup_monitor: setup_monitor,
      nonce: nonce,
      socket: socket,
      tcp: tcp,
      tcp_monitor: tcp_monitor,
      writer: writer,
      writer_monitor: writer_monitor,
      connection_monitor: connection_monitor,
      control: context.control_deadline
    }
  end

  defp success(a) do
    setup = a.setup
    nonce = a.nonce
    observer = a.observer
    socket = a.socket
    assert_receive {:lifecycle_tls_ready, ^setup, ^nonce, ^observer, ^socket}, 5_000
    monitor = a.setup_monitor
    assert_receive {:DOWN, ^monitor, :process, ^setup, :normal}, 1_000

    assert {:ok, %{setup: :connected, admission: :open}} =
             Observer.snapshot(a.receipt, deadline(500))
  end

  defp private_io(a, request),
    do: :gen_statem.call(a.socket.pid, {a.socket.ref, {:lifecycle_io, request}}, 3_000)

  defp private_send(a, bytes) do
    {:ok, token} = private_io(a, :reserve_write)
    {:ok, cursor, size} = SSL.IodataCursor.new(bytes)
    private_io(a, {:send, token, cursor, size})
  end

  defp cleanup(a, setup \\ :connected) do
    for {pid, monitor} <- [
          {a.socket.pid, a.connection_monitor},
          {a.writer, a.writer_monitor}
        ] do
      assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1_000
    end

    tcp = a.tcp
    monitor = a.tcp_monitor
    assert_receive {:DOWN, ^monitor, :socket, ^tcp, :closed}, 1_000

    assert {:ok, %{roles: 31, observed_down: 31, cleanup: :confirmed, setup: ^setup}} =
             Reader.await(a.receipt, deadline(2_000))

    observer = a.observer
    monitor = a.observer_monitor
    assert_receive {:DOWN, ^monitor, :process, ^observer, _}, 1_000
  end

  defp absolute(ms), do: System.monotonic_time(:millisecond) + ms
  defp deadline(ms), do: {:abs_ms, absolute(ms)}
end

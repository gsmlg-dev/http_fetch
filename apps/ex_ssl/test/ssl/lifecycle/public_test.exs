defmodule SSL.Lifecycle.PublicTest do
  use ExUnit.Case, async: false
  alias SSL.Lifecycle

  test "deadline status opts into actual Observer counts without changing legacy maps" do
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)
    assert {:pending, legacy} = Lifecycle.status(handle)
    refute Map.has_key?(legacy, :provider_resources)
    assert {:pending, numeric} = Lifecycle.status(handle, deadline(1_000))
    assert Map.delete(numeric, :provider_resources) == legacy

    assert numeric.provider_resources == %{
             processes: 1,
             tcp_sockets: 0,
             observers: 1,
             data_resources: 0
           }

    assert {:error, :invalid_deadline} = Lifecycle.status(handle, :infinity)

    assert {:pending, %{snapshot: :unavailable, provider_resources: nil}} =
             Lifecycle.status(handle, deadline(0))

    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    assert {:ok, receipt} = Lifecycle.await(handle, deadline(2_000))
    assert {:terminal, ^receipt} = Lifecycle.status(handle, deadline(0))
    assert {:terminal, ^receipt} = Lifecycle.status(handle)
    refute Map.has_key?(receipt, :provider_resources)
  end

  test "one suspended Observer consumes only the original status deadline" do
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)
    observer = handle.receipt.observer
    :erlang.suspend_process(observer)
    entered = System.monotonic_time(:millisecond)

    try do
      assert {:pending, %{provider_resources: nil}} = Lifecycle.status(handle, deadline(40))
      assert System.monotonic_time(:millisecond) - entered < 250
    after
      :erlang.resume_process(observer)
    end

    assert {:pending, %{provider_resources: %{observers: 1}}} =
             Lifecycle.status(handle, deadline(1_000))

    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    assert {:ok, _} = Lifecycle.await(handle, deadline(2_000))
  end

  test "reservation is allocation-free, cancellation and concurrent await are durable" do
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)

    assert {:pending, %{setup: :not_started, roles: 0, allocations: 0, epoch: 0}} =
             Lifecycle.status(handle)

    waiters = for _ <- 1..4, do: Task.async(fn -> Lifecycle.await(handle, deadline(2_000)) end)
    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    receipts = Enum.map(waiters, &Task.await(&1, 3_000))
    assert [{:ok, %{setup: :cancelled, roles: 0, cleanup: :confirmed}}] = Enum.uniq(receipts)
    assert {:terminal, %{cleanup: :confirmed}} = Lifecycle.status(handle)
    assert {:ok, _} = Lifecycle.await(handle, deadline(0))
  end

  test "finite await does not shorten an infinite reservation and invalid controls allocate nothing" do
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)
    assert {:pending, _} = Lifecycle.await(handle, deadline(0))
    assert {:pending, %{setup: :not_started}} = Lifecycle.status(handle)
    assert {:error, :invalid_deadline} = Lifecycle.await(handle, :infinity)
    assert {:error, :invalid_deadline} = Lifecycle.cancel(lease, :infinity)

    assert {:error, :invalid_options} =
             Lifecycle.new(controller: self(), deadline: :infinity, extra: true)

    assert {:error, :deadline_exceeded} =
             Lifecycle.new(controller: self(), deadline: deadline(-1))

    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    assert {:ok, _} = Lifecycle.await(handle, deadline(2_000))
  end

  test "observer evidence loss is unconfirmed, never an empty-resource receipt" do
    {:ok, handle, _lease} = Lifecycle.new(controller: self(), deadline: :infinity)
    # Provider fault injection; consumer assertions use only the public facade.
    observer = handle.receipt.observer
    monitor = Process.monitor(observer)
    Process.exit(observer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^observer, :killed}
    assert {:unconfirmed, :observer_unsealed} = Lifecycle.status(handle)
    assert {:unconfirmed, :observer_unsealed} = Lifecycle.await(handle, deadline(100))
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.Lifecycle.PublicTransportTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{LocalTLSPeer, OpenSSLPeer}
  alias SSL.Lifecycle
  @ip {127, 0, 0, 1}
  @ip6 {0, 0, 0, 0, 0, 0, 0, 1}
  @root Path.expand("../../fixtures/server_flight/root.pem", __DIR__)
  @wrong_root Path.expand("../../fixtures/pkix/wrong_root.pem", __DIR__)
  @cipher %{key_exchange: :ecdhe_rsa, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}

  for version <- [:"tlsv1.3", :"tlsv1.2"], route <- [:dial, :upgrade, :prepared] do
    test "public #{route} authenticates #{version}, exchanges data and confirms cleanup" do
      version = unquote(version)

      with_version_peer(version, fn peer, options ->
        {:ok, handle, lease} = new()

        try do
          assert {:ok, socket} =
                   connect(unquote(route), peer.port, options, descriptor(handle, lease))

          assert {:pending, %{setup: :connected, logical: :open, cleanup: :pending}} =
                   Lifecycle.status(handle)

          frame = <<4::32, "ping">>
          assert :ok = SSL.send(socket, frame)
          assert {:ok, ^frame} = SSL.recv(socket, 8, 2_000)
          assert :ok = SSL.close(socket)

          assert {:ok, %{setup: :connected, cleanup: :confirmed}} =
                   Lifecycle.await(handle, deadline(2_000))
        after
          Lifecycle.cancel(lease, deadline(500))
        end
      end)
    end
  end

  for host <- ["localhost", ~c"localhost", @ip] do
    test "native public dial resolves #{inspect(host)} and preserves local bind and socket options" do
      with_peer(fn peer ->
        {:ok, handle, lease} = new()

        options =
          client_options(
            nodelay: true,
            keepalive: true,
            buffer: 32_768,
            sndbuf: 65_536,
            recbuf: 65_536,
            ip: @ip,
            port: 0,
            send_timeout: :infinity
          )

        try do
          assert {:ok, socket} =
                   SSL.connect(
                     unquote(Macro.escape(host)),
                     peer.port,
                     options ++ descriptor(handle, lease),
                     3_000
                   )

          assert {:ok, {@ip, local_port}} = SSL.sockname(socket)
          assert local_port > 0
          assert {:ok, {@ip, remote_port}} = SSL.peername(socket)
          assert remote_port == peer.port
          # Provider option readback is deliberately confined to this fault/adapter test.
          {:connected, state} = :sys.get_state(socket.pid)
          assert {:ok, true} = :socket.getopt(state.tcp, :tcp, :nodelay)
          assert {:ok, true} = :socket.getopt(state.tcp, :socket, :keepalive)
          assert {:ok, 32_768} = :socket.getopt(state.tcp, :otp, :rcvbuf)
          assert {:ok, sndbuf} = :socket.getopt(state.tcp, :socket, :sndbuf)
          assert sndbuf >= 65_536
          assert :ok = SSL.setopts(socket, nodelay: false, buffer: 49_152)
          assert {:ok, false} = :socket.getopt(state.tcp, :tcp, :nodelay)
          assert {:ok, 49_152} = :socket.getopt(state.tcp, :otp, :rcvbuf)
          assert :ok = SSL.send(socket, "ping")
          assert {:ok, "ping"} = SSL.recv(socket, 4, 1_000)
          assert :ok = SSL.close(socket)
          assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
        after
          Lifecycle.cancel(lease, deadline(500))
        end
      end)
    end
  end

  test "native IPv6 literal and DNS endpoints preserve IPv6 local bind" do
    for host <- [@ip6, "::1", ~c"localhost"] do
      with_ipv6_peer(fn port ->
        {:ok, handle, lease} = new()

        try do
          options = [:inet6 | client_options(ip: @ip6, port: 0, tclass: 16)]

          assert {:ok, socket} =
                   SSL.connect(host, port, options ++ descriptor(handle, lease), 3_000)

          assert {:ok, {@ip6, _}} = SSL.sockname(socket)
          {:connected, state} = :sys.get_state(socket.pid)
          assert {:ok, 16} = :socket.getopt(state.tcp, :ipv6, :tclass)
          assert :ok = SSL.send(socket, "ipv6")
          assert {:ok, "ipv6"} = SSL.recv(socket, 4, 1_000)
          assert :ok = SSL.close(socket)
          assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
        after
          Lifecycle.cancel(lease, deadline(500))
        end
      end)
    end
  end

  test "active-once uses the stable public socket without lease data" do
    with_peer(fn peer ->
      {:ok, handle, lease} = new()

      try do
        assert {:ok, socket} =
                 SSL.connect(
                   @ip,
                   peer.port,
                   client_options(active: :once) ++ descriptor(handle, lease),
                   3_000
                 )

        assert :ok = SSL.send(socket, "active")
        assert_receive {:ssl, ^socket, "active"}, 1_000
        assert :ok = SSL.setopts(socket, active: false)
        assert :ok = SSL.send(socket, "passive")
        assert {:ok, "passive"} = SSL.recv(socket, 7, 1_000)
        assert :ok = SSL.close(socket)
        assert {:ok, _} = Lifecycle.await(handle, deadline(2_000))
      after
        Lifecycle.cancel(lease, deadline(500))
      end
    end)
  end

  test "raw refusal and DNS errors survive producer teardown with finite failure evidence" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false])
    {:ok, {_, port}} = :inet.sockname(listener)
    :ok = :gen_tcp.close(listener)
    baseline = MapSet.new(:socket.which_sockets())

    # Keep DNS lookup failure distinct from malformed-host argument rejection.
    for {host, expected} <- [
          {@ip, :econnrefused},
          {~c"http-fetch-nonexistent.invalid", :nxdomain}
        ] do
      {:ok, handle, lease} = new()

      try do
        assert {:error, ^expected} =
                 SSL.connect(host, port, client_options() ++ descriptor(handle, lease), 2_000)

        assert {:ok, %{setup: :failed, setup_failure: :connect, cleanup: :confirmed}} =
                 Lifecycle.await(handle, deadline(2_000))

        if expected == :econnrefused do
          assert {:ok, %{phase: :connect}} = Lifecycle.connect_failure(handle)
        else
          assert :unknown = Lifecycle.connect_failure(handle)
        end

        assert :unknown = Lifecycle.setup_failure(handle)
      after
        Lifecycle.cancel(lease, deadline(500))
      end
    end

    assert MapSet.new(:socket.which_sockets()) == baseline
  end

  for {kind, overrides} <- [
        wrong_ca: [cacerts: :wrong],
        wrong_identity: [server_name_indication: ~c"wrong.test"]
      ] do
    test "#{kind} returns the original TLS error and confirms resource cleanup" do
      with_peer(fn peer ->
        {:ok, handle, lease} = new()
        overrides = unquote(Macro.escape(overrides))

        overrides =
          if overrides[:cacerts] == :wrong,
            do: [cacerts: certificates(@wrong_root)],
            else: overrides

        try do
          assert {:error, {:tls_alert, {_, message}}} =
                   SSL.connect(
                     @ip,
                     peer.port,
                     client_options(overrides) ++ descriptor(handle, lease),
                     3_000
                   )

          assert is_list(message)

          assert {:ok, %{setup: :failed, setup_failure: :tls, cleanup: :confirmed}} =
                   Lifecycle.await(handle, deadline(2_000))
        after
          Lifecycle.cancel(lease, deadline(500))
        end
      end)
    end
  end

  test "option rejection binds once without data allocation and cannot enter a prepared snapshot" do
    {:ok, handle, lease} = new()
    attempt = descriptor(handle, lease)

    assert {:error, {:options, {:active, :unsupported_or_invalid}}} =
             SSL.connect(@ip, 1, client_options(active: true) ++ attempt, 1_000)

    assert {:ok, %{setup: :failed, setup_failure: :options, roles: 0}} =
             Lifecycle.await(handle, deadline(2_000))

    assert {:error, {:options, :lifecycle_is_per_attempt}} =
             SSL.prepare_upgrade(client_options() ++ attempt)

    {:ok, prepared} = SSL.prepare_upgrade(client_options())

    assert {:error, {:options, :invalid_attempt_options}} =
             SSL.connect_prepared(:invalid, prepared, attempt ++ [verify: :verify_none], 1_000)
  end

  test "foreign STARTTLS socket and its reservation remain untouched" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
    {:ok, {_, port}} = :inet.sockname(listener)
    {:ok, tcp} = :gen_tcp.connect(@ip, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listener, 1_000)
    other = actor()
    {:ok, handle, lease} = new()

    try do
      assert {:error, :not_owner} =
               run(other, fn ->
                 SSL.connect(tcp, client_options() ++ descriptor(handle, lease), 1_000)
               end)

      assert {:ok, [active: false]} = :inet.getopts(tcp, [:active])
      assert {:pending, %{setup: :not_started, roles: 0}} = Lifecycle.status(handle)
      assert :ok = :gen_tcp.send(server, "unconsumed plaintext")
      assert {:ok, "unconsumed plaintext"} = :gen_tcp.recv(tcp, 20, 1_000)
      assert :ok = :gen_tcp.send(tcp, "still owned")
      assert {:ok, "still owned"} = :gen_tcp.recv(server, 11, 1_000)
    after
      :gen_tcp.close(server)
      :gen_tcp.close(tcp)
      :gen_tcp.close(listener)
      Lifecycle.cancel(lease, deadline(500))
    end
  end

  test "owned STARTTLS pending plaintext produces adopted cleanup proof" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
    {:ok, {_, port}} = :inet.sockname(listener)
    {:ok, tcp} = :gen_tcp.connect(@ip, port, [:binary, active: false], 1_000)
    {:ok, server} = :gen_tcp.accept(listener, 1_000)
    {:ok, handle, lease} = new()

    try do
      assert :ok = :gen_tcp.send(server, "plaintext")
      assert :ok = :inet.setopts(tcp, active: :once)
      assert_receive {:tcp, ^tcp, "plaintext"}, 1_000
      assert :ok = :inet.setopts(tcp, active: false)
      send(self(), {:tcp, tcp, "plaintext"})

      assert {:error, :pending_plaintext} =
               SSL.connect(tcp, client_options() ++ descriptor(handle, lease), 1_000)

      assert {:ok, %{scope: :upgrade, setup: :failed, roles: 16, observed_down: 16}} =
               Lifecycle.await(handle, deadline(2_000))

      assert Port.info(tcp) == nil
    after
      :gen_tcp.close(server)
      :gen_tcp.close(tcp)
      :gen_tcp.close(listener)
      Lifecycle.cancel(lease, deadline(500))
    end
  end

  test "independent controller and owner transfer through a real ACK; stale owners and leases are denied" do
    with_peer(fn peer ->
      controller = actor()
      owner = actor()
      recipient = actor()
      new_owner = actor()
      {:ok, handle, lease} = new(controller)

      assert {:ok, socket} =
               run(owner, fn ->
                 SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)
               end)

      assert :ok = SSL.send(socket, "sender task")
      reader = Task.async(fn -> SSL.recv(socket, 11, 1_000) end)
      assert {:ok, "sender task"} = Task.await(reader)

      assert {:ok, ticket} =
               Lifecycle.offer(lease, %{controller: recipient, owner: new_owner}, deadline(2_000))

      assert {:error, :not_recipient} = Lifecycle.accept(ticket, deadline(1_000))

      assert {:ok, replacement} =
               run(recipient, fn -> Lifecycle.accept(ticket, deadline(1_000)) end)

      assert {:ok, ^replacement} =
               run(recipient, fn -> Lifecycle.accept(ticket, deadline(1_000)) end)

      assert {:pending, %{epoch: 1, transfer: :accepted}} = Lifecycle.status(handle)
      assert {:error, :stale_lease} = Lifecycle.cancel(lease, deadline(500))

      for operation <- [
            fn -> SSL.close(socket) end,
            fn -> SSL.setopts(socket, nodelay: true) end,
            fn -> SSL.controlling_process(socket, owner) end,
            fn -> SSL.enable_duplex_reads(socket) end,
            fn -> SSL.abandon_send(socket) end
          ] do
        assert {:error, :not_owner} = run(owner, operation)
      end

      stop_actor(controller)
      stop_actor(owner)
      assert :ok = SSL.send(socket, "after transfer")
      assert {:ok, "after transfer"} = SSL.recv(socket, 14, 1_000)
      assert :ok = run(new_owner, fn -> SSL.close(socket) end)
      assert {:ok, %{epoch: 1, cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
    end)
  end

  test "controlling_process replaces application-owner monitors without changing controller authority" do
    with_peer(fn peer ->
      controller = actor()
      owner = actor()
      next_owner = actor()
      {:ok, handle, lease} = new(controller)

      assert {:ok, socket} =
               run(owner, fn ->
                 SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)
               end)

      assert :ok = run(owner, fn -> SSL.controlling_process(socket, next_owner) end)
      stop_actor(owner)
      assert {:pending, %{setup: :connected, epoch: 0}} = Lifecycle.status(handle)
      assert :ok = SSL.send(socket, "alive")
      assert {:ok, "alive"} = SSL.recv(socket, 5, 1_000)
      assert :ok = Lifecycle.cancel(lease, deadline(500))
      assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
    end)
  end

  for victim <- [:controller, :owner] do
    test "#{victim} death independently retires the public provider graph" do
      with_peer(fn peer ->
        controller = actor()
        owner = actor()
        {:ok, handle, lease} = new(controller)

        assert {:ok, _socket} =
                 run(owner, fn ->
                   SSL.connect(
                     @ip,
                     peer.port,
                     client_options() ++ descriptor(handle, lease),
                     3_000
                   )
                 end)

        stop_actor(if unquote(victim) == :controller, do: controller, else: owner)

        assert {:ok, %{setup: :connected, cleanup: :confirmed}} =
                 Lifecycle.await(handle, deadline(2_000))
      end)
    end
  end

  test "accepted cancel prevents a suspended transfer ACK from reopening admission" do
    with_peer(fn peer ->
      {:ok, handle, lease} = new()

      assert {:ok, socket} =
               SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)

      recipient = actor()
      owner = actor()

      assert {:ok, ticket} =
               Lifecycle.offer(lease, %{controller: recipient, owner: owner}, deadline(2_000))

      :ok = :sys.suspend(socket.pid)
      parent = self()

      send(
        recipient,
        {:run, parent, :accept_race, fn -> Lifecycle.accept(ticket, deadline(1_000)) end}
      )

      eventually(fn ->
        case :sys.get_state(handle.receipt.observer) do
          %{transfer: transfer} -> transfer != nil
        end
      end)

      assert :ok = Lifecycle.cancel(lease, deadline(500))
      assert_receive {:accept_race, {:error, :cancelled}}, 1_000
      assert {:ok, %{epoch: 0, cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
      assert {:error, _} = run(recipient, fn -> Lifecycle.accept(ticket, deadline(100)) end)
    end)
  end

  test "timed-out owner ACK stays pending and cannot authorize a stale close or rollback" do
    with_peer(fn peer ->
      {:ok, handle, lease} = new()

      assert {:ok, socket} =
               SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)

      recipient = actor()
      owner = actor()

      assert {:ok, ticket} =
               Lifecycle.offer(lease, %{controller: recipient, owner: owner}, deadline(2_000))

      :ok = :sys.suspend(socket.pid)
      parent = self()

      send(
        recipient,
        {:run, parent, :unknown_accept, fn -> Lifecycle.accept(ticket, deadline(100)) end}
      )

      eventually(fn ->
        case :sys.get_state(handle.receipt.observer) do
          %{transfer: transfer} -> transfer != nil
        end
      end)

      assert_receive {:unknown_accept, {:error, reason}}, 1_000
      assert reason in [:acceptance_unconfirmed, :deadline_exceeded]
      assert {:pending, %{epoch: 0, cleanup: :pending}} = Lifecycle.status(handle)
      :ok = :sys.resume(socket.pid)
      eventually(fn -> :sys.get_state(handle.receipt.observer).transfer == nil end)
      assert {:pending, %{setup: :connected, epoch: 0}} = Lifecycle.status(handle)
      assert :ok = SSL.send(socket, "still open")
      assert {:ok, "still open"} = SSL.recv(socket, 10, 1_000)
      assert :ok = Lifecycle.cancel(lease, deadline(500))
      assert {:ok, _} = Lifecycle.await(handle, deadline(2_000))
    end)
  end

  test "finite handshake cancellation and infinite setup retain their original deadlines" do
    options = client_options()

    for setup <- [:finite, :infinity] do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
      {:ok, {_, port}} = :inet.sockname(listener)
      controller = self()

      {:ok, handle, lease} =
        new(controller, if(setup == :finite, do: deadline(200), else: :infinity))

      caller =
        Task.async(fn ->
          SSL.connect(@ip, port, options ++ descriptor(handle, lease), :infinity)
        end)

      {:ok, accepted} = :gen_tcp.accept(listener, 1_000)

      try do
        assert {:ok, _client_hello} = :gen_tcp.recv(accepted, 0, 1_000)

        if setup == :infinity do
          assert {:pending, _} = Lifecycle.await(handle, deadline(1_150))
          assert {:pending, %{setup: :pending}} = Lifecycle.status(handle)
          assert :ok = Lifecycle.cancel(lease, deadline(500))
        end

        assert {:error, _} = Task.await(caller, 3_000)

        assert {:ok, %{setup: :cancelled, cleanup: :confirmed}} =
                 Lifecycle.await(handle, deadline(2_000))
      after
        :gen_tcp.close(accepted)
        :gen_tcp.close(listener)
        Lifecycle.cancel(lease, deadline(500))
        Task.shutdown(caller, :brutal_kill)
      end
    end
  end

  test "a real owner ACK delivered after timeout is reconciled once and replayed" do
    with_peer(fn peer ->
      {:ok, handle, lease} = new()

      assert {:ok, socket} =
               SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)

      recipient = actor()
      owner = actor()

      assert {:ok, ticket} =
               Lifecycle.offer(lease, %{controller: recipient, owner: owner}, deadline(2_000))

      observer = handle.receipt.observer
      :ok = :sys.suspend(socket.pid)
      parent = self()

      send(
        recipient,
        {:run, parent, :late_accept, fn -> Lifecycle.accept(ticket, deadline(400)) end}
      )

      eventually(fn -> :sys.get_state(observer).transfer != nil end)
      :ok = :sys.suspend(observer)

      try do
        :ok = :sys.resume(socket.pid)

        eventually(fn ->
          {:connected, state} = :sys.get_state(socket.pid)
          state.owner == owner and state.lifecycle.epoch == 1
        end)

        assert_receive {:late_accept, {:error, :acceptance_unconfirmed}}, 1_000
        assert {:error, :not_owner} = SSL.close(socket)
      after
        :sys.resume(observer)
      end

      eventually(fn ->
        match?({:pending, %{epoch: 1, transfer: :accepted}}, Lifecycle.status(handle))
      end)

      assert {:ok, replacement} =
               run(recipient, fn -> Lifecycle.accept(ticket, deadline(500)) end)

      assert {:ok, ^replacement} =
               run(recipient, fn -> Lifecycle.accept(ticket, deadline(500)) end)

      assert {:error, :stale_lease} = Lifecycle.cancel(lease, deadline(500))
      assert :ok = SSL.send(socket, "reconciled")
      assert {:ok, "reconciled"} = SSL.recv(socket, 10, 1_000)
      assert :ok = Lifecycle.cancel(replacement, deadline(500))
      assert {:ok, %{epoch: 1}} = Lifecycle.await(handle, deadline(2_000))
    end)
  end

  test "pending reader blocks transfer without changing owner or epoch" do
    with_peer(fn peer ->
      {:ok, handle, lease} = new()

      assert {:ok, socket} =
               SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)

      recipient = actor()
      owner = actor()
      reader = Task.async(fn -> SSL.recv(socket, 4, 2_000) end)
      eventually(fn -> elem(:sys.get_state(socket.pid), 1).recv != nil end)

      assert {:ok, ticket} =
               Lifecycle.offer(lease, %{controller: recipient, owner: owner}, deadline(2_000))

      assert {:error, :busy} = run(recipient, fn -> Lifecycle.accept(ticket, deadline(500)) end)
      assert {:pending, %{epoch: 0}} = Lifecycle.status(handle)
      assert :ok = SSL.send(socket, "read")
      assert {:ok, "read"} = Task.await(reader)

      assert {:ok, replacement} =
               run(recipient, fn -> Lifecycle.accept(ticket, deadline(500)) end)

      assert :ok = Lifecycle.cancel(replacement, deadline(500))
      assert {:ok, %{epoch: 1}} = Lifecycle.await(handle, deadline(2_000))
    end)
  end

  test "authenticated closure with retained plaintext reports logical closure before cleanup" do
    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        assert {:ok, "start"} = :ssl.recv(socket, 5, 2_000)
        assert :ok = :ssl.send(socket, "retained plaintext")
        :ssl.close(socket)
      end)

    {:ok, handle, lease} = new()

    try do
      assert {:ok, socket} =
               SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)

      assert :ok = SSL.send(socket, "start")

      eventually(fn ->
        match?({:pending, %{logical: :closed, cleanup: :pending}}, Lifecycle.status(handle))
      end)

      assert {:ok, "retained plaintext"} = SSL.recv(socket, 18, 1_000)
      assert {:error, :closed} = SSL.recv(socket, 0, 1_000)

      assert {:ok, %{setup: :connected, cleanup: :confirmed}} =
               Lifecycle.await(handle, deadline(2_000))
    after
      Lifecycle.cancel(lease, deadline(500))
      :ssl.close(peer.listener)
      Task.shutdown(peer.task, :brutal_kill)
    end
  end

  test "loss of an established observer cannot fabricate cleanup proof" do
    with_peer(fn peer ->
      {:ok, handle, lease} = new()

      assert {:ok, socket} =
               SSL.connect(@ip, peer.port, client_options() ++ descriptor(handle, lease), 3_000)

      monitor = Process.monitor(socket.pid)
      Process.exit(handle.receipt.observer, :kill)
      assert_receive {:DOWN, ^monitor, :process, _, _}, 2_000
      assert {:unconfirmed, :observer_unsealed} = Lifecycle.await(handle, deadline(1_000))
      assert {:unconfirmed, :observer_unsealed} = Lifecycle.status(handle)
    end)
  end

  defp connect(:dial, port, options, attempt),
    do: SSL.connect(@ip, port, options ++ attempt, 3_000)

  defp connect(route, port, options, attempt) do
    {:ok, tcp} = :gen_tcp.connect(@ip, port, [:binary, active: false], 1_000)

    if route == :prepared do
      {:ok, prepared} = SSL.prepare_upgrade(options)
      SSL.connect_prepared(tcp, prepared, attempt, 3_000)
    else
      SSL.connect(tcp, options ++ attempt, 3_000)
    end
  end

  defp with_version_peer(:"tlsv1.3", fun), do: with_peer(&fun.(&1, client_options()))

  defp with_version_peer(:"tlsv1.2", fun) do
    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: Path.expand("../../fixtures/server_flight/leaf-rsa.pem", __DIR__),
        keyfile: Path.expand("../../fixtures/server_flight/leaf-rsa-key.pem", __DIR__),
        min_version: :tls12,
        max_version: :tls12
      )

    try do
      fun.(peer,
        mode: :binary,
        active: false,
        cacerts: certificates(@root),
        server_name_indication: ~c"example.test",
        versions: [:"tlsv1.2"],
        ciphers: [@cipher]
      )
    after
      OpenSSLPeer.stop(peer)
    end
  end

  defp with_peer(fun) do
    {:ok, peer} = LocalTLSPeer.start(&echo/1)

    try do
      fun.(peer)
    after
      :ssl.close(peer.listener)
      Task.shutdown(peer.task, :brutal_kill)
    end
  end

  defp with_ipv6_peer(fun) do
    certs = LocalTLSPeer.certificates()

    {:ok, listener} =
      :ssl.listen(0, [
        :inet6,
        certfile: String.to_charlist(certs.certfile),
        keyfile: String.to_charlist(certs.keyfile),
        versions: [:"tlsv1.3"],
        active: false,
        mode: :binary,
        ip: @ip6,
        verify: :verify_none
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, socket} = :ssl.transport_accept(listener, 5_000)
        {:ok, socket} = :ssl.handshake(socket, 5_000)
        echo(socket)
      end)

    try do
      fun.(port)
    after
      :ssl.close(listener)
      Task.shutdown(task, :brutal_kill)
    end
  end

  defp echo(socket) do
    case :ssl.recv(socket, 0, 5_000) do
      {:ok, bytes} ->
        case :ssl.send(socket, bytes) do
          :ok -> echo(socket)
          {:error, _} -> :ok
        end

      {:error, _} ->
        :ok
    end
  end

  defp new(controller \\ self(), expiry \\ :infinity),
    do: Lifecycle.new(controller: controller, deadline: expiry)

  defp descriptor(handle, lease), do: [ex_ssl: [lifecycle: {handle, lease}]]

  defp client_options(overrides \\ []) do
    LocalTLSPeer.client_options()
    |> Enum.map(fn
      :binary -> {:mode, :binary}
      option -> option
    end)
    |> Keyword.merge(overrides)
  end

  defp certificates(path),
    do:
      for(
        {:Certificate, der, :not_encrypted} <- :public_key.pem_decode(File.read!(path)),
        do: der
      )

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}

  defp actor do
    pid = spawn(fn -> actor_loop() end)
    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    pid
  end

  defp actor_loop do
    receive do
      {:run, caller, ref, fun} ->
        send(caller, {ref, fun.()})
        actor_loop()

      :stop ->
        :ok
    end
  end

  defp run(pid, fun) do
    ref = make_ref()
    send(pid, {:run, self(), ref, fun})

    receive do
      {^ref, result} -> result
    after
      5_000 -> flunk("actor operation timed out")
    end
  end

  defp stop_actor(pid) do
    monitor = Process.monitor(pid)
    send(pid, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
  end

  defp eventually(fun, timeout \\ 1_000, assert? \\ true) do
    expiry = System.monotonic_time(:millisecond) + timeout
    poll(fun, expiry, assert?)
  end

  defp poll(fun, expiry, assert?) do
    cond do
      fun.() ->
        :ok

      System.monotonic_time(:millisecond) >= expiry ->
        if(assert?, do: flunk("condition did not become true"), else: :ok)

      true ->
        receive do
        after
          1 -> poll(fun, expiry, assert?)
        end
    end
  end
end

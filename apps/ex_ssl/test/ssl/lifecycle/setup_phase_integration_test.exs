defmodule SSL.Lifecycle.SetupPhaseIntegrationTest do
  use ExUnit.Case, async: false
  alias SSL.Lifecycle
  alias SSL.Lifecycle.{Observer, Receipt}
  @moduletag :integration

  @ip {127, 0, 0, 1}
  @fixtures Path.expand("../../../../http_fetch/test/support/fixtures", __DIR__)
  @peer Path.expand("../../../../http_fetch/test/support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      transport <- [:native, :adopted],
      rejection <- [:wrong_ca, :wrong_identity] do
    test "#{version} #{transport} #{rejection} publishes phase before cleanup and preserves the peer alert" do
      assert_fatal_alert(unquote(version), unquote(transport), unquote(rejection))
    end
  end

  test "only a timely original Connection nonce commit publishes durable phase separately from cleanup" do
    a = enrolled_attempt() |> committed()
    attempt = elem(a.lease, 0)
    handle = %Lifecycle.Handle{receipt: a.receipt}
    assert :unknown = Lifecycle.setup_failure(handle)
    assert {:error, _} = Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())

    for actor <- [a.setup, a.writer, a.allocator] do
      assert {:error, _} =
               in_actor(actor, fn ->
                 Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
               end)
    end

    for {id, epoch} <- [{make_ref(), 0}, {attempt, 1}] do
      assert {:error, _} =
               in_actor(a.connection, fn ->
                 Observer.prepare_setup_failure(a.receipt, id, epoch, deadline())
               end)
    end

    {:ok, nonce} =
      in_actor(a.connection, fn ->
        Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
      end)

    assert :unknown = Lifecycle.setup_failure(handle)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.commit_setup_failure(a.receipt, attempt, 0, make_ref(), deadline())
             end)

    assert {:error, _} = Observer.commit_setup_failure(a.receipt, attempt, 0, nonce, deadline())

    assert :ok =
             in_actor(a.connection, fn ->
               Observer.commit_setup_failure(a.receipt, attempt, 0, nonce, deadline())
             end)

    assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
    assert :unsealed = Receipt.read(a.receipt)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.commit_setup_failure(a.receipt, attempt, 0, nonce, deadline())
             end)

    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    assert {:ok, _} = Lifecycle.await(handle, deadline())
    observer_monitor = Process.monitor(a.observer)
    assert_receive {:DOWN, ^observer_monitor, :process, _, _}, 1_500
    assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
  end

  test "prepare alone and cancellation never publish a phase" do
    a = enrolled_attempt() |> committed()
    attempt = elem(a.lease, 0)

    {:ok, _nonce} =
      in_actor(a.connection, fn ->
        Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
      end)

    handle = %Lifecycle.Handle{receipt: a.receipt}
    assert :unknown = Lifecycle.setup_failure(handle)
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
    assert {:ok, _} = Lifecycle.await(handle, deadline())
    assert :unknown = Lifecycle.setup_failure(handle)
  end

  test "lost prepare reply grants no public phase without an echoed commit" do
    a = enrolled_attempt() |> committed()
    attempt = elem(a.lease, 0)
    assert :ok = :sys.suspend(a.observer)

    try do
      assert :timeout =
               in_actor(a.connection, fn ->
                 request =
                   :gen_server.send_request(
                     a.observer,
                     {{:prepare_setup_failure, attempt, 0}, deadline()}
                   )

                 :gen_server.receive_response(request, 0)
               end)
    after
      :sys.resume(a.observer)
    end

    assert {:ok, _} = in_actor(a.connection, fn -> Observer.snapshot(a.receipt, deadline()) end)
    assert %{caller: caller, nonce: nonce} = :sys.get_state(a.observer).setup_phase_grant
    assert caller == a.connection and is_reference(nonce)
    assert :unknown = Lifecycle.setup_failure(%Lifecycle.Handle{receipt: a.receipt})
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
  end

  test "accepted timely commit survives a dropped final reply" do
    a = enrolled_attempt() |> committed()
    attempt = elem(a.lease, 0)

    {:ok, nonce} =
      in_actor(a.connection, fn ->
        Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
      end)

    assert :ok = :sys.suspend(a.observer)

    try do
      assert :timeout =
               in_actor(a.connection, fn ->
                 request =
                   :gen_server.send_request(
                     a.observer,
                     {{:commit_setup_failure, attempt, 0, nonce}, deadline()}
                   )

                 :gen_server.receive_response(request, 0)
               end)
    after
      :sys.resume(a.observer)
    end

    assert {:ok, _} = in_actor(a.connection, fn -> Observer.snapshot(a.receipt, deadline()) end)

    assert {:ok, %{phase: :tls_setup}} =
             Lifecycle.setup_failure(%Lifecycle.Handle{receipt: a.receipt})

    assert :unsealed = Receipt.read(a.receipt)
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
  end

  test "suspended Observer cannot accept a commit after the prepare grant expires" do
    a = enrolled_attempt() |> committed()
    attempt = elem(a.lease, 0)
    grant_deadline = deadline(100)

    {:ok, nonce} =
      in_actor(a.connection, fn ->
        Observer.prepare_setup_failure(a.receipt, attempt, 0, grant_deadline)
      end)

    assert :ok = :sys.suspend(a.observer)

    try do
      assert :timeout =
               in_actor(a.connection, fn ->
                 request =
                   :gen_server.send_request(
                     a.observer,
                     {{:commit_setup_failure, attempt, 0, nonce}, deadline()}
                   )

                 :gen_server.receive_response(request, 0)
               end)

      wait_until(elem(grant_deadline, 1) + 10)
    after
      :sys.resume(a.observer)
    end

    assert {:ok, _} = in_actor(a.connection, fn -> Observer.snapshot(a.receipt, deadline()) end)
    assert :unknown = Lifecycle.setup_failure(%Lifecycle.Handle{receipt: a.receipt})
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
  end

  test "original setup deadline rejects a later commit even with a longer control deadline" do
    original = deadline(300)
    a = enrolled_attempt(original) |> committed()
    attempt = elem(a.lease, 0)

    {:ok, nonce} =
      in_actor(a.connection, fn ->
        Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
      end)

    assert :ok = :sys.suspend(a.observer)

    try do
      assert :timeout =
               in_actor(a.connection, fn ->
                 request =
                   :gen_server.send_request(
                     a.observer,
                     {{:commit_setup_failure, attempt, 0, nonce}, deadline()}
                   )

                 :gen_server.receive_response(request, 0)
               end)

      wait_until(elem(original, 1) + 10)
    after
      :sys.resume(a.observer)
    end

    handle = %Lifecycle.Handle{receipt: a.receipt}
    assert {:ok, %{setup_failure: :timeout}} = Lifecycle.await(handle, deadline())
    assert :unknown = Lifecycle.setup_failure(handle)
  end

  test "prepare and commit each require the original committed TCP ownership" do
    a = enrolled_attempt()
    attempt = elem(a.lease, 0)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
             end)

    a = committed(a)
    assert :ok = in_actor(a.connection, fn -> :gen_tcp.controlling_process(a.tcp, a.setup) end)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
             end)

    assert :ok = in_actor(a.setup, fn -> :gen_tcp.controlling_process(a.tcp, a.connection) end)

    {:ok, nonce} =
      in_actor(a.connection, fn ->
        Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
      end)

    assert :ok = in_actor(a.connection, fn -> :gen_tcp.controlling_process(a.tcp, a.setup) end)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.commit_setup_failure(a.receipt, attempt, 0, nonce, deadline())
             end)

    assert :unknown = Lifecycle.setup_failure(%Lifecycle.Handle{receipt: a.receipt})
    assert :ok = in_actor(a.setup, fn -> :gen_tcp.controlling_process(a.tcp, a.connection) end)
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
  end

  test "a connected outcome cannot later publish setup failure" do
    a = enrolled_attempt() |> committed()
    attempt = elem(a.lease, 0)

    assert :ok =
             in_actor(a.setup, fn -> Observer.publish_setup(a.receipt, :connected, deadline()) end)

    assert {:error, _} =
             in_actor(a.connection, fn ->
               Observer.prepare_setup_failure(a.receipt, attempt, 0, deadline())
             end)

    assert :unknown = Lifecycle.setup_failure(%Lifecycle.Handle{receipt: a.receipt})
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
  end

  test "late prepare acceptance cannot create a grant or phase" do
    a = enrolled_attempt() |> committed()
    attempt = elem(a.lease, 0)
    prepare_deadline = deadline(100)
    assert :ok = :sys.suspend(a.observer)

    try do
      assert :timeout =
               in_actor(a.connection, fn ->
                 request =
                   :gen_server.send_request(
                     a.observer,
                     {{:prepare_setup_failure, attempt, 0}, prepare_deadline}
                   )

                 :gen_server.receive_response(request, 0)
               end)

      wait_until(elem(prepare_deadline, 1) + 10)
    after
      :sys.resume(a.observer)
    end

    assert {:ok, _} = in_actor(a.connection, fn -> Observer.snapshot(a.receipt, deadline()) end)
    assert :sys.get_state(a.observer).setup_phase_grant == nil
    assert :unknown = Lifecycle.setup_failure(%Lifecycle.Handle{receipt: a.receipt})
    assert :ok = Observer.cancel(a.receipt, a.lease, deadline())
  end

  test "an actual early peer alert before ServerHello never establishes public phase" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 2_000)

        try do
          assert {:ok, <<22, 3, _, size::16>>} = :gen_tcp.recv(tcp, 5, 2_000)
          assert {:ok, <<1, _::binary>>} = :gen_tcp.recv(tcp, size, 2_000)
          :ok = :gen_tcp.send(tcp, <<21, 3, 3, 0, 2, 2, 40>>)
          assert {:error, :closed} = :gen_tcp.recv(tcp, 0, 2_000)
        after
          :gen_tcp.close(tcp)
        end
      end)

    on_exit(fn -> if Process.alive?(peer.pid), do: Task.shutdown(peer, :brutal_kill) end)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))
    on_exit(fn -> Lifecycle.cancel(lease, deadline(500)) end)

    assert {:error, {:peer_alert, 2, 40}} =
             SSL.connect(
               @ip,
               port,
               [verify: :verify_none, cacerts: [], ex_ssl: [lifecycle: {handle, lease}]],
               2_000
             )

    assert :unknown = Lifecycle.setup_failure(handle)
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
    assert {:error, :closed} = Task.await(peer, 2_000)
  end

  for {level, description, expected} <- [
        {1, 0, :unknown},
        {1, 90, :unknown},
        {1, 40, :unknown},
        {2, 0, :unknown},
        {2, 90, :unknown},
        {2, 40, {:ok, %{phase: :tls_setup}}}
      ] do
    test "accepted TLS12 hello then peer alert #{level}/#{description} preserves conservative phase" do
      level = unquote(level)
      description = unquote(description)
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: @ip])
      on_exit(fn -> :gen_tcp.close(listener) end)
      {:ok, {_, port}} = :inet.sockname(listener)

      peer =
        Task.async(fn ->
          {:ok, tcp} = :gen_tcp.accept(listener, 2_000)

          try do
            assert {:ok, <<22, 3, _, size::16>>} = :gen_tcp.recv(tcp, 5, 2_000)
            assert {:ok, <<1, _::binary>>} = :gen_tcp.recv(tcp, size, 2_000)
            extensions = <<23::16, 0::16, 0xFF01::16, 1::16, 0>>

            body =
              <<3, 3, 7::256, 0, 0xC02F::16, 0, byte_size(extensions)::16, extensions::binary>>

            hello = <<2, byte_size(body)::24, body::binary>>

            :ok =
              :gen_tcp.send(tcp, [
                <<22, 3, 3, byte_size(hello)::16, hello::binary>>,
                <<21, 3, 3, 0, 2, level, description>>
              ])

            assert {:error, :closed} = :gen_tcp.recv(tcp, 0, 2_000)
          after
            :gen_tcp.close(tcp)
          end
        end)

      on_exit(fn -> if Process.alive?(peer.pid), do: Task.shutdown(peer, :brutal_kill) end)
      {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))
      on_exit(fn -> Lifecycle.cancel(lease, deadline(500)) end)

      assert {:error, {:peer_alert, ^level, ^description}} =
               SSL.connect(
                 @ip,
                 port,
                 [
                   versions: [:"tlsv1.2"],
                   verify: :verify_none,
                   cacerts: [],
                   ex_ssl: [lifecycle: {handle, lease}]
                 ],
                 2_000
               )

      assert unquote(Macro.escape(expected)) == Lifecycle.setup_failure(handle)
      assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
      assert {:error, :closed} = Task.await(peer, 2_000)
    end
  end

  for transport <- [:native, :adopted], trigger <- [:cancel, :deadline] do
    test "#{transport} #{trigger} during verification before fatal outcome keeps phase unknown" do
      transport = unquote(transport)
      trigger = unquote(trigger)
      {peer, port} = peer("TLSv1.3", "http/1.1", "forward")
      parent = self()
      reference = make_ref()
      {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(1_000))

      callback = fn _, event, state ->
        if event == :valid_peer do
          send(parent, {reference, :verifying})
          receive do: ({^reference, :reject} -> {:fail, :rejected})
        else
          {:valid, state}
        end
      end

      options = [
        versions: [:"tlsv1.3"],
        cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
        server_name_indication: ~c"localhost",
        alpn_advertised_protocols: ["http/1.1"],
        verify_fun: {callback, nil},
        ex_ssl: [lifecycle: {handle, lease}]
      ]

      owner = Task.async(fn -> connect(transport, port, options) end)

      on_exit(fn ->
        Lifecycle.cancel(lease, deadline(500))
        if Process.alive?(owner.pid), do: Task.shutdown(owner, :brutal_kill)
      end)

      assert_receive {^reference, :verifying}, 1_000
      assert :unknown = Lifecycle.setup_failure(handle)
      verification_stop(trigger, lease)
      assert {:error, _} = Task.await(owner, 2_000)
      assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
      assert :unknown = Lifecycle.setup_failure(handle)
      state = stats(peer, &(&1["closed_connections"] == 1))
      assert state["requests"] == []
      stop_peer(peer)
    end
  end

  defp verification_stop(:cancel, lease), do: assert(:ok = Lifecycle.cancel(lease, deadline(500)))
  defp verification_stop(:deadline, _lease), do: :ok

  defp wait_until(absolute) do
    timer = :erlang.start_timer(absolute, self(), :boundary, abs: true)
    assert_receive {:timeout, ^timer, :boundary}, 2_000
  end

  for transport <- [:native, :adopted], trigger <- [:output_timeout, :cancel, :deadline] do
    test "#{transport} fatal output commits phase before bounded drain with #{trigger}" do
      assert_pending_output(unquote(transport), unquote(trigger))
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "successful #{version} handshake and HTTP send never publish a failure phase" do
      version = unquote(version)
      {peer, port} = peer(wire(version), "http/1.1", "forward")
      {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))
      on_exit(fn -> Lifecycle.cancel(lease, deadline(500)) end)

      options = [
        versions: [version],
        cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
        server_name_indication: ~c"localhost",
        alpn_advertised_protocols: ["http/1.1"],
        active: false,
        mode: :binary,
        ex_ssl: [lifecycle: {handle, lease}]
      ]

      assert {:ok, socket} = SSL.connect(@ip, port, options, 2_000)
      assert :unknown = Lifecycle.setup_failure(handle)
      assert :ok = SSL.send(socket, "GET /success HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert {:ok, response} = SSL.recv(socket, 0, 2_000)
      assert response =~ "HTTP/1.1 200 OK"
      assert :ok = SSL.close(socket)
      assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
      assert :unknown = Lifecycle.setup_failure(handle)
      state = stats(peer, &(&1["closed_connections"] == 1))
      assert [%{"method" => "GET", "target" => "/success"}] = state["requests"]
      stop_peer(peer)
    end
  end

  defp assert_pending_output(transport, trigger) do
    {peer, port} = peer("TLSv1.3", "http/1.1", "forward")
    parent = self()
    ref = make_ref()
    {:abs_ms, expiry} = setup_deadline = deadline(2_000)
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: setup_deadline)

    verify = fn _, event, state ->
      if event == :valid_peer do
        send(parent, {ref, :verification, self()})
        receive do: ({^ref, :reject} -> {:fail, :rejected})
      else
        {:valid, state}
      end
    end

    options = [
      verify: :verify_peer,
      cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
      server_name_indication: ~c"localhost",
      versions: [:"tlsv1.3"],
      alpn_advertised_protocols: ["http/1.1"],
      verify_fun: {verify, nil},
      ex_ssl: [lifecycle: {handle, lease}]
    ]

    caller = Task.async(fn -> connect(transport, port, options) end)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(500))
      if Process.alive?(caller.pid), do: Task.shutdown(caller, :brutal_kill)
    end)

    assert_receive {^ref, :verification, connection}, 1_000
    # Provider fault instrumentation holds the original enrolled Writer. The
    # terminal assertion uses the public join, including actual resource DOWN.
    %{resources: resources} = :sys.get_state(handle.receipt.observer)
    %{identity: {_, :process, writer}} = resources.writer
    writer_monitor = Process.monitor(writer)
    assert true = :erlang.suspend_process(writer)

    if trigger == :deadline do
      remaining = max(expiry - System.monotonic_time(:millisecond) - 100, 0)

      receive do
      after
        remaining -> :ok
      end
    end

    sent = System.monotonic_time(:millisecond)
    send(connection, {ref, :reject})
    assert {:closing, pending} = :sys.get_state(connection)
    assert pending.output.kind == :fatal_alert
    assert pending.output.deadline <= sent + 300
    assert pending.lifecycle.tls.outcome_pending
    assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
    assert :unsealed = Receipt.read(handle.receipt)
    assert Task.yield(caller, 0) == nil

    if trigger == :cancel, do: assert(:ok = Lifecycle.cancel(lease, deadline(500)))

    assert {:error, _} = Task.await(caller, 1_000)

    assert {:ok, %{cleanup: :confirmed, losses: 0}} =
             Lifecycle.await(handle, deadline(1_000))

    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000
    refute Process.alive?(connection)
    assert System.monotonic_time(:millisecond) - sent < 1_000
    if trigger == :deadline, do: assert(System.monotonic_time(:millisecond) < expiry + 200)
    stop_peer(peer)
  end

  defp assert_fatal_alert(version, transport, rejection) do
    {peer, port} = peer(wire(version), "http/1.1", "forward")
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(3_000))
    on_exit(fn -> Lifecycle.cancel(lease, deadline(500)) end)

    options = [
      verify: :verify_peer,
      cacertfile: Path.join(@fixtures, authority(rejection)),
      server_name_indication: identity(rejection),
      versions: [version],
      alpn_advertised_protocols: ["http/1.1"],
      active: false,
      mode: :binary,
      ex_ssl: [lifecycle: {handle, lease}]
    ]

    expected = alert(version, rejection)
    assert {:error, {:tls_alert, {^expected, _}}} = connect(transport, port, options)
    assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
    state = stats(peer, &(&1["closed_connections"] == 1))
    assert state["accepted_connections"] == 1
    assert state["requests"] == []
    assert [%{"kind" => "tls", "reason" => reason}] = state["errors"]
    assert reason =~ expected |> Atom.to_string() |> String.upcase()
    assert reason =~ "ALERT"
    stop_peer(peer)

    assert {:ok, %{setup: :failed, setup_failure: :tls, cleanup: :confirmed, losses: 0}} =
             Lifecycle.await(handle, deadline(1_000))

    assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
  end

  defp connect(:native, port, options), do: SSL.connect(@ip, port, options, 2_000)

  defp connect(:adopted, port, options) do
    {:ok, tcp} = :gen_tcp.connect(@ip, port, [:binary, active: false], 1_000)
    SSL.connect(tcp, options, 2_000)
  end

  defp authority(:wrong_ca), do: "pinned-ca.pem"
  defp authority(:wrong_identity), do: "localhost-ca.pem"
  defp identity(:wrong_ca), do: ~c"localhost"
  defp identity(:wrong_identity), do: ~c"wrong.invalid"
  defp alert(:"tlsv1.2", _), do: :bad_certificate
  defp alert(:"tlsv1.3", :wrong_ca), do: :unknown_ca
  defp alert(:"tlsv1.3", :wrong_identity), do: :certificate_unknown
  defp wire(:"tlsv1.2"), do: "TLSv1.2"
  defp wire(:"tlsv1.3"), do: "TLSv1.3"

  defp peer(version, protocol, route) do
    port =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          @peer,
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key"),
          "--tls",
          version,
          "--protocol",
          protocol,
          "--route",
          route
        ]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    assert %{"event" => "ready", "port" => number} = event(port)
    {port, number}
  end

  defp event(peer) do
    receive do
      {^peer, {:data, {:eol, line}}} ->
        if System.get_env("P3_PROXY_PEER_EVIDENCE"), do: IO.puts("P3_PROXY_PEER " <> line)
        JSON.decode!(line)

      {^peer, {:exit_status, code}} ->
        flunk("independent proxy peer exit #{code}")
    after
      5_000 -> flunk("independent proxy peer timeout")
    end
  end

  defp stats(peer, predicate),
    do: stats(peer, predicate, System.monotonic_time(:millisecond) + 2_000)

  defp stats(peer, predicate, deadline) do
    assert Port.command(peer, JSON.encode!(%{command: "stats"}) <> "\n")
    result = event(peer)

    if predicate.(result) do
      result
    else
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        2 -> stats(peer, predicate, deadline)
      end
    end
  end

  defp stop_peer(peer) do
    assert Port.command(peer, JSON.encode!(%{command: "stop"}) <> "\n")
    assert event(peer)["event"] == "stop"
    assert_receive {^peer, {:exit_status, 0}}, 5_000
  end

  # Cooperative protocol actors below are NOT actual TLS engine actors.
  defp enrolled_attempt(original \\ :infinity) do
    enrollment_deadline = deadline(5_000)
    {:ok, receipt, lease} = Observer.start(self(), original)
    observer = Receipt.observer(receipt)
    on_exit(fn -> if Process.alive?(observer), do: Process.exit(observer, :kill) end)
    assert :ok = Observer.bind(receipt, lease, enrollment_deadline)

    {:ok, allocator_permit} =
      Observer.reserve_root(receipt, lease, :allocator, enrollment_deadline)

    {:ok, setup_permit} = Observer.reserve_root(receipt, lease, :setup, enrollment_deadline)
    allocator = enrolled_actor(receipt, :allocator, allocator_permit, enrollment_deadline)
    setup = enrolled_actor(receipt, :setup, setup_permit, enrollment_deadline)

    {:ok, connection_permit} =
      in_actor(setup, fn -> Observer.reserve_child(receipt, :connection, enrollment_deadline) end)

    connection = enrolled_actor(receipt, :connection, connection_permit, enrollment_deadline)

    {:ok, writer_permit} =
      in_actor(connection, fn -> Observer.reserve_child(receipt, :writer, enrollment_deadline) end)

    writer = enrolled_actor(receipt, :writer, writer_permit, enrollment_deadline)

    {:ok, tcp_permit} =
      in_actor(allocator, fn -> Observer.reserve_child(receipt, :tcp, enrollment_deadline) end)

    # Listener and peer are test fixtures outside the attempt's resource set.
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, packet: :raw, ip: {127, 0, 0, 1}])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port_number}} = :inet.sockname(listener)

    {:ok, tcp} =
      in_actor(allocator, fn ->
        :gen_tcp.connect(
          {127, 0, 0, 1},
          port_number,
          [:binary, active: false, packet: :raw],
          SSL.Options.remaining(elem(enrollment_deadline, 1))
        )
      end)

    {:ok, peer} = :gen_tcp.accept(listener, 1_000)
    on_exit(fn -> :gen_tcp.close(peer) end)
    tcp_monitor = :erlang.monitor(:port, tcp)
    assert Port.info(tcp, :connected) == {:connected, allocator}

    assert :use =
             in_actor(allocator, fn ->
               Observer.enroll_port(receipt, tcp_permit, tcp, enrollment_deadline)
             end)

    assert {:ok, %{roles: 31, allocations: 0, losses: 0, admission: :open}} =
             Observer.snapshot(receipt, enrollment_deadline)

    %{
      receipt: receipt,
      lease: lease,
      observer: observer,
      allocator: allocator,
      setup: setup,
      connection: connection,
      writer: writer,
      tcp: tcp,
      peer: peer,
      tcp_monitor: tcp_monitor
    }
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

  defp committed(a) do
    {a, grant} = prepared(a)
    :ok = in_actor(a.connection, fn -> Observer.commit_handoff(a.receipt, grant, deadline()) end)
    a
  end

  defp prepared(a) do
    d = deadline()
    {:ok, ready} = in_actor(a.writer, fn -> Observer.writer_ready(a.receipt, d) end)
    :ok = in_actor(a.connection, fn -> Observer.connection_ready(a.receipt, ready, d) end)

    {:ok, grant} =
      in_actor(a.allocator, fn -> Observer.prepare_handoff(a.receipt, a.tcp, a.connection, d) end)

    :ok = in_actor(a.allocator, fn -> :gen_tcp.controlling_process(a.tcp, a.connection) end)
    {a, grant}
  end

  defp deadline(ms \\ 2_000), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

defmodule SSL.Lifecycle.PolicySetupPhaseIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :policy_setup
  alias ExSSL.TestSupport.{RevocationFixtures, RevocationPeer}
  alias SSL.Lifecycle
  alias SSL.Lifecycle.Receipt

  for {version, peer_type} <- [
        {:"tlsv1.2", :independent},
        {:"tlsv1.3", :independent},
        {:"tlsv1.2", :constructed_same_record}
      ],
      route <- [:direct, :prepared],
      io <- [:http, :hash],
      material <- [:revoked, :invalid] do
    test "#{version} #{peer_type} #{route} builtin #{io} #{material} retains phase and independent auxiliary proof",
         %{directory: directory} do
      version = unquote(version)

      alert =
        unquote(
          if version == :"tlsv1.2" or material == :invalid,
            do: :bad_certificate,
            else: :unknown_ca
        )

      route = unquote(route)
      source = policy_source(directory, unquote(io), unquote(material))
      peer = start_policy_peer(directory, version, unquote(peer_type))
      {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: deadline(10_000))
      monitor = Process.monitor(handle.receipt.observer)
      reference = make_ref()
      options = policy_options(directory, version, source, self(), reference)

      try do
        result = connect_policy(peer.port, options, route, {handle, lease})
        assert {:error, {:tls_alert, {^alert, _}}} = result
        assert_policy_event(reference, unquote(material))
        refute inspect(result) =~ directory
        assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
        assert :ok = source.join.()
        assert_policy_peer(peer, unquote(peer_type))
        mask = unquote(if route == :direct, do: 31, else: 30)
        auxiliary_roles = source.roles

        assert {:ok,
                %{
                  version: 2,
                  cleanup: :confirmed,
                  roles: ^mask,
                  observed_down: ^mask,
                  losses: 0,
                  auxiliary: %{
                    roles: ^auxiliary_roles,
                    observed_down: ^auxiliary_roles,
                    losses: 0
                  }
                }} =
                 Lifecycle.await(handle, deadline(3_000))

        assert_receive {:DOWN, ^monitor, :process, _, :normal}, 500
        assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(handle)
        assert_independent_extension(handle.receipt)
      after
        source.stop.()
        RevocationPeer.stop(peer)
        Lifecycle.cancel(lease, deadline(500))
      end
    end
  end

  # Reader fault controls on a retained real-I/O receipt. These prove missing,
  # incomplete and lost extension payload cannot inherit primary confirmation;
  # they do not claim to delay a native operation or suppress its actual ACK.
  defp assert_independent_extension(receipt) do
    assert :atomics.info(receipt.cell).size == 8
    assert :atomics.info(receipt.setup_phase).size == 1
    assert :atomics.info(receipt.auxiliary_cell).size == 4
    missing = %{receipt | auxiliary_cell: nil}
    assert {:ok, %{phase: :tls_setup}} = Receipt.setup_failure(missing)
    assert {:error, :invalid_evidence} = Receipt.read(missing)

    cell = :atomics.new(4, signed: false)
    incomplete = %{receipt | auxiliary_cell: cell}
    assert {:error, :invalid_evidence} = Receipt.read(incomplete)
    for index <- 1..3, do: :atomics.put(cell, index, :atomics.get(receipt.auxiliary_cell, index))
    assert {:error, :invalid_evidence} = Receipt.read(incomplete)
    :atomics.put(cell, 4, 1)
    assert Receipt.read(incomplete) == Receipt.read(receipt)
    :atomics.put(cell, 3, :atomics.get(cell, 1))
    assert {:sealed, %{cleanup: :unconfirmed}} = Receipt.read(incomplete)
    assert {:ok, %{phase: :tls_setup}} = Receipt.setup_failure(incomplete)
  end

  # This peer constructs one TLS12 record containing ServerHello and Certificate.
  # Its signed flight is deterministic parser/progress coverage, not independent
  # interoperability; independent OpenSSL cases above cover real peer behavior.
  defp start_policy_peer(directory, version, :independent),
    do: RevocationPeer.start(directory, version)

  defp start_policy_peer(directory, :"tlsv1.2", :constructed_same_record),
    do: RevocationPeer.start_tls12(directory, status: :not_negotiated, fragment: false)

  defp assert_policy_peer(_peer, :independent), do: :ok

  defp assert_policy_peer(peer, :constructed_same_record) do
    assert %{result: {:rejected, 42}} = RevocationPeer.join_tls13(peer)
  end

  defp connect_policy(port, options, :direct, lifecycle),
    do: SSL.connect(~c"127.0.0.1", port, options ++ [ex_ssl: [lifecycle: lifecycle]], 5_000)

  defp connect_policy(port, options, :prepared, lifecycle) do
    {:ok, prepared} = SSL.prepare_upgrade(options)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 5_000)
    SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: lifecycle]], 5_000)
  end

  setup_all do
    {:ok, directory: RevocationFixtures.directory!()}
  end

  defp policy_source(directory, :hash, :revoked) do
    %{
      options: [
        crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: Path.join(directory, "revoked")]}}
      ],
      roles: 2,
      join: fn -> :ok end,
      stop: fn -> :ok end
    }
  end

  defp policy_source(directory, :hash, :invalid) do
    good = File.read!(Path.join(directory, "leaf-good.crl.pem"))

    filename =
      Path.wildcard(Path.join([directory, "good", "*.r0"]))
      |> Enum.find(&(File.read!(&1) == good))
      |> Path.basename()

    target = Path.join(directory, "setup-invalid-#{System.unique_integer([:positive])}")
    File.mkdir!(target)
    File.write!(Path.join(target, filename), <<48, 1, 0>>)

    %{
      options: [crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: target]}}],
      roles: 2,
      join: fn -> :ok end,
      stop: fn -> File.rm_rf!(target) end
    }
  end

  defp policy_source(directory, :http, material) do
    bytes =
      if material == :revoked,
        do: File.read!(Path.join(directory, "leaf-revoked.crl.der")),
        else: <<48, 1, 0>>

    {:ok, listener} =
      :gen_tcp.listen(18_749, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    server =
      Task.async(fn ->
        try do
          {:ok, socket} = :gen_tcp.accept(listener, 5_000)

          try do
            {:ok, request} = :gen_tcp.recv(socket, 0, 2_000)
            assert hd(String.split(request, "\r\n")) == "GET /leaf.crl HTTP/1.1"

            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(bytes)}\r\n\r\n" <> bytes
              )
          after
            :gen_tcp.close(socket)
          end
        after
          :gen_tcp.close(listener)
        end
      end)

    %{
      options: [crl_cache: {:ssl_crl_cache, {:internal, [http: 2_000]}}],
      roles: 1,
      join: fn -> assert :ok = Task.await(server, 5_000) end,
      stop: fn ->
        if Process.alive?(server.pid), do: Task.shutdown(server, :brutal_kill)
        :gen_tcp.close(listener)
      end
    }
  end

  defp assert_policy_event(reference, :revoked) do
    assert_receive {^reference, {:bad_cert, {:revoked, :keyCompromise}}}, 500
  end

  defp assert_policy_event(reference, :invalid) do
    # Invalid fetched ASN.1 is rejected before a status event can be authorized.
    refute_receive {^reference, {:bad_cert, _}}, 0
  end

  defp policy_options(directory, version, source, owner, reference) do
    verify = fn _, event, state ->
      case event do
        {:bad_cert, reason} ->
          send(owner, {reference, {:bad_cert, reason}})
          {:fail, :policy_rejected}

        {:extension, _} ->
          {:unknown, state}

        _ ->
          {:valid, state}
      end
    end

    RevocationFixtures.options(directory, version) ++
      [crl_check: :peer, verify_fun: {verify, nil}] ++ source.options
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

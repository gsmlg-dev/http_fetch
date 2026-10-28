defmodule SSL.Lifecycle.NestedTLSTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.{LocalTLSPeer, OpenSSLPeer}
  alias SSL.Lifecycle

  for route <- [:direct, :prepared],
      outer_version <- [:"tlsv1.2", :"tlsv1.3"],
      inner_version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{route} #{outer_version}/#{inner_version} reports separate receipts and one physical TCP" do
      {proxy, origin} = peers(unquote(outer_version), unquote(inner_version))
      {outer_handle, outer_lease} = attempt()
      {inner_handle, inner_lease} = attempt()

      assert {:ok, outer} =
               SSL.connect(
                 {127, 0, 0, 1},
                 proxy.port,
                 options(unquote(outer_version), "proxy", {outer_handle, outer_lease}),
                 3_000
               )

      assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)

      assert {:ok, inner} =
               connect(
                 unquote(route),
                 outer,
                 unquote(inner_version),
                 {inner_handle, inner_lease}
               )

      assert {:ok, _} = OpenSSLPeer.event(origin, "handshake", 2_000)
      assert {:ok, "proxy"} = SSL.negotiated_protocol(outer)
      assert {:ok, "origin"} = SSL.negotiated_protocol(inner)

      assert {:pending,
              %{
                scope: :dial,
                setup: :connected,
                provider_resources: %{tcp_sockets: 1, observers: 1, data_resources: 3}
              }} = Lifecycle.status(outer_handle, deadline(1_000))

      assert {:pending,
              %{
                scope: :layer,
                setup: :connected,
                roles: 14,
                provider_resources: %{tcp_sockets: 0, observers: 1, data_resources: 2}
              }} = Lifecycle.status(inner_handle, deadline(1_000))

      assert :ok = SSL.send(inner, <<0, 255, 42>>, deadline(1_000))
      assert {:ok, <<42, 255, 0>>} = SSL.recv(inner, 3, 2_000)
      assert :ok = SSL.close(inner)
      assert_cleanup(inner_handle, outer_handle)
      assert {:ok, %{"bytes" => forwarded}} = OpenSSLPeer.event(proxy, "exchange", 2_000)
      assert forwarded > 3
      assert {:ok, %{"accepted_connections" => 1}} = OpenSSLPeer.event(proxy, "closed", 2_000)
    end
  end

  test "inner cancellation joins its own processes and the outer native TCP" do
    {outer, inner, outer_handle, inner_handle, inner_lease} = connected()
    assert :ok = Lifecycle.cancel(inner_lease, deadline(1_000))
    assert_cleanup(inner_handle, outer_handle)
    assert {:error, :econnreset} = SSL.send(inner, "retired")
    assert {:error, reason} = SSL.negotiated_protocol(outer)
    # Outer owner-DOWN and Observer retirement race, as on scalar connections.
    assert reason in [:closed, :econnreset]
  end

  test "a foreign caller cannot bind the layer or retire the carrier" do
    {proxy, _origin} = peers(:"tlsv1.3", :"tlsv1.3")
    {outer_handle, outer_lease} = attempt()
    {inner_handle, inner_lease} = attempt()

    assert {:ok, outer} =
             SSL.connect(
               {127, 0, 0, 1},
               proxy.port,
               options(:"tlsv1.3", "proxy", {outer_handle, outer_lease}),
               3_000
             )

    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)

    caller =
      Task.async(fn -> connect(:direct, outer, :"tlsv1.3", {inner_handle, inner_lease}) end)

    assert {:error, :not_owner} = Task.await(caller, 2_000)
    assert {:pending, %{setup: :not_started, roles: 0}} = Lifecycle.status(inner_handle)
    assert {:ok, "proxy"} = SSL.negotiated_protocol(outer)
    assert :ok = SSL.close(outer)
  end

  test "inner authentication failure publishes setup phase separately from both cleanups" do
    {proxy, origin} = peers(:"tlsv1.3", :"tlsv1.3")
    {outer_handle, outer_lease} = attempt()
    {inner_handle, inner_lease} = attempt()

    assert {:ok, outer} =
             SSL.connect(
               {127, 0, 0, 1},
               proxy.port,
               options(:"tlsv1.3", "proxy", {outer_handle, outer_lease}),
               3_000
             )

    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)

    invalid =
      options(:"tlsv1.3", "origin", {inner_handle, inner_lease})
      |> Keyword.put(:server_name_indication, ~c"wrong.invalid")

    assert {:error, {:tls_alert, _}} = SSL.connect(outer, invalid, 3_000)
    assert {:ok, %{phase: :tls_setup}} = Lifecycle.setup_failure(inner_handle)

    assert {:ok, %{scope: :layer, setup: :failed, cleanup: :confirmed, roles: 14}} =
             Lifecycle.await(inner_handle, deadline(2_000))

    assert {:ok, %{scope: :dial, cleanup: :confirmed, roles: 31}} =
             Lifecycle.await(outer_handle, deadline(2_000))

    assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(origin, "handshake", 2_000)
  end

  test "inner application owner death retires both observed resource sets" do
    {_outer, inner, outer_handle, inner_handle, _lease} = connected()
    owner = spawn(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> Process.exit(owner, :kill) end)
    assert :ok = SSL.controlling_process(inner, owner)
    monitor = Process.monitor(owner)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}, 1_000
    assert_cleanup(inner_handle, outer_handle)
  end

  test "outer controller loss still joins the inner layer and the physical socket" do
    {outer, _inner, outer_handle, inner_handle, _lease} = connected()
    Process.exit(outer.pid, :kill)
    assert_cleanup(inner_handle, outer_handle)
  end

  test "a confirmed layer receipt cannot conceal loss of the outer observer" do
    {_outer, _inner, outer_handle, inner_handle, _lease} = connected()
    observer = outer_handle.receipt.observer
    monitor = Process.monitor(observer)
    Process.exit(observer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^observer, :killed}, 1_000

    assert {:ok, %{scope: :layer, cleanup: :confirmed, roles: 14}} =
             Lifecycle.await(inner_handle, deadline(2_000))

    assert {:unconfirmed, :observer_unsealed} = Lifecycle.await(outer_handle, deadline(2_000))
  end

  test "an active carrier fails before inner births and still retires the owned outer session" do
    {proxy, _origin} = peers(:"tlsv1.3", :"tlsv1.3")
    {outer_handle, outer_lease} = attempt()
    {inner_handle, inner_lease} = attempt()

    assert {:ok, outer} =
             SSL.connect(
               {127, 0, 0, 1},
               proxy.port,
               options(:"tlsv1.3", "proxy", {outer_handle, outer_lease}),
               3_000
             )

    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    assert :ok = SSL.setopts(outer, active: :once)

    assert {:error, {:options, :unsupported_tcp_state}} =
             connect(:direct, outer, :"tlsv1.3", {inner_handle, inner_lease})

    assert {:ok, %{scope: :layer, setup: :failed, roles: 0, cleanup: :confirmed}} =
             Lifecycle.await(inner_handle, deadline(2_000))

    assert {:ok, %{scope: :dial, roles: 31, cleanup: :confirmed}} =
             Lifecycle.await(outer_handle, deadline(2_000))
  end

  test "the original inner setup deadline bounds a stalled handshake and both cleanup receipts" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    parent = self()

    origin =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        {:ok, hello} = :gen_tcp.recv(socket, 0, 3_000)
        send(parent, {:inner_hello, byte_size(hello)})
        send(parent, {:stalled_origin_closed, :gen_tcp.recv(socket, 0, 3_000)})
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      monitor = Process.monitor(origin.pid)
      if Process.alive?(origin.pid), do: Process.exit(origin.pid, :kill)
      assert_receive {:DOWN, ^monitor, :process, _, _}, 1_000
    end)

    files = LocalTLSPeer.certificates()

    {:ok, proxy} =
      OpenSSLPeer.start(
        peer_options(files, :"tlsv1.3", "proxy", :tunnel) ++ [upstream_port: port]
      )

    on_exit(fn -> OpenSSLPeer.stop(proxy) end)
    {outer_handle, outer_lease} = attempt()
    {inner_handle, inner_lease} = attempt()

    assert {:ok, outer} =
             SSL.connect(
               {127, 0, 0, 1},
               proxy.port,
               options(:"tlsv1.3", "proxy", {outer_handle, outer_lease}),
               3_000
             )

    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    started = System.monotonic_time(:millisecond)

    assert {:error, :timeout} =
             SSL.connect(outer, options(:"tlsv1.3", "origin", {inner_handle, inner_lease}), 150)

    assert System.monotonic_time(:millisecond) - started < 1_000
    assert_receive {:inner_hello, bytes}, 1_000
    assert bytes > 0
    assert_cleanup(inner_handle, outer_handle)
    assert_receive {:stalled_origin_closed, {:error, :closed}}, 2_000
    Task.await(origin, 1_000)
  end

  test "the pair counts one physical socket and awaits both independent receipts" do
    {_outer, inner, handle, _lease, _layers} = pair_connected()

    assert {:pending,
            %{
              scope: :pair,
              setup: :connected,
              bound?: true,
              provider_resources: %{
                processes: 6,
                observers: 2,
                tcp_sockets: 1,
                data_resources: 5
              }
            }} = Lifecycle.status(handle, deadline(1_000))

    assert :ok = SSL.close(inner)

    assert {:ok,
            %{
              cleanup: :confirmed,
              layers: %{
                outer: %{scope: :dial, roles: 31, observed_down: 31},
                inner: %{scope: :layer, roles: 14, observed_down: 14}
              }
            }} = Lifecycle.await(handle, deadline(2_000))
  end

  for terminal <- [:timeout, :cancel, :peer_close, :observer_down] do
    @tag terminal: terminal
    test "queued observer DOWN preserves #{terminal} during nested setup", %{terminal: terminal} do
      parent = self()

      {:ok, peer} =
        LocalTLSPeer.start(
          fn socket ->
            assert {:ok, <<22, _::binary>>} = :ssl.recv(socket, 0, 2_000)
            send(parent, :nested_hello)

            receive do
              :close -> :ok
              :await_closed -> assert {:error, :closed} = :ssl.recv(socket, 0, 2_000)
            after
              2_000 -> flunk("nested peer was not released")
            end

            :ssl.close(socket)
          end,
          ssl_options: [alpn_preferred_protocols: ["proxy"]]
        )

      on_exit(fn ->
        stop_owned(peer.task.pid)
        :ssl.close(peer.listener)
      end)

      {outer_handle, outer_lease} = attempt()

      caller =
        Task.async(fn ->
          assert {:ok, outer} =
                   SSL.connect(
                     {127, 0, 0, 1},
                     peer.port,
                     options(:"tlsv1.3", "proxy", {outer_handle, outer_lease}),
                     3_000
                   )

          {:ok, inner_handle, inner_lease} =
            Lifecycle.new(controller: parent, deadline: deadline(500))

          send(parent, {:nested_attempt, inner_handle, inner_lease})
          SSL.connect(outer, options(:"tlsv1.3", "origin", {inner_handle, inner_lease}), 500)
        end)

      on_exit(fn -> stop_owned(caller.pid) end)
      assert_receive {:nested_attempt, inner_handle, inner_lease}, 2_000
      assert_receive :nested_hello, 2_000
      observer = inner_handle.receipt.observer
      monitor = Process.monitor(observer)
      assert :erlang.suspend_process(caller.pid)

      try do
        assert {:current_function, {SSL.Lifecycle.Driver, :await, 8}} =
                 Process.info(caller.pid, :current_function)

        send(peer.task.pid, if(terminal == :peer_close, do: :close, else: :await_closed))

        case terminal do
          :timeout -> :ok
          :cancel -> assert :ok = Lifecycle.cancel(inner_lease, deadline(1_000))
          :peer_close -> :ok
          :observer_down -> Process.exit(observer, :kill)
        end

        assert_receive {:DOWN, ^monitor, :process, ^observer, _}, 2_000

        case terminal do
          :timeout ->
            assert {:ok, %{setup_failure: :timeout, cleanup: :confirmed}} =
                     Lifecycle.await(inner_handle, deadline(0))

          :cancel ->
            assert {:ok, %{setup_failure: :cancelled, cleanup: :confirmed}} =
                     Lifecycle.await(inner_handle, deadline(0))

          :peer_close ->
            assert {:ok, %{setup: :failed, setup_failure: :tls, cleanup: :confirmed}} =
                     Lifecycle.await(inner_handle, deadline(0))

          :observer_down ->
            assert {:unconfirmed, :observer_unsealed} = Lifecycle.await(inner_handle, deadline(0))
        end
      after
        :erlang.resume_process(caller.pid)
      end

      expected =
        case terminal do
          :timeout -> :timeout
          :peer_close -> :econnreset
          _ -> :closed
        end

      assert {:error, ^expected} = Task.await(caller, 1_000)

      assert {:ok, %{scope: :dial, cleanup: :confirmed, roles: 31, observed_down: 31}} =
               Lifecycle.await(outer_handle, deadline(2_000))

      assert :ok = Task.await(peer.task, 1_000)
    end
  end

  test "pair acceptance preserves the outer carrier owner and recovers both accepted leases" do
    {_outer, inner, handle, lease, _layers} = pair_connected()
    recipient = recipient()

    assert {:ok, transfer} =
             Lifecycle.offer(lease, %{controller: recipient, owner: recipient}, deadline(1_000))

    assert {:error, {:outer, :not_recipient}} = Lifecycle.accept(transfer, deadline(1_000))
    send(recipient, {:accept, transfer, deadline(1_000)})
    assert_receive {^recipient, :accept, {:ok, accepted}}, 1_000
    send(recipient, {:accept, transfer, deadline(1_000)})
    assert_receive {^recipient, :accept, {:ok, ^accepted}}, 1_000

    assert {:pending,
            %{
              epoch: {1, 1},
              transfer: :accepted,
              layers: %{outer: %{epoch: 1}, inner: %{epoch: 1}}
            }} = Lifecycle.status(handle)

    assert {:error, {:outer, :stale_lease}} = Lifecycle.cancel(lease, deadline(1_000))
    send(recipient, {:exchange, inner})
    assert_receive {^recipient, :exchange, {:ok, <<42, 255, 0>>}}, 2_000
    assert :ok = Lifecycle.cancel(accepted, deadline(1_000))
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
  end

  test "partial pair acceptance keeps the source inner lease able to retire both layers" do
    {_outer, _inner, handle, lease, layers} = pair_connected()
    recipient = recipient()

    assert {:ok, transfer} =
             Lifecycle.offer(lease, %{controller: recipient, owner: recipient}, deadline(1_000))

    {inner_handle, _} = layers.inner
    observer = inner_handle.receipt.observer
    :erlang.suspend_process(observer)

    try do
      send(recipient, {:accept, transfer, deadline(150)})
      assert_receive {^recipient, :accept, {:error, {:inner, :acceptance_unconfirmed}}}, 500
    after
      :erlang.resume_process(observer)
    end

    assert {:pending, %{epoch: {1, 0}, transfer: :pending}} = Lifecycle.status(handle)
    assert {:error, {:outer, :stale_lease}} = Lifecycle.cancel(lease, deadline(1_000))
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
  end

  test "pair transfer supports a separate pool controller and application owner" do
    {_outer, inner, handle, lease, _layers} = pair_connected()
    controller = recipient()
    owner = recipient()

    assert {:ok, transfer} =
             Lifecycle.offer(lease, %{controller: controller, owner: owner}, deadline(1_000))

    send(controller, {:accept, transfer, deadline(1_000)})
    assert_receive {^controller, :accept, {:ok, accepted}}, 1_000
    send(owner, {:exchange, inner})
    assert_receive {^owner, :exchange, {:ok, <<42, 255, 0>>}}, 2_000
    assert :ok = Lifecycle.cancel(accepted, deadline(1_000))
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
  end

  test "a replacement pair offer fences both earlier transfer nonces" do
    {_outer, _inner, handle, lease, _layers} = pair_connected()
    recipient = recipient()
    target = %{controller: recipient, owner: recipient}
    assert {:ok, replaced} = Lifecycle.offer(lease, target, deadline(1_000))
    assert {:ok, current} = Lifecycle.offer(lease, target, deadline(1_000))
    send(recipient, {:accept, replaced, deadline(1_000)})
    assert_receive {^recipient, :accept, {:error, {:outer, :stale_transfer}}}, 1_000
    send(recipient, {:accept, current, deadline(1_000)})
    assert_receive {^recipient, :accept, {:ok, accepted}}, 1_000
    assert :ok = Lifecycle.cancel(accepted, deadline(1_000))
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
  end

  test "an expired pair offer never releases either source obligation" do
    {_outer, _inner, handle, lease, _layers} = pair_connected()
    recipient = recipient()

    assert {:ok, transfer} =
             Lifecycle.offer(lease, %{controller: recipient, owner: recipient}, deadline(50))

    Process.sleep(60)
    send(recipient, {:accept, transfer, deadline(1_000)})
    assert_receive {^recipient, :accept, {:error, {:outer, :offer_expired}}}, 1_000
    assert {:pending, %{epoch: {0, 0}, transfer: :expired}} = Lifecycle.status(handle)
    assert :ok = Lifecycle.cancel(lease, deadline(1_000))
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
  end

  test "pair recipient death retires the inner owner, both controllers and the physical TCP" do
    {_outer, _inner, handle, lease, _layers} = pair_connected()
    recipient = recipient()

    assert {:ok, transfer} =
             Lifecycle.offer(lease, %{controller: recipient, owner: recipient}, deadline(1_000))

    send(recipient, {:accept, transfer, deadline(1_000)})
    assert_receive {^recipient, :accept, {:ok, _}}, 1_000
    monitor = Process.monitor(recipient)
    Process.exit(recipient, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^recipient, :killed}, 1_000
    assert {:ok, %{cleanup: :confirmed}} = Lifecycle.await(handle, deadline(2_000))
  end

  defp pair_connected do
    {proxy, origin} = peers(:"tlsv1.3", :"tlsv1.3")
    assert {:ok, handle, lease} = Lifecycle.new_pair(controller: self(), deadline: :infinity)
    assert {:ok, layers} = Lifecycle.layers({handle, lease})

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(1_000))
      Lifecycle.await(handle, deadline(2_000))
    end)

    assert {:ok, outer} =
             SSL.connect(
               {127, 0, 0, 1},
               proxy.port,
               options(:"tlsv1.3", "proxy", layers.outer),
               3_000
             )

    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    assert {:ok, inner} = connect(:prepared, outer, :"tlsv1.3", layers.inner)
    assert {:ok, _} = OpenSSLPeer.event(origin, "handshake", 2_000)
    {outer, inner, handle, lease, layers}
  end

  defp recipient do
    parent = self()
    pid = spawn(fn -> recipient_loop(parent) end)
    on_exit(fn -> Process.exit(pid, :kill) end)
    pid
  end

  defp recipient_loop(parent) do
    receive do
      {:accept, transfer, deadline} ->
        send(parent, {self(), :accept, Lifecycle.accept(transfer, deadline)})
        recipient_loop(parent)

      {:exchange, socket} ->
        result =
          with :ok <- SSL.send(socket, <<0, 255, 42>>, deadline(1_000)),
               do: SSL.recv(socket, 3, 1_000)

        send(parent, {self(), :exchange, result})
        recipient_loop(parent)
    end
  end

  defp connected do
    {proxy, origin} = peers(:"tlsv1.3", :"tlsv1.3")
    {outer_handle, outer_lease} = attempt()
    {inner_handle, inner_lease} = attempt()

    assert {:ok, outer} =
             SSL.connect(
               {127, 0, 0, 1},
               proxy.port,
               options(:"tlsv1.3", "proxy", {outer_handle, outer_lease}),
               3_000
             )

    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    assert {:ok, inner} = connect(:direct, outer, :"tlsv1.3", {inner_handle, inner_lease})
    assert {:ok, _} = OpenSSLPeer.event(origin, "handshake", 2_000)
    {outer, inner, outer_handle, inner_handle, inner_lease}
  end

  defp connect(:direct, outer, version, descriptor),
    do: SSL.connect(outer, options(version, "origin", descriptor), 3_000)

  defp connect(:prepared, outer, version, descriptor) do
    assert {:ok, prepared} = SSL.prepare_upgrade(options(version, "origin"))
    SSL.connect_prepared(outer, prepared, [ex_ssl: [lifecycle: descriptor]], 3_000)
  end

  defp assert_cleanup(inner, outer) do
    assert {:ok, %{scope: :layer, cleanup: :confirmed, roles: 14, observed_down: 14}} =
             Lifecycle.await(inner, deadline(2_000))

    assert {:ok, %{scope: :dial, cleanup: :confirmed, roles: 31, observed_down: 31}} =
             Lifecycle.await(outer, deadline(2_000))
  end

  defp attempt do
    {:ok, handle, lease} = Lifecycle.new(controller: self(), deadline: :infinity)

    on_exit(fn ->
      Lifecycle.cancel(lease, deadline(1_000))
      Lifecycle.await(handle, deadline(2_000))
    end)

    {handle, lease}
  end

  defp stop_owned(pid) do
    monitor = Process.monitor(pid)
    if Process.alive?(pid), do: Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1_000
  end

  defp options(version, protocol, descriptor \\ nil) do
    options = [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      versions: [version],
      server_name_indication: ~c"exssl.test",
      cacerts: LocalTLSPeer.certificate_authorities(),
      alpn_advertised_protocols: [protocol],
      send_timeout: 1_000
    ]

    if descriptor, do: options ++ [ex_ssl: [lifecycle: descriptor]], else: options
  end

  defp peers(outer_version, inner_version) do
    files = LocalTLSPeer.certificates()
    {:ok, origin} = OpenSSLPeer.start(peer_options(files, inner_version, "origin", :raw3))
    on_exit(fn -> OpenSSLPeer.stop(origin) end)

    {:ok, proxy} =
      OpenSSLPeer.start(
        peer_options(files, outer_version, "proxy", :tunnel) ++ [upstream_port: origin.port]
      )

    on_exit(fn -> OpenSSLPeer.stop(proxy) end)
    {proxy, origin}
  end

  defp peer_options(files, version, alpn, mode) do
    version = if version == :"tlsv1.2", do: :tls12, else: :tls13

    [
      certfile: files.certfile,
      keyfile: files.keyfile,
      min_version: version,
      max_version: version,
      alpn: [alpn],
      mode: mode
    ]
  end

  defp deadline(ms), do: {:abs_ms, System.monotonic_time(:millisecond) + ms}
end

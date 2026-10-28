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

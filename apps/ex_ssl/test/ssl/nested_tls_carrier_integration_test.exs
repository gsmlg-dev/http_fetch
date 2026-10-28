defmodule SSL.NestedTLSCarrierIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.{LocalTLSPeer, OpenSSLPeer}

  defmodule OTPTransport do
    @moduledoc false
    defdelegate send(socket, bytes), to: :ssl
    defdelegate recv(socket, length, timeout), to: :ssl
    defdelegate setopts(socket, options), to: :ssl
    defdelegate getopts(socket, options), to: :ssl
    defdelegate peername(socket), to: :ssl
    defdelegate sockname(socket), to: :ssl
    defdelegate getstat(socket, options), to: :ssl
    defdelegate controlling_process(socket, owner), to: :ssl
    defdelegate shutdown(socket, direction), to: :ssl
    defdelegate close(socket), to: :ssl

    def port(socket) do
      with {:ok, {_address, port}} <- :ssl.sockname(socket), do: {:ok, port}
    end
  end

  for provider <- [:ex_ssl, :ssl],
      outer_version <- [:"tlsv1.2", :"tlsv1.3"],
      inner_version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{provider} #{outer_version} carries independently negotiated #{inner_version} TLS" do
      provider = unquote(provider)
      api = api(provider)
      outer_version = unquote(outer_version)
      inner_version = unquote(inner_version)
      {proxy, origin} = peers(outer_version, inner_version)

      assert {:ok, outer} = api.connect({127, 0, 0, 1}, proxy.port, options(outer_version), 3_000)
      on_exit(fn -> api.close(outer) end)
      assert {:ok, "proxy"} = api.negotiated_protocol(outer)
      assert {:ok, %{"alpn" => "proxy"}} = OpenSSLPeer.event(proxy, "handshake", 2_000)

      inner_options = inner_options(provider, options(inner_version, "origin"))

      assert {:ok, inner} = api.connect(outer, inner_options, 3_000)
      on_exit(fn -> api.close(inner) end)
      assert {:ok, "origin"} = api.negotiated_protocol(inner)
      assert {:ok, "proxy"} = api.negotiated_protocol(outer)
      assert {:ok, [protocol: ^inner_version]} = api.connection_information(inner, [:protocol])
      assert {:ok, [protocol: ^outer_version]} = api.connection_information(outer, [:protocol])
      assert api.peername(inner) == api.peername(outer)
      assert api.sockname(inner) == api.sockname(outer)
      assert {:ok, %{"alpn" => "origin"}} = OpenSSLPeer.event(origin, "handshake", 2_000)

      assert :ok = api.send(inner, <<0, 255, 42>>)
      digest = :crypto.hash(:sha256, <<0, 255, 42>>) |> Base.encode16(case: :lower)

      assert {:ok, %{"bytes" => 3, "request_sha256" => ^digest}} =
               OpenSSLPeer.event(origin, "exchange", 2_000)

      assert {:ok, <<42, 255, 0>>} = api.recv(inner, 3, 2_000)
      assert :ok = api.close(inner)
      assert {:ok, %{"bytes" => bytes}} = OpenSSLPeer.event(proxy, "exchange", 2_000)
      assert bytes > 3
      assert {:ok, %{"accepted_connections" => 1}} = OpenSSLPeer.event(proxy, "closed", 2_000)
    end
  end

  test "a foreign caller cannot adopt or close the outer TLS session" do
    {proxy, _origin} = peers(:"tlsv1.3", :"tlsv1.3")
    assert {:ok, outer} = SSL.connect({127, 0, 0, 1}, proxy.port, options(:"tlsv1.3"), 3_000)
    on_exit(fn -> SSL.close(outer) end)
    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)

    caller = Task.async(fn -> SSL.connect(outer, options(:"tlsv1.3", "origin"), 1_000) end)
    assert {:error, :not_owner} = Task.await(caller, 2_000)
    assert {:ok, "proxy"} = SSL.negotiated_protocol(outer)
  end

  test "inner authentication failure does not send application data or reconnect" do
    {proxy, origin} = peers(:"tlsv1.3", :"tlsv1.3")
    assert {:ok, outer} = SSL.connect({127, 0, 0, 1}, proxy.port, options(:"tlsv1.3"), 3_000)
    on_exit(fn -> SSL.close(outer) end)
    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)

    inner_options =
      options(:"tlsv1.3", "origin")
      |> Keyword.put(:server_name_indication, ~c"wrong.invalid")

    assert {:error, {:tls_alert, _}} = SSL.connect(outer, inner_options, 3_000)
    assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(origin, "handshake", 2_000)
    assert {:ok, _} = OpenSSLPeer.event(proxy, "exchange", 2_000)
    assert {:ok, %{"accepted_connections" => 1}} = OpenSSLPeer.event(proxy, "closed", 2_000)
  end

  test "carrier death retires the inner connection while it awaits application bytes" do
    {proxy, origin} = peers(:"tlsv1.3", :"tlsv1.3")
    assert {:ok, outer} = SSL.connect({127, 0, 0, 1}, proxy.port, options(:"tlsv1.3"), 3_000)
    on_exit(fn -> SSL.close(outer) end)
    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    assert {:ok, inner} = SSL.connect(outer, options(:"tlsv1.3", "origin"), 3_000)
    on_exit(fn -> SSL.close(inner) end)
    assert {:ok, _} = OpenSSLPeer.event(origin, "handshake", 2_000)
    monitor = Process.monitor(inner.pid)
    Process.exit(outer.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 2_000
  end

  test "prepared inner policy retains distinct ALPN and both application owners retire" do
    {proxy, origin} = peers(:"tlsv1.3", :"tlsv1.3")
    assert {:ok, prepared} = SSL.prepare_upgrade(options(:"tlsv1.3", "origin"))
    assert {:ok, outer} = SSL.connect({127, 0, 0, 1}, proxy.port, options(:"tlsv1.3"), 3_000)
    on_exit(fn -> SSL.close(outer) end)
    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    assert {:ok, inner} = SSL.connect_prepared(outer, prepared, 3_000)
    on_exit(fn -> SSL.close(inner) end)
    assert {:ok, _} = OpenSSLPeer.event(origin, "handshake", 2_000)
    assert {:ok, "origin"} = SSL.negotiated_protocol(inner)
    assert {:ok, "proxy"} = SSL.negotiated_protocol(outer)

    owner = spawn(fn -> receive do: (:stop -> :ok) end)
    on_exit(fn -> Process.exit(owner, :kill) end)
    assert :ok = SSL.controlling_process(inner, owner)
    inner_monitor = Process.monitor(inner.pid)
    outer_monitor = Process.monitor(outer.pid)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^inner_monitor, :process, _, _}, 2_000
    assert_receive {:DOWN, ^outer_monitor, :process, _, _}, 2_000
  end

  test "an active carrier is rejected and the owned session closes" do
    {proxy, _origin} = peers(:"tlsv1.3", :"tlsv1.3")
    assert {:ok, outer} = SSL.connect({127, 0, 0, 1}, proxy.port, options(:"tlsv1.3"), 3_000)
    on_exit(fn -> SSL.close(outer) end)
    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    assert :ok = SSL.setopts(outer, active: :once)
    monitor = Process.monitor(outer.pid)

    assert {:error, {:options, :unsupported_tcp_state}} =
             SSL.connect(outer, options(:"tlsv1.3", "origin"), 3_000)

    assert_receive {:DOWN, ^monitor, :process, _, _}, 2_000
  end

  test "unread carrier plaintext prevents an inner ClientHello and closes the session" do
    parent = self()

    {:ok, peer} =
      LocalTLSPeer.start(fn socket ->
        :ok = :ssl.send(socket, "pending")
        send(parent, {:prelude_closed, :ssl.recv(socket, 0, 3_000)})
      end)

    on_exit(fn ->
      :ssl.close(peer.listener)
      stop_process(peer.task.pid)
    end)

    assert {:ok, outer} =
             SSL.connect(
               {127, 0, 0, 1},
               peer.port,
               Keyword.delete(options(:"tlsv1.3"), :alpn_advertised_protocols),
               3_000
             )

    on_exit(fn -> SSL.close(outer) end)
    assert {:ok, "p"} = SSL.recv(outer, 1, 2_000)
    monitor = Process.monitor(outer.pid)
    assert {:error, :pending_plaintext} = SSL.connect(outer, options(:"tlsv1.3", "origin"), 3_000)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 2_000
    assert_receive {:prelude_closed, {:error, :closed}}, 2_000
    Task.await(peer.task, 1_000)
  end

  test "the original connect timeout bounds a stalled inner handshake" do
    parent = self()
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    origin =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 3_000)
        {:ok, hello} = :gen_tcp.recv(socket, 0, 3_000)
        send(parent, {:inner_hello, byte_size(hello)})
        send(parent, {:stalled_origin_closed, :gen_tcp.recv(socket, 0, 3_000)})
        :gen_tcp.close(socket)
      end)

    on_exit(fn -> stop_process(origin.pid) end)
    files = LocalTLSPeer.certificates()

    {:ok, proxy} =
      OpenSSLPeer.start(
        peer_options(files, :"tlsv1.3", "proxy", :tunnel) ++ [upstream_port: port]
      )

    on_exit(fn -> OpenSSLPeer.stop(proxy) end)
    assert {:ok, outer} = SSL.connect({127, 0, 0, 1}, proxy.port, options(:"tlsv1.3"), 3_000)
    on_exit(fn -> SSL.close(outer) end)
    assert {:ok, _} = OpenSSLPeer.event(proxy, "handshake", 2_000)
    monitor = Process.monitor(outer.pid)
    started = System.monotonic_time(:millisecond)
    assert {:error, :timeout} = SSL.connect(outer, options(:"tlsv1.3", "origin"), 150)
    assert System.monotonic_time(:millisecond) - started < 1_000
    assert_receive {:inner_hello, size}, 2_000
    assert size > 0
    assert_receive {:DOWN, ^monitor, :process, _, _}, 2_000
    assert_receive {:stalled_origin_closed, {:error, :closed}}, 2_000
    Task.await(origin, 1_000)
  end

  defp options(version, protocol \\ "proxy") do
    [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      versions: [version],
      server_name_indication: ~c"exssl.test",
      cacerts: LocalTLSPeer.certificate_authorities(),
      alpn_advertised_protocols: [protocol],
      send_timeout: 1_000
    ]
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

  defp api(:ssl), do: :ssl
  defp api(:ex_ssl), do: SSL

  defp inner_options(:ssl, options) do
    Keyword.put(options, :cb_info, {OTPTransport, :ssl, :ssl_closed, :ssl_error, :ssl_passive})
  end

  defp inner_options(:ex_ssl, options), do: options

  defp stop_process(pid) do
    monitor = Process.monitor(pid)
    if Process.alive?(pid), do: Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1_000
  end
end

defmodule HTTP.ProxyPreparedTLSTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias Elixir.ExSSL.TestSupport.OpenSSLPeer
  alias HTTP.Transport.{ExSSL, TCP}
  alias SSL.ClientHello.WireProfile

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)
  @ca Path.join(@fixtures, "localhost-ca.pem")
  @cert Path.join(@fixtures, "localhost.pem")
  @key Path.join(@fixtures, "localhost.key")

  @tag :tmp_dir
  test "invalid effective TLS configuration has zero proxy and origin accepts", %{
    tmp_dir: directory
  } do
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()
    missing = Path.join(directory, "missing.pem")
    {tracker, _} = HTTP.RequestLifecycle.start()
    on_exit(fn -> stop_tracker(tracker) end)

    sni_profile = %WireProfile{
      extensions: [
        {:server_name, :from_connection},
        {:supported_versions, [0x0304]},
        {:supported_groups, [:x25519]},
        {:signature_algorithms, [:rsa_pss_rsae_sha256]},
        {:key_share, [:x25519]}
      ]
    }

    for opts <- [
          [ssl: [unsupported_tls_option: true]],
          [ssl: :invalid],
          [ssl: [versions: [:"tlsv1.1"]]],
          [ssl: [alpn_advertised_protocols: [""]]],
          [ssl: [cacertfile: missing]],
          [ssl: [certfile: @cert, keyfile: missing]],
          [ssl: [ex_ssl: [profile: %WireProfile{}]]],
          [
            ssl: [
              verify: :verify_none,
              server_name_indication: :disable,
              versions: [:"tlsv1.3"],
              ex_ssl: [profile: sni_profile, reference_identity: {:ip, {127, 0, 0, 1}}]
            ]
          ],
          [
            ssl: [
              alpn_advertised_protocols: ["h2"],
              versions: [:"tlsv1.3"],
              ex_ssl: [profile: sni_profile]
            ]
          ],
          [socket_opts: [ip: {127, 0, 0, 1}]],
          [socket_opts: [port: 0]],
          [socket_opts: [send_timeout: :invalid]],
          [socket_opts: [:inet6]]
        ] do
      for effective <- [opts, Keyword.put(opts, :request_lifecycle, tracker)] do
        assert {:error, {:options, _}} =
                 HTTP.Proxy.connect(
                   ExSSL,
                   "localhost",
                   origin_port,
                   effective,
                   500,
                   route(proxy_port)
                 )

        assert :sys.get_state(tracker).providers == %{}
        assert {:error, :timeout} = :gen_tcp.accept(proxy, 20)
        assert {:error, :timeout} = :gen_tcp.accept(origin, 20)
      end
    end
  end

  for host <- ["localhost", "127.0.0.1"],
      {version, alpn} <- [{:"tlsv1.2", "http/1.1"}, {:"tlsv1.3", "h2"}] do
    if version == :"tlsv1.2" do
      @tag :integration
    end

    test "verified #{host} CONNECT retains #{version} and #{alpn} policy and option precedence" do
      {origin, origin_port} = listener()
      {proxy, proxy_port} = listener()
      peer = start_peer(unquote(version), proxy, unquote(host), origin_port, unquote(alpn))

      # socket_opts wins over the invalid lower-precedence ssl send timeout.
      opts = [
        ssl: [cacertfile: @ca, send_timeout: :invalid, alpn_advertised_protocols: [unquote(alpn)]],
        socket_opts: [send_timeout: 5_000]
      ]

      assert {:ok, socket} =
               HTTP.Proxy.connect(
                 ExSSL,
                 unquote(host),
                 origin_port,
                 opts,
                 5_000,
                 route(proxy_port)
               )

      assert {:ok, unquote(alpn)} = ExSSL.negotiated_protocol(socket)
      assert {:ok, [protocol: unquote(version)]} = SSL.connection_information(socket, [:protocol])
      assert :ok = ExSSL.send(socket, <<4::32, "ping">>)
      assert {:ok, <<4::32, "ping">>} = ExSSL.recv(socket, 8, 5_000)
      ExSSL.close(socket)
      assert_receive :replied, 5_000
      send(peer.pid, :close)
      Task.await(peer, 5_000)
      assert {:error, :timeout} = :gen_tcp.accept(origin, 20)
    end
  end

  test "an exhausted preparation deadline never calls raw proxy TCP connect" do
    {origin, origin_port} = listener()
    {proxy, proxy_port} = listener()
    opts = [ssl: [cacertfile: @ca]]
    assert {:ok, _} = ExSSL.prepare_upgrade("localhost", opts)

    assert {:error, :timeout} =
             HTTP.Proxy.connect(ExSSL, "localhost", origin_port, opts, 0, route(proxy_port))

    {tracker, _} = HTTP.RequestLifecycle.start()

    assert {:error, :request_timeout} =
             HTTP.Proxy.connect(
               ExSSL,
               "localhost",
               origin_port,
               Keyword.put(opts, :request_lifecycle, tracker),
               0,
               route(proxy_port)
             )

    assert :sys.get_state(tracker).providers == %{}
    stop_tracker(tracker)
    assert {:error, :timeout} = :gen_tcp.accept(proxy, 50)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 50)
  end

  @tag :tmp_dir
  test "CONNECT consumes trust frozen before the proxy response", %{tmp_dir: directory} do
    frozen_trust(directory, nil)
  end

  @tag :tmp_dir
  @tag :p3_proxy_ex_ssl_core
  test "tracked CONNECT preserves frozen trust and provider accounting", %{tmp_dir: directory} do
    {tracker, _} = HTTP.RequestLifecycle.start()
    listeners = {listener(), listener()}

    task =
      Task.async(fn ->
        HTTP.RequestLifecycle.enter(tracker, :dial)
        frozen_trust(directory, tracker, listeners)
        HTTP.RequestLifecycle.complete(tracker)
      end)

    Task.await(task, 10_000)
    await_no_providers(tracker, deadline())
    stop_tracker(tracker)
  end

  defp frozen_trust(directory, tracker, listeners \\ nil) do
    ca = Path.join(directory, "trust.pem")
    File.cp!(@ca, ca)
    {{origin, origin_port}, {proxy, proxy_port}} = listeners || {listener(), listener()}

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(proxy, 5_000)
        recv_head(tcp)
        File.write!(ca, "replacement is not a CA bundle")
        :ok = :gen_tcp.send(tcp, "HTTP/1.1 200 OK\r\n\r\n")

        {:ok, socket} =
          :ssl.handshake(
            tcp,
            [
              certfile: @cert,
              keyfile: @key,
              active: false,
              mode: :binary
            ],
            5_000
          )

        assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
        :ok = :ssl.send(socket, "pong")
        :ssl.close(socket)
      end)

    assert {:ok, socket} =
             HTTP.Proxy.connect(
               ExSSL,
               "localhost",
               origin_port,
               [request_lifecycle: tracker, ssl: [cacertfile: ca]],
               5_000,
               route(proxy_port)
             )

    handles = if tracker, do: Map.keys(:sys.get_state(tracker).providers), else: []
    assert :ok = ExSSL.send(socket, "ping")
    assert {:ok, "pong"} = ExSSL.recv(socket, 4, 5_000)
    ExSSL.close(socket)

    for handle <- handles do
      assert {:ok, %{cleanup: :confirmed}} = SSL.Lifecycle.await(handle, {:abs_ms, deadline()})
    end

    Task.await(peer, 5_000)
    assert {:error, :timeout} = :gen_tcp.accept(origin, 20)
  end

  @tag :p3_proxy_ex_ssl_core
  test "prepared adoption releases only the known raw socket after public bound proof" do
    fixture = adoption_fixture()
    %{tracker: tracker, tcp: tcp, descriptor: {handle, _} = descriptor, actor: actor} = fixture
    assert {tcp, :socket} in Map.values(:sys.get_state(tracker).resources)
    assert {:pending, %{bound?: true, setup: :connected}} = SSL.Lifecycle.status(handle)
    send(actor, {:adopt, descriptor, tcp, deadline()})
    assert_receive {:adopted, ^actor, :ok}, 1_000
    refute {tcp, :socket} in Map.values(:sys.get_state(tracker).resources)
    assert :sys.get_state(tracker).providers[handle].socket == fixture.socket
    close_adoption(fixture)
  end

  for invalid <- [:wrong_actor, :wrong_lease, :unknown_raw, :expired, :late_ack] do
    @tag :p3_proxy_ex_ssl_core
    test "#{invalid} cannot release raw responsibility or publish prepared adoption" do
      fixture = adoption_fixture()
      reject_adoption(fixture, unquote(invalid))
      close_adoption(fixture)
    end
  end

  @tag :p3_proxy_adoption_deadline
  test "connected status queued before expiry cannot commit adoption after the original deadline" do
    fixture = adoption_fixture()
    %{tracker: tracker, actor: actor, descriptor: {handle, _} = descriptor} = fixture
    observer = handle.receipt.observer
    expires = System.monotonic_time(:millisecond) + 500
    :ok = :sys.suspend(observer)

    try do
      send(actor, {:adopt, descriptor, fixture.tcp, expires})

      await_queued_message(observer, expires, fn message ->
        match?(
          {:"$gen_call", {^tracker, _}, {:snapshot_resources, {:abs_ms, ^expires}}},
          message
        )
      end)

      # Both genuine callers remain suspended after their calls were admitted.
      # A queued timeout/abort cannot race the state inspection and hide a late
      # successful adoption. The connected snapshot is the real provider reply.
      assert true = :erlang.suspend_process(tracker)
      assert true = :erlang.suspend_process(actor)
      :ok = :sys.resume(observer)

      await_queued_message(tracker, expires, fn message ->
        match?({_, {:ok, %{bound?: true, setup: :connected}}}, message)
      end)

      remaining = max(expires - System.monotonic_time(:millisecond) + 20, 0)

      receive do
      after
        remaining -> :ok
      end

      assert System.monotonic_time(:millisecond) >= expires
      assert true = :erlang.resume_process(tracker)
      assert_raw_retained(fixture)
      assert :sys.get_state(tracker).uncertain?
      assert true = :erlang.resume_process(actor)
      assert_receive {:adopted, ^actor, {:error, :adoption_unconfirmed}}, 1_000
    after
      :sys.resume(observer)
      resume_fixture_process(tracker)
      resume_fixture_process(actor)
      close_adoption(fixture)
    end
  end

  defp await_queued_message(pid, expires, predicate) do
    {:messages, messages} = Process.info(pid, :messages)

    unless Enum.any?(messages, predicate) do
      assert System.monotonic_time(:millisecond) < expires

      receive do
      after
        1 -> await_queued_message(pid, expires, predicate)
      end
    end
  end

  defp resume_fixture_process(pid) do
    :erlang.resume_process(pid)
  rescue
    ArgumentError -> :ok
  end

  defp reject_adoption(fixture, :wrong_actor) do
    assert {:error, :adoption_unconfirmed} =
             HTTP.RequestLifecycle.adopt_provider(
               fixture.tracker,
               fixture.descriptor,
               fixture.tcp,
               fixture.socket,
               deadline()
             )

    assert_raw_retained(fixture)
  end

  defp reject_adoption(fixture, :wrong_lease) do
    {handle, _lease} = fixture.descriptor
    send(fixture.actor, {:adopt, {handle, make_ref()}, fixture.tcp, deadline()})
    assert_receive {:adopted, _, {:error, :adoption_unconfirmed}}, 1_000
    assert_raw_retained(fixture)
  end

  defp reject_adoption(fixture, :unknown_raw) do
    {unknown, _} = listener()
    send(fixture.actor, {:adopt, fixture.descriptor, unknown, deadline()})
    assert_receive {:adopted, _, {:error, :adoption_unconfirmed}}, 1_000
    assert_raw_retained(fixture)
  end

  defp reject_adoption(fixture, :expired) do
    send(
      fixture.actor,
      {:adopt, fixture.descriptor, fixture.tcp, System.monotonic_time(:millisecond)}
    )

    assert_receive {:adopted, _, {:error, :request_timeout}}, 1_000
    assert_raw_retained(fixture)
  end

  defp reject_adoption(fixture, :late_ack) do
    :sys.suspend(fixture.tracker)

    try do
      send(
        fixture.actor,
        {:adopt, fixture.descriptor, fixture.tcp, System.monotonic_time(:millisecond) + 50}
      )

      assert_receive {:adopted, _, {:error, :request_timeout}}, 1_000
      assert Port.info(fixture.tcp) != nil
    after
      :sys.resume(fixture.tracker)
    end

    state = :sys.get_state(fixture.tracker)
    assert state.uncertain?
    assert state.providers[elem(fixture.descriptor, 0)].socket == nil
  end

  defp assert_raw_retained(fixture) do
    state = :sys.get_state(fixture.tracker)
    assert {fixture.tcp, :socket} in Map.values(state.resources)
    assert state.providers[elem(fixture.descriptor, 0)].socket == nil
  end

  defp adoption_fixture do
    {listener, port} = listener()

    peer =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 5_000)

        {:ok, socket} =
          :ssl.handshake(
            tcp,
            [certfile: @cert, keyfile: @key, active: false, versions: [:"tlsv1.3"]],
            5_000
          )

        receive do: (:close -> :ssl.close(socket))
      end)

    {tracker, _latch} = HTTP.RequestLifecycle.start()
    parent = self()

    actor =
      spawn(fn ->
        :ok = HTTP.RequestLifecycle.enter(tracker, :dial)
        opts = [request_lifecycle: tracker, ssl: [cacertfile: @ca, versions: [:"tlsv1.3"]]]

        {:ok, {:prepared_attempt, prepared, descriptor, ^tracker, _}} =
          ExSSL.prepare_upgrade("localhost", opts, deadline())

        {:ok, tcp} = TCP.connect("localhost", port, opts, 5_000)

        {:ok, socket} =
          SSL.connect_prepared(tcp, prepared, [ex_ssl: [lifecycle: descriptor]], 5_000)

        send(parent, {:adoption_fixture, self(), tcp, socket, descriptor})
        adoption_actor(parent, tracker, socket)
      end)

    on_exit(fn ->
      if Process.alive?(actor), do: Process.exit(actor, :kill)
      stop_tracker(tracker)
      if Process.alive?(peer.pid), do: send(peer.pid, :close)
    end)

    assert_receive {:adoption_fixture, ^actor, tcp, socket, descriptor}, 5_000

    %{
      actor: actor,
      tracker: tracker,
      tcp: tcp,
      socket: socket,
      descriptor: descriptor,
      peer: peer
    }
  end

  defp adoption_actor(parent, tracker, socket) do
    receive do
      {:adopt, descriptor, tcp, expires} ->
        result = HTTP.RequestLifecycle.adopt_provider(tracker, descriptor, tcp, socket, expires)
        send(parent, {:adopted, self(), result})
        adoption_actor(parent, tracker, socket)

      :close ->
        ExSSL.close(socket)
        HTTP.RequestLifecycle.complete(tracker)
    end
  end

  defp close_adoption(fixture) do
    {handle, lease} = fixture.descriptor
    SSL.Lifecycle.cancel(lease, {:abs_ms, deadline()})
    assert {:ok, %{cleanup: :confirmed}} = SSL.Lifecycle.await(handle, {:abs_ms, deadline()})
    monitor = Process.monitor(fixture.actor)
    send(fixture.actor, :close)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 1_000
    send(fixture.peer.pid, :close)
    Task.await(fixture.peer, 1_000)
    stop_tracker(fixture.tracker)
  end

  defp await_no_providers(tracker, expires) do
    if :sys.get_state(tracker).providers != %{} do
      assert System.monotonic_time(:millisecond) < expires

      receive do
      after
        5 -> await_no_providers(tracker, expires)
      end
    end
  end

  defp stop_tracker(tracker) do
    monitor = Process.monitor(tracker)

    try do
      GenServer.stop(tracker, :normal, 1_000)
    catch
      :exit, {:noproc, _} -> :ok
      :exit, {:normal, _} -> :ok
    end

    assert_receive {:DOWN, ^monitor, :process, ^tracker, _}, 1_000
  end

  defp deadline, do: System.monotonic_time(:millisecond) + 5_000

  # OTP 29's TLS12 server omits EMS; bounded ExSSL TLS12 requires it.
  # The combined client offer remains unchanged for both independent peers.
  defp start_peer(:"tlsv1.2", proxy, host, origin_port, alpn) do
    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: @cert,
        keyfile: @key,
        min_version: :tls12,
        max_version: :tls12,
        alpn: [alpn],
        max_connections: 1
      )

    on_exit(fn -> OpenSSLPeer.stop(peer) end)
    parent = self()

    Task.async(fn ->
      tcp = accept_tunnel(proxy, host, origin_port)

      {:ok, upstream} =
        :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 5_000)

      :ok = :inet.setopts(tcp, active: :once)
      :ok = :inet.setopts(upstream, active: :once)
      forward(tcp, upstream)
      send(parent, :replied)
    end)
  end

  defp start_peer(:"tlsv1.3", proxy, host, origin_port, alpn) do
    parent = self()

    Task.async(fn ->
      tcp = accept_tunnel(proxy, host, origin_port)

      {:ok, socket} =
        :ssl.handshake(
          tcp,
          [
            certfile: @cert,
            keyfile: @key,
            active: false,
            mode: :binary,
            versions: [:"tlsv1.3"],
            alpn_preferred_protocols: [alpn]
          ],
          5_000
        )

      assert {:ok, <<4::32, "ping">>} = :ssl.recv(socket, 8, 5_000)
      :ok = :ssl.send(socket, <<4::32, "ping">>)
      send(parent, :replied)
      receive do: (:close -> :ssl.close(socket))
    end)
  end

  defp accept_tunnel(proxy, host, origin_port) do
    {:ok, tcp} = :gen_tcp.accept(proxy, 5_000)
    assert recv_head(tcp) =~ "CONNECT #{host}:#{origin_port} HTTP/1.1\r\n"
    :ok = :gen_tcp.send(tcp, "HTTP/1.1 200 OK\r\n\r\n")
    tcp
  end

  defp forward(client, upstream) do
    receive do
      {:tcp, ^client, data} ->
        :ok = :gen_tcp.send(upstream, data)
        :ok = :inet.setopts(client, active: :once)
        forward(client, upstream)

      {:tcp, ^upstream, data} ->
        case :gen_tcp.send(client, data) do
          :ok ->
            :ok = :inet.setopts(upstream, active: :once)
            forward(client, upstream)

          {:error, :closed} ->
            :gen_tcp.close(client)
            :gen_tcp.close(upstream)
        end

      {:tcp_closed, _} ->
        :gen_tcp.close(client)
        :gen_tcp.close(upstream)
    after
      5_000 -> flunk("independent TLS peer did not finish its bounded exchange")
    end
  end

  defp route(port),
    do: %{scheme: :http, host: "127.0.0.1", port: port, timeout: 5_000, headers: []}

  defp listener do
    {:ok, socket} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    {:ok, port} = :inet.port(socket)
    on_exit(fn -> :gen_tcp.close(socket) end)
    {socket, port}
  end

  defp recv_head(socket, acc \\ "") do
    assert byte_size(acc) <= 16_384

    case :binary.match(acc, "\r\n\r\n") do
      {_, 4} ->
        acc

      :nomatch ->
        {:ok, bytes} = :gen_tcp.recv(socket, 0, 5_000)
        recv_head(socket, acc <> bytes)
    end
  end
end

defmodule HTTP.TLSTransportTest do
  use ExUnit.Case, async: true

  alias HTTP.Transport.ExSSL

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)
  @ca Path.join(@fixtures, "localhost-ca.pem")
  @cert Path.join(@fixtures, "localhost.pem")

  for transport <- [HTTP.Transport.SSL, ExSSL] do
    @transport transport

    describe "#{inspect(transport)}" do
      @tag :integration
      test "verified passive traffic and absent ALPN" do
        port =
          peer(fn socket ->
            assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
            :ok = :ssl.send(socket, "pong")
          end)

        assert {:ok, socket} =
                 @transport.connect("localhost", port, [ssl: [cacertfile: @ca]], 5_000)

        assert {:ok, nil} = @transport.negotiated_protocol(socket)
        assert :ok = @transport.send(socket, ["pi", "ng"])
        assert {:ok, "pong"} = @transport.recv(socket, 4, 5_000)
        assert {:error, :closed} = @transport.recv(socket, 0, 5_000)
        assert :ok = @transport.close(socket)
      end

      @tag :integration
      test "worker ownership transfer, ALPN and active-once delivery survive worker exit" do
        parent = self()

        port =
          peer(
            fn socket ->
              assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
              :ok = :ssl.send(socket, "pong")
              send(parent, {:peer_replied, self()})
              receive do: (:allow_peer_close -> :ok)
            end,
            alpn_preferred_protocols: ["h2"]
          )

        {worker, monitor} =
          spawn_monitor(fn ->
            {:ok, socket} =
              @transport.connect(
                "localhost",
                port,
                [ssl: [cacertfile: @ca, alpn_advertised_protocols: ["h2"]]],
                5_000
              )

            :ok = @transport.controlling_process(socket, parent)
            send(parent, {:connected, socket})
          end)

        assert_receive {:connected, socket}, 5_000
        assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 5_000
        assert {:ok, "h2"} = @transport.negotiated_protocol(socket)
        assert :ok = @transport.setopts(socket, active: :once)
        assert :ok = @transport.send(socket, "ping")
        assert_receive {:ssl, ^socket, "pong"} = message, 5_000
        assert {:data, "pong"} = @transport.normalize_message(message, socket)
        assert_receive {:peer_replied, peer}, 5_000
        assert :ok = @transport.setopts(socket, active: :once)
        send(peer, :allow_peer_close)
        assert_receive {:ssl_closed, ^socket} = message, 5_000
        assert :closed = @transport.normalize_message(message, socket)
        assert :unknown = @transport.normalize_message({:ssl, :other_socket, "pong"}, socket)
        assert :ok = @transport.close(socket)
      end

      @tag :integration
      test "explicit verify_none permits untrusted wrong-host traffic" do
        port =
          peer(fn socket ->
            assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
            :ok = :ssl.send(socket, "pong")
          end)

        assert {:ok, socket} =
                 @transport.connect(
                   "localhost",
                   port,
                   [ssl: [verify: :verify_none, server_name_indication: ~c"wrong.example"]],
                   5_000
                 )

        try do
          assert :ok = @transport.send(socket, "ping")
          assert {:ok, "pong"} = @transport.recv(socket, 4, 5_000)
        after
          @transport.close(socket)
        end
      end

      @tag :integration
      test "rejects an untrusted peer" do
        port = peer(fn _socket -> :ok end)
        assert {:error, _} = @transport.connect("localhost", port, [], 5_000)
      end

      @tag :integration
      test "rejects a mismatched reference hostname" do
        port = peer(fn _socket -> :ok end)

        assert {:error, _} =
                 @transport.connect(
                   "localhost",
                   port,
                   [ssl: [cacertfile: @ca, server_name_indication: ~c"wrong.example"]],
                   5_000
                 )
      end
    end
  end

  @tag :integration
  test "ex_ssl verifies IP literals without treating the IP as DNS SNI" do
    port = peer(fn socket -> :ssl.send(socket, "ip") end)
    assert {:ok, socket} = ExSSL.connect("127.0.0.1", port, [ssl: [cacertfile: @ca]], 5_000)
    assert {:ok, "ip"} = ExSSL.recv(socket, 2, 5_000)
    assert :ok = ExSSL.close(socket)
  end

  @tag :integration
  test "ex_ssl keeps IP verification separate from DNS SNI with a custom profile" do
    parent = self()

    port =
      peer(fn socket ->
        assert {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
        send(parent, {:wire_sni, info[:sni_hostname]})
        :ssl.send(socket, "ip")
      end)

    assert {:ok, socket} =
             ExSSL.connect(
               "127.0.0.1",
               port,
               [
                 ssl: [
                   cacertfile: @ca,
                   server_name_indication: ~c"wrong.example",
                   ex_ssl: [profile: :default, reference_identity: {:ip, {127, 0, 0, 1}}]
                 ]
               ],
               5_000
             )

    assert_receive {:wire_sni, ~c"wrong.example"}, 5_000
    assert {:ok, "ip"} = ExSSL.recv(socket, 2, 5_000)
    assert :ok = ExSSL.close(socket)
  end

  @tag :integration
  test "ex_ssl direct IP dialing preserves DNS SNI identity with profile-only options" do
    port = peer(fn socket -> :ssl.send(socket, "dns") end, [], "pinned")

    assert {:ok, socket} =
             ExSSL.connect(
               "127.0.0.1",
               port,
               [
                 ssl: [
                   cacertfile: Path.join(@fixtures, "pinned-ca.pem"),
                   server_name_indication: ~c"pinned.invalid",
                   ex_ssl: [profile: :default]
                 ]
               ],
               5_000
             )

    assert {:ok, "dns"} = ExSSL.recv(socket, 3, 5_000)
    assert :ok = ExSSL.close(socket)
  end

  for fixture <- ["localhost", "pinned"] do
    @tag :integration
    test "ex_ssl direct IP with wrong DNS SNI rejects trusted #{fixture} certificate" do
      port =
        peer(
          fn _socket -> flunk("wrong DNS identity was authenticated") end,
          [],
          unquote(fixture)
        )

      assert {:error, {:tls_alert, {:certificate_unknown, _}}} =
               ExSSL.connect(
                 "127.0.0.1",
                 port,
                 [
                   ssl: [
                     cacertfile: Path.join(@fixtures, unquote(fixture) <> "-ca.pem"),
                     server_name_indication: ~c"wrong.example",
                     ex_ssl: [profile: :default]
                   ]
                 ],
                 5_000
               )
    end
  end

  @tag :integration
  test "ex_ssl rejects unsupported TLS and TCP options before connecting" do
    for ssl <- [
          [verify: :invalid],
          [versions: [:"tlsv1.1"]],
          [certfile: @cert]
        ] do
      assert {:error, {:options, _}} = ExSSL.connect("localhost", 0, [ssl: ssl], 100)
    end

    assert {:error, {:options, {:nodelay, :unsupported_or_invalid}}} =
             ExSSL.connect("localhost", 0, [socket_opts: [nodelay: :invalid]], 100)

    port = closed_port()

    assert {:error, :econnrefused} =
             ExSSL.connect("127.0.0.1", port, [socket_opts: [nodelay: true]], 100)

    for versions <- [[:"tlsv1.2"], [:"tlsv1.3", :"tlsv1.2"]] do
      assert {:error, :econnrefused} =
               ExSSL.connect("127.0.0.1", port, [ssl: [versions: versions]], 100)
    end

    assert {:error, {:options, {:send_timeout_close, :unsupported_or_invalid}}} =
             ExSSL.connect("localhost", 0, [socket_opts: [send_timeout_close: false]], 100)
  end

  test "ex_ssl rejects malformed and duplicate options" do
    for opts <- [[ssl: nil], [socket_opts: [:binary]], [ssl: [depth: 1, depth: 2]]] do
      assert {:error, {:options, :invalid_options}} = ExSSL.connect("localhost", 0, opts, 100)
    end
  end

  @tag :integration
  test "ex_ssl rejects malformed nested options for literal IP routes before I/O" do
    for ex_ssl <- [
          [],
          nil,
          123,
          [:invalid],
          [reference_identity: {:ip, "127.0.0.1"}, reference_identity: {:ip, "127.0.0.2"}]
        ] do
      assert {:error, {:options, {:ex_ssl, :unsupported_or_invalid}}} =
               ExSSL.connect("127.0.0.1", 0, [ssl: [ex_ssl: ex_ssl]], 100)

      {:ok, tcp} = :gen_tcp.listen(0, [:binary, active: false])
      on_exit(fn -> :gen_tcp.close(tcp) end)

      assert {:error, {:options, {:ex_ssl, :unsupported_or_invalid}}} =
               ExSSL.upgrade(tcp, "127.0.0.1", [ssl: [ex_ssl: ex_ssl]], 100)

      assert :erlang.port_info(tcp) == :undefined
    end
  end

  @tag :integration
  test "ex_ssl socket send options take precedence over matching TLS options" do
    port = peer(fn socket -> :ssl.send(socket, "ok") end)

    assert {:ok, socket} =
             ExSSL.connect(
               "localhost",
               port,
               [
                 ssl: [cacertfile: @ca, send_timeout_close: false],
                 socket_opts: [send_timeout: 1_000, send_timeout_close: true]
               ],
               5_000
             )

    assert {:ok, "ok"} = ExSSL.recv(socket, 2, 5_000)
    assert :ok = ExSSL.close(socket)
  end

  @tag :integration
  test "ex_ssl driver buffer and traffic socket options override matching ssl entries" do
    port = peer(fn socket -> :ssl.recv(socket, 0, 5_000) end)

    assert {:ok, socket} =
             ExSSL.connect(
               "localhost",
               port,
               [
                 ssl: [cacertfile: @ca, buffer: -1, tos: :invalid, priority: :invalid],
                 socket_opts: [buffer: 65_536, tos: 16, priority: 6]
               ],
               5_000
             )

    try do
      # Test-only driver probe; buffer attach and verify-mode forwarding audited.
      # Private inert births leave classic tuple5 buffer and verify-mode forwarding unchanged.
      # Production HTTP consumes only the transport API.
      source = SSL.Connection.module_info(:compile)[:source] |> List.to_string()

      assert :crypto.hash(:sha256, File.read!(source)) |> Base.encode16(case: :lower) ==
               "61b2fa41a60fb00d01335ea8486e698aecac8fc0a45a47e10d5adecb34cc3f91"

      assert Application.spec(:ex_ssl, :vsn) == Application.spec(:http_core, :vsn)
      {:connected, state} = :sys.get_state(socket.pid)
      assert {:ok, [buffer: 65_536, tos: 16]} = :inet.getopts(state.tcp, [:buffer, :tos])
      assert :ok = ExSSL.setopts(socket, buffer: 32_768, tos: 32)
      assert {:ok, [buffer: 32_768, tos: 32]} = :inet.getopts(state.tcp, [:buffer, :tos])
      assert {:ok, [priority: priority]} = :inet.getopts(state.tcp, [:priority])
      IO.puts("HTTP ExSSL priority requested6, observed #{priority} on #{inspect(:os.type())}")
    after
      ExSSL.close(socket)
    end
  end

  @tag :integration
  test "ex_ssl upgrade retains socket option precedence and caller driver buffer" do
    port = peer(fn socket -> :ssl.recv(socket, 0, 5_000) end)
    {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)

    assert {:ok, socket} =
             ExSSL.upgrade(
               tcp,
               "localhost",
               [
                 ssl: [cacertfile: @ca, buffer: -1, tos: :invalid],
                 socket_opts: [buffer: 65_536, tos: 16]
               ],
               5_000
             )

    try do
      assert {:ok, [buffer: 65_536, tos: 16]} = :inet.getopts(tcp, [:buffer, :tos])
    after
      ExSSL.close(socket)
    end
  end

  @tag :integration
  test "ex_ssl reports invalid admitted options and native family errors explicitly" do
    for key <- [:buffer, :tos, :tclass, :priority] do
      assert {:error, {:options, {^key, :unsupported_or_invalid}}} =
               ExSSL.connect("localhost", 0, [socket_opts: [{key, -1}]], 100)
    end

    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, invalid_port}} = :inet.sockname(listener)

    assert {:error, :badarg} =
             ExSSL.connect("127.0.0.1", invalid_port, [socket_opts: [tclass: 16]], 100)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 30)

    port = peer(fn socket -> :ssl.recv(socket, 0, 5_000) end)
    assert {:ok, socket} = ExSSL.connect("localhost", port, [ssl: [cacertfile: @ca]], 5_000)

    try do
      assert {:error, :einval} = ExSSL.setopts(socket, tclass: 16)
    after
      ExSSL.close(socket)
    end
  end

  @tag :integration
  test "ex_ssl explicit TLS 1.3 rejects TLS 1.2-only peers without backend fallback" do
    port = peer(fn _socket -> :ok end, versions: [:"tlsv1.2"])

    assert {:error, _} =
             ExSSL.connect(
               "localhost",
               port,
               [ssl: [cacertfile: @ca, versions: [:"tlsv1.3"]]],
               5_000
             )
  end

  @tag :integration
  test "ex_ssl keeps partial passive bytes across receive timeouts" do
    parent = self()

    port =
      peer(fn socket ->
        :ok = :ssl.send(socket, "a")
        send(parent, {:partial_sent, self()})

        receive do
          :finish -> :ssl.send(socket, "b")
        after
          5_000 -> flunk("test did not finish the response")
        end
      end)

    assert {:ok, socket} = ExSSL.connect("localhost", port, [ssl: [cacertfile: @ca]], 5_000)
    assert_receive {:partial_sent, server}, 5_000
    assert {:error, :timeout} = ExSSL.recv(socket, 2, 20)
    send(server, :finish)
    assert {:ok, "ab"} = ExSSL.recv(socket, 2, 5_000)
    assert :ok = ExSSL.close(socket)
  end

  @tag :integration
  test "ex_ssl closes a passive connection when its application owner exits" do
    parent = self()

    port =
      peer(fn socket ->
        send(parent, {:peer_closed, :ssl.recv(socket, 0, 5_000)})
      end)

    {owner, monitor} =
      spawn_monitor(fn ->
        {:ok, socket} = ExSSL.connect("localhost", port, [ssl: [cacertfile: @ca]], 5_000)
        send(parent, {:owned, socket})

        receive do
          :exit -> :ok
        end
      end)

    assert_receive {:owned, socket}, 5_000
    assert {:error, :not_owner} = ExSSL.controlling_process(socket, self())
    send(owner, :exit)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 5_000
    assert_receive {:peer_closed, {:error, _}}, 5_000
    assert :ok = ExSSL.close(socket)
  end

  @tag :integration
  test "ex_ssl propagates custom-profile ALPN conflicts without connecting" do
    profile = %SSL.ClientHello.WireProfile{extensions: [{:alpn, ["http/1.1"]}]}

    assert {:error, {:options, {:alpn_advertised_protocols, :profile_conflict}}} =
             ExSSL.connect(
               "localhost",
               0,
               [
                 ssl: [
                   cacertfile: @ca,
                   alpn_advertised_protocols: ["h2"],
                   ex_ssl: [profile: profile]
                 ]
               ],
               100
             )
  end

  @tag :integration
  test "ex_ssl accepts the default custom profile with HTTP ALPN" do
    port = peer(fn socket -> :ssl.send(socket, "ok") end, alpn_preferred_protocols: ["http/1.1"])

    assert {:ok, socket} =
             ExSSL.connect(
               "localhost",
               port,
               [
                 ssl: [
                   cacertfile: @ca,
                   alpn_advertised_protocols: ["http/1.1"],
                   ex_ssl: [profile: :default]
                 ]
               ],
               5_000
             )

    assert {:ok, "http/1.1"} = ExSSL.negotiated_protocol(socket)
    assert {:ok, "ok"} = ExSSL.recv(socket, 2, 5_000)
    assert :ok = ExSSL.close(socket)
  end

  defp peer(handler, options \\ [], fixture \\ "localhost") do
    {:ok, listener} =
      :ssl.listen(
        0,
        [
          :binary,
          packet: :raw,
          active: false,
          ip: {127, 0, 0, 1},
          certfile: Path.join(@fixtures, fixture <> ".pem"),
          keyfile: Path.join(@fixtures, fixture <> ".key")
        ] ++ Keyword.put_new(options, :versions, [:"tlsv1.3"])
      )

    {:ok, {{127, 0, 0, 1}, port}} = :ssl.sockname(listener)

    pid =
      spawn_link(fn ->
        case :ssl.transport_accept(listener, 5_000) do
          {:ok, tcp} ->
            case :ssl.handshake(tcp, 5_000) do
              {:ok, socket} ->
                handler.(socket)
                :ssl.close(socket)

              {:error, _} ->
                :ok
            end

          {:error, _} ->
            :ok
        end
      end)

    on_exit(fn ->
      :ssl.close(listener)
      if Process.alive?(pid), do: Process.exit(pid, :kill)
    end)

    port
  end

  defp closed_port do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: false])

    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)
    :ok = :gen_tcp.close(listener)
    port
  end
end

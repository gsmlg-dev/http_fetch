defmodule HTTP.TLSTransportTest do
  use ExUnit.Case, async: true

  alias HTTP.Transport.ExSSL

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)
  @ca Path.join(@fixtures, "localhost-ca.pem")
  @cert Path.join(@fixtures, "localhost.pem")
  @key Path.join(@fixtures, "localhost.key")

  for transport <- [HTTP.Transport.SSL, ExSSL] do
    @transport transport

    describe "#{inspect(transport)}" do
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

      test "worker ownership transfer, ALPN and active-once delivery survive worker exit" do
        port =
          peer(
            fn socket ->
              assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
              :ok = :ssl.send(socket, "pong")
            end,
            alpn_preferred_protocols: ["h2"]
          )

        parent = self()

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
        assert :ok = @transport.setopts(socket, active: :once)
        assert_receive {:ssl_closed, ^socket} = message, 5_000
        assert :closed = @transport.normalize_message(message, socket)
        assert :unknown = @transport.normalize_message({:ssl, :other_socket, "pong"}, socket)
        assert :ok = @transport.close(socket)
      end

      test "rejects an untrusted peer" do
        port = peer(fn _socket -> :ok end)
        assert {:error, _} = @transport.connect("localhost", port, [], 5_000)
      end

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

  test "ex_ssl verifies IP literals without treating the IP as DNS SNI" do
    port = peer(fn socket -> :ssl.send(socket, "ip") end)
    assert {:ok, socket} = ExSSL.connect("127.0.0.1", port, [ssl: [cacertfile: @ca]], 5_000)
    assert {:ok, "ip"} = ExSSL.recv(socket, 2, 5_000)
    assert :ok = ExSSL.close(socket)
  end

  test "ex_ssl rejects unsupported TLS and TCP options before connecting" do
    for ssl <- [
          [verify: :verify_none],
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

  test "ex_ssl rejects TLS 1.2-only peers without backend fallback" do
    port = peer(fn _socket -> :ok end, versions: [:"tlsv1.2"])
    assert {:error, _} = ExSSL.connect("localhost", port, [ssl: [cacertfile: @ca]], 5_000)
  end

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

  defp peer(handler, options \\ []) do
    {:ok, listener} =
      :ssl.listen(
        0,
        [
          :binary,
          packet: :raw,
          active: false,
          ip: {127, 0, 0, 1},
          certfile: @cert,
          keyfile: @key
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

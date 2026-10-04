defmodule SSL.TCPOptionsTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias ExSSL.TestSupport.ClientAuthFixtures
  alias SSL.TCPOptions

  @moduletag :integration

  test "extracts only validated TCP options and infers literal address family" do
    assert {:ok, [verify: :verify_peer], [{:nodelay, true}, :inet6]} =
             TCPOptions.extract({0, 0, 0, 0, 0, 0, 0, 1}, nodelay: true, verify: :verify_peer)

    assert {:ok, [], [{:ip, {127, 0, 0, 1}}, :inet]} =
             TCPOptions.extract("localhost", ip: {127, 0, 0, 1})

    assert {:ok, [], [keepalive: false]} = TCPOptions.extract_setopts(keepalive: false)

    for raw <- [
          [nodelay: 1],
          [keepalive: :yes],
          [sndbuf: 0],
          [recbuf: -1],
          [sndbuf: 0x80000000],
          [{:keepalive, true} | :invalid],
          [port: 65_536],
          [ip: {256, 0, 0, 1}],
          [ip: "127.0.0.1"],
          [ip: ~c"::1"],
          [nodelay: true, nodelay: false],
          [:inet, :inet6],
          [:inet6, ip: {127, 0, 0, 1}],
          [:inet, ip: {0, 0, 0, 0, 0, 0, 0, 1}],
          [:inet6, nodelay: true]
        ] do
      result =
        if(raw == [:inet6, nodelay: true],
          do: TCPOptions.extract_setopts(raw),
          else: TCPOptions.extract("localhost", raw)
        )

      assert {:error, {:options, _}} = result
    end

    assert {:error, {:options, _}} = TCPOptions.extract({127, 0, 0, 1}, [:inet6])
    assert {:error, {:options, _}} = TCPOptions.extract(:upgrade, port: 0)
    assert {:error, {:options, _}} = TCPOptions.extract(:upgrade, [:inet])
    assert {:error, {:options, _}} = TCPOptions.extract_setopts(ip: {127, 0, 0, 1})
  end

  test "connect applies the safe TCP options and a local IPv4 bind" do
    peer = waiting_peer()

    options =
      Peer.client_options() ++
        [nodelay: true, keepalive: true, sndbuf: 8192, recbuf: 8192, ip: {127, 0, 0, 1}, port: 0]

    assert {:ok, socket} = SSL.connect({127, 0, 0, 1}, peer.port, options, 5_000)
    tcp = raw_socket(socket)

    assert {:ok, [{:nodelay, true}, {:keepalive, true}, {:sndbuf, sndbuf}, {:recbuf, recbuf}]} =
             :inet.getopts(tcp, [:nodelay, :keepalive, :sndbuf, :recbuf])

    assert sndbuf >= 8192
    assert recbuf >= 8192
    assert {:ok, {{127, 0, 0, 1}, local_port}} = :inet.sockname(tcp)
    assert local_port in 1..65_535
    assert {:ok, [{:active, active}, {:packet, packet}]} = :inet.getopts(tcp, [:active, :packet])
    assert active in [false, :once]
    assert packet in [0, :raw]
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "setopts validates all values before mutating TLS or TCP state" do
    peer = waiting_peer()
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, Peer.client_options(), 5_000)
    tcp = raw_socket(socket)
    assert {:ok, [nodelay: initial]} = :inet.getopts(tcp, [:nodelay])

    assert {:error, {:options, _}} = SSL.setopts(socket, nodelay: not initial, active: true)
    assert {:ok, [nodelay: ^initial]} = :inet.getopts(tcp, [:nodelay])
    assert {:error, {:options, _}} = SSL.setopts(socket, active: :once, buffer: 1_000_000)
    assert :ok = SSL.setopts(socket, nodelay: not initial, keepalive: true, active: false)

    assert {:ok, [{:nodelay, changed}, {:keepalive, true}]} =
             :inet.getopts(tcp, [:nodelay, :keepalive])

    assert changed == not initial
    assert {:ok, [active: :once]} = :inet.getopts(tcp, [:active])
    assert :ok = SSL.close(socket)
    assert {:error, :closed} = SSL.setopts(socket, nodelay: true)
    assert :ok = Peer.stop(peer)
  end

  test "unsupported raw socket controls are rejected before connect" do
    for option <- [[buffer: 32_768], [linger: {true, 0}], [send_timeout_close: false]] do
      assert {:error, {:options, _}} =
               SSL.connect(~c"127.0.0.1", 1, Peer.client_options() ++ option, 1_000)
    end
  end

  test "an IPv4 literal verifies the certificate IP SAN without SNI" do
    directory =
      Path.join(System.tmp_dir!(), "ex-ssl-tcp-ip-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    fixtures = ClientAuthFixtures.create(directory)

    {:ok, peer} =
      Peer.start(
        fn socket ->
          assert {:ok, []} = :ssl.connection_information(socket, [:sni_hostname])
          assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
          :ok
        end,
        ssl_options: [
          certfile: String.to_charlist(fixtures.server.certificate),
          keyfile: String.to_charlist(fixtures.server.key)
        ]
      )

    options = [
      :binary,
      active: false,
      packet: :raw,
      verify: :verify_peer,
      cacerts: [fixtures.ca.der],
      versions: [:"tlsv1.3"]
    ]

    assert {:ok, socket} = SSL.connect({127, 0, 0, 1}, peer.port, options, 5_000)
    assert :ok = SSL.close(socket)
    assert :ok = Peer.stop(peer)
  end

  test "IPv6 literal and DNS connections honor local IPv6 binds" do
    for host <- [{0, 0, 0, 0, 0, 0, 0, 1}, "::1", ~c"::1", "localhost"] do
      {listener, port, server} = ipv6_peer()

      options = Peer.client_options() ++ [ip: {0, 0, 0, 0, 0, 0, 0, 1}]
      assert {:ok, socket} = SSL.connect(host, port, options, 5_000)
      assert {:ok, {{0, 0, 0, 0, 0, 0, 0, 1}, _}} = :inet.sockname(raw_socket(socket))
      assert :ok = SSL.close(socket)
      assert :ok = :ssl.close(listener)
      assert :ok = Task.await(server, 6_000)
    end
  end

  test "textual IPv6 literal verifies its IP SAN and sends no SNI" do
    directory =
      Path.join(System.tmp_dir!(), "ex-ssl-tcp-ip6-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    fixtures = ClientAuthFixtures.create(directory)

    {listener, port, server} =
      ipv6_peer(%{certfile: fixtures.server.certificate, keyfile: fixtures.server.key}, true)

    options = [mode: :binary, active: false, cacerts: [fixtures.ca.der], verify: :verify_peer]

    try do
      assert {:ok, socket} = SSL.connect("::1", port, options, 5_000)
      assert :ok = SSL.close(socket)
      assert :ok = Task.await(server, 6_000)
    after
      :ssl.close(listener)
      if Process.alive?(server.pid), do: Task.shutdown(server)
    end
  end

  test "OTP reference accepts the same safe TCP option forms" do
    peer = waiting_peer()

    options =
      Peer.client_options() ++
        [nodelay: true, keepalive: true, sndbuf: 8192, recbuf: 8192, ip: {127, 0, 0, 1}, port: 0]

    assert {:ok, socket} = :ssl.connect({127, 0, 0, 1}, peer.port, options, 5_000)

    try do
      assert {:ok, options} = :ssl.getopts(socket, [:nodelay, :keepalive])
      assert Map.new(options) == %{nodelay: true, keepalive: true}

      assert :ok = :ssl.setopts(socket, nodelay: false, recbuf: 16_384)
      assert {:ok, [nodelay: false]} = :ssl.getopts(socket, [:nodelay])
    after
      :ssl.close(socket)
      assert :ok = Peer.stop(peer)
    end
  end

  test "STARTTLS applies mutable TCP options after a validated plaintext handoff" do
    {:ok, peer} =
      Peer.start_starttls(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 5_000)

    try do
      assert {:ok, "220 local STARTTLS peer\r\n"} = :gen_tcp.recv(tcp, 25, 5_000)
      assert :ok = :gen_tcp.send(tcp, "STARTTLS\r\n")
      assert {:ok, "220 begin TLS\r\n"} = :gen_tcp.recv(tcp, 15, 5_000)

      assert {:ok, socket} =
               SSL.connect(tcp, Peer.client_options() ++ [nodelay: true, keepalive: true], 5_000)

      assert {:ok, [nodelay: true, keepalive: true]} = :inet.getopts(tcp, [:nodelay, :keepalive])
      assert :ok = SSL.close(socket)
      assert :ok = Peer.stop(peer)
    after
      :gen_tcp.close(tcp)
      :gen_tcp.close(peer.listener)
    end
  end

  test "underlying socket errors propagate without crashing the connection" do
    peer = waiting_peer()
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, Peer.client_options(), 5_000)
    tcp = raw_socket(socket)
    connection = socket.pid
    monitor = Process.monitor(connection)
    assert :ok = :sys.suspend(connection)

    caller =
      Task.async(fn ->
        receive do
          :start -> SSL.setopts(socket, nodelay: true, active: :once)
        after
          5_000 -> flunk("test did not start setopts caller")
        end
      end)

    try do
      assert 1 = :erlang.trace(caller.pid, true, [:send])
      send(caller.pid, :start)
      assert_receive {:trace, _, :send, {:"$gen_call", _, {_, {:setopts, _}}}, ^connection}, 1_000
      assert true = Port.close(tcp)
      expected = :inet.setopts(tcp, nodelay: true)
      assert {:error, _} = expected
      assert :ok = :sys.resume(connection)
      assert Task.await(caller, 1_000) == expected
      assert {:connected, state} = :sys.get_state(connection)
      assert state.active == false
      assert :ok = SSL.close(socket)
      assert_receive {:DOWN, ^monitor, :process, ^connection, :normal}, 1_000
      assert :ok = Peer.stop(peer)
    after
      if Process.alive?(connection), do: :sys.resume(connection)
      SSL.close(socket)
      Task.shutdown(caller)
      :ssl.close(peer.listener)
    end
  end

  defp waiting_peer do
    {:ok, peer} =
      Peer.start(fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    peer
  end

  defp raw_socket(socket) do
    {_phase, state} = :sys.get_state(socket.pid)
    state.tcp
  end

  defp ipv6_peer(fixtures \\ Peer.certificates(), no_sni? \\ false) do
    :ok = :ssl.start()

    {:ok, listener} =
      :ssl.listen(0, [
        :inet6,
        certfile: String.to_charlist(fixtures.certfile),
        keyfile: String.to_charlist(fixtures.keyfile),
        versions: [:"tlsv1.3"],
        verify: :verify_none,
        active: false,
        mode: :binary,
        packet: :raw,
        ip: {0, 0, 0, 0, 0, 0, 0, 1}
      ])

    {:ok, {_address, port}} = :ssl.sockname(listener)

    server =
      Task.async(fn ->
        {:ok, socket} = :ssl.transport_accept(listener, 5_000)
        {:ok, socket} = :ssl.handshake(socket, 5_000)
        if no_sni?, do: assert({:ok, []} == :ssl.connection_information(socket, [:sni_hostname]))
        {:error, :closed} = :ssl.recv(socket, 0, 5_000)
        :ok
      end)

    {listener, port, server}
  end
end

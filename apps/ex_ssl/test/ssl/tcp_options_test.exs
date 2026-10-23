defmodule SSL.TCPOptionsTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.LocalTLSPeer, as: Peer
  alias ExSSL.TestSupport.ClientAuthFixtures
  alias SSL.TCPOptions

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

  test "driver buffer and traffic options retain values and phase validation" do
    options = [buffer: 0, tos: 16, tclass: 32, priority: 6]
    assert {:ok, [], ^options} = TCPOptions.extract("localhost", options)
    assert {:ok, [], ^options} = TCPOptions.extract(:upgrade, options)
    assert {:ok, [], ^options} = TCPOptions.extract_setopts(options)
    assert TCPOptions.mutable(options ++ [port: 0]) == options

    for key <- [:buffer, :tos, :tclass, :priority], value <- [-1, 1.5, true, nil] do
      expected = {:error, {:options, {key, :unsupported_or_invalid}}}
      assert TCPOptions.extract("localhost", [{key, value}]) == expected
      assert TCPOptions.extract_setopts([{key, value}]) == expected
    end

    for key <- [:buffer, :tos, :tclass, :priority] do
      assert {:error, {:options, {^key, :duplicate}}} =
               TCPOptions.extract("localhost", [{key, 0}, {key, 1}])
    end
  end

  @tag :integration
  test "connect and setopts match actual driver values for both address families and OTP" do
    for family <- [:inet, :inet6], provider <- [SSL, :ssl] do
      traffic = if family == :inet, do: [tos: 16], else: [tclass: 16]
      options = [buffer: 65_536, priority: 6] ++ traffic
      {:ok, expected} = driver_reference(family, options)

      with_tls_peer(family, fn host, port ->
        assert {:ok, socket} =
                 provider.connect(host, port, Peer.client_options() ++ options, 5_000)

        try do
          assert driver_values(provider, socket, Keyword.keys(options)) == {:ok, expected}

          changed =
            [buffer: 32_768, priority: 1] ++ Keyword.new(traffic, fn {key, _} -> {key, 32} end)

          {:ok, expected_changed} = driver_reference(family, changed)
          assert :ok = provider.setopts(socket, changed)
          assert driver_values(provider, socket, Keyword.keys(changed)) == {:ok, expected_changed}
          IO.puts("#{inspect(provider)} #{family} driver options: #{inspect(expected_changed)}")
        after
          provider.close(socket)
        end
      end)
    end
  end

  @tag :integration
  test "driver buffer zero and large-value rounding agree with the public OTP reference" do
    for provider <- [SSL, :ssl] do
      with_tls_peer(:inet, fn host, port ->
        assert {:ok, socket} = provider.connect(host, port, Peer.client_options(), 5_000)

        try do
          for value <- [0, 65_536, 0x80000000] do
            {:ok, expected} = driver_reference(:inet, buffer: value)
            assert :ok = provider.setopts(socket, buffer: value)
            assert driver_values(provider, socket, [:buffer]) == {:ok, expected}
            IO.puts("#{inspect(provider)} driver buffer #{value}: #{inspect(expected)}")
          end
        after
          provider.close(socket)
        end
      end)
    end
  end

  @tag :integration
  test "traffic option results match the OS without committing virtual active mode on failure" do
    for {family, options} <- [{:inet, [tclass: 16]}, {:inet6, [tos: 16]}] do
      reference = driver_reference(family, options)

      with_tls_peer(family, fn host, port ->
        assert {:ok, socket} = SSL.connect(host, port, Peer.client_options(), 5_000)

        try do
          assert_traffic_result(socket, options, reference)
        after
          SSL.close(socket)
        end
      end)
    end
  end

  @tag :integration
  test "wrong-family connect classifies raw badarg without accepting a connection" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    host = {127, 0, 0, 1}

    assert catch_exit(:gen_tcp.connect(host, port, [:binary, active: false, tclass: 16], 100)) ==
             :badarg

    assert {:error, {:badarg, details}} =
             :ssl.connect(host, port, Peer.client_options() ++ [tclass: 16], 100)

    assert is_list(details)
    assert {:error, :badarg} = SSL.connect(host, port, Peer.client_options() ++ [tclass: 16], 100)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 30)
  end

  @tag :integration
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

  @tag :integration
  test "setopts validates all values before mutating TLS or TCP state" do
    peer = waiting_peer()
    assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, Peer.client_options(), 5_000)
    tcp = raw_socket(socket)
    assert {:ok, [nodelay: initial]} = :inet.getopts(tcp, [:nodelay])

    assert {:error, {:options, _}} = SSL.setopts(socket, nodelay: not initial, active: true)
    assert {:ok, [nodelay: ^initial]} = :inet.getopts(tcp, [:nodelay])
    assert {:error, {:options, _}} = SSL.setopts(socket, active: :once, buffer: -1)
    assert :ok = SSL.setopts(socket, nodelay: not initial, keepalive: true, active: false)

    assert {:ok, [{:nodelay, changed}, {:keepalive, true}]} =
             :inet.getopts(tcp, [:nodelay, :keepalive])

    assert changed == not initial
    assert {:ok, [active: :once]} = :inet.getopts(tcp, [:active])
    assert :ok = SSL.close(socket)
    assert {:error, :closed} = SSL.setopts(socket, nodelay: true)
    assert :ok = Peer.stop(peer)
  end

  @tag :integration
  test "unsupported raw socket controls are rejected before connect" do
    for option <- [[buffer: -1], [linger: {true, 0}], [send_timeout_close: false]] do
      assert {:error, {:options, _}} =
               SSL.connect(~c"127.0.0.1", 1, Peer.client_options() ++ option, 1_000)
    end
  end

  @tag :integration
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

  @tag :integration
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

  @tag :integration
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

  @tag :integration
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

  @tag :integration
  test "STARTTLS applies mutable TCP options after a validated plaintext handoff" do
    for provider <- [SSL, :ssl] do
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
        options = [nodelay: true, keepalive: true, buffer: 65_536, tos: 16, priority: 6]
        {:ok, expected} = driver_reference(:inet, options)
        {:ok, before_upgrade} = :inet.getopts(tcp, Keyword.keys(options))

        assert {:ok, socket} = provider.connect(tcp, Peer.client_options() ++ options, 5_000)

        if provider == :ssl do
          assert driver_values(provider, socket, Keyword.keys(options)) ==
                   {:ok, Map.new(before_upgrade)}

          assert :ok = provider.setopts(socket, options)
          IO.puts("OTP STARTTLS retains existing TCP options; explicit setopts applies changes")
        end

        assert driver_values(provider, socket, Keyword.keys(options)) == {:ok, expected}
        assert :ok = provider.close(socket)
        assert :ok = Peer.stop(peer)
      after
        :gen_tcp.close(tcp)
        :gen_tcp.close(peer.listener)
      end
    end
  end

  @tag :integration
  test "STARTTLS without a TLS buffer option preserves the existing raw driver buffer" do
    for provider <- [SSL, :ssl] do
      {:ok, peer} =
        Peer.start_starttls(fn socket ->
          assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
          :ok
        end)

      {:ok, tcp} =
        :gen_tcp.connect(
          ~c"127.0.0.1",
          peer.port,
          [:binary, active: false, buffer: 65_536],
          5_000
        )

      try do
        assert {:ok, [buffer: 65_536]} = :inet.getopts(tcp, [:buffer])
        assert {:ok, "220 local STARTTLS peer\r\n"} = :gen_tcp.recv(tcp, 25, 5_000)
        assert :ok = :gen_tcp.send(tcp, "STARTTLS\r\n")
        assert {:ok, "220 begin TLS\r\n"} = :gen_tcp.recv(tcp, 15, 5_000)
        assert {:ok, socket} = provider.connect(tcp, Peer.client_options(), 5_000)
        assert {:ok, %{buffer: 65_536}} = driver_values(provider, socket, [:buffer])
        assert :ok = provider.close(socket)
        assert :ok = Peer.stop(peer)
      after
        :gen_tcp.close(tcp)
        :gen_tcp.close(peer.listener)
      end
    end
  end

  @tag :integration
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

  defp assert_traffic_result(socket, options, {:error, _reason} = error) do
    assert SSL.setopts(socket, options ++ [active: :once]) == error
    assert {:connected, %{active: false}} = :sys.get_state(socket.pid)
  end

  defp assert_traffic_result(socket, options, {:ok, expected}) do
    assert :ok = SSL.setopts(socket, options ++ [active: :once])
    assert driver_values(SSL, socket, Keyword.keys(options)) == {:ok, expected}
  end

  defp driver_reference(family, options) do
    {:ok, tcp} = :gen_tcp.listen(0, [family, :binary, active: false])

    try do
      with :ok <- :inet.setopts(tcp, options),
           {:ok, values} <- :inet.getopts(tcp, Keyword.keys(options)),
           do: {:ok, Map.new(values)}
    after
      :gen_tcp.close(tcp)
    end
  end

  defp driver_values(SSL, socket, keys) do
    with {:ok, values} <- :inet.getopts(raw_socket(socket), keys), do: {:ok, Map.new(values)}
  end

  defp driver_values(:ssl, socket, keys) do
    with {:ok, values} <- :ssl.getopts(socket, keys), do: {:ok, Map.new(values)}
  end

  defp with_tls_peer(:inet, fun) do
    peer = waiting_peer()

    try do
      fun.({127, 0, 0, 1}, peer.port)
    after
      assert :ok = Peer.stop(peer)
    end
  end

  defp with_tls_peer(:inet6, fun) do
    {listener, port, server} = ipv6_peer()

    try do
      fun.({0, 0, 0, 0, 0, 0, 0, 1}, port)
      assert :ok = Task.await(server, 6_000)
    after
      :ssl.close(listener)
      if Process.alive?(server.pid), do: Task.shutdown(server)
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

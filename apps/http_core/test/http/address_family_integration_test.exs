defmodule HTTP.Transport.AddressFamilyIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)
  @wait 4_000

  test "native TCP prefers a successful IPv6 endpoint without an IPv4 attempt" do
    port = tcp_peer({0, 0, 0, 0, 0, 0, 0, 1}, [:inet6, {:ipv6_v6only, true}])
    {result, attempts} = connect(HTTP.Transport.TCP, "::1", port, prefer_ipv6: true)
    assert {:ok, socket} = result
    assert_families(attempts, [:inet6])
    assert {:ok, "pong"} = HTTP.Transport.TCP.recv(socket, 4, @wait)
    :ok = HTTP.Transport.TCP.close(socket)
  end

  for transport <- [HTTP.Transport.TCP, HTTP.Transport.SSL, HTTP.Transport.ExSSL],
      host <- ["localhost", "127.0.0.1"] do
    test "#{inspect(transport)} falls back to IPv4 for #{host} before sending payload" do
      transport = unquote(transport)
      host = unquote(host)

      port = transport_peer(transport)

      {result, attempts} =
        connect(transport, host, port,
          prefer_ipv6: true,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
        )

      assert {:ok, socket} = result
      assert_families(attempts, [:inet6, :inet])
      assert {:ok, "pong"} = transport.recv(socket, 4, @wait)
      :ok = transport.close(socket)
    end
  end

  for transport <- [HTTP.Transport.SSL, HTTP.Transport.ExSSL] do
    test "#{inspect(transport)} verifies localhost over the preferred IPv6 connection" do
      transport = unquote(transport)
      port = tls_peer({0, 0, 0, 0, 0, 0, 0, 1}, [:inet6, {:ipv6_v6only, true}])

      {result, attempts} =
        connect(transport, "localhost", port,
          prefer_ipv6: true,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
        )

      assert {:ok, socket} = result
      assert_families(attempts, [:inet6])
      assert {:ok, "pong"} = transport.recv(socket, 4, @wait)
      :ok = transport.close(socket)
    end

    test "#{inspect(transport)} does not fall back after IPv6 TLS verification fails" do
      transport = unquote(transport)
      port = tls_peer({0, 0, 0, 0, 0, 0, 0, 1}, [:inet6, {:ipv6_v6only, true}], :reject)
      {:ok, ipv4} = :gen_tcp.listen(port, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_tcp.close(ipv4) end)

      {result, attempts} =
        connect(transport, "::1", port,
          prefer_ipv6: true,
          ssl: [
            cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
            server_name_indication: ~c"wrong.example"
          ]
        )

      assert {:error, _} = result
      assert_families(attempts, [:inet6])
      assert {:error, :timeout} = :gen_tcp.accept(ipv4, 0)
    end
  end

  test "strict inet6 and connect_address pinning never fall back" do
    port = tcp_peer({127, 0, 0, 1})

    {result, attempts} =
      connect(HTTP.Transport.TCP, "127.0.0.1", port,
        prefer_ipv6: true,
        socket_opts: [:inet6]
      )

    assert {:error, :nxdomain} = result
    assert_families(attempts, [:inet6])

    {result, attempts} =
      connect(HTTP.Transport.TCP, "unresolvable.invalid", port,
        prefer_ipv6: true,
        connect_address: {127, 0, 0, 2}
      )

    assert {:error, :econnrefused} = result
    assert [{_, ^port, _socket_opts, _timeout}] = attempts
    assert elem(hd(attempts), 0) == {127, 0, 0, 2}
  end

  test "a spent IPv6 connection budget cannot start a fresh IPv4 attempt" do
    {:ok, ipv6} =
      :gen_tcp.listen(0, [
        :binary,
        :inet6,
        active: false,
        ip: {0, 0, 0, 0, 0, 0, 0, 1},
        ipv6_v6only: true,
        backlog: 0
      ])

    {:ok, port} = :inet.port(ipv6)
    {:ok, queued} = :gen_tcp.connect(~c"::1", port, [:binary, :inet6, active: false], @wait)
    {:ok, ipv4} = :gen_tcp.listen(port, [:binary, active: false, ip: {127, 0, 0, 1}])

    try do
      started = System.monotonic_time(:millisecond)

      assert {:error, :timeout} =
               HTTP.Transport.AddressFamily.connect(
                 "localhost",
                 port,
                 [:binary, active: false],
                 [prefer_ipv6: true],
                 120
               )

      assert System.monotonic_time(:millisecond) - started < 1_000
      assert {:error, :timeout} = :gen_tcp.accept(ipv4, 0)
    after
      :gen_tcp.close(queued)
      :gen_tcp.close(ipv6)
      :gen_tcp.close(ipv4)
    end
  end

  defp connect(transport, host, port, opts) do
    parent = self()

    {worker, monitor} =
      spawn_monitor(fn ->
        receive do
          :start -> :ok
        end

        result = transport.connect(host, port, opts, @wait)

        case result do
          {:ok, socket} -> :ok = transport.controlling_process(socket, parent)
          _ -> :ok
        end

        send(parent, {:connected, self(), result})
      end)

    :erlang.trace_pattern({:gen_tcp, :connect, 4}, [{:_, [], []}], [])
    :erlang.trace(worker, true, [:call, {:tracer, self()}])

    on_exit(fn ->
      :erlang.trace_pattern({:gen_tcp, :connect, 4}, false, [])
      if Process.alive?(worker), do: Process.exit(worker, :kill)
    end)

    send(worker, :start)
    assert_receive {:connected, ^worker, result}, @wait
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, @wait
    fence = :erlang.trace_delivered(worker)
    assert_receive {:trace_delivered, ^worker, ^fence}, @wait
    {result, attempts(worker, [])}
  end

  defp attempts(worker, acc) do
    receive do
      {:trace, ^worker, :call, {:gen_tcp, :connect, [host, port, opts, timeout]}} ->
        attempts(worker, [{host, port, opts, timeout} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp assert_families(attempts, expected) do
    assert Enum.map(attempts, fn {_host, _port, opts, _timeout} ->
             Enum.find(opts, &(&1 in [:inet, :inet6]))
           end) == expected
  end

  defp transport_peer(HTTP.Transport.TCP), do: tcp_peer({127, 0, 0, 1})
  defp transport_peer(_transport), do: tls_peer({127, 0, 0, 1})

  defp tcp_peer(address, extra \\ []) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ip: address, reuseaddr: true] ++ extra)

    {:ok, port} = :inet.port(listener)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @wait)
        :gen_tcp.close(listener)
        :ok = :gen_tcp.send(socket, "pong")
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, @wait)
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listener)
    end)

    port
  end

  defp tls_peer(address, extra \\ [], outcome \\ :accept) do
    {:ok, listener} =
      :ssl.listen(
        0,
        [
          :binary,
          active: false,
          ip: address,
          reuseaddr: true,
          certfile: String.to_charlist(Path.join(@fixtures, "localhost.pem")),
          keyfile: String.to_charlist(Path.join(@fixtures, "localhost.key"))
        ] ++ extra
      )

    {:ok, {_, port}} = :ssl.sockname(listener)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :ssl.transport_accept(listener, @wait)

        case :ssl.handshake(socket, @wait) do
          {:ok, socket} ->
            assert outcome == :accept
            :ok = :ssl.send(socket, "pong")
            assert {:error, :closed} = :ssl.recv(socket, 0, @wait)
            :ssl.close(socket)

          {:error, _} ->
            assert outcome == :reject
        end

        :ssl.close(listener)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :ssl.close(listener)
    end)

    port
  end
end

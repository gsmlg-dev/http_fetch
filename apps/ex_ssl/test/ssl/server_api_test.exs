defmodule SSL.ServerAPITest do
  use ExUnit.Case, async: true

  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.Protocol.{ClientOffer, Record}

  @dir Path.expand("../support/server", __DIR__)
  @cert Path.join(@dir, "cert.pem")
  @key Path.join(@dir, "key.pem")
  @ca Path.join(@dir, "ca.pem")
  @server [certfile: @cert, keyfile: @key, ip: {127, 0, 0, 1}]

  setup do
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  test "listen validates options before opening a port" do
    ports = owned_ports()

    assert SSL.listen(0, verify: :bogus, certfile: @cert, keyfile: @key) ==
             {:error, {:invalid_option, :verify}}

    assert SSL.listen(0, verify: :verify_peer, certfile: @cert, keyfile: @key) ==
             {:error, {:invalid_option, :cacerts}}

    assert SSL.listen(0, certfile: @cert, keyfile: @key, versions: [:"tlsv1.2"]) ==
             {:error, {:unsupported_option, :versions}}

    for {extra, key} <- [
          {[active: true], :active},
          {[active: :once], :active},
          {[mode: :list], :mode},
          {[:list], :mode}
        ] do
      assert SSL.listen(0, @server ++ extra) == {:error, {:unsupported_option, key}}
    end

    assert {:ok, listen} = SSL.listen(0, [:binary, mode: :binary, active: false] ++ @server)
    assert :ok = SSL.close(listen)

    assert owned_ports() == ports
  end

  test "listen, transport_accept and handshake with an OTP client" do
    {listen, port} = listen([])
    assert {:ok, {{127, 0, 0, 1}, ^port}} = SSL.sockname(listen)

    client =
      client(port, [], fn c ->
        :ok = :ssl.send(c, "ping")
        :ssl.recv(c, 0, 2000)
      end)

    assert {:ok, %SSL.Socket{} = accepted} = SSL.transport_accept(listen, 5000)
    assert {:ok, %SSL.Socket{} = s} = SSL.handshake(accepted, 5000)
    assert SSL.recv(s, 0, 1000) == {:ok, "ping"}
    assert :ok = SSL.send(s, "pong")
    assert finish(client) == {:ok, "pong"}
    assert :ok = SSL.close(s)
    assert :ok = SSL.close(listen)
    assert SSL.transport_accept(listen, 100) == {:error, :closed}
  end

  test "handshake timeout" do
    {listen, port} = listen([])
    {:ok, raw} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    {:ok, %SSL.Socket{pid: pid} = s} = SSL.transport_accept(listen, 5000)
    monitor = Process.monitor(pid)
    started = System.monotonic_time(:millisecond)
    assert SSL.handshake(s, 100) == {:error, :timeout}
    assert System.monotonic_time(:millisecond) - started < 1_000
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1000
    :gen_tcp.close(raw)
  end

  test "client TCP close mid-handshake returns closed and stops the connection" do
    hello = client_hello()
    {listen, port} = listen([])
    {:ok, raw} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    {:ok, %SSL.Socket{pid: pid} = s} = SSL.transport_accept(listen, 5000)
    monitor = Process.monitor(pid)
    handshake = Task.async(fn -> SSL.handshake(s, 5000) end)
    :ok = :gen_tcp.send(raw, hello)
    assert {:ok, <<22, 3, 3, _::binary>>} = :gen_tcp.recv(raw, 0, 2000)
    :ok = :gen_tcp.close(raw)
    assert Task.await(handshake) == {:error, :closed}
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1000
  end

  test "controlling_process moves active delivery" do
    test = self()
    {listen, port} = listen([])

    client =
      Task.async(fn ->
        {:ok, c} = :ssl.connect({127, 0, 0, 1}, port, client_options(active: true), 5000)
        :ok = :ssl.send(c, "moved")

        receive do
          {:ssl_closed, ^c} -> :closed
        after
          5000 -> :timeout
        end
      end)

    {:ok, %SSL.Socket{pid: pid} = s} = accept(listen)

    owner =
      spawn(fn ->
        receive do: (:go -> :ok = SSL.setopts(s, active: :once))
        receive do: ({:ssl, ^s, data} -> send(test, {:moved, data}))
        receive do: (:never -> :ok)
      end)

    assert :ok = SSL.controlling_process(s, owner)
    send(owner, :go)
    assert_receive {:moved, "moved"}, 2000
    refute_received {:ssl, ^s, _}
    monitor = Process.monitor(pid)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1000
    assert Task.await(client) == :closed
  end

  test "listen socket supports controlling_process" do
    {listen, _port} = listen([])
    test = self()

    owner =
      spawn(fn ->
        receive do: (:close -> send(test, {:closed, SSL.close(listen)}))
      end)

    assert :ok = SSL.controlling_process(listen, owner)
    assert :erlang.port_info(listen.carrier, :connected) == {:connected, owner}
    send(owner, :close)
    assert_receive {:closed, :ok}, 1000
  end

  test "server upgrade of an existing gen_tcp socket" do
    {:ok, tcp_listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(tcp_listen)

    client =
      client(port, [], fn c ->
        :ok = :ssl.send(c, "upgraded")
        :ssl.recv(c, 0, 2000)
      end)

    {:ok, tcp} = :gen_tcp.accept(tcp_listen, 5000)

    assert {:ok, %SSL.Socket{} = s, []} =
             SSL.handshake(tcp, [certfile: @cert, keyfile: @key], 2000)

    assert SSL.getopts(s, [:send_timeout, :send_timeout_close]) ==
             {:ok, [send_timeout: 30_000, send_timeout_close: true]}

    assert SSL.recv(s, 0, 1000) == {:ok, "upgraded"}
    assert :ok = SSL.send(s, "ok")
    assert finish(client) == {:ok, "ok"}
    SSL.close(s)
    :gen_tcp.close(tcp_listen)
  end

  test "server upgrade rejects non-passive carrier modes without taking the socket" do
    {:ok, tcp_listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(tcp_listen)
    {:ok, raw} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    {:ok, tcp} = :gen_tcp.accept(tcp_listen, 5000)

    for {extra, key} <- [{[active: true], :active}, {[mode: :list], :mode}, {[:list], :mode}] do
      assert SSL.handshake(tcp, [certfile: @cert, keyfile: @key] ++ extra, 100) ==
               {:error, {:unsupported_option, key}}
    end

    assert :erlang.port_info(tcp, :connected) == {:connected, self()}
    assert :inet.getopts(tcp, [:active, :mode]) == {:ok, [active: false, mode: :binary]}
    :gen_tcp.close(raw)
    :gen_tcp.close(tcp)
    :gen_tcp.close(tcp_listen)
  end

  test "server upgrade rejects invalid options without taking the socket" do
    {:ok, tcp_listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(tcp_listen)
    {:ok, raw} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    {:ok, tcp} = :gen_tcp.accept(tcp_listen, 5000)

    assert SSL.handshake(tcp, [certfile: @cert, keyfile: @key, verify: :bogus], 100) ==
             {:error, {:invalid_option, :verify}}

    assert SSL.handshake(tcp, [certfile: @cert, keyfile: @key, verify: :verify_peer], 100) ==
             {:error, {:invalid_option, :cacerts}}

    assert :erlang.port_info(tcp, :connected) == {:connected, self()}
    :gen_tcp.close(raw)
    :gen_tcp.close(tcp)
    :gen_tcp.close(tcp_listen)
  end

  test "server carriers default to a finite send timeout" do
    {listen, port} = listen([])
    client = client(port, [], fn _c -> :ok end)
    {:ok, s} = accept(listen)

    assert SSL.getopts(s, [:send_timeout, :send_timeout_close]) ==
             {:ok, [send_timeout: 30_000, send_timeout_close: true]}

    assert :ok = finish(client)
    SSL.close(s)
  end

  test "an explicit send_timeout or send_timeout_close replaces both defaults" do
    for {extra, expected} <- [
          {[send_timeout: 1230], [send_timeout: 1230, send_timeout_close: false]},
          {[send_timeout_close: false], [send_timeout: :infinity, send_timeout_close: false]}
        ] do
      {listen, port} = listen(extra)
      client = client(port, [], fn _c -> :ok end)
      {:ok, s} = accept(listen)
      assert SSL.getopts(s, [:send_timeout, :send_timeout_close]) == {:ok, expected}
      assert :ok = finish(client)
      SSL.close(s)
    end
  end

  test "an ex_ssl client accepts the server chain it can verify" do
    # The fixture chain matches none of the ex_ssl client's offered certificate
    # schemes, so this exercises the RFC 8446 §4.4.2.2 TCP relaxation.
    {:ok, offer} = ClientOffer.from_client_hello(ex_ssl_client_hello())
    {:ok, %{identity: identity}} = SSL.ServerOptions.build(certfile: @cert, keyfile: @key)

    refute CertificateSignaturePolicy.compatible?(
             identity.chain,
             nil,
             offer.certificate_signature_schemes || offer.signature_schemes
           )

    {listen, port} = listen([])

    client =
      Task.async(fn ->
        with {:ok, c} <-
               SSL.connect(~c"localhost", port,
                 verify: :verify_peer,
                 cacertfile: @ca,
                 server_name_indication: ~c"localhost"
               ) do
          result = SSL.recv(c, 0, 2000)
          SSL.close(c)
          result
        end
      end)

    assert {:ok, s} = accept(listen)
    assert :ok = SSL.send(s, "hello")
    assert Task.await(client) == {:ok, "hello"}
    SSL.close(s)
  end

  test "a client offering none of the identity's signature schemes is handshake_failure" do
    {listen, port} = listen([])

    client =
      Task.async(fn ->
        :ssl.connect(
          {127, 0, 0, 1},
          port,
          client_options(signature_algs: [:ecdsa_secp256r1_sha256]),
          5000
        )
      end)

    assert {:ok, s} = SSL.transport_accept(listen, 5000)

    assert {:error, {:tls_alert, {:handshake_failure, description}}} = SSL.handshake(s, 5000)
    assert List.to_string(description) =~ "no_shared_signature"
    assert {:error, {:tls_alert, {:handshake_failure, _}}} = Task.await(client)
  end

  test "getstat returns carrier counters" do
    {listen, port} = listen([])

    client =
      client(port, [], fn c ->
        :ok = :ssl.send(c, "count")
        :ok
      end)

    {:ok, s} = accept(listen)
    assert SSL.recv(s, 0, 1000) == {:ok, "count"}
    assert {:ok, stats} = SSL.getstat(s)
    assert stats[:recv_oct] > 0
    assert {:ok, [recv_oct: received]} = SSL.getstat(s, [:recv_oct])
    assert received > 0
    assert :ok = finish(client)
    SSL.close(s)
  end

  test "client sockets do not support server-only calls" do
    {:ok, otp} =
      :ssl.listen(0,
        certfile: @cert,
        keyfile: @key,
        versions: [:"tlsv1.3"],
        ip: {127, 0, 0, 1},
        log_level: :none
      )

    {:ok, {_, port}} = :ssl.sockname(otp)

    server =
      Task.async(fn ->
        {:ok, t} = :ssl.transport_accept(otp, 5000)
        {:ok, t} = :ssl.handshake(t, 5000)
        receive do: (:finish -> :ssl.close(t))
      end)

    {:ok, c} =
      SSL.connect(~c"localhost", port,
        verify: :verify_peer,
        cacertfile: @ca,
        server_name_indication: ~c"localhost"
      )

    assert SSL.getopts(c, [:send_timeout]) == {:error, :enotsup}
    assert SSL.getstat(c) == {:error, :enotsup}
    assert SSL.shutdown(c, :write) == {:error, :enotsup}
    assert SSL.handshake(c, 100) == {:error, :enotsup}
    SSL.close(c)
    assert :ok = finish(server)
    :ssl.close(otp)
  end

  test "a peer KeyUpdate after shutdown(:write) only updates the read key" do
    {listen, port} = listen([])
    proxy = proxy(port)
    test = self()

    client =
      client(proxy.port, [], fn c ->
        receive do: (:rekey -> :ok)
        :ok = :ssl.update_keys(c, :read_write)
        :ok = :ssl.send(c, "after-shutdown")
        send(test, :rekeyed)
        :ssl.recv(c, 0, 2000)
      end)

    {:ok, s} = accept(listen)
    # The client must not see close_notify before it sends its KeyUpdate.
    send(proxy.pid, :hold)
    assert_receive {:held, proxy_pid} when proxy_pid == proxy.pid, 1000
    assert :ok = SSL.shutdown(s, :write)
    send(client.pid, :rekey)
    assert_receive :rekeyed, 2000
    assert SSL.recv(s, 0, 2000) == {:ok, "after-shutdown"}
    send(proxy.pid, :release)
    assert {:error, _} = finish(client)
    SSL.close(s)
  end

  test "an inner alert record that is not two bytes is a decode_error" do
    {listen, port} = listen([])
    proxy = proxy(port)
    client = client(proxy.port, [], fn _c -> :ok end)
    {:ok, s} = accept(listen)
    # Protect a raw record with the server's own client-application read state.
    {:connected, %{read: read}} = :sys.get_state(s.pid)
    {:ok, record, _read} = Record.encrypt(read, :alert, <<2>>)
    send(proxy.pid, {:inject, record})
    assert {:error, {:tls_alert, {:decode_error, _}}} = SSL.recv(s, 0, 2000)
    assert :ok = finish(client)
  end

  test "peer TCP close with a pending recv stops the connection normally" do
    {listen, port} = listen([])
    proxy = proxy(port)
    client = client(proxy.port, [], fn _c -> :ok end)
    {:ok, %SSL.Socket{pid: pid} = s} = accept(listen)
    monitor = Process.monitor(pid)
    recv = Task.async(fn -> SSL.recv(s, 0, 5000) end)
    await_pending_recv(pid)
    send(proxy.pid, :close_server_side)
    assert Task.await(recv) == {:error, :closed}
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1000
    send(client.pid, :finish)
  end

  defp listen(extra) do
    {:ok, listen} = SSL.listen(0, @server ++ extra)
    on_exit(fn -> SSL.close(listen) end)
    {:ok, {_, port}} = SSL.sockname(listen)
    {listen, port}
  end

  defp accept(listen) do
    with {:ok, s} <- SSL.transport_accept(listen, 5000), do: SSL.handshake(s, 5000)
  end

  defp await_pending_recv(pid) do
    case :sys.get_state(pid) do
      {:connected, %{recv: %{}}} -> :ok
      _ -> await_pending_recv(pid)
    end
  end

  defp owned_ports do
    Port.list()
    |> Enum.filter(&(Port.info(&1, :connected) == {:connected, self()}))
    |> Enum.sort()
  end

  defp client_options(extra) do
    Keyword.merge(
      [
        mode: :binary,
        active: false,
        versions: [:"tlsv1.3"],
        verify: :verify_peer,
        cacertfile: @ca,
        server_name_indication: ~c"localhost",
        log_level: :none
      ],
      extra
    )
  end

  # The client runs its script and keeps its socket open until told to finish.
  defp client(port, extra, script) do
    Task.async(fn ->
      {:ok, c} = :ssl.connect({127, 0, 0, 1}, port, client_options(extra), 5000)
      result = script.(c)
      receive do: (:finish -> result)
    end)
  end

  defp finish(task) do
    send(task.pid, :finish)
    Task.await(task)
  end

  # Captures one OTP ClientHello record from a plain TCP listener.
  defp client_hello do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)

    connect =
      Task.async(fn -> :ssl.connect({127, 0, 0, 1}, port, client_options([]), 5000) end)

    {:ok, tcp} = :gen_tcp.accept(listen, 5000)
    {:ok, <<22, 3, _minor, length::16>> = header} = :gen_tcp.recv(tcp, 5, 2000)
    {:ok, body} = :gen_tcp.recv(tcp, length, 2000)
    :gen_tcp.close(tcp)
    :gen_tcp.close(listen)
    assert {:error, _} = Task.await(connect)
    header <> body
  end

  # Captures the ClientHello handshake message of an ex_ssl client.
  defp ex_ssl_client_hello do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)

    connect =
      Task.async(fn ->
        SSL.connect(~c"localhost", port,
          verify: :verify_peer,
          cacertfile: @ca,
          server_name_indication: ~c"localhost"
        )
      end)

    {:ok, tcp} = :gen_tcp.accept(listen, 5000)
    {:ok, <<22, 3, _minor, length::16>>} = :gen_tcp.recv(tcp, 5, 2000)
    {:ok, hello} = :gen_tcp.recv(tcp, length, 2000)
    :gen_tcp.close(tcp)
    :gen_tcp.close(listen)
    assert {:error, _} = Task.await(connect)
    hello
  end

  # A relay between the client and the server. It can inject client-to-server bytes
  # and hold server-to-client bytes until released.
  defp proxy(server_port) do
    test = self()
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)

    pid =
      spawn_link(fn ->
        {:ok, front} = :gen_tcp.accept(listen, 5000)

        {:ok, back} =
          :gen_tcp.connect({127, 0, 0, 1}, server_port, [
            :binary,
            active: true,
            exit_on_close: false
          ])

        :ok = :inet.setopts(front, active: true)
        relay(%{test: test, front: front, back: back, held: nil})
      end)

    on_exit(fn -> :gen_tcp.close(listen) end)
    %{pid: pid, port: port}
  end

  defp relay(%{front: front, back: back} = state) do
    receive do
      {:tcp, ^front, bytes} ->
        _ = :gen_tcp.send(back, bytes)
        relay(state)

      {:tcp, ^back, bytes} when is_list(state.held) ->
        relay(%{state | held: [state.held, bytes]})

      {:tcp, ^back, bytes} ->
        _ = :gen_tcp.send(front, bytes)
        relay(state)

      :close_server_side ->
        :gen_tcp.close(back)
        relay(state)

      {:inject, bytes} ->
        :ok = :gen_tcp.send(back, bytes)
        relay(state)

      :hold ->
        send(state.test, {:held, self()})
        relay(%{state | held: []})

      :release ->
        _ = :gen_tcp.send(front, state.held)
        _ = :gen_tcp.shutdown(front, :write)
        relay(%{state | held: nil})

      {:tcp_closed, _} ->
        relay(state)
    end
  end
end

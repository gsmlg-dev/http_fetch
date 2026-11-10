defmodule SSL.ServerConnectionTest do
  use ExUnit.Case, async: true

  alias SSL.{ServerConnection, ServerOptions}

  @dir Path.expand("../support/server", __DIR__)
  @cert Path.join(@dir, "cert.pem")
  @key Path.join(@dir, "key.pem")
  @ca Path.join(@dir, "ca.pem")
  @hrr_random Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

  setup do
    {:ok, _} = Application.ensure_all_started(:ssl)
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listen) end)
    {:ok, port} = :inet.port(listen)
    %{listen: listen, port: port}
  end

  test "completes TLS 1.3 handshake and echoes data", ctx do
    client =
      client(ctx.port, [], fn c ->
        :ok = :ssl.send(c, "ping")
        :ssl.recv(c, 0, 2000)
      end)

    {:ok, s} = accept(ctx, [])
    assert SSL.recv(s, 0, 1000) == {:ok, "ping"}
    assert :ok = SSL.send(s, "ping")
    assert finish(client) == {:ok, "ping"}
    assert :ok = SSL.close(s)
  end

  test "negotiates ALPN h2", ctx do
    client = client(ctx.port, [alpn_advertised_protocols: ["h2"]], &:ssl.negotiated_protocol/1)
    {:ok, s} = accept(ctx, alpn_preferred_protocols: ["h2", "http/1.1"])
    assert SSL.negotiated_protocol(s) == {:ok, "h2"}
    assert finish(client) == {:ok, "h2"}
    SSL.close(s)
  end

  test "client without ALPN connects with no protocol", ctx do
    client = client(ctx.port, [], &:ssl.negotiated_protocol/1)
    {:ok, s} = accept(ctx, alpn_preferred_protocols: ["h2"])
    assert SSL.negotiated_protocol(s) == {:error, :protocol_not_negotiated}
    assert finish(client) == {:error, :protocol_not_negotiated}
    SSL.close(s)
  end

  test "ALPN mismatch sends no_application_protocol", ctx do
    client = failing_client(ctx.port, alpn_advertised_protocols: ["http/1.1"])

    assert {:error, {:tls_alert, {:no_application_protocol, _}}} =
             accept(ctx, alpn_preferred_protocols: ["h2"])

    assert {:error, {:tls_alert, {:no_application_protocol, _}}} = Task.await(client)
  end

  test "TLS 1.2-only client gets protocol_version and server process exits", ctx do
    client = failing_client(ctx.port, versions: [:"tlsv1.2"])
    {:ok, tcp} = :gen_tcp.accept(ctx.listen, 5000)
    {:ok, %SSL.Socket{pid: pid} = s} = ServerConnection.start(tcp, config([]), self())
    monitor = Process.monitor(pid)
    assert {:error, {:tls_alert, {:protocol_version, _}}} = ServerConnection.handshake(s, 5000)
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 1000
    assert {:error, {:tls_alert, {:protocol_version, _}}} = Task.await(client)
  end

  test "HelloRetryRequest when client key_share lacks a server group", ctx do
    %{pid: proxy_pid} = proxy = proxy(ctx.port)

    client =
      client(proxy.port, [supported_groups: [:secp256r1, :x25519]], fn c ->
        :ok = :ssl.send(c, "after-retry")
        :ssl.recv(c, 0, 2000)
      end)

    {:ok, s} = accept(ctx, [])
    assert SSL.recv(s, 0, 1000) == {:ok, "after-retry"}
    assert :ok = SSL.send(s, "ok")
    assert finish(client) == {:ok, "ok"}

    assert_receive {:server_bytes, ^proxy_pid,
                    <<22, 3, 3, _::16, 2, _::24, 3, 3, random::binary-32>>},
                   1000

    assert random == @hrr_random
    SSL.close(s)
  end

  test "active once delivers {:ssl, socket, data} and {:ssl_closed, socket}", ctx do
    test = self()

    client =
      client(ctx.port, [], fn c ->
        :ok = :ssl.send(c, "hello")
        send(test, :sent)
        receive do: (:close -> :ssl.close(c))
      end)

    {:ok, s} = accept(ctx, [])
    assert :ok = SSL.setopts(s, active: :once)
    assert_receive {:ssl, ^s, "hello"}, 1000
    send(client.pid, :close)
    assert_receive {:ssl_closed, ^s}, 1000
    assert :ok = finish(client)
  end

  # #158: a transport error must not discard plaintext already decrypted.
  for mode <- [:passive, :once] do
    test "#{mode} delivers buffered plaintext before a transport error", ctx do
      client = client(ctx.port, [], fn c -> :ssl.send(c, "buffered") end)
      {:ok, s} = accept(ctx, [])
      await_server_buffer(s, byte_size("buffered"))
      {:connected, %{tcp: tcp}} = :sys.get_state(s.pid)
      send(s.pid, {:tcp_error, tcp, :econnreset})

      if unquote(mode) == :passive do
        assert SSL.recv(s, 0, 1000) == {:ok, "buffered"}
        assert SSL.recv(s, 0, 1000) == {:error, :econnreset}
      else
        assert :ok = SSL.setopts(s, active: :once)
        assert_receive {:ssl, ^s, "buffered"}, 1000
        assert_receive {:ssl_error, ^s, :econnreset}, 1000
        refute_receive {:ssl_closed, ^s}, 20
      end

      assert :ok = finish(client)
    end
  end

  test "client KeyUpdate requesting an update keeps both directions usable", ctx do
    client =
      client(ctx.port, [], fn c ->
        :ok = :ssl.update_keys(c, :read_write)
        :ok = :ssl.send(c, "rekeyed")
        :ssl.recv(c, 0, 2000)
      end)

    {:ok, s} = accept(ctx, [])
    assert SSL.recv(s, 0, 1000) == {:ok, "rekeyed"}
    assert :ok = SSL.send(s, "ack")
    assert finish(client) == {:ok, "ack"}
    SSL.close(s)
  end

  # RFC 8446 §4.2.10: a server that rejects early data skips the 0-RTT records it
  # cannot decrypt and completes a full handshake.
  test "client 0-RTT with an unknown PSK is skipped and the full handshake completes", ctx do
    ticket = otp_early_data_ticket()
    early = :binary.copy("0", 4096)

    client =
      client(
        ctx.port,
        [session_tickets: :manual, use_ticket: [ticket], early_data: early],
        fn c ->
          :ok = :ssl.send(c, "after-early-data")
          :ssl.recv(c, 0, 2000)
        end
      )

    {:ok, s} = accept(ctx, [])
    assert SSL.recv(s, 0, 1000) == {:ok, "after-early-data"}
    assert :ok = SSL.send(s, "full")
    assert finish(client) == {:ok, "full"}
    SSL.close(s)
  end

  # OTP's client cannot complete 0-RTT across a HelloRetryRequest, so its first
  # flight (ClientHello offering early_data, then 0-RTT records) is replayed raw.
  test "0-RTT offered before a HelloRetryRequest is skipped", ctx do
    ticket = otp_early_data_ticket()

    flight =
      captured_first_flight(
        supported_groups: [:secp256r1, :x25519],
        session_tickets: :manual,
        use_ticket: [ticket],
        early_data: "early"
      )

    {:ok, raw} = :gen_tcp.connect({127, 0, 0, 1}, ctx.port, [:binary, active: false])
    :ok = :gen_tcp.send(raw, flight)
    test = self()
    server = spawn_link(fn -> send(test, {:accepted, accept(ctx, [])}) end)

    assert {:ok, <<22, 3, 3, _::16, 2, _::24, 3, 3, random::binary-32, _::binary>>} =
             :gen_tcp.recv(raw, 0, 2000)

    assert random == @hrr_random
    # The skipped early data draws no alert; the server waits for a second hello.
    assert {:error, :timeout} = :gen_tcp.recv(raw, 0, 200)
    :ok = :gen_tcp.close(raw)
    assert_receive {:accepted, {:error, :closed}}, 2000
    refute Process.alive?(server)
  end

  test "an undecryptable record without an early_data offer is bad_record_mac", ctx do
    proxy = proxy(ctx.port, bogus_record(64))
    failing_client(proxy.port, [])
    assert {:error, {:tls_alert, {:bad_record_mac, _}}} = accept(ctx, [])
  end

  test "rejected early data beyond the skip budget is bad_record_mac", ctx do
    ticket = otp_early_data_ticket()
    # One maximal skipped record plus the client's own early data exceeds 16 KiB.
    proxy = proxy(ctx.port, bogus_record(16_384 + 17))

    failing_client(proxy.port,
      session_tickets: :manual,
      use_ticket: [ticket],
      early_data: "early"
    )

    assert {:error, {:tls_alert, {:bad_record_mac, _}}} = accept(ctx, [])
  end

  # A fast sender must be throttled by the server's buffer, never fail it.
  test "a slow reader backpressures a large upload without enobufs", ctx do
    payload = :crypto.strong_rand_bytes(8 * 1_048_576)

    client =
      client(ctx.port, [], fn c ->
        :ok = :ssl.send(c, payload)
        :ok
      end)

    {:ok, tcp} = :gen_tcp.accept(ctx.listen, 5000)
    # Large carrier reads make one TCP delivery overshoot the rearm reserve.
    :ok = :inet.setopts(tcp, buffer: 1_048_576, recbuf: 1_048_576)
    {:ok, s} = ServerConnection.start(tcp, config([]), self())
    {:ok, s} = ServerConnection.handshake(s, 5000)
    # Let the client run ahead so the server buffer reaches its cap.
    Process.sleep(300)
    received = slow_read(s, byte_size(payload), 0, [])
    assert byte_size(received) == byte_size(payload)
    assert received == payload
    assert finish(client) == :ok
    SSL.close(s)
  end

  defp slow_read(_s, remaining, _count, acc) when remaining <= 0,
    do: IO.iodata_to_binary(Enum.reverse(acc))

  defp slow_read(s, remaining, count, acc) do
    if rem(count, 256) == 0, do: Process.sleep(20)
    # Mix small reads with one near-cap read that must wait on the full buffer.
    length = if count == 512, do: min(remaining, 1_000_000), else: min(remaining, 4096)
    {:ok, bytes} = SSL.recv(s, length, 5000)
    slow_read(s, remaining - byte_size(bytes), count + 1, [bytes | acc])
  end

  # The first client flight up to and including its first 0-RTT record.
  defp captured_first_flight(extra) do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)
    Task.start(fn -> :ssl.connect({127, 0, 0, 1}, port, client_options(extra), 2000) end)
    {:ok, tcp} = :gen_tcp.accept(listen, 5000)
    flight = capture(tcp, <<>>)
    :gen_tcp.close(tcp)
    :gen_tcp.close(listen)
    flight
  end

  defp capture(tcp, bytes) do
    if early_record?(bytes) do
      bytes
    else
      {:ok, more} = :gen_tcp.recv(tcp, 0, 2000)
      capture(tcp, bytes <> more)
    end
  end

  defp early_record?(<<23, 3, 3, length::16, _::binary-size(length), _::binary>>), do: true

  defp early_record?(<<_type, 3, _, length::16, _::binary-size(length), rest::binary>>),
    do: early_record?(rest)

  defp early_record?(_bytes), do: false

  defp bogus_record(length),
    do: <<23, 3, 3, length::16, :crypto.strong_rand_bytes(length)::binary>>

  # A resumption ticket that permits early data, issued by an OTP :ssl server.
  defp otp_early_data_ticket do
    {:ok, listen} =
      :ssl.listen(0, [
        :binary,
        active: false,
        versions: [:"tlsv1.3"],
        certfile: @cert,
        keyfile: @key,
        session_tickets: :stateless,
        early_data: :enabled,
        log_level: :none
      ])

    {:ok, {_, port}} = :ssl.sockname(listen)

    server =
      Task.async(fn ->
        {:ok, t} = :ssl.transport_accept(listen, 5000)
        {:ok, s} = :ssl.handshake(t, 5000)
        :ok = :ssl.send(s, "t")
        {:ok, _} = :ssl.recv(s, 0, 5000)
        :ssl.close(s)
      end)

    {:ok, c} =
      :ssl.connect({127, 0, 0, 1}, port, client_options(session_tickets: :manual), 5000)

    {:ok, "t"} = :ssl.recv(c, 0, 5000)
    ticket = receive do: ({:ssl, :session_ticket, ticket} -> ticket), after: (5000 -> flunk())
    :ok = :ssl.send(c, "done")
    Task.await(server)
    :ssl.close(c)
    :ssl.close(listen)
    ticket
  end

  defp await_server_buffer(s, size, attempts \\ 500)
  defp await_server_buffer(_s, _size, 0), do: flunk("server did not buffer plaintext")

  defp await_server_buffer(s, size, attempts) do
    case :sys.get_state(s.pid) do
      {_name, %{size: ^size}} ->
        :ok

      _ ->
        Process.sleep(2)
        await_server_buffer(s, size, attempts - 1)
    end
  end

  defp config(extra) do
    {:ok, config} = ServerOptions.build([certfile: @cert, keyfile: @key] ++ extra)
    config
  end

  defp accept(ctx, extra) do
    {:ok, tcp} = :gen_tcp.accept(ctx.listen, 5000)
    {:ok, s} = ServerConnection.start(tcp, config(extra), self())
    ServerConnection.handshake(s, 5000)
  end

  defp client_options(extra) do
    [
      :binary,
      active: false,
      versions: [:"tlsv1.3"],
      verify: :verify_peer,
      cacertfile: @ca,
      server_name_indication: ~c"localhost",
      log_level: :none
    ] ++ extra
  end

  # The client runs its script and keeps its socket open until told to finish.
  defp client(port, extra, script) do
    Task.async(fn ->
      {:ok, c} = :ssl.connect({127, 0, 0, 1}, port, client_options(extra), 5000)
      result = script.(c)
      receive do: (:finish -> result)
    end)
  end

  defp failing_client(port, extra) do
    Task.async(fn -> :ssl.connect({127, 0, 0, 1}, port, client_options(extra), 5000) end)
  end

  defp finish(task) do
    send(task.pid, :finish)
    Task.await(task)
  end

  # A relay that reports the first server-to-client bytes and appends `inject`
  # to the first client-to-server chunk (the ClientHello).
  defp proxy(server_port, inject \\ <<>>) do
    test = self()
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)

    pid =
      spawn_link(fn ->
        {:ok, front} = :gen_tcp.accept(listen, 5000)
        {:ok, back} = :gen_tcp.connect({127, 0, 0, 1}, server_port, [:binary, active: true])
        :ok = :inet.setopts(front, active: true)
        relay(test, front, back, <<>>, inject)
      end)

    on_exit(fn -> :gen_tcp.close(listen) end)
    %{pid: pid, port: port}
  end

  # Reports the first 43 server bytes: record header, handshake header and random.
  defp relay(test, front, back, seen, inject) do
    receive do
      {:tcp, ^front, bytes} ->
        _ = :gen_tcp.send(back, [bytes, inject])
        relay(test, front, back, seen, <<>>)

      {:tcp, ^back, bytes} ->
        seen = report(test, seen, bytes)
        _ = :gen_tcp.send(front, bytes)
        relay(test, front, back, seen, inject)

      {:tcp_closed, _} ->
        :gen_tcp.close(front)
        :gen_tcp.close(back)
    end
  end

  defp report(_test, :reported, _bytes), do: :reported

  defp report(test, seen, bytes) do
    case seen <> bytes do
      <<prefix::binary-43, _::binary>> ->
        send(test, {:server_bytes, self(), prefix})
        :reported

      partial ->
        partial
    end
  end
end

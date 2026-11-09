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

  # A byte-transparent relay that reports the first server-to-client bytes.
  defp proxy(server_port) do
    test = self()
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)

    pid =
      spawn_link(fn ->
        {:ok, front} = :gen_tcp.accept(listen, 5000)
        {:ok, back} = :gen_tcp.connect({127, 0, 0, 1}, server_port, [:binary, active: true])
        :ok = :inet.setopts(front, active: true)
        relay(test, front, back, <<>>)
      end)

    on_exit(fn -> :gen_tcp.close(listen) end)
    %{pid: pid, port: port}
  end

  # Reports the first 43 server bytes: record header, handshake header and random.
  defp relay(test, front, back, seen) do
    receive do
      {:tcp, ^front, bytes} ->
        :ok = :gen_tcp.send(back, bytes)
        relay(test, front, back, seen)

      {:tcp, ^back, bytes} ->
        seen = report(test, seen, bytes)
        :ok = :gen_tcp.send(front, bytes)
        relay(test, front, back, seen)

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

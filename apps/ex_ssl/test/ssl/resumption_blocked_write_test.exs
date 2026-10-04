defmodule SSL.ResumptionBlockedWriteTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer, OpenSSLPeer}

  @moduletag :integration
  @host {127, 0, 0, 1}

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "resumption-write-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    %{fixtures: ClientAuthFixtures.create(directory)}
  end

  for outcome <- [:close, :deadline] do
    test "#{outcome} settles a resumed write blocked by real TCP backpressure", %{
      fixtures: fixtures
    } do
      {:ok, peer} =
        OpenSSLPeer.start(
          certfile: fixtures.server.certificate,
          keyfile: fixtures.server.key,
          min_version: :tls13,
          max_version: :tls13,
          alpn: ["http/1.1"],
          max_connections: 2
        )

      {:ok, warm_proxy} = LocalTLSPeer.start_backpressure_proxy(peer.port, self())
      port = warm_proxy.port
      warm_ref = warm_proxy.ref

      try do
        assert {:ok, warm} = SSL.connect(@host, port, options(fixtures), 5_000)
        assert_receive {:backpressure_proxy, ^warm_ref, :ready}, 1_000
        assert {:ok, %{"resumed" => false}} = OpenSSLPeer.event(peer, "handshake", 5_000)
        assert :ok = SSL.send(warm, <<4::32, "ping">>)
        assert {:ok, <<4::32, "ping">>} = SSL.recv(warm, 8, 5_000)
        assert {:ok, %{"kind" => "exchange"}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        assert :ok = SSL.close(warm)
        LocalTLSPeer.stop_backpressure_proxy(warm_proxy)

        {:ok, proxy} = LocalTLSPeer.start_backpressure_proxy(peer.port, self(), port: port)
        proxy_ref = proxy.ref

        try do
          send_timeout = unquote(if outcome == :deadline, do: 1_500, else: :infinity)
          assert {:ok, socket} = SSL.connect(@host, port, options(fixtures, send_timeout), 5_000)
          assert_receive {:backpressure_proxy, ^proxy_ref, :ready}, 1_000
          assert {:ok, %{"resumed" => true}} = OpenSSLPeer.event(peer, "handshake", 5_000)
          assert :ok = LocalTLSPeer.pause_client_to_server(proxy, self())
          assert_receive {:backpressure_proxy, ^proxy_ref, :paused}, 1_000
          {:connected, state} = :sys.get_state(socket.pid)
          connection = Process.monitor(socket.pid)
          writer = Process.monitor(state.writer)
          sender = Task.async(fn -> SSL.send(socket, :binary.copy("x", 16 * 1_048_576)) end)
          assert_receive {:backpressure_proxy, ^proxy_ref, :held, _}, 5_000
          assert_writer_is_socket_blocked(socket, sender)
          {:connected, %{write: %{deadline: original_deadline}}} = :sys.get_state(socket.pid)
          assert :ok = SSL.setopts(socket, send_timeout: :infinity)

          assert {:connected, %{write: %{deadline: ^original_deadline}}} =
                   :sys.get_state(socket.pid)

          settle(unquote(outcome), socket, sender)

          assert_receive {:DOWN, ^connection, :process, _, :normal}, 1_000
          assert_receive {:DOWN, ^writer, :process, _, :killed}, 1_000
          assert Port.info(state.tcp) == nil
        after
          if Process.alive?(proxy.task.pid), do: LocalTLSPeer.stop_backpressure_proxy(proxy)
        end
      after
        if Process.alive?(warm_proxy.task.pid),
          do: LocalTLSPeer.stop_backpressure_proxy(warm_proxy)

        OpenSSLPeer.stop(peer)
      end
    end
  end

  defp options(f, send_timeout \\ nil),
    do:
      [
        cacerts: [f.ca.der],
        server_name_indication: ~c"exssl.test",
        versions: [:"tlsv1.3"],
        alpn_advertised_protocols: ["http/1.1"],
        session_tickets: :auto
      ]
      |> then(fn options ->
        if(send_timeout, do: Keyword.put(options, :send_timeout, send_timeout), else: options)
      end)

  defp settle(:close, socket, sender) do
    assert :ok = SSL.close(socket)
    assert {:error, :closed} = Task.await(sender, 1_000)
  end

  defp settle(:deadline, _socket, sender),
    do: assert({:error, :timeout} = Task.await(sender, 2_000))

  defp assert_writer_is_socket_blocked(socket, sender) do
    deadline = System.monotonic_time(:millisecond) + 5_000
    wait_for_socket_block(socket, sender, deadline)
  end

  defp wait_for_socket_block(socket, sender, deadline) do
    case :sys.get_state(socket.pid) do
      {:connected, %{output: %{kind: :application}, tcp: tcp}} ->
        if Task.yield(sender, 0) == nil and send_pend(tcp) > 0,
          do: :ok,
          else: retry_socket_block(socket, sender, deadline)

      _ ->
        retry_socket_block(socket, sender, deadline)
    end
  end

  defp retry_socket_block(socket, sender, deadline) do
    if System.monotonic_time(:millisecond) < deadline do
      Process.sleep(1)
      wait_for_socket_block(socket, sender, deadline)
    else
      flunk("resumed writer did not become socket-blocked")
    end
  end

  defp send_pend(tcp) do
    case :inet.getstat(tcp, [:send_pend]) do
      {:ok, stats} -> Keyword.fetch!(stats, :send_pend)
      {:error, _} -> 0
    end
  end
end

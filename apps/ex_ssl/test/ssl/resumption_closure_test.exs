defmodule SSL.ResumptionClosureTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, OpenSSLPeer}
  @moduletag :integration

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "resumed-close-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    %{fixtures: ClientAuthFixtures.create(directory)}
  end

  for {abrupt, terminal} <- [{false, :closed}, {true, :econnreset}],
      mode <- [:passive, :once] do
    test "full and resumed #{mode} preserve bytes before #{terminal}", %{fixtures: fixtures} do
      peer = peer(fixtures, abrupt_close: unquote(abrupt))

      for resumed <- [false, true] do
        socket = connect(peer, fixtures, resumed)
        monitor = Process.monitor(socket.pid)
        assert :ok = SSL.send(socket, <<4::32, "ping">>)
        assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)

        if unquote(mode) == :passive do
          assert {:ok, <<0, 0, 0>>} = SSL.recv(socket, 3, 5_000)
          assert {:ok, <<4, "ping">>} = SSL.recv(socket, 5, 5_000)
          if unquote(abrupt), do: release_abrupt_close(peer)
          assert {:error, unquote(terminal)} = SSL.recv(socket, 0, 5_000)
        else
          assert :ok = SSL.setopts(socket, active: :once)
          assert_receive {:ssl, ^socket, <<4::32, "ping">>}, 5_000

          if unquote(abrupt) do
            assert :ok = SSL.setopts(socket, active: :once)
            release_abrupt_close(peer)
            assert_receive {:ssl_error, ^socket, :econnreset}, 5_000
          else
            assert_receive {:ssl_closed, ^socket}, 5_000
          end
        end

        assert_receive {:DOWN, ^monitor, :process, _, _}, 5_000
        assert {:error, unquote(terminal)} = SSL.recv(socket, 0, 0)
        assert :ok = SSL.close(socket)
        refute_receive {:ssl, ^socket, _}, 0
        refute_receive {:ssl_error, ^socket, _}, 0
        refute_receive {:ssl_closed, ^socket}, 0
      end
    end
  end

  test "cancelled receive on resumed connection leaves later plaintext available", %{fixtures: f} do
    peer = peer(f, [])
    first = connect(peer, f, false)
    assert :ok = SSL.send(first, <<4::32, "warm">>)
    assert {:ok, <<4::32, "warm">>} = SSL.recv(first, 8, 5_000)
    assert {:ok, _} = OpenSSLPeer.event(peer, "exchange", 5_000)
    assert :ok = SSL.close(first)

    socket = connect(peer, f, true)
    receiver = spawn(fn -> SSL.recv(socket, 8, :infinity) end)
    on_exit(fn -> if Process.alive?(receiver), do: Process.exit(receiver, :kill) end)
    wait_receiver(socket, true, System.monotonic_time(:millisecond) + 5_000)
    monitor = Process.monitor(receiver)
    Process.exit(receiver, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^receiver, :killed}, 5_000
    wait_receiver(socket, false, System.monotonic_time(:millisecond) + 5_000)

    assert :ok = SSL.send(socket, <<4::32, "kept">>)
    assert {:ok, <<4::32, "kept">>} = SSL.recv(socket, 8, 5_000)
    assert {:ok, _} = OpenSSLPeer.event(peer, "exchange", 5_000)
    assert :ok = SSL.close(socket)
  end

  defp peer(fixtures, extra) do
    {:ok, peer} =
      OpenSSLPeer.start(
        Keyword.merge(
          [
            certfile: fixtures.server.certificate,
            keyfile: fixtures.server.key,
            min_version: :tls13,
            max_version: :tls13,
            max_connections: 2
          ],
          extra
        )
      )

    on_exit(fn -> OpenSSLPeer.stop(peer) end)
    peer
  end

  defp connect(peer, f, resumed) do
    assert {:ok, socket} =
             SSL.connect({127, 0, 0, 1}, peer.port,
               cacerts: [f.ca.der],
               server_name_indication: ~c"exssl.test",
               session_tickets: :auto
             )

    assert {:ok, %{"resumed" => ^resumed}} = OpenSSLPeer.event(peer, "handshake", 5_000)

    assert {:ok, [session_resumption: ^resumed]} =
             SSL.connection_information(socket, [:session_resumption])

    socket
  end

  defp wait_receiver(socket, expected, deadline) do
    {:connected, state} = :sys.get_state(socket.pid)

    if state.recv != nil != expected do
      assert System.monotonic_time(:millisecond) < deadline
      wait_receiver(socket, expected, deadline)
    end
  end

  defp release_abrupt_close(peer) do
    assert {:ok, %{"kind" => "close_ready"}} = OpenSSLPeer.event(peer, "close_ready", 5_000)
    assert Port.command(peer.handle, "close\n")
  end
end

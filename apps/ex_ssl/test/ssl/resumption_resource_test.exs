defmodule SSL.ResumptionResourceTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, OpenSSLPeer}
  alias SSL.TicketCache

  @moduletag :integration
  @host {127, 0, 0, 1}

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "resumption-resource-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "repeated resumed, failed-identity, and owner-death connections release resources", %{
    fixtures: fixtures
  } do
    assert {:ok, _} = Application.ensure_all_started(:ex_ssl)
    baseline_ports = :erlang.system_info(:port_count)
    baseline_children = active_connections()

    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: fixtures.server.certificate,
        keyfile: fixtures.server.key,
        min_version: :tls13,
        max_version: :tls13,
        alpn: ["http/1.1"],
        max_connections: 17
      )

    try do
      for index <- 1..12 do
        success(peer, fixtures, index > 1, baseline_children)

        if rem(index, 4) == 0 do
          failed_identity(peer, fixtures, baseline_children)
        end
      end

      for _ <- 1..2 do
        owner_death(peer, fixtures, true, baseline_children)
      end

      assert %{count: count, bytes: bytes} = TicketCache.stats()
      assert count <= 128
      assert bytes <= 4_194_304
      assert active_connections() == baseline_children
    after
      OpenSSLPeer.stop(peer)
    end

    assert active_connections() == baseline_children
    assert :erlang.system_info(:port_count) <= baseline_ports + 1
  end

  test "three simultaneous eight-connection bursts release every TLS process and socket", %{
    fixtures: fixtures
  } do
    assert {:ok, _} = Application.ensure_all_started(:ex_ssl)
    baseline_children = active_connections()
    baseline_ports = :erlang.system_info(:port_count)

    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: fixtures.server.certificate,
        keyfile: fixtures.server.key,
        min_version: :tls13,
        max_version: :tls13,
        alpn: ["http/1.1"],
        max_connections: 25
      )

    try do
      success(peer, fixtures, false, baseline_children)

      for _batch <- 1..3 do
        parent = self()

        tasks =
          for _ <- 1..8 do
            Task.async(fn ->
              send(parent, {:burst_ready, self()})

              receive do
                :go -> burst_exchange(peer.port, fixtures)
              end
            end)
          end

        for %{pid: pid} <- tasks do
          assert_receive {:burst_ready, ^pid}, 5_000
        end

        Enum.each(tasks, &send(&1.pid, :go))
        Enum.each(tasks, &assert(:ok == Task.await(&1, 15_000)))

        for _ <- 1..8 do
          assert {:ok, %{"kind" => "handshake", "version" => "TLSv1.3"}} =
                   OpenSSLPeer.event(peer, "handshake", 5_000)

          assert {:ok, %{"kind" => "exchange", "bytes" => 4}} =
                   OpenSSLPeer.event(peer, "exchange", 5_000)
        end

        assert active_connections() == baseline_children
        assert %{count: count, bytes: bytes} = TicketCache.stats()
        assert count <= 128
        assert bytes <= 4_194_304
      end
    after
      OpenSSLPeer.stop(peer)
    end

    assert active_connections() == baseline_children
    assert :erlang.system_info(:port_count) <= baseline_ports + 1
  end

  defp burst_exchange(port, fixtures) do
    assert {:ok, socket} = SSL.connect(@host, port, options(fixtures), 10_000)
    state = connection_state(socket)
    assert_live_resources(state)
    connection_monitor = Process.monitor(socket.pid)
    writer_monitor = Process.monitor(state.writer)

    assert :ok = SSL.send(socket, <<4::32, "ping">>)
    assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 10_000)
    assert :ok = SSL.close(socket)
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert Port.info(state.tcp) == nil
    assert Process.info(socket.pid) == nil
    assert Process.info(state.writer) == nil
    :ok
  end

  defp success(peer, fixtures, resumed, baseline_children) do
    assert {:ok, socket} = SSL.connect(@host, peer.port, options(fixtures), 5_000)
    state = connection_state(socket)
    assert {:ok, %{"resumed" => ^resumed}} = OpenSSLPeer.event(peer, "handshake", 5_000)

    assert {:ok, [session_resumption: ^resumed]} =
             SSL.connection_information(socket, [:session_resumption])

    assert_live_resources(state)
    connection_monitor = Process.monitor(socket.pid)
    writer_monitor = Process.monitor(state.writer)

    assert :ok = SSL.send(socket, <<4::32, "ping">>)
    assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 5_000)
    assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
    assert :ok = SSL.close(socket)

    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert_released(state, baseline_children)
  end

  defp failed_identity(peer, fixtures, baseline_children) do
    before = connection_children()

    assert {:error, _} =
             SSL.connect(
               @host,
               peer.port,
               Keyword.put(options(fixtures), :server_name_indication, ~c"wrong.exssl.test"),
               5_000
             )

    assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5_000)

    # A connect error is replied before the connection's termination callback
    # has necessarily completed. Monitor any still-owned child rather than
    # treating the public reply as a process-exit barrier.
    for pid <- MapSet.difference(connection_children(), before) do
      monitor = Process.monitor(pid)
      assert_receive {:DOWN, ^monitor, :process, ^pid, reason}, 1_000
      assert reason in [:normal, :noproc]
    end

    assert active_connections() == baseline_children
  end

  defp owner_death(peer, fixtures, resumed, baseline_children) do
    parent = self()

    owner =
      spawn(fn ->
        result = SSL.connect(@host, peer.port, options(fixtures), 5_000)
        send(parent, {:owner_connected, self(), result})

        receive do
          :finish -> :ok
        end
      end)

    owner_monitor = Process.monitor(owner)
    assert_receive {:owner_connected, ^owner, {:ok, socket}}, 5_000

    assert {:ok, %{"kind" => "handshake", "resumed" => ^resumed}} =
             OpenSSLPeer.event(peer, "handshake", 5_000)

    state = connection_state(socket)
    assert_live_resources(state)
    connection_monitor = Process.monitor(socket.pid)
    writer_monitor = Process.monitor(state.writer)

    send(owner, :finish)
    assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 1_000
    assert_receive {:DOWN, ^connection_monitor, :process, _, :normal}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, _, :killed}, 1_000
    assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
    assert_released(state, baseline_children)
  end

  defp connection_state(socket) do
    assert {:connected, state} = :sys.get_state(socket.pid)
    state
  end

  defp assert_live_resources(state) do
    assert is_port(state.tcp)
    assert Port.info(state.tcp) != nil
    assert is_pid(state.writer)
    assert Process.alive?(state.writer)
    assert state.handshake_timer == nil
    assert state.recv == nil
    assert state.write == nil
    assert state.output == nil
    connection = resource_snapshot(state.socket.pid)
    assert connection.memory < 8_388_608
    assert connection.queue < 64
    assert connection.monitors <= 4
    assert connection.binaries < 4_194_304
    # The sensitive plain-process writer has no sys callback. Its aggregate
    # retained binaries/monitors are not externally observable; death below
    # proves those resources cannot outlive the owned connection.
    assert {:memory, writer_memory} = Process.info(state.writer, :memory)
    assert writer_memory < 4_194_304
  end

  # Sensitive processes hide binary/monitor information from other callers.
  # Measure inside the process and return only aggregate, non-secret counts.
  defp resource_snapshot(pid) do
    caller = self()
    token = make_ref()

    :sys.replace_state(pid, fn state ->
      info = Process.info(self(), [:memory, :message_queue_len, :monitors, :binary])

      send(
        caller,
        {token,
         %{
           memory: info[:memory],
           queue: info[:message_queue_len],
           monitors: length(info[:monitors]),
           binaries: Enum.reduce(info[:binary], 0, fn {_, size, _}, total -> total + size end)
         }}
      )

      state
    end)

    assert_receive {^token, snapshot}, 1_000
    snapshot
  end

  defp assert_released(state, baseline_children) do
    assert Port.info(state.tcp) == nil
    assert Process.info(state.socket.pid) == nil
    assert Process.info(state.writer) == nil
    assert active_connections() == baseline_children
  end

  defp active_connections do
    DynamicSupervisor.count_children(SSL.ConnectionSupervisor).active
  end

  defp connection_children do
    SSL.ConnectionSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.map(fn {_, pid, _, _} -> pid end)
    |> MapSet.new()
  end

  defp options(fixtures) do
    [
      verify: :verify_peer,
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      versions: [:"tlsv1.3"],
      alpn_advertised_protocols: ["http/1.1"],
      session_tickets: :auto
    ]
  end
end

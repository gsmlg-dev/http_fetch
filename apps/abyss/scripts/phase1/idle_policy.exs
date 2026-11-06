# Run from either QUIC example with `mix run --no-start ../../scripts/phase1/idle_policy.exs`.
# All traffic uses the released engine and loopback UDP; no engine state is injected.
root = System.get_env("ABYSS_PATH", Path.expand("../..", __DIR__))

provenance =
  case System.get_env("ABYSS_ENGINE_MODE") do
    "current" -> "current_provenance.exs"
    "candidate" -> "candidate_provenance.exs"
    _ -> "published_provenance.exs"
  end

Code.require_file(Path.join(__DIR__, provenance))

Application.put_env(
  :abyss,
  :idle_policy_fixture,
  Path.join(root, "test/fixtures/quic/server_flight")
)

{:ok, _} = Application.ensure_all_started(:abyss)
{:ok, _} = Application.ensure_all_started(:elixir_quic)
{:ok, _} = Application.ensure_all_started(:public_key)
ExUnit.start(autorun: false)

defmodule AbyssPhase1.IdleHandler do
  @behaviour Abyss.QUIC.Handler

  def init(connection, metadata, opts) do
    send(opts[:observer], {:idle_bound, connection, metadata})

    {:ok,
     %{
       connection: connection,
       observer: opts[:observer],
       interval: opts[:ping_interval],
       next_ping: System.monotonic_time(:millisecond)
     }}
  end

  def handle_event({:readable, stream}, state) do
    {:ok, items} = Abyss.QUIC.read(stream, 1024)

    for {:data, _, bytes} <- items do
      {:ok, _} = Abyss.QUIC.send_stream(stream, bytes)
    end

    {:ok, state}
  end

  def handle_event(:tick, state) do
    now = System.monotonic_time(:millisecond)

    state =
      if state.interval && now >= state.next_ping do
        {:ok, _} = Abyss.QUIC.ping(state.connection, timeout: 100, deadline: 100)
        %{state | next_ping: now + state.interval}
      else
        state
      end

    {:ok, state}
  end

  def handle_event(_, state), do: {:ok, state}
end

defmodule AbyssPhase1.IdlePolicyTest do
  use ExUnit.Case, async: false

  @streams [max_data: 16_384, max_stream_data: 4096, max_streams_bidi: 16]

  test "public host PING preserves admission references, deadlines and stale handle errors" do
    listener = listener(30_000)
    {connection, server, _} = connect(listener, 30_000)
    ref = make_ref()
    assert {:ok, ^ref} = Abyss.QUIC.ping(connection, ref: ref, timeout: 100, deadline: 100)
    assert {:ok, ^ref} = Abyss.QUIC.ping(connection, ref: ref, timeout: 100, deadline: 100)

    assert %{status: :admitted, result: {:ok, ^ref}} =
             Abyss.QUIC.operation_status(connection, ref)

    assert {:error, :deadline_expired} = Abyss.QUIC.ping(connection, deadline: 0)
    assert {:error, :stale_handle} = Abyss.QUIC.ping(%{connection | generation: make_ref()})
    roundtrip(connection, "ping-traffic")
    monitor = Process.monitor(server.id)
    assert :ok = Abyss.QUIC.close(connection)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 2000
    assert {:error, :closed} = Abyss.QUIC.ping(server)
  end

  test "real TLS admission advertises finite and disabled limits in both directions" do
    for {local, peer, negotiated} <- [
          {:infinity, :infinity, :infinity},
          {:infinity, 20_000, 20_000},
          {15_000, :infinity, 15_000},
          {20_000, 15_000, 15_000}
        ] do
      listener = listener(local)
      {connection, server, metadata} = connect(listener, peer)
      assert metadata.idle_timeout.local_ms == local
      assert metadata.idle_timeout.peer_ms == peer
      assert metadata.idle_timeout.negotiated_ms == negotiated
      assert {:ok, info} = Abyss.QUIC.info(server)
      assert info.idle_timeout == metadata.idle_timeout
      assert {:ok, client_info} = Quic.info(connection)
      assert client_info.idle_timeout.local_ms == peer
      assert client_info.idle_timeout.peer_ms == local
      assert client_info.idle_timeout.negotiated_ms == negotiated
      assert client_info.idle_timeout.effective_ms == negotiated
      roundtrip(connection, "negotiated")
    end
  end

  test "disabled quiet connections survive finite peer expiry before and after listener recreation" do
    spec = Supervisor.child_spec({Abyss.QUIC, options(:infinity)}, id: :idle_listener)
    {:ok, supervisor} = Supervisor.start_link([spec], strategy: :one_for_one)
    on_exit(fn -> stop(supervisor, &Supervisor.stop/1) end)
    [{:idle_listener, initial, _, _}] = Supervisor.which_children(supervisor)
    {old, old_server, _} = quiet_gate(initial)
    old_monitor = Process.monitor(old_server.id)
    assert :ok = Supervisor.terminate_child(supervisor, :idle_listener)
    assert_receive {:DOWN, ^old_monitor, :process, _, _}, 2000
    assert {:ok, recreated} = Supervisor.restart_child(supervisor, :idle_listener)
    assert recreated != initial
    {new, new_server, _} = quiet_gate(recreated)
    assert new_server.generation != old_server.generation
    assert new.generation != old.generation
  end

  test "caller-managed PING keeps a finite peer alive while a quiet finite peer expires" do
    listener = listener(:infinity, ping_interval: 25)
    {connection, server, _} = connect(listener, 200)
    quiet = listener(:infinity)
    {control, _quiet_server, _} = connect(quiet, 200)
    assert_receive {:quic_closed, ^control, :idle_timeout}, 5000
    assert {:ok, info} = Abyss.QUIC.info(server)
    assert info.idle_timeout.local_ms == :infinity
    assert info.idle_timeout.peer_ms == 200
    assert info.idle_timeout.negotiated_ms == 200
    assert info.idle_timeout.effective_ms >= 200
    roundtrip(connection, "after-peer-expiry")
  end

  test "finite local expiry and handshake bounds stay independent of disabled idle policy" do
    listener = listener(200)
    {connection, _server, metadata} = connect(listener, :infinity)
    assert metadata.idle_timeout.local_ms == 200
    assert metadata.idle_timeout.peer_ms == :infinity
    assert_receive {:quic_closed, ^connection, :idle_timeout}, 5000

    {:ok, blackhole} = :gen_udp.open(0, [:binary, {:ip, {127, 0, 0, 1}}, {:active, false}])
    on_exit(fn -> :gen_udp.close(blackhole) end)
    {:ok, remote} = :inet.sockname(blackhole)

    {:ok, client} =
      Quic.client(tls: client_tls(), idle_timeout: :infinity, handshake_timeout: 100)

    on_exit(fn -> stop(client, &GenServer.stop/1) end)
    {:ok, connection} = Quic.connect(client, remote)
    assert :ok = Quic.attach(connection, self())
    assert {:ok, {_, _, bytes}} = :gen_udp.recv(blackhole, 0, 1000)
    assert byte_size(bytes) >= 1200
    assert_receive {:quic_closed, ^connection, :handshake_timeout}, 2000
  end

  defp quiet_gate(listener) do
    {connection, server, metadata} = connect(listener, :infinity)
    {control, _finite, _} = connect(listener, 200)
    # An actual finite engine expiry supplies the quiet-period barrier.
    # A post-barrier echo proves the disabled connection still carries traffic.
    assert_receive {:quic_closed, ^control, :idle_timeout}, 5000
    assert {:ok, info} = Abyss.QUIC.info(server)
    assert info.idle_timeout.effective_ms == :infinity
    roundtrip(connection, "after-quiet-period")
    {connection, server, metadata}
  end

  defp listener(timeout, handler_opts \\ []) do
    {:ok, listener} = Abyss.QUIC.start_link(options(timeout, handler_opts))
    on_exit(fn -> stop(listener, &Abyss.QUIC.stop/1) end)
    listener
  end

  defp options(timeout, handler_opts \\ []) do
    [
      ip: {127, 0, 0, 1},
      handler: {AbyssPhase1.IdleHandler, [observer: self()] ++ handler_opts},
      alpn: ["abyss-idle-v1"],
      tls: server_tls(),
      quic_options: [
        idle_timeout: timeout,
        handshake_timeout: 1000,
        closing_timeout: 20,
        draining_timeout: 20,
        streams: @streams
      ]
    ]
  end

  defp connect(listener, timeout) do
    {:ok, client} =
      Quic.client(
        tls: client_tls(),
        idle_timeout: timeout,
        closing_timeout: 20,
        draining_timeout: 20,
        streams: @streams
      )

    on_exit(fn -> stop(client, &GenServer.stop/1) end)
    {:ok, remote} = Abyss.QUIC.local(listener)
    {:ok, connection} = Quic.connect(client, remote)
    assert :ok = Quic.attach(connection, self())
    assert_receive {:quic_ready, ^connection, _}, 2000
    assert_receive {:idle_bound, server, metadata}, 2000
    {connection, server, metadata}
  end

  defp roundtrip(connection, bytes) do
    assert {:ok, stream} = Quic.open_stream(connection, :bidi)
    assert {:ok, _} = Quic.send_stream(stream, bytes)

    assert read_until(stream, <<>>, byte_size(bytes), System.monotonic_time(:millisecond) + 2000) ==
             bytes
  end

  defp read_until(_stream, bytes, size, _deadline) when byte_size(bytes) >= size, do: bytes

  defp read_until(stream, bytes, size, deadline) do
    assert System.monotonic_time(:millisecond) < deadline, "echo deadline expired"
    assert {:ok, items} = Quic.read(stream, 1024)
    received = for {:data, _, part} <- items, into: <<>>, do: part

    if received == <<>> do
      receive do
        :poll -> :ok
      after
        5 -> :ok
      end
    end

    read_until(stream, bytes <> received, size, deadline)
  end

  defp server_tls do
    fixture = Application.fetch_env!(:abyss, :idle_policy_fixture)

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    [cert: [cert("leaf.pem")], key: {type, key}]
  end

  defp client_tls do
    [
      cacerts: [cert("root.pem")],
      reference_identity: {:dns_id, "example.test"},
      alpn: ["abyss-idle-v1"]
    ]
  end

  defp cert(name) do
    fixture = Application.fetch_env!(:abyss, :idle_policy_fixture)

    [{:Certificate, der, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, name)))

    der
  end

  defp stop(pid, fun) do
    monitor = Process.monitor(pid)

    try do
      if Process.alive?(pid), do: fun.(pid)
    catch
      :exit, reason ->
        # The linked owner may already be shutting the resource down. Accept a
        # concurrent stop only after observing that resource's actual DOWN.
        receive do
          {:DOWN, ^monitor, :process, ^pid, _} -> :ok
        after
          1000 -> exit(reason)
        end
    after
      Process.demonitor(monitor, [:flush])
    end
  end
end

result = ExUnit.run()
if result.failures > 0, do: System.halt(1)
IO.puts("QUIC_IDLE_POLICY_PASS")

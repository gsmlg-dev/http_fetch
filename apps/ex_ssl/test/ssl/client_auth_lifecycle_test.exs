defmodule SSL.ClientAuthLifecycleTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer, OpenSSLPeer}

  @moduletag :integration
  @timeout 5_000

  setup_all do
    directory =
      Path.join(
        System.tmp_dir!(),
        "exssl-client-auth-lifecycle-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  for version <- [:"tlsv1.3", :"tlsv1.2"] do
    test "#{version} original handshake deadline tears down a blocked large client certificate flight",
         %{fixtures: fixtures} do
      pending = pending_client_auth(fixtures, @timeout, unquote(version))

      try do
        assert {:error, :timeout} = Task.await(pending.connect, @timeout + 1_000)
        assert_connection_cleanup(pending)
        refute_receive :client_authenticated, 0
      after
        cleanup(pending)
      end
    end

    test "#{version} owner cancellation tears down a blocked large client certificate flight", %{
      fixtures: fixtures
    } do
      pending = pending_client_auth(fixtures, @timeout, unquote(version))

      try do
        assert Task.shutdown(pending.connect, :brutal_kill) == nil
        assert_connection_cleanup(pending)
        refute_receive :client_authenticated, 0
      after
        cleanup(pending)
      end
    end
  end

  defp pending_client_auth(fixtures, timeout, version) do
    assert byte_size(fixtures.large.der) > 16_384
    parent = self()
    before = connection_children()

    {:ok, peer} =
      if version == :"tlsv1.2" do
        OpenSSLPeer.start(
          certfile: fixtures.server.certificate,
          keyfile: fixtures.server.key,
          cafile: fixtures.ca.certificate,
          verify: :required
        )
      else
        LocalTLSPeer.start(
          fn _socket ->
            send(parent, :client_authenticated)
            :unexpected_client_authentication
          end,
          ssl_options: [
            certfile: String.to_charlist(fixtures.server.certificate),
            keyfile: String.to_charlist(fixtures.server.key),
            cacerts: [fixtures.ca.der],
            verify: :verify_peer,
            fail_if_no_peer_cert: true
          ]
        )
      end

    on_exit(fn -> emergency_stop_peer(peer) end)

    {:ok, proxy} = LocalTLSPeer.start_record_gate_proxy(peer.port, self(), initially_gated: true)
    on_exit(fn -> emergency_stop_proxy(proxy) end)

    proxy_ref = proxy.ref
    assert_receive {:tls_record_proxy, ^proxy_ref, :gated}, 1_000

    connect =
      Task.async(fn ->
        SSL.connect(~c"127.0.0.1", proxy.port, client_options(fixtures, version), timeout)
      end)

    assert_receive {:tls_record_proxy, ^proxy_ref, :queued, 1}, 1_000
    [connection] = MapSet.difference(connection_children(), before) |> MapSet.to_list()
    initial = wait_for_initial_handshake(connection)
    on_exit(fn -> stop_connection(connection, initial.writer) end)

    assert true = :erlang.suspend_process(initial.writer)

    assert :ok = LocalTLSPeer.release_server_record(proxy)
    output_size = await_client_auth_output(connection, proxy, proxy_ref)
    {:handshaking, state} = :sys.get_state(connection)
    assert %{size: size, timer: timer} = state.output
    assert state.output.kind == if(version == :"tlsv1.2", do: :handshake, else: :client_finished)
    assert size == output_size
    assert size > byte_size(fixtures.large.der)
    assert state.deadline == initial.deadline
    remaining = Process.read_timer(timer)
    assert is_integer(remaining)
    assert remaining <= SSL.Options.remaining(initial.deadline) + 1

    %{
      connection: connection,
      connection_monitor: Process.monitor(connection),
      writer: initial.writer,
      writer_monitor: Process.monitor(initial.writer),
      tcp: initial.tcp,
      handshake_timer: initial.handshake_timer,
      output_timer: timer,
      connect: connect,
      peer: peer,
      proxy: proxy
    }
  end

  defp wait_for_initial_handshake(connection, attempts \\ 100)
  defp wait_for_initial_handshake(_connection, 0), do: flunk("ClientHello output did not settle")

  defp wait_for_initial_handshake(connection, attempts) do
    case :sys.get_state(connection) do
      {:handshaking, %{output: nil} = state} ->
        state

      {:handshaking, %{output: %{kind: :handshake}}} ->
        Process.send_after(self(), {:initial_handshake_probe, connection}, 1)

        assert_receive {:initial_handshake_probe, ^connection}, 1_000
        wait_for_initial_handshake(connection, attempts - 1)
    end
  end

  defp await_client_auth_output(connection, proxy, proxy_ref, attempts \\ 64)

  defp await_client_auth_output(_connection, _proxy, _proxy_ref, 0),
    do: flunk("server flight did not reach the client authentication output")

  defp await_client_auth_output(connection, proxy, proxy_ref, attempts) do
    case :sys.get_state(connection) do
      {:handshaking, %{output: %{kind: :client_finished} = output}} ->
        output.size

      {:handshaking,
       %{
         output: %{kind: :handshake} = output,
         machine: %SSL.Protocol.TLS12{phase: :await_server_ccs}
       }} ->
        output.size

      _ ->
        await_server_flight_progress(connection, proxy, proxy_ref, attempts)
    end
  end

  defp await_server_flight_progress(connection, proxy, proxy_ref, attempts) do
    receive do
      {:tls_record_proxy, ^proxy_ref, :queued, _count} ->
        assert :ok = LocalTLSPeer.release_server_record(proxy)
        await_client_auth_output(connection, proxy, proxy_ref, attempts - 1)

      {:tls_record_proxy, ^proxy_ref, event, _value} when event in [:record, :released] ->
        await_client_auth_output(connection, proxy, proxy_ref, attempts - 1)
    after
      10 -> await_client_auth_output(connection, proxy, proxy_ref, attempts - 1)
    end
  end

  defp assert_connection_cleanup(pending) do
    %{
      connection: connection,
      connection_monitor: connection_monitor,
      writer: writer,
      writer_monitor: writer_monitor
    } =
      pending

    assert_receive {:DOWN, ^connection_monitor, :process, ^connection, :normal}, 1_000
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, :killed}, 1_000
    assert Port.info(pending.tcp) == nil
    assert Process.read_timer(pending.handshake_timer) == false
    assert Process.read_timer(pending.output_timer) == false
  end

  defp cleanup(pending) do
    stop_connection(pending.connection, pending.writer)
    stop_proxy(pending.proxy)
    stop_peer(pending.peer)
  end

  defp stop_connection(connection, writer) do
    if Process.alive?(writer), do: :erlang.resume_process(writer)
    if Process.alive?(connection), do: Process.exit(connection, :kill)
  end

  defp stop_proxy(proxy) do
    _ = LocalTLSPeer.stop_record_gate_proxy(proxy)
    :ok
  end

  defp stop_peer(%{handle: _} = peer), do: OpenSSLPeer.stop(peer)

  defp stop_peer(peer) do
    _ = :ssl.close(peer.listener)

    if Process.alive?(peer.task.pid) do
      _ = Task.shutdown(peer.task, 1_000)
    end

    :ok
  end

  defp emergency_stop_proxy(proxy) do
    _ = :gen_tcp.close(proxy.listener)
    if Process.alive?(proxy.controller), do: Process.exit(proxy.controller, :kill)
    if Process.alive?(proxy.task.pid), do: Process.exit(proxy.task.pid, :kill)
  end

  defp emergency_stop_peer(%{handle: _} = peer), do: OpenSSLPeer.stop(peer)

  defp emergency_stop_peer(peer) do
    _ = :ssl.close(peer.listener)
    if Process.alive?(peer.task.pid), do: Process.exit(peer.task.pid, :kill)
  end

  defp client_options(fixtures, version) do
    [
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      active: false,
      mode: :binary,
      verify: :verify_peer,
      versions: [version],
      certfile: fixtures.large.certificate,
      keyfile: fixtures.large.key
    ]
  end

  defp connection_children do
    SSL.ConnectionSupervisor
    |> DynamicSupervisor.which_children()
    |> Enum.map(fn {_, pid, _, _} -> pid end)
    |> MapSet.new()
  end
end

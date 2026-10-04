defmodule Quic.EndpointTest do
  use ExUnit.Case, async: true
  alias Quic.{Endpoint, Connection}

  defmodule RecordedTLS do
    def new(:client, _), do: {:ok, :client, [{:emit, :initial, <<1, 2>>}]}
    def new(:server, _), do: {:ok, :server, []}
    def info(_), do: %{receive_level: :initial}
    def feed(:server, :initial, <<1, 2>>), do: {:ok, :done, [{:emit, :initial, <<3, 4>>}]}
    def feed(:client, :initial, <<3, 4>>), do: {:ok, :done, []}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defmodule LossProxy do
    use GenServer
    def start_link(server, kind), do: GenServer.start_link(__MODULE__, {server, kind})

    def init({server, kind}) do
      {:ok, socket} = :gen_udp.open(0, [:binary, {:ip, {127, 0, 0, 1}}, {:active, :once}])
      {:ok, %{socket: socket, server: server, client: nil, kind: kind, dropped: false}}
    end

    def handle_call(:local, _, state) do
      {:ok, address} = :inet.sockname(state.socket)
      {:reply, address, state}
    end

    def handle_call(:dropped, _, state), do: {:reply, state.dropped, state}

    def handle_info({:udp, socket, ip, port, bytes}, state) do
      from_server = {ip, port} == state.server
      state = if from_server, do: state, else: %{state | client: {ip, port}}
      target = if from_server, do: state.client, else: state.server
      first = :binary.at(bytes, 0)

      drop =
        not state.dropped and
          ((state.kind == :initial and not from_server and Bitwise.band(first, 0xF0) == 0xC0) or
             (state.kind == :handshake and from_server and Bitwise.band(first, 0xF0) == 0xE0))

      if not drop and target, do: :gen_udp.send(socket, elem(target, 0), elem(target, 1), bytes)
      :inet.setopts(socket, active: :once)
      {:noreply, %{state | dropped: state.dropped or drop}}
    end

    def terminate(_, state), do: :gen_udp.close(state.socket)
  end

  test "shared socket admits persistent CID-routed connections and survives one closing" do
    {:ok, server} =
      Endpoint.start_link(
        role: :server,
        closing_timeout: 40,
        draining_timeout: 40,
        tls: [adapter: RecordedTLS]
      )

    {:ok, first} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        closing_timeout: 40,
        draining_timeout: 40,
        tls: [adapter: RecordedTLS]
      )

    {:ok, second} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        closing_timeout: 40,
        draining_timeout: 40,
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> Enum.each([first, second, server], &stop/1) end)
    assert eventually(fn -> length(Endpoint.connections(server)) == 2 end)

    assert eventually(fn ->
             [connection] = Endpoint.connections(first)
             Connection.status(connection.pid).bytes_received > 0
           end)

    [one, two] = Endpoint.connections(server)
    assert one.pid != two.pid
    :ok = Connection.close(one.pid)
    assert eventually(fn -> length(Endpoint.connections(server)) == 1 end)
    assert Process.alive?(two.pid)
    assert Process.alive?(server)
  end

  test "admission limit bounds connections and handshake timeout reclaims routes" do
    {:ok, server} =
      Endpoint.start_link(
        role: :server,
        max_connections: 1,
        handshake_timeout: 300,
        tls: [adapter: RecordedTLS]
      )

    {:ok, first} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> Enum.each([first, server], &stop/1) end)
    assert eventually(fn -> length(Endpoint.connections(server)) == 1 end)

    {:ok, second} =
      Endpoint.start_link(
        role: :client,
        remote: Endpoint.local(server),
        tls: [adapter: RecordedTLS]
      )

    on_exit(fn -> stop(second) end)
    assert eventually(fn -> Endpoint.stats(server).admission_drops == 1 end)
    assert length(Endpoint.connections(server)) == 1
    assert eventually(fn -> Endpoint.connections(server) == [] end)
    assert Endpoint.stats(server).routes == 0
  end

  test "late Initial for a closing CID is routed to the draining connection" do
    {:ok, server} =
      Endpoint.start_link(
        role: :server,
        closing_timeout: 40,
        draining_timeout: 40,
        tls: [adapter: RecordedTLS]
      )

    {:ok, sender} = :gen_udp.open(0, [:binary, {:ip, {127, 0, 0, 1}}])

    on_exit(fn ->
      :gen_udp.close(sender)
      stop(server)
    end)

    server_address = Endpoint.local(server)
    server_cid = <<1, 2, 3, 4, 5, 6, 7, 8>>

    {:ok, _client_scheduler, [initial]} =
      Quic.HandshakeScheduler.new(:client,
        dcid: server_cid,
        scid: <<9, 10, 11, 12, 13, 14, 15, 16>>,
        adapter: RecordedTLS
      )

    {ip, port} = server_address
    :ok = :gen_udp.send(sender, ip, port, initial.bytes)
    assert eventually(fn -> length(Endpoint.connections(server)) == 1 end)
    [entry] = Endpoint.connections(server)

    :ok = Connection.close(entry.pid)
    assert eventually(fn -> Connection.status(entry.pid).phase == :closing end)
    :ok = :gen_udp.send(sender, ip, port, initial.bytes)
    Process.sleep(50)
    assert length(Endpoint.connections(server)) == 1

    assert eventually(fn -> Endpoint.connections(server) == [] end)
  end

  test "replayed Initial for a retired CID cannot recreate a connection" do
    {:ok, server} =
      Endpoint.start_link(
        role: :server,
        closing_timeout: 40,
        draining_timeout: 40,
        tls: [adapter: RecordedTLS]
      )

    {:ok, sender} = :gen_udp.open(0, [:binary, {:ip, {127, 0, 0, 1}}])

    on_exit(fn ->
      :gen_udp.close(sender)
      stop(server)
    end)

    {ip, port} = Endpoint.local(server)
    dcid = <<21, 22, 23, 24, 25, 26, 27, 28>>

    {:ok, _scheduler, [initial]} =
      Quic.HandshakeScheduler.new(:client,
        dcid: dcid,
        scid: <<31, 32, 33, 34, 35, 36, 37, 38>>,
        adapter: RecordedTLS
      )

    :ok = :gen_udp.send(sender, ip, port, initial.bytes)
    assert eventually(fn -> length(Endpoint.connections(server)) == 1 end)
    [%{pid: pid}] = Endpoint.connections(server)
    :ok = Connection.close(pid)
    assert eventually(fn -> Endpoint.connections(server) == [] end)

    :ok = :gen_udp.send(sender, ip, port, initial.bytes)
    Process.sleep(50)
    assert Endpoint.connections(server) == []
    assert Endpoint.stats(server).routes == 0
  end

  test "real certificate handshake crosses UDP in both roles" do
    {server_tls, client_tls} = certificate_options()
    {:ok, server} = Endpoint.start_link(role: :server, handshake_timeout: 2_000, tls: server_tls)

    {:ok, client} =
      Endpoint.start_link(
        role: :client,
        handshake_timeout: 2_000,
        remote: Endpoint.local(server),
        tls: client_tls
      )

    on_exit(fn -> Enum.each([client, server], &stop/1) end)

    passed =
      eventually(fn ->
        case {Endpoint.connections(client), Endpoint.connections(server)} do
          {[c], [s]} ->
            Connection.status(c.pid).phase == :established and
              Connection.status(s.pid).phase == :established and
              Map.get(Connection.status(c.pid), :quic_confirmed, false)

          _ ->
            false
        end
      end)

    assert passed,
           inspect(%{
             client: Endpoint.stats(client),
             server: Endpoint.stats(server),
             clients: Enum.map(Endpoint.connections(client), &Connection.status(&1.pid)),
             servers: Enum.map(Endpoint.connections(server), &Connection.status(&1.pid))
           })

    [c] = Endpoint.connections(client)
    [s] = Endpoint.connections(server)
    assert Connection.status(c.pid).parameters_valid
    assert Connection.status(s.pid).parameters_valid
    assert Connection.status(c.pid).peer_authenticated
    refute Connection.status(s.pid).peer_authenticated
    assert Connection.status(s.pid).address_validated
    Process.sleep(2_100)
    assert Connection.status(c.pid).phase == :established
    assert Connection.status(s.pid).phase == :established

    for connection <- [c, s] do
      status = Connection.status(connection.pid)
      assert status.retired_levels == [:initial, :handshake]
      assert status.packets.initial == %{sent: 0, acked: 0, queued: 0, failed: 0}
      assert status.packets.handshake == %{sent: 0, acked: 0, queued: 0, failed: 0}
      {:established, data} = :sys.get_state(connection.pid)
      refute Map.has_key?(data.scheduler.keys, :initial)
      refute Map.has_key?(data.scheduler.keys, :handshake)
      assert data.scheduler.read_keys == %{}

      for level <- [:initial, :handshake] do
        assert data.scheduler.tls.levels[level].sent == []
        assert data.scheduler.tls.levels[level].pending == <<>>
        assert data.scheduler.tls.levels[level].recv.intervals == []
      end
    end

    assert Connection.status(s.pid).packets.application.acked >= 1
  end

  test "authenticated peer flow limits are installed in the live connection" do
    {server_tls, client_tls} = certificate_options()

    {:ok, server} =
      Endpoint.start_link(
        role: :server,
        tls: server_tls,
        streams: [max_data: 9, max_stream_data: 7, max_streams_bidi: 1, max_streams_uni: 0]
      )

    {:ok, client} =
      Endpoint.start_link(role: :client, remote: Endpoint.local(server), tls: client_tls)

    on_exit(fn -> Enum.each([client, server], &stop/1) end)

    assert eventually(fn ->
             case Endpoint.connections(client) do
               [c] -> Connection.status(c.pid).phase == :established
               _ -> false
             end
           end)

    [c] = Endpoint.connections(client)
    assert {:ok, 0} = Connection.open_stream(c.pid, :bidi)
    assert {:blocked, _} = Connection.open_stream(c.pid, :bidi)
    assert {:blocked, _} = Connection.open_stream(c.pid, :uni)
    assert {:blocked, _} = Connection.send_stream(c.pid, 0, "12345678")
    {:established, data} = :sys.get_state(c.pid)
    assert data.scheduler.streams.peer_max_data == 9
    assert data.scheduler.streams.streams[0].send_limit == 7
  end

  test "real UDP handshakes recover a dropped Initial and a dropped Handshake packet" do
    {server_tls, client_tls} = certificate_options()

    for kind <- [:initial, :handshake] do
      {:ok, server} = Endpoint.start_link(role: :server, tls: server_tls)
      {:ok, proxy} = LossProxy.start_link(Endpoint.local(server), kind)

      {:ok, client} =
        Endpoint.start_link(role: :client, remote: GenServer.call(proxy, :local), tls: client_tls)

      on_exit(fn -> Enum.each([client, proxy, server], &stop/1) end)

      passed =
        eventually(
          fn ->
            case {Endpoint.connections(client), Endpoint.connections(server)} do
              {[c], [s]} ->
                Connection.status(c.pid).quic_confirmed and
                  Connection.status(s.pid).quic_confirmed

              _ ->
                false
            end
          end,
          400
        )

      assert passed,
             inspect(%{
               dropped: kind,
               client: Endpoint.stats(client),
               server: Endpoint.stats(server)
             })

      assert GenServer.call(proxy, :dropped)
    end
  end

  test "wrong hostname and incompatible ALPN terminate with explicit TLS errors" do
    {server_tls, client_tls} = certificate_options()

    for {override, failing_role} <- [
          {[reference_identity: {:dns_id, "wrong.example.test"}], :client},
          {[alpn: ["incompatible"]], :server}
        ] do
      {:ok, server} = Endpoint.start_link(role: :server, tls: server_tls)

      {:ok, client} =
        Endpoint.start_link(
          role: :client,
          remote: Endpoint.local(server),
          tls: Keyword.merge(client_tls, override)
        )

      failed_endpoint = if failing_role == :client, do: client, else: server

      try do
        assert eventually(fn ->
                 match?({:tls, :tls, _, _}, Endpoint.stats(failed_endpoint).last_error)
               end)

        assert Endpoint.connections(failed_endpoint) == []
      after
        Enum.each([client, server], &stop/1)
      end
    end
  end

  test "server Retry validates the address and completes the certificate handshake" do
    {server_tls, client_tls} = certificate_options()
    {:ok, server} = Endpoint.start_link(role: :server, retry: true, tls: server_tls)

    {:ok, client} =
      Endpoint.start_link(role: :client, remote: Endpoint.local(server), tls: client_tls)

    on_exit(fn -> Enum.each([client, server], &stop/1) end)

    assert eventually(fn ->
             case {Endpoint.connections(client), Endpoint.connections(server)} do
               {[c], [s]} ->
                 Connection.status(c.pid).quic_confirmed and
                   Connection.status(s.pid).quic_confirmed

               _ ->
                 false
             end
           end)

    assert %{retry_sent: 1, retry_validated: 1} = Endpoint.stats(server)
    [s] = Endpoint.connections(server)
    assert Connection.status(s.pid).address_validated
    assert Connection.status(s.pid).parameters_valid
  end

  test "Retry admission allocates no connection before validation and bounds replies" do
    {:ok, server} =
      Endpoint.start_link(role: :server, retry: true, retry_limit: 1, tls: [adapter: RecordedTLS])

    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])
    {:ok, other} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])

    on_exit(fn ->
      stop(server)
      :gen_udp.close(socket)
      :gen_udp.close(other)
    end)

    {ip, port} = Endpoint.local(server)

    {:ok, scheduler, [initial]} =
      Quic.HandshakeScheduler.new(:client,
        dcid: <<1, 2, 3, 4, 5, 6, 7, 8>>,
        scid: <<8, 7, 6, 5, 4, 3, 2, 1>>,
        adapter: RecordedTLS
      )

    :ok = :gen_udp.send(socket, ip, port, initial.bytes)
    assert {:ok, {^ip, ^port, retry}} = :gen_udp.recv(socket, 0, 1_000)
    assert byte_size(retry) < 1200
    assert Endpoint.connections(server) == []
    assert %{routes: 0, retry_sent: 1, retry_validated: 0} = Endpoint.stats(server)

    :ok = :gen_udp.send(socket, ip, port, initial.bytes)
    assert eventually(fn -> Endpoint.stats(server).admission_drops == 1 end)
    assert {:error, :timeout} = :gen_udp.recv(socket, 0, 20)

    {:ok, _, [%{type: :retry, generated: [retried]}]} =
      Quic.HandshakeScheduler.receive_datagram(scheduler, retry, 0)

    :ok = :gen_udp.send(other, ip, port, retried.bytes)
    assert eventually(fn -> Endpoint.stats(server).admission_drops == 2 end)
    assert Endpoint.connections(server) == []
    assert {:error, :timeout} = :gen_udp.recv(other, 0, 20)

    :ok = :gen_udp.send(socket, ip, port, retried.bytes)
    assert eventually(fn -> Endpoint.stats(server).retry_validated == 1 end)
    [entry] = Endpoint.connections(server)
    assert Connection.status(entry.pid).address_validated
    :ok = :gen_udp.send(socket, ip, port, retried.bytes)
    assert {:ok, {^ip, ^port, _}} = :gen_udp.recv(socket, 0, 1_000)
    assert [^entry] = Endpoint.connections(server)
    assert %{retry_sent: 1, retry_validated: 1} = Endpoint.stats(server)
  end

  defp certificate_options do
    fixture = Path.expand("../fixtures/tls", __DIR__)

    der = fn name ->
      [{:Certificate, bytes, :not_encrypted}] =
        fixture |> Path.join(name) |> File.read!() |> :public_key.pem_decode()

      bytes
    end

    [{type, key, :not_encrypted}] =
      fixture |> Path.join("leaf-key.pem") |> File.read!() |> :public_key.pem_decode()

    {[cert: [der.("leaf.pem")], key: {type, key}, alpn: ["ex-quic-test"]],
     [
       cacerts: [der.("root.pem")],
       reference_identity: {:dns_id, "example.test"},
       alpn: ["ex-quic-test"]
     ]}
  end

  defp eventually(fun, attempts \\ 100)
  defp eventually(fun, 0), do: fun.()

  defp eventually(fun, attempts) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(10)
          eventually(fun, attempts - 1)
        )
  end

  defp stop(pid), do: if(Process.alive?(pid), do: GenServer.stop(pid))
end

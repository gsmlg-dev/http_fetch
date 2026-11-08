defmodule Quic.ClientMigrationRuntimeTest do
  use ExUnit.Case, async: true
  alias Quic.{Connection, HandshakeScheduler, PeerCIDs}
  alias Quic.IO.Endpoint

  defmodule RecordedTLS do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      actions =
        for {direction, value} <- [read: read, write: write],
            do: %SSL.QUIC.Secret{
              level: :application,
              direction: direction,
              cipher_suite: 0x1301,
              aead: :aes_128_gcm,
              hkdf: :sha256,
              secret: <<value::256>>
            }

      {:ok, nil, actions}
    end

    def info(_), do: %{receive_level: :application}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defmodule ClockedIO do
    def monotonic_time, do: Process.get(:migration_time, 0)

    def send(owner, bytes, remote) do
      send(owner, {:written, bytes, remote})
      {:ok, monotonic_time()}
    end
  end

  @old {{127, 0, 0, 1}, 4000}
  @new {{127, 0, 0, 2}, 4001}
  @remote {{127, 0, 0, 1}, 4433}

  defp runtime do
    Process.put(:migration_time, System.monotonic_time(:microsecond))
    opts = [dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, adapter: RecordedTLS]

    {:ok, :handshaking, data, _} =
      Connection.init(
        role: :client,
        owner: self(),
        io: {ClockedIO, self()},
        local: @old,
        remote: @remote,
        exclusive_io: true,
        scheduler: opts
      )

    {:ok, scheduler, []} = HandshakeScheduler.new(:client, opts)
    cids = PeerCIDs.new(opts[:dcid], 8)

    {:ok, cids, []} =
      PeerCIDs.receive_id(cids, %{
        sequence: 1,
        retire_prior_to: 0,
        cid: <<9, 10, 11, 12>>,
        token: <<1::128>>
      })

    scheduler = %{
      scheduler
      | peer_cids: cids,
        tls: %{
          scheduler.tls
          | facts: %{
              scheduler.tls.facts
              | tls_complete: true,
                peer_authenticated: true,
                quic_confirmed: true
            }
        }
    }

    %{data | scheduler: scheduler, ready: true, ready_notified: true}
  end

  defp migrate(data, ref, local \\ @new) do
    Connection.handle_event(
      {:call, {self(), make_ref()}},
      {:operation, data.generation, ref, System.monotonic_time(:millisecond) + 5000,
       {:migrate, local}},
      :established,
      data
    )
  end

  test "confirmed exclusive client reserves CID before binding; ref retry never binds twice" do
    data = runtime()
    ref = make_ref()
    assert {:keep_state, next, _} = migrate(data, ref)
    assert_receive {:quic_bind_path, _, generation, ^ref, 1, @new, _}
    assert generation == data.generation
    assert next.scheduler.peer_cids.bindings[1] == 1
    assert {:keep_state_and_data, [{:reply, _, {:ok, ^ref}}]} = migrate(next, ref)
    refute_receive {:quic_bind_path, _, _, _, _, _, _}, 0

    assert {:keep_state, rejected, [{:reply, _, {:error, :migration_busy}}]} =
             migrate(next, make_ref())

    assert rejected.paths.active == :default
  end

  test "new socket emits a 1200-byte probe without transferring old receive credit" do
    data = runtime()
    ref = make_ref()
    {:keep_state, next, _} = migrate(data, ref)

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               :info,
               {:quic_path_bound, data.generation, ref, 1, {:ok, self(), @new}},
               :established,
               next
             )

    assert_receive {:written, bytes, @remote}
    assert byte_size(bytes) == 1200
    assert Endpoint.path(next.budget, 1).bytes_received == 0
    assert Endpoint.path(next.budget, 1).bytes_sent == 1200
    assert next.paths.paths[1].local == @new
    assert next.paths.active == :default
  end

  test "bind rejection preserves old path and retained admission result" do
    data = runtime()
    ref = make_ref()
    {:keep_state, next, _} = migrate(data, ref)

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               :info,
               {:quic_path_bound, data.generation, ref, 1, {:error, {:bind_failed, :eaddrinuse}}},
               :established,
               next
             )

    assert next.paths.active == :default
    assert next.operations[ref].result == {:ok, ref}
    assert next.operations[ref].outcome == {:error, {:bind_failed, :eaddrinuse}}
    assert_receive {:quic_retire_local_path, _, _, 1}

    assert {:next_state, :established, settled, _} =
             Connection.handle_event(
               :info,
               {:quic_path_retired, data.generation, 1},
               :established,
               next
             )

    assert map_size(settled.paths.paths) == 1
    assert settled.local_migration == nil
  end

  test "policy and CID failures do not request a socket" do
    data = runtime()

    for {data, expected} <- [
          {%{data | exclusive_io: false}, :endpoint_not_exclusive},
          {%{data | role: :server}, :client_only},
          {%{
             data
             | scheduler: %{
                 data.scheduler
                 | tls: %{
                     data.scheduler.tls
                     | facts: %{data.scheduler.tls.facts | quic_confirmed: false}
                   }
               }
           }, :handshake_not_confirmed},
          {%{data | scheduler: %{data.scheduler | peer_disable_active_migration: true}},
           :peer_disabled_migration},
          {%{data | scheduler: %{data.scheduler | peer_cids: PeerCIDs.new(data.scheduler.dcid)}},
           :no_unused_connection_id}
        ] do
      assert {:keep_state, _, [{:reply, _, {:error, ^expected}}]} = migrate(data, make_ref())
      refute_receive {:quic_bind_path, _, _, _, _, _, _}, 0
    end
  end

  test "validation timeout retains a usable old writer and the original admission ref" do
    data = runtime()
    ref = make_ref()
    {:keep_state, next, _} = migrate(data, ref)

    {:next_state, :established, next, _} =
      Connection.handle_event(
        :info,
        {:quic_path_bound, data.generation, ref, 1, {:ok, self(), @new}},
        :established,
        next
      )

    assert_receive {:written, _, @remote}
    Process.put(:migration_time, next.paths.paths[1].deadline)

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               {:timeout, :path},
               {data.generation, 1},
               :established,
               next
             )

    assert next.paths.active == :default
    assert next.operations[ref].outcome == {:error, :validation_timeout}
    assert {:keep_state_and_data, [{:reply, _, {:ok, ^ref}}]} = migrate(next, ref)
    {:ok, scheduler, id} = HandshakeScheduler.open_stream(next.scheduler, :bidi)

    {:ok, scheduler, [effect]} =
      HandshakeScheduler.send_stream(scheduler, id, "old-still-usable", true)

    assert effect.path_id == :default
    assert scheduler.recovery.spaces.application.next > effect.packet_number
  end

  test "invalid local addresses never allocate a candidate socket" do
    data = runtime()

    for local <- [{{0, 0, 0, 0}, 0}, {{999, 0, 0, 1}, 0}, {{127, 0, 0, 1}, -1}, :bad] do
      assert {:keep_state, _, [{:reply, _, {:error, :invalid_local_address}}]} =
               migrate(data, make_ref(), local)
    end

    refute_receive {:quic_bind_path, _, _, _, _, _, _}, 0
  end

  test "late old-socket ingress is ignored after settlement and before native retirement" do
    data = runtime()
    ref = make_ref()
    {:keep_state, next, _} = migrate(data, ref)

    {:next_state, :established, next, _} =
      Connection.handle_event(
        :info,
        {:quic_path_bound, data.generation, ref, 1, {:ok, self(), @new}},
        :established,
        next
      )

    {:ok, peer, []} =
      HandshakeScheduler.new(:server,
        dcid: data.scheduler.scid,
        scid: data.scheduler.dcid,
        adapter: RecordedTLS
      )

    [challenge] = next.paths.paths[1].challenges

    {:ok, peer, [response]} =
      HandshakeScheduler.send_path_frames(
        peer,
        :default,
        [%{type: :path_response, data: challenge.value}],
        0
      )

    from = {self(), make_ref()}

    {:next_state, :established, next, _} =
      Connection.handle_event(
        {:call, from},
        {:datagram, next.generation, response.bytes, ClockedIO.monotonic_time(),
         %{local: @new, remote: @remote}},
        :established,
        next
      )

    assert next.paths.active == 1
    assert next.local_migration.phase == :retiring
    assert Map.has_key?(next.paths.paths, :default)
    assert Quic.Recovery.path(next.scheduler.recovery, :default) == nil
    assert Endpoint.path(next.budget, :default) == nil
    assert_receive {:quic_retire_local_path, _, _, :default}
    {:ok, _, [packet]} = HandshakeScheduler.ping(peer)

    assert {:keep_state_and_data, [{:reply, ^from, :ok}]} =
             Connection.handle_event(
               {:call, from},
               {:datagram, next.generation, packet.bytes, ClockedIO.monotonic_time(),
                %{local: @old, remote: @remote}},
               :established,
               next
             )

    assert {:next_state, :established, usable, _} =
             Connection.handle_event(
               {:call, from},
               {:datagram, next.generation, packet.bytes, ClockedIO.monotonic_time(),
                %{local: @new, remote: @remote}},
               :established,
               next
             )

    assert usable.scheduler.authenticated_packets > next.scheduler.authenticated_packets
    assert usable.paths.active == 1
  end

  test "queued ingress for a retired native socket never routes or returns receive credit" do
    {closed, monitor} = spawn_monitor(fn -> :ok end)
    assert_receive {:DOWN, ^monitor, :process, ^closed, :normal}
    generation = make_ref()

    data = %{
      cleanup: nil,
      ingress_local: @new,
      socket: self(),
      ios: %{
        :default => %{generation: generation, local: @old, socket: closed, retiring: true},
        1 => %{generation: make_ref(), local: @new, socket: self(), retiring: false}
      }
    }

    assert {:noreply, ^data} =
             Quic.Endpoint.handle_info(
               {:quic_udp, generation, make_ref(), @remote, <<0>>, 0},
               data
             )
  end
end

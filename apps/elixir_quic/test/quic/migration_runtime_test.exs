defmodule Quic.MigrationRuntimeTest do
  use ExUnit.Case, async: true
  alias Quic.{Connection, HandshakeScheduler, LocalCIDs, Paths, PeerCIDs, Recovery}
  alias Quic.IO.Endpoint

  @local {{127, 0, 0, 1}, 4433}
  @old {{127, 0, 0, 1}, 4000}
  @new {{127, 0, 0, 2}, 4001}

  test "public capabilities report accepted M1 server, M2 client migration and resumption" do
    assert Quic.capabilities().migration == %{peer: [:server], local: [:client]}
    assert Quic.capabilities().resumption
    refute Quic.capabilities().http3
  end

  defmodule ClockedIO do
    def monotonic_time, do: Process.get(:migration_time, 0)

    def send(owner, bytes, remote) do
      send(owner, {:written, bytes, remote})
      {:ok, monotonic_time()}
    end
  end

  defmodule RecordedTLS do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      secrets =
        for {direction, value} <- [read: read, write: write] do
          %SSL.QUIC.Secret{
            level: :application,
            direction: direction,
            cipher_suite: 0x1301,
            aead: :aes_128_gcm,
            hkdf: :sha256,
            secret: <<value::256>>
          }
        end

      {:ok, nil, secrets}
    end

    def info(_), do: %{receive_level: :application}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defp runtime do
    opts = [
      dcid: <<1, 2, 3, 4>>,
      scid: <<5, 6, 7, 8>>,
      adapter: RecordedTLS,
      max_datagram_frame_size: 1200
    ]

    {:ok, :handshaking, data, _} =
      Connection.init(
        role: :server,
        owner: self(),
        io: {ClockedIO, self()},
        local: @local,
        remote: @old,
        address_validated: true,
        scheduler: opts
      )

    {:ok, scheduler, []} = HandshakeScheduler.new(:server, opts)

    scheduler =
      HandshakeScheduler.install_peer_parameters(scheduler, %{
        initial_max_data: 10_000,
        initial_max_streams_bidi: 4,
        initial_max_stream_data_bidi_remote: 10_000,
        max_datagram_frame_size: 1200
      })

    scheduler = %{
      scheduler
      | tls: %{
          scheduler.tls
          | facts: %{
              scheduler.tls.facts
              | tls_complete: true,
                peer_authenticated: true,
                quic_confirmed: true
            }
        }
    }

    {:ok, peer, []} =
      HandshakeScheduler.new(
        :client,
        Keyword.merge(opts, dcid: opts[:scid], scid: opts[:dcid])
      )

    {%{data | scheduler: scheduler, ready: true, ready_notified: true}, peer}
  end

  defp inbound(data, packet, remote, at \\ 0) do
    Connection.handle_event(
      {:call, {self(), make_ref()}},
      {:datagram, data.generation, packet, at, %{local: @local, remote: remote}},
      :established,
      data
    )
  end

  defp ping(peer) do
    {:ok, peer, [packet]} = HandshakeScheduler.ping(peer)
    {peer, packet.bytes}
  end

  defp attempt(data) do
    {:ok, paths, 1, true} = Paths.observe(data.paths, @new, 0, false, 0, 1000)
    {:ok, recovery} = Recovery.add_path(data.scheduler.recovery, 1)
    {:ok, recovery} = Recovery.select_path(recovery, 1)

    {:ok, scheduler} =
      HandshakeScheduler.bind_path(%{data.scheduler | recovery: recovery}, 1, :default, true)

    {:ok, budget} = Endpoint.add_path(data.budget, 1, false)
    {:ok, budget} = Endpoint.select_path(budget, 1)

    %{
      data
      | paths: paths,
        remote: @new,
        budget: budget,
        scheduler: scheduler
    }
  end

  test "new validation deadline includes conservative new-path PTO after a warmed old path" do
    {data, peer} = runtime()
    recovery = data.scheduler.recovery
    recovery = %{recovery | rtt: %{recovery.rtt | smoothed: 1000, variance: 500}}
    data = %{data | scheduler: %{data.scheduler | recovery: recovery}}
    {:ok, prospective} = Recovery.add_path(recovery, 1)
    pto = max(Recovery.pto_duration(recovery), Recovery.pto_duration(prospective, 1))
    {_peer, bytes} = ping(peer)

    assert {:next_state, :established, next, _} = inbound(data, bytes, @new, 10)
    assert next.paths.paths[1].deadline == 10 + 3 * pto
    assert next.paths.paths[:default].deadline == next.paths.paths[1].deadline
  end

  test "changed incoming CID with no unused peer CID cannot create or select a new path" do
    {data, peer} = runtime()
    spare = <<9, 10, 11, 12>>
    {:ok, cids, _} = LocalCIDs.reserve(data.scheduler.local_cids, spare, <<1::128>>, :cid)
    {:ok, cids, _} = LocalCIDs.registered(cids, :cid)
    {:ok, cids} = LocalCIDs.published(cids, 1)
    data = %{data | scheduler: %{data.scheduler | local_cids: cids}}
    {_peer, bytes} = ping(%{peer | dcid: spare})
    assert {:keep_state_and_data, _} = inbound(data, bytes, @new)
    refute_receive {:written, _, _}, 0
    assert map_size(data.paths.paths) == 1
  end

  test "forged sources and preconfirmation traffic never allocate alternate paths" do
    {data, peer} = runtime()
    {_peer, bytes} = ping(peer)
    size = byte_size(bytes) - 1
    <<prefix::binary-size(size), last>> = bytes
    forged = prefix <> <<Bitwise.bxor(last, 1)>>
    assert {:keep_state_and_data, _} = inbound(data, forged, @new)
    assert map_size(data.paths.paths) == 1

    scheduler = %{
      data.scheduler
      | tls: %{data.scheduler.tls | facts: %{data.scheduler.tls.facts | quic_confirmed: false}}
    }

    assert {:keep_state_and_data, _} = inbound(%{data | scheduler: scheduler}, bytes, @new)
    refute_receive {:written, _, _}, 0
  end

  test "matching response on the old arrival path validates the challenge send path" do
    {data, peer} = runtime()
    data = attempt(data)
    {:ok, paths} = Paths.probe(data.paths, 1, <<77::64>>, true, 0, 1000)
    data = %{data | paths: paths}

    {:ok, _peer, [response]} =
      HandshakeScheduler.send_path_frames(
        peer,
        :default,
        [%{type: :path_response, data: <<77::64>>}],
        0
      )

    assert {:next_state, :established, next, _} = inbound(data, response.bytes, @old, 100)
    assert next.paths.active == 1
    assert next.paths.paths[1].validated
    assert next.paths.paths[1].mtu_validated
    assert Endpoint.path(next.budget, 1).address_validated
    assert Endpoint.path(next.budget, 1).bytes_received == 0
    assert Endpoint.path(next.budget, :default).bytes_received == byte_size(response.bytes)
  end

  test "new source credit remains independent and stale path timers have no effect" do
    {data, peer} = runtime()
    {_peer, bytes} = ping(peer)
    assert {:next_state, :established, next, _} = inbound(data, bytes, @new)
    ledger = Endpoint.path(next.budget, 1)
    assert ledger.bytes_received == byte_size(bytes)
    assert ledger.bytes_sent + ledger.bytes_pending <= 3 * byte_size(bytes)

    assert :keep_state_and_data =
             Connection.handle_event({:timeout, :path}, {make_ref(), 1}, :established, next)

    assert :keep_state_and_data =
             Connection.handle_event({:timeout, :path}, {next.generation, 2}, :established, next)

    assert {:keep_state_and_data, _} = inbound(next, bytes, {{127, 0, 0, 3}, 4002})
    assert map_size(next.paths.paths) == 2
  end

  test "unauthenticated malformed headers on a known path cannot close the connection" do
    {data, _peer} = runtime()
    malformed = <<0, data.scheduler.scid::binary, 0::160>>
    assert {:keep_state_and_data, _} = inbound(data, malformed, @old)
    data = attempt(data)
    assert {:keep_state_and_data, _} = inbound(data, malformed, @new)
    refute_receive {:written, _, _}, 0
  end

  test "amplification-blocked application output cannot starve validation on either path" do
    {data, _peer} = runtime()
    data = attempt(data)
    {:ok, budget} = Endpoint.receive_bytes(data.budget, 32, 1)
    {:ok, scheduler, id} = HandshakeScheduler.open_stream(data.scheduler, :bidi)

    {:ok, scheduler, pending} =
      HandshakeScheduler.send_stream(scheduler, id, :binary.copy(<<1>>, 1000), false)

    data = %{data | budget: budget, scheduler: scheduler, pending: pending}

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               {:timeout, :path},
               {data.generation, 1},
               :established,
               data
             )

    assert_receive {:written, _, @old}
    assert_receive {:written, _, @new}
    assert next.pending == pending
    ledger = Endpoint.path(next.budget, 1)
    assert ledger.bytes_sent <= 3 * ledger.bytes_received
  end

  test "congestion-blocked probing retains a Paths struct and finite retry" do
    {data, _peer} = runtime()
    data = attempt(data)
    recovery = data.scheduler.recovery
    recovery = %{recovery | congestion: %{recovery.congestion | cwnd: 0}}
    data = %{data | scheduler: %{data.scheduler | recovery: recovery}}

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               {:timeout, :path},
               {data.generation, 1},
               :established,
               data
             )

    assert %Paths{} = next.paths
    assert next.paths.paths[1].retry_at > 0
    assert next.paths.paths[1].retry_at <= next.paths.paths[1].deadline
  end

  test "probe padding includes ACKs generated by the same received packet" do
    {data, peer} = runtime()
    data = attempt(data)

    {:ok, _peer, [packet]} =
      HandshakeScheduler.send_path_frames(peer, :default, [%{type: :ping}], 400)

    assert {:next_state, :established, next, _} = inbound(data, packet.bytes, @new)
    assert next.pending == []
    assert [%{padded: false}] = next.paths.paths[1].challenges
    ledger = Endpoint.path(next.budget, 1)
    assert ledger.bytes_sent <= 3 * ledger.bytes_received
    assert_receive {:written, _, @new}
  end

  test "fallback cancels definitely unsent candidate packets and recovers STREAM without DATAGRAM" do
    {data, _peer} = runtime()
    data = attempt(data)
    {:ok, paths} = Paths.probe(data.paths, :default, <<1::64>>, true, 0, 1000)
    {:ok, paths, :default} = Paths.response(paths, <<1::64>>, 1)
    {:ok, scheduler, id} = HandshakeScheduler.open_stream(data.scheduler, :bidi)
    {:ok, scheduler, stream} = HandshakeScheduler.send_stream(scheduler, id, "preserved", true)
    {:ok, scheduler, datagram} = HandshakeScheduler.send_datagram(scheduler, "unreliable")
    data = %{data | paths: paths, scheduler: scheduler, pending: stream ++ datagram}
    [first | _] = data.pending
    assert Endpoint.path(data.budget, 1).bytes_received == 0
    Process.put(:migration_time, 3000)

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               {:timeout, :path},
               {data.generation, 1},
               :established,
               data
             )

    assert next.paths.active == :default
    assert map_size(next.paths.paths) == 1
    assert next.pending == []
    assert next.scheduler.queued == 0

    assert next.scheduler.recovery.spaces.application.next >
             scheduler.recovery.spaces.application.next

    assert next.scheduler.recovery.spaces.application.sent[first.packet_number].status == :failed
    assert Recovery.path(next.scheduler.recovery, 1) == nil
    assert Endpoint.path(next.budget, 1) == nil
    assert_receive {:written, _, @old}
    refute_receive {:written, _, @new}, 0

    frames =
      for {_, packet} <- next.scheduler.recovery.spaces.application.sent,
          packet.status == :sent,
          frame <- Map.get(packet.metadata, :control, []),
          do: frame

    assert %{type: :stream, stream_id: id, offset: 0, data: "preserved", fin: true} in frames
    refute Enum.any?(frames, &(&1.type in [:datagram, :path_challenge, :path_response]))
  end

  test "fallback with no usable outgoing CID has a finite terminal outcome" do
    {data, _peer} = runtime()
    data = attempt(data)
    {:ok, paths} = Paths.probe(data.paths, :default, <<1::64>>, true, 0, 1000)
    {:ok, paths, :default} = Paths.response(paths, <<1::64>>, 1)
    cids = PeerCIDs.new(<<1, 2, 3, 4>>)

    {:ok, cids, []} =
      PeerCIDs.receive_id(cids, %{
        sequence: 1,
        retire_prior_to: 0,
        cid: <<9, 8, 7, 6>>,
        token: <<1::128>>
      })

    {:ok, cids} = PeerCIDs.bind_path(cids, 1, :default, false)

    {:ok, cids, _retired} =
      PeerCIDs.receive_id(
        cids,
        %{
          sequence: 2,
          retire_prior_to: 2,
          cid: <<8, 7, 6, 5>>,
          token: <<2::128>>
        },
        1
      )

    assert PeerCIDs.current(cids, :default) == nil
    data = %{data | paths: paths, scheduler: %{data.scheduler | peer_cids: cids}}
    Process.put(:migration_time, 3000)

    assert {:stop, :normal, %{reason: {:migration, :no_validated_path}}} =
             Connection.handle_event({:timeout, :path}, {data.generation, 1}, :established, data)
  end
end

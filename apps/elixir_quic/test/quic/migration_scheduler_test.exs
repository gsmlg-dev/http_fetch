unless Process.whereis(ExUnit.Server), do: ExUnit.start()

defmodule Quic.MigrationSchedulerTest do
  use ExUnit.Case, async: true
  import Bitwise
  alias Quic.{Codec, HandshakeScheduler, LocalCIDs, PeerCIDs, Recovery, TLSDriver}

  defmodule Recorded do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      actions =
        for {direction, secret} <- [read: read, write: write] do
          %SSL.QUIC.Secret{
            level: :application,
            direction: direction,
            cipher_suite: 0x1301,
            aead: :aes_128_gcm,
            hkdf: :sha256,
            secret: <<secret::256>>
          }
        end

      {:ok, 0, actions}
    end

    def info(_), do: %{receive_level: :application}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defmodule RecordedCrypto do
    def new(role, opts) do
      {:ok, state, actions} = Recorded.new(role, opts)
      {:ok, state, actions ++ [{:emit, :application, "retained crypto"}]}
    end

    defdelegate info(state), to: Recorded
    defdelegate feed(state, level, bytes), to: Recorded
    defdelegate abort(state, reason), to: Recorded
  end

  defmodule StrictOptions do
    def new(role, opts) do
      if Keyword.has_key?(opts, :active_connection_id_limit),
        do: {:error, :unexpected_scheduler_option},
        else: Recorded.new(role, opts)
    end

    defdelegate info(state), to: Recorded
    defdelegate feed(state, level, bytes), to: Recorded
    defdelegate abort(state, reason), to: Recorded
  end

  defmodule RecordedHandshake do
    def new(role, opts) do
      {:ok, state, application} = Recorded.new(role, opts)
      handshake = Enum.map(application, &%{&1 | level: :handshake})
      {:ok, state, application ++ handshake ++ [{:emit, :handshake, "retained handshake"}]}
    end

    defdelegate info(state), to: Recorded
    defdelegate feed(state, level, bytes), to: Recorded
    defdelegate abort(state, reason), to: Recorded
  end

  defp new do
    {:ok, state, []} =
      HandshakeScheduler.new(:server,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: Recorded
      )

    state
  end

  test "local CID receive limit remains internal to the scheduler" do
    assert {:ok, state, []} =
             HandshakeScheduler.new(:server,
               dcid: <<1, 2, 3, 4>>,
               scid: <<5, 6, 7, 8>>,
               active_connection_id_limit: 8,
               adapter: StrictOptions
             )

    assert state.local_cid_limit == 8
  end

  test "path frames carry exactly eight bytes and retain following frames" do
    frames = [
      %{type: :path_challenge, data: <<1::64>>},
      %{type: :path_response, data: <<2::64>>},
      %{type: :ping}
    ]

    assert {:ok, <<0x1A, 1::64, 0x1B, 2::64, 1>>} = Codec.encode_frames(frames)
    assert {:ok, ^frames, <<>>} = Codec.decode_frames(<<0x1A, 1::64, 0x1B, 2::64, 1>>)

    for type <- [0x1A, 0x1B], size <- 0..7 do
      assert {:error, :malformed_path_frame} =
               Codec.decode_frames(<<type>> <> :binary.copy(<<0>>, size))
    end

    assert {:error, :unsupported_frame} =
             Codec.encode_frames([%{type: :path_challenge, data: <<1>>}])
  end

  test "path frame legality is restricted to application protection" do
    for type <- [:path_challenge, :path_response], level <- [:initial, :handshake] do
      assert {:wrong_encryption_level, ^type, ^level} =
               Codec.validate_frame_levels([%{type: type, data: <<0::64>>}], level)
    end
  end

  test "authenticated path facts preserve incoming DCID PN and probing classification" do
    state = new()
    packet = peer_packet(state, 0, <<0x1A, 1::64>>)
    assert {:ok, state, events} = HandshakeScheduler.receive_datagram(state, packet, 10, 1)

    assert %{
             type: :authenticated_packet,
             level: :application,
             number: 0,
             dcid: <<5, 6, 7, 8>>,
             path_id: 1,
             probing: true
           } in events

    assert %{type: :path_challenge, data: <<1::64>>} in events
    packet = peer_packet(state, 1, <<1, 0x1B, 2::64>>)
    assert {:ok, _state, events} = HandshakeScheduler.receive_datagram(state, packet, 11, 1)
    assert Enum.any?(events, &(&1.type == :authenticated_packet and not &1.probing))
  end

  test "probing classification covers padding path and CID combinations versus non-probing frames" do
    challenge = %{type: :path_challenge, data: <<1::64>>}
    response = %{type: :path_response, data: <<2::64>>}

    cid = %{
      type: :new_connection_id,
      sequence: 1,
      retire_prior_to: 0,
      cid: <<9, 8, 7, 6>>,
      token: <<1::128>>
    }

    ack = %{type: :ack, largest: 0, delay: 0, ranges: [{0, 0}]}
    ping = %{type: :ping}
    stream = %{type: :stream, stream_id: 0, offset: 0, data: "x", fin: false}

    vectors = [
      {[], true},
      {[challenge], true},
      {[response], true},
      {[cid], true},
      {[challenge, response, cid], true},
      {[ack], false},
      {[ping], false},
      {[stream], false},
      {[challenge, ack], false},
      {[response, ping, cid], false},
      {[challenge, response, stream], false}
    ]

    for {frames, probing} <- vectors do
      state = new()
      state = %{state | peer_cids: PeerCIDs.new(state.dcid, 8)}

      {:ok, state, [sent]} =
        HandshakeScheduler.send_path_frames(state, :default, [ping], 0)

      {:ok, state, [:sent]} =
        HandshakeScheduler.local_send(state, :application, sent.packet_number, :ok, 1)

      {:ok, plaintext} = Codec.encode_frames(frames)
      packet = peer_packet(state, 0, <<0, 0, plaintext::binary>>)
      assert {:ok, next, events} = HandshakeScheduler.receive_datagram(state, packet, 2, 1)
      assert next.authenticated_packets == 1

      assert %{probing: ^probing, path_id: 1, number: 0} =
               Enum.find(events, &(&1.type == :authenticated_packet))
    end
  end

  test "unknown and retired incoming CIDs cannot produce authenticated path facts" do
    state = new()
    unknown = peer_packet(state, 0, <<1>>, <<9, 9, 9, 9>>)

    assert {:error, :wrong_connection_id, unchanged} =
             HandshakeScheduler.receive_datagram(state, unknown, 1, 1)

    assert unchanged.authenticated_packets == 0
    assert unchanged.recovery.spaces.application.largest_received == -1
    {:ok, cids, _} = LocalCIDs.reserve(state.local_cids, <<9, 8, 7, 6>>, <<1::128>>, :cid)
    {:ok, cids, _} = LocalCIDs.registered(cids, :cid)
    {:ok, cids} = LocalCIDs.published(cids, 1)
    state = %{state | local_cids: cids}
    retire = peer_packet(state, 0, <<0x19, 0>>, <<9, 8, 7, 6>>)
    {:ok, state, _} = HandshakeScheduler.receive_datagram(state, retire, 2, :default)
    stale = peer_packet(state, 1, <<1>>)

    assert {:error, :wrong_connection_id, unchanged} =
             HandshakeScheduler.receive_datagram(state, stale, 3, 1)

    assert unchanged.authenticated_packets == state.authenticated_packets
    assert unchanged.recovery.spaces.application.largest_received == 0
  end

  test "path probe reservation pins its path and padding without redirecting normal scheduling" do
    state = new()
    {:ok, recovery} = Recovery.add_path(state.recovery, 1)
    state = %{state | recovery: recovery}

    assert {:ok, next, [effect]} =
             HandshakeScheduler.send_path_frames(
               state,
               1,
               [%{type: :path_challenge, data: <<1::64>>}],
               1200
             )

    assert byte_size(effect.bytes) == 1200
    assert effect.path_id == 1
    assert next.recovery.spaces.application.sent[effect.packet_number].metadata.path_id == 1
    assert Recovery.selected_path(next.recovery) == :default
  end

  test "new destination and retained old-path probes use their own outgoing CIDs" do
    state = new()
    {:ok, recovery} = Recovery.add_path(state.recovery, 1)
    cids = PeerCIDs.new(state.dcid, 8)
    {:ok, cids, []} = PeerCIDs.receive_id(cids, peer_cid(1, <<9, 8, 7, 6>>))
    state = %{state | recovery: recovery, peer_cids: cids}
    assert {:ok, state} = HandshakeScheduler.bind_path(state, 1, :default, false)
    {:ok, recovery} = Recovery.select_path(state.recovery, 1)
    state = %{state | recovery: recovery}
    {:ok, state, [normal]} = HandshakeScheduler.ping(state)
    assert binary_part(normal.bytes, 1, 4) == <<9, 8, 7, 6>>

    {:ok, state, [old_probe]} =
      HandshakeScheduler.send_path_frames(
        state,
        :default,
        [%{type: :path_response, data: <<1::64>>}],
        1200
      )

    assert binary_part(old_probe.bytes, 1, 4) == state.dcid
    assert byte_size(old_probe.bytes) == 1200

    {:ok, state, [new_probe]} =
      HandshakeScheduler.send_path_frames(state, 1, [%{type: :ping}], 0)

    assert binary_part(new_probe.bytes, 1, 4) == <<9, 8, 7, 6>>
    assert state.dcid == <<1, 2, 3, 4>>
  end

  test "synthetic initial CID binding permits NAT rebinding but fails closed without a spare" do
    state = new()

    assert {:error, :no_unused_connection_id} =
             HandshakeScheduler.bind_path(state, 1, :default, false)

    assert {:ok, state} = HandshakeScheduler.bind_path(state, 1, :default, true)
    assert PeerCIDs.current(state.peer_cids, 1) == state.dcid
    state = HandshakeScheduler.drop_path_binding(state, :default)
    assert map_size(state.peer_cids.bindings) == 1

    assert {:error, :no_unused_connection_id} =
             HandshakeScheduler.bind_path(state, 2, 1, false)
  end

  test "releasing an old path queues peer CID retirement before accepting a replacement" do
    state = new()
    cids = PeerCIDs.new(state.dcid, 8)
    {:ok, cids, []} = PeerCIDs.receive_id(cids, peer_cid(1, <<9, 8, 7, 6>>))
    state = %{state | peer_cids: cids}
    {:ok, state} = HandshakeScheduler.bind_path(state, 1, :default, false)
    state = HandshakeScheduler.drop_path_binding(state, :default)
    assert state.peer_cids.retired_before == 1
    assert state.pending_control.application == [%{type: :retire_connection_id, sequence: 0}]
    assert HandshakeScheduler.path_available?(state, 1)
    refute HandshakeScheduler.path_available?(state, :default)
    state = HandshakeScheduler.drop_path_binding(state, :default)
    assert state.pending_control.application == [%{type: :retire_connection_id, sequence: 0}]

    {:ok, recovery} = Recovery.add_path(state.recovery, 1)
    {:ok, recovery} = Recovery.select_path(recovery, 1)
    {:ok, state, [effect]} = HandshakeScheduler.schedule(%{state | recovery: recovery})
    assert binary_part(effect.bytes, 1, 4) == <<9, 8, 7, 6>>

    assert [%{type: :retire_connection_id, sequence: 0}] ==
             state.recovery.spaces.application.sent[effect.packet_number].metadata.control
  end

  test "peer retirement invalidates queued ciphertext and safely defers old-path output" do
    state = new()
    {:ok, recovery} = Recovery.add_path(state.recovery, 1)
    cids = PeerCIDs.new(state.dcid, 8)
    {:ok, cids, []} = PeerCIDs.receive_id(cids, peer_cid(1, <<9, 8, 7, 6>>))
    state = %{state | recovery: recovery, peer_cids: cids}
    {:ok, state} = HandshakeScheduler.bind_path(state, 1, :default, false)
    {:ok, recovery} = Recovery.select_path(state.recovery, 1)
    state = %{state | recovery: recovery}
    stream = %{type: :stream, stream_id: 0, offset: 0, data: "reliable", fin: true}
    state = HandshakeScheduler.queue_control(state, :application, [stream])
    {:ok, state, [queued]} = HandshakeScheduler.schedule(state)
    assert HandshakeScheduler.pending_send_valid?(state, queued)

    frame = %{peer_cid(2, <<4, 3, 2, 1>>) | retire_prior_to: 2}
    {:ok, plaintext} = Codec.encode_frames([frame])
    packet = peer_packet(state, 0, plaintext)
    {:ok, state, _} = HandshakeScheduler.receive_datagram(state, packet, 1, 1)
    refute HandshakeScheduler.pending_send_valid?(state, queued)

    assert {:blocked, :no_unused_connection_id} =
             HandshakeScheduler.send_path_frames(state, :default, [%{type: :ping}], 0)

    {:ok, state} = HandshakeScheduler.cancel_unsent(state, :application, queued.packet_number)
    {:ok, state, effects} = HandshakeScheduler.schedule(state)
    assert effects != []
    assert Enum.all?(effects, &(binary_part(&1.bytes, 1, 4) == <<4, 3, 2, 1>>))

    assert Enum.any?(effects, fn effect ->
             stream in state.recovery.spaces.application.sent[effect.packet_number].metadata.control
           end)

    {:ok, plaintext} = Codec.encode_frames([peer_cid(3, <<8, 8, 8, 8>>)])

    {:ok, state, _} =
      HandshakeScheduler.receive_datagram(state, peer_packet(state, 1, plaintext), 2, 1)

    {:ok, _state, [old_probe]} =
      HandshakeScheduler.send_path_frames(state, :default, [%{type: :ping}], 0)

    assert binary_part(old_probe.bytes, 1, 4) == <<8, 8, 8, 8>>
  end

  test "peer CID retirement also updates retained long-header Handshake retries" do
    {:ok, state, [first]} =
      HandshakeScheduler.new(:client,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: RecordedHandshake
      )

    state = %{state | peer_cids: PeerCIDs.new(state.dcid, 8)}

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :handshake, first.packet_number, :ok, 1)

    replacement = <<9, 8, 7, 6>>

    {:ok, plaintext} =
      Codec.encode_frames([%{peer_cid(1, replacement) | retire_prior_to: 1}])

    packet = peer_packet(state, 0, plaintext)
    {:ok, state, _} = HandshakeScheduler.receive_datagram(state, packet, 2, :default)
    assert state.dcid == replacement

    {:ok, _state, effects} =
      HandshakeScheduler.retry_crypto(state, :handshake, first.packet_number)

    retry = Enum.find(effects, &(&1.level == :handshake))
    assert retry.packet_number > first.packet_number
    assert <<_first, 1::32, 4, ^replacement::binary-size(4), _::binary>> = retry.bytes
  end

  test "path responses are not blindly retransmitted as reliable control" do
    state = new()

    {:ok, state, [effect]} =
      HandshakeScheduler.send_path_frames(
        state,
        :default,
        [%{type: :path_response, data: <<1::64>>}],
        0
      )

    {:ok, state, _} =
      HandshakeScheduler.local_send(state, :application, effect.packet_number, :ok, 1)

    assert {:ok, next, sends} =
             HandshakeScheduler.retry_crypto(state, :application, effect.packet_number)

    for send <- sends,
        frame <- next.recovery.spaces.application.sent[send.packet_number].metadata.control do
      refute frame.type in [:path_challenge, :path_response]
    end
  end

  test "retirement uses the actual incoming replacement DCID and removes local issuance" do
    state = new()
    {:ok, cids} = LocalCIDs.new(state.scid)
    {:ok, cids, _} = LocalCIDs.reserve(cids, <<9, 8, 7, 6>>, <<1::128>>, :registration)
    {:ok, cids, _} = LocalCIDs.registered(cids, :registration)
    {:ok, cids} = LocalCIDs.published(cids, 1)
    state = Map.put(state, :local_cids, cids)
    packet = peer_packet(state, 0, <<0x19, 0>>, <<9, 8, 7, 6>>)
    assert {:ok, next, events} = HandshakeScheduler.receive_datagram(state, packet, 10, :default)
    refute LocalCIDs.active?(next.local_cids, state.scid)
    assert Enum.any?(events, &(&1.type == :retire_connection_id and &1.cid == state.scid))
    packet = peer_packet(next, 1, <<0x19, 1>>, <<9, 8, 7, 6>>)

    assert {:error, {:protocol_violation, 0x0A, 0x19}, _} =
             HandshakeScheduler.receive_datagram(next, packet, 11, :default)
  end

  test "ACK before writer receipt still publishes a registered local CID exactly once" do
    state = new()

    {:ok, cids, _} =
      LocalCIDs.reserve(state.local_cids, <<9, 8, 7, 6>>, <<1::128>>, :registration)

    {:ok, cids, frame} = LocalCIDs.registered(cids, :registration)
    state = HandshakeScheduler.queue_control(%{state | local_cids: cids}, :application, [frame])
    {:ok, state, [effect]} = HandshakeScheduler.schedule(state)

    ack = %{
      largest: effect.packet_number,
      delay: 0,
      ranges: [{effect.packet_number, effect.packet_number}]
    }

    {:ok, state, _} = HandshakeScheduler.receive_ack(state, :application, ack, 1)

    {:ok, state, [:acked]} =
      HandshakeScheduler.local_send(state, :application, effect.packet_number, :ok, 2)

    assert state.local_cids.highest_sent == 1
    assert state.local_cids.pending == nil
  end

  test "retained retransmission keeps its original path after send selection changes" do
    state = new()
    {:ok, recovery} = Recovery.add_path(state.recovery, 1)
    state = %{state | recovery: recovery}

    {:ok, state, [effect]} =
      HandshakeScheduler.send_path_frames(state, 1, [%{type: :ping}], 0)

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, effect.packet_number, :ok, 1)

    assert {:ok, retained} =
             HandshakeScheduler.retransmit(state, :application, effect.packet_number)

    assert retained.path_id == 1
    assert retained.bytes == effect.bytes
  end

  test "retiring a CID invalidates protected queued issuance and retained ciphertext" do
    state = new()

    {:ok, cids, _} =
      LocalCIDs.reserve(state.local_cids, <<9, 8, 7, 6>>, <<1::128>>, :registration)

    {:ok, cids, frame} = LocalCIDs.registered(cids, :registration)
    state = HandshakeScheduler.queue_control(%{state | local_cids: cids}, :application, [frame])
    {:ok, state, [first]} = HandshakeScheduler.schedule(state)

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, first.packet_number, :ok, 1)

    {:ok, state, [queued]} =
      HandshakeScheduler.retry_crypto(state, :application, first.packet_number)

    assert HandshakeScheduler.pending_send_valid?(state, queued)
    packet = peer_packet(state, 0, <<0x19, 1>>)
    {:ok, state, _events} = HandshakeScheduler.receive_datagram(state, packet, 10, :default)
    refute HandshakeScheduler.pending_send_valid?(state, queued)

    for effect <- [first, queued] do
      assert {:error, :unknown_packet} =
               HandshakeScheduler.retransmit(state, :application, effect.packet_number)
    end

    assert {:ok, state} =
             HandshakeScheduler.cancel_unsent(state, :application, queued.packet_number)

    assert state.queued == 0
    assert state.recovery.spaces.application.sent[queued.packet_number].status == :failed
    {:ok, state, effects} = HandshakeScheduler.schedule(state)

    for effect <- effects,
        frame <- state.recovery.spaces.application.sent[effect.packet_number].metadata.control do
      refute frame.type == :new_connection_id
    end
  end

  test "cancelling unsent path output preserves reliable frames with fresh packet numbers" do
    state = new()
    {:ok, recovery} = Recovery.add_path(state.recovery, 1)
    {:ok, recovery} = Recovery.select_path(recovery, 1)
    stream = %{type: :stream, stream_id: 0, offset: 7, data: "reliable", fin: true}

    frames = [
      stream,
      %{type: :datagram, data: "unreliable"},
      %{type: :path_challenge, data: <<1::64>>},
      %{type: :path_response, data: <<2::64>>},
      %{type: :max_data, value: 100}
    ]

    state = HandshakeScheduler.queue_control(%{state | recovery: recovery}, :application, frames)
    {:ok, state, cancelled} = HandshakeScheduler.schedule(state)
    assert cancelled != []
    assert Enum.all?(cancelled, &(&1.path_id == 1))
    assert state.queued == length(cancelled)

    state =
      Enum.reduce(cancelled, state, fn effect, state ->
        assert {:ok, next} =
                 HandshakeScheduler.cancel_unsent(state, :application, effect.packet_number)

        refute HandshakeScheduler.pending_send_valid?(next, effect)
        next
      end)

    assert state.queued == 0
    assert state.queued_bytes == byte_size(stream.data)
    assert Recovery.path(state.recovery, 1).congestion.bytes_in_flight == 0
    assert state.pending_control.application == [stream, %{type: :max_data, value: 100}]
    {:ok, recovery} = Recovery.select_path(state.recovery, :default)
    {:ok, state, replacement} = HandshakeScheduler.schedule(%{state | recovery: recovery})
    assert replacement != []
    assert Enum.all?(replacement, &(&1.path_id == :default))
    assert hd(replacement).packet_number > List.last(cancelled).packet_number
    assert state.queued_bytes == 0

    replayed =
      Enum.flat_map(replacement, fn effect ->
        state.recovery.spaces.application.sent[effect.packet_number].metadata.control
      end)

    assert replayed == [stream, %{type: :max_data, value: 100}]

    assert {:error, :packet_not_unsent} =
             HandshakeScheduler.cancel_unsent(state, :application, hd(cancelled).packet_number)

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, hd(replacement).packet_number, :ok, 20)

    assert {:error, :packet_not_unsent} =
             HandshakeScheduler.cancel_unsent(state, :application, hd(replacement).packet_number)
  end

  test "cancelling unsent CRYPTO retains bytes and allocates a fresh packet number" do
    {:ok, state, [first]} =
      HandshakeScheduler.new(:server,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        adapter: RecordedCrypto
      )

    assert {:ok, state} =
             HandshakeScheduler.cancel_unsent(state, :application, first.packet_number)

    assert state.pending == [%{level: :application, offset: 0, bytes: "retained crypto"}]
    assert state.recovery.congestion.bytes_in_flight == 0
    assert state.queued == 0
    assert {:ok, state, [replacement]} = HandshakeScheduler.schedule(state)
    assert replacement.packet_number == first.packet_number + 1
    assert replacement.bytes != first.bytes

    assert state.recovery.spaces.application.sent[replacement.packet_number].metadata.crypto ==
             {0, byte_size("retained crypto")}

    assert {:ok, "retained crypto"} =
             TLSDriver.retransmit(state.tls, :application, 0, byte_size("retained crypto"))

    assert {:error, :not_retransmittable} =
             HandshakeScheduler.retry_crypto(state, :application, first.packet_number)
  end

  test "cancelling an ACK packet restores the latest receive ranges" do
    state = new()

    {:ok, state, _} =
      HandshakeScheduler.receive_datagram(state, peer_packet(state, 0, <<1>>), 1, :default)

    {:ok, state, [first]} = HandshakeScheduler.schedule(state)

    {:ok, state, _} =
      HandshakeScheduler.receive_datagram(state, peer_packet(state, 1, <<1>>), 2, :default)

    assert {:ok, state} =
             HandshakeScheduler.cancel_unsent(state, :application, first.packet_number)

    assert [%{largest: 1, ranges: [{0, 1}]}] = state.pending_acks.application
    assert {:ok, state, [replacement]} = HandshakeScheduler.schedule(state)
    assert replacement.packet_number > first.packet_number

    assert [%{largest: 1, ranges: [{0, 1}]}] =
             state.recovery.spaces.application.sent[replacement.packet_number].metadata.acks
  end

  defp peer_cid(sequence, cid),
    do: %{
      type: :new_connection_id,
      sequence: sequence,
      retire_prior_to: 0,
      cid: cid,
      token: <<sequence::128>>
    }

  defp peer_packet(state, pn, plaintext, dcid \\ nil) do
    keys = state.keys.application.read
    dcid = dcid || state.scid
    plaintext = plaintext <> :binary.copy(<<0>>, max(0, 3 - byte_size(plaintext)))
    prefix = <<0x40, dcid::binary>>
    aad = prefix <> <<pn>>
    nonce = :crypto.exor(keys.iv, <<pn::96>>)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_128_gcm, keys.key, nonce, plaintext, aad, 16, true)

    packet = aad <> ciphertext <> tag
    sample = binary_part(packet, byte_size(prefix) + 4, 16)
    <<mask, pn_mask, _::binary>> = :crypto.crypto_one_time(:aes_128_ecb, keys.hp, sample, true)

    <<bxor(0x40, band(mask, 0x1F)), dcid::binary, bxor(pn, pn_mask), ciphertext::binary,
      tag::binary>>
  end
end

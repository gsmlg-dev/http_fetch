defmodule Quic.KeyRetirementTest do
  use ExUnit.Case, async: true
  alias Quic.{Recovery, TLSDriver, HandshakeScheduler}

  defmodule Recorded do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      secrets =
        for level <- [:handshake, :application],
            {direction, value} <- [read: read, write: write] do
          %SSL.QUIC.Secret{
            level: level,
            direction: direction,
            cipher_suite: 0x1301,
            aead: :aes_128_gcm,
            hkdf: :sha256,
            secret: <<value::256>>
          }
        end

      {:ok, %{feeds: [], phase: :initial},
       secrets ++ [{:emit, :initial, <<1, 2>>}, {:emit, :handshake, <<3, 4>>}]}
    end

    def info(state), do: %{receive_level: state.phase}

    def feed(state, level, bytes),
      do: {:ok, %{state | feeds: state.feeds ++ [{level, bytes}], phase: :handshake}, []}

    def abort(state, _), do: state
  end

  defp scheduler(role) do
    HandshakeScheduler.new(role,
      dcid: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      scid: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      adapter: Recorded,
      min_initial_size: 0
    )
  end

  test "permanent recovery retirement frees reservations once, preserves PN and rejects stale work" do
    r = Recovery.new()
    {:ok, r, _} = Recovery.reserve(r, :initial, %{bytes: <<1>>}, 100)
    {:ok, r, _} = Recovery.local_send(r, :initial, 0, :ok, 10)
    {:ok, r, _} = Recovery.reserve(r, :handshake, %{bytes: <<2>>}, 200)
    {:ok, r, _} = Recovery.local_send(r, :handshake, 0, :ok, 20)
    {:ok, r, _} = Recovery.reserve(r, :initial, %{bytes: <<3>>}, 50)
    {:ok, r, _} = Recovery.receive_ack(r, :initial, %{largest: 1, ranges: [{1, 1}]}, 25)
    assert MapSet.member?(r.spaces.initial.pending_acks, 1)
    token = r.timer_generation
    next = Recovery.retire_space(r, :initial)
    assert next.spaces.initial.next == 2
    assert next.spaces.initial.sent == %{}
    assert next.congestion.bytes_in_flight == 200
    assert next.deadline != nil
    refute Recovery.timer_expired?(next, token, next.deadline)
    assert Recovery.retire_space(next, :initial) == next
    assert {:error, :retired_space} = Recovery.reserve(next, :initial, %{}, 1)
    assert {:ok, ^next, [:retired]} = Recovery.local_send(next, :initial, 0, :ok, 30)

    assert {:ok, ^next, [:retired]} =
             Recovery.local_send(next, :initial, 0, {:error, :closed}, 30)

    assert {:error, :retired_space} =
             Recovery.receive_ack(next, :initial, %{largest: 0, ranges: [{0, 0}]}, 30)

    done = Recovery.retire_space(next, :handshake)
    assert done.congestion.bytes_in_flight == 0
    assert done.deadline == nil
  end

  test "TLS retirement drops sparse, pending and retransmission bytes without feeding TLS" do
    {:ok, tls, _} = TLSDriver.new(:client, adapter: Recorded)
    {:ok, tls, []} = TLSDriver.feed(tls, :handshake, 0, <<3>>)
    {:ok, tls, []} = TLSDriver.feed(tls, :handshake, 5, <<9>>)
    next = TLSDriver.retire_level(tls, :handshake)
    assert next.future_bytes == 0
    assert next.levels.handshake.pending == <<>>
    assert next.levels.handshake.recv.intervals == []
    assert next.levels.handshake.recv.buffered_bytes == 0
    assert {:ok, ^next, []} = TLSDriver.feed(next, :handshake, 0, <<3, 4>>)
    assert next.tls == tls.tls
    assert TLSDriver.retire_level(next, :handshake) == next
    next = TLSDriver.retire_level(next, :initial)
    assert next.emitted_bytes == 0
    assert next.levels.initial.sent == []
    assert next.levels.initial.next_send == 2
    assert {:error, :retired_level} = TLSDriver.retransmit(next, :initial, 0, 2)
  end

  test "client Initial retirement follows actual Handshake success, not keys or admission" do
    {:ok, client, [initial, handshake]} = scheduler(:client)
    assert Map.has_key?(client.keys, :initial)
    assert Map.has_key?(client.keys, :application)

    {:ok, failed, [:failed]} =
      HandshakeScheduler.local_send(
        client,
        :handshake,
        handshake.packet_number,
        {:error, :closed},
        0
      )

    assert Map.has_key?(failed.keys, :initial)

    {:ok, next, [:sent]} =
      HandshakeScheduler.local_send(client, :handshake, handshake.packet_number, :ok, 0)

    refute Map.has_key?(next.keys, :initial)
    assert next.read_keys == %{}
    assert next.tls.levels.initial.sent == []
    assert next.recovery.spaces.initial.sent == %{}
    assert next.recovery.spaces.initial.next == 1
    refute Enum.any?(next.effects, &(&1.level == :initial))

    assert {:ok, ^next, [:retired]} =
             HandshakeScheduler.local_send(next, :initial, initial.packet_number, :ok, 5)

    assert {:ok, ^next, [%{type: :discard, reason: :retired_level}]} =
             HandshakeScheduler.receive_datagram(next, initial.bytes, 5)
  end

  test "server processes authenticated coalesced Handshake before retiring Initial" do
    {:ok, client, [initial, handshake]} = scheduler(:client)
    {:ok, server, [_, _]} = scheduler(:server)
    size = byte_size(handshake.bytes) - 1
    <<prefix::binary-size(^size), last>> = handshake.bytes
    damaged = prefix <> <<Bitwise.bxor(last, 1)>>
    assert {:error, _, ^server} = HandshakeScheduler.receive_datagram(server, damaged, 0)

    {:ok, partial, events} =
      HandshakeScheduler.receive_datagram(server, initial.bytes <> damaged, 1)

    assert Enum.any?(events, &match?(%{type: :discard, reason: :bad_tag}, &1))
    assert Map.has_key?(partial.keys, :initial)
    refute partial.tls.facts.address_validated

    {:ok, server, _} =
      HandshakeScheduler.receive_datagram(server, initial.bytes <> handshake.bytes, 1)

    refute Map.has_key?(server.keys, :initial)
    assert server.tls.facts.address_validated
    assert server.tls.tls.feeds == [{:initial, <<1, 2>>}, {:handshake, <<3, 4>>}]
    assert Map.has_key?(server.keys, :handshake)
    refute client.tls.facts.quic_confirmed
  end

  test "server confirmation retires Handshake but HANDSHAKE_DONE remains retransmittable in Application" do
    {:ok, server, [_, handshake]} = scheduler(:server)

    {:ok, server, [:sent]} =
      HandshakeScheduler.local_send(server, :handshake, handshake.packet_number, :ok, 0)

    old_token = server.recovery.timer_generation
    server = %{server | tls: %{server.tls | facts: %{server.tls.facts | tls_complete: true}}}
    confirmed = HandshakeScheduler.confirm_handshake(server)
    assert confirmed.tls.facts.quic_confirmed
    refute Map.has_key?(confirmed.keys, :handshake)
    assert confirmed.recovery.spaces.handshake.sent == %{}
    assert confirmed.tls.levels.handshake.sent == []
    assert confirmed.tls.emitted_bytes == 2
    refute Recovery.timer_expired?(confirmed.recovery, old_token, 10_000_000)
    assert HandshakeScheduler.confirm_handshake(confirmed) == confirmed
    {:ok, confirmed, [done]} = HandshakeScheduler.handshake_done(confirmed)
    assert done.level == :application

    {:ok, confirmed, [:sent]} =
      HandshakeScheduler.local_send(confirmed, :application, done.packet_number, :ok, 10)

    {:ok, recovery, %{probes: [{:application, number}]}} =
      Recovery.on_time(confirmed.recovery, confirmed.recovery.deadline)

    {:ok, confirmed, [retry]} =
      HandshakeScheduler.retry_crypto(%{confirmed | recovery: recovery}, :application, number)

    assert retry.packet_number > done.packet_number

    assert confirmed.recovery.spaces.application.sent[retry.packet_number].metadata.control == [
             %{type: :handshake_done}
           ]

    refute Map.has_key?(confirmed.keys, :handshake)

    assert {:ok, ^confirmed, [:retired]} =
             HandshakeScheduler.local_send(
               confirmed,
               :handshake,
               handshake.packet_number,
               :ok,
               20
             )
  end

  test "client retires Handshake only on authenticated HANDSHAKE_DONE and ignores a delayed old packet" do
    {:ok, client, [_, client_handshake]} = scheduler(:client)
    {:ok, server, [server_initial, server_handshake]} = scheduler(:server)
    # Recorded completion facts let this test isolate confirmation from real TLS.
    client = %{client | tls: %{client.tls | facts: %{client.tls.facts | tls_complete: true}}}
    server = %{server | tls: %{server.tls | facts: %{server.tls.facts | tls_complete: true}}}
    assert Map.has_key?(client.keys, :handshake)

    {:ok, client, [:sent]} =
      HandshakeScheduler.local_send(client, :handshake, client_handshake.packet_number, :ok, 0)

    {:ok, server, [done]} = HandshakeScheduler.handshake_done(server)
    size = byte_size(done.bytes) - 1
    <<prefix::binary-size(^size), last>> = done.bytes
    damaged = prefix <> <<Bitwise.bxor(last, 1)>>
    assert {:error, :bad_tag, ^client} = HandshakeScheduler.receive_datagram(client, damaged, 1)

    {:ok, confirmed, events} =
      HandshakeScheduler.receive_datagram(client, server_initial.bytes <> done.bytes, 1)

    assert Enum.any?(events, &match?(%{type: :discard, reason: :retired_level}, &1))
    assert Enum.any?(events, &(&1.type == :handshake_done))
    assert confirmed.tls.facts.quic_confirmed
    refute Map.has_key?(confirmed.keys, :handshake)
    assert confirmed.tls.emitted_bytes == 0

    assert {:ok, ^confirmed, [%{type: :discard, reason: :retired_level}]} =
             HandshakeScheduler.receive_datagram(confirmed, server_handshake.bytes, 2)

    {:ok, duplicate, _} = HandshakeScheduler.receive_datagram(confirmed, done.bytes, 3)
    assert duplicate.tls == confirmed.tls
    assert duplicate.recovery.congestion == confirmed.recovery.congestion
    assert server.recovery.spaces.application.next == 1
  end

  test "late valid Retry cannot reinstall retired Initial keys" do
    {:ok, client, [_, handshake]} = scheduler(:client)

    {:ok, client, [:sent]} =
      HandshakeScheduler.local_send(client, :handshake, handshake.packet_number, :ok, 0)

    scid = <<9, 10, 11, 12>>
    body = <<0xF0, 1::32, byte_size(client.scid), client.scid::binary, 4, scid::binary, 42>>
    {:ok, tag} = Quic.Protection.retry_tag(client.original_dcid, body)

    assert {:error, :unexpected_retry, ^client} =
             HandshakeScheduler.receive_datagram(client, body <> tag, 1)
  end

  defmodule RecordingWriter do
    def send(owner, bytes, _remote) do
      Kernel.send(owner, {:written, bytes})
      {:ok, monotonic_time()}
    end

    def monotonic_time, do: System.monotonic_time(:microsecond)
  end

  test "runtime discards retired pending effects and ignores the old recovery timer" do
    {:ok, server, [initial, handshake]} = scheduler(:server)

    {:ok, recovery, [:sent]} =
      Recovery.local_send(server.recovery, :initial, initial.packet_number, :ok, 0)

    old_timer = recovery.timer_generation
    server = %{server | recovery: recovery}
    retired = HandshakeScheduler.retire_level(server, :initial)
    {:ok, budget} = Quic.IO.Endpoint.new()
    {:ok, budget} = Quic.IO.Endpoint.validate_address(budget)
    generation = make_ref()

    data = %{
      scheduler: retired,
      pending: [initial, handshake],
      event_error: nil,
      highwaters: %{},
      operations: %{},
      events: [],
      datagrams: [],
      datagram_bytes: 0,
      datagram_drops: 0,
      ready: false,
      budget: budget,
      remote: {{127, 0, 0, 1}, 443},
      adapter: RecordingWriter,
      writer: self(),
      generation: generation,
      deadline: RecordingWriter.monotonic_time() + 1_000_000
    }

    assert :keep_state_and_data =
             Quic.Connection.handle_event(
               {:timeout, :recovery},
               {generation, old_timer},
               :handshaking,
               data
             )

    refute_receive {:written, _}
    # A valid application-independent recovery callback flushes current pending
    # work, but the obsolete Initial effect must never reach the writer.
    {:ok, recovery, [:sent]} =
      Recovery.local_send(
        retired.recovery,
        :handshake,
        handshake.packet_number,
        :ok,
        RecordingWriter.monotonic_time() - 2_000_000
      )

    retired = %{retired | recovery: recovery}

    data = %{
      data
      | scheduler: retired,
        pending: [initial],
        deadline: RecordingWriter.monotonic_time() + 5_000_000
    }

    assert {:keep_state, next, _} =
             Quic.Connection.handle_event(
               {:timeout, :recovery},
               {generation, recovery.timer_generation},
               :handshaking,
               data
             )

    assert_receive {:written, bytes}
    refute bytes == initial.bytes
    refute_receive {:written, _}
    assert next.pending == []
    assert next.scheduler.recovery.spaces.initial.sent == %{}
  end
end

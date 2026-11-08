defmodule Quic.EarlyDataTest do
  use ExUnit.Case, async: true
  alias Quic.{Codec, EarlyData, HandshakeScheduler, Recovery, TransportParameters}

  defmodule Provider do
    def new(role, _) do
      secret = %SSL.QUIC.Secret{
        level: :early_data,
        direction: if(role == :client, do: :write, else: :read),
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: <<1::256>>
      }

      request = %SSL.QUIC.Request{id: :continuation, operation: :lookup}
      {:ok, role, [secret, {:session_lookup, request}]}
    end

    def info(_), do: %{receive_level: :initial}
    def feed(state, _, _), do: {:ok, state, []}

    def continue(role, :continuation, disposition) do
      secret = %SSL.QUIC.Secret{
        level: :application,
        direction: if(role == :client, do: :write, else: :read),
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: <<2::256>>
      }

      {:ok, role, [{:early_data, disposition}, secret]}
    end

    def abort(state, _), do: state
  end

  defp scheduler(role) do
    {:ok, state, []} =
      HandshakeScheduler.new(role,
        dcid: <<1, 2, 3, 4>>,
        scid: <<1, 2, 3, 4>>,
        adapter: Provider,
        resumption: [early_data: true],
        early_staging_limit: 32_768,
        streams: [delivery: :manual],
        max_datagram_frame_size: 1200
      )

    %{state | peer_max_datagram_frame_size: 1200}
  end

  defp parameters(data \\ 65_536) do
    entries =
      for {id, value} <- [
            {4, data},
            {5, 65_536},
            {6, 65_536},
            {7, 65_536},
            {8, 8},
            {9, 8},
            {0x20, 1200}
          ] do
        {:ok, wire} = Codec.encode_varint(value)
        %{id: id, value: wire}
      end

    {:ok, bytes} =
      TransportParameters.encode([%{id: 0x0F, value: <<1>>}, %{id: 0, value: <<2>>} | entries],
        role: :server
      )

    bytes
  end

  test "payload and ciphertext reservations are independent, bounded and released by owner" do
    wire = parameters()

    state =
      Enum.reduce(1..64, %EarlyData{}, fn id, state ->
        {:ok, state} = EarlyData.reserve(state, id, wire, wire)
        state
      end)

    assert {:error, :early_capacity} = EarlyData.reserve(state, :extra, wire, wire)
    assert EarlyData.stats(state).payload_reserved == 8_388_608
    assert {:ok, _} = EarlyData.reserve(EarlyData.release(state, 1), :extra, wire, wire)

    {state, granted} =
      Enum.reduce(1..33, {%EarlyData{}, []}, fn id, {state, grants} ->
        {state, grant} = EarlyData.reserve_staging(state, id)
        {state, [grant | grants]}
      end)

    assert Enum.count(granted, &(&1 == 32_768)) == 32
    assert EarlyData.stats(state).staging_reserved == 1_048_576

    assert {:error, :remembered_transport_limits} =
             EarlyData.reserve(%EarlyData{}, 1, parameters(262_144), wire)
  end

  test "type-1 packet protection shares application numbers and withholds plaintext events" do
    client = scheduler(:client)
    server = scheduler(:server)
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    {:ok, client, [effect]} = HandshakeScheduler.send_stream(client, id, "early-prefix", true)
    assert effect.level == :early_data
    assert effect.space == :application
    assert Bitwise.band(:binary.at(effect.bytes, 0), 0xF0) == 0xD0

    {:ok, client, _} =
      HandshakeScheduler.local_send(client, :application, effect.packet_number, :ok, 0)

    {:ok, server, events} = HandshakeScheduler.receive_datagram(server, effect.bytes, 1)
    refute Enum.any?(events, &(&1.type == :stream))
    assert server.streams.ready_bytes == 12
    assert server.early_stream_ids == MapSet.new([id])
    {:ok, client, []} = HandshakeScheduler.continue_tls(client, :continuation, :accepted)
    {:ok, client, [later]} = HandshakeScheduler.ping(client)
    assert later.level == :application
    assert later.packet_number > effect.packet_number
    assert client.recovery.spaces.application.next == later.packet_number + 1
  end

  test "rejection erases early work and stream state without reusing packet numbers" do
    state = scheduler(:client)
    {:ok, state, id} = HandshakeScheduler.open_stream(state, :bidi)
    {:ok, state, [effect]} = HandshakeScheduler.send_stream(state, id, "never-replay", true)
    next_number = state.recovery.spaces.application.next
    {:ok, state, []} = HandshakeScheduler.continue_tls(state, :continuation, :rejected)
    assert state.early_epoch == 1
    assert state.streams.streams == %{}
    assert state.pending_control == %{}
    assert state.recovery.spaces.application.next == next_number
    assert state.recovery.spaces.application.sent[effect.packet_number].status == :discarded

    assert {:error, :not_retransmittable} =
             HandshakeScheduler.retry_crypto(state, :application, effect.packet_number)

    assert Recovery.reject_early(state.recovery).spaces.application.next == next_number
  end

  test "ACK and CRYPTO are illegal in early packets" do
    for frame <- [%{type: :ack}, %{type: :crypto}, %{type: :handshake_done}] do
      assert {:wrong_encryption_level, _, :early_data} =
               Codec.validate_frame_levels([frame], :early_data)
    end
  end

  test "pre-key staging drops whole excess packets and drains authenticated duplicates once" do
    client = scheduler(:client)
    server = scheduler(:server)
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    {:ok, _, [packet]} = HandshakeScheduler.send_stream(client, id, "held", true)
    read = server.keys.early_data
    server = %{server | keys: Map.delete(server.keys, :early_data)}

    server =
      Enum.reduce(1..17, server, fn _, state ->
        {:ok, state, _} = HandshakeScheduler.receive_datagram(state, packet.bytes, 1)
        state
      end)

    assert length(server.early_staged) == 16
    assert server.early_staged_bytes == 16 * byte_size(packet.bytes)
    assert server.streams.ready_bytes == 0
    server = %{server | keys: Map.put(server.keys, :early_data, read)}
    # No server write secret in this fixture: a read-only state leaves ACK output
    # to the ordinary writer, installed here with the same independent test key.
    server = %{server | keys: Map.put(server.keys, :application, %{write: read.read})}
    {:ok, server, _} = HandshakeScheduler.continue_tls(server, :continuation, :accepted)
    assert server.early_staged == []
    assert server.early_staged_bytes == 0
    assert server.streams.ready_bytes == 4
    {server, events} = HandshakeScheduler.take_early_events(server)
    assert Enum.count(events, &(&1.type == :stream)) == 1
    {_, events} = HandshakeScheduler.take_early_events(server)
    assert events == []
  end

  test "accepted early STREAM loss crosses to 1-RTT while DATAGRAM never retransmits" do
    client = scheduler(:client)
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    {:ok, client, [packet]} = HandshakeScheduler.send_stream(client, id, "reliable", true)

    {:ok, client, _} =
      HandshakeScheduler.local_send(client, :application, packet.packet_number, :ok, 0)

    {:ok, client, [datagram]} = HandshakeScheduler.send_datagram(client, "unreliable")

    {:ok, client, _} =
      HandshakeScheduler.local_send(client, :application, datagram.packet_number, :ok, 0)

    {:ok, client, []} = HandshakeScheduler.continue_tls(client, :continuation, :accepted)

    {:ok, client, [retried]} =
      HandshakeScheduler.retry_crypto(client, :application, packet.packet_number)

    assert retried.level == :application and retried.packet_number > datagram.packet_number

    assert [%{type: :stream, data: "reliable"}] =
             client.recovery.spaces.application.sent[retried.packet_number].metadata.control

    {:ok, client, [probe]} =
      HandshakeScheduler.retry_crypto(client, :application, datagram.packet_number)

    refute Enum.any?(
             client.recovery.spaces.application.sent[probe.packet_number].metadata.control,
             &(&1.type == :datagram)
           )
  end

  test "Retry changes destination and requeues reliable early work without a TLS rejection" do
    client = scheduler(:client)
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    {:ok, client, [packet]} = HandshakeScheduler.send_stream(client, id, "retry-prefix", true)
    dcid = client.scid
    scid = <<10, 11, 12, 13, 14, 15, 16, 17>>
    body = <<0xF0, 1::32, byte_size(dcid), dcid::binary, byte_size(scid), scid::binary, "token">>
    {:ok, tag} = Quic.Protection.retry_tag(client.original_dcid, body)

    {:ok, client, [%{type: :retry, generated: [retry]}]} =
      HandshakeScheduler.receive_datagram(client, body <> tag, 1)

    assert client.early_epoch == 0 and client.early_status == :pending
    assert client.streams.streams[id].send_offset == 12
    assert retry.level == :early_data and retry.packet_number > packet.packet_number
    assert client.recovery.spaces.application.sent[retry.packet_number].metadata.dcid == scid
    assert client.recovery.spaces.application.sent[packet.packet_number].status == :discarded
  end

  test "early DATAGRAM exhaustion is independent of reliable STREAM capacity" do
    client = scheduler(:client)

    client =
      Enum.reduce(1..64, client, fn _, state ->
        {:ok, state, [packet]} = HandshakeScheduler.send_datagram(state, "message")

        {:ok, state, _} =
          HandshakeScheduler.local_send(state, :application, packet.packet_number, :ok, 0)

        state
      end)

    assert {:blocked, :early_datagram_limit} =
             HandshakeScheduler.send_datagram(client, "overflow")

    assert {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    assert {:ok, _, _} = HandshakeScheduler.send_stream(client, id, "reserved-reliable", true)
  end

  test "fresh 1-RTT credit cannot enlarge delayed early STREAM or stream-count allowance" do
    client = scheduler(:client)
    server = scheduler(:server)

    {ordinary, _} =
      Quic.Streams.grant_ordinary(server.streams,
        max_data: 262_144,
        max_stream_data: 262_144,
        max_streams_bidi: 16
      )

    server = %{server | streams: ordinary, early_delivery_ready: true}
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    streams = client.streams
    streams = put_in(streams.streams[id].send_offset, 65_536)
    streams = put_in(streams.streams[id].send_limit, 262_144)
    client = %{client | streams: %{streams | peer_max_data: 262_144, data_sent: 65_536}}
    {:ok, _, [packet]} = HandshakeScheduler.send_stream(client, id, "beyond-remembered", false)

    assert {:error, {:transport_error, 0x03, 0x08, :early_flow_control}, _} =
             HandshakeScheduler.receive_datagram(server, packet.bytes, 1)

    client = scheduler(:client)
    client = %{client | streams: %{client.streams | next_local_bidi: 8}}
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    {:ok, _, [packet]} = HandshakeScheduler.send_stream(client, id, <<>>, true)

    assert {:error, {:transport_error, 0x04, 0x08, :early_stream_limit}, _} =
             HandshakeScheduler.receive_datagram(server, packet.bytes, 1)
  end

  test "early packet numbers cannot follow 1-RTT, and retired early keys discard late packets" do
    client = scheduler(:client)
    client = put_in(client.recovery.spaces.application.next, 2)
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    {:ok, _, [packet]} = HandshakeScheduler.send_stream(client, id, "late", true)
    server = %{scheduler(:server) | first_one_rtt_received: 1}

    assert {:error, {:protocol_violation, 0x0A, 0}, _} =
             HandshakeScheduler.receive_datagram(server, packet.bytes, 1)

    server = HandshakeScheduler.retire_early_keys(server)
    assert server.keys[:early_data] == nil

    assert {:ok, _, [%{type: :discard, reason: :retired_level}]} =
             HandshakeScheduler.receive_datagram(server, packet.bytes, 2)
  end

  test "ordinary credit never advertises receive credit on a locally initiated unidirectional stream" do
    {:ok, streams, id} = Quic.Streams.open(Quic.Streams.new(:client, delivery: :manual), :uni)
    {_, credit} = Quic.Streams.grant_ordinary(streams, [])
    refute Enum.any?(credit, &match?(%{type: :max_stream_data, stream_id: ^id}, &1))
  end

  test "coalesced pre-key packets reserve one whole UDP datagram and overflow drops all of it" do
    client = scheduler(:client)
    {:ok, client, id} = HandshakeScheduler.open_stream(client, :bidi)
    {:ok, client, [first]} = HandshakeScheduler.send_stream(client, id, "one", false)
    {:ok, _, [second]} = HandshakeScheduler.send_stream(client, id, "two", true)
    datagram = first.bytes <> second.bytes
    server = scheduler(:server)
    server = %{server | keys: Map.delete(server.keys, :early_data)}
    {:ok, staged, _} = HandshakeScheduler.receive_datagram(server, datagram, 1)
    assert staged.early_staged == [{datagram, 1}]
    assert staged.early_staged_bytes == byte_size(datagram)

    {:ok, dropped, _} =
      HandshakeScheduler.receive_datagram(
        %{server | early_staging_limit: byte_size(datagram) - 1},
        datagram,
        1
      )

    assert dropped.early_staged == []
    assert dropped.early_staged_bytes == 0
    assert dropped.early_status == :pending
  end
end

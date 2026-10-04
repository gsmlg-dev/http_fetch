defmodule Quic.Phase1PacketizationTest do
  use ExUnit.Case, async: true
  alias Quic.{HandshakeScheduler, Recovery}

  defmodule Recorded do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      actions =
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

      {:ok, nil, actions}
    end

    def info(_), do: %{receive_level: :application}
    def abort(state, _), do: state
    def feed(state, _, _), do: {:ok, state, []}
  end

  defp pair(opts \\ []) do
    {:ok, sender, []} =
      HandshakeScheduler.new(
        :client,
        [adapter: Recorded, dcid: <<1, 2, 3, 4>>, scid: <<5, 6, 7, 8>>, max_packet_size: 1200] ++
          opts
      )

    {:ok, receiver, []} =
      HandshakeScheduler.new(:server,
        adapter: Recorded,
        dcid: sender.scid,
        scid: sender.dcid,
        max_packet_size: 1200
      )

    {:ok, sender, 0} = HandshakeScheduler.open_stream(sender, :bidi)
    {sender, receiver}
  end

  test "a 16 KiB write is packetized below the protected ceiling with FIN only at the end" do
    {sender, receiver} = pair(recovery: Recovery.new(initial_cwnd: 24_000))
    payload = :binary.copy("0123456789abcdef", 1024)
    assert {:ok, sender, effects} = HandshakeScheduler.send_stream(sender, 0, payload, true)
    assert length(effects) > 1
    assert Enum.all?(effects, &(byte_size(&1.bytes) <= 1200))

    {_, data, fins} =
      Enum.reduce(effects, {receiver, <<>>, 0}, fn effect, {state, data, fins} ->
        {:ok, state, events} = HandshakeScheduler.receive_datagram(state, effect.bytes, 10)
        stream_events = Enum.flat_map(events, &Map.get(&1, :events, []))
        bytes = for {:data, 0, bytes} <- stream_events, into: <<>>, do: bytes
        {state, data <> bytes, fins + Enum.count(stream_events, &(&1 == {:fin, 0}))}
      end)

    assert data == payload
    assert fins == 1
    assert sender.effects == []
    assert sender.queued_bytes == 0
  end

  test "partial congestion scheduling retains admitted bytes and resumes with fresh packet numbers" do
    {sender, _} = pair(recovery: Recovery.new(initial_cwnd: 2400))

    assert {:ok, sender, effects} =
             HandshakeScheduler.send_stream(sender, 0, :binary.copy("x", 16_384), true)

    assert length(effects) in 1..2
    assert sender.queued_bytes > 0
    last = List.last(effects).packet_number

    sender =
      Enum.reduce(effects, sender, fn effect, state ->
        {:ok, next, _} =
          HandshakeScheduler.local_send(state, :application, effect.packet_number, :ok, 1)

        next
      end)

    {:ok, sender, _} =
      HandshakeScheduler.receive_ack(
        sender,
        :application,
        %{largest: last, delay: 0, ranges: [{0, last}]},
        100
      )

    assert {:ok, sender, more} = HandshakeScheduler.schedule(sender)
    assert more != []
    assert hd(more).packet_number > last
    assert sender.recovery.spaces.application.next > last + 1
  end

  test "invalid or temporarily blocked admissions have stable results and no offset mutation" do
    {sender, _} = pair()
    assert {:error, :unknown_stream} = HandshakeScheduler.send_stream(sender, 99, "x")

    assert {:error, :chunk_too_large} =
             HandshakeScheduler.send_stream(sender, 0, :binary.copy("x", 16_385))

    sender = %{sender | max_queue_bytes: 1}
    assert {:blocked, :send_queue_bytes_limit} = HandshakeScheduler.send_stream(sender, 0, "xx")
    assert sender.streams.streams[0].send_offset == 0
  end

  test "one MiB cumulative writes reclaim packet payload and effects" do
    {sender, _} = pair(recovery: Recovery.new(initial_cwnd: 24_000))
    sender = put_in(sender.streams.streams[0].send_limit, 1_048_576)

    {sender, total} =
      Enum.reduce(1..64, {sender, 0}, fn index, {state, total} ->
        {:ok, state, effects} =
          HandshakeScheduler.send_stream(state, 0, :binary.copy("x", 16_384), index == 64)

        assert state.queued_bytes == 0

        state =
          Enum.reduce(effects, state, fn effect, state ->
            {:ok, state, _} =
              HandshakeScheduler.local_send(
                state,
                :application,
                effect.packet_number,
                :ok,
                index * 10_000
              )

            {:ok, state, _} =
              HandshakeScheduler.receive_ack(
                state,
                :application,
                %{
                  largest: effect.packet_number,
                  ranges: [{effect.packet_number, effect.packet_number}],
                  delay: 0
                },
                index * 10_000 + 1000
              )

            state
          end)

        assert state.effects == []

        assert Enum.all?(state.recovery.spaces.application.sent, fn {_, packet} ->
                 packet.status != :acked or not Map.has_key?(packet.metadata, :bytes)
               end)

        {state, total + 16_384}
      end)

    assert total == 1_048_576
    assert sender.recovery.congestion.bytes_in_flight == 0
  end

  test "acknowledging an original transmission suppresses queued and lost STREAM retries" do
    {sender, _} = pair()
    {:ok, sender, [first]} = HandshakeScheduler.send_stream(sender, 0, "payload", true)

    {:ok, sender, _} =
      HandshakeScheduler.local_send(sender, :application, first.packet_number, :ok, 1)

    {:ok, sender, [retry]} =
      HandshakeScheduler.retry_crypto(sender, :application, first.packet_number)

    {:ok, sender, _} =
      HandshakeScheduler.local_send(sender, :application, retry.packet_number, :ok, 2)

    {:ok, sender, _} =
      HandshakeScheduler.receive_ack(
        sender,
        :application,
        %{
          largest: first.packet_number,
          ranges: [{first.packet_number, first.packet_number}],
          delay: 0
        },
        100
      )

    assert {:error, :not_retransmittable} =
             HandshakeScheduler.retry_crypto(sender, :application, retry.packet_number)

    refute Map.has_key?(
             sender.recovery.spaces.application.sent[retry.packet_number].metadata,
             :bytes
           )
  end

  test "canceling one admitted send removes its queued ranges without affecting another stream" do
    {sender, _} = pair(recovery: Recovery.new(initial_cwnd: 2400))
    {:ok, sender, 4} = HandshakeScheduler.open_stream(sender, :bidi)
    {:ok, sender, _} = HandshakeScheduler.send_stream(sender, 0, :binary.copy("x", 16_384), true)
    assert sender.queued_bytes > 0
    assert {:ok, sender, _} = HandshakeScheduler.reset_stream(sender, 0, 99)

    refute Enum.any?(
             Map.get(sender.pending_control, :application, []),
             &(Map.get(&1, :stream_id) == 0 and &1.type == :stream)
           )

    assert sender.queued_bytes == 0
    assert {:ok, sender, _} = HandshakeScheduler.send_stream(sender, 4, "other")
    assert sender.streams.streams[4].send_offset == 5
  end

  test "ACK before receipt reclaims logical STREAM ranges once receipt arrives" do
    {sender, _} = pair()
    {:ok, sender, [first]} = HandshakeScheduler.send_stream(sender, 0, "payload", true)

    {:ok, sender, _} =
      HandshakeScheduler.receive_ack(
        sender,
        :application,
        %{
          largest: first.packet_number,
          ranges: [{first.packet_number, first.packet_number}],
          delay: 0
        },
        10
      )

    {:ok, sender, [:acked]} =
      HandshakeScheduler.local_send(sender, :application, first.packet_number, :ok, 1)

    assert sender.acked_stream_ranges[0] == [{0, 7}]
    assert MapSet.member?(sender.acked_stream_fins, 0)
    assert sender.recovery.congestion.bytes_in_flight == 0
  end
end

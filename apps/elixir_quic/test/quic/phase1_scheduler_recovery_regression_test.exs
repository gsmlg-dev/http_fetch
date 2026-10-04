defmodule Quic.Phase1SchedulerRecoveryRegressionTest do
  use ExUnit.Case, async: true

  alias Quic.{HandshakeScheduler, Recovery}

  defmodule InitialTLS do
    def new(_, _), do: {:ok, :tls, [{:emit, :initial, <<1, 2, 3>>}]}
    def info(_), do: %{receive_level: :initial}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  defmodule ApplicationTLS do
    def new(role, _) do
      {read, write} = if role == :client, do: {1, 2}, else: {2, 1}

      {:ok, nil,
       for {direction, value} <- [read: read, write: write] do
         %SSL.QUIC.Secret{
           level: :application,
           direction: direction,
           cipher_suite: 0x1301,
           aead: :aes_128_gcm,
           hkdf: :sha256,
           secret: <<value::256>>
         }
       end}
    end

    def info(_), do: %{receive_level: :application}
    def feed(state, _, _), do: {:ok, state, []}
    def abort(state, _), do: state
  end

  test "a congestion-limited CRYPTO retry is retained once for its lost packet" do
    {:ok, state, [first]} =
      HandshakeScheduler.new(:client,
        adapter: InitialTLS,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>
      )

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :initial, first.packet_number, :ok, 0)

    state = put_in(state.recovery.spaces.initial.sent[first.packet_number].status, :lost)
    state = put_in(state.recovery.congestion.cwnd, 0)

    assert {:ok, state, []} =
             HandshakeScheduler.retry_crypto(state, :initial, first.packet_number)

    assert {:error, :not_retransmittable} =
             HandshakeScheduler.retry_crypto(state, :initial, first.packet_number)

    assert [%{level: :initial, offset: 0, bytes: <<1, 2, 3>>}] = state.pending

    recovery = state.recovery

    assert {:ok, ^recovery, []} =
             Quic.Recovery.local_send(recovery, :initial, first.packet_number, :ok, 1)
  end

  test "a fatal suffix does not strand a queued prefix reservation" do
    {:ok, state, _} =
      HandshakeScheduler.new(:client,
        adapter: InitialTLS,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>
      )

    state = %{
      state
      | pending: [
          %{level: :initial, offset: 3, bytes: <<4>>},
          %{level: :handshake, offset: 0, bytes: <<5>>}
        ]
    }

    flight = state.recovery.congestion.bytes_in_flight

    assert {:error, {:unsupported_level, :handshake}, state} = HandshakeScheduler.schedule(state)
    assert state.recovery.spaces.initial.next == 2
    assert state.recovery.spaces.initial.sent[1].status in [:failed, :discarded]
    assert state.recovery.congestion.bytes_in_flight == flight
  end

  test "superseded loss history frees bounded capacity without recycling packet numbers" do
    state = Recovery.new(max_sent_packets: 2, initial_cwnd: 10_000)
    {:ok, state, first} = Recovery.reserve(state, :application, %{crypto: {0, 1}}, 10)
    {:ok, state} = Recovery.transition(state, :application, first.number, :queued)
    {:ok, state, _} = Recovery.local_send(state, :application, first.number, :ok, 0)
    state = put_in(state.spaces.application.sent[first.number].status, :lost)

    {:ok, state, replacement} = Recovery.reserve(state, :application, %{crypto: {0, 1}}, 10)
    {:ok, state} = Recovery.supersede(state, :application, first.number)
    {:ok, state, next} = Recovery.reserve(state, :application, %{crypto: {1, 1}}, 10)

    assert {first.number, replacement.number, next.number} == {0, 1, 2}
    refute Map.has_key?(state.spaces.application.sent, first.number)
    assert Map.has_key?(state.spaces.application.sent, replacement.number)
  end

  test "lost STREAM retries make progress beyond history capacity and a retained late ACK prunes its replacement" do
    {:ok, state, []} =
      HandshakeScheduler.new(:client,
        adapter: ApplicationTLS,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        recovery: Recovery.new(max_sent_packets: 2, initial_cwnd: 24_000)
      )

    {:ok, state, 0} = HandshakeScheduler.open_stream(state, :bidi)
    {:ok, state, [first]} = HandshakeScheduler.send_stream(state, 0, "payload", true)

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, first.packet_number, :ok, 0)

    state = put_in(state.recovery.spaces.application.sent[first.packet_number].status, :lost)

    {:ok, state, [replacement]} =
      HandshakeScheduler.retry_crypto(state, :application, first.packet_number)

    assert state.recovery.spaces.application.sent[first.packet_number].status == :superseded

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, replacement.packet_number, :ok, 1)

    {:ok, state, %{acked: [0]}} =
      HandshakeScheduler.receive_ack(
        state,
        :application,
        %{
          largest: first.packet_number,
          delay: 0,
          ranges: [{first.packet_number, first.packet_number}]
        },
        2
      )

    refute Map.has_key?(
             state.recovery.spaces.application.sent[replacement.packet_number].metadata,
             :control
           )

    {:ok, loss_state} = stream_loss_state()

    {loss_state, packet_number} =
      Enum.reduce(1..12, {loss_state, 0}, fn index, {state, previous} ->
        {:ok, state, [retry]} = HandshakeScheduler.retry_crypto(state, :application, previous)

        {:ok, state, [:sent]} =
          HandshakeScheduler.local_send(state, :application, retry.packet_number, :ok, index + 10)

        state = put_in(state.recovery.spaces.application.sent[retry.packet_number].status, :lost)
        {state, retry.packet_number}
      end)

    assert packet_number > 10
    assert loss_state.recovery.spaces.application.next > packet_number
  end

  test "a long-lived stream accepts a cumulative ACK after terminal history is pruned" do
    {:ok, state, []} =
      HandshakeScheduler.new(:client,
        adapter: ApplicationTLS,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        recovery: Recovery.new(max_sent_packets: 4, initial_cwnd: 1_000_000)
      )

    {:ok, state, 0} = HandshakeScheduler.open_stream(state, :bidi)

    {state, last_packet} =
      Enum.reduce(1..4100, {state, nil}, fn index, {state, _last_packet} ->
        {:ok, state, [packet]} = HandshakeScheduler.send_stream(state, 0, <<index::16>>, false)

        {:ok, state, [:sent]} =
          HandshakeScheduler.local_send(
            state,
            :application,
            packet.packet_number,
            :ok,
            index * 10
          )

        {:ok, state, %{acked: [packet_number]}} =
          HandshakeScheduler.receive_ack(
            state,
            :application,
            %{
              largest: packet.packet_number,
              ranges: [{packet.packet_number, packet.packet_number}]
            },
            index * 10 + 1
          )

        assert packet_number == packet.packet_number
        {state, packet.packet_number}
      end)

    assert last_packet == 4099
    assert state.streams.streams[0].send_offset == 8_200
    assert state.recovery.congestion.bytes_in_flight == 0
    assert map_size(state.recovery.spaces.application.sent) <= 4
    refute Map.has_key?(state.recovery.spaces.application.sent, 0)

    assert {:ok, state, %{acked: [], lost: [], rtt_sample: nil}} =
             HandshakeScheduler.receive_ack(
               state,
               :application,
               %{largest: last_packet, ranges: [{0, last_packet}]},
               50_000
             )

    assert state.recovery.congestion.bytes_in_flight == 0
    assert state.streams.streams[0].send_offset == 8_200
  end

  defp stream_loss_state do
    {:ok, state, []} =
      HandshakeScheduler.new(:client,
        adapter: ApplicationTLS,
        dcid: <<1, 2, 3, 4>>,
        scid: <<5, 6, 7, 8>>,
        recovery: Recovery.new(max_sent_packets: 2, initial_cwnd: 24_000)
      )

    {:ok, state, 0} = HandshakeScheduler.open_stream(state, :bidi)
    {:ok, state, [first]} = HandshakeScheduler.send_stream(state, 0, "retry", false)

    {:ok, state, [:sent]} =
      HandshakeScheduler.local_send(state, :application, first.packet_number, :ok, 0)

    {:ok, put_in(state.recovery.spaces.application.sent[first.packet_number].status, :lost)}
  end
end

defmodule Quic.TLSContinuationRuntimeTest do
  use ExUnit.Case, async: true
  alias Quic.Connection

  defmodule Provider do
    def new(_, _) do
      request = %SSL.QUIC.Request{id: :request, operation: :lookup}
      {:ok, :pending, [{:session_lookup, request}]}
    end

    def info(_), do: %{receive_level: :initial}
    def feed(state, _, _), do: {:ok, state, []}
    def continue(_, :request, result), do: {:ok, result, []}
    def abort(state, _), do: state
  end

  defmodule IO do
    def monotonic_time, do: System.monotonic_time(:microsecond)
    def send(_, _, _), do: {:ok, monotonic_time()}
  end

  defmodule ReadyProvider do
    defdelegate new(role, opts), to: Provider
    defdelegate info(state), to: Provider
    defdelegate feed(state, level, bytes), to: Provider
    defdelegate abort(state, reason), to: Provider

    def continue(_, :request, _) do
      secret = %SSL.QUIC.Secret{
        level: :application,
        direction: :write,
        cipher_suite: 0x1301,
        aead: :aes_128_gcm,
        hkdf: :sha256,
        secret: <<1::256>>
      }

      {:ok, :complete,
       [
         secret,
         {:peer_transport_parameters, <<15, 4, 5, 6, 7, 8>>, :authenticated},
         :handshake_complete
       ]}
    end
  end

  defp pending do
    {:ok, :handshaking, data, _} =
      Connection.init(
        role: :server,
        owner: self(),
        io: {IO, self()},
        remote: {{127, 0, 0, 1}, 4433},
        scheduler: [
          dcid: <<1, 2, 3, 4>>,
          scid: <<1, 2, 3, 4>>,
          adapter: Provider
        ]
      )

    {:keep_state, data, _} = Connection.handle_event(:internal, :start, :handshaking, data)
    assert_receive {:quic_tls_request, _, generation, request, deadline}
    assert deadline <= System.monotonic_time(:millisecond) + 100
    {data, generation, request.id}
  end

  test "authority timeout resumes a full handshake and late, stale and duplicate replies are ignored" do
    {data, generation, id} = pending()

    assert :keep_state_and_data =
             Connection.handle_event(
               :info,
               {:quic_tls_result, make_ref(), id, :miss},
               :handshaking,
               data
             )

    assert {:keep_state, next, _} =
             Connection.handle_event(
               {:timeout, :tls_authority},
               {generation, id},
               :handshaking,
               data
             )

    assert next.pending_tls == nil
    assert next.scheduler.tls.tls == :miss
    assert_receive {:quic_early_release, _, ^generation}

    assert :keep_state_and_data =
             Connection.handle_event(
               :info,
               {:quic_tls_result, generation, id, {:ok, :early_data}},
               :handshaking,
               next
             )

    assert :keep_state_and_data =
             Connection.handle_event(
               {:timeout, :tls_authority},
               {generation, id},
               :handshaking,
               next
             )
  end

  test "a matching result past its absolute deadline is a miss, including quota release" do
    {data, generation, id} = pending()
    data = put_in(data.pending_tls.deadline, System.monotonic_time(:millisecond) - 1)

    assert {:keep_state, next, _} =
             Connection.handle_event(
               :info,
               {:quic_tls_result, generation, id, {:ok, :early_data}},
               :handshaking,
               data
             )

    assert next.scheduler.tls.tls == :miss
    assert_receive {:quic_early_release, _, ^generation}
  end

  test "ready metadata follows parameter validation and precedes retained early readable events" do
    {:ok, :handshaking, data, _} =
      Connection.init(
        role: :server,
        public: true,
        owner: self(),
        io: {IO, self()},
        remote: {{127, 0, 0, 1}, 4433},
        scheduler: [
          dcid: <<1, 2, 3, 4>>,
          scid: <<5, 6, 7, 8>>,
          adapter: ReadyProvider,
          streams: [delivery: :manual]
        ]
      )

    {:keep_state, data, _} = Connection.handle_event(:internal, :start, :handshaking, data)
    assert_receive {:quic_tls_request, _, generation, request, _}

    {:ok, streams, _} =
      Quic.Streams.receive(data.scheduler.streams, %{
        type: :stream,
        stream_id: 0,
        offset: 0,
        data: "retained",
        fin: true
      })

    scheduler = %{
      data.scheduler
      | peer_initial_scid: <<5, 6, 7, 8>>,
        streams: streams,
        early_stream_ids: MapSet.new([0]),
        early_datagrams: [%{type: :datagram, data: "retained-datagram"}]
    }

    assert {:next_state, :established, next, _} =
             Connection.handle_event(
               :info,
               {:quic_tls_result, generation, request.id, :miss},
               :handshaking,
               %{data | scheduler: scheduler}
             )

    assert_receive {:quic_ready, _, ^generation, %{parameters_valid: true, quic_confirmed: true}}

    assert [
             {:ready, %{parameters_valid: true}},
             {:stream_open, _, :bidi},
             {:readable, _},
             :datagram_readable
           ] = next.events

    assert next.ready and next.parameters_valid
  end
end

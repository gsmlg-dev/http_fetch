defmodule Quic.StreamsTest do
  use ExUnit.Case, async: true

  alias Quic.Streams

  test "stream IDs encode role and direction and enforce local permissions" do
    state = Streams.new(:client, peer_max_streams_bidi: 1, peer_max_streams_uni: 1)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:blocked, %{type: :streams_blocked_bidi}} = Streams.open(state, :bidi)
    assert {:ok, state, 2} = Streams.open(state, :uni)

    assert {:ok, state, _} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 3,
               offset: 0,
               data: <<1>>,
               fin: false
             })

    assert {:error, :send_on_receive_only_stream} = Streams.send(state, 3, <<2>>)
  end

  test "out of order stream data is reassembled and FIN is exact" do
    state = Streams.new(:client, max_buffer: 32)
    assert {:ok, state, 0} = Streams.open(state, :bidi)

    assert {:ok, state, []} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 0,
               offset: 3,
               data: "def",
               fin: true
             })

    assert {:ok, _state, events} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 0,
               offset: 0,
               data: "abc",
               fin: false
             })

    assert events == [{:data, 0, "abc"}, {:data, 0, "def"}, {:fin, 0}]
  end

  test "flow control, final-size and overlap violations are explicit" do
    state = Streams.new(:client, peer_max_data: 3, peer_max_stream_data: 3)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:blocked, %{type: :data_blocked}} = Streams.send(state, 0, "abcd")
    assert {:ok, state, _} = Streams.send(state, 0, "abc", true)
    assert {:error, :final_size_error} = Streams.send(state, 0, <<>>, false)

    assert {:ok, _state, []} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 1,
               offset: 1,
               data: "x",
               fin: false
             })
  end

  test "reset and stop sending cancel one stream" do
    state = Streams.new(:client)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:ok, state, [{:reset, 0, 9, 0}]} = Streams.reset(state, 0, 9, 0)

    assert {:ok, _state, %{type: :stop_sending, stream_id: 0, error_code: 10}} =
             Streams.stop_sending(state, 0, 10)
  end

  test "manual delivery keeps a bounded ready queue until consumption" do
    state = Streams.new(:client, delivery: :manual, max_ready_bytes: 3)

    assert {:ok, state, 0} = Streams.open(state, :bidi)

    assert {:ok, state, []} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 0,
               offset: 0,
               data: "abc",
               fin: false
             })

    assert state.ready_bytes == 3

    assert {:error, :flow_control} =
             Streams.receive(state, %{
               type: :stream,
               stream_id: 0,
               offset: 3,
               data: "d",
               fin: false
             })

    assert {:ok, state, [{:data, 0, "abc"}]} = Streams.consume(state, 0, 3)
    assert state.ready_bytes == 0
  end

  test "invalid manual delivery limits fall back to immediate mode" do
    state = Streams.new(:client, delivery: :invalid)
    assert state.delivery == :immediate
  end

  test "allocates each local stream class from its protocol-defined sequence" do
    client = Streams.new(:client, peer_max_streams_bidi: 3, peer_max_streams_uni: 3)
    assert {:ok, client, 0} = Streams.open(client, :bidi)
    assert {:ok, client, 2} = Streams.open(client, :uni)
    assert {:ok, client, 4} = Streams.open(client, :bidi)
    assert {:ok, _client, 6} = Streams.open(client, :uni)

    server = Streams.new(:server, peer_max_streams_bidi: 3, peer_max_streams_uni: 3)
    assert {:ok, server, 1} = Streams.open(server, :bidi)
    assert {:ok, server, 3} = Streams.open(server, :uni)
    assert {:ok, server, 5} = Streams.open(server, :bidi)
    assert {:ok, _server, 7} = Streams.open(server, :uni)
  end

  test "continues an existing peer stream when its class limit is reached" do
    state = Streams.new(:client, max_streams_bidi: 1)

    assert {:ok, state, [{:data, 1, "a"}]} = receive_stream(state, 1, 0, "a")
    assert {:ok, _state, [{:data, 1, "b"}]} = receive_stream(state, 1, 1, "b")
    assert {:error, :stream_limit} = receive_stream(state, 5, 0, "c")
  end

  test "opens sparse peer streams without materializing implicit predecessors" do
    state = Streams.new(:client, max_streams_bidi: 3)

    assert {:ok, state, [{:data, 9, "x"}]} = receive_stream(state, 9, 0, "x")
    assert Map.keys(state.streams) == [9]
    assert {:error, :stream_limit} = receive_stream(state, 13, 0, "y")
  end

  test "reassembles reordered overlapping frames and ignores delivered duplicates" do
    state = Streams.new(:client, max_buffer: 32)

    assert {:ok, state, []} = receive_stream(state, 1, 3, "def")

    assert {:ok, state, [{:data, 1, "abc"}, {:data, 1, "def"}]} =
             receive_stream(state, 1, 0, "abcde")

    assert {:ok, state, []} = receive_stream(state, 1, 0, "abcdef")
    assert {:ok, _state, []} = receive_stream(state, 1, 1, "bc")
  end

  test "rejects conflicting overlaps that are still buffered" do
    state = Streams.new(:client, max_buffer: 32)
    assert {:ok, state, []} = receive_stream(state, 1, 2, "cde")
    assert {:error, :overlap_conflict} = receive_stream(state, 1, 3, "X")
  end

  test "does not charge an exact buffered duplicate against the receive buffer" do
    state = Streams.new(:client, max_buffer: 3)
    assert {:ok, state, []} = receive_stream(state, 1, 3, "def")
    assert {:ok, _state, []} = receive_stream(state, 1, 3, "def")
  end

  test "installs peer parameters with zero defaults and sender-perspective stream windows" do
    state = Streams.new(:client)
    state = Streams.install_peer_parameters(state, %{})
    assert state.peer_max_data == 0
    assert state.peer_max_streams_bidi == 0
    assert state.peer_max_streams_uni == 0

    state =
      Streams.install_peer_parameters(state, %{
        initial_max_data: 123,
        initial_max_streams_bidi: 2,
        initial_max_streams_uni: 3,
        initial_max_stream_data_bidi_local: 11,
        initial_max_stream_data_bidi_remote: 22,
        initial_max_stream_data_uni: 33
      })

    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:ok, state, 2} = Streams.open(state, :uni)
    assert {:ok, state, []} = receive_stream(state, 1, 0, <<>>)
    assert state.streams[0].send_limit == 22
    assert state.streams[1].send_limit == 11
    assert state.streams[2].send_limit == 33
  end

  test "charges connection credit once by each stream high-water mark, including reset final size" do
    state = Streams.new(:client, max_data: 5, max_buffer: 5)
    assert {:ok, state, []} = receive_stream(state, 1, 3, "de")
    assert state.data_received == 5
    assert {:ok, state, []} = receive_stream(state, 1, 3, "de")
    assert state.data_received == 5
    assert {:error, :flow_control} = receive_stream(state, 5, 0, "x")

    reset_state = Streams.new(:client, max_data: 4, max_buffer: 4)
    assert {:ok, reset_state, [{:reset, 1, 9, 4}]} = Streams.receive_reset(reset_state, 1, 9, 4)
    assert reset_state.data_received == 4
    assert {:ok, reset_state, []} = Streams.receive_reset(reset_state, 1, 9, 4)
    assert reset_state.data_received == 4
  end

  test "keeps accounted receive credit separate from delivered bytes" do
    state = Streams.new(:client, max_data: 2)
    assert {:ok, state, [{:data, 1, "a"}]} = receive_stream(state, 1, 0, "a")
    assert state.data_received == 1
    assert state.data_delivered == 1
  end

  test "splits manual reads and coalesces consumption-driven credit updates" do
    state =
      Streams.new(:client,
        delivery: :manual,
        max_data: 6,
        max_stream_data: 6,
        max_buffer: 6,
        max_ready_bytes: 6
      )

    assert {:ok, state, []} = receive_stream(state, 1, 0, "abcdef")
    assert {:ok, state, [{:data, 1, "ab"}]} = Streams.consume(state, 1, 2)
    assert {:ok, state, [{:data, 1, "cd"}]} = Streams.consume(state, 1, 2)
    assert {:ok, state, [{:data, 1, "ef"}]} = Streams.consume(state, 1, 2)
    {state, frames} = Streams.take_credit(state)
    assert %{type: :max_data, value: 12} in frames
    assert %{type: :max_stream_data, stream_id: 1, value: 12} in frames
    assert state.pending_credit == %{}
  end

  test "bounds retained sparse stream records while preserving existing peer streams" do
    state = Streams.new(:client, max_streams_bidi: 3, max_stream_records: 1)
    assert {:ok, state, [{:data, 1, "a"}]} = receive_stream(state, 1, 0, "a")
    assert {:ok, state, [{:data, 1, "b"}]} = receive_stream(state, 1, 1, "b")
    assert {:error, :stream_limit} = receive_stream(state, 5, 0, "c")
  end

  test "releases a peer stream slot only after its terminal event is consumed" do
    state = Streams.new(:client, delivery: :manual, max_streams_bidi: 1)
    assert {:ok, state, []} = receive_stream(state, 1, 0, "a", true)
    assert {:error, :stream_limit} = receive_stream(state, 5, 0, "b")
    assert {:ok, state, [{:data, 1, "a"}, {:fin, 1}]} = Streams.consume(state, 1, 1)
    {state, frames} = Streams.take_credit(state)
    assert %{type: :max_streams_bidi, value: 2} in frames
    assert {:ok, _state, []} = receive_stream(state, 5, 0, "b")
  end

  test "releases reset final-size connection credit once its reset event is consumed" do
    state = Streams.new(:client, delivery: :manual, max_data: 4)
    assert {:ok, state, []} = Streams.receive_reset(state, 1, 7, 4)
    assert {:ok, state, [{:reset, 1, 7, 4}]} = Streams.consume(state, 1, 1)
    {state, frames} = Streams.take_credit(state)
    assert %{type: :max_data, value: 8} in frames
    assert state.data_consumed == 4
  end

  test "rejects a reset final size beyond its stream receive window" do
    state = Streams.new(:client, max_data: 8, max_stream_data: 4)
    assert {:error, :flow_control} = Streams.receive_reset(state, 1, 7, 5)
  end

  test "bounds manual receive credit and peer stream classes by retained capacity" do
    state =
      Streams.new(:client, delivery: :manual, max_data: 100, max_buffer: 4, max_ready_bytes: 3)

    assert state.max_data == 3

    state = Streams.new(:client, max_streams_bidi: 3, max_streams_uni: 3, max_stream_records: 4)
    assert state.max_streams_bidi + state.max_streams_uni <= 4
  end

  test "keeps bidirectional send and receive FIN states independent" do
    state = Streams.new(:client)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:ok, state, %{type: :stream, fin: true}} = Streams.send(state, 0, "request", true)
    assert {:error, :final_size_error} = Streams.send(state, 0, "again")

    assert {:ok, _state, [{:data, 0, "response"}, {:fin, 0}]} =
             receive_stream(state, 0, 0, "response", true)
  end

  test "responds to peer STOP_SENDING with one RESET_STREAM without affecting other streams" do
    state = Streams.new(:client)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:ok, state, 4} = Streams.open(state, :bidi)
    assert {:ok, state, _} = Streams.send(state, 0, "ab")

    assert {:ok, state, %{type: :reset_stream, stream_id: 0, error_code: 9, final_size: 2}} =
             Streams.peer_stop_sending(state, 0, 9)

    assert {:ok, _state, %{type: :stream, stream_id: 4}} = Streams.send(state, 4, "ok")
    assert {:error, :stopped} = Streams.send(state, 0, "later")
    assert {:ok, _state, nil} = Streams.peer_stop_sending(state, 0, 9)
  end

  test "reset_send reports the admitted final size and local STOP_SENDING leaves bidi sending open" do
    state = Streams.new(:client)
    assert {:ok, state, 0} = Streams.open(state, :bidi)
    assert {:ok, state, _} = Streams.send(state, 0, "abc")

    assert {:ok, state, %{type: :reset_stream, stream_id: 0, error_code: 12, final_size: 3}} =
             Streams.reset_send(state, 0, 12)

    assert {:error, :stopped} = Streams.send(state, 0, "later")
    assert {:ok, _state, nil} = Streams.reset_send(state, 0, 12)

    state = Streams.new(:client)
    assert {:ok, state, 0} = Streams.open(state, :bidi)

    assert {:ok, state, %{type: :stop_sending, stream_id: 0, error_code: 8}} =
             Streams.stop_sending(state, 0, 8)

    assert {:ok, _state, %{type: :stream, stream_id: 0}} = Streams.send(state, 0, "still-send")
  end

  test "local STOP_SENDING discards unread receive data and returns only connection credit" do
    state = Streams.new(:client, delivery: :manual, max_data: 4, max_stream_data: 4)
    assert {:ok, state, []} = receive_stream(state, 1, 0, "abcd")
    assert {:ok, state, %{type: :stop_sending}} = Streams.stop_sending(state, 1, 5)
    {state, frames} = Streams.take_credit(state)
    assert %{type: :max_data, value: 8} in frames
    refute Enum.any?(frames, &match?(%{type: :max_stream_data}, &1))
    assert state.ready == %{}
  end

  test "emits one FIN and rejects final sizes below received high water" do
    state = Streams.new(:client, max_buffer: 32)
    assert {:ok, state, []} = receive_stream(state, 1, 3, "def")
    assert {:error, :final_size_error} = receive_stream(state, 1, 0, "abc", true)

    assert {:ok, state, [{:data, 1, "abc"}, {:data, 1, "def"}]} =
             receive_stream(state, 1, 0, "abc", false)

    assert {:ok, state, [{:fin, 1}]} = receive_stream(state, 1, 6, <<>>, true)
    assert {:ok, _state, []} = receive_stream(state, 1, 6, <<>>, true)
  end

  test "handles FIN-only frames and emits a reset terminal event once" do
    state = Streams.new(:client)
    assert {:ok, state, [{:fin, 1}]} = receive_stream(state, 1, 0, <<>>, true)
    assert {:ok, _state, []} = receive_stream(state, 1, 0, <<>>, true)

    state = Streams.new(:client)
    assert {:ok, state, [{:reset, 1, 9, 4}]} = Streams.receive_reset(state, 1, 9, 4)
    assert {:ok, state, []} = Streams.receive_reset(state, 1, 9, 4)
    assert {:ok, _state, []} = receive_stream(state, 1, 0, "drop")
    assert {:error, :final_size_error} = receive_stream(state, 1, 4, "x")
  end

  defp receive_stream(state, id, offset, data, fin \\ false) do
    Streams.receive(state, %{type: :stream, stream_id: id, offset: offset, data: data, fin: fin})
  end
end

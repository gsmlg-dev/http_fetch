defmodule QuicHttp3.CreditTest do
  use ExUnit.Case, async: true
  alias Quic.Streams
  alias QuicHttp3.{Frame, Qpack, Session}

  # Use real QUIC whole-binary admission at the Session transport boundary.
  defmodule Transport do
    def connect(_, _, _), do: {:ok, :connection}
    def ready(_, _), do: :ready

    def open_stream(_, kind, _) do
      {:ok, state, id} = Streams.open(Process.get(:streams), kind)
      Process.put(:streams, state)
      {:ok, id}
    end

    def send_stream(id, bytes, fin, opts) do
      send(self(), {:attempt, id, bytes, fin, opts})

      case Streams.send(Process.get(:streams), id, bytes, fin) do
        {:ok, state, frame} ->
          state =
            if Process.get(:grant_credit) do
              stream = state.streams[id]
              limit = max(stream.send_limit, stream.send_offset + 16_384)
              state = put_in(state.streams[id].send_limit, limit)
              %{state | peer_max_data: state.data_sent + 16_384}
            else
              state
            end

          Process.put(:streams, state)
          send(self(), {:admitted, frame})

          if Process.delete(:unknown_next) do
            Process.put(:operation_result, %{status: :admitted, result: {:ok, opts[:ref]}})
            {:unknown, opts[:ref]}
          else
            {:ok, opts[:ref]}
          end

        failure ->
          if Process.delete(:unknown_rejection) do
            Process.put(:operation_result, %{status: :rejected, result: failure})
            {:unknown, opts[:ref]}
          else
            failure
          end
      end
    end

    def operation_status(_, _, _), do: Process.get(:operation_result, :unknown)
  end

  setup do
    Process.put(:streams, Streams.new(:client, peer_max_stream_data: 16_384))
    {:ok, session} = Session.new(transport: Transport)
    {:ok, session} = Session.connect(session, {127, 0, 0, 1}, 443, [])
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/tiny-upload"}], :stream, [])
    _ = calls()
    %{session: session, ref: ref}
  end

  test "16KiB chunks progress through residual stream credit without replay", context do
    Process.put(:grant_credit, true)
    chunk = :binary.copy(<<0, 255, 42, 13>>, 4_096)

    session =
      Enum.reduce(1..64, context.session, fn index, session ->
        assert {:ok, next} = Session.send_data(session, context.ref, chunk, index == 64, [])
        next
      end)

    frames = admitted(calls())
    wire = IO.iodata_to_binary(Enum.map(frames, & &1.data))
    assert wire == :binary.copy(Frame.encode!(:data, chunk), 64)
    assert Enum.count(frames, & &1.fin) == 1
    assert List.last(frames).fin
    assert session.requests[context.ref].upload == :closed
    assert_offsets(frames)
  end

  test "zero connection credit blocks one byte and retains suffix and deadline", context do
    state = Process.get(:streams)
    Process.put(:streams, %{state | peer_max_data: state.data_sent + 5})
    bytes = :binary.copy(<<17>>, 16_384)

    assert {:blocked, session, %{type: :data_blocked}} =
             Session.send_data(context.session, context.ref, bytes, true, timeout: 5_000)

    deadline = session.work.deadline
    assert session.pending.deadline == deadline
    assert {:send, _, <<_>>, false} = session.pending.action
    initial = admitted(calls())
    assert IO.iodata_length(Enum.map(initial, & &1.data)) == 5
    assert length(session.work.steps) <= 15
    assert {:blocked, session, _} = Session.resume(session)
    assert session.work.deadline == deadline
    assert [{:attempt, _, <<_>>, false, _}] = calls()

    state = Process.get(:streams)
    Process.put(:streams, %{state | peer_max_data: state.data_sent + 65_536})
    Process.put(:grant_credit, true)
    assert {:ok, _} = Session.resume(session)
    frames = initial ++ admitted(calls())
    assert IO.iodata_to_binary(Enum.map(frames, & &1.data)) == Frame.encode!(:data, bytes)
    assert Enum.count(frames, & &1.fin) == 1
    assert_offsets(frames)
  end

  test "unknown admitted prefix is reconciled without splitting or replay", context do
    Process.put(:unknown_next, true)
    bytes = :binary.copy(<<42>>, 16_384)

    assert {:unknown, session, operation_ref} =
             Session.send_data(context.session, context.ref, bytes, true, [])

    initial = admitted(calls())
    assert length(initial) == 1
    assert byte_size(hd(initial).data) < 16_384
    assert session.pending.ref == operation_ref
    deadline = session.work.deadline
    Process.put(:operation_result, :unknown)
    assert {:unknown, ^session, ^operation_ref} = Session.resume(session)
    assert session.pending.deadline == deadline
    assert calls() == []

    state = Process.get(:streams)
    Process.put(:streams, %{state | peer_max_data: state.data_sent + 65_536})
    Process.put(:grant_credit, true)
    Process.put(:operation_result, %{status: :admitted, result: {:ok, operation_ref}})
    assert {:ok, next} = Session.resume(session)
    assert next.pending == nil
    assert next.requests[context.ref].upload == :closed
    frames = initial ++ admitted(calls())
    assert IO.iodata_to_binary(Enum.map(frames, & &1.data)) == Frame.encode!(:data, bytes)
    assert Enum.count(frames, & &1.fin) == 1
    assert_offsets(frames)
  end

  test "expired original deadline prevents any suffix attempt", context do
    state = Process.get(:streams)
    Process.put(:streams, %{state | peer_max_data: state.data_sent})

    assert {:blocked, session, _} =
             Session.send_data(context.session, context.ref, "bytes", true, [])

    _ = calls()
    session = put_in(session.pending.deadline, System.monotonic_time(:millisecond) - 1)
    assert {:error, _, :deadline_expired} = Session.resume(session)
    assert calls() == []
  end

  test "unknown rejection waits for reconciliation before fragmentation", context do
    bytes = :binary.copy("x", 16_384)
    Process.put(:unknown_rejection, true)

    assert {:unknown, session, operation_ref} =
             Session.send_data(context.session, context.ref, bytes, true, [])

    assert [{:attempt, _, fragment, false, _}] = calls()
    assert byte_size(fragment) == 16_384
    assert session.pending.status == :unknown
    assert session.pending.ref == operation_ref
    Process.put(:grant_credit, true)
    assert {:ok, next} = Session.resume(session)
    assert next.pending == nil
    assert next.requests[context.ref].upload == :closed
    frames = admitted(calls())
    assert IO.iodata_to_binary(Enum.map(frames, & &1.data)) == Frame.encode!(:data, bytes)
    assert Enum.count(frames, & &1.fin) == 1
    assert_offsets(frames)
  end

  test "large HEADERS and final body use the same residual-credit admission", context do
    state = Process.get(:streams)
    Process.put(:streams, %{state | peer_max_data: state.data_sent + 5})
    Process.put(:grant_credit, true)
    fields = [{":path", "/headers"}, {"x-large", :binary.copy("h", 20_000)}]
    {:ok, block} = Qpack.encode_header_block(fields)
    body = :binary.copy("b", 16_384)
    assert {:ok, _, _} = Session.request(context.session, fields, body, [])
    frames = admitted(calls())

    assert IO.iodata_to_binary(Enum.map(frames, & &1.data)) ==
             Frame.encode!(:headers, block) <> Frame.encode!(:data, body)

    assert Enum.count(frames, & &1.fin) == 1
    assert_offsets(frames)
  end

  defp admitted(calls), do: for({:admitted, frame} <- calls, do: frame)

  defp assert_offsets(frames) do
    Enum.reduce(frames, hd(frames).offset, fn frame, offset ->
      assert frame.offset == offset
      offset + byte_size(frame.data)
    end)
  end

  defp calls(acc \\ []) do
    receive do
      call -> calls([call | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end

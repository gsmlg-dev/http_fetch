defmodule QuicHttp3.SessionTest do
  use ExUnit.Case, async: true
  alias QuicHttp3.{Frame, Qpack, Session, Settings}

  defmodule Transport do
    def connect(_, _, _), do: {:ok, :connection}
    def ready(_, _), do: :ready
    def open_stream(_, kind, _), do: send_call({:open, kind}, {:ok, {:stream, kind}})
    def send_stream(stream, bytes, fin, _), do: send_call(:send, {:ok, {stream, bytes, fin}})
    def events(_, _, _), do: Process.get(:events, {:ok, []})

    def read(_, _, _) do
      result = Process.get(:read, {:ok, []})
      Process.put(:read, {:ok, []})
      result
    end

    def stop_stream(_, _, _), do: :ok
    def reset_stream(_, _, _), do: {:ok, make_ref()}
    def cleanup(_), do: :ok
    def close(_, _, _, _), do: :ok

    defp send_call(key, result) do
      send(Process.get(:owner), {key, result})
      result
    end
  end

  setup do
    Process.put(:owner, self())
    {:ok, session} = Session.new(transport: Transport, max_frame: 64)
    {:ok, session} = Session.connect(session, {127, 0, 0, 1}, 443, [])
    {:ok, session: session}
  end

  test "opens control stream without FIN and requests with final data FIN", %{session: session} do
    assert {:ok, session} = Session.open(session)
    assert_received {{:open, :uni}, {:ok, {:stream, :uni}}}
    assert_received {:send, {:ok, {{:stream, :uni}, _bytes, false}}}
    assert {:ok, _session, _ref} = Session.request(session, [{":path", "/"}], "body", [])
    assert_received {{:open, :bidi}, {:ok, {:stream, :bidi}}}
    assert_received {:send, {:ok, {{:stream, :bidi}, _headers, false}}}
    assert_received {:send, {:ok, {{:stream, :bidi}, "body", true}}}
  end

  test "partial response frames are retained across reads", %{session: session} do
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    {:ok, header_block} = Qpack.encode_header_block([{":status", "200"}], indexed: true)
    frame = Frame.encode!(:headers, header_block) <> Frame.encode!(:data, "ok")
    Process.put(:events, {:ok, [{:readable, {:stream, :bidi}}]})
    Process.put(:read, {:ok, [{:data, binary_part(frame, 0, 2)}]})
    assert {:ok, session, []} = Session.poll(session, 8)
    Process.put(:events, {:ok, [{:readable, {:stream, :bidi}}]})
    Process.put(:read, {:ok, [{:data, binary_part(frame, 2, byte_size(frame) - 2)}, {:fin}]})
    assert {:ok, _session, events} = Session.poll(session, 8)
    assert Enum.any?(events, &(&1 == {:data, ref, "ok"}))
    assert Enum.any?(events, &(&1 == {:done, ref}))
  end

  test "unknown transport events are explicit errors", %{session: session} do
    Process.put(:events, {:ok, [{:mystery}]})
    assert {:error, _session, :invalid_transport_event} = Session.poll(session, 8)
  end

  test "consumes opaque peer control streams and normal transport events", %{session: session} do
    {:ok, session} = Session.open(session)
    peer = {:stream, :peer_control}
    settings = <<0>> <> Frame.encode!(:settings, Settings.encode!([]))

    Process.put(
      :events,
      {:ok, [:ready, {:stream_open, peer, :uni}, :writable, {:readable, peer}]}
    )

    Process.put(:read, {:ok, [{:data, 3, settings}]})

    assert {:ok, _session, events} = Session.poll(session, 8)
    assert :ready in events
    assert :writable in events
    assert {:settings, []} in events
  end
end

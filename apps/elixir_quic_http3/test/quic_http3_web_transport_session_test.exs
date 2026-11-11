defmodule QuicHttp3.WebTransportSessionTest do
  use ExUnit.Case, async: true
  alias HTTP.H3.{Capsule, Datagram}
  alias HTTP.H3.WebTransport.Draft17
  alias QuicHttp3.{Control, Frame, Qpack, Session}
  alias QuicHttp3.Transport.Quic.Stream, as: TStream

  defmodule Transport do
    alias QuicHttp3.Transport.Quic.Stream, as: TStream

    def open_stream(_, kind, opts) do
      send(self(), {:open, kind, Keyword.get(opts, :reliable_prefix)})
      {next, ids} = Process.get(:ids, {0, %{bidi: 0, uni: 2}})
      id = ids[kind]
      Process.put(:ids, {next, %{ids | kind => id + 4}})
      {:ok, %TStream{handle: %{id: id}}}
    end

    def send_stream(stream, bytes, fin, _), do: record({:send, stream.handle.id, bytes, fin})

    def reset_stream_at(stream, code, size, _),
      do: record({:reset_at, stream.handle.id, code, size})

    def reset_stream(stream, code, _), do: record({:reset, stream.handle.id, code})
    def stop_stream(stream, code, _), do: record({:stop, stream.handle.id, code})
    def send_datagram(_, bytes, _), do: record({:datagram, bytes})

    def close(_, code, reason, _) do
      send(self(), {:close, code, reason})
      :ok
    end

    def read_datagrams(_, _, _), do: {:ok, Process.delete(:datagrams) || []}
    def events(_, _, _), do: {:ok, Process.delete(:events) || []}
    def info(_), do: Process.get(:info)

    def read(stream, _, _) do
      items = Process.get({:items, stream.handle.id}, [])
      Process.delete({:items, stream.handle.id})
      {:ok, items}
    end

    defp record(event) do
      send(self(), event)
      {:ok, make_ref()}
    end
  end

  @fields [
    {":method", "CONNECT"},
    {":scheme", "https"},
    {":authority", "example.test"},
    {":path", "/wt"}
  ]
  @server [{8, 1}, {0x33, 1}, {0x20B8933B, 1}]
  @info {:ok,
         %{
           reliable_reset: %{draft: 11, local: true, peer: true, negotiated: true},
           datagram: %{send_max_bytes: 1197}
         }}

  defp session(peer_settings \\ @server, opts \\ [webtransport: true]) do
    Process.put(:info, @info)
    {:ok, session} = Session.new([transport: Transport] ++ opts)
    {:ok, control} = Control.new(:client)
    control = %{control | received_settings?: true, peer_settings: peer_settings}
    %{session | connection: :connection, control: control, open?: true}
  end

  defp accepted do
    {:ok, session, ref} = Session.extended_connect(session(), "webtransport-h3", @fields)
    assert_received {:send, 0, _headers, false}
    {:ok, block} = Qpack.encode_header_block([{":status", "200"}])
    Process.put({:items, 0}, [{:data, 0, Frame.encode!(:headers, block)}])
    Process.put(:events, [{:readable, %TStream{handle: %{id: 0}}}])
    {:ok, session, events} = Session.poll(session, 8)
    assert [{:headers, ^ref, _}] = events
    {session, ref}
  end

  test "draft-17 client SETTINGS are advertised only when WebTransport is enabled" do
    {:ok, plain} = Session.new()
    {:ok, wt} = Session.new(webtransport: true)
    assert plain.wt == nil
    assert wt.wt.router.phase == :new
    assert {:error, :invalid_session_options} = Session.new(webtransport: :yes)

    {:ok, control} = Control.new(:client, [{1, 0}] ++ Draft17.client_settings())
    assert {0x20B8933B, 1} in control.local_settings
    assert {0x33, 1} in control.local_settings
  end

  test "CONNECT is refused before any bytes without the full negotiated profile" do
    assert {:error, _, :webtransport_not_enabled} =
             Session.extended_connect(session(@server, []), "webtransport-h3", @fields)

    assert {:error, _, :webtransport_draft17_not_enabled} =
             Session.extended_connect(session([{8, 1}, {0x33, 1}]), "webtransport-h3", @fields)

    assert {:error, _, :h3_datagram_disabled} =
             Session.extended_connect(
               session([{8, 1}, {0x20B8933B, 1}]),
               "webtransport-h3",
               @fields
             )

    base = session()

    Process.put(
      :info,
      {:ok,
       %{
         reliable_reset: %{draft: 11, local: true, peer: false, negotiated: false},
         datagram: %{send_max_bytes: 1197}
       }}
    )

    assert {:error, _, :reliable_reset_not_negotiated} =
             Session.extended_connect(base, "webtransport-h3", @fields)

    Process.put(
      :info,
      {:ok,
       %{
         reliable_reset: %{draft: 11, local: true, peer: true, negotiated: true},
         datagram: %{send_max_bytes: 0}
       }}
    )

    assert {:error, _, :quic_datagram_not_negotiated} =
             Session.extended_connect(base, "webtransport-h3", @fields)

    refute_received {:send, _, _, _}
  end

  test "one session per connection; streams carry the prefix and reset keeps it reliable" do
    {session, _ref} = accepted()

    assert {:error, _, :webtransport_session_capacity} =
             Session.extended_connect(session, "webtransport-h3", @fields)

    assert {:ok, %{session_id: 0, max_datagram_payload: 1196}} =
             Session.webtransport_info(session)

    assert {:ok, session, 2} = Session.webtransport_open(session, :uni)
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    uni_size = byte_size(prefix)
    # The WT prefix is declared reliable so a peer STOP_SENDING keeps it.
    assert_received {:open, :uni, ^uni_size}
    assert_received {:send, 2, ^prefix, false}
    assert {:ok, session} = Session.webtransport_send(session, 2, "abc", false)
    assert_received {:send, 2, "abc", false}
    assert {:ok, session} = Session.webtransport_reset(session, 2, 42)
    {:ok, code} = Draft17.application_error(42)
    size = byte_size(prefix)
    assert_received {:reset_at, 2, ^code, ^size}
    assert {:error, _, :unknown_stream} = Session.webtransport_send(session, 2, "late", false)

    assert {:ok, session, 4} = Session.webtransport_open(session, :bidi)
    {:ok, bidi} = Draft17.prefix(:bidi, 0)
    bidi_size = byte_size(bidi)
    assert_received {:open, :bidi, ^bidi_size}
    assert_received {:send, 4, ^bidi, false}
    assert {:ok, session} = Session.webtransport_stop(session, 4, 7)
    {:ok, stop} = Draft17.application_error(7)
    assert_received {:stop, 4, ^stop}
    assert {:ok, _} = Session.webtransport_send(session, 4, "", true)
    assert_received {:send, 4, "", true}
  end

  test "peer streams and datagrams are delivered with credit receipts" do
    {session, ref} = accepted()
    peer_uni = %TStream{handle: %{id: 3}}
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    {:ok, wire} = Datagram.encode(0, "dg", 1200)
    Process.put({:items, 3}, [{:data, 3, prefix <> "hi"}, {:fin, 3}])
    Process.put(:datagrams, [wire])

    Process.put(:events, [
      {:stream_open, peer_uni, :uni},
      {:readable, peer_uni},
      :datagram_readable
    ])

    {:ok, session, events} = Session.poll(session, 8)

    assert [{:wt, ^ref, {:datagram, "dg", r1}}, {:wt, ^ref, {:stream, 3, :uni, "hi", true, r2}}] =
             Enum.sort(events)

    assert session.wt.router.retained_bytes == 4
    assert {:ok, session} = Session.webtransport_acknowledge(session, r1)
    assert {:ok, session} = Session.webtransport_acknowledge(session, r2)
    assert {:error, :unknown_receipt} = Session.webtransport_acknowledge(session, r2)
    assert session.wt.router.retained_bytes == 0
    assert session.wt.streams == %{}
  end

  test "close and drain capsules on the CONNECT stream become session events" do
    {session, ref} = accepted()
    {:ok, drain} = Capsule.encode(0x78AE, <<>>)
    {:ok, close} = Draft17.close_capsule(5, "done")
    {:ok, unknown} = Capsule.encode(0x190B4D3B, "ignored")
    Process.put({:items, 0}, [{:data, 0, Frame.encode!(:data, drain <> unknown <> close)}])
    Process.put(:events, [{:readable, %TStream{handle: %{id: 0}}}])
    {:ok, session, events} = Session.poll(session, 8)
    assert [{:wt, ^ref, :drain}, {:wt, ^ref, {:close, 5, "done"}}] = events
    assert {:ok, _} = Session.webtransport_close(session, 1, "bye")
    {:ok, capsule} = Draft17.close_capsule(1, "bye")
    frame = Frame.encode!(:data, capsule)
    assert_received {:send, 0, ^frame, true}
  end

  @gone 0x170D7B68

  test "rejected peer bidirectional streams leave no session state behind" do
    {session, _ref} = accepted()
    {:ok, foreign} = Draft17.prefix(:bidi, 4)

    session =
      Enum.reduce(Enum.map(0..39, &(4 * &1 + 1)), session, fn id, session ->
        stream = %TStream{handle: %{id: id}}
        Process.put({:items, id}, [{:data, id, foreign <> "x"}])
        Process.put(:events, [{:stream_open, stream, :bidi}, {:readable, stream}])
        assert {:ok, session, []} = Session.poll(session, 8)
        assert_received {:reset, ^id, _code}
        assert_received {:stop, ^id, _code}
        session
      end)

    assert session.wt.streams == %{}
    assert MapSet.size(session.retired) == 40
  end

  test "closing the session resets and stops every associated stream with WT_SESSION_GONE" do
    {session, _ref} = accepted()
    {:ok, session, 2} = Session.webtransport_open(session, :uni)
    {:ok, session, 4} = Session.webtransport_open(session, :bidi)
    {:ok, prefix} = Draft17.prefix(:bidi, 0)
    peer = %TStream{handle: %{id: 1}}
    Process.put({:items, 1}, [{:data, 1, prefix <> "hi"}])
    Process.put(:events, [{:stream_open, peer, :bidi}, {:readable, peer}])
    {:ok, session, [{:wt, _, {:stream, 1, :bidi, "hi", false, _}}]} = Session.poll(session, 8)
    flush()

    assert {:ok, session} = Session.webtransport_close(session, 0, "")
    {:ok, uni_prefix} = Draft17.prefix(:uni, 0)
    uni_size = byte_size(uni_prefix)
    bidi_size = byte_size(prefix)
    assert_received {:send, 0, _capsule, true}
    assert_received {:reset_at, 2, @gone, ^uni_size}
    assert_received {:reset_at, 4, @gone, ^bidi_size}
    assert_received {:stop, 4, @gone}
    assert_received {:reset, 1, @gone}
    assert_received {:stop, 1, @gone}
    assert session.wt.streams == %{}
  end

  test "the CONNECT stream ending resets and stops every associated stream" do
    {session, _ref} = accepted()
    {:ok, session, 4} = Session.webtransport_open(session, :bidi)
    flush()
    Process.put({:items, 0}, [{:fin, 0}])
    Process.put(:events, [{:readable, %TStream{handle: %{id: 0}}}])
    {:ok, session, _events} = Session.poll(session, 8)
    {:ok, prefix} = Draft17.prefix(:bidi, 0)
    size = byte_size(prefix)
    assert_received {:reset_at, 4, @gone, ^size}
    assert_received {:stop, 4, @gone}
    assert session.wt.streams == %{}
  end

  test "a datagram with a malformed quarter stream ID is an H3_DATAGRAM_ERROR" do
    {session, _ref} = accepted()
    Process.put(:datagrams, [<<0x40>>])
    Process.put(:events, [:datagram_readable])

    assert {:error, _session, {:http3_error, :connection, 0x33, :malformed_datagram}} =
             Session.poll(session, 8)

    assert_received {:close, 0x33, "malformed_datagram"}
  end

  defp flush do
    receive do
      _ -> flush()
    after
      0 -> :ok
    end
  end
end

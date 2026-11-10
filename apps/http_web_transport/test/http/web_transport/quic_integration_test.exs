defmodule HTTP.WebTransport.QUICIntegrationTest do
  # In-repo raw Quic server acting as a draft-17 peer. This exercises the live
  # adapter end to end; it is not independent interoperability acceptance.
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.H3.{Capsule, Datagram, Settings}
  alias HTTP.H3.WebTransport.Draft17
  alias HTTP.WebTransport

  alias HTTP.WebTransport.{
    BidirectionalStream,
    DatagramDuplexStream,
    DatagramsWritable,
    ReceiveStream,
    SendStream,
    StreamQueue
  }

  alias QuicHttp3.{Frame, Qpack}

  @wt_settings [{8, 1}, {0x33, 1}, {0x20B8933B, 1}]
  @fixture Path.expand("../../../../elixir_quic/test/fixtures/tls", __DIR__)

  setup context do
    Process.delete(:seen)
    Process.delete(:datagrams)
    cert = fn name -> der(Path.join(@fixture, name)) end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(@fixture, "leaf-key.pem")))

    server_opts =
      [
        tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]],
        datagram: [max_frame_size: 1200]
      ] ++ if(context[:no_reset], do: [], else: [reliable_reset: true])

    {:ok, server} = Quic.listen(server_opts)
    on_exit(fn -> HTTP.WebTransport.TestStop.quietly(server) end)
    {_, port} = Quic.local(server)
    ssl = [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
    %{server: server, url: "https://127.0.0.1:#{port}/wt?x=1", ssl: ssl}
  end

  test "bidi and uni streams carry exact bytes and FIN in both directions", ctx do
    {transport, peer} = open(ctx)

    {:ok, %BidirectionalStream{readable: readable, writable: writable}} =
      WebTransport.create_bidirectional_stream(transport)

    assert :ok = SendStream.write(writable, ["hel", "lo"])
    assert :ok = SendStream.close(writable)
    bidi = next_stream(peer.conn, :bidi)
    {:ok, prefix} = Draft17.prefix(:bidi, 0)
    assert {expected, :fin} = read_all(bidi)
    assert expected == prefix <> "hello"
    send!(bidi, "world", true)
    assert {:ok, "world"} = ReceiveStream.read(readable, timeout: 5_000)
    assert :fin = ReceiveStream.read(readable, timeout: 5_000)

    {:ok, uni_out} = WebTransport.create_unidirectional_stream(transport)
    payload = :binary.copy("u", 40_000)
    assert :ok = SendStream.write(uni_out, payload)
    assert :ok = SendStream.close(uni_out)
    uni = next_stream(peer.conn, :uni)
    {:ok, uni_prefix} = Draft17.prefix(:uni, 0)
    assert {wire, :fin} = read_all(uni)
    assert wire == uni_prefix <> payload

    {:ok, server_uni} = Quic.open_stream(peer.conn, :uni)
    send!(server_uni, uni_prefix <> "srv-uni", true)
    incoming = WebTransport.incoming_unidirectional_streams(transport)
    assert {:ok, %ReceiveStream{} = from_server} = read_queue(incoming)
    assert {"srv-uni", :fin} = read_stream(from_server)

    {:ok, server_bidi} = Quic.open_stream(peer.conn, :bidi)
    send!(server_bidi, prefix <> "srv-bidi", false)
    bidis = WebTransport.incoming_bidirectional_streams(transport)
    assert {:ok, %BidirectionalStream{} = accepted} = read_queue(bidis)
    assert {:ok, "srv-bidi"} = ReceiveStream.read(accepted.readable, timeout: 5_000)
    assert :ok = SendStream.write(accepted.writable, "reply")
    assert :ok = SendStream.close(accepted.writable)
    assert {"reply", :fin} = read_all(server_bidi)
    send!(server_bidi, <<>>, true)
    assert :fin = ReceiveStream.read(accepted.readable, timeout: 5_000)
    assert :ok = WebTransport.close(transport)
  end

  test "empty, duplicate and boundary datagrams are associated with the session", ctx do
    {transport, peer} = open(ctx)
    max = :sys.get_state(transport.pid).max_datagram_size
    assert max > 0 and max < 1200
    datagrams = WebTransport.datagrams(transport)
    boundary = :binary.copy("b", max)

    writer = DatagramDuplexStream.create_writable(datagrams)

    for payload <- ["dg", "dg", "", boundary],
        do: assert(:ok = DatagramsWritable.write(writer, payload))

    assert ["dg", "dg", "", ^boundary] = receive_datagrams(peer.conn, 4)

    for payload <- ["one", "", :binary.copy("s", 1000)] do
      {:ok, wire} = Datagram.encode(0, payload, 1200)
      assert {:ok, _} = Quic.send_datagram(peer.conn, wire)
    end

    # A datagram for another session is discarded, not delivered.
    {:ok, foreign} = Datagram.encode(4, "foreign", 1200)
    assert {:ok, _} = Quic.send_datagram(peer.conn, foreign)

    received = for _ <- 1..3, do: read_datagram(datagrams)
    assert Enum.sort(received) == Enum.sort(["one", "", :binary.copy("s", 1000)])
    refute "foreign" in received
    assert :ok = WebTransport.close(transport)
  end

  # Draft-17 requires RESET_STREAM_AT with the WT stream prefix as reliable size;
  # an ordinary RESET_STREAM is never substituted.
  test "local abort sends a reliable reset that preserves the stream prefix", ctx do
    {transport, peer} = open(ctx)
    {:ok, out} = WebTransport.create_unidirectional_stream(transport)
    assert :ok = SendStream.write(out, "partial")
    assert :ok = SendStream.abort(out, code: 42)
    assert {:error, _} = SendStream.write(out, "-rest")
    stream = next_stream(peer.conn, :uni)
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    {:ok, code} = Draft17.application_error(42)
    assert {wire, {:reset, ^code}} = read_all(stream)
    assert String.starts_with?(wire, prefix)
    assert WebTransport.state(transport) == :connected
    assert :ok = WebTransport.close(transport)
  end

  test "peer reliable reset and STOP_SENDING map draft-17 application codes", ctx do
    {transport, peer} = open(ctx)
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    {:ok, server_uni} = Quic.open_stream(peer.conn, :uni)
    send!(server_uni, prefix <> "abc", false)
    incoming = WebTransport.incoming_unidirectional_streams(transport)
    assert {:ok, reader} = read_queue(incoming)
    assert {:ok, "abc"} = ReceiveStream.read(reader, timeout: 5_000)
    {:ok, reset_code} = Draft17.application_error(43)
    assert {:ok, _} = Quic.reset_stream_at(server_uni, reset_code, byte_size(prefix) + 3)
    assert {:error, {:reset, 43}} = ReceiveStream.read(reader, timeout: 5_000)

    {:ok, %BidirectionalStream{readable: readable, writable: writable}} =
      WebTransport.create_bidirectional_stream(transport)

    assert :ok = SendStream.write(writable, "x")
    assert :ok = ReceiveStream.cancel(readable, code: 7)
    {:ok, stop_code} = Draft17.application_error(7)
    _ = next_stream(peer.conn, :bidi)
    assert stop_code in await_stopped(peer.conn)

    # A peer STOP_SENDING closes the local send side; later writes fail.
    bidi = next_stream_after(peer.conn, transport)
    {:ok, peer_stop} = Draft17.application_error(11)
    assert {:ok, _} = Quic.stop_stream(bidi.server, peer_stop)
    assert :ok = await_send_closed(bidi.writable)
    assert WebTransport.state(transport) == :connected
    assert :ok = WebTransport.close(transport)
  end

  # Draft-17: a STOP_SENDING answer must still deliver the WT stream prefix, so the
  # engine answers with RESET_STREAM_AT whose reliable size covers the prefix.
  test "peer STOP_SENDING on a client stream is answered with a prefix-preserving reset", ctx do
    {transport, peer} = open(ctx)
    {:ok, prefix} = Draft17.prefix(:bidi, 0)
    bidi = next_stream_after(peer.conn, transport)
    {:ok, stop_code} = Draft17.application_error(12)
    assert {:ok, _} = Quic.stop_stream(bidi.server, stop_code)
    assert :ok = await_send_closed(bidi.writable)

    assert %{reset: ^stop_code, recv_reliable: reliable, recv_final: final} =
             await_peer_reset(peer.conn, bidi.server.id)

    assert reliable == byte_size(prefix)
    assert final >= reliable
    assert WebTransport.state(transport) == :connected
    assert :ok = WebTransport.close(transport)
  end

  test "streams and datagrams sent before CONNECT acceptance are delivered after it", ctx do
    {transport, peer} =
      open(ctx, fn conn ->
        {:ok, prefix} = Draft17.prefix(:uni, 0)
        {:ok, early} = Quic.open_stream(conn, :uni)
        send!(early, prefix <> "early", true)
        {:ok, wire} = Datagram.encode(0, "early-dg", 1200)
        {:ok, _} = Quic.send_datagram(conn, wire)
        Process.sleep(50)
      end)

    incoming = WebTransport.incoming_unidirectional_streams(transport)
    assert {:ok, reader} = read_queue(incoming)
    assert {"early", :fin} = read_stream(reader)
    assert "early-dg" == read_datagram(WebTransport.datagrams(transport))
    assert :ok = WebTransport.close(transport, close_code: 1, reason: "done")
    _ = peer
  end

  test "malformed association is rejected per stream without failing the session", ctx do
    {transport, peer} = open(ctx)
    {:ok, wrong} = Draft17.prefix(:uni, 4)
    {:ok, stray} = Quic.open_stream(peer.conn, :uni)
    send!(stray, wrong <> "x", false)
    assert 0x3994BD84 in await_stopped(peer.conn)
    assert WebTransport.state(transport) == :connected
    assert :ok = WebTransport.close(transport)
  end

  test "local close sends CLOSE_WEBTRANSPORT_SESSION with FIN and confirms cleanup", ctx do
    {transport, peer} = open(ctx)
    watch_close(peer.conn)
    owner = :sys.get_state(transport.pid).session_ref.owner
    monitor = Process.monitor(owner)
    closing = Task.async(fn -> WebTransport.close(transport, close_code: 9, reason: "bye") end)
    assert {wire, :fin} = read_all(peer.connect)
    {:ok, frame, <<>>} = Frame.decode(wire)

    assert {:ok, _, [{:capsule, 0x2843, <<9::32, "bye">>}]} =
             Capsule.feed(Capsule.new(), frame.payload)

    # A compliant peer ends its side of the CONNECT stream in reply, so the
    # owner retires no live request.
    send!(peer.connect, "", true)
    assert :ok = Task.await(closing, 5_000)
    assert {:ok, %{close_code: 9, reason: "bye"}} = WebTransport.await_closed(transport, 1_000)
    # RFC 9114 section 5.2: the retired exclusive connection then closes with
    # H3_NO_ERROR.
    assert {{:application_close, 0x100}, _stream} = await_close(peer.conn, now() + 2_000)
    assert_receive {:DOWN, ^monitor, :process, ^owner, _}, 5_000
  end

  test "peer close and drain capsules settle the session once", ctx do
    {transport, peer} = open(ctx)
    {:ok, drain} = Capsule.encode(0x78AE, <<>>)
    send!(peer.connect, Frame.encode!(:data, drain), false)
    assert :ok = WebTransport.await_draining(transport, 5_000)
    assert {:error, :invalid_state} = WebTransport.create_unidirectional_stream(transport)
    {:ok, close} = Draft17.close_capsule(3, "server")
    send!(peer.connect, Frame.encode!(:data, close), true)
    assert {:ok, %{close_code: 3, reason: "server"}} = WebTransport.await_closed(transport, 5_000)
    assert WebTransport.state(transport) == :closed
  end

  test "missing draft-17 SETTINGS refuses before any CONNECT bytes", ctx do
    transport = client(ctx)
    conn = accept(ctx.server)
    control!(conn, [{8, 1}, {0x33, 1}])

    assert {:error, :webtransport_draft17_not_enabled} =
             WebTransport.await_ready(transport, 5_000)

    assert WebTransport.state(transport) == :failed
    refute Enum.any?(drain_events(conn), &match?({:stream_open, _, :bidi}, &1))
  end

  @tag :no_reset
  test "a peer without reliable reset is refused without RESET_STREAM substitution", ctx do
    transport = client(ctx)
    conn = accept(ctx.server)
    control!(conn, @wt_settings)
    assert {:error, :reliable_reset_not_negotiated} = WebTransport.await_ready(transport, 5_000)
  end

  test "non-2xx CONNECT response is an explicit refusal", ctx do
    transport = client(ctx)
    conn = accept(ctx.server)
    control!(conn, @wt_settings)
    stream = next_stream(conn, :bidi)
    _fields = connect_fields(stream)
    send!(stream, headers(404), true)
    assert {:error, {:webtransport_rejected, 404}} = WebTransport.await_ready(transport, 5_000)
  end

  test "opening deadline bounds a silent peer and leaves no owner", ctx do
    before = DynamicSupervisor.count_children(:http_fetch_http3_connection_supervisor).active
    transport = client(ctx, connect_timeout: 300)
    _conn = accept(ctx.server)
    assert {:error, _} = WebTransport.await_ready(transport, 5_000)

    assert DynamicSupervisor.count_children(:http_fetch_http3_connection_supervisor).active ==
             before
  end

  # Port migration on loopback; IP migration needs a loopback alias (127.0.0.2)
  # that is not configured by default on macOS.
  test "client migration moves the session to a new local port with stream and datagram continuity",
       ctx do
    {transport, peer} = open(ctx)
    owner = :sys.get_state(transport.pid).session_ref.owner
    {:ok, %{local: {_, old_port}}} = Quic.info(:sys.get_state(owner).session.connection.handle)

    assert {:ok, %{local: {{127, 0, 0, 1}, new_port} = local}} =
             WebTransport.migrate(transport, local: {{127, 0, 0, 1}, 0}, timeout: 5_000)

    assert new_port != old_port
    assert {:ok, %{remote: ^local}} = Quic.info(peer.conn)

    {:ok, %BidirectionalStream{readable: readable, writable: writable}} =
      WebTransport.create_bidirectional_stream(transport)

    assert :ok = SendStream.write(writable, "after-migration")
    assert :ok = SendStream.close(writable)
    bidi = next_stream(peer.conn, :bidi)
    {:ok, prefix} = Draft17.prefix(:bidi, 0)
    assert {wire, :fin} = read_all(bidi)
    assert wire == prefix <> "after-migration"
    send!(bidi, "migrated-reply", true)
    assert {"migrated-reply", :fin} = read_stream(readable)

    writer = DatagramDuplexStream.create_writable(WebTransport.datagrams(transport))
    assert :ok = DatagramsWritable.write(writer, "dg-after")
    assert ["dg-after"] = receive_datagrams(peer.conn, 1)
    {:ok, wire} = Datagram.encode(0, "dg-back", 1200)
    assert {:ok, _} = Quic.send_datagram(peer.conn, wire)
    assert "dg-back" == read_datagram(WebTransport.datagrams(transport))
    assert :ok = WebTransport.close(transport)
  end

  test "invalid migration requests are refused and leave the session usable", ctx do
    {transport, peer} = open(ctx)

    assert {:error, :invalid_local_address} =
             WebTransport.migrate(transport, local: {{0, 0, 0, 0}, 0})

    assert {:error, :invalid_local_address} = WebTransport.migrate(transport, local: :bad)

    assert {:error, :invalid_timeout} =
             WebTransport.migrate(transport, local: {{127, 0, 0, 1}, 0}, timeout: 0)

    {:ok, out} = WebTransport.create_unidirectional_stream(transport)
    assert :ok = SendStream.write(out, "still-here")
    assert :ok = SendStream.close(out)
    {:ok, prefix} = Draft17.prefix(:uni, 0)
    assert {wire, :fin} = read_all(next_stream(peer.conn, :uni))
    assert wire == prefix <> "still-here"
    assert :ok = WebTransport.close(transport)
    assert {:error, :invalid_state} = WebTransport.migrate(transport, local: {{127, 0, 0, 1}, 0})
  end

  test "owner death fails the session and rejects later operations", ctx do
    {transport, _peer} = open(ctx)
    owner = :sys.get_state(transport.pid).session_ref.owner
    Process.exit(owner, :kill)
    assert {:error, {:owner_down, :killed}} = WebTransport.await_closed(transport, 5_000)
    assert WebTransport.state(transport) == :failed
    assert {:error, :invalid_state} = WebTransport.create_bidirectional_stream(transport)
  end

  # -- client helpers --------------------------------------------------------

  defp client(ctx, opts \\ []) do
    transport =
      WebTransport.new(ctx.url, Keyword.merge([ssl: ctx.ssl, connect_timeout: 5_000], opts))

    assert %WebTransport{} = transport
    on_exit(fn -> if Process.alive?(transport.pid), do: WebTransport.close(transport) end)
    transport
  end

  defp open(ctx, before_accept \\ fn _ -> :ok end) do
    transport = client(ctx)
    conn = accept(ctx.server)
    control!(conn, @wt_settings)
    stream = next_stream(conn, :bidi)
    fields = connect_fields(stream)
    assert {":protocol", "webtransport-h3"} in fields
    assert {":path", "/wt?x=1"} in fields
    before_accept.(conn)
    send!(stream, headers(200), false)
    assert :ok = WebTransport.await_ready(transport, 5_000)
    {transport, %{conn: conn, connect: stream}}
  end

  defp next_stream_after(conn, transport) do
    {:ok, %BidirectionalStream{writable: writable}} =
      WebTransport.create_bidirectional_stream(transport)

    assert :ok = SendStream.write(writable, "y")
    %{server: next_stream(conn, :bidi), writable: writable}
  end

  # Peer-side engine view of the reset it received; `recv_reliable` is set only
  # by RESET_STREAM_AT, never by an ordinary RESET_STREAM.
  defp await_peer_reset(conn, id, deadline \\ now() + 5_000) do
    assert now() < deadline
    {_phase, data} = :sys.get_state(conn.id)

    case data.scheduler.streams.streams[id] do
      %{reset: code} = stream when is_integer(code) ->
        stream

      _ ->
        Process.sleep(5)
        await_peer_reset(conn, id, deadline)
    end
  end

  defp await_send_closed(writable, deadline \\ now() + 5_000) do
    assert now() < deadline

    case SendStream.write(writable, "z") do
      {:error, :invalid_state} ->
        :ok

      _ ->
        Process.sleep(10)
        await_send_closed(writable, deadline)
    end
  end

  defp read_queue(queue) do
    StreamQueue.read(queue, timeout: 5_000)
  end

  defp read_datagram(datagrams) do
    assert {:ok, bytes} = DatagramDuplexStream.read(datagrams, timeout: 5_000)
    bytes
  end

  defp read_stream(reader, acc \\ <<>>) do
    case ReceiveStream.read(reader, timeout: 5_000) do
      {:ok, bytes} -> read_stream(reader, acc <> bytes)
      :fin -> {acc, :fin}
      other -> {acc, other}
    end
  end

  # -- server helpers --------------------------------------------------------

  defp der(path) do
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(File.read!(path))
    der
  end

  defp accept(server) do
    assert_receive {:quic_accept, ^server}, 5_000
    {:ok, conn} = Quic.accept(server)
    :ok = Quic.attach(conn, self())
    on_exit(fn -> Quic.close(conn, 0x100, <<>>) end)
    conn
  end

  defp control!(conn, settings) do
    {:ok, control} = Quic.open_stream(conn, :uni)
    send!(control, <<0>> <> Frame.encode!(:settings, Settings.encode!(settings)), false)
  end

  defp send!(stream, bytes, fin), do: assert({:ok, _} = Quic.send_stream(stream, bytes, fin))

  defp headers(status) do
    {:ok, block} = Qpack.encode_header_block([{":status", Integer.to_string(status)}])
    Frame.encode!(:headers, block)
  end

  defp connect_fields(stream, acc \\ <<>>, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc <> for({:data, _, bytes} <- items, into: <<>>, do: bytes)

    case Frame.decode(acc) do
      {:ok, %{type: 1, payload: block}, _} ->
        {:ok, fields} = Qpack.decode_header_block(block)
        fields

      _ ->
        Process.sleep(5)
        connect_fields(stream, acc, deadline)
    end
  end

  # Client control/QPACK uni streams carry H3 types; WT uni streams begin 0x54.
  defp next_stream(conn, kind, deadline \\ now() + 5_000) do
    assert now() < deadline
    seen = Process.get(:seen, [])

    case Enum.find(seen, fn {stream, k, used?} -> k == kind and not used? and wt?(stream, k) end) do
      {stream, _, _} ->
        Process.put(:seen, List.keyreplace(seen, stream, 0, {stream, kind, true}))
        stream

      nil ->
        record_events(conn)
        Process.sleep(5)
        next_stream(conn, kind, deadline)
    end
  end

  defp wt?(%{id: id}, :uni) when id in [2, 6, 10], do: false
  defp wt?(_stream, _kind), do: true

  defp record_events(conn) do
    {:ok, events} = Quic.events(conn, 32)

    for event <- events do
      case event do
        {:stream_open, stream, kind} ->
          Process.put(:seen, Process.get(:seen, []) ++ [{stream, kind, false}])

        {:stopped, _stream, code} ->
          Process.put(:stopped, Process.get(:stopped, []) ++ [code])

        :datagram_readable ->
          {:ok, datagrams} = Quic.read_datagrams(conn, 32)
          Process.put(:datagrams, Process.get(:datagrams, []) ++ datagrams)

        _ ->
          :ok
      end
    end

    events
  end

  defp drain_events(conn),
    do:
      record_events(conn) ++
        Enum.map(Process.get(:seen, []), &{:stream_open, elem(&1, 0), elem(&1, 1)})

  defp await_stopped(conn, deadline \\ now() + 5_000) do
    assert now() < deadline
    record_events(conn)

    case Process.get(:stopped, []) do
      [] ->
        Process.sleep(5)
        await_stopped(conn, deadline)

      codes ->
        codes
    end
  end

  defp receive_datagrams(conn, count, deadline \\ now() + 5_000) do
    assert now() < deadline
    record_events(conn)
    datagrams = Process.get(:datagrams, [])

    if length(datagrams) >= count do
      Enum.map(datagrams, fn wire ->
        {:ok, 0, payload} = Datagram.decode(wire, 1200)
        payload
      end)
    else
      Process.sleep(5)
      receive_datagrams(conn, count, deadline)
    end
  end

  defp read_all(stream, acc \\ <<>>, deadline \\ now() + 5_000) do
    assert now() < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc <> for({:data, _, bytes} <- items, into: <<>>, do: bytes)

    cond do
      Enum.any?(items, &match?({:fin, _}, &1)) ->
        {acc, :fin}

      reset = Enum.find(items, &match?({:reset, _, _, _}, &1)) ->
        {acc, {:reset, elem(reset, 2)}}

      true ->
        Process.sleep(5)
        read_all(stream, acc, deadline)
    end
  end

  # The raw server records a peer close only as `:peer_closed`; the decoded
  # frame is the observable carrying the application error code.
  defp watch_close(%{id: connection}) do
    on_exit(fn -> :erlang.trace_pattern({Quic.Codec, :decode_frames, 2}, false, [:local]) end)

    :erlang.trace_pattern({Quic.Codec, :decode_frames, 2}, [{:_, [], [{:return_trace}]}], [
      :local
    ])

    :erlang.trace(connection, true, [:call])
  end

  defp await_close(%{id: connection} = handle, deadline, stream \\ []) do
    receive do
      {:trace, ^connection, :return_from, {Quic.Codec, :decode_frames, 2}, {:ok, frames, _}} ->
        stream = stream ++ Enum.filter(frames, &(&1.type == :stream))

        case Enum.find(frames, &(&1.type in [:application_close, :connection_close])) do
          nil -> await_close(handle, deadline, stream)
          frame -> {{frame.type, frame.error_code}, stream}
        end

      {:trace, ^connection, _, _, _} ->
        await_close(handle, deadline, stream)

      {:trace, ^connection, _, _, _, _} ->
        await_close(handle, deadline, stream)
    after
      max(deadline - now(), 0) -> {:no_peer_close, stream}
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end

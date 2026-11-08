defmodule QuicHttp3.DynamicQpackSessionTest do
  use ExUnit.Case, async: true

  alias Quic.Runtime.{ConnectionHandle, StreamHandle}
  alias QuicHttp3.{Control, Frame, Qpack, Session, Settings}

  defmodule Ops do
    def client(opts), do: call(:client, [opts], {:ok, self()})

    def connect(endpoint, remote, opts),
      do: call(:connect, [endpoint, remote, opts], {:ok, Process.get(:connection)})

    def attach(handle, consumer, opts), do: call(:attach, [handle, consumer, opts], :ok)
    def ready(handle), do: call(:ready, [handle], :ready)

    def info(handle),
      do:
        call(
          :info,
          [handle],
          {:ok,
           %{alpn: "h3", tls_complete: true, peer_authenticated: true, parameters_valid: true}}
        )

    def open_stream(handle, kind, opts) do
      id = Process.get(:next_stream, 0)
      Process.put(:next_stream, id + 4)
      call(:open_stream, [handle, kind, opts], {:ok, %StreamHandle{connection: handle, id: id}})
    end

    def send_stream(stream, bytes, fin, opts),
      do: call(:send_stream, [stream, bytes, fin, opts], {:ok, opts[:ref] || make_ref()})

    def events(handle, max, opts), do: call(:events, [handle, max, opts], {:ok, []})
    def read(stream, max, opts), do: call(:read, [stream, max, opts], {:ok, []})

    def reset_stream(stream, code, opts),
      do: call(:reset_stream, [stream, code, opts], {:ok, opts[:ref] || make_ref()})

    def stop_stream(stream, code, opts),
      do: call(:stop_stream, [stream, code, opts], {:ok, opts[:ref] || make_ref()})

    def close(handle, code, reason, opts), do: call(:close, [handle, code, reason, opts], :ok)
    def stop_endpoint(endpoint), do: call(:stop_endpoint, [endpoint], :ok)
    def operation_status(target, ref), do: call(:operation_status, [target, ref], :unknown)

    defp call(name, args, default) do
      send(self(), {:call, name, args})

      case Process.get({:results, name}, []) do
        [result | rest] ->
          Process.put({:results, name}, rest)
          if is_function(result, 1), do: result.(args), else: result

        [] ->
          default
      end
    end
  end

  # Local streams: control 0, QPACK encoder 4, QPACK decoder 8, requests from 12.
  @decoder_stream 8

  setup do
    native = %ConnectionHandle{id: self(), generation: make_ref()}
    Process.put(:connection, native)
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls/root.pem", __DIR__)
    [{:Certificate, ca, :not_encrypted}] = :public_key.pem_decode(File.read!(fixture))
    opts = [ops: Ops, tls: [cacerts: [ca], reference_identity: {:dns_id, "example.test"}]]
    %{opts: opts, native: native, peer_encoder: %StreamHandle{connection: native, id: 3}}
  end

  test "default profile advertises dynamic QPACK and opens typed QPACK streams", %{opts: opts} do
    session = open_session(opts, [], false)
    calls = calls()
    assert Enum.count(calls, &match?({:call, :open_stream, [_, :uni, _]}, &1)) == 3

    sends = for {:call, :send_stream, [stream, bytes, false, _]} <- calls, do: {stream.id, bytes}
    assert {4, <<2>>} in sends
    assert {8, <<3>>} in sends
    assert {1, 4_096} in local_settings(session)
    assert {7, 16} in local_settings(session)
    assert session.qpack_encoder_stream.handle.id == 4
    assert session.qpack_decoder_stream.handle.id == @decoder_stream
  end

  test "explicit 0/0 restores the static profile without QPACK streams", %{opts: opts} do
    session = open_session(opts, [qpack_max_table_capacity: 0, qpack_blocked_streams: 0], false)
    assert Enum.count(calls(), &match?({:call, :open_stream, _}, &1)) == 1
    assert {1, 0} in local_settings(session)
    assert {7, 0} in local_settings(session)
    assert session.qpack == nil and session.qpack_decoder_stream == nil
  end

  test "custom capacity and blocked limits are advertised and validated", %{opts: opts} do
    session = open_session(opts, qpack_max_table_capacity: 1_024, qpack_blocked_streams: 2)
    assert {1, 1_024} in local_settings(session)
    assert {7, 2} in local_settings(session)
    assert session.qpack.max_capacity == 1_024

    assert {:error, :invalid_session_options} = Session.new(qpack_max_table_capacity: -1)
    assert {:error, :invalid_session_options} = Session.new(qpack_max_table_capacity: 65_537)
    assert {:error, :invalid_session_options} = Session.new(qpack_blocked_streams: 129)
  end

  test "encoder inserts are acknowledged with Insert Count Increment", %{
    opts: opts,
    peer_encoder: encoder
  } do
    session = open_session(opts)

    session =
      peer_encoder(session, encoder, <<2>> <> set_capacity(4_096) <> insert("x-a", "1"))

    assert session.qpack.insert_count == 1
    assert decoder_writes() == [Qpack.insert_count_increment(1)]

    # A split instruction is buffered until complete.
    wire = insert("x-b", "2")
    <<head::binary-size(2), tail::binary>> = wire
    session = peer_encoder(session, encoder, head, false)
    assert session.qpack.insert_count == 1
    assert decoder_writes() == []
    session = peer_encoder(session, encoder, tail, false)
    assert session.qpack.insert_count == 2
    assert decoder_writes() == [Qpack.insert_count_increment(1)]
  end

  test "dynamic sections are decoded and acknowledged per stream", %{
    opts: opts,
    peer_encoder: encoder
  } do
    session = open_session(opts)
    session = peer_encoder(session, encoder, <<2>> <> set_capacity(4_096) <> insert("x-a", "1"))
    _ = decoder_writes()
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    poll_read(stream, [{:data, stream.handle.id, headers(<<2, 0, 0xD9, 0x80>>)}])

    assert {:ok, _session, [{:headers, ^ref, [{":status", "200"}, {"x-a", "1"}]}]} =
             Session.poll(session, 8)

    assert decoder_writes() == [Qpack.section_ack(stream.handle.id)]
  end

  test "blocked sections wait without reading and resume in blocking order", %{
    opts: opts,
    peer_encoder: encoder
  } do
    session = open_session(opts)
    session = peer_encoder(session, encoder, <<2>> <> set_capacity(4_096))
    {:ok, session, first} = Session.request(session, [{":path", "/a"}], "", [])
    {:ok, session, second} = Session.request(session, [{":path", "/b"}], "", [])
    a = session.requests[first].stream
    b = session.requests[second].stream

    # The first response needs two inserts and has its body and FIN held.
    poll_read(a, [
      {:data, a.handle.id, headers(<<3, 0, 0xD9, 0x80, 0x81>>) <> Frame.encode!(:data, "A")},
      {:fin, a.handle.id}
    ])

    assert {:ok, session, []} = Session.poll(session, 8)
    poll_read(b, [{:data, b.handle.id, headers(<<2, 0, 0xD9, 0x80>>)}])
    assert {:ok, session, []} = Session.poll(session, 8)
    assert session.qpack_blocked == [first, second]

    # A blocked stream is not read even when it is reported readable.
    Process.put({:results, :events}, [{:ok, [{:readable, b.handle}]}])
    _ = calls()
    assert {:ok, session, []} = Session.poll(session, 8)
    refute Enum.any?(calls(), &match?({:call, :read, _}, &1))

    {session, events} =
      peer_encoder_events(session, encoder, insert("x-a", "1") <> insert("x-b", "2"))

    assert events == [
             {:headers, first, [{":status", "200"}, {"x-b", "2"}, {"x-a", "1"}]},
             {:data, first, "A"},
             {:done, first},
             {:headers, second, [{":status", "200"}, {"x-a", "1"}]}
           ]

    refute Map.has_key?(session.requests, first)
    assert session.qpack_blocked == []
    # The unblocked stream is requeued and read again in the same poll.
    calls = calls()
    b_id = b.handle.id
    assert Enum.any?(calls, &match?({:call, :read, [%{id: ^b_id}, _, _]}, &1))

    writes =
      for {:call, :send_stream, [%{id: @decoder_stream}, bytes, false, _]} <- calls, do: bytes

    assert writes == [Qpack.section_ack(a.handle.id) <> Qpack.section_ack(b_id)]
  end

  test "more blocked streams than advertised is QPACK_DECOMPRESSION_FAILED", %{opts: opts} do
    session = open_session(opts, qpack_blocked_streams: 1)
    {:ok, session, first} = Session.request(session, [{":path", "/a"}], "", [])
    {:ok, session, second} = Session.request(session, [{":path", "/b"}], "", [])
    a = session.requests[first].stream
    b = session.requests[second].stream
    poll_read(a, [{:data, a.handle.id, headers(<<2, 0, 0x80>>)}])
    assert {:ok, session, []} = Session.poll(session, 8)
    poll_read(b, [{:data, b.handle.id, headers(<<2, 0, 0x80>>)}])

    assert {:error, _, {:http3_error, :connection, 0x200, :qpack_blocked_streams_limit}} =
             Session.poll(session, 8)
  end

  test "zero blocked streams rejects any blocking section", %{opts: opts} do
    session = open_session(opts, qpack_blocked_streams: 0)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    poll_read(stream, [{:data, stream.handle.id, headers(<<2, 0, 0x80>>)}])

    assert {:error, _, {:http3_error, :connection, 0x200, :qpack_blocked_streams_limit}} =
             Session.poll(session, 8)
  end

  test "cancelling a blocked stream sends Stream Cancellation", %{opts: opts} do
    session = open_session(opts)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    poll_read(stream, [{:data, stream.handle.id, headers(<<2, 0, 0x80>>)}])
    assert {:ok, session, []} = Session.poll(session, 8)
    assert {:ok, session} = Session.cancel(session, ref)
    assert session.qpack_blocked == []
    assert decoder_writes() == [Qpack.stream_cancel(stream.handle.id)]
  end

  test "peer reset of an incomplete stream sends Stream Cancellation", %{opts: opts} do
    session = open_session(opts)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    poll_read(stream, [{:reset, stream.handle.id, 0x10C, 0}])
    assert {:ok, _session, [{:stream_reset, ^ref, 0x10C, 0}]} = Session.poll(session, 8)
    assert decoder_writes() == [Qpack.stream_cancel(stream.handle.id)]
  end

  test "completed streams are not cancelled", %{opts: opts} do
    session = open_session(opts)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream

    poll_read(stream, [
      {:data, stream.handle.id, headers(<<0, 0, 0xD9>>)},
      {:fin, stream.handle.id}
    ])

    assert {:ok, _session, events} = Session.poll(session, 8)
    assert {:done, ref} in events
    assert decoder_writes() == []
  end

  test "encoder stream errors are QPACK_ENCODER_STREAM_ERROR", %{
    opts: opts,
    peer_encoder: encoder
  } do
    session = open_session(opts)
    poll_peer(encoder, <<2>> <> set_capacity(4_097))

    assert {:error, _, {:http3_error, :connection, 0x201, :invalid_dynamic_table_capacity}} =
             Session.poll(session, 8)

    poll_peer(encoder, <<2>> <> set_capacity(64) <> insert("x", String.duplicate("v", 64)))

    assert {:error, _, {:http3_error, :connection, 0x201, :dynamic_entry_too_large}} =
             Session.poll(session, 8)
  end

  test "invalid dynamic references in a section are QPACK_DECOMPRESSION_FAILED", %{
    opts: opts,
    peer_encoder: encoder
  } do
    session = open_session(opts)
    session = peer_encoder(session, encoder, <<2>> <> set_capacity(4_096) <> insert("x-a", "1"))
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    poll_read(stream, [{:data, stream.handle.id, headers(<<2, 0, 0xD9>>)}])

    assert {:error, _, {:http3_error, :connection, 0x200, :invalid_required_insert_count}} =
             Session.poll(session, 8)
  end

  test "peer decoder stream accepts cancellations only", %{opts: opts, native: native} do
    session = open_session(opts)
    decoder = %StreamHandle{connection: native, id: 7}
    poll_peer(decoder, <<3>> <> Qpack.stream_cancel(12))
    assert {:ok, session, []} = Session.poll(session, 8)
    Process.put({:results, :events}, [{:ok, [{:readable, decoder}]}])
    Process.put({:results, :read}, [{:ok, [{:data, 7, Qpack.section_ack(12)}]}])

    assert {:error, _, {:http3_error, :connection, 0x202, :unexpected_decoder_instruction}} =
             Session.poll(session, 8)

    poll_peer(%StreamHandle{connection: native, id: 11}, <<3>>)

    assert {:error, _, {:http3_error, :connection, 0x103, :duplicate_qpack_decoder}} =
             Session.poll(session, 8)
  end

  defp open_session(opts, session_opts \\ [], drain? \\ true) do
    {:ok, session} = Session.new(Keyword.put_new(session_opts, :max_frame, 128))
    {:ok, session} = Session.connect(session, {127, 0, 0, 1}, 443, opts)
    {:ok, session} = Session.open(session)
    if drain?, do: calls()
    session
  end

  defp local_settings(session) do
    <<0, bytes::binary>> = Control.local_payload(session.control)
    {:ok, %{payload: payload}, <<>>} = Frame.decode(bytes)
    {:ok, settings} = Settings.decode(payload)
    settings
  end

  defp peer_encoder(session, encoder, bytes, open? \\ true) do
    events = if open?, do: [{:stream_open, encoder, :uni}], else: []
    Process.put({:results, :events}, [{:ok, events ++ [{:readable, encoder}]}])
    Process.put({:results, :read}, [{:ok, [{:data, encoder.id, bytes}]}])
    {:ok, session, []} = Session.poll(session, 8)
    session
  end

  defp peer_encoder_events(session, encoder, bytes) do
    Process.put({:results, :events}, [{:ok, [{:readable, encoder}]}])
    Process.put({:results, :read}, [{:ok, [{:data, encoder.id, bytes}]}])
    {:ok, session, events} = Session.poll(session, 8)
    {session, events}
  end

  defp poll_peer(stream, bytes) do
    Process.put({:results, :events}, [{:ok, [{:stream_open, stream, :uni}, {:readable, stream}]}])
    Process.put({:results, :read}, [{:ok, [{:data, stream.id, bytes}]}])
  end

  defp poll_read(stream, items) do
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}]}])
    Process.put({:results, :read}, [{:ok, items}])
  end

  defp headers(block), do: Frame.encode!(:headers, block)

  defp set_capacity(capacity) do
    {:ok, bytes} = Qpack.encode_integer(capacity, 5, 0x20)
    bytes
  end

  defp insert(name, value) do
    {:ok, length} = Qpack.encode_integer(byte_size(name), 5, 0x40)
    {:ok, encoded} = Qpack.encode_string(value)
    length <> name <> encoded
  end

  defp decoder_writes do
    for {:call, :send_stream, [%{id: @decoder_stream}, bytes, false, _]} <- calls(), do: bytes
  end

  defp calls(acc \\ []) do
    receive do
      {:call, _, _} = call -> calls([call | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end

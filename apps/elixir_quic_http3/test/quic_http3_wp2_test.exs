defmodule QuicHttp3.WP2Test do
  use ExUnit.Case, async: true

  alias Quic.Runtime.{ConnectionHandle, StreamHandle}
  alias QuicHttp3.{Frame, Qpack, Session, Varint}
  alias QuicHttp3.Transport.Quic, as: Adapter

  defmodule Ops do
    def client(opts), do: call(:client, [opts], {:ok, self()})

    def connect(endpoint, remote, opts),
      do: call(:connect, [endpoint, remote, opts], {:ok, connection()})

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
    def connection, do: Process.get(:connection)

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

  setup do
    native = %ConnectionHandle{id: self(), generation: make_ref()}
    Process.put(:connection, native)
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls/root.pem", __DIR__)
    [{:Certificate, ca, :not_encrypted}] = :public_key.pem_decode(File.read!(fixture))
    opts = [ops: Ops, tls: [cacerts: [ca], reference_identity: {:dns_id, "example.test"}]]
    {:ok, session} = Session.new(max_frame: 128)
    {:ok, session} = Session.connect(session, {127, 0, 0, 1}, 443, opts)
    {:ok, session} = Session.open(session)
    _ = calls()
    %{session: session, opts: opts, native: native}
  end

  test "arbitrary binary bodies decode as bounded DATA frames after independent write concatenation",
       %{session: session} do
    body = :binary.copy(<<0, 255, 1, 2, 3, 4, 5>>, 6_000)

    {:ok, _session, _ref} =
      Session.request(session, [{":method", "POST"}, {":path", "/"}], body, [])

    writes = for {:call, :send_stream, [_, bytes, fin, _]} <- calls(), do: {bytes, fin}
    assert Enum.all?(writes, fn {bytes, _} -> byte_size(bytes) <= 128 end)
    assert Enum.count(writes, &elem(&1, 1)) == 1
    wire = IO.iodata_to_binary(Enum.map(writes, &elem(&1, 0)))
    assert [%{type: 1} | data] = frames(wire)
    assert Enum.all?(data, &(&1.type == 0 and byte_size(&1.payload) <= 16_384))
    assert IO.iodata_to_binary(Enum.map(data, & &1.payload)) == body
  end

  test "streamed upload frames demanded chunks and admits a true empty FIN", %{session: session} do
    {:ok, session, ref} =
      Session.request(session, [{":method", "POST"}, {":path", "/"}], :stream, [])

    headers = calls()
    refute Enum.any?(headers, &match?({:call, :send_stream, [_, _, true, _]}, &1))
    {:ok, session} = Session.send_data(session, ref, <<0, 255, 17>>, false, [])
    {:ok, _session} = Session.send_data(session, ref, <<>>, true, [])
    assert_received {:call, :send_stream, [_, <<>>, true, _]}
    wire = for {:call, :send_stream, [_, bytes, _, _]} <- calls(), into: <<>>, do: bytes
    assert [%{type: 0, payload: <<0, 255, 17>>}] = frames(wire)
  end

  test "response lifecycle preserves informational/final/trailers and retires exactly once", %{
    session: session
  } do
    {:ok, session, ref} = Session.request(session, [{":method", "GET"}, {":path", "/"}], "", [])
    stream = session.requests[ref].stream

    wire =
      headers([{":status", "103"}, {"link", "a"}]) <>
        headers([{":status", "200"}, {"content-length", "2"}]) <>
        Frame.encode!(:data, "ok") <> headers([{"x-trailer", "yes"}])

    poll_read(stream, [{:data, stream.handle.id, wire}, {:fin, stream.handle.id}])
    assert {:ok, session, events} = Session.poll(session, 8)
    assert {:informational, ref, 103, [{"link", "a"}]} in events
    assert {:headers, ref, [{":status", "200"}, {"content-length", "2"}]} in events
    assert {:trailers, ref, [{"x-trailer", "yes"}]} in events
    assert {:done, ref} in events
    refute Map.has_key?(session.requests, ref)
    assert {:error, _, :unknown_request} = Session.cancel(session, ref)
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}]}])
    assert {:ok, _, []} = Session.poll(session, 8)
  end

  test "malformed complete HEADERS is a structured connection error", %{session: session} do
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    poll_read(stream, [{:data, stream.handle.id, Frame.encode!(:headers, <<0>>)}])

    assert {:error, _, {:http3_error, :connection, 0x200, :malformed_qpack}} =
             Session.poll(session, 8)
  end

  test "HEAD body and content length errors are isolated from siblings", %{session: session} do
    {:ok, session, ref} = Session.request(session, [{":method", "HEAD"}, {":path", "/"}], "", [])
    {:ok, session, sibling} = Session.request(session, [{":path", "/sibling"}], "", [])
    stream = session.requests[ref].stream

    poll_read(stream, [
      {:data, stream.handle.id, headers([{":status", "200"}]) <> Frame.encode!(:data, "bad")}
    ])

    assert {:ok, session, [{:stream_error, ^ref, 0x10E, :body_forbidden}]} =
             Session.poll(session, 8)

    assert Map.has_key?(session.requests, sibling)
    refute Map.has_key?(session.requests, ref)
  end

  test "outgoing decoded and peer SETTINGS field budgets reject before allocation", %{
    session: session
  } do
    fields = List.duplicate({"x", "y"}, 129)
    assert {:error, _, :request_field_limit} = Session.request(session, fields, "", [])
    refute_received {:call, :open_stream, _}
    session = %{session | control: %{session.control | peer_settings: [{6, 32}]}}

    assert {:error, _, :peer_field_section_limit} =
             Session.request(session, [{":path", "/"}], "", [])

    refute_received {:call, :open_stream, _}
  end

  test "aggregate retained decoder budget is bounded across partial responses", %{
    session: session
  } do
    session = %{session | max_retained_bytes: 16}
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    wire = Varint.encode!(1) <> Varint.encode!(100) <> :binary.copy(<<0>>, 17)
    poll_read(stream, [{:data, stream.handle.id, wire}])

    assert {:error, _, {:http3_error, :connection, 0x107, :session_retained_bytes_limit}} =
             Session.poll(session, 8)
  end

  test "detached blocked upload keeps current response state and observes control credit", %{
    session: session
  } do
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], :stream, [])
    Process.put({:results, :send_stream}, [{:blocked, :credit}])
    assert {:blocked, session, :credit} = Session.send_data(session, ref, "upload", false, [])
    assert {:ok, session, continuation} = Session.suspend_blocked(session)
    stream = session.requests[ref].stream
    poll_read(stream, [{:data, stream.handle.id, headers([{":status", "200"}])}])
    assert {:ok, session, [{:headers, ^ref, _}]} = Session.poll(session, 8)
    assert {:ok, session} = Session.resume(session, continuation)
    assert session.requests[ref].decoder.phase == :final
    assert {:error, _, :stale_continuation} = Session.resume(session, continuation)
  end

  test "unknown operations cannot detach or reset sending half", %{session: session} do
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], :stream, [])
    Process.put({:results, :send_stream}, [fn [_, _, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, _} = Session.send_data(session, ref, "upload", false, [])
    assert {:error, _, :operation_not_definitely_blocked} = Session.suspend_blocked(session)
    assert {:error, _, :operation_pending} = Session.reset_send(session, ref)
  end

  test "detached upload deadlines expire without replay and cancellation invalidates tokens", %{
    session: session
  } do
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], :stream, [])
    Process.put({:results, :send_stream}, [{:blocked, :credit}])
    {:blocked, session, :credit} = Session.send_data(session, ref, "upload", false, [])
    session = put_in(session.pending.deadline, System.monotonic_time(:millisecond) - 1)
    {:ok, suspended, expired} = Session.suspend_blocked(session)
    _ = calls()
    assert {:error, _, :deadline_expired} = Session.resume(suspended, expired)
    refute_received {:call, :send_stream, _}
    assert {:ok, cancelled} = Session.cancel(suspended, ref)
    assert {:error, _, :stale_continuation} = Session.resume(cancelled, expired)
    refute Map.has_key?(cancelled.requests, ref)
  end

  test "terminal response invalidates blocked upload and reconciles unknown reset once", %{
    session: session
  } do
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], :stream, [])
    Process.put({:results, :send_stream}, [{:blocked, :credit}])
    {:blocked, session, :credit} = Session.send_data(session, ref, "upload", false, [])
    {:ok, session, continuation} = Session.suspend_blocked(session)
    stream = session.requests[ref].stream

    poll_read(stream, [
      {:data, stream.handle.id, headers([{":status", "200"}])},
      {:fin, stream.handle.id}
    ])

    Process.put({:results, :reset_stream}, [fn [_, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, reset_ref} = Session.poll(session, 8)
    refute Map.has_key?(session.requests, ref)
    assert session.continuations == %{}
    _ = calls()
    Process.put({:results, :operation_status}, [%{status: :admitted, result: {:ok, reset_ref}}])
    assert {:ok, session, events} = Session.resume(session)
    assert {:done, ref} in events
    assert {:error, _, :stale_continuation} = Session.resume(session, continuation)
    refute_received {:call, :reset_stream, _}
    refute_received {:call, :stop_stream, _}
  end

  test "structured control protocol errors retain their original code and reason", %{
    session: session,
    native: native
  } do
    control = %StreamHandle{connection: native, id: 3}

    Process.put({:results, :events}, [
      {:ok, [{:stream_open, control, :uni}, {:readable, control}]}
    ])

    wire = <<0>> <> Frame.encode!(:settings, <<>>) <> Frame.encode!(:max_push_id, <<0>>)
    Process.put({:results, :read}, [{:ok, [{:data, 3, wire}]}])

    assert {:error, _, {:http3_error, :connection, 0x105, :forbidden_control_frame}} =
             Session.poll(session, 8)
  end

  test "control failures map to SETTINGS, missing SETTINGS and excessive load codes", %{
    session: session,
    native: native
  } do
    control = %StreamHandle{connection: native, id: 3}

    cases = [
      {Frame.encode!(:goaway, <<0>>), 0x10A, :settings_must_be_first},
      {Frame.encode!(:settings, <<2, 0>>), 0x109, {:reserved_setting, 2}},
      {Frame.encode!(:settings, <<8, 2>>), 0x109, {:invalid_setting_value, 8, 2}},
      {Frame.encode!(:settings, <<1, 0, 1, 0>>), 0x109, {:duplicate_setting, 1}},
      {Varint.encode!(4) <> Varint.encode!(65_537), 0x107, :control_frame_too_large}
    ]

    for {payload, code, reason} <- cases do
      Process.put({:results, :events}, [
        {:ok, [{:stream_open, control, :uni}, {:readable, control}]}
      ])

      Process.put({:results, :read}, [{:ok, [{:data, 3, <<0>> <> payload}]}])

      assert {:error, _, {:http3_error, :connection, ^code, ^reason}} = Session.poll(session, 8)
    end
  end

  test "early final reset abandons only known upload work and leaves receive half readable", %{
    session: session
  } do
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], :stream, [])
    Process.put({:results, :send_stream}, [{:blocked, :credit}])
    assert {:blocked, session, :credit} = Session.send_data(session, ref, "not sent", false, [])
    {:ok, session, continuation} = Session.suspend_blocked(session)
    assert {:ok, session} = Session.reset_send(session, ref)
    assert_received {:call, :reset_stream, [_, 0x10C, _]}
    refute_received {:call, :stop_stream, _}
    assert {:error, _, :stale_continuation} = Session.resume(session, continuation)
    assert Map.has_key?(session.requests, ref)
    assert {:error, _, :upload_closed} = Session.send_data(session, ref, "later", true, [])
  end

  test "GOAWAY rejects admission before and after stream allocation", %{
    session: session,
    native: native
  } do
    closed = %{session | control: %{session.control | goaway_id: 0}}
    assert {:error, _, :goaway} = Session.request(closed, [{":path", "/"}], "", [])
    refute_received {:call, :open_stream, _}
    raced = %{session | control: %{session.control | goaway_id: 4}}
    Process.put({:results, :open_stream}, [{:ok, %StreamHandle{connection: native, id: 4}}])

    assert {:error, session, {:request_rejected, _ref, :goaway}} =
             Session.request(raced, [{":path", "/"}], "", [])

    assert session.requests == %{}
    refute_received {:call, :send_stream, _}
  end

  test "static QPACK critical streams reject instructions and duplicates", %{
    session: session,
    native: native
  } do
    encoder = %StreamHandle{connection: native, id: 3}

    Process.put({:results, :events}, [
      {:ok, [{:stream_open, encoder, :uni}, {:readable, encoder}]}
    ])

    Process.put({:results, :read}, [{:ok, [{:data, 3, <<2, 0x20>>}]}])
    assert {:ok, session, []} = Session.poll(session, 8)
    Process.put({:results, :events}, [{:ok, [{:readable, encoder}]}])
    Process.put({:results, :read}, [{:ok, [{:data, 3, <<0x21>>}]}])

    assert {:error, _, {:http3_error, :connection, 0x201, :invalid_static_encoder_instruction}} =
             Session.poll(session, 8)

    other = %StreamHandle{connection: native, id: 7}
    Process.put({:results, :events}, [{:ok, [{:stream_open, other, :uni}, {:readable, other}]}])
    Process.put({:results, :read}, [{:ok, [{:data, 7, <<2>>}]}])

    assert {:error, _, {:http3_error, :connection, 0x103, :duplicate_qpack_encoder}} =
             Session.poll(session, 8)
  end

  test "critical stream FIN errors but unknown extension FIN retires normally", %{
    session: session,
    native: native
  } do
    encoder = %StreamHandle{connection: native, id: 3}

    Process.put({:results, :events}, [
      {:ok, [{:stream_open, encoder, :uni}, {:readable, encoder}]}
    ])

    Process.put({:results, :read}, [{:ok, [{:data, 3, <<2>>}, {:fin, 3}]}])

    assert {:error, _, {:http3_error, :connection, 0x104, :closed_critical_stream}} =
             Session.poll(session, 8)

    unknown = %StreamHandle{connection: native, id: 7}

    Process.put({:results, :events}, [
      {:ok, [{:stream_open, unknown, :uni}, {:readable, unknown}]}
    ])

    Process.put({:results, :read}, [{:ok, [{:data, 7, <<33, 1, 2, 3>>}, {:fin, 7}]}])
    assert {:ok, session, []} = Session.poll(session, 8)
    assert session.peer_streams == %{}
  end

  test "unsolicited push and static decoder instructions fail explicitly", %{
    session: session,
    native: native
  } do
    push = %StreamHandle{connection: native, id: 3}
    Process.put({:results, :events}, [{:ok, [{:stream_open, push, :uni}, {:readable, push}]}])
    Process.put({:results, :read}, [{:ok, [{:data, 3, <<1, 0>>}]}])

    assert {:error, _, {:http3_error, :connection, 0x108, :push_not_enabled}} =
             Session.poll(session, 8)

    decoder = %StreamHandle{connection: native, id: 7}

    Process.put({:results, :events}, [
      {:ok, [{:stream_open, decoder, :uni}, {:readable, decoder}]}
    ])

    Process.put({:results, :read}, [{:ok, [{:data, 7, <<3, 0x80>>}]}])

    assert {:error, _, {:http3_error, :connection, 0x202, :invalid_static_decoder_instruction}} =
             Session.poll(session, 8)
  end

  test "explicit compatible QUIC wire profile preserves cipher and extension ordering", %{
    opts: opts
  } do
    {:ok, named} = Quic.Profile.compile(:compact, alpn: ["h3"])
    supplied = %{named.tls | extensions: Enum.reverse(named.tls.extensions)}
    tls = Keyword.put(opts[:tls], :profile, supplied)
    assert {:ok, _} = Adapter.connect({127, 0, 0, 1}, 443, Keyword.put(opts, :tls, tls))
    {:call, :client, [endpoint_opts]} = Enum.find(calls(), &match?({:call, :client, _}, &1))
    assert endpoint_opts[:profile].tls == supplied
  end

  test "incompatible wire ALPN and conflicting TLS cipher policy reject before endpoint startup",
       %{opts: opts} do
    {:ok, named} = Quic.Profile.compile(:ordered, alpn: ["h2"])

    assert {:error, :invalid_h3_wire_profile} =
             Adapter.connect(
               {127, 0, 0, 1},
               443,
               Keyword.put(opts, :tls, Keyword.put(opts[:tls], :profile, named.tls))
             )

    assert {:error, {:profile_option_mismatch, :ciphers}} =
             Adapter.connect(
               {127, 0, 0, 1},
               443,
               Keyword.put(opts, :tls, Keyword.put(opts[:tls], :ciphers, [0x1302]))
             )

    refute_received {:call, :client, _}
  end

  test "supplied SNI extension policy is preserved without duplicate injection", %{opts: opts} do
    {:ok, named} = Quic.Profile.compile(:ordered, alpn: ["h3"])

    supplied = %{
      named.tls
      | extensions: [{:server_name, :from_connection} | named.tls.extensions]
    }

    tls = Keyword.put(opts[:tls], :profile, supplied)
    assert {:ok, _} = Adapter.connect("localhost", 443, Keyword.put(opts, :tls, tls))
    {:call, :client, [endpoint_opts]} = Enum.find(calls(), &match?({:call, :client, _}, &1))
    assert endpoint_opts[:profile].tls.extensions == supplied.extensions
  end

  test "malformed wire profile returns validation failure before inspecting policy", %{opts: opts} do
    {:ok, named} = Quic.Profile.compile(:ordered, alpn: ["h3"])
    tls = Keyword.put(opts[:tls], :profile, %{named.tls | extensions: nil})

    assert {:error, _reason} =
             Adapter.connect({127, 0, 0, 1}, 443, Keyword.put(opts, :tls, tls))

    refute_received {:call, :client, _}
  end

  defp poll_read(stream, items) do
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}]}])
    Process.put({:results, :read}, [{:ok, items}])
  end

  defp headers(fields) do
    {:ok, bytes} = Qpack.encode_header_block(fields)
    Frame.encode!(:headers, bytes)
  end

  defp frames(<<>>), do: []

  defp frames(bytes) do
    {:ok, frame, rest} = Frame.decode(bytes)
    [frame | frames(rest)]
  end

  defp calls(acc \\ []) do
    receive do
      {:call, _, _} = call -> calls([call | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end

defmodule QuicHttp3.WP1Test do
  use ExUnit.Case, async: true

  alias Quic.Runtime.{ConnectionHandle, StreamHandle}
  alias QuicHttp3.{Frame, Qpack, Session}
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
    connection = %ConnectionHandle{id: self(), generation: make_ref()}
    Process.put(:connection, connection)
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls/root.pem", __DIR__)
    [{:Certificate, ca, :not_encrypted}] = :public_key.pem_decode(File.read!(fixture))
    opts = [ops: Ops, tls: [cacerts: [ca], reference_identity: {:dns_id, "example.test"}]]
    {:ok, session} = Session.new(max_frame: 8)
    {:ok, session} = Session.connect(session, {127, 0, 0, 1}, 443, opts)
    %{session: session, opts: opts, native: connection}
  end

  test "attaches the native consumer and wraps generation handles in events", %{
    session: session,
    native: native
  } do
    assert_received {:call, :attach, [^native, consumer, _]}
    assert consumer == self()
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    %{stream: stream} = session.requests[ref]
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}]}])
    {:ok, headers} = Qpack.encode_header_block([{":status", "200"}])

    Process.put({:results, :read}, [
      {:ok,
       [{:data, stream.handle.id, Frame.encode!(:headers, headers)}, {:fin, stream.handle.id}]}
    ])

    assert {:ok, _, events} = Session.poll(session, 8)
    assert {:done, ref} in events
  end

  test "blocked control write keeps stream and admitted prefix", %{session: session} do
    Process.put({:results, :send_stream}, [{:ok, make_ref()}, {:blocked, :credit}])
    assert {:blocked, session, :credit} = Session.open(session)
    stream = session.control_stream
    assert stream != nil
    assert {:ok, resumed} = Session.resume(session)
    assert resumed.control_stream == stream
    calls = drain_calls()
    assert Enum.count(calls, &match?({:call, :open_stream, _}, &1)) == 1
    sends = for {:call, :send_stream, [_, bytes, _, _]} <- calls, do: bytes
    assert [first, blocked | remaining] = sends
    assert blocked == hd(remaining)
    assert first <> Enum.join(remaining) == QuicHttp3.Control.local_payload(resumed.control)
  end

  test "unknown admitted write resumes without resending", %{session: session} do
    Process.put({:results, :send_stream}, [fn [_, _, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, ref} = Session.open(session)
    Process.put({:results, :operation_status}, [%{status: :admitted, result: {:ok, ref}}])
    assert {:ok, _} = Session.resume(session)
    calls = drain_calls()
    refs = for {:call, :send_stream, [_, _, _, opts]} <- calls, do: opts[:ref]
    assert Enum.count(refs, &(&1 == ref)) == 1
  end

  test "unknown event batch and read retain exact consumed results", %{session: session} do
    {:ok, session} = Session.open(session)
    {:ok, session, request_ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[request_ref].stream
    Process.put({:results, :events}, [fn [_, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, event_ref} = Session.poll(session, 8)

    Process.put({:results, :operation_status}, [
      %{status: :completed, result: {:ok, [:writable, {:readable, stream.handle}]}}
    ])

    Process.put({:results, :read}, [fn [_, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, read_ref} = Session.resume(session)
    refute read_ref == event_ref

    Process.put({:results, :operation_status}, [
      %{status: :completed, result: {:ok, [{:reset, stream.handle.id, 0x10C, 0}]}}
    ])

    assert {:ok, _, events} = Session.resume(session)
    assert :writable in events
    assert {:stream_reset, request_ref, 0x10C, 0} in events
  end

  test "partial reads remain runnable without another readable notification", %{session: session} do
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    {:ok, headers} = Qpack.encode_header_block([{":status", "200"}])
    frame = Frame.encode!(:headers, headers)
    <<first, rest::binary>> = frame
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}]}])

    Process.put({:results, :read}, [
      {:ok, [{:data, stream.handle.id, <<first>>}]},
      {:ok, [{:data, stream.handle.id, rest}, {:fin, stream.handle.id}]}
    ])

    assert {:ok, _, events} = Session.poll(session, 8)
    assert {:done, ref} in events
  end

  test "cancels both halves with native admission refs", %{session: session} do
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    assert {:ok, session} = Session.cancel(session, ref)
    refute Map.has_key?(session.requests, ref)
    assert_received {:call, :reset_stream, [_, 0x10C, _]}
    assert_received {:call, :stop_stream, [_, 0x10C, _]}
  end

  test "unknown connect retains owned endpoint and resolves native result", %{
    opts: opts,
    native: native
  } do
    {:ok, session} = Session.new()
    Process.put({:results, :connect}, [fn [_, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, _ref} = Session.connect(session, {127, 0, 0, 1}, 443, opts)
    refute_received {:call, :stop_endpoint, _}
    Process.put({:results, :operation_status}, [%{status: :admitted, result: {:ok, native}}])
    assert {:ok, session} = Session.resume(session)
    assert session.connection.handle == native
  end

  test "expired unresolved outcome is explicitly indeterminate", %{session: session} do
    Process.put({:results, :send_stream}, [fn [_, _, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, ref} = Session.open(session)

    session = %{
      session
      | pending: %{session.pending | deadline: System.monotonic_time(:millisecond) - 1}
    }

    assert {:error, _, {:indeterminate_operation, ^ref}} = Session.resume(session)
  end

  test "secure readiness requires h3 and authenticated metadata", %{session: session} do
    Process.put({:results, :info}, [
      {:ok, %{alpn: "h2", peer_authenticated: true, tls_complete: true, parameters_valid: true}}
    ])

    assert {:error, :h3_not_negotiated} = Session.ready(session)

    Process.put({:results, :info}, [
      {:ok, %{alpn: "h3", peer_authenticated: false, tls_complete: true, parameters_valid: true}}
    ])

    assert {:error, :peer_not_authenticated} = Session.ready(session)
  end

  test "original DNS identity and SNI survive endpoint preparation", %{opts: opts} do
    tls = Keyword.delete(opts[:tls], :reference_identity)
    assert {:ok, _} = Adapter.connect("localhost", 443, Keyword.put(opts, :tls, tls))
    calls = drain_calls()

    {:call, :client, [endpoint_opts]} =
      List.last(Enum.filter(calls, &match?({:call, :client, _}, &1)))

    assert endpoint_opts[:tls][:reference_identity] == {:dns_id, "localhost"}
    assert endpoint_opts[:tls][:server_name] == "localhost"
    assert {:server_name, :from_connection} in endpoint_opts[:profile].tls.extensions
    assert endpoint_opts[:tls][:alpn] == ["h3"]
  end

  test "close stops owned endpoint and preserves shared endpoint", %{session: session, opts: opts} do
    assert :ok = Session.close(session)
    assert_received {:call, :stop_endpoint, [_]}
    assert {:ok, shared} = Session.new()
    assert {:ok, descriptor} = Adapter.client(Keyword.put(opts, :host, "127.0.0.1"))

    assert {:ok, shared} =
             Session.connect(
               shared,
               {127, 0, 0, 1},
               443,
               Keyword.put(opts, :endpoint, descriptor)
             )

    assert :ok = Session.close(shared)
    refute_received {:call, :stop_endpoint, _}
  end

  test "unknown stream open preserves the original generation and avoids replacement", %{
    session: session,
    native: native
  } do
    Process.put({:results, :open_stream}, [fn [_, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, _ref} = Session.open(session)
    stream = %StreamHandle{connection: native, id: 2}
    Process.put({:results, :operation_status}, [%{status: :admitted, result: {:ok, stream}}])
    assert {:ok, session} = Session.resume(session)
    assert session.control_stream.handle == stream
    assert Enum.count(drain_calls(), &match?({:call, :open_stream, _}, &1)) == 1
  end

  test "cancel resumes its second half without repeating reset", %{session: session} do
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    Process.put({:results, :stop_stream}, [fn [_, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, operation_ref} = Session.cancel(session, ref)
    assert Map.has_key?(session.requests, ref)

    Process.put({:results, :operation_status}, [
      %{status: :admitted, result: {:ok, operation_ref}}
    ])

    assert {:ok, session} = Session.resume(session)
    refute Map.has_key?(session.requests, ref)
    assert Enum.count(drain_calls(), &match?({:call, :reset_stream, _}, &1)) == 1
  end

  test "paused request reads retain demand while control and siblings progress", %{
    session: session
  } do
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}, :writable]}])
    assert {:ok, session, [:writable]} = Session.poll(session, 8, paused: MapSet.new([ref]))
    refute_received {:call, :read, _}
    Process.put({:results, :read}, [{:ok, [{:reset, stream.handle.id, 0x10C, 0}]}])
    assert {:ok, _, [{:stream_reset, ^ref, 0x10C, 0}]} = Session.poll(session, 8)
  end

  test "stale event generations are rejected before reading", %{session: session, native: native} do
    stream = %StreamHandle{connection: %{native | generation: make_ref()}, id: 3}
    Process.put({:results, :events}, [{:ok, [{:stream_open, stream, :uni}]}])
    assert {:error, _, :stale_stream_handle} = Session.poll(session, 8)
    refute_received {:call, :read, _}
  end

  test "unsafe TLS and TCP backend options are rejected before endpoint creation", %{opts: opts} do
    _ = drain_calls()

    assert {:error, :verify_none_not_supported} =
             Adapter.connect("example.test", 443, Keyword.put(opts, :tls, verify: :verify_none))

    assert {:error, :tls_backend_not_supported_for_quic} =
             Adapter.connect("example.test", 443, Keyword.put(opts, :tls_backend, :ssl))

    refute_received {:call, :client, _}
  end

  test "transport result bounds reject oversized drains and reads", %{session: session} do
    Process.put({:results, :events}, [{:ok, List.duplicate(:writable, 129)}])
    assert {:error, _, :invalid_event_batch} = Session.poll(session, 128)
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}]}])

    Process.put({:results, :read}, [
      {:ok, [{:data, stream.handle.id, String.duplicate("x", 16_385)}]}
    ])

    assert {:error, _, :invalid_read_batch} = Session.poll(session, 8)
  end

  test "native read stream identity is checked", %{session: session} do
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    stream = session.requests[ref].stream
    Process.put({:results, :events}, [{:ok, [{:readable, stream.handle}]}])
    Process.put({:results, :read}, [{:ok, [{:reset, stream.handle.id + 4, 0x10C, 0}]}])
    assert {:error, _, :invalid_stream_identity} = Session.poll(session, 8)
  end

  test "peer initiated bidirectional streams are explicit protocol failures", %{
    session: session,
    native: native
  } do
    Process.put({:results, :events}, [
      {:ok, [{:stream_open, %StreamHandle{connection: native, id: 1}, :bidi}]}
    ])

    assert {:error, _, :peer_bidirectional_stream} = Session.poll(session, 8)
  end

  test "default SNI comes from DNS host independently of reference identity", %{opts: opts} do
    assert {:ok, _} = Adapter.connect("localhost", 443, opts)
    calls = drain_calls()

    {:call, :client, [endpoint_opts]} =
      List.last(Enum.filter(calls, &match?({:call, :client, _}, &1)))

    assert endpoint_opts[:tls][:reference_identity] == {:dns_id, "example.test"}
    assert endpoint_opts[:tls][:server_name] == "localhost"
  end

  test "connection already closed still cleans its owned endpoint", %{session: session} do
    Process.put({:results, :close}, [{:error, :closed}])
    assert :ok = Session.close(session)
    assert_received {:call, :stop_endpoint, [_]}
  end

  test "definitive attach failure retains cleanup context", %{opts: opts} do
    {:ok, session} = Session.new()
    Process.put({:results, :attach}, [{:error, :not_consumer}])

    assert {:error, session, {:attach_failed, {:error, :not_consumer}}} =
             Session.connect(session, {127, 0, 0, 1}, 443, opts)

    assert session.connection.endpoint == self()
    assert :ok = Session.close(session)
    assert_received {:call, :stop_endpoint, [_]}
  end

  test "attach timeout retries only attachment to known connection", %{opts: opts} do
    {:ok, session} = Session.new()
    _ = drain_calls()
    Process.put({:results, :attach}, [{:error, :timeout}])
    assert {:unknown, session, _ref} = Session.connect(session, {127, 0, 0, 1}, 443, opts)
    assert session.connection.handle != nil
    refute_received {:call, :stop_endpoint, _}
    assert {:ok, _session} = Session.resume(session)
    assert Enum.count(drain_calls(), &match?({:call, :connect, _}, &1)) == 1
  end

  test "cancelled paused stream ignores only its terminal late events while sibling progresses",
       %{session: session} do
    {:ok, session} = Session.open(session)
    {:ok, session, cancelled_ref} = Session.request(session, [{":path", "/cancelled"}], "", [])
    {:ok, session, sibling_ref} = Session.request(session, [{":path", "/sibling"}], "", [])
    cancelled = session.requests[cancelled_ref].stream
    sibling = session.requests[sibling_ref].stream
    Process.put({:results, :events}, [{:ok, [{:readable, cancelled.handle}]}])
    {:ok, session, []} = Session.poll(session, 8, paused: MapSet.new([cancelled_ref]))
    {:ok, session} = Session.cancel(session, cancelled_ref)

    Process.put({:results, :events}, [
      {:ok,
       [
         {:readable, cancelled.handle},
         {:stopped, cancelled.handle, 0x10C},
         {:readable, sibling.handle}
       ]}
    ])

    Process.put({:results, :read}, [{:ok, [{:reset, sibling.handle.id, 0x10C, 0}]}])
    assert {:ok, _session, [{:stream_reset, ^sibling_ref, 0x10C, 0}]} = Session.poll(session, 8)
    cancelled_handle = cancelled.handle
    refute_received {:call, :read, [^cancelled_handle, _, _]}
  end

  test "recovered rejection becomes safely resumable blocked work", %{session: session} do
    Process.put({:results, :send_stream}, [fn [_, _, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, _ref} = Session.open(session)

    Process.put({:results, :operation_status}, [%{status: :rejected, result: {:blocked, :credit}}])

    assert {:blocked, session, :credit} = Session.resume(session)
    assert {:ok, _session} = Session.resume(session)
  end

  test "repeated attach timeout retains known connection and pending identity", %{opts: opts} do
    {:ok, session} = Session.new()
    Process.put({:results, :attach}, [{:error, :timeout}, {:error, :timeout}])
    assert {:unknown, session, ref} = Session.connect(session, {127, 0, 0, 1}, 443, opts)
    assert {:unknown, session, ^ref} = Session.resume(session)
    assert {:ok, _session} = Session.resume(session)
  end

  test "raw shared endpoints are rejected and descriptors bind immutable TLS", %{opts: opts} do
    assert {:error, :unverified_endpoint} =
             Adapter.connect({127, 0, 0, 1}, 443, Keyword.put(opts, :endpoint, self()))

    assert {:ok, descriptor} = Adapter.client(Keyword.put(opts, :host, "127.0.0.1"))
    changed_tls = Keyword.put(opts[:tls], :reference_identity, {:dns_id, "wrong.test"})

    assert {:error, :endpoint_configuration_mismatch} =
             Adapter.connect(
               {127, 0, 0, 1},
               443,
               opts |> Keyword.put(:endpoint, descriptor) |> Keyword.put(:tls, changed_tls)
             )
  end

  test "unknown connect rejected later still permits endpoint cleanup", %{opts: opts} do
    {:ok, session} = Session.new()
    Process.put({:results, :connect}, [fn [_, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, _ref} = Session.connect(session, {127, 0, 0, 1}, 443, opts)

    Process.put({:results, :operation_status}, [
      %{status: :rejected, result: {:error, :deadline_expired}}
    ])

    assert {:error, session, :deadline_expired} = Session.resume(session)
    assert :ok = Session.close(session)
    assert_received {:call, :stop_endpoint, [_]}
  end

  test "terminal abort releases owned endpoint without replaying indeterminate mutation", %{
    session: session
  } do
    _ = drain_calls()
    Process.put({:results, :send_stream}, [fn [_, _, _, opts] -> {:unknown, opts[:ref]} end])
    assert {:unknown, session, ref} = Session.open(session)

    session = %{
      session
      | pending: %{session.pending | deadline: System.monotonic_time(:millisecond) - 1}
    }

    assert {:error, session, {:indeterminate_operation, ^ref}} = Session.resume(session)
    assert {:ok, session} = Session.abort(session)
    assert session.connection == nil
    calls = drain_calls()
    assert Enum.count(calls, &match?({:call, :send_stream, _}, &1)) == 1
    assert Enum.count(calls, &match?({:call, :stop_endpoint, _}, &1)) == 1
  end

  defp drain_calls(acc \\ []) do
    receive do
      {:call, _, _} = call -> drain_calls([call | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end
end

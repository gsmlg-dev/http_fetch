defmodule QuicHttp3.NativeSessionTest do
  use ExUnit.Case, async: true

  alias Quic.Runtime.StreamHandle
  alias QuicHttp3.{Frame, Qpack, Session, Varint}

  setup do
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, server} = Quic.listen(tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]])
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    opts = [tls: [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]]
    %{server: server, opts: opts}
  end

  test "Session and real adapter exchange native UDP response and cancellation", %{
    server: server,
    opts: opts
  } do
    {ip, port} = Quic.local(server)
    {:ok, session} = Session.new(max_frame: 8)
    {:ok, session} = Session.connect(session, ip, port, opts)
    endpoint = session.connection.endpoint
    on_exit(fn -> if Process.alive?(endpoint), do: GenServer.stop(endpoint) end)
    connection = session.connection.handle
    assert_receive {:quic_ready, ^connection, %{alpn: "h3", peer_authenticated: true}}, 2_000
    assert :ready = Session.ready(session)
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    {:ok, session} = Session.open(session)
    {:ok, session, ref} = Session.request(session, [{":path", "/"}], "", [])
    request = session.requests[ref].stream.handle
    incoming = %StreamHandle{connection: accepted, id: request.id}
    events = await_events(accepted, fn events -> {:readable, incoming} in events end)
    assert {:stream_open, incoming, :bidi} in events
    request_items = await_fin(incoming, System.monotonic_time(:millisecond) + 2_000, [])
    assert Enum.any?(request_items, &match?({:fin, _}, &1))
    {:ok, headers} = Qpack.encode_header_block([{":status", "200"}])

    {:ok, _} =
      Quic.send_stream(
        incoming,
        Frame.encode!(:headers, headers) <> Frame.encode!(:data, "native UDP"),
        true
      )

    {session, response_events} = await_session(session, fn events -> {:done, ref} in events end)
    assert {:headers, ref, [{":status", "200"}]} in response_events
    body = for {:data, ^ref, bytes} <- response_events, into: <<>>, do: bytes
    assert body == "native UDP"
    assert {:error, _session, :unknown_request} = Session.cancel(session, ref)
    {:ok, session, sibling_ref} = Session.request(session, [{":path", "/cancel-active"}], "", [])
    assert {:ok, session} = Session.cancel(session, sibling_ref)
    assert :ok = Session.close(session)
    refute Process.alive?(endpoint)
  end

  test "wrong certificate identity fails readiness without opening HTTP streams", %{
    server: server,
    opts: opts
  } do
    {ip, port} = Quic.local(server)
    tls = Keyword.put(opts[:tls], :reference_identity, {:dns_id, "wrong.test"})
    {:ok, session} = Session.new()
    {:ok, session} = Session.connect(session, ip, port, Keyword.put(opts, :tls, tls))
    endpoint = session.connection.endpoint
    on_exit(fn -> if Process.alive?(endpoint), do: GenServer.stop(endpoint) end)
    connection = session.connection.handle
    assert_receive {:quic_closed, ^connection, _reason}, 2_000
    assert {:error, :closed} = Session.ready(session)
    assert {:error, _, :closed} = Session.open(session)
  end

  test "native UDP binary upload preserves DATA payloads across frame and write boundaries",
       context do
    {session, accepted} = native_session(context)
    body = :binary.copy(<<0, 1, 13, 10, 255, 17, 42>>, 6_000)

    {:ok, session, ref} =
      Session.request(session, [{":method", "POST"}, {":path", "/binary"}], body, [])

    {incoming, frames} = receive_request(session, accepted, ref)
    assert [{1, _headers} | data] = frames
    assert length(data) == 3
    assert Enum.all?(data, fn {type, bytes} -> type == 0 and byte_size(bytes) <= 16_384 end)
    assert IO.iodata_to_binary(Enum.map(data, &elem(&1, 1))) == body
    complete_request(session, incoming, ref)
  end

  test "native UDP streamed upload sends requested DATA chunks and an empty final write",
       context do
    {session, accepted} = native_session(context)

    {:ok, session, ref} =
      Session.request(session, [{":method", "POST"}, {":path", "/stream"}], :stream, [])

    chunks = [:binary.copy(<<255, 0>>, 8_192), <<1, 13, 10>>, :binary.copy(<<42>>, 8_193)]

    session =
      Enum.reduce(chunks, session, fn bytes, session ->
        {:ok, next} = Session.send_data(session, ref, bytes, false, [])
        next
      end)

    {:ok, session} = Session.send_data(session, ref, <<>>, true, [])
    {incoming, frames} = receive_request(session, accepted, ref)
    assert [{1, _headers} | data] = frames
    assert data == Enum.map(chunks, &{0, &1})
    assert {:error, _, :upload_closed} = Session.send_data(session, ref, "later", true, [])
    complete_request(session, incoming, ref)
  end

  defp native_session(%{server: server, opts: opts}) do
    {ip, port} = Quic.local(server)
    {:ok, session} = Session.new(max_frame: 1_024)
    {:ok, session} = Session.connect(session, ip, port, opts)
    endpoint = session.connection.endpoint
    on_exit(fn -> if Process.alive?(endpoint), do: GenServer.stop(endpoint) end)
    connection = session.connection.handle
    assert_receive {:quic_ready, ^connection, %{alpn: "h3", peer_authenticated: true}}, 2_000
    assert_receive {:quic_accept, ^server}, 2_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    {:ok, session} = Session.open(session)
    {session, accepted}
  end

  defp receive_request(session, accepted, ref) do
    incoming = %StreamHandle{connection: accepted, id: session.requests[ref].stream.handle.id}
    _ = await_events(accepted, fn events -> {:readable, incoming} in events end)
    items = await_fin(incoming, System.monotonic_time(:millisecond) + 2_000, [])
    assert List.last(items) == {:fin, incoming.id}
    wire = for {:data, _id, bytes} <- items, into: <<>>, do: bytes
    {incoming, decode_wire(wire)}
  end

  # Decode the concatenated peer stream without the sender's frame codec.
  defp decode_wire(<<>>), do: []

  defp decode_wire(wire) do
    {:ok, type, rest} = Varint.decode(wire)
    {:ok, size, rest} = Varint.decode(rest)
    <<payload::binary-size(^size), rest::binary>> = rest
    [{type, payload} | decode_wire(rest)]
  end

  defp complete_request(session, incoming, ref) do
    {:ok, headers} = Qpack.encode_header_block([{":status", "200"}])
    {:ok, _} = Quic.send_stream(incoming, Frame.encode!(:headers, headers), true)
    {session, events} = await_session(session, fn events -> {:done, ref} in events end)
    assert {:headers, ref, [{":status", "200"}]} in events
    assert session.requests == %{}
    assert :ok = Session.close(session)
    refute Process.alive?(session.connection.endpoint)
  end

  defp await_fin(stream, deadline, acc) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc ++ items
    if Enum.any?(items, &match?({:fin, _}, &1)), do: acc, else: await_fin(stream, deadline, acc)
  end

  defp await_events(handle, predicate),
    do: await_events(handle, predicate, System.monotonic_time(:millisecond) + 2_000, [])

  defp await_events(handle, predicate, deadline, acc) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(handle)
    acc = acc ++ events
    if predicate.(acc), do: acc, else: await_events(handle, predicate, deadline, acc)
  end

  defp await_session(session, predicate),
    do: await_session(session, predicate, System.monotonic_time(:millisecond) + 2_000, [])

  defp await_session(session, predicate, deadline, acc) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, session, events} = Session.poll(session, 128)
    acc = acc ++ events
    if predicate.(acc), do: {session, acc}, else: await_session(session, predicate, deadline, acc)
  end
end

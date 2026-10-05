defmodule HTTP.EventSource.HTTP3Test do
  use ExUnit.Case, async: false

  alias HTTP.EventSource
  alias HTTP.EventSource.Event.{Error, Message, Open}
  alias Quic.Runtime.StreamHandle
  alias QuicHttp3.{Frame, Qpack}

  setup do
    fixture = Path.expand("../../../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, server} = Quic.listen(tls: [cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]])
    on_exit(fn -> if Process.alive?(server), do: GenServer.stop(server) end)
    {_, port} = Quic.local(server)
    ssl = [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}]
    %{server: server, url: "https://127.0.0.1:#{port}/events", ssl: ssl}
  end

  test "native HTTP3 preserves split BOM, UTF8, informational headers and trailers", context do
    source = source(context)
    accepted = accept(context.server)
    stream = request(accepted, 0)
    write(stream, headers(103, [{"link", "</style.css>"}]), false)
    write(stream, headers(200, [{"content-type", "text/event-stream"}]), false)

    for data <- [
          <<0xEF>>,
          <<0xBB, 0xBF>>,
          "id: 7\r\nevent: custom\r\ndata: ",
          <<0xCE>>,
          <<0xBB>>,
          "\r",
          "\ndata: second\r\n\r\nid:\ndata: reset\n\n"
        ] do
      write(stream, Frame.encode!(:data, data), false)
    end

    {:ok, trailers} = Qpack.encode_header_block([{"x-trailer", "ignored"}])
    write(stream, Frame.encode!(:headers, trailers), true)
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert EventSource.http_version(source) == :http3

    assert_receive {EventSource, ^source,
                    %Message{type: "custom", data: "λ\nsecond", last_event_id: "7"}},
                   5_000

    assert_receive {EventSource, ^source, %Message{data: "reset", last_event_id: ""}}, 5_000
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 5_000
  end

  test "HTTP3 acknowledged deliveries stay bounded and drain before EOF", context do
    source =
      source(context,
        delivery: :ack,
        max_event_size: 32,
        max_queue_bytes: 80,
        max_queue_events: 2,
        idle_timeout: 30_000
      )

    accepted = accept(context.server)
    stream = request(accepted, 0)
    body = Enum.map_join(1..30, &"data: #{&1}\n\n")

    write(
      stream,
      headers(200, [{"content-type", "text/event-stream"}]) <> Frame.encode!(:data, body),
      true
    )

    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "1"}, first}, 5_000

    assert %{queued_events: 2, raw_bytes: bytes, queued_bytes: queued} =
             EventSource.status(source)

    assert bytes > 0
    assert queued <= 80
    assert :sys.get_state(source.pid).idle_timer == nil
    refute_receive {EventSource, ^source, %Error{}}, 0
    assert :ok = EventSource.acknowledge(source, first)

    for number <- 2..30 do
      expected = Integer.to_string(number)
      assert_receive {EventSource, ^source, %Message{data: ^expected}, ref}, 5_000
      assert :ok = EventSource.acknowledge(source, ref)
    end

    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 5_000
    assert %{queued_events: 0, raw_bytes: 0} = EventSource.status(source)
  end

  test "HTTP3 reconnect carries dispatched cursor and rejects stale relay messages", context do
    source = source(context)
    accepted = accept(context.server)
    stream = request(accepted, 0)

    write(
      stream,
      headers(200, [{"content-type", "text/event-stream"}]) <>
        Frame.encode!(:data, "id: 7\ndata: first\n\n"),
      false
    )

    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "first", last_event_id: "7"}}, 5_000
    previous = :sys.get_state(source.pid)
    write(stream, <<>>, true)
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 5_000
    {_timer, token} = :sys.get_state(source.pid).reconnect_timer
    send(source.pid, {:reconnect, token})
    next = request(accepted, 4, fn fields -> assert {"last-event-id", "7"} in fields end)
    send(source.pid, {:http_runtime, previous.generation, previous.stream, {:error, :stale}})

    write(
      next,
      headers(200, [{"content-type", "text/event-stream"}]) <>
        Frame.encode!(:data, "data: second\n\n"),
      false
    )

    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "second", last_event_id: "7"}}, 5_000
    refute_receive {EventSource, ^source, %Error{reason: :stale}}, 0
    assert EventSource.http_version(source) == :http3
  end

  test "HTTP3 redirects retain selection and same-origin request headers", context do
    source = source(context, headers: [{"Authorization", "Bearer token"}])
    accepted = accept(context.server)
    stream = request(accepted, 0)
    write(stream, headers(307, [{"location", "/next?cursor=7"}]), true)

    next =
      request(accepted, 4, fn fields ->
        assert {":path", "/next?cursor=7"} in fields
        assert {"authorization", "Bearer token"} in fields
      end)

    write(
      next,
      headers(200, [{"content-type", "text/event-stream"}]) <>
        Frame.encode!(:data, "data: redirected\n\n"),
      false
    )

    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "redirected"}}, 5_000
    assert EventSource.http_version(source) == :http3
  end

  test "HTTP3 wrong certificate identity closes without establishing or downgrading", context do
    source =
      source(context, ssl: Keyword.put(context.ssl, :reference_identity, {:dns_id, "wrong.test"}))

    assert_receive {EventSource, ^source, %Error{reason: {:http3_not_established, _} = reason}},
                   5_000

    assert EventSource.ready_state(source) == EventSource.closed(), inspect(reason)
    assert EventSource.http_version(source) == nil
    refute_receive {EventSource, ^source, %Open{}}, 0
  end

  test "closing one HTTP3 EventSource leaves a reused sibling readable", context do
    first = source(context)
    accepted = accept(context.server)
    stream = request(accepted, 0)

    write(
      stream,
      headers(200, [{"content-type", "text/event-stream"}]) <>
        Frame.encode!(:data, "data: first\n\n"),
      false
    )

    assert_receive {EventSource, ^first, %Message{data: "first"}}, 5_000
    sibling = source(%{context | url: context.url <> "?sibling=1"})
    sibling_stream = request(accepted, 4)

    write(
      sibling_stream,
      headers(200, [{"content-type", "text/event-stream"}]) <>
        Frame.encode!(:data, "data: sibling\n\n"),
      false
    )

    assert_receive {EventSource, ^sibling, %Message{data: "sibling"}}, 5_000
    monitor = Process.monitor(first.pid)
    assert :ok = EventSource.close(first)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 5_000
    write(sibling_stream, Frame.encode!(:data, "data: still-open\n\n"), false)
    assert_receive {EventSource, ^sibling, %Message{data: "still-open"}}, 5_000
    assert EventSource.ready_state(sibling) == EventSource.open()
    assert EventSource.http_version(sibling) == :http3
    refute_receive {EventSource, ^sibling, %Error{}}, 0
  end

  test "HTTP3 established native TLS failure terminates without reconnect", context do
    source = source(context)
    accepted = accept(context.server)
    stream = request(accepted, 0)
    write(stream, headers(200, [{"content-type", "text/event-stream"}]), false)
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    state = :sys.get_state(source.pid)
    monitor = Process.monitor(source.pid)
    reason = {:owner_down, {:shutdown, {:tls, :tls, :decode_error, :invalid_ticket}}}
    send(source.pid, {:http_runtime, state.generation, state.stream, {:error, reason}})
    assert_receive {EventSource, ^source, %Error{reason: ^reason}}, 1_000
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 500
    assert EventSource.ready_state(source) == EventSource.closed()
  end

  test "HTTP3 established ordinary peer closure remains reconnectable", context do
    source = source(context)
    accepted = accept(context.server)
    stream = request(accepted, 0)
    write(stream, headers(200, [{"content-type", "text/event-stream"}]), false)
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    state = :sys.get_state(source.pid)
    reason = {:owner_down, {:shutdown, {:closed, :normal}}}
    send(source.pid, {:http_runtime, state.generation, state.stream, {:error, reason}})
    assert_receive {EventSource, ^source, %Error{reason: ^reason}}, 1_000
    assert EventSource.ready_state(source) == EventSource.connecting()
    assert Process.alive?(source.pid)
    assert :sys.get_state(source.pid).reconnect_timer != nil
  end

  test "HTTP3 established lifetime has an EventSource idle timer and rejects stale timer tokens",
       context do
    source = source(context, idle_timeout: 30_000)
    accepted = accept(context.server)
    stream = request(accepted, 0)

    write(
      stream,
      headers(200, [{"content-type", "text/event-stream"}]) <>
        Frame.encode!(:data, "data: first\n\n"),
      false
    )

    assert_receive {EventSource, ^source, %Message{data: "first"}}, 5_000
    {_timer, original} = :sys.get_state(source.pid).idle_timer
    write(stream, Frame.encode!(:data, ": heartbeat\n\n"), false)
    current = await_idle_token(source, original, System.monotonic_time(:millisecond) + 5_000)
    send(source.pid, {:idle_timeout, original})
    assert EventSource.ready_state(source) == EventSource.open()
    send(source.pid, {:idle_timeout, current})
    assert_receive {EventSource, ^source, %Error{reason: :idle_timeout}}, 5_000
    assert EventSource.ready_state(source) == EventSource.connecting()
    assert :sys.get_state(source.pid).opening_timer == nil
  end

  defp source(context, opts \\ []) do
    source =
      EventSource.new(
        context.url,
        Keyword.merge([http_version: :http3, ssl: context.ssl, reconnect_time: 30_000], opts)
      )

    assert %EventSource{} = source
    on_exit(fn -> EventSource.close(source) end)
    source
  end

  defp accept(server) do
    assert_receive {:quic_accept, ^server}, 5_000
    {:ok, accepted} = Quic.accept(server)
    :ok = Quic.attach(accepted, self())
    on_exit(fn -> Quic.close(accepted, 0x100, <<>>) end)
    accepted
  end

  defp await_idle_token(source, original, deadline) do
    assert System.monotonic_time(:millisecond) < deadline
    {_timer, token} = :sys.get_state(source.pid).idle_timer
    if token == original, do: await_idle_token(source, original, deadline), else: token
  end

  defp request(connection, id, check \\ fn _ -> :ok end) do
    deadline = System.monotonic_time(:millisecond) + 5_000
    stream = await_stream(connection, id, deadline)
    items = await_fin(stream, deadline, [])
    wire = for {:data, ^id, bytes} <- items, into: <<>>, do: bytes
    {:ok, %{type: 1, payload: payload}, <<>>} = Frame.decode(wire)
    {:ok, fields} = Qpack.decode_header_block(payload)
    assert {":method", "GET"} in fields
    assert {"accept", "text/event-stream"} in fields
    check.(fields)
    stream
  end

  defp await_stream(connection, id, deadline) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, events} = Quic.events(connection)

    case Enum.find(events, &match?({:stream_open, %StreamHandle{id: ^id}, :bidi}, &1)) do
      {:stream_open, stream, :bidi} -> stream
      nil -> await_stream(connection, id, deadline)
    end
  end

  defp await_fin(stream, deadline, acc) do
    assert System.monotonic_time(:millisecond) < deadline
    {:ok, items} = Quic.read(stream, 16_384)
    acc = acc ++ items
    if Enum.any?(items, &match?({:fin, _}, &1)), do: acc, else: await_fin(stream, deadline, acc)
  end

  defp headers(status, fields) do
    {:ok, payload} = Qpack.encode_header_block([{":status", Integer.to_string(status)} | fields])
    Frame.encode!(:headers, payload)
  end

  defp write(stream, bytes, fin), do: assert({:ok, _} = Quic.send_stream(stream, bytes, fin))
end

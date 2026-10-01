defmodule HTTP.EventSource.HTTP2Test do
  use ExUnit.Case, async: false

  alias HTTP.EventSource
  alias HTTP.EventSource.Event.Error
  alias HTTP.EventSource.Event.Message
  alias HTTP.EventSource.Event.Open

  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  test "h2c preserves split BOM, UTF8, CRLF, cursor reset and ignores informational headers/trailers" do
    {url, peer} =
      peer(fn socket ->
        {id, flags, _} = request(socket)
        assert flags == 5
        :ok = :gen_tcp.send(socket, frame(1, 4, id, headers([{":status", "103"}])))
        :ok = :gen_tcp.send(socket, response_headers(id))

        for data <- [
              <<0xEF>>,
              <<0xBB, 0xBF>>,
              "id: 7\r\nevent: custom\r\ndata: ",
              <<0xCE>>,
              <<0xBB>>,
              "\r",
              "\ndata: second\r\n\r\nid:\ndata: reset\n\n"
            ] do
          :ok = :gen_tcp.send(socket, frame(0, 0, id, data))
        end

        :ok = :gen_tcp.send(socket, frame(1, 5, id, headers([{"x-trailer", "ignored"}])))
      end)

    source = source(url, reconnect_time: 30_000)
    assert_receive {EventSource, ^source, %Open{}}, 5_000

    assert_receive {EventSource, ^source,
                    %Message{type: "custom", data: "λ\nsecond", last_event_id: "7"}},
                   5_000

    assert_receive {EventSource, ^source, %Message{data: "reset", last_event_id: ""}}, 5_000
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 5_000
    refute_receive {EventSource, ^source, %Open{}}, 20
    send(peer, :stop)
  end

  test "acknowledged coalesced tiny events pause within bounds and drain without overload" do
    {url, peer} =
      peer(fn socket ->
        {id, _, _} = request(socket)
        data = Enum.map_join(1..30, &"data: #{&1}\n\n")
        :ok = :gen_tcp.send(socket, [response_headers(id), frame(0, 0, id, data)])
      end)

    source =
      source(url,
        delivery: :ack,
        max_event_size: 32,
        max_queue_bytes: 80,
        max_queue_events: 2,
        idle_timeout: 1_000
      )

    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "1"}, first}, 5_000
    status = EventSource.status(source)
    assert status.queued_events == 2
    assert status.raw_bytes > 0
    assert status.raw_chunks == 1
    assert status.queued_bytes <= 80
    assert status.parser_bytes <= 32
    # A local pause has no idle timer; a forged stale timer is harmless.
    state = :sys.get_state(source.pid)
    assert state.idle_timer == nil
    send(source.pid, {:idle_timeout, make_ref()})
    assert EventSource.acknowledge(source, make_ref()) == :ok
    assert EventSource.acknowledge(source, first) == :ok
    assert EventSource.acknowledge(source, first) == :ok

    for number <- 2..30 do
      expected = Integer.to_string(number)
      assert_receive {EventSource, ^source, %Message{data: ^expected}, ref}, 5_000
      assert EventSource.acknowledge(source, ref) == :ok
    end

    assert %{queued_events: 0, queued_bytes: 0, raw_bytes: 0, raw_chunks: 0} =
             EventSource.status(source)

    assert :ok = EventSource.close(source)
    send(peer, :stop)
  end

  test "only this SSE stream's body activity refreshes its idle timer" do
    parent = self()
    heartbeat = ": heartbeat\n\n"
    ping = "sse-idle"

    {url, peer} =
      peer(fn socket ->
        {sse, _, _} = request(socket)
        :ok = :gen_tcp.send(socket, response_headers(sse))

        receive do
          :heartbeat -> :ok = :gen_tcp.send(socket, frame(0, 0, sse, heartbeat))
        after
          5_000 -> flunk("missing heartbeat barrier")
        end

        # Stream credit proves the comment body reached the SSE consumer.
        assert {8, 0, ^sse, <<0::1, credit::31>>} = next_frame(socket, 8, sse)
        assert credit == byte_size(heartbeat)
        send(parent, {:heartbeat_consumed, self()})

        receive do
          :ping -> :ok = :gen_tcp.send(socket, frame(6, 0, 0, ping))
        after
          5_000 -> flunk("missing PING barrier")
        end

        assert {6, 1, 0, ^ping} = next_frame(socket, 6, 0)
        send(parent, {:ping_acknowledged, self()})

        {fetch, _, _} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, fetch, headers([{":status", "200"}, {"content-length", "5"}])),
            frame(0, 1, fetch, "fetch")
          ])

        assert {3, 0, ^sse, <<8::32>>} = next_frame(socket, 3, sse)
        send(parent, {:idle_stream_reset, self()})
      end)

    scope = "sse-idle-#{System.unique_integer([:positive])}"
    source = source(url, http2_scope: scope, idle_timeout: 30_000, reconnect_time: 30_000)
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    %{stream_handle: %{owner: owner}} = EventSource.status(source)
    {initial_timer, initial_token} = :sys.get_state(source.pid).idle_timer

    send(peer, :heartbeat)
    assert_receive {:heartbeat_consumed, ^peer}, 5_000
    {heartbeat_timer, heartbeat_token} = :sys.get_state(source.pid).idle_timer
    assert heartbeat_token != initial_token
    assert Process.read_timer(initial_timer) == false
    assert is_integer(Process.read_timer(heartbeat_timer))
    refute_receive {EventSource, ^source, %Message{}}, 0

    send(source.pid, {:idle_timeout, initial_token})
    assert EventSource.ready_state(source) == EventSource.open()

    send(peer, :ping)
    assert_receive {:ping_acknowledged, ^peer}, 5_000
    assert :sys.get_state(source.pid).idle_timer == {heartbeat_timer, heartbeat_token}

    promise = HTTP.fetch(url, http_version: :h2c, http2_scope: scope, connect_timeout: 30_000)
    assert HTTP.Promise.await(promise).body == "fetch"
    assert :sys.get_state(source.pid).idle_timer == {heartbeat_timer, heartbeat_token}
    assert EventSource.ready_state(source) == EventSource.open()
    refute_receive {EventSource, ^source, %Error{}}, 0

    # Exercise the current deadline token directly, without an elapsed-time claim.
    send(source.pid, {:idle_timeout, heartbeat_token})
    assert_receive {EventSource, ^source, %Error{reason: :idle_timeout}}, 5_000
    assert_receive {:idle_stream_reset, ^peer}, 5_000
    assert Process.alive?(owner)
    assert EventSource.ready_state(source) == EventSource.connecting()
    assert :ok = EventSource.close(source)
    send(peer, :stop)
  end

  test "an event larger than one receive window returns credit during bounded assembly" do
    parent = self()

    payload =
      Enum.map_join(1..160, fn _ -> "data: " <> String.duplicate("x", 1024) <> "\n" end) <> "\n"

    {url, peer} =
      peer(fn socket ->
        {id, _, _} = request(socket)
        :ok = :gen_tcp.send(socket, response_headers(id))

        for chunk <- chunks(payload, 16_384) do
          :ok = :gen_tcp.send(socket, frame(0, 0, id, chunk))
          assert {8, 0, ^id, <<0::1, credit::31>>} = next_frame(socket, 8, id)
          assert credit == byte_size(chunk)
        end

        send(parent, {:all_credit_returned, self()})
      end)

    source = source(url, delivery: :ack)
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: data}, ref}, 5_000
    assert byte_size(data) == 160 * 1025 - 1
    assert_receive {:all_credit_returned, ^peer}, 5_000
    assert %{queued_events: 1, raw_bytes: 0, parser_parts: 0} = EventSource.status(source)
    assert :ok = EventSource.acknowledge(source, ref)
    assert :ok = EventSource.close(source)
  end

  test "short undelimited lines terminate at the event bound without reconnect" do
    {url, _peer} =
      peer(fn socket ->
        {id, _, _} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            response_headers(id),
            frame(0, 0, id, String.duplicate("data: x\n", 40))
          ])
      end)

    source = source(url, max_event_size: 32, reconnect_time: 0)
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Error{reason: :event_too_large}}, 5_000
    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {EventSource, ^source, %Open{}}, 20
  end

  for {status, content_type, reason} <- [
        {204, nil, {:http_status, 204}},
        {200, "application/json", :invalid_content_type},
        {403, nil, {:http_status, 403}}
      ] do
    test "final response #{status}/#{inspect(content_type)} is fatal" do
      {url, _peer} =
        peer(fn socket ->
          {id, _, _} = request(socket)
          fields = [{":status", Integer.to_string(unquote(status))}]

          fields =
            if unquote(content_type),
              do: fields ++ [{"content-type", unquote(content_type)}],
              else: fields

          :ok = :gen_tcp.send(socket, frame(1, 5, id, headers(fields)))
        end)

      source = source(url)
      assert_receive {EventSource, ^source, %Error{reason: reason}}, 5_000
      assert reason == unquote(Macro.escape(reason))
      assert EventSource.ready_state(source) == EventSource.closed()
    end
  end

  test "reconnect reuses an eligible owner and sends the latest cursor, including empty resets" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {first, _, fields} = request(socket)
        refute Enum.any?(fields, fn {name, _} -> name == "last-event-id" end)

        :ok =
          :gen_tcp.send(socket, [
            response_headers(first),
            frame(0, 1, first, "id: 7\ndata: first\n\n")
          ])

        {second, _, fields} = request(socket)
        assert {"last-event-id", "7"} in fields

        :ok =
          :gen_tcp.send(socket, [
            response_headers(second),
            frame(0, 1, second, "id:\ndata: reset\n\n")
          ])

        {third, _, fields} = request(socket)
        refute Enum.any?(fields, fn {name, _} -> name == "last-event-id" end)
        send(parent, {:cursor_requests, self(), first, second, third})

        :ok =
          :gen_tcp.send(socket, [response_headers(third), frame(0, 0, third, "data: third\n\n")])
      end)

    source = source(url, reconnect_time: 0, headers: [{"Last-Event-ID", "stale"}])
    assert_receive {EventSource, ^source, %Message{data: "first"}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "reset", last_event_id: ""}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "third", last_event_id: ""}}, 5_000
    assert_receive {:cursor_requests, ^peer, first, second, third}, 5_000
    assert first < second and second < third
    assert EventSource.http_version(source) == :http2
    assert %{stream_handle: %{id: ^third}} = EventSource.status(source)
  end

  test "GOAWAY keeps accepted SSE data and closing SSE preserves a Fetch sibling owner" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {sse, _, _} = request(socket)
        :ok = :gen_tcp.send(socket, response_headers(sse))
        {fetch, _, _} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, fetch, headers([{":status", "200"}, {"content-length", "5"}])),
            frame(7, 0, 0, <<0::1, fetch::31, 0::32>>),
            frame(0, 0, sse, "data: after-goaway\n\n")
          ])

        assert {3, 0, ^sse, <<8::32>>} = next_frame(socket, 3, sse)
        send(parent, {:sse_reset, self()})

        receive do
          :finish_fetch -> :ok = :gen_tcp.send(socket, frame(0, 1, fetch, "fetch"))
        after
          5_000 -> flunk("missing Fetch completion barrier")
        end
      end)

    scope = "sse-mixed-#{System.unique_integer([:positive])}"
    source = source(url, http2_scope: scope)
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    %{stream_handle: %{owner: owner}} = EventSource.status(source)

    promise =
      HTTP.fetch(url, http_version: :h2c, http2_scope: scope, connect_timeout: 30_000)

    assert_receive {EventSource, ^source, %Message{data: "after-goaway"}}, 5_000
    assert :ok = EventSource.close(source)
    assert_receive {:sse_reset, ^peer}, 5_000
    assert Process.alive?(owner)
    send(peer, :finish_fetch)
    assert HTTP.Promise.await(promise).body == "fetch"
  end

  test "closing an unfinished TLS dial is responsive and stale generations are ignored" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          assert {:ok, _hello} = :gen_tcp.recv(socket, 0, 5_000)
          send(parent, {:accepted, self()})
          assert_tls_closed(socket)
          send(parent, {:dial_closed, self()})
        end,
        false
      )

    source =
      EventSource.new(String.replace(url, "http:", "https:"),
        connect_timeout: 30_000,
        ssl: [verify: :verify_none]
      )

    assert_receive {:accepted, ^peer}, 5_000
    started = System.monotonic_time(:millisecond)
    assert :ok = EventSource.close(source)
    assert System.monotonic_time(:millisecond) - started < 500
    assert_receive {:dial_closed, ^peer}, 5_000
    refute_receive {EventSource, ^source, _}, 20
  end

  defp source(url, opts \\ []) do
    source =
      EventSource.new(
        url,
        Keyword.merge(
          [http_version: :h2c, http2_scope: "sse-#{System.unique_integer([:positive])}"],
          opts
        )
      )

    assert %EventSource{} = source
    on_exit(fn -> EventSource.close(source) end)
    source
  end

  defp peer(script, h2? \\ true) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)

        if h2? do
          assert {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), 5_000)
          :ok = :gen_tcp.send(socket, frame(4, 0, 0, <<3::16, 10::32>>))
        end

        script.(socket)
        receive do: (:stop -> :gen_tcp.close(socket))
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {"http://127.0.0.1:#{port}/events", peer}
  end

  defp headers(fields) do
    HTTP.HTTP2.HPACK.encode_headers(fields) |> IO.iodata_to_binary()
  end

  # OTP may send user_canceled and close_notify before closing the unfinished
  # handshake. Accept only those alert records, then require actual socket EOF.
  defp assert_tls_closed(socket, alerts_left \\ 2)

  defp assert_tls_closed(socket, alerts_left) when alerts_left > 0 do
    case :gen_tcp.recv(socket, 5, 5_000) do
      {:error, :closed} ->
        :ok

      {:ok, <<21, 3, 3, 0, 2>>} ->
        assert {:ok, <<1, description>>} = :gen_tcp.recv(socket, 2, 5_000)
        assert description in [0, 90]
        assert_tls_closed(socket, alerts_left - 1)

      other ->
        flunk("unexpected TLS close record: #{inspect(other)}")
    end
  end

  defp assert_tls_closed(socket, 0),
    do: assert({:error, :closed} = :gen_tcp.recv(socket, 1, 5_000))

  defp response_headers(id),
    do: frame(1, 4, id, headers([{":status", "200"}, {"content-type", "text/event-stream"}]))

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp receive_frame(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, 5_000)
    payload = if size == 0, do: <<>>, else: elem(:gen_tcp.recv(socket, size, 5_000), 1)
    {type, flags, id, payload}
  end

  defp request(socket), do: request(socket, Process.get(:decoder, HTTP.HTTP2.HPACK.new_decoder()))

  defp request(socket, decoder) do
    case receive_frame(socket) do
      {1, flags, id, payload} ->
        assert {:ok, next_decoder, fields} = HTTP.HTTP2.HPACK.decode(decoder, payload)
        Process.put(:decoder, next_decoder)
        {id, flags, fields}

      {4, 0, 0, _} ->
        :ok = :gen_tcp.send(socket, frame(4, 1, 0, <<>>))
        request(socket, decoder)

      _ ->
        request(socket, decoder)
    end
  end

  defp next_frame(socket, type, id) do
    case receive_frame(socket) do
      {^type, _, ^id, _} = frame -> frame
      _ -> next_frame(socket, type, id)
    end
  end

  defp chunks(<<>>, _), do: []
  defp chunks(bytes, size) when byte_size(bytes) <= size, do: [bytes]

  defp chunks(bytes, size) do
    <<chunk::binary-size(size), rest::binary>> = bytes
    [chunk | chunks(rest, size)]
  end
end

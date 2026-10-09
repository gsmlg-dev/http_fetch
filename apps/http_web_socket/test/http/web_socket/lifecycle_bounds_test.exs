defmodule HTTP.WebSocket.LifecycleBoundsTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}

  @timeout 5_000
  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  test "acknowledged sends complete only after H2 write credit settles" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          {id, 4} = request(socket)
          :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
          receive do: (:grant -> :ok)
          :ok = :gen_tcp.send(socket, frame(8, 0, id, <<0::1, 128::31>>))
          assert {1, "credit"} = websocket_frame(socket, id)
          send(parent, {:written, self()})
          receive do: (:close -> clean_close(socket, id))
        end,
        0
      )

    ws = websocket(url)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert {:ok, ref} = WebSocket.send_ack(ws, "credit")
    assert %{pending_send_frames: 1} = WebSocket.status(ws)
    refute_receive {WebSocket, ^ws, {:send_result, ^ref, :ok}}, 0
    send(peer, :grant)
    assert_receive {WebSocket, ^ws, {:send_result, ^ref, :ok}}, @timeout
    assert_receive {:written, ^peer}, @timeout
    send(peer, :close)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
    refute_receive {WebSocket, ^ws, {:send_result, ^ref, _}}, 0
  end

  test "empty application frames count toward the send bound and blocked close is finite" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          {id, 4} = request(socket)
          :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
          assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
          send(parent, {:cancelled, self()})
        end,
        0
      )

    ws = websocket(url, max_send_frames: 2, close_timeout: 50)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert :ok = WebSocket.send(ws, "")
    assert :ok = WebSocket.send(ws, "")
    assert {:error, :send_queue_full} = WebSocket.send(ws, "")
    assert %{pending_send_frames: 2, buffered_amount: 0} = WebSocket.status(ws)
    started = System.monotonic_time(:millisecond)
    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, 1_000
    assert System.monotonic_time(:millisecond) - started < 1_000
    assert_receive {:cancelled, ^peer}, @timeout
  end

  test "bounded runtime telemetry reports queues and preserves legacy connect metadata" do
    parent = self()
    handler = make_ref()
    events = for event <- [:open, :queue, :close], do: [:http_runtime, :stream, event]

    :ok =
      :telemetry.attach_many(
        handler,
        [[:http_web_socket, :connect, :stop] | events],
        &__MODULE__.capture_telemetry/4,
        parent
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    {url, peer} =
      peer(
        fn socket ->
          {id, 4} = request(socket)

          :ok =
            :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 0, id, <<0x81, 1, "a">>)])

          assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
          send(parent, {:telemetry_reset, self()})
        end,
        0
      )

    ws =
      websocket(url, delivery: :ack, max_message_size: 2, max_queue_bytes: 9, close_timeout: 50)

    pid = ws.pid
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout

    assert_receive {^pid, [:http_web_socket, :connect, :stop], %{duration: duration},
                    %{protocol: "", http_version: :http2, fallback: false}},
                   @timeout

    assert is_integer(duration)

    assert_receive {^pid, [:http_runtime, :stream, :open], open_measurements, open_metadata},
                   @timeout

    assert open_metadata == %{client: :web_socket, http_version: :http2, outcome: :accepted}
    assert Enum.all?(open_measurements, fn {_key, value} -> is_number(value) end)
    assert_receive {WebSocket, ^ws, %Message{data: "a"}, ref}, @timeout

    assert_receive {^pid, [:http_runtime, :stream, :queue], %{queued_bytes: 8, queued_events: 1},
                    %{client: :web_socket, outcome: :receive_admitted}},
                   @timeout

    assert :ok = WebSocket.send(ws, "blocked")

    assert_receive {^pid, [:http_runtime, :stream, :queue],
                    %{buffered_amount: 7, pending_send_frames: 1},
                    %{client: :web_socket, outcome: :send_admitted}},
                   @timeout

    assert :ok = WebSocket.acknowledge(ws, ref)

    assert_receive {^pid, [:http_runtime, :stream, :queue], %{queued_bytes: 0, queued_events: 0},
                    %{client: :web_socket, outcome: :settled}},
                   @timeout

    assert :ok = WebSocket.close(ws)
    assert_receive {WebSocket, ^ws, %Close{was_clean: false}}, @timeout

    assert_receive {^pid, [:http_runtime, :stream, :close], close_measurements, close_metadata},
                   @timeout

    assert close_metadata == %{client: :web_socket, http_version: :http2, outcome: :abnormal}

    assert %{
             queued_bytes: 0,
             queued_events: 0,
             raw_bytes: 0,
             pending_send_frames: 0,
             control_frames: 0
           } = close_measurements

    assert_receive {:telemetry_reset, ^peer}, @timeout
  end

  def capture_telemetry(event, measurements, metadata, parent),
    do: send(parent, {self(), event, measurements, metadata})

  test "control overflow discards bytes following its terminal event" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          {id, 4} = request(socket)

          :ok =
            :gen_tcp.send(socket, [
              frame(1, 4, id, <<0x88>>),
              frame(0, 0, id, <<0x89, 0, 0x89, 0, 0x81, 4, "late">>)
            ])

          assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
          send(parent, {:overflow_reset, self()})
        end,
        0
      )

    ws = websocket(url, max_control_frames: 1)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert_receive {WebSocket, ^ws, %Error{reason: :control_queue_full}}, @timeout
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, @timeout
    assert_receive {:overflow_reset, ^peer}, @timeout
    refute_receive {WebSocket, ^ws, %Message{data: "late"}}, 0
  end

  test "actual binary bytes determine send capacity despite forged size fields" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          {id, 4} = request(socket)
          :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
          assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
          send(parent, {:cancelled, self()})
        end,
        0
      )

    ws = websocket(url, max_send_queue: 2, close_timeout: 50)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert {:error, :send_queue_full} = WebSocket.send(ws, %HTTP.Blob{data: <<1, 2, 3>>, size: 0})

    assert {:error, :send_queue_full} =
             WebSocket.send(ws, %WebSocket.ArrayBuffer{data: <<1, 2, 3>>, byte_length: 0})

    assert :ok = WebSocket.send(ws, %HTTP.Blob{data: <<1, 2>>, size: 1_000_000})
    assert %{buffered_amount: 2, pending_send_frames: 1} = WebSocket.status(ws)
    assert :ok = WebSocket.close(ws)
    assert_receive {WebSocket, ^ws, %Close{was_clean: false}}, @timeout
    assert_receive {:cancelled, ^peer}, @timeout
  end

  for {name, options, expected_events} <- [
        {"byte", [max_message_size: 2, max_queue_bytes: 9, max_queue_events: 64], 1},
        {"count", [max_message_size: 2, max_queue_bytes: 1_024, max_queue_events: 1], 1}
      ] do
    test "ACK #{name} capacity pauses parsing instead of overloading delivery" do
      parent = self()

      {url, peer} =
        peer(fn socket ->
          {id, 4} = request(socket)

          :ok =
            :gen_tcp.send(socket, [
              frame(1, 4, id, <<0x88>>),
              frame(0, 0, id, <<0x81, 1, "a", 0x81, 1, "b", 0x81, 1, "c", 0x89, 0>>)
            ])

          assert {10, ""} = websocket_frame(socket, id)
          send(parent, {:drained, self()})
          receive do: (:close -> :ok)
          clean_close(socket, id)
        end)

      ws = websocket(url, [delivery: :ack] ++ unquote(options))
      assert_receive {WebSocket, ^ws, %Open{}}, @timeout
      assert_receive {WebSocket, ^ws, %Message{data: "a"}, first}, @timeout

      assert %{queued_events: unquote(expected_events), queued_bytes: 8, raw_bytes: 8} =
               WebSocket.status(ws)

      assert :ok = WebSocket.acknowledge(ws, first)
      assert_receive {WebSocket, ^ws, %Message{data: "b"}, second}, @timeout
      assert %{queued_events: 1, queued_bytes: 8, raw_bytes: 5} = WebSocket.status(ws)
      assert :ok = WebSocket.acknowledge(ws, second)
      assert_receive {WebSocket, ^ws, %Message{data: "c"}, third}, @timeout
      assert :ok = WebSocket.acknowledge(ws, third)
      assert_receive {:drained, ^peer}, @timeout
      assert %{queued_events: 0, queued_bytes: 0, raw_bytes: 0} = WebSocket.status(ws)
      refute_receive {WebSocket, ^ws, %Error{}}, 0
      send(peer, :close)
      assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
    end
  end

  test "ACK backpressure pauses idle and settlement restarts the configured deadline" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)

        :ok =
          :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 0, id, <<0x81, 1, "a">>)])

        assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
        send(parent, {:idle_reset, self()})
      end)

    ws = websocket(url, delivery: :ack, idle_timeout: 50)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert_receive {WebSocket, ^ws, %Message{data: "a"}, ref}, @timeout
    assert :sys.get_state(ws.pid).idle_timer == nil
    assert :ok = WebSocket.acknowledge(ws, ref)
    assert :sys.get_state(ws.pid).idle_timer != nil
    assert_receive {WebSocket, ^ws, %Error{reason: :idle_timeout}}, 1_000
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, 1_000
    assert_receive {:idle_reset, ^peer}, @timeout
  end

  test "ordinary sibling traffic cannot reset this stream's idle deadline" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        {sibling, 5} = request(socket)
        :ok = :gen_tcp.send(socket, [frame(1, 4, sibling, <<0x88>>), frame(0, 1, sibling, "ok")])
        assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
        send(parent, {:idle_reset, self()})
      end)

    scope = scope()
    ws = websocket(url, http2_scope: scope, idle_timeout: 1_000)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    {_timer, idle_token} = :sys.get_state(ws.pid).idle_timer

    response =
      HTTP.fetch(HTTP.Runtime.Options.origin_uri(URI.parse(url)),
        http_version: :h2c,
        http2_scope: scope,
        connect_timeout: 30_000
      )
      |> HTTP.Promise.await(@timeout)

    assert HTTP.Response.read_all(response) == "ok"
    assert {_timer, ^idle_token} = :sys.get_state(ws.pid).idle_timer
    assert_receive {WebSocket, ^ws, %Error{reason: :idle_timeout}}, 2_000
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, 1_000
    assert_receive {:idle_reset, ^peer}, @timeout
  end

  test "stream task death drains accepted ACK delivery before one Error and Close" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)

        :ok =
          :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 0, id, <<0x81, 1, "a">>)])

        assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
        send(parent, {:task_reset, self()})
      end)

    scope = scope()
    ws = websocket(url, delivery: :ack, http2_scope: scope)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert_receive {WebSocket, ^ws, %Message{data: "a"}, ref}, @timeout
    runtime_owner = WebSocket.status(ws).stream_handle.owner
    stream = :sys.get_state(ws.pid).stream
    assert_scope_active(scope)
    stream_monitor = Process.monitor(stream)
    ws_monitor = Process.monitor(ws.pid)
    Process.exit(stream, :kill)
    assert_receive {:DOWN, ^stream_monitor, :process, ^stream, :killed}, @timeout
    refute_receive {WebSocket, ^ws, %Error{}}, 0
    assert :ok = WebSocket.acknowledge(ws, ref)
    assert_receive {WebSocket, ^ws, %Error{reason: {:stream_down, :killed}}}, @timeout
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, @timeout
    assert_receive {:DOWN, ^ws_monitor, :process, _, :normal}, @timeout
    assert_receive {:task_reset, ^peer}, @timeout
    assert_scope_released(scope)
    assert_runtime_empty(runtime_owner)
    refute_receive {WebSocket, ^ws, %Error{}}, 0
    refute_receive {WebSocket, ^ws, %Close{}}, 0
  end

  test "application owner death stops its client and releases the runtime stream" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
        send(parent, {:owner_reset, self()})
      end)

    scope = scope()

    owner =
      spawn(fn ->
        ws = WebSocket.new(url, [], http_version: :h2c, http2_scope: scope)

        receive do
          {WebSocket, ^ws, %Open{}} -> send(parent, {:opened, self(), ws})
        end

        receive do: (:stop -> :ok)
      end)

    assert_receive {:opened, ^owner, ws}, @timeout
    runtime_owner = WebSocket.status(ws).stream_handle.owner
    stream = :sys.get_state(ws.pid).stream
    assert_scope_active(scope)
    ws_monitor = Process.monitor(ws.pid)
    stream_monitor = Process.monitor(stream)
    send(owner, :stop)
    assert_receive {:DOWN, ^ws_monitor, :process, _, :shutdown}, @timeout
    assert_receive {:DOWN, ^stream_monitor, :process, ^stream, _}, @timeout
    assert_receive {:owner_reset, ^peer}, @timeout
    assert_scope_released(scope)
    assert_runtime_empty(runtime_owner)
  end

  test "accepted GOAWAY leaves the tunnel usable without reconnect or message replay" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, id, <<0x88>>),
            frame(7, 0, 0, <<0::1, id::31, 0::32>>),
            frame(0, 0, id, <<0x81, 5, "after">>)
          ])

        assert {1, "once"} = websocket_frame(socket, id)
        :ok = :gen_tcp.send(socket, frame(0, 0, id, <<0x81, 4, "echo">>))
        send(parent, {:sent_once, self()})
        receive do: (:close -> :ok)
        clean_close(socket, id)
      end)

    ws = websocket(url)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert_receive {WebSocket, ^ws, %Message{data: "after"}}, @timeout
    assert :ok = WebSocket.send(ws, "once")
    assert_receive {WebSocket, ^ws, %Message{data: "echo"}}, @timeout
    assert_receive {:sent_once, ^peer}, @timeout
    refute_receive {WebSocket, ^ws, %Open{}}, 0
    refute_receive {WebSocket, ^ws, %Error{}}, 0
    send(peer, :close)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
  end

  test "Pong takes priority over queued data only after the current frame completes" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          {id, 4} = request(socket)
          :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
          assert {0, 0, ^id, first} = next_frame(socket, 0, id)
          assert byte_size(first) == 8
          :ok = :gen_tcp.send(socket, frame(0, 0, id, <<0x89, 1, "p", 0x81, 5, "ready">>))
          receive do: (:grant -> :ok)
          :ok = :gen_tcp.send(socket, frame(8, 0, id, <<0::1, 64::31>>))
          bytes = collect_data(socket, id, first, 30)
          assert [{1, "abcdefghij"}, {10, "p"}, {1, "b"}] = decode_frames(bytes)
          :ok = :gen_tcp.send(socket, frame(0, 0, id, <<0x81, 7, "settled">>))
          send(parent, {:ordered_wire, self()})
          receive do: (:close -> :ok)
          clean_close(socket, id)
        end,
        8
      )

    ws = websocket(url)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert :ok = WebSocket.send(ws, "abcdefghij")
    assert_receive {WebSocket, ^ws, %Message{data: "ready"}}, @timeout
    assert %{buffered_amount: 8, pending_send_frames: 1, control_frames: 1} = WebSocket.status(ws)
    assert :ok = WebSocket.send(ws, "b")
    send(peer, :grant)
    assert_receive {:ordered_wire, ^peer}, @timeout
    assert_receive {WebSocket, ^ws, %Message{data: "settled"}}, @timeout
    assert %{buffered_amount: 0, pending_send_frames: 0, control_frames: 0} = WebSocket.status(ws)
    send(peer, :close)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
  end

  defp websocket(url, options \\ []) do
    ws = WebSocket.new(url, [], [http_version: :h2c, timeout: @timeout] ++ options)
    assert %WebSocket{} = ws
    on_exit(fn -> if Process.alive?(ws.pid), do: Process.exit(ws.pid, :kill) end)
    ws
  end

  defp scope, do: "ws-bounds-#{System.unique_integer([:positive])}"

  defp assert_scope_released(scope) do
    deadline = System.monotonic_time(:millisecond) + @timeout
    assert_scope_released(scope, deadline)
  end

  defp assert_scope_released(scope, deadline) do
    entries = scope_entries(scope)

    if Enum.all?(entries, &(&1.streams == 0 and &1.pending == 0 and &1.connecting == 0)) do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline
      :erlang.yield()
      assert_scope_released(scope, deadline)
    end
  end

  defp assert_runtime_empty(owner) do
    assert %{
             active_streams: 0,
             protocol_streams: 0,
             pending_upload_bytes: 0,
             buffered_receive_bytes: 0,
             bytes: 0
           } = HTTP.HTTP2.ConnectionOwner.status(owner)
  end

  defp assert_scope_active(scope), do: assert(Enum.any?(scope_entries(scope), &(&1.streams == 1)))

  defp scope_entries(scope) do
    digest =
      Base.encode16(:crypto.hash(:sha256, :erlang.term_to_binary(scope, [:deterministic])),
        case: :lower
      )

    entries = HTTP.HTTP2.Pool.stats(Process.whereis(:http_fetch_http2_pool))

    for {key, entry} <- entries,
        key.http2_scope == %{kind: :http2_scope, digest: digest},
        do: entry
  end

  defp peer(script, window \\ 65_535) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @timeout)
        assert {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), @timeout)

        :ok =
          :gen_tcp.send(
            socket,
            frame(4, 0, 0, <<3::16, 10::32, 8::16, 1::32, 4::16, window::32>>)
          )

        script.(socket)
        receive do: (:stop -> :gen_tcp.close(socket))
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {"ws://127.0.0.1:#{port}/chat", peer}
  end

  defp clean_close(socket, id) do
    :ok = :gen_tcp.send(socket, frame(0, 1, id, <<0x88, 2, 1000::16>>))
    assert {8, <<1000::16>>} = websocket_frame(socket, id)
    assert {0, 1, ^id, ""} = next_frame(socket, 0, id)
  end

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp receive_frame(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, @timeout)
    payload = if size == 0, do: <<>>, else: recv_payload(socket, size)
    {type, flags, id, payload}
  end

  defp recv_payload(socket, size) do
    assert {:ok, payload} = :gen_tcp.recv(socket, size, @timeout)
    payload
  end

  defp request(socket) do
    case receive_frame(socket) do
      {1, flags, id, _payload} ->
        {id, flags}

      {4, 0, 0, _payload} ->
        :ok = :gen_tcp.send(socket, frame(4, 1, 0, <<>>))
        request(socket)

      _ ->
        request(socket)
    end
  end

  defp next_frame(socket, type, id) do
    case receive_frame(socket) do
      {^type, _flags, ^id, _payload} = observed -> observed
      _ -> next_frame(socket, type, id)
    end
  end

  defp websocket_frame(socket, id) do
    {0, 0, ^id, bytes} = next_frame(socket, 0, id)
    [decoded] = decode_frames(bytes)
    decoded
  end

  defp collect_data(_socket, _id, bytes, length) when byte_size(bytes) == length, do: bytes

  defp collect_data(socket, id, bytes, length) do
    {0, 0, ^id, next} = next_frame(socket, 0, id)
    collect_data(socket, id, bytes <> next, length)
  end

  defp decode_frames(<<>>), do: []

  defp decode_frames(
         <<first, 1::1, length::7, key::binary-size(4), payload::binary-size(length),
           rest::binary>>
       ) do
    decoded =
      for <<byte <- payload>>, reduce: {0, []} do
        {index, acc} -> {index + 1, [bxor(byte, :binary.at(key, rem(index, 4))) | acc]}
      end

    [
      {first &&& 15, decoded |> elem(1) |> Enum.reverse() |> :erlang.list_to_binary()}
      | decode_frames(rest)
    ]
  end
end

defmodule HTTP.EventSource.LifecycleTest do
  use ExUnit.Case, async: false

  alias HTTP.EventSource
  alias HTTP.EventSource.Event.Error
  alias HTTP.EventSource.Event.Message
  alias HTTP.EventSource.Event.Open

  @certfile Path.expand("../../support/fixtures/localhost.pem", __DIR__)
  @keyfile Path.expand("../../support/fixtures/localhost.key", __DIR__)
  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  test "relative redirects retain same-origin headers and resolve the request target" do
    {url, peer} = peer()
    source = source(url, headers: [{"Authorization", "Bearer private"}])
    assert_receive {:peer_request, ^peer, request}, 5_000
    assert request =~ "GET /events HTTP/1.1"
    write(peer, redirect("../next?cursor=7"))
    assert_receive {:peer_request, ^peer, request}, 5_000
    assert request =~ "GET /next?cursor=7 HTTP/1.1"
    assert request =~ "Authorization: Bearer private"
    write(peer, response("data: redirected\n\n"))
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "redirected"}}, 5_000
  end

  test "redirect cap permanently stops a loop without another request" do
    {url, peer} = peer()
    source = source(url, max_redirects: 1)
    assert_receive {:peer_request, ^peer, _}, 5_000
    write(peer, redirect("/again"))
    assert_receive {:peer_request, ^peer, _}, 5_000
    write(peer, redirect("/again"))
    assert_receive {EventSource, ^source, %Error{reason: :too_many_redirects}}, 5_000
    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {:peer_request, ^peer, _}, 0
  end

  test "cross-origin redirects strip authorization, cookies and caller host" do
    {url, first} = peer()
    {target, second} = peer()

    source =
      source(url,
        headers: [
          {"Authorization", "Bearer secret"},
          {"Proxy-Authorization", "Basic secret"},
          {"Cookie", "session=secret"},
          {"Host", "original.invalid"},
          {"X-Visible", "kept"}
        ]
      )

    assert_receive {:peer_request, ^first, request}, 5_000
    assert request =~ "Cookie: session=secret"
    write(first, redirect(target))
    assert_receive {:peer_request, ^second, request}, 5_000
    refute String.downcase(request) =~ "authorization:"
    refute String.downcase(request) =~ "cookie:"
    refute request =~ "original.invalid"
    assert request =~ "X-Visible: kept"
    assert request =~ "Host: #{URI.parse(target).host}:#{URI.parse(target).port}"
    write(second, response("data: public\n\n"))
    assert_receive {EventSource, ^source, %Message{data: "public"}}, 5_000
  end

  test "cross-origin redirect refuses configured client identity" do
    {url, first} = peer()
    {target, second} = peer()
    source = source(url, ssl: [certfile: @certfile, keyfile: @keyfile])
    assert_receive {:peer_request, ^first, _}, 5_000
    write(first, redirect(target))

    assert_receive {EventSource, ^source, %Error{reason: :client_identity_cross_origin_redirect}},
                   5_000

    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {:peer_request, ^second, _}, 0
  end

  test "HTTPS redirect refuses a cleartext downgrade" do
    {url, first} = peer(:tls)
    {target, second} = peer()
    source = source(url, ssl: [verify: :verify_none])
    assert_receive {:peer_request, ^first, _}, 5_000
    write(first, redirect(target))
    assert_receive {EventSource, ^source, %Error{reason: :insecure_redirect}}, 5_000
    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {:peer_request, ^second, _}, 0
  end

  test "redirects reject unsupported schemes, userinfo and missing locations" do
    for location <- [
          "ftp://example.test/events",
          "http://private:secret@example.test/events",
          nil
        ] do
      {url, peer} = peer()
      source = source(url)
      assert_receive {:peer_request, ^peer, _}, 5_000
      write(peer, redirect(location))
      assert_receive {EventSource, ^source, %Error{reason: :invalid_redirect}}, 5_000
      assert EventSource.ready_state(source) == EventSource.closed()
    end
  end

  for {protocol, version, reason} <- [
        {:http, :http1, :timeout},
        {:h2, :h2c, :opening_timeout}
      ] do
    test "#{version} opening deadline retains its public timeout reason" do
      {url, peer} = peer(unquote(protocol))
      source = source(url, http_version: unquote(version), connect_timeout: 30_000)
      assert_receive {:peer_request, ^peer, _}, 5_000
      state = :sys.get_state(source.pid)
      assert is_reference(state.opening_timer)
      send(source.pid, {:opening_timeout, state.generation})
      assert_receive {EventSource, ^source, %Error{reason: unquote(reason)}}, 5_000
      assert EventSource.ready_state(source) == EventSource.connecting()
      assert :sys.get_state(source.pid).opening_timer == nil
      refute_receive {EventSource, ^source, %Open{}}, 0
    end
  end

  test "HTTP/1 opening deadline cancels a held TLS worker and retains timeout" do
    {url, peer} = peer(:raw)

    source =
      source(String.replace(url, "http:", "https:"),
        ssl: [verify: :verify_none],
        connect_timeout: 30_000
      )

    assert_receive {:peer_input, ^peer, <<22, _::binary>>}, 5_000
    state = :sys.get_state(source.pid)
    assert is_pid(state.worker)
    monitor = Process.monitor(state.worker)
    send(source.pid, {:opening_timeout, state.generation})
    assert_receive {EventSource, ^source, %Error{reason: :timeout}}, 5_000
    assert_receive {:DOWN, ^monitor, :process, _, _}, 5_000
    assert :sys.get_state(source.pid).worker == nil
    refute_receive {EventSource, ^source, %Open{}}, 0
  end

  test "accepted headers invalidate the opening deadline and replaced idle token" do
    {url, peer} = peer()
    source = source(url, idle_timeout: 30_000)
    assert_receive {:peer_request, ^peer, _}, 5_000
    generation = :sys.get_state(source.pid).generation
    write(peer, response("data: first\n\n"))
    assert_receive {EventSource, ^source, %Message{data: "first"}}, 5_000
    state = :sys.get_state(source.pid)
    assert state.opening_timer == nil
    {_timer, old_idle} = state.idle_timer
    write(peer, "data: second\n\n")
    assert_receive {EventSource, ^source, %Message{data: "second"}}, 5_000
    {_timer, current_idle} = :sys.get_state(source.pid).idle_timer
    assert old_idle != current_idle

    send(source.pid, {:opening_timeout, generation})
    send(source.pid, {:idle_timeout, old_idle})
    assert EventSource.ready_state(source) == EventSource.open()
    refute_receive {EventSource, ^source, %Error{}}, 0
    write(peer, "data: still-open\n\n")
    assert_receive {EventSource, ^source, %Message{data: "still-open"}}, 5_000
  end

  test "reconnect invalidates old timers and worker notifications" do
    {url, peer} = peer()
    source = source(url, idle_timeout: 30_000)
    assert_receive {:peer_request, ^peer, _}, 5_000
    write(peer, response("id: 7\ndata: first\n\n"))
    assert_receive {EventSource, ^source, %Message{data: "first"}}, 5_000
    before = :sys.get_state(source.pid)
    {_timer, idle_token} = before.idle_timer
    send(source.pid, {:idle_timeout, idle_token})
    assert_receive {EventSource, ^source, %Error{reason: :idle_timeout}}, 5_000
    {_timer, reconnect_token} = :sys.get_state(source.pid).reconnect_timer
    send(peer, :next)
    send(source.pid, {:reconnect, reconnect_token})
    assert_receive {:peer_request, ^peer, request}, 5_000
    assert request =~ "Last-Event-ID: 7"
    write(peer, response("data: resumed\n\n"))
    assert_receive {EventSource, ^source, %Message{data: "resumed", last_event_id: "7"}}, 5_000
    after_reconnect = :sys.get_state(source.pid)
    assert after_reconnect.generation != before.generation

    send(source.pid, {:opening_timeout, before.generation})
    send(source.pid, {:idle_timeout, idle_token})
    send(source.pid, {:reconnect, reconnect_token})
    send(source.pid, {:http1_connected, before.generation, self(), {:error, :stale_worker}})
    send(source.pid, {:http_runtime, before.generation, self(), {:error, :stale_stream}})
    assert EventSource.ready_state(source) == EventSource.open()
    assert :sys.get_state(source.pid).generation == after_reconnect.generation
    refute_receive {EventSource, ^source, %Error{}}, 0
  end

  test "close cancels pending reconnect and ignores later attempt notifications" do
    {url, peer} = peer()
    source = source(url)
    assert_receive {:peer_request, ^peer, _}, 5_000
    write(peer, response("data: first\n\n"))
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "first"}}, 5_000
    old_generation = :sys.get_state(source.pid).generation
    send(peer, :next)
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 5_000
    {_timer, token} = :sys.get_state(source.pid).reconnect_timer
    monitor = Process.monitor(source.pid)
    assert :ok = EventSource.close(source)
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 5_000
    send(source.pid, {:reconnect, token})
    send(source.pid, {:opening_timeout, old_generation})
    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {EventSource, ^source, _}, 0
    refute_receive {:peer_request, ^peer, _}, 0
  end

  test "owner death cancels a worker blocked in the TLS handshake" do
    {url, peer} = peer(:raw)
    parent = self()

    owner =
      spawn(fn ->
        source =
          EventSource.new(String.replace(url, "http:", "https:"),
            ssl: [verify: :verify_none],
            connect_timeout: 30_000
          )

        send(parent, {:owned_source, source})
        receive do: (:stop -> :ok)
      end)

    assert_receive {:owned_source, source}, 5_000
    on_exit(fn -> EventSource.close(source) end)
    assert_receive {:peer_input, ^peer, <<22, _::binary>>}, 5_000
    state = :sys.get_state(source.pid)
    assert is_pid(state.worker)
    worker_monitor = Process.monitor(state.worker)
    source_monitor = Process.monitor(source.pid)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^source_monitor, :process, _, :shutdown}, 1_000
    assert_receive {:DOWN, ^worker_monitor, :process, _, _}, 1_000
  end

  test "close cancels a shared stream awaiting peer SETTINGS" do
    {url, peer} = peer(:raw)
    source = source(url, http_version: :h2c, http2_reuse: false)
    assert_receive {:peer_input, ^peer, input}, 5_000
    assert String.starts_with?(input, @preface)
    state = :sys.get_state(source.pid)
    assert is_pid(state.stream)
    monitor = Process.monitor(state.stream)
    assert :ok = EventSource.close(source)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 1_000
  end

  test "DATA followed by reset in one owner batch drains acknowledged events before error" do
    {url, peer} = peer(:h2)

    source =
      source(url,
        http_version: :h2c,
        http2_reuse: false,
        delivery: :ack,
        max_event_size: 32,
        max_queue_bytes: 80,
        max_queue_events: 2
      )

    assert_receive {:peer_request, ^peer, id}, 5_000

    headers =
      HTTP.HTTP2.HPACK.encode_headers([{":status", "200"}, {"content-type", "text/event-stream"}])

    write(peer, [
      frame(1, 4, id, IO.iodata_to_binary(headers)),
      frame(0, 0, id, "id: 1\ndata: 1\n\n")
    ])

    assert_receive {EventSource, ^source, %Message{data: "1"}, first}, 5_000
    %{stream_handle: %{owner: connection_owner}} = EventSource.status(source)
    remaining = Enum.map_join(2..6, &"id: #{&1}\ndata: #{&1}\n\n")

    assert :ok =
             HTTP.HTTP2.ConnectionOwner.receive_bytes(
               connection_owner,
               frame(0, 0, id, remaining) <> frame(3, 0, id, <<8::32>>)
             )

    assert :ok = EventSource.acknowledge(source, first)

    for number <- 2..6 do
      data = Integer.to_string(number)

      assert_receive {EventSource, ^source, %Message{data: ^data, last_event_id: ^data}, ref},
                     5_000

      refute_receive {EventSource, ^source, %Error{}}, 0
      assert :ok = EventSource.acknowledge(source, ref)
    end

    assert_receive {EventSource, ^source, %Error{reason: {:http2, :reset, 8}}}, 5_000
    assert EventSource.last_event_id(source) == "6"
  end

  test "remote END_STREAM waits for the final application acknowledgement before EOF" do
    {url, peer} = peer(:h2)

    source =
      source(url,
        http_version: :h2c,
        http2_reuse: false,
        delivery: :ack,
        max_event_size: 32,
        max_queue_bytes: 80,
        max_queue_events: 2
      )

    assert_receive {:peer_request, ^peer, id}, 5_000

    headers =
      HTTP.HTTP2.HPACK.encode_headers([
        {":status", "200"},
        {"content-type", "text/event-stream"}
      ])

    write(peer, [
      frame(1, 4, id, IO.iodata_to_binary(headers)),
      frame(0, 1, id, "id: 7\ndata: final\n\n")
    ])

    assert_receive {EventSource, ^source, %Message{data: "final"}, ref}, 5_000
    # Observe admission of the actual peer END_STREAM before acknowledging;
    # a status request alone could overtake the runtime's terminal notification.
    terminal_barrier(source, :eof, System.monotonic_time(:millisecond) + 5_000)
    assert %{ready_state: 1, queued_events: 1} = EventSource.status(source)
    refute_receive {EventSource, ^source, %Error{}}, 0
    assert :ok = EventSource.acknowledge(source, ref)
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 5_000
    assert EventSource.last_event_id(source) == "7"
  end

  test "parser fatal drains accepted deliveries before its exact error and permanent stop" do
    {url, peer} = peer()

    source =
      source(url,
        delivery: :ack,
        max_event_size: 32,
        max_queue_bytes: 160,
        max_queue_events: 4,
        reconnect_time: 0
      )

    monitor = Process.monitor(source.pid)
    assert_receive {:peer_request, ^peer, _}, 5_000
    body = "data: first\n\ndata: second\n\n" <> <<255>> <> "\n\n"
    write(peer, response(body))
    assert_receive {EventSource, ^source, %Open{}}, 5_000
    assert_receive {EventSource, ^source, %Message{data: "first"}, first}, 5_000
    assert is_reference(first)

    assert :ok = EventSource.acknowledge(source, make_ref())
    assert %{ready_state: 1, queued_events: 2} = EventSource.status(source)
    refute_receive {EventSource, ^source, %Error{}}, 0
    refute_receive {EventSource, ^source, %Message{}, _}, 0
    assert :ok = EventSource.acknowledge(source, first)
    assert_receive {EventSource, ^source, %Message{data: "second"}, second}, 5_000
    assert is_reference(second) and second != first

    assert :ok = EventSource.acknowledge(source, first)
    assert :ok = EventSource.acknowledge(source, make_ref())
    assert %{ready_state: 1, queued_events: 1} = EventSource.status(source)
    refute_receive {EventSource, ^source, %Error{}}, 0
    assert :ok = EventSource.acknowledge(source, second)
    assert_receive {EventSource, ^source, %Error{reason: :invalid_utf8}}, 5_000
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 5_000
    assert :ok = EventSource.acknowledge(source, second)
    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {EventSource, ^source, _}, 0
    refute_receive {EventSource, ^source, _, _}, 0
    refute_receive {:peer_request, ^peer, _}, 0
  end

  defp terminal_barrier(source, reason, deadline) do
    state = :sys.get_state(source.pid)
    assert state.ready_state == EventSource.open()

    if state.terminal_reason != reason do
      assert System.monotonic_time(:millisecond) < deadline
      terminal_barrier(source, reason, deadline)
    end
  end

  defp source(url, opts \\ []) do
    source = EventSource.new(url, Keyword.merge([reconnect_time: 30_000], opts))
    assert %EventSource{} = source
    on_exit(fn -> EventSource.close(source) end)
    source
  end

  defp response(body), do: ["HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n", body]
  defp redirect(nil), do: "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"

  defp redirect(location),
    do: ["HTTP/1.1 302 Found\r\nLocation: ", location, "\r\nContent-Length: 0\r\n\r\n"]

  defp write(peer, bytes), do: send(peer, {:write, bytes})

  defp peer(protocol \\ :http) do
    transport = if protocol == :tls, do: :ssl, else: :gen_tcp
    opts = [:binary, packet: :raw, active: false, reuseaddr: true, ip: {127, 0, 0, 1}]
    opts = if protocol == :tls, do: opts ++ [certfile: @certfile, keyfile: @keyfile], else: opts
    {:ok, listener} = transport.listen(0, opts)

    {:ok, {{127, 0, 0, 1}, port}} =
      if protocol == :tls, do: :ssl.sockname(listener), else: :inet.sockname(listener)

    parent = self()
    peer = spawn_link(fn -> accept_peer(listener, transport, protocol, parent) end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      transport.close(listener)
    end)

    scheme = if protocol == :tls, do: "https", else: "http"
    {"#{scheme}://127.0.0.1:#{port}/events", peer}
  end

  defp accept_peer(listener, transport, protocol, parent) do
    socket =
      if protocol == :tls do
        assert {:ok, socket} = :ssl.transport_accept(listener, 5_000)
        assert {:ok, socket} = :ssl.handshake(socket, 5_000)
        socket
      else
        assert {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        socket
      end

    case protocol do
      :raw ->
        assert {:ok, input} = transport.recv(socket, 0, 5_000)
        send(parent, {:peer_input, self(), input})

      :h2 ->
        assert {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), 5_000)
        :ok = :gen_tcp.send(socket, frame(4, 0, 0, <<>>))
        send(parent, {:peer_request, self(), h2_request(socket)})

      _ ->
        send(parent, {:peer_request, self(), http_request(transport, socket, <<>>)})
    end

    peer_commands(listener, transport, protocol, socket, parent)
  end

  defp peer_commands(listener, transport, protocol, socket, parent) do
    receive do
      {:write, bytes} ->
        :ok = transport.send(socket, bytes)

        if IO.iodata_to_binary(bytes) |> String.starts_with?("HTTP/1.1 302") do
          transport.close(socket)
          accept_peer(listener, transport, protocol, parent)
        else
          peer_commands(listener, transport, protocol, socket, parent)
        end

      :next ->
        transport.close(socket)
        accept_peer(listener, transport, protocol, parent)
    end
  end

  defp http_request(transport, socket, buffer) do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      assert {:ok, data} = transport.recv(socket, 0, 5_000)
      http_request(transport, socket, buffer <> data)
    else
      buffer
    end
  end

  defp h2_request(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, 5_000)
    if size > 0, do: assert({:ok, _payload} = :gen_tcp.recv(socket, size, 5_000))

    case {type, flags} do
      {1, _} ->
        id

      {4, 0} ->
        :ok = :gen_tcp.send(socket, frame(4, 1, 0, <<>>))
        h2_request(socket)

      _ ->
        h2_request(socket)
    end
  end

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>
end

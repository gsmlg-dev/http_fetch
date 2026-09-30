defmodule HTTP.Runtime.StreamTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.ConnectionOwner
  alias HTTP.Runtime.Stream

  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  test "h2c delivers generation-qualified headers and DATA and restores receive credit" do
    test_pid = self()

    {url, peer} =
      peer(fn socket ->
        {id, flags} = request(socket)
        send(test_pid, {:request, self(), id, flags})
        :ok = :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 0, id, "hello")])
        assert {8, 0, ^id, <<0::1, 5::31>>} = next_frame(socket, 8, id)
        send(test_pid, {:credit_restored, self()})
      end)

    generation = make_ref()
    {stream, ^generation} = start_stream(url, self(), generation: generation)

    assert_receive {:http_runtime, ^generation, ^stream,
                    {:opened, %{id: id, owner: owner, protocol: :h2c}}},
                   5_000

    assert_receive {:request, ^peer, ^id, 5}, 5_000

    assert_receive {:http_runtime, ^generation, ^stream, {:headers, [{":status", "200"}], 4}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^stream, {:data, "hello", 0, delivery}}, 5_000
    assert %{buffered_receive_bytes: 5} = ConnectionOwner.status(owner)
    Stream.acknowledge(stream, delivery)
    assert_receive {:credit_restored, ^peer}, 5_000
    assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
    close_stream(stream)
    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
  end

  test "cancelling one stream leaves its sibling usable on the same observed connection" do
    test_pid = self()

    {url, peer} =
      peer(fn socket ->
        {first, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, first, <<0x88>>))
        {second, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, second, <<0x88>>))
        send(test_pid, {:siblings, self(), first, second})
        assert {3, 0, ^first, <<8::32>>} = next_frame(socket, 3, first)
        send(test_pid, {:first_reset, self()})
        receive do: (:send_sibling -> :ok)
        :ok = :gen_tcp.send(socket, frame(0, 0, second, "survived"))
      end)

    scope = "siblings-#{System.unique_integer([:positive])}"
    {first, first_generation} = start_stream(url, self(), scope: scope)

    assert_receive {:http_runtime, ^first_generation, ^first,
                    {:opened, %{owner: owner, id: first_id}}},
                   5_000

    {second, second_generation} = start_stream(url, self(), scope: scope)

    assert_receive {:http_runtime, ^second_generation, ^second,
                    {:opened, %{owner: ^owner, id: second_id}}},
                   5_000

    assert first_id < second_id
    assert_receive {:siblings, ^peer, ^first_id, ^second_id}, 5_000
    close_stream(first)
    assert_receive {:first_reset, ^peer}, 5_000
    send(peer, :send_sibling)

    assert_receive {:http_runtime, ^second_generation, ^second, {:data, "survived", 0, delivery}},
                   5_000

    Stream.acknowledge(second, delivery)
    close_stream(second)
    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
    assert Process.alive?(owner)
  end

  test "delivery references settle in order and duplicate or unknown ACKs return no extra credit" do
    test_pid = self()

    {url, peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, id, <<0x88>>),
            frame(0, 0, id, "first"),
            frame(0, 0, id, "second"),
            frame(0, 0, id, "third!!")
          ])

        for bytes <- [5, 6, 7] do
          assert {8, 0, ^id, <<0::1, ^bytes::31>>} = next_frame(socket, 8, id)
        end

        :ok = :gen_tcp.send(socket, frame(6, 0, 0, "ackproof"))
        assert {6, 1, 0, "ackproof"} = next_frame(socket, 6, 0)
        send(test_pid, {:credit_barrier, self()})
      end)

    {stream, generation} = start_stream(url, self())
    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000
    assert_receive {:http_runtime, ^generation, ^stream, {:data, "first", 0, first}}, 5_000
    assert_receive {:http_runtime, ^generation, ^stream, {:data, "second", 0, second}}, 5_000
    assert_receive {:http_runtime, ^generation, ^stream, {:data, "third!!", 0, third}}, 5_000

    acknowledge_barrier(stream, second)
    assert %{buffered_receive_bytes: 18} = ConnectionOwner.status(owner)
    acknowledge_barrier(stream, first)
    assert %{buffered_receive_bytes: 7} = ConnectionOwner.status(owner)
    acknowledge_barrier(stream, first)
    acknowledge_barrier(stream, second)
    assert %{buffered_receive_bytes: 7} = ConnectionOwner.status(owner)
    acknowledge_barrier(stream, third)
    assert_receive {:credit_barrier, ^peer}, 5_000
    assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
    close_stream(stream)
  end

  test "subscriber death releases the established stream without closing the shared owner" do
    test_pid = self()

    {url, peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
        send(test_pid, {:subscriber_reset, self()})
      end)

    subscriber = subscriber(test_pid)
    {stream, generation} = start_stream(url, subscriber)
    monitor = Process.monitor(stream)

    assert_receive {:forwarded,
                    {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}},
                   5_000

    send(subscriber, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 5_000
    assert_receive {:subscriber_reset, ^peer}, 5_000
    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
  end

  test "GOAWAY preserves an accepted stream and forwards later DATA" do
    {url, _peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, id, <<0x88>>),
            frame(7, 0, 0, <<0::1, id::31, 0::32>>),
            frame(0, 0, id, "after-goaway")
          ])
      end)

    {stream, generation} = start_stream(url, self())

    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{id: id, owner: owner}}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^stream, {:goaway, ^id, 0}}, 5_000

    assert_receive {:http_runtime, ^generation, ^stream, {:data, "after-goaway", 0, delivery}},
                   5_000

    assert Process.alive?(stream)
    assert %{lifecycle: :draining, active_streams: 1} = ConnectionOwner.status(owner)
    Stream.acknowledge(stream, delivery)
    close_stream(stream)
  end

  test "final HEADERS release a completed request without sending a reset" do
    test_pid = self()

    {url, peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        send(test_pid, {:final_request, self()})
        receive do: (:respond_final -> :ok)
        :ok = :gen_tcp.send(socket, frame(1, 5, id, <<0x88>>))
        receive do: (:prove_completed -> :ok)
        no_reset_barrier(socket, id)
        send(test_pid, {:completed_without_reset, self()})
      end)

    {stream, generation} = start_stream(url, self())
    monitor = Process.monitor(stream)
    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000
    assert_receive {:final_request, ^peer}, 5_000
    send(peer, :respond_final)

    assert_receive {:http_runtime, ^generation, ^stream, {:headers, [{":status", "200"}], 5}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^stream, :remote_end}, 5_000
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 5_000
    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
    send(peer, :prove_completed)
    assert_receive {:completed_without_reset, ^peer}, 5_000
  end

  for payload <- ["", "final bytes"] do
    test "END_STREAM DATA #{inspect(payload)} releases only after its transport delivery ACK" do
      test_pid = self()
      payload = unquote(payload)

      {url, peer} =
        peer(fn socket ->
          {id, _flags} = request(socket)
          :ok = :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 1, id, payload)])
          receive do: (:prove_completed -> :ok)
          no_reset_barrier(socket, id)
          send(test_pid, {:completed_without_reset, self()})
        end)

      {stream, generation} = start_stream(url, self())
      monitor = Process.monitor(stream)
      assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000

      assert_receive {:http_runtime, ^generation, ^stream, {:data, ^payload, 1, delivery}}, 5_000
      assert_receive {:http_runtime, ^generation, ^stream, :remote_end}, 5_000
      assert Process.alive?(stream)
      assert %{active_streams: 1} = ConnectionOwner.status(owner)
      Stream.acknowledge(stream, delivery)
      assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 5_000
      assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
      send(peer, :prove_completed)
      assert_receive {:completed_without_reset, ^peer}, 5_000
    end
  end

  for cancellation <- [:deadline, :close, :subscriber_death] do
    test "#{cancellation} while the owner is suspended cannot write queued request headers" do
      test_pid = self()

      {url, peer} =
        peer(fn socket ->
          {id, _flags} = request(socket)
          :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
          receive do: (:prove_no_open -> :ok)
          :ok = :gen_tcp.send(socket, frame(6, 0, 0, "no-open!"))
          no_new_headers(socket)
          send(test_pid, {:no_expired_open, self()})
        end)

      scope = "deadline-#{System.unique_integer([:positive])}"
      {first, first_generation} = start_stream(url, self(), scope: scope)
      assert_receive {:http_runtime, ^first_generation, ^first, {:opened, %{owner: owner}}}, 5_000
      assert_receive {:http_runtime, ^first_generation, ^first, {:headers, _, 4}}, 5_000
      :ok = :sys.suspend(owner)
      :erlang.trace(owner, true, [:receive, {:tracer, self()}])

      try do
        subscriber =
          if unquote(cancellation) == :subscriber_death, do: subscriber(test_pid), else: self()

        timeout = if unquote(cancellation) == :deadline, do: 100, else: 5_000

        {second, second_generation} =
          start_stream(url, subscriber, scope: scope, opening_timeout: timeout)

        monitor = Process.monitor(second)

        assert_receive {:trace, ^owner, :receive,
                        {:"$gen_call", {^second, _tag}, {:open_stream, _headers, _opts}}},
                       5_000

        case unquote(cancellation) do
          :deadline ->
            assert_receive {:http_runtime, ^second_generation, ^second,
                            {:error, :opening_timeout}},
                           1_000

          :close ->
            Stream.close(second)

          :subscriber_death ->
            send(subscriber, :stop)
        end

        assert_receive {:DOWN, ^monitor, :process, ^second, :normal}, 1_000
      after
        :erlang.trace(owner, false, [:receive])
        :ok = :sys.resume(owner)
      end

      assert %{active_streams: 1} = ConnectionOwner.status(owner)
      send(peer, :prove_no_open)
      assert_receive {:no_expired_open, ^peer}, 5_000
      close_stream(first)
    end
  end

  test "owner death during a queued opening settles both admitted and opening logical streams" do
    {url, _peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
      end)

    scope = "owner-down-#{System.unique_integer([:positive])}"
    {first, first_generation} = start_stream(url, self(), scope: scope)
    first_monitor = Process.monitor(first)
    assert_receive {:http_runtime, ^first_generation, ^first, {:opened, %{owner: owner}}}, 5_000
    assert_receive {:http_runtime, ^first_generation, ^first, {:headers, _, 4}}, 5_000
    :ok = :sys.suspend(owner)
    :erlang.trace(owner, true, [:receive, {:tracer, self()}])
    {second, second_generation} = start_stream(url, self(), scope: scope)
    second_monitor = Process.monitor(second)

    assert_receive {:trace, ^owner, :receive,
                    {:"$gen_call", {^second, _tag}, {:open_stream, _headers, _opts}}},
                   5_000

    Process.exit(owner, :kill)

    assert_receive {:http_runtime, ^second_generation, ^second, {:error, {:owner_down, :killed}}},
                   5_000

    assert_receive {:DOWN, ^first_monitor, :process, ^first, :normal}, 5_000
    assert_receive {:DOWN, ^second_monitor, :process, ^second, :normal}, 5_000
  end

  test "a bodyful request is rejected before dialing instead of discarding its upload" do
    {stream, generation} =
      start_stream("http://127.0.0.1:1/", self(), method: :post, body: "unsent upload")

    monitor = Process.monitor(stream)

    assert_receive {:http_runtime, ^generation, ^stream, {:error, :stream_body_requires_writer}},
                   5_000

    assert_receive {:DOWN, ^monitor, :process, ^stream, reason}, 5_000
    assert reason in [:normal, :noproc]
  end

  test "explicit HTTP/1 cannot open a stream on a healthy pooled HTTP/2 owner" do
    test_pid = self()

    {url, peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        receive do: (:prove_no_open -> :ok)
        :ok = :gen_tcp.send(socket, frame(6, 0, 0, "no-open!"))
        no_new_headers(socket)
        send(test_pid, {:no_http1_stream, self()})
      end)

    {first, first_generation} = start_stream(url, self())
    assert_receive {:http_runtime, ^first_generation, ^first, {:opened, %{owner: owner}}}, 5_000
    assert_receive {:http_runtime, ^first_generation, ^first, {:headers, _, 4}}, 5_000

    request = %HTTP.Request{
      url: URI.parse(url),
      transport_options: [http_version: :http1, tls_backend: :ssl]
    }

    {:ok, second, second_generation} = Stream.start(request, self())
    monitor = Process.monitor(second)

    assert_receive {:http_runtime, ^second_generation, ^second, {:error, :http1_negotiated}},
                   5_000

    assert_receive {:DOWN, ^monitor, :process, ^second, reason}, 5_000
    assert reason in [:normal, :noproc]
    assert %{active_streams: 1} = ConnectionOwner.status(owner)
    send(peer, :prove_no_open)
    assert_receive {:no_http1_stream, ^peer}, 5_000
    close_stream(first)
  end

  for cancellation <- [:close, :subscriber_death] do
    test "#{cancellation} does not wait for a suspended exclusive owner to stop" do
      test_pid = self()

      {url, peer} =
        peer(fn socket ->
          {id, _flags} = request(socket)
          :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
          assert :closed = receive_until_closed(socket)
          send(test_pid, {:exclusive_socket_closed, self()})
        end)

      subscriber = subscriber(test_pid)
      {stream, generation} = start_stream(url, subscriber, reuse: false)
      stream_monitor = Process.monitor(stream)

      assert_receive {:forwarded,
                      {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}},
                     5_000

      owner_monitor = Process.monitor(owner)
      :ok = :sys.suspend(owner)

      try do
        case unquote(cancellation) do
          :close -> Stream.close(stream)
          :subscriber_death -> send(subscriber, :stop)
        end

        assert_receive {:DOWN, ^stream_monitor, :process, ^stream, :normal}, 1_000
        assert Process.alive?(owner)
      after
        :ok = :sys.resume(owner)
      end

      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, :normal}, 5_000
      assert_receive {:exclusive_socket_closed, ^peer}, 5_000
    end
  end

  test "fragmented bytes coalesce under pressure without losing bounded FIFO credit" do
    {url, _peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
      end)

    {stream, generation} = start_stream(url, self())

    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner, id: id}}},
                   5_000

    assert_receive {:http_runtime, ^generation, ^stream, {:headers, _, _}}, 5_000

    bytes = IO.iodata_to_binary(for _ <- 1..256, do: frame(0, 0, id, "x"))
    assert :ok = ConnectionOwner.receive_bytes(owner, bytes)

    deliveries =
      for _ <- 1..64 do
        assert_receive {:http_runtime, ^generation, ^stream, {:data, data, 0, ref}}, 5_000
        {data, ref}
      end

    assert IO.iodata_to_binary(Enum.map(deliveries, &elem(&1, 0))) == String.duplicate("x", 256)
    assert %{buffered_receive_bytes: 256} = ConnectionOwner.status(owner)
    assert :queue.len(:sys.get_state(owner).streams[id].deliveries) == 64
    Enum.each(deliveries, fn {_, ref} -> Stream.acknowledge(stream, ref) end)
    acknowledge_barrier(stream, make_ref())
    assert %{buffered_receive_bytes: 0} = ConnectionOwner.status(owner)
    close_stream(stream)
  end

  test "settled remote EOF does not keep its task blocked behind a stalled owner" do
    {url, _peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 1, id, "done")])
      end)

    {stream, generation} = start_stream(url, self())
    monitor = Process.monitor(stream)
    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000
    assert_receive {:http_runtime, ^generation, ^stream, {:data, "done", 1, ref}}, 5_000
    assert_receive {:http_runtime, ^generation, ^stream, :remote_end}, 5_000
    :ok = :sys.suspend(owner)

    try do
      Stream.acknowledge(stream, ref)
      assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
    after
      :ok = :sys.resume(owner)
    end

    assert %{active_streams: 0, protocol_streams: 0} = ConnectionOwner.status(owner)
  end

  test "shared owner death settles the logical stream with its generation" do
    {url, _peer} =
      peer(fn socket ->
        {id, _flags} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
      end)

    {stream, generation} = start_stream(url, self())
    monitor = Process.monitor(stream)

    assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000
    Process.exit(owner, :kill)

    assert_receive {:http_runtime, ^generation, ^stream, {:error, {:owner_down, :killed}}}, 5_000
    assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 5_000
  end

  for cancellation <- [:close, :subscriber_death], timeout <- [5_000, :infinity] do
    test "#{cancellation} interrupts a stalled TLS handshake with #{timeout} timeout and closes the dial socket" do
      test_pid = self()

      {url, peer} =
        peer(
          fn socket ->
            send(test_pid, {:dial_accepted, self()})
            assert :closed = receive_until_closed(socket)
            send(test_pid, {:dial_closed, self()})
          end,
          :stalled_tls
        )

      subscriber = subscriber(test_pid)

      {stream, _generation} =
        start_stream(url, subscriber,
          http_version: :http2,
          connect_timeout: unquote(timeout),
          opening_timeout: unquote(timeout)
        )

      monitor = Process.monitor(stream)
      assert_receive {:dial_accepted, ^peer}, 5_000

      case unquote(cancellation) do
        :close -> Stream.close(stream)
        :subscriber_death -> send(subscriber, :stop)
      end

      assert_receive {:DOWN, ^monitor, :process, ^stream, :normal}, 1_000
      assert_receive {:dial_closed, ^peer}, 1_000
    end
  end

  defp start_stream(url, subscriber, opts \\ []) do
    request = %HTTP.Request{
      method: Keyword.get(opts, :method, :get),
      url: URI.parse(url),
      body: Keyword.get(opts, :body),
      transport_options: [
        http_version: Keyword.get(opts, :http_version, :h2c),
        http2_scope: Keyword.get(opts, :scope, "stream-#{System.unique_integer([:positive])}"),
        http2_reuse: Keyword.get(opts, :reuse, true),
        connect_timeout: Keyword.get(opts, :connect_timeout, 5_000),
        tls_backend: :ssl
      ]
    }

    {:ok, stream, generation} =
      Stream.start(request, subscriber, Keyword.take(opts, [:generation, :opening_timeout]))

    on_exit(fn ->
      if Process.alive?(stream), do: close_stream(stream)
    end)

    {stream, generation}
  end

  defp close_stream(stream) do
    monitor = Process.monitor(stream)
    Stream.close(stream)
    Stream.close(stream)
    assert_receive {:DOWN, ^monitor, :process, ^stream, reason}, 5_000
    assert reason in [:normal, :noproc]
  end

  defp acknowledge_barrier(stream, delivery) do
    marker = make_ref()
    :erlang.trace_pattern({Stream, :settle, 3}, true, [:local])
    :erlang.trace(stream, true, [:call, {:tracer, self()}])

    try do
      Stream.acknowledge(stream, delivery)
      Stream.acknowledge(stream, marker)

      assert_receive {:trace, ^stream, :call, {Stream, :settle, [_lease, _deliveries, ^marker]}},
                     5_000
    after
      :erlang.trace(stream, false, [:call])
      :erlang.trace_pattern({Stream, :settle, 3}, false, [:local])
    end
  end

  defp subscriber(parent) do
    pid = spawn(fn -> subscriber_loop(parent) end)
    on_exit(fn -> Process.exit(pid, :kill) end)
    pid
  end

  defp subscriber_loop(parent) do
    receive do
      :stop ->
        :ok

      event ->
        send(parent, {:forwarded, event})
        subscriber_loop(parent)
    end
  end

  defp peer(script, mode \\ :h2c) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)

        if mode == :h2c do
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

    scheme = if mode == :h2c, do: "http", else: "https"
    {"#{scheme}://127.0.0.1:#{port}/events", peer}
  end

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp receive_frame(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, 5_000)
    payload = if size == 0, do: <<>>, else: recv_payload(socket, size)
    {type, flags, id, payload}
  end

  defp recv_payload(socket, size) do
    assert {:ok, payload} = :gen_tcp.recv(socket, size, 5_000)
    payload
  end

  defp request(socket) do
    case receive_frame(socket) do
      {1, flags, id, _payload} ->
        {id, flags}

      {4, 0, 0, _payload} ->
        :ok = :gen_tcp.send(socket, frame(4, 1, 0, <<>>))
        request(socket)

      _frame ->
        request(socket)
    end
  end

  defp next_frame(socket, type, id) do
    case receive_frame(socket) do
      {^type, _flags, ^id, _payload} = observed -> observed
      _frame -> next_frame(socket, type, id)
    end
  end

  defp receive_until_closed(socket) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, _client_hello} -> receive_until_closed(socket)
      {:error, :closed} -> :closed
      {:error, reason} -> reason
    end
  end

  defp no_reset_barrier(socket, id) do
    :ok = :gen_tcp.send(socket, frame(6, 0, 0, "endproof"))
    no_reset_before_ping_ack(socket, id)
  end

  defp no_reset_before_ping_ack(socket, id) do
    case receive_frame(socket) do
      {3, _, ^id, _} -> flunk("completed request received an unexpected RST_STREAM")
      {6, 1, 0, "endproof"} -> :ok
      _frame -> no_reset_before_ping_ack(socket, id)
    end
  end

  defp no_new_headers(socket) do
    case receive_frame(socket) do
      {1, _, _, _} -> flunk("expired opening wrote request HEADERS")
      {6, 1, 0, "no-open!"} -> :ok
      _frame -> no_new_headers(socket)
    end
  end
end

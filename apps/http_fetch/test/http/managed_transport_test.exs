defmodule HTTP.ManagedTransportTest do
  use ExUnit.Case, async: false

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  test "suspended coordinator has bounded nonblocking ingress and no late dialing" do
    {origin, listener} = listener()
    scope = open(origin, max_requests: 2)
    :sys.suspend(scope.coordinator)

    try do
      first = fetch(origin, scope, timeout: 100)
      second = fetch(origin, scope, timeout: 100)

      for _ <- 1..20 do
        assert {:error, {:transport_scope_capacity, :requests}} =
                 Promise.await(fetch(origin, scope))
      end

      assert {:error, :request_timeout} = Promise.await(first)
      assert {:error, :request_timeout} = Promise.await(second)
      assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
      assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
      assert {:messages, messages} = Process.info(scope.coordinator, :messages)
      refute Enum.any?(messages, &match?({:"$gen_call", _, _}, &1))
      assert :ets.info(scope.ingress, :size) == 2
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    after
      :sys.resume(scope.coordinator)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  test "dead preparer releases a fixed ingress slot without admission messages" do
    {origin, _} = listener()
    scope = open(origin, max_requests: 1)
    parent = self()

    preparer =
      spawn(fn ->
        request = %HTTP.Request{
          url: URI.parse(origin),
          transport_options: [
            transport_scope: scope,
            redirect: :manual,
            stream_response: true,
            decode_body: false
          ]
        }

        assert {:ok, _} = ManagedTransport.prepare(request, [])
        send(parent, :claimed)
      end)

    monitor = Process.monitor(preparer)
    assert_receive :claimed
    assert_receive {:DOWN, ^monitor, _, _, :normal}

    wait_until(fn ->
      match?({:ok, %{preparing_requests: 0}}, ManagedTransport.snapshot(scope, 100))
    end)

    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
  end

  test "a live source without attachment acknowledgement times out without premature cleanup" do
    {origin, listener} = listener()
    scope = open(origin, max_requests: 1)
    source = spawn(fn -> receive do: (:fixture_stop -> :ok) end)
    source_monitor = Process.monitor(source)
    promise = fetch(origin, scope, body: source, method: :post, timeout: 40)

    assert {:error, :request_timeout} = Promise.await(promise, 500)
    assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(promise), 0)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    assert {:error, {:transport_scope_capacity, :requests}} = Promise.await(fetch(origin, scope))
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 20)

    send(source, :fixture_stop)
    assert_receive {:DOWN, ^source_monitor, _, ^source, :normal}
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
  end

  test "canceled suspended tracker gets one abort and holds its slot until termination" do
    {origin, _} = listener()
    scope = open(origin, max_requests: 1)
    {tracker, _} = HTTP.RequestLifecycle.start()
    :sys.suspend(tracker)
    token = make_ref()
    :ets.insert(scope.ingress, {1, token, self(), :canceled, tracker})

    try do
      for _ <- 1..20 do
        assert {:ok, %{preparing_requests: 1}} = ManagedTransport.snapshot(scope, 100)
      end

      assert {:messages, messages} = Process.info(tracker, :messages)
      assert Enum.count(messages, &(&1 == :abort)) == 1
      assert [{1, ^token, _, :canceling, ^tracker}] = :ets.lookup(scope.ingress, 1)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 0)
    after
      :sys.resume(tracker)
      GenServer.stop(tracker, :normal)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
  end

  test "scope binding respects remaining deadline while tracker is suspended" do
    {origin, listener} = listener()
    scope = open(origin, max_requests: 1)
    {tracker, _} = HTTP.RequestLifecycle.start()
    request = managed_request(origin, scope, timeout: 40)
    assert {:ok, request} = ManagedTransport.prepare(request, [])
    assert :ok = ManagedTransport.associate(request, tracker)
    :sys.suspend(tracker)

    try do
      admission = Task.async(fn -> ManagedTransport.admit(request, tracker) end)
      assert {:error, :request_timeout} = Task.await(admission, 500)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 0)
    after
      :sys.resume(tracker)
      GenServer.stop(tracker, :normal)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  test "retirement invalidates a preparing lease before tracker association" do
    {origin, listener} = listener()
    scope = open(origin, max_requests: 1)
    assert {:ok, request} = ManagedTransport.prepare(managed_request(origin, scope), [])
    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    {tracker, _} = HTTP.RequestLifecycle.start()
    assert {:error, :transport_scope_retired} = ManagedTransport.associate(request, tracker)
    GenServer.stop(tracker, :normal)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  test "connector admission cannot outlast the request deadline or dial after coordinator resume" do
    {origin, listener} = listener()
    scope = open(origin, max_requests: 1)
    {tracker, _} = HTTP.RequestLifecycle.start()

    assert {:ok, request} =
             ManagedTransport.prepare(managed_request(origin, scope, timeout: 100), [])

    assert :ok = ManagedTransport.associate(request, tracker)
    assert :ok = ManagedTransport.admit(request, tracker)
    :sys.suspend(scope.coordinator)

    try do
      connector =
        Task.async(fn ->
          Process.put(HTTP.RequestLifecycle, tracker)
          ManagedTransport.connect_start(request)
        end)

      assert {:error, :request_timeout} = Task.await(connector, 500)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    after
      :sys.resume(scope.coordinator)
      GenServer.stop(tracker, :normal)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  for failure <- [:creator, :coordinator] do
    test "#{failure} death closes live resources with honest durable evidence" do
      parent = self()
      {origin, listener} = listener()

      creator =
        spawn(fn ->
          scope = open(origin)
          send(parent, {:scope, scope})
          receive do: (:stop -> :ok)
        end)

      assert_receive {:scope, scope}

      peer =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)
          assert {:ok, _} = :gen_tcp.recv(socket, 0, 2_000)
          :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nraw")
          assert {:error, :closed} = :gen_tcp.recv(socket, 0, 2_000)
          :gen_tcp.close(listener)
        end)

      promise = fetch(origin, scope)
      assert %Response{stream: stream} = Promise.await(promise)
      stream_monitor = Process.monitor(stream)
      children = :sys.get_state(scope.coordinator).children |> Map.values()
      monitors = Enum.map(children, &Process.monitor/1)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)

      case unquote(failure) do
        :creator ->
          send(creator, :stop)

        :coordinator ->
          Process.exit(scope.coordinator, :kill)
          send(creator, :stop)
      end

      expected = if unquote(failure) == :creator, do: :ok, else: {:error, :cleanup_unconfirmed}
      assert ManagedTransport.await_retired(receipt, 2_000) == expected
      assert_receive {:DOWN, ^stream_monitor, _, ^stream, _}, 2_000
      for monitor <- monitors, do: assert_receive({:DOWN, ^monitor, _, _, _}, 2_000)
      assert :ok = Task.await(peer, 2_000)
      assert ManagedTransport.await_retired(receipt, 0) == expected
    end
  end

  test "concurrent and repeated retirement receipts survive coordinator termination" do
    {origin, _} = listener()
    scope = open(origin)
    receipts = for _ <- 1..8, do: Task.async(fn -> ManagedTransport.retire(scope) end)

    for task <- receipts do
      assert {:ok, receipt} = Task.await(task)

      waiters =
        for _ <- 1..4, do: Task.async(fn -> ManagedTransport.await_retired(receipt, 1_000) end)

      assert Enum.all?(waiters, &(Task.await(&1) == :ok))
      assert :ok = ManagedTransport.await_retired(receipt, 0)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 0)
  end

  test "incompatible camelCase policy and oversized body reject before any accept" do
    {origin, listener} = listener()
    scope = open(origin)

    for override <- [
          %{"httpVersion" => :auto},
          %{"connectAddress" => {127, 0, 0, 2}},
          %{"tlsBackend" => :ex_ssl},
          %{"socketOpts" => [send_timeout: 10]}
        ] do
      options =
        Map.merge(
          %{transport_scope: scope, redirect: :manual, stream_response: true, decode_body: false},
          override
        )

      assert {:error, :transport_scope_policy_mismatch} =
               Promise.await(HTTP.fetch(origin, options))
    end

    assert {:error, :transport_scope_request_limit} =
             Promise.await(
               fetch(origin, scope, method: :post, body: :binary.copy("x", 1_048_577))
             )

    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
  end

  test "invalid socket and TLS policy rejects at open" do
    {origin, _} = listener()

    for sockets <- [[send_timeout: true], [nodelay: 3], [send_timeout_close: false]] do
      assert {:error, :invalid_transport_scope_socket_policy} =
               ManagedTransport.open(
                 origin: origin,
                 connect_address: {127, 0, 0, 1},
                 http_version: :http1,
                 socket_opts: sockets
               )
    end

    assert {:error, :invalid_transport_scope_tls_policy} =
             ManagedTransport.open(
               origin: "https://localhost",
               connect_address: {127, 0, 0, 1},
               http_version: :http1,
               ssl: [verify: :invented]
             )
  end

  for version <- [:http1, :h2c] do
    test "#{version} upload rejects a source chunk larger than 65536 bytes" do
      parent = self()
      {origin, listener} = listener()

      peer =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 2_000)

          case unquote(version) do
            :http1 ->
              assert {:ok, head} = :gen_tcp.recv(socket, 0, 2_000)
              assert head =~ "POST / HTTP/1.1"

            :h2c ->
              assert {:ok, _preface} = :gen_tcp.recv(socket, 24, 2_000)
              :ok = :gen_tcp.send(socket, Peer.frame(4, 0, 0, <<>>))
              {id, false} = Peer.request(socket)
              await_reset(socket, id)
          end

          send(parent, :chunk_rejected_wire)
          assert_closed(socket)
          :gen_tcp.close(listener)
        end)

      scope = open(origin, http_version: unquote(version))
      {:ok, source} = HTTP.Stream.start_link(0)
      source_monitor = Process.monitor(source)

      promise =
        fetch(origin, scope, method: :post, body: source, duplex: :half, request_mode: :proxy)

      assert {:error, :buffer_limit} = HTTP.Stream.chunk(source, :binary.copy("x", 65_537), 2_000)

      expected =
        if unquote(version) == :http1, do: :buffer_limit, else: {:body_error, :buffer_limit}

      assert {:error, ^expected} = Promise.await(promise)
      assert_receive {:DOWN, ^source_monitor, _, ^source, _}, 1_000
      assert_receive :chunk_rejected_wire, 1_000
      assert {:ok, receipt} = ManagedTransport.retire(scope)
      assert :ok = ManagedTransport.await_retired(receipt, 1_000)
      assert :ok = Task.await(peer, 2_000)
    end
  end

  test "managed H1 upload sends acknowledged DATA before ordered duplicate request trailers" do
    {origin, listener} = listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        wire = receive_until(socket, "0\r\nx-checksum: first\r\nx-checksum: second\r\n\r\n")
        assert String.downcase(wire) =~ "trailer: x-checksum\r\n"
        assert wire =~ "4\r\ndata\r\n0\r\n"
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        assert_closed(socket)
        :gen_tcp.close(listener)
      end)

    scope = open(origin)
    {:ok, source} = HTTP.Stream.start_link(0)

    promise =
      fetch(origin, scope,
        method: :post,
        body: source,
        duplex: :half,
        request_mode: :proxy,
        headers: [{"trailer", "x-checksum"}]
      )

    assert :ok = HTTP.Stream.chunk(source, "data", 2_000)
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "first"}, {"x-checksum", "second"}])
    assert %Response{} = response = Promise.await(promise)
    assert Response.read_all(response) == "ok"
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    assert :ok = Task.await(peer, 2_000)
  end

  test "managed H2 upload maintains HPACK and ordered duplicate request trailers after DATA" do
    {origin, listener} = listener()

    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 2_000)
        assert {:ok, _} = :gen_tcp.recv(socket, 24, 2_000)
        :ok = :gen_tcp.send(socket, Peer.frame(4, 0, 0, <<>>))
        {1, 4, id, initial} = next_headers(socket)

        assert {:ok, decoder, _} =
                 HTTP.HTTP2.HPACK.decode(HTTP.HTTP2.HPACK.new_decoder(), initial)

        assert {"data", encoded} = upload_trailers(socket, id)
        assert {:ok, _, trailers} = HTTP.HTTP2.HPACK.decode(decoder, encoded)
        assert trailers == [{"x-checksum", "first"}, {"x-checksum", "second"}]
        :ok = Peer.response(socket, id, "ok")
        assert_closed(socket)
        :gen_tcp.close(listener)
      end)

    scope = open(origin, http_version: :h2c)
    {:ok, source} = HTTP.Stream.start_link(4)

    promise =
      fetch(origin, scope,
        method: :post,
        body: source,
        duplex: :half,
        request_mode: :proxy,
        headers: [{"content-length", "4"}]
      )

    assert :ok = HTTP.Stream.chunk(source, "data", 2_000)
    assert :ok = HTTP.Stream.finish(source, [{"x-checksum", "first"}, {"x-checksum", "second"}])
    assert %Response{} = response = Promise.await(promise)
    assert Response.read_all(response) == "ok"
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    assert :ok = Task.await(peer, 2_000)
  end

  test "H2 short request deadline preserves frozen writer and healthy sibling trailers" do
    parent = self()

    {url, peer} =
      Peer.start(parent, fn socket ->
        {first, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, first, <<0x88>>))
        {second, true} = Peer.request(socket)
        :ok = :gen_tcp.send(socket, Peer.frame(1, 4, second, <<0x88>>))
        await_reset(socket, second)
        send(parent, :deadline_reset)

        fields =
          HTTP.HTTP2.HPACK.encode_headers([{"x-raw", "first"}, {"x-raw", "second"}])
          |> IO.iodata_to_binary()

        :ok =
          :gen_tcp.send(socket, [Peer.frame(0, 0, first, "raw"), Peer.frame(1, 5, first, fields)])
      end)

    origin = url |> URI.parse() |> Map.put(:path, nil) |> URI.to_string()
    scope = open(origin, http_version: :h2c, socket_opts: [send_timeout: 1_500])
    first = fetch(origin, scope)
    assert %Response{stream: first_stream} = Promise.await(first)
    second = fetch(origin, scope, timeout: 100)
    assert %Response{stream: second_stream} = Promise.await(second)
    send(second_stream, {:read_chunk, self()})
    assert_receive {:stream_error, ^second_stream, :request_timeout}, 1_000
    assert_receive :deadline_reset, 1_000

    owner =
      :sys.get_state(scope.coordinator).resources
      |> Map.values()
      |> Enum.find_value(fn {resource, kind, _} -> if kind == :connection, do: resource end)

    assert :sys.get_state(owner).write_timeout == 1_500
    send(first_stream, {:read_chunk, self(), :ack})
    assert_receive {:stream_chunk, ^first_stream, "raw", ack}, 1_000
    send(first_stream, {:stream_chunk_ack, ack})
    assert_receive {:stream_trailers, ^first_stream, trailers}, 1_000
    assert HTTP.Headers.get_all(trailers, "x-raw") == ["first", "second"]
    assert_receive {:stream_end, ^first_stream}, 1_000
    assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
    assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    assert {:ok, receipt} = ManagedTransport.retire(scope)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    assert_receive {:peer_complete, ^peer}, 1_000
    send(peer, :close)
  end

  defp await_reset(socket, id) do
    case Peer.recv(socket) do
      {3, 0, ^id, <<8::32>>} -> :ok
      _ -> await_reset(socket, id)
    end
  end

  defp receive_until(socket, suffix, acc \\ "") do
    if String.ends_with?(acc, suffix) do
      acc
    else
      assert {:ok, bytes} = :gen_tcp.recv(socket, 0, 2_000)
      receive_until(socket, suffix, acc <> bytes)
    end
  end

  defp next_headers(socket) do
    case Peer.recv(socket) do
      {1, _, _, _} = frame -> frame
      _ -> next_headers(socket)
    end
  end

  defp upload_trailers(socket, id, body \\ "") do
    case Peer.recv(socket) do
      {0, 0, ^id, bytes} -> upload_trailers(socket, id, body <> bytes)
      {1, 5, ^id, encoded} -> {body, encoded}
      {0, 1, ^id, _} -> flunk("DATA ended the request before trailers")
      _ -> upload_trailers(socket, id, body)
    end
  end

  defp assert_closed(socket) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, _control} -> assert_closed(socket)
      result -> assert result == {:error, :closed}
    end
  end

  defp listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {"http://127.0.0.1:#{port}", listener}
  end

  defp open(origin, extra \\ []) do
    assert {:ok, scope} =
             ManagedTransport.open(
               Keyword.merge(
                 [origin: origin, connect_address: {127, 0, 0, 1}, http_version: :http1],
                 extra
               )
             )

    scope
  end

  defp fetch(origin, scope, extra \\ []),
    do:
      HTTP.fetch(
        origin <> "/",
        Keyword.merge(
          [
            transport_scope: scope,
            redirect: :manual,
            stream_response: true,
            decode_body: false,
            timeout: 3_000
          ],
          extra
        )
      )

  defp managed_request(origin, scope, extra \\ []) do
    %HTTP.Request{
      url: URI.parse(origin),
      transport_options:
        Keyword.merge(
          [transport_scope: scope, redirect: :manual, stream_response: true, decode_body: false],
          extra
        )
    }
  end

  defp wait_until(fun, attempts \\ 200)
  defp wait_until(_, 0), do: flunk("condition did not settle")

  defp wait_until(fun, attempts) do
    if fun.(),
      do: :ok,
      else:
        (receive do
         after
           5 -> wait_until(fun, attempts - 1)
         end)
  end
end

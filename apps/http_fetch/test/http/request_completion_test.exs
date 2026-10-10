defmodule HTTP.RequestCompletionTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion, RequestLifecycle}

  test "a stream terminal event is not cleanup completion; concurrent waits and retries" do
    {tracker, latch} = RequestLifecycle.start()
    handle = %RequestCompletion{tracker: tracker, latch: latch}
    test = self()

    owner =
      spawn(fn ->
        RequestLifecycle.enter(tracker, :owner)
        send(test, {:ready, self()})

        receive do
          :abort ->
            send(test, :stream_terminal)

            receive do
              :cleanup_released -> RequestLifecycle.complete(tracker)
            end
        end
      end)

    assert_receive {:ready, ^owner}
    assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 0)
    assert_receive :stream_terminal
    waiters = for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(handle, 20) end)
    assert Enum.all?(waiters, &(Task.await(&1) == {:error, :cleanup_pending}))
    send(owner, :cleanup_released)
    assert :ok = RequestCompletion.await(handle, 1_000)
    assert :ok = RequestCompletion.abort_and_await(handle, 0)
    refute Process.alive?(tracker)
  end

  test "sticky cancellation before registration and persistent owner-death evidence" do
    {tracker, latch} = RequestLifecycle.start()
    handle = %RequestCompletion{tracker: tracker, latch: latch}
    assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 0)
    parent = self()

    owner =
      spawn(fn ->
        RequestLifecycle.enter(tracker, :owner)

        receive do
          :abort -> send(parent, :early_abort)
        end
      end)

    assert_receive :early_abort
    monitor = Process.monitor(owner)
    assert_receive {:DOWN, ^monitor, :process, ^owner, _}
    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(handle, 1_000)
    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(handle, 0)
  end

  test "tracker death does not exit the waiter or become successful cleanup" do
    {tracker, latch} = RequestLifecycle.start()
    handle = %RequestCompletion{tracker: tracker, latch: latch}
    monitor = Process.monitor(tracker)
    Process.exit(tracker, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^tracker, :killed}
    assert {:error, :cleanup_unconfirmed} = RequestCompletion.abort_and_await(handle, 0)
  end

  test "an owner waiting for launch stops if its parent dies during registration" do
    {tracker, latch} = RequestLifecycle.start()
    handle = %RequestCompletion{tracker: tracker, latch: latch}
    :erlang.suspend_process(tracker)

    caller =
      spawn(fn ->
        receive do
          :start ->
            HTTP.SocketClient.request(%HTTP.Request{
              url: URI.parse("http://127.0.0.1:1/"),
              transport_options: [redirect: :manual, request_lifecycle: tracker]
            })
        end
      end)

    :erlang.trace(caller, true, [:send])
    send(caller, :start)

    try do
      assert_receive {:trace, ^caller, :send, {:"$gen_call", _from, {:register, owner, :owner}},
                      ^tracker},
                     1_000

      on_exit(fn ->
        if Process.alive?(owner), do: Process.exit(owner, :kill)
      end)

      monitor = Process.monitor(owner)
      Process.exit(caller, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
    after
      Process.exit(caller, :kill)
      :erlang.resume_process(tracker)
    end

    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(handle, 1_000)
  end

  test "actual TCP streaming abort waits for request resource shutdown" do
    {server, url} =
      server(fn socket, parent ->
        {:ok, _head} = :gen_tcp.recv(socket, 0, 2_000)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        send(parent, :headers_sent)
        send(parent, {:peer_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    promise = HTTP.fetch(url, redirect: :manual, stream_response: true)
    handle = Promise.completion(promise)
    assert %RequestCompletion{} = handle
    assert_receive :headers_sent
    response = Promise.await(promise)
    stream = response.stream
    stream_monitor = Process.monitor(stream)
    assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    assert :ok = RequestCompletion.abort_and_await(handle, 2_000)
    assert_receive {:DOWN, ^stream_monitor, :process, ^stream, :normal}
    assert_receive {:peer_closed, {:error, :closed}}
    assert :ok = RequestCompletion.await(handle, 0)
    assert :ok = Task.await(server)
  end

  test "actual streamed terminal stays pending while its real socket owner is suspended" do
    {server, url} =
      server(fn socket, parent ->
        {:ok, _head} = :gen_tcp.recv(socket, 0, 2_000)
        :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        send(parent, {:held_peer_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    controller = HTTP.AbortController.new()
    promise = HTTP.fetch(url, signal: controller, redirect: :manual, stream_response: true)
    handle = Promise.completion(promise)
    response = Promise.await(promise)
    owner = Agent.get(controller, & &1.request_id)
    stream = response.stream
    stream_monitor = Process.monitor(stream)
    send(stream, {:read_chunk, self(), :ack})
    :erlang.suspend_process(owner)

    try do
      assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 20)
      assert_receive {:stream_error, ^stream, :aborted}
      assert_receive {:DOWN, ^stream_monitor, :process, ^stream, :normal}
      assert Process.alive?(owner)
      assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    after
      :erlang.resume_process(owner)
    end

    assert :ok = RequestCompletion.await(handle, 1_000)
    assert_receive {:held_peer_closed, {:error, :closed}}
    assert :ok = Task.await(server)
  end

  test "OTP TLS handshake cancellation confirms the retained TCP and dial worker stop" do
    {server, url} =
      server(fn socket, parent ->
        {:ok, _client_hello} = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, :handshake_started)
        send(parent, {:handshake_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    promise =
      HTTP.fetch(String.replace(url, "http:", "https:"),
        redirect: :manual,
        ssl: [verify: :verify_none],
        timeout: 2_000
      )

    handle = Promise.completion(promise)
    assert_receive :handshake_started, 1_000
    assert :ok = RequestCompletion.abort_and_await(handle, 1_000)
    assert {:error, _} = Promise.await(promise)
    assert_receive {:handshake_closed, {:error, :closed}}
    assert :ok = Task.await(server)
  end

  test "a suspended upload source cannot block access to its public cancellation handle" do
    {:ok, source} = HTTP.Stream.start_link(0)
    :erlang.suspend_process(source)
    promise = HTTP.fetch("http://127.0.0.1:1/", redirect: :manual, body: source, duplex: :half)
    handle = Promise.completion(promise)

    try do
      assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(handle, 20)
    after
      :erlang.resume_process(source)
    end

    assert :ok = RequestCompletion.await(handle, 1_000)
    assert {:error, _} = Promise.await(promise)
    refute Process.alive?(source)
  end

  test "library enumerable blocked before its first item is stopped on cancellation" do
    parent = self()

    enumerable =
      Stream.resource(
        fn ->
          send(parent, {:enumerating, self()})
          :ready
        end,
        fn _ ->
          receive do
            :never -> {["body"], :ready}
          end
        end,
        fn _ -> :ok end
      )

    {:ok, source} = HTTP.Stream.from_enumerable(enumerable)
    assert_receive {:enumerating, producer}
    monitor = Process.monitor(producer)

    {server, url} =
      server(fn socket, parent ->
        {:ok, _head} = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, :upload_headers)
        send(parent, {:upload_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    promise = HTTP.fetch(url, method: :post, body: source, duplex: :half, redirect: :manual)
    assert_receive :upload_headers
    assert :ok = RequestCompletion.abort_and_await(Promise.completion(promise), 2_000)
    assert_receive {:DOWN, ^monitor, :process, ^producer, :killed}
    refute Process.alive?(source)
    assert_receive {:upload_closed, {:error, :closed}}
    assert {:error, _} = Promise.await(promise)
    assert :ok = Task.await(server)
  end

  test "buffered success and invalid URL seal requests without leaking the tracker" do
    {server, url} =
      server(fn socket, _parent ->
        {:ok, _head} = :gen_tcp.recv(socket, 0, 2_000)
        :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
      end)

    promise = HTTP.fetch(url, redirect: :manual)
    assert %HTTP.Response{body: "ok"} = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    assert :ok = Task.await(server)
    invalid = HTTP.fetch("bad://host", redirect: :manual)
    assert {:error, _} = Promise.await(invalid)
    assert :ok = RequestCompletion.await(Promise.completion(invalid), 1_000)
  end

  test "unsupported scheme cleans up an attached upload source without an owner" do
    {:ok, source} = HTTP.Stream.start_link(0)
    promise = HTTP.fetch("bad://host", redirect: :manual, body: source, duplex: :half)
    assert {:error, _} = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
    refute Process.alive?(source)
  end

  test "an already-aborted public controller confirms cleanup without dialing" do
    controller = HTTP.AbortController.new()
    HTTP.AbortController.abort(controller)
    promise = HTTP.fetch("http://127.0.0.1:1/", signal: controller, redirect: :manual)
    assert {:error, :aborted} = Promise.await(promise)
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
  end

  test "failed task launch releases the coordinator and preserves the exception" do
    {tracker, latch} = RequestLifecycle.start()
    handle = %RequestCompletion{tracker: tracker, latch: latch}

    assert_raise RuntimeError, "launch failed", fn ->
      RequestLifecycle.launch(tracker, fn -> raise "launch failed" end)
    end

    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(handle, 1_000)
    refute Process.alive?(tracker)
  end

  test "unsupported configurations and chained promise expose no broad guarantee" do
    for opts <- [
          [http_version: :http2],
          [http1_reuse: true],
          [tls_backend: :ex_ssl],
          [tls_backend: "ex_ssl"],
          [redirect: :follow]
        ] do
      options = HTTP.FetchOptions.new(Keyword.merge([redirect: :manual], opts))
      handle = RequestCompletion.new(options)
      assert {:error, {:unsupported_completion, _}} = RequestCompletion.await(handle, 0)
    end

    assert Promise.completion(%Promise{}) == nil
  end

  defp server(fun) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, {_address, port}} = :inet.sockname(listener)
    parent = self()

    task =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)

        try do
          fun.(socket, parent)
          :ok
        after
          :gen_tcp.close(socket)
          :gen_tcp.close(listener)
        end
      end)

    {task, "http://127.0.0.1:#{port}/"}
  end
end

defmodule HTTP.RequestCompletionBackendTest do
  use ExUnit.Case, async: false

  test "public option normalization pins the global ExSSL backend before eligibility" do
    previous = Application.fetch_env(:http_core, :tls_backend)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:http_core, :tls_backend, value)
        :error -> Application.delete_env(:http_core, :tls_backend)
      end
    end)

    Application.put_env(:http_core, :tls_backend, "ex_ssl")
    options = HTTP.FetchOptions.new(redirect: :manual)
    assert options.tls_backend == :ex_ssl
    handle = HTTP.RequestCompletion.new(options)

    assert {:error, {:unsupported_completion, :tls_backend}} =
             HTTP.RequestCompletion.await(handle, 0)

    explicit = HTTP.FetchOptions.new(redirect: :manual, tls_backend: "ssl")
    assert explicit.tls_backend == :ssl
  end
end

defmodule HTTP.RequestCompletionTest do
  use ExUnit.Case, async: true

  alias HTTP.{Promise, RequestCompletion, RequestLifecycle}

  test "handoff proof requires the exact public nonce and one epoch advance" do
    nonce = make_ref()
    carrier = %{epoch: 4, nonce: nonce}
    accepted = %{epoch: 5, transfer_nonce: nonce, transfer: :accepted}
    assert :accepted = RequestLifecycle.transfer_state(carrier, {:pending, accepted})

    for evidence <- [
          {:pending, %{accepted | epoch: 4}},
          {:pending, %{accepted | epoch: 6}},
          {:pending, %{accepted | transfer_nonce: make_ref()}},
          {:pending, Map.delete(accepted, :transfer_nonce)},
          {:terminal, accepted},
          {:unconfirmed, :invalid_evidence}
        ] do
      assert :unconfirmed = RequestLifecycle.transfer_state(carrier, evidence)
    end

    for outcome <- [:pending, :unknown, :expired, :cancelled] do
      evidence = %{epoch: 4, transfer_nonce: nonce, transfer: outcome}
      assert :pending = RequestLifecycle.transfer_state(carrier, {:pending, evidence})
    end

    assert :unconfirmed =
             RequestLifecycle.transfer_state(%{carrier | nonce: nil}, {:pending, accepted})
  end

  test "completed HTTP workers still join a pending public provider attempt" do
    {completion, owner, handle} = provider_request()
    monitor = Process.monitor(owner)
    send(owner, :complete)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
    assert {:pending, _} = SSL.Lifecycle.await(handle, provider_deadline(0))
    assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)

    waiters = for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(completion, 20) end)
    assert Enum.all?(waiters, &(Task.await(&1) == {:error, :cleanup_pending}))

    assert :ok = RequestCompletion.abort_and_await(completion, 1_000)
    assert {:ok, %{cleanup: :confirmed}} = SSL.Lifecycle.await(handle, provider_deadline(0))
    assert :ok = RequestCompletion.await(completion, 0)
    refute Process.alive?(completion.tracker)
  end

  test "genuine provider cleanup cannot complete an independent HTTP worker" do
    {completion, owner, handle} = provider_request()
    RequestLifecycle.provider_failed(completion.tracker)
    assert {:ok, %{cleanup: :confirmed}} = SSL.Lifecycle.await(handle, provider_deadline(1_000))
    assert Process.alive?(owner)
    assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 20)
    send(owner, :complete)
    assert :ok = RequestCompletion.await(completion, 1_000)
  end

  test "missing or unconfirmed public evidence never becomes confirmed cleanup" do
    missing = SSL.Lifecycle.await(:missing, provider_deadline(0))
    assert {:unconfirmed, :invalid_evidence} = missing
    assert :unconfirmed = RequestLifecycle.provider_cleanup(missing)
    assert :unconfirmed = RequestLifecycle.provider_cleanup({:ok, %{version: 1}})

    assert :unconfirmed =
             RequestLifecycle.provider_cleanup({:ok, %{version: 2, cleanup: :unconfirmed}})

    assert :confirmed =
             RequestLifecycle.provider_cleanup({:ok, %{version: 2, cleanup: :confirmed}})

    {completion, owner, handle} = provider_request()
    RequestLifecycle.unconfirmed(completion.tracker)
    RequestLifecycle.provider_failed(completion.tracker)
    assert {:ok, %{cleanup: :confirmed}} = SSL.Lifecycle.await(handle, provider_deadline(1_000))
    send(owner, :complete)
    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(completion, 1_000)
    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(completion, 0)
  end

  test "only direct HTTPS HTTP/1 and HTTP/2 admit ExSSL completion, including reuse" do
    options = HTTP.FetchOptions.new(redirect: :manual, tls_backend: :ex_ssl)
    request = %HTTP.Request{url: URI.parse("https://localhost/")}

    for excluded <- [
          %{options | transport_scope: :not_integrated}
        ] do
      assert {:error, {:unsupported_completion, :tls_backend}} =
               excluded |> RequestCompletion.new(request) |> RequestCompletion.await(0)
    end

    completion = RequestCompletion.new(options, request)
    assert %RequestCompletion{unsupported: nil, tracker: tracker} = completion
    GenServer.stop(tracker)

    reused = RequestCompletion.new(%{options | http1_reuse: true}, request)
    assert %RequestCompletion{unsupported: nil, tracker: reused_tracker} = reused
    GenServer.stop(reused_tracker)
    http2 = RequestCompletion.new(%{options | http_version: :http2}, request)
    assert %RequestCompletion{unsupported: nil, tracker: http2_tracker} = http2
    GenServer.stop(http2_tracker)
  end

  test "untracked opaque socket handoff respects the absolute deadline" do
    socket = make_ref()

    assert :ok =
             RequestLifecycle.handoff_socket(
               nil,
               socket,
               System.monotonic_time(:millisecond) + 1_000
             )

    assert {:error, :handoff_expired} =
             RequestLifecycle.handoff_socket(nil, socket, System.monotonic_time(:millisecond))
  end

  test "expired handoff retains the tracker resource monitors" do
    {tracker, _latch} = RequestLifecycle.start()
    resource = spawn(fn -> receive do: (:stop -> :ok) end)
    :ok = RequestLifecycle.register(tracker, resource, :tls)

    assert {:error, :handoff_expired} =
             RequestLifecycle.handoff_socket(
               tracker,
               resource,
               System.monotonic_time(:millisecond)
             )

    assert Enum.any?(:sys.get_state(tracker).resources, fn {_, value} ->
             value == {resource, :tls}
           end)

    send(resource, :stop)
    GenServer.stop(tracker)
  end

  test "deadline handoff does not manufacture success after tracker death" do
    {tracker, _latch} = RequestLifecycle.start()
    GenServer.stop(tracker)

    assert {:error, :handoff_unconfirmed} =
             RequestLifecycle.handoff_socket(
               tracker,
               self(),
               System.monotonic_time(:millisecond) + 1_000
             )
  end

  test "a settled latch still waits for the tracker to terminate" do
    latch = :atomics.new(1, [])
    :atomics.put(latch, 1, 2)
    parent = self()

    tracker =
      spawn(fn ->
        send(parent, :tracker_ready)

        receive do
          :stop -> :ok
        end
      end)

    assert_receive :tracker_ready
    handle = %RequestCompletion{tracker: tracker, latch: latch}
    assert {:error, :cleanup_pending} = RequestCompletion.await(handle, 0)
    monitor = Process.monitor(tracker)
    send(tracker, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^tracker, :normal}
    assert :ok = RequestCompletion.await(handle, 0)
  end

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

  @tag :p3_fetch_launch_bounds
  test "Fetch launch admission times out without launching its waiting owner" do
    {tracker, latch} = RequestLifecycle.start()
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    :sys.suspend(tracker)
    parent = self()

    {caller, caller_down} =
      spawn_monitor(fn ->
        receive do
          :start ->
            result =
              HTTP.SocketClient.request(%HTTP.Request{
                url: URI.parse("http://127.0.0.1:1/never"),
                transport_options: [
                  http_version: :h2c,
                  request_lifecycle: tracker,
                  timeout: 30
                ]
              })

            send(parent, {:launch_result, result})
        end
      end)

    :erlang.trace(caller, true, [:send])
    send(caller, :start)

    try do
      assert_receive {:trace, ^caller, :send, {:"$gen_call", _from, {:register, owner, :owner}},
                      ^tracker},
                     1_000

      owner_down = Process.monitor(owner)
      assert_receive {:launch_result, {:error, :request_timeout}}, 200
      assert_receive {:DOWN, ^caller_down, :process, ^caller, :normal}, 200
      assert_receive {:DOWN, ^owner_down, :process, ^owner, :normal}, 200
      refute_receive {:trace, ^caller, :send, :owner_launch, ^owner}, 0
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
    after
      if Process.alive?(caller), do: Process.exit(caller, :kill)
      :sys.resume(tracker)
    end

    assert :ok = RequestCompletion.await(completion, 1_000)
  end

  @tag :p3_provider_control
  test "zero-deadline stream attachment retains a known-created suspended resource" do
    {tracker, latch} = RequestLifecycle.start()
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    {:ok, stream} = HTTP.Stream.start_link(0)
    :erlang.suspend_process(stream)
    stream_down = Process.monitor(stream)
    parent = self()

    {worker, worker_down} =
      spawn_monitor(fn ->
        RequestLifecycle.enter(tracker, :owner)

        result =
          RequestLifecycle.attach_stream(tracker, stream, System.monotonic_time(:millisecond))

        send(parent, {:attachment_result, result})
        RequestLifecycle.complete(tracker, :infinity)
      end)

    try do
      assert_receive {:attachment_result, {:error, :request_timeout}}, 1_000
      assert_receive {:DOWN, ^worker_down, :process, ^worker, :normal}, 200
      assert Process.alive?(stream)
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 20)
    after
      :erlang.resume_process(stream)
    end

    assert_receive {:DOWN, ^stream_down, :process, ^stream, :normal}, 1_000
    assert :ok = RequestCompletion.await(completion, 1_000)
  end

  @tag :p3_provider_control
  test "infinite network setup still has a finite provider enrollment wait" do
    {tracker, latch} = RequestLifecycle.start()
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    parent = self()

    {worker, down} =
      spawn_monitor(fn ->
        RequestLifecycle.enter(tracker, :owner)
        send(parent, :provider_worker_ready)
        receive do: (:begin -> :ok)

        send(
          parent,
          {:provider_result, RequestLifecycle.begin_provider(tracker, :ex_ssl, :infinity)}
        )

        RequestLifecycle.complete(tracker, :infinity)
      end)

    assert_receive :provider_worker_ready, 1_000
    :sys.suspend(tracker)
    send(worker, :begin)

    try do
      assert_receive {:provider_result, {:error, :request_timeout}}, 1_200
      assert_receive {:DOWN, ^down, :process, ^worker, :normal}, 200
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
    after
      :sys.resume(tracker)
    end

    assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(completion, 1_000)
  end

  @tag :integration
  @tag :p3_provider_control
  test "HTTP/1 send enrollment timeout cannot launch late request bytes" do
    {server, url} =
      server(fn socket, parent ->
        send(parent, {:send_peer_result, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    {tracker, latch} = RequestLifecycle.start()
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    parent = self()
    token = make_ref()

    hook = fn blocked?, event, _ ->
      case event do
        {:in, {:"$gen_call", {owner, _}, {:register, resource, :send}}} when not blocked? ->
          send(parent, {:send_enrollment, owner, resource})
          receive do: ({:release_send, ^token} -> :ok)
          true

        _ ->
          blocked?
      end
    end

    :ok = :sys.install(tracker, {hook, false})

    task =
      Task.async(fn ->
        HTTP.SocketClient.request(%HTTP.Request{
          url: URI.parse(url),
          transport_options: [request_lifecycle: tracker, timeout: 500]
        })
      end)

    assert_receive {:send_enrollment, owner, resource}, 1_000
    owner_down = Process.monitor(owner)
    resource_down = Process.monitor(resource)

    try do
      assert_receive {:DOWN, ^owner_down, :process, ^owner, :normal}, 800
      assert_receive {:DOWN, ^resource_down, :process, ^resource, :normal}, 200
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
      assert_receive {:send_peer_result, {:error, :closed}}, 200
    after
      send(tracker, {:release_send, token})
    end

    assert {:error, :request_timeout} = Task.await(task, 1_000)
    assert :ok = RequestCompletion.await(completion, 1_000)
    assert :ok = Task.await(server, 1_000)
  end

  @tag :integration
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

  @tag :integration
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

  @tag :integration
  test "ExSSL cancellation joins TCP and provider cleanup" do
    {server, url} =
      server(fn socket, parent ->
        {:ok, _client_hello} = :gen_tcp.recv(socket, 0, 2_000)
        send(parent, :handshake_started)
        send(parent, {:handshake_closed, :gen_tcp.recv(socket, 0, 2_000)})
      end)

    promise =
      HTTP.fetch(String.replace(url, "http:", "https:"),
        tls_backend: :ex_ssl,
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

  @tag :integration
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

  @tag :integration
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

  @tag :integration
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
          [http_version: :http3],
          [http_version: :auto],
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

  defp provider_request do
    {tracker, latch} = RequestLifecycle.start()
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    parent = self()

    owner =
      spawn(fn ->
        RequestLifecycle.enter(tracker, :owner)
        {:ok, {handle, _lease}} = RequestLifecycle.begin_provider(tracker, :ex_ssl, :infinity)
        send(parent, {:provider_ready, self(), handle})

        receive do
          :complete -> RequestLifecycle.complete(tracker)
        end
      end)

    on_exit(fn ->
      send(owner, :complete)
      RequestCompletion.abort_and_await(completion, 1_000)
    end)

    assert_receive {:provider_ready, ^owner, handle}, 1_000
    {completion, owner, handle}
  end

  defp provider_deadline(timeout), do: {:abs_ms, System.monotonic_time(:millisecond) + timeout}
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

    assert_raise ArgumentError, ~r/unsupported tls_backend/, fn ->
      HTTP.FetchOptions.new(redirect: :manual, tls_backend: "ssl")
    end
  end
end

defmodule HTTP.UploadFinalizationWireTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.{Promise, RequestCompletion, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @wait 4_000

  setup do
    previous = Application.fetch_env(:http_fetch, :streaming_timeout)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:http_fetch, :streaming_timeout, value)
        :error -> Application.delete_env(:http_fetch, :streaming_timeout)
      end
    end)

    :ok
  end

  for backend <- [:tcp, nil, :ex_ssl], streamed <- [false, true], chunks <- [[], ["ab", "cd"]] do
    test "#{backend} streamed=#{streamed} #{inspect(chunks)} confirms finalization before exposing response" do
      backend = unquote(backend)
      chunks = unquote(chunks)
      {peer, url} = peer(backend, Enum.join(chunks))
      {source, producer, gate} = source(chunks)
      monitors = watch([source, producer])
      controller = HTTP.AbortController.new()

      promise =
        fetch(url, backend, source, byte_size(Enum.join(chunks)),
          signal: controller,
          stream_response: unquote(streamed)
        )

      assert_receive {:finalizer_entered, ^producer, ^gate}, @wait
      assert_receive {:response_sent, peer_pid}, @wait
      assert peer_pid == peer.pid
      owner = Agent.get(controller, & &1.request_id)
      monitors = watch([owner]) ++ monitors
      await_completion_wait(owner, promise)
      assert Process.alive?(producer)
      assert Task.yield(promise.task, 0) == nil
      send(producer, {:release, gate})
      assert_receive {:source_closed, ^producer, ^gate}, @wait
      assert %Response{status: 200} = response = Promise.await(promise, @wait)
      assert Response.read_all(response) == "ok"
      await_down(monitors)
      finish(peer, promise, backend)
    end
  end

  for backend <- [:tcp, nil, :ex_ssl], outcome <- [:raise, :throw, :exit] do
    test "#{backend} finalizer #{outcome} fails despite an immediate HTTP 200" do
      backend = unquote(backend)
      {peer, url} = peer(backend, "abcd")
      {source, producer, gate} = source(["abcd"], unquote(outcome))
      controller = HTTP.AbortController.new()
      promise = fetch(url, backend, source, 4, signal: controller)
      assert_receive {:finalizer_entered, ^producer, ^gate}, @wait
      assert_receive {:response_sent, _}, @wait
      await_completion_wait(Agent.get(controller, & &1.request_id), promise)
      send(producer, {:release, gate})

      assert_finalizer_failure(Promise.await(promise, @wait), unquote(outcome))

      finish(peer, promise, backend)
    end
  end

  for backend <- [:tcp, nil, :ex_ssl],
      outcome <- [:timeout, :cancel, :deadline, :owner_down, :reader_down] do
    test "#{backend} blocked finalizer #{outcome} remains bounded and never succeeds" do
      backend = unquote(backend)
      outcome = unquote(outcome)
      Application.put_env(:http_fetch, :streaming_timeout, 2_000)
      {peer, url} = peer(backend, "abcd")
      {source, producer, gate} = source(["abcd"])
      source_monitor = Process.monitor(source)
      producer_monitor = Process.monitor(producer)
      controller = HTTP.AbortController.new()

      extra = interruption_options(outcome)

      promise = fetch(url, backend, source, 4, Keyword.put(extra, :signal, controller))
      assert_receive {:finalizer_entered, ^producer, ^gate}, @wait
      assert_receive {:response_sent, _}, @wait
      owner = Agent.get(controller, & &1.request_id)
      owner_monitor = Process.monitor(owner)
      await_completion_wait(owner, promise)

      expected = interrupt(outcome, controller, owner)

      assert {:error, ^expected} = Promise.await(promise, 1_500)
      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _}, @wait
      assert_receive {:DOWN, ^source_monitor, :process, ^source, _}, @wait
      assert_receive {:DOWN, ^producer_monitor, :process, ^producer, _}, @wait
      refute_receive {:source_closed, ^producer, ^gate}, 0
      completion = completion_result(outcome)
      finish(peer, promise, backend, completion)
    end
  end

  for backend <- [:tcp, nil, :ex_ssl] do
    test "#{backend} completed writes leave a longer source finalizer independent of write idle" do
      backend = unquote(backend)
      Application.put_env(:http_fetch, :streaming_timeout, 2_000)
      {peer, url} = peer(backend, "abcd")
      {source, producer, gate} = source(["abcd"])
      monitors = watch([source, producer])
      controller = HTTP.AbortController.new()

      promise =
        fetch(url, backend, source, 4,
          signal: controller,
          write_idle_timeout: 100,
          socket_opts: [send_timeout: 100]
        )

      assert_receive {:finalizer_entered, ^producer, ^gate}, @wait
      assert_receive {:response_sent, _}, @wait
      owner = Agent.get(controller, & &1.request_id)
      monitors = watch([owner]) ++ monitors
      await_completion_wait(owner, promise)
      # The gate stays closed beyond both socket-only budgets; no socket send
      # remains pending, and only local finalization is allowed to progress.
      refute_receive {:source_closed, ^producer, ^gate}, 250
      assert Task.yield(promise.task, 0) == nil
      send(producer, {:release, gate})
      assert_receive {:source_closed, ^producer, ^gate}, @wait
      assert %Response{status: 200} = Promise.await(promise, @wait)
      await_down(monitors)
      finish(peer, promise, backend)
    end
  end

  for backend <- [:tcp, nil, :ex_ssl], mismatch <- [:underflow, :overflow] do
    test "#{backend} #{mismatch} retains length validation and emits no extra payload" do
      backend = unquote(backend)
      mismatch = unquote(mismatch)
      {chunks, expected, overflow?} = mismatch_source(mismatch)
      {peer, url} = peer(backend, expected, 4, overflow?)
      {source, producer, gate} = source(chunks, :release, overflow?)
      promise = fetch(url, backend, source, 4)
      assert_receive {:payload_received, _}, @wait
      release_mismatch_source(overflow?, producer, gate)
      assert {:error, :content_length_mismatch} = Promise.await(promise, @wait)
      finish(peer, promise, backend)
    end
  end

  for backend <- [:tcp, nil, :ex_ssl], interruption <- [:abort, :deadline] do
    test "#{backend} queued #{interruption} wins over confirmed finalization before response publication" do
      backend = unquote(backend)
      {peer, url} = peer(backend, "abcd")
      {source, producer, gate} = source(["abcd"])
      controller = HTTP.AbortController.new()
      promise = fetch(url, backend, source, 4, signal: controller)
      assert_receive {:finalizer_entered, ^producer, ^gate}, @wait
      assert_receive {:response_sent, _}, @wait
      owner = Agent.get(controller, & &1.request_id)
      await_completion_wait(owner, promise)
      {:links, links} = Process.info(owner, :links)
      worker = Enum.find(links, &upload_worker?/1)
      assert is_pid(worker)
      :erlang.trace(worker, true, [:send])
      :erlang.suspend_process(owner)

      try do
        send(producer, {:release, gate})
        assert_receive {:source_closed, ^producer, ^gate}, @wait
        assert_receive {:trace, ^worker, :send, {:http1_upload, _, :ok}, ^owner}, @wait
        send(owner, unquote(interruption))
      after
        :erlang.resume_process(owner)
      end

      expected = interruption_reason(unquote(interruption))
      assert {:error, ^expected} = Promise.await(promise, @wait)
      finish(peer, promise, backend)
    end
  end

  defp interruption_reason(:abort), do: :aborted
  defp interruption_reason(:deadline), do: :request_timeout

  defp watch(pids), do: Enum.map(pids, &{&1, Process.monitor(&1)})

  defp await_down(monitors) do
    for {pid, monitor} <- monitors do
      assert_receive {:DOWN, ^monitor, :process, ^pid, _}, @wait
    end
  end

  defp assert_finalizer_failure(result, :raise) do
    assert {:error, %RuntimeError{message: "source validation failed"}} = result
  end

  defp assert_finalizer_failure(result, kind) do
    assert {:error, {:source_failure, ^kind, :source_validation_failed}} = result
  end

  defp interruption_options(:timeout) do
    Application.put_env(:http_fetch, :streaming_timeout, 500)
    []
  end

  defp interruption_options(:deadline), do: [timeout: 500]
  defp interruption_options(_), do: []

  defp interrupt(:cancel, controller, _owner) do
    HTTP.AbortController.abort(controller)
    :aborted
  end

  defp interrupt(:owner_down, _controller, owner) do
    Process.exit(owner, :kill)
    {:request_process_down, :killed}
  end

  defp interrupt(:reader_down, _controller, owner) do
    {:links, links} = Process.info(owner, :links)
    reader = Enum.find(links, &upload_worker?/1)
    assert is_pid(reader)
    Process.exit(reader, :kill)
    {:request_process_down, :killed}
  end

  defp interrupt(:deadline, _, _), do: :request_timeout
  defp interrupt(:timeout, _, _), do: :timeout

  defp completion_result(outcome) when outcome in [:owner_down, :reader_down], do: :unconfirmed
  defp completion_result(_), do: :ok

  defp mismatch_source(:overflow), do: {["abcd", "extra"], "abcd", true}
  defp mismatch_source(:underflow), do: {["abc"], "abc", false}

  defp release_mismatch_source(true, producer, gate) do
    assert_receive {:response_sent, _}, @wait
    send(producer, {:emit_extra, gate})
  end

  defp release_mismatch_source(false, producer, gate) do
    assert_receive {:finalizer_entered, ^producer, ^gate}, @wait
    send(producer, {:release, gate})
  end

  defp upload_worker?(pid) when is_pid(pid) do
    case Process.info(pid, :current_stacktrace) do
      {:current_stacktrace, stack} ->
        Enum.any?(stack, fn {mod, _, _, _} -> mod == HTTP.HTTP1.Upload end)

      nil ->
        false
    end
  end

  defp upload_worker?(_), do: false

  defp source(chunks, outcome \\ :release, gate_extra? \\ false) do
    parent = self()
    gate = make_ref()

    enumerable =
      Stream.resource(
        fn ->
          send(parent, {:source_started, self()})
          chunks
        end,
        fn
          [] ->
            {:halt, []}

          [chunk | rest] ->
            if gate_extra? and chunk == "extra" do
              receive do
                {:emit_extra, ^gate} -> :ok
              end
            end

            {[chunk], rest}
        end,
        fn _ ->
          send(parent, {:finalizer_entered, self(), gate})

          receive do
            {:release, ^gate} -> :ok
          end

          case outcome do
            :release -> send(parent, {:source_closed, self(), gate})
            :raise -> raise "source validation failed"
            :throw -> throw(:source_validation_failed)
            :exit -> exit(:source_validation_failed)
          end
        end
      )

    {:ok, stream} = HTTP.Stream.from_enumerable(enumerable, telemetry: false)
    assert_receive {:source_started, producer}, @wait

    on_exit(fn ->
      if Process.alive?(stream), do: HTTP.Stream.stop(stream, :aborted)
      if Process.alive?(producer), do: Process.exit(producer, :kill)
    end)

    {stream, producer, gate}
  end

  # The peer really sent its immediate response, and the owner must actually
  # enter its completion barrier while the source finalizer remains gated.
  # Scheduler turns alone are never treated as evidence of that barrier.
  defp await_completion_wait(owner, promise, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + @wait

    case Process.info(owner, :current_stacktrace) do
      {:current_stacktrace, stack} ->
        if Enum.any?(stack, fn {mod, fun, _, _} ->
             mod == HTTP.SocketClient and fun == :await_http1_upload_completion
           end) do
          :ok
        else
          assert Task.yield(promise.task, 0) == nil,
                 "request exposed a response before source finalization"

          assert System.monotonic_time(:millisecond) < deadline,
                 "owner never entered the upload completion barrier"

          receive do
          after
            1 -> await_completion_wait(owner, promise, deadline)
          end
        end

      nil ->
        flunk("request owner stopped before source finalization")
    end
  end

  defp fetch(url, backend, source, length, extra \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          method: :put,
          body: source,
          duplex: :half,
          headers: [{"content-length", Integer.to_string(length)}],
          http_version: :http1,
          redirect: :manual,
          decode_body: false,
          timeout: :infinity,
          connect_timeout: 3_000,
          telemetry: false,
          tls_backend: if(backend == :tcp, do: nil, else: backend),
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
        ],
        extra
      )
    )
  end

  defp peer(backend, expected, declared \\ nil, respond? \\ true) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)
    parent = self()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, @wait)
        {transport, socket} = handshake(backend, tcp)
        headers = headers(transport, socket, "")
        assert headers =~ "Content-Length: #{declared || byte_size(expected)}\r\n"
        assert recv_exact(transport, socket, byte_size(expected)) == expected
        send(parent, {:payload_received, self()})

        if respond? do
          :ok =
            transport.send(
              socket,
              "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )

          send(parent, {:response_sent, self()})
        end

        assert {:error, reason} = transport.recv(socket, 0, @wait)
        assert reason in [:closed, :econnreset]
        transport.close(socket)
        :ok
      end)

    on_exit(fn ->
      if Process.alive?(task.pid), do: Process.exit(task.pid, :kill)
      :gen_tcp.close(listener)
    end)

    scheme = if backend == :tcp, do: "http", else: "https"
    {task, "#{scheme}://localhost:#{port}/upload"}
  end

  defp handshake(:tcp, socket), do: {:gen_tcp, socket}

  defp handshake(_backend, socket) do
    {:ok, tls} =
      :ssl.handshake(
        socket,
        [
          certfile: Path.join(@fixtures, "localhost.pem"),
          keyfile: Path.join(@fixtures, "localhost.key"),
          active: false
        ],
        @wait
      )

    {:ssl, tls}
  end

  defp headers(transport, socket, bytes) do
    if String.ends_with?(bytes, "\r\n\r\n"),
      do: bytes,
      else: headers(transport, socket, bytes <> recv_exact(transport, socket, 1))
  end

  defp recv_exact(_transport, _socket, 0), do: ""

  defp recv_exact(transport, socket, length) do
    assert {:ok, bytes} = transport.recv(socket, length, @wait)
    bytes
  end

  defp finish(peer, promise, _backend, completion \\ :ok) do
    assert Task.await(peer, @wait) == :ok

    expected =
      if completion == :unconfirmed, do: {:error, :cleanup_unconfirmed}, else: :ok

    assert RequestCompletion.await(Promise.completion(promise), @wait) == expected
  end
end

defmodule HTTP.HTTP1CancellationRaceTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.{Promise, RequestCompletion}

  # Interpose only the transport boundary, retaining the original transport
  # bodies and real sockets. This schedules a syscall; it does not fake its result.
  defmodule Gate do
    def around(module, operation, args, fun) do
      key = {__MODULE__, operation}

      case :persistent_term.get(__MODULE__, nil) do
        {test, ^module, mode} when mode in [:activation, :send_return, :send_failure] ->
          selected? =
            (mode == :activation and operation == :setopts and
               List.last(args) == [active: :once]) or
              (mode in [:send_return, :send_failure] and operation == :send)

          if selected? and not Process.get(key, false) do
            Process.put(key, true)
            run(test, mode, args, fun)
          else
            fun.()
          end

        _ ->
          fun.()
      end
    end

    defp run(test, :activation, _args, fun) do
      gate(test, nil)
      result = fun.()
      send(test, {:native_activation_result, result})
      result
    end

    defp run(test, :send_return, _args, fun) do
      result = fun.()
      gate(test, result)
      result
    end

    defp run(test, :send_failure, _args, fun) do
      gate(test, :before_send)
      result = fun.()
      gate(test, result)
      result
    end

    defp gate(test, result) do
      ref = make_ref()
      send(test, {:transport_gate, self(), ref, result})

      receive do
        {:release_transport, ^ref} -> :ok
      after
        5_000 -> raise "transport gate was not released"
      end
    end
  end

  setup_all do
    previous = Code.compiler_options(ignore_module_conflict: true)

    try do
      for module <- [HTTP.Transport.TCP, HTTP.Transport.SSL] do
        {^module, binary, filename} = :code.get_object_code(module)
        source = module.module_info(:compile)[:source] |> List.to_string()
        quoted = source |> File.read!() |> Code.string_to_quoted!()

        instrumented =
          Macro.postwalk(quoted, fn
            {:def, meta, [{operation, head_meta, args}, [do: body]]}
            when operation in [:send, :setopts] ->
              vars = Macro.generate_arguments(length(args), __MODULE__)
              head = Enum.zip_with(vars, args, fn var, arg -> {:=, [], [var, arg]} end)

              wrapped =
                quote do
                  unquote(Gate).around(
                    unquote(module),
                    unquote(operation),
                    unquote(vars),
                    fn -> unquote(body) end
                  )
                end

              {:def, meta, [{operation, head_meta, head}, [do: wrapped]]}

            ast ->
              ast
          end)

        on_exit(fn ->
          :code.purge(module)
          {:module, ^module} = :code.load_binary(module, filename, binary)
          :code.purge(module)
        end)

        [{^module, _binary}] = Code.compile_quoted(instrumented, source)
      end
    after
      Code.compiler_options(previous)
    end

    :ok
  end

  setup do
    on_exit(fn -> :persistent_term.erase(Gate) end)
    :ok
  end

  for backend <- [:tcp, :ssl] do
    test "#{backend}: public cancellation before post-send activation remains aborted" do
      backend = unquote(backend)
      transport = transport(backend)
      :persistent_term.put(Gate, {self(), transport, :activation})
      {peer, url} = peer(backend)

      promise =
        HTTP.fetch(url,
          http_version: :http1,
          http1_reuse: false,
          tls_backend: :ssl,
          ssl: [verify: :verify_none],
          redirect: :manual,
          decode_body: false,
          request_mode: :proxy,
          timeout: 4_000
        )

      completion = Promise.completion(promise)
      assert_receive {:transport_gate, owner, gate, nil}, 3_000
      assert_receive :complete_request_headers, 3_000
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)

      try do
        assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(completion, 0)
        assert_receive :peer_closed, 3_000
      after
        send(owner, {:release_transport, gate})
      end

      assert_receive {:native_activation_result, {:error, native_reason}}, 3_000
      assert native_reason in [:closed, :einval]
      assert :ok = RequestCompletion.await(completion, 3_000)
      assert {:error, :aborted} = Promise.await(promise, 3_000)
      join_peer(peer)
      assert :ok = RequestCompletion.await(completion, 0)
    end
  end

  for backend <- [:tcp, :ssl] do
    test "#{backend}: activation failure without cancellation preserves the native error" do
      backend = unquote(backend)
      :persistent_term.put(Gate, {self(), transport(backend), :activation})
      {peer, url} = peer(backend)
      promise = fetch(url)
      completion = Promise.completion(promise)
      assert_receive {:transport_gate, owner, gate, nil}, 3_000
      assert_receive :complete_request_headers, 3_000

      try do
        state = :sys.get_state(completion.tracker)

        tcp =
          Enum.find_value(state.resources, fn {_, {resource, kind}} ->
            if kind == :socket, do: resource
          end)

        :ok = :gen_tcp.close(tcp)
        assert_receive :peer_closed, 3_000
      after
        send(owner, {:release_transport, gate})
      end

      assert_receive {:native_activation_result, {:error, native_reason}}, 3_000
      assert native_reason in [:closed, :einval]
      assert {:error, ^native_reason} = Promise.await(promise, 3_000)
      assert :ok = RequestCompletion.await(completion, 3_000)
      join_peer(peer)
    end

    test "#{backend}: cancellation before final send result publication remains aborted" do
      backend = unquote(backend)
      :persistent_term.put(Gate, {self(), transport(backend), :send_return})
      {peer, url} = peer(backend)
      promise = fetch(url)
      completion = Promise.completion(promise)
      assert_receive {:transport_gate, _sender, _gate, :ok}, 3_000
      assert_receive :complete_request_headers, 3_000
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
      assert :ok = RequestCompletion.abort_and_await(completion, 3_000)
      assert {:error, :aborted} = Promise.await(promise, 3_000)
      assert_receive :peer_closed, 3_000
      join_peer(peer)
      assert :ok = RequestCompletion.await(completion, 0)
    end

    test "#{backend}: native send failure delivered before cancellation keeps its reason" do
      backend = unquote(backend)
      :persistent_term.put(Gate, {self(), transport(backend), :send_failure})
      {peer, url} = peer(backend, :unwritten)
      promise = fetch(url)
      completion = Promise.completion(promise)
      assert_receive {:transport_gate, sender, before_send, :before_send}, 3_000
      state = :sys.get_state(completion.tracker)

      tcp =
        Enum.find_value(state.resources, fn {_, {resource, kind}} ->
          if kind == :socket, do: resource
        end)

      :ok = :gen_tcp.close(tcp)
      send(sender, {:release_transport, before_send})
      assert_receive {:transport_gate, ^sender, gate, {:error, native_reason}}, 3_000
      assert native_reason in [:closed, :einval]

      owner =
        Enum.find_value(state.resources, fn {_, {resource, kind}} ->
          if kind == :owner, do: resource
        end)

      monitor = Process.monitor(sender)
      :erlang.suspend_process(owner)

      try do
        send(sender, {:release_transport, gate})
        assert_receive {:DOWN, ^monitor, :process, ^sender, :normal}, 3_000
        assert {:error, :cleanup_pending} = RequestCompletion.abort_and_await(completion, 0)
        :sys.get_state(completion.tracker)
      after
        :erlang.resume_process(owner)
      end

      assert {:error, ^native_reason} = Promise.await(promise, 3_000)
      assert :ok = RequestCompletion.await(completion, 3_000)
      assert_receive :peer_closed, 3_000
      join_peer(peer)
    end
  end

  test "a real parser failure settled before abort remains a protocol failure" do
    {peer, url} = peer(:tcp, :held)
    promise = fetch(url)
    completion = Promise.completion(promise)
    assert_receive :complete_request_headers, 3_000
    send(peer.pid, {:respond, "HTTP/1.1 INVALID\r\n\r\n"})
    assert {:error, :invalid_status_line} = Promise.await(promise, 3_000)
    assert :ok = RequestCompletion.abort_and_await(completion, 3_000)
    assert_receive :peer_closed, 3_000
    join_peer(peer)
  end

  test "lifecycle notifies the owner before closing an earlier-enumerated socket" do
    {peer, url} = peer(:tcp, :unwritten)
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", URI.parse(url).port, [:binary, active: false])
    test = self()

    # Explicit callback state makes socket-first enumeration deterministic.
    state = %{resources: %{0 => {socket, :socket}, 1 => {test, :owner}}, aborted?: false}

    worker =
      spawn(fn -> receive do: (:cancel -> HTTP.RequestLifecycle.handle_info(:abort, state)) end)

    :erlang.trace_pattern({:gen_tcp, :close, 1}, true, [:local])
    :erlang.trace(worker, true, [:send, :call])
    on_exit(fn -> :erlang.trace_pattern({:gen_tcp, :close, 1}, false, [:local]) end)
    send(worker, :cancel)
    assert_owner_notified_first(worker, test)
    assert_receive {:trace, ^worker, :call, {:gen_tcp, :close, [^socket]}}, 3_000
    assert_receive :peer_closed, 3_000
    join_peer(peer)
  end

  defp assert_owner_notified_first(worker, owner) do
    receive do
      {:trace, ^worker, :send, :abort, ^owner} -> :ok
      {:trace, ^worker, :call, {:gen_tcp, :close, _}} -> flunk("socket closed before owner abort")
      {:trace, ^worker, _, _, _} -> assert_owner_notified_first(worker, owner)
    after
      3_000 -> flunk("no owner cancellation trace")
    end
  end

  defp fetch(url, options \\ []) do
    HTTP.fetch(
      url,
      Keyword.merge(
        [
          http_version: :http1,
          http1_reuse: false,
          tls_backend: :ssl,
          ssl: [verify: :verify_none],
          redirect: :manual,
          decode_body: false,
          request_mode: :proxy,
          timeout: 4_000
        ],
        options
      )
    )
  end

  defp transport(:tcp), do: HTTP.Transport.TCP
  defp transport(:ssl), do: HTTP.Transport.SSL

  defp peer(backend, mode \\ :headers) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    test = self()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 3_000)
        {transport, socket} = handshake(backend, tcp)

        if mode != :unwritten do
          headers = recv_headers(transport, socket, "")
          assert headers =~ "/cancel HTTP/1.1\r\n"
          send(test, :complete_request_headers)
        end

        if mode == :held do
          receive do
            :drain_peer -> :ok
            {:respond, bytes} -> :ok = transport.send(socket, bytes)
          after
            5_000 -> raise "peer was not released"
          end
        end

        recv_closed(transport, socket)
        transport.close(socket)
        send(test, :peer_closed)
        :ok
      end)

    scheme = if backend == :tcp, do: "http", else: "https"
    {task, "#{scheme}://127.0.0.1:#{port}/cancel"}
  end

  defp handshake(:tcp, tcp), do: {:gen_tcp, tcp}

  defp handshake(:ssl, tcp) do
    fixtures = Path.expand("../support/fixtures", __DIR__)

    {:ok, socket} =
      :ssl.handshake(
        tcp,
        [
          certfile: Path.join(fixtures, "localhost.pem"),
          keyfile: Path.join(fixtures, "localhost.key"),
          active: false
        ],
        3_000
      )

    {:ssl, socket}
  end

  defp join_peer(peer) do
    monitor = Process.monitor(peer.pid)
    assert :ok = Task.await(peer, 3_000)
    assert_receive {:DOWN, ^monitor, :process, pid, reason} when pid == peer.pid, 3_000
    assert reason in [:normal, :noproc]
  end

  defp recv_closed(transport, socket) do
    case transport.recv(socket, 0, 3_000) do
      {:ok, _} -> recv_closed(transport, socket)
      {:error, reason} -> assert reason in [:closed, :econnreset]
    end
  end

  defp recv_headers(transport, socket, bytes) do
    if String.contains?(bytes, "\r\n\r\n") do
      bytes
    else
      {:ok, data} = transport.recv(socket, 1, 3_000)
      recv_headers(transport, socket, bytes <> data)
    end
  end
end

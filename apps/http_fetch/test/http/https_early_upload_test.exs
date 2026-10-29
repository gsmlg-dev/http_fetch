defmodule HTTP.HTTPSEarlyUploadTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.ManagedLifecycleProbe, as: Probe

  @fixtures Path.expand("../../../http_web_socket/test/support/fixtures", __DIR__)
  @timeout 5_000

  for backend <- [nil, :ex_ssl],
      version <- [:http1, :auto],
      outcome <- [:buffered, :streamed, :cancel, :deadline, :send_timeout, :owner_down],
      timeout <- [4_000, :infinity],
      not (outcome == :deadline and timeout == :infinity) do
    @tag tls_outcome: outcome

    test "#{backend} #{version} #{outcome} #{timeout} cleans up a verified HTTPS upload blocked in TLS send" do
      {url, peer} = if unquote(outcome) == :send_timeout, do: timeout_peer(), else: peer()

      {:ok, upload} =
        HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> :binary.copy("x", 65_536) end))

      source_monitor = Process.monitor(upload)
      controller = HTTP.AbortController.new()
      request_timeout = if unquote(outcome) == :deadline, do: 1_500, else: unquote(timeout)

      socket_opts =
        if unquote(outcome) == :send_timeout,
          # Each public send is bounded separately. Keep its deadline below the
          # ~200–500 ms loopback write progress observed with small BSD buffers.
          do: [sndbuf: 1_024, send_timeout: 150],
          else: [sndbuf: 1_024]

      promise =
        HTTP.fetch(url,
          method: :post,
          redirect: :manual,
          body: upload,
          duplex: :half,
          signal: controller,
          http_version: unquote(version),
          tls_backend: unquote(backend),
          timeout: request_timeout,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          socket_opts: socket_opts
        )

      assert_receive {:peer_ready, ^peer}, @timeout
      owner = Agent.get(controller, & &1.request_id)
      owner_monitor = Process.monitor(owner)
      writer = blocked_writer(owner, System.monotonic_time(:millisecond) + 1_000)

      provider = pending_tls_output(promise, owner, System.monotonic_time(:millisecond) + 1_000)

      writer_monitor = Process.monitor(writer)
      started = System.monotonic_time(:millisecond)

      case unquote(outcome) do
        :buffered ->
          send(peer, {:response, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n"})
          assert %HTTP.Response{status: 413} = HTTP.Promise.await(promise, 1_000)

        :streamed ->
          send(
            peer,
            {:response, "HTTP/1.1 413 Payload Too Large\r\nTransfer-Encoding: chunked\r\n\r\n"}
          )

          response = HTTP.Promise.await(promise, 1_000)
          assert response.status == 413
          refute Process.alive?(upload)
          assert Process.alive?(owner)
          send(peer, {:response, "4\r\nstop\r\n0\r\n\r\n"})
          assert HTTP.Response.read_all(response) == "stop"

        :cancel ->
          send(
            peer,
            {:response, "HTTP/1.1 413 Payload Too Large\r\nTransfer-Encoding: chunked\r\n\r\n"}
          )

          response = HTTP.Promise.await(promise, 1_000)
          reader = response.stream
          send(reader, {:read_chunk, self(), :ack})
          HTTP.AbortController.abort(controller)
          assert_receive {:stream_error, ^reader, :aborted}, 1_000

        :deadline ->
          assert {:error, :request_timeout} = HTTP.Promise.await(promise, 2_000)

        :send_timeout ->
          # The native send timeout must settle before the request deadline.
          assert {:error, reason} = HTTP.Promise.await(promise, 2_000)

          assert reason == :timeout

        :owner_down ->
          Process.exit(owner, :kill)
          assert {:error, {:request_process_down, :killed}} = HTTP.Promise.await(promise, 1_000)
      end

      assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000
      assert_receive {:DOWN, ^source_monitor, :process, ^upload, :normal}, 1_000
      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _}, 1_000

      if provider do
        assert_receive {:DOWN, monitor, :process, connection, _}
                       when monitor == provider.connection_monitor and
                              connection == provider.connection,
                       1_000

        assert_receive {:DOWN, monitor, :process, writer, _}
                       when monitor == provider.writer_monitor and writer == provider.writer,
                       1_000

        if Map.has_key?(provider, :handle) do
          assert_receive {:DOWN, monitor, :socket, tcp, _}
                         when monitor == provider.monitors.tcp and tcp == provider.tcp,
                         1_000

          assert {:ok, %{cleanup: :confirmed}} =
                   SSL.Lifecycle.await(
                     provider.handle,
                     {:abs_ms, System.monotonic_time(:millisecond) + 1_000}
                   )

          Probe.await_down(provider, [:observer], 1_000)
          Probe.release_monitors(provider)
        else
          assert Port.info(provider.tcp) == nil
        end
      end

      if unquote(version) == :http1 do
        completion = HTTP.Promise.completion(promise)

        expected =
          if unquote(outcome) == :owner_down, do: {:error, :cleanup_unconfirmed}, else: :ok

        assert HTTP.RequestCompletion.await(completion, 1_000) == expected
      end

      if unquote(outcome) != :deadline,
        do: assert(System.monotonic_time(:millisecond) - started < 1_000)

      send(peer, :drain)
      assert_receive {:peer_closed, ^peer}, 3_000
    end
  end

  defp blocked_writer(owner, deadline) do
    {:links, links} = Process.info(owner, :links)

    writer =
      Enum.find(Enum.filter(links, &is_pid/1), fn pid ->
        case Process.info(pid, :current_stacktrace) do
          {:current_stacktrace, stack} ->
            Enum.any?(stack, fn {mod, _, _, _} -> mod == HTTP.HTTP1.Upload end) and
              Enum.any?(stack, fn {mod, function, _, _} ->
                function in [:call, :send] and
                  mod in [:ssl_gen_statem, :ssl, :gen_statem, :gen, GenServer, SSL.Connection]
              end)

          _ ->
            false
        end
      end)

    cond do
      writer ->
        writer

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("upload never blocked in TLS send")

      true ->
        receive do
        after
          1 -> blocked_writer(owner, deadline)
        end
    end
  end

  # Test-only TLS state evidence: the actual encrypted writer job must remain
  # blocked with nonzero inet output before the peer sends the first headers.
  defp pending_tls_output(%{completion: %{tracker: tracker}}, _owner, deadline)
       when is_pid(tracker) do
    assert System.monotonic_time(:millisecond) < deadline
    [handle] = Map.keys(:sys.get_state(tracker, 1_000).providers)
    graph = Probe.graph_handle(handle)
    on_exit(fn -> Probe.release_monitors(graph) end)
    :ok = Probe.await_native_blocked(graph, deadline)

    Map.merge(graph, %{
      connection_monitor: graph.monitors.connection,
      writer_monitor: graph.monitors.writer
    })
  end

  defp pending_tls_output(_promise, owner, deadline), do: pending_tls_output(owner, deadline)

  defp pending_tls_output(owner, deadline) do
    assert System.monotonic_time(:millisecond) < deadline

    candidate =
      Enum.find_value(DynamicSupervisor.which_children(SSL.ConnectionSupervisor), fn
        {_, pid, _, _} when is_pid(pid) ->
          try do
            case :sys.get_state(pid, 100) do
              {:connected, %{owner: ^owner, output: %{kind: :application}} = state} -> state
              _ -> nil
            end
          catch
            :exit, _ -> nil
          end

        _ ->
          nil
      end)

    if candidate do
      case :inet.getstat(candidate.tcp, [:send_pend]) do
        {:ok, [{:send_pend, bytes}]} when bytes > 0 ->
          token = candidate.output.token

          receive do
          after
            20 -> :ok
          end

          case :sys.get_state(candidate.socket.pid, 100) do
            {:connected, %{output: %{token: ^token}}} ->
              %{
                connection: candidate.socket.pid,
                connection_monitor: Process.monitor(candidate.socket.pid),
                writer: candidate.writer,
                writer_monitor: Process.monitor(candidate.writer),
                tcp: candidate.tcp
              }

            _ ->
              pending_tls_output(owner, deadline)
          end

        _ ->
          receive do
          after
            1 -> pending_tls_output(owner, deadline)
          end
      end
    else
      receive do
      after
        1 -> pending_tls_output(owner, deadline)
      end
    end
  end

  defp timeout_peer do
    parent = self()

    peer =
      spawn_link(fn ->
        executable = System.find_executable("python3") || raise "python3 is required"
        script = Path.expand("../../../../scripts/https_early_upload_peer.py", __DIR__)

        port =
          Port.open({:spawn_executable, executable}, [
            :binary,
            :exit_status,
            :stderr_to_stdout,
            {:line, 16_384},
            {:args,
             [
               "-u",
               script,
               "--cert",
               Path.join(@fixtures, "localhost.pem"),
               "--key",
               Path.join(@fixtures, "localhost.key")
             ]}
          ])

        %{"kind" => "listen", "port" => number} = peer_event(port)
        send(parent, {:peer_port, self(), number})
        %{"kind" => "ready"} = peer_event(port)
        send(parent, {:peer_ready, self()})

        receive do
          :drain ->
            true = Port.command(port, "drain\n")
            %{"kind" => "closed"} = peer_event(port)

            receive do
              {^port, {:exit_status, 0}} -> :ok
              {^port, {:exit_status, status}} -> flunk("timeout peer exited with #{status}")
            after
              1_000 -> flunk("timeout peer did not terminate after closure")
            end

            send(parent, {:peer_closed, self()})
        after
          @timeout -> flunk("timeout peer was never permitted to drain")
        end
      end)

    assert_receive {:peer_port, ^peer, number}, @timeout
    {"https://localhost:#{number}/upload", peer}
  end

  defp peer_event(port) do
    receive do
      {^port, {:data, {:eol, line}}} -> JSON.decode!(line)
      {^port, {:data, {:noeol, _}}} -> flunk("oversized timeout peer event")
      {^port, {:exit_status, status}} -> flunk("timeout peer exited with #{status}")
    after
      @timeout -> flunk("timeout peer event deadline")
    end
  end

  defp peer do
    parent = self()

    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        reuseaddr: true,
        recbuf: 1_024,
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key")
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, @timeout)
        {:ok, socket} = :ssl.handshake(tcp, @timeout)
        headers(socket, "")
        # Prepare the bounded probe while the client is held at peer readiness.
        # Setting native options after client cleanup can race the TCP close.
        :ok = :ssl.setopts(socket, send_timeout: 100, send_timeout_close: false)
        send(parent, {:peer_ready, self()})
        serve(socket, parent)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)

    {"https://localhost:#{port}/upload", peer}
  end

  defp headers(socket, bytes) do
    if :binary.match(bytes, "\r\n\r\n") == :nomatch do
      {:ok, next} = :ssl.recv(socket, 0, @timeout)
      headers(socket, bytes <> next)
    end
  end

  defp serve(socket, parent) do
    receive do
      {:response, bytes} ->
        :ok = :ssl.send(socket, bytes)
        serve(socket, parent)

      :drain ->
        deadline = System.monotonic_time(:millisecond) + 2_000
        probe_peer(socket, deadline)
        drain(socket, deadline)
        send(parent, {:peer_closed, self()})
    after
      @timeout -> :ssl.close(socket)
    end
  end

  # Test-only OTP reference introspection; never inspect keys, buffers or messages.
  defp peer_state({:sslsocket, tcp, receiver, sender, :gen_tcp, _, _, _}) do
    %{
      socket: :inet.getopts(tcp, [:active, :buffer, :recbuf]),
      counters: :inet.getstat(tcp, [:recv_oct, :send_oct, :send_pend]),
      receiver: Process.info(receiver, [:status, :current_function, :message_queue_len]),
      sender: Process.info(sender, [:status, :current_function, :message_queue_len])
    }
  end

  defp peer_state(_), do: :unsupported_reference_layout

  # The test joins every original local resource before permitting this peer
  # observation. A successful probe send does not establish terminal receive.
  defp probe_peer(socket, drain_deadline) do
    parent = self()
    token = make_ref()
    probe_deadline = min(drain_deadline, System.monotonic_time(:millisecond) + 100)

    {worker, monitor} =
      spawn_monitor(fn ->
        remaining = max(probe_deadline - System.monotonic_time(:millisecond), 0)

        result =
          if remaining == 0 do
            {:error, :timeout}
          else
            :ssl.send(socket, <<0>>)
          end

        send(parent, {token, result})
      end)

    result =
      receive do
        {^token, result} ->
          result

        {:DOWN, ^monitor, :process, ^worker, reason} ->
          flunk("HTTPS peer probe died: #{inspect(reason)}")
      after
        max(probe_deadline - System.monotonic_time(:millisecond), 0) ->
          # The observation has failed; only now stop and join this owned helper.
          Process.exit(worker, :kill)
          assert_receive {:DOWN, ^monitor, :process, ^worker, _}, 1_000
          flunk("HTTPS peer probe exceeded its original drain budget")
      end

    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal},
                   max(probe_deadline - System.monotonic_time(:millisecond), 0)

    assert result in [:ok, {:error, :closed}, {:error, :econnreset}],
           "HTTPS peer probe failed: #{inspect(result)}"
  end

  defp drain(socket, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    assert remaining > 0, "HTTPS peer exhausted original drain budget"

    case :ssl.recv(socket, 0, remaining) do
      {:ok, _} ->
        drain(socket, deadline)

      {:error, :timeout} ->
        flunk("HTTPS peer still open after local cleanup: #{inspect(peer_state(socket))}")

      {:error, _} ->
        :ok
    end
  end
end

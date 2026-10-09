defmodule HTTP.HTTPSEarlyUploadTest do
  use ExUnit.Case, async: false

  @fixtures Path.expand("../../../http_web_socket/test/support/fixtures", __DIR__)
  @timeout 5_000

  for backend <- [:ssl, :ex_ssl],
      outcome <- [:buffered, :streamed, :cancel, :deadline, :send_timeout, :owner_down] do
    if backend == :ssl and outcome == :buffered, do: @tag(:tls_repro)

    test "#{backend} #{outcome} cleans up a verified HTTPS upload blocked in TLS send" do
      {url, peer} = peer()

      {:ok, upload} =
        HTTP.Stream.from_enumerable(Stream.repeatedly(fn -> :binary.copy("x", 65_536) end))

      source_monitor = Process.monitor(upload)
      controller = HTTP.AbortController.new()
      request_timeout = if unquote(outcome) == :deadline, do: 1_500, else: 4_000

      socket_opts =
        if unquote(outcome) == :send_timeout,
          do: [sndbuf: 1_024, send_timeout: 600],
          else: [sndbuf: 1_024]

      promise =
        HTTP.fetch(url,
          method: :post,
          body: upload,
          duplex: :half,
          signal: controller,
          http_version: :http1,
          tls_backend: unquote(backend),
          timeout: request_timeout,
          ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")],
          socket_opts: socket_opts
        )

      assert_receive {:peer_ready, ^peer}, @timeout
      owner = Agent.get(controller, & &1.request_id)
      owner_monitor = Process.monitor(owner)
      writer = blocked_writer(owner, System.monotonic_time(:millisecond) + 1_000)

      if unquote(backend) == :ex_ssl do
        pending_tls_output(owner, System.monotonic_time(:millisecond) + 1_000)
      end

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
          # OTP closes its TLS connection on send_timeout_close; ExSSL reports
          # the send timeout directly. Neither is a request-deadline expiry.
          reason = if unquote(backend) == :ssl, do: :closed, else: :timeout
          assert {:error, ^reason} = HTTP.Promise.await(promise, 2_000)

        :owner_down ->
          Process.exit(owner, :kill)
          assert {:error, {:request_process_down, :killed}} = HTTP.Promise.await(promise, 1_000)
      end

      assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _}, 1_000
      assert_receive {:DOWN, ^source_monitor, :process, ^upload, :normal}, 1_000
      assert_receive {:DOWN, ^owner_monitor, :process, ^owner, _}, 1_000

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
            {:connected, %{output: %{token: ^token}}} -> :ok
            _ -> pending_tls_output(owner, deadline)
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
        drain(socket)
        send(parent, {:peer_closed, self()})
    after
      @timeout -> :ssl.close(socket)
    end
  end

  defp drain(socket) do
    case :ssl.recv(socket, 0, 2_000) do
      {:ok, _} -> drain(socket)
      {:error, :timeout} -> flunk("HTTPS socket remained open after confirmed request cleanup")
      {:error, _} -> :ok
    end
  end
end

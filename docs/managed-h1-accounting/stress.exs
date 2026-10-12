defmodule H1ControlStress do
  def run do
    root = File.cwd!()
    fixtures = Path.join(root, "apps/http_fetch/test/support/fixtures")

    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        active: false,
        reuseaddr: true,
        certfile: String.to_charlist(Path.join(fixtures, "localhost.pem")),
        keyfile: String.to_charlist(Path.join(fixtures, "localhost.key"))
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)
    parent = self()

    server =
      spawn(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
        {:ok, socket} = :ssl.handshake(tcp, 5_000)
        serve(socket, parent, 0)
      end)

    {:ok, scope} =
      HTTP.ManagedTransport.open(
        origin: "https://localhost:#{port}",
        connect_address: {127, 0, 0, 1},
        http_version: :http1,
        max_connections: 2,
        max_requests: 32,
        max_pending: 0,
        ssl: [cacertfile: Path.join(fixtures, "localhost-ca.pem"), verify: :verify_peer],
        socket_opts: [buffer: 8192, recbuf: 8192, sndbuf: 8192]
      )

    before = sample(scope)

    for _ <- 1..200 do
      promise = fetch(port, scope, "/short")
      %HTTP.Response{} = response = HTTP.Promise.await(promise, 5_000)
      "ok" = HTTP.Response.read_all(response)
      :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 5_000)
    end

    repeated = sample(scope)
    promise = fetch(port, scope, "/long")
    %HTTP.Response{} = response = HTTP.Promise.await(promise, 5_000)
    stream = response.stream
    send(stream, {:read_chunk, self(), :ack})

    for _ <- 1..1_000 do
      send(server, :next)

      receive do
        {:stream_chunk, ^stream, "x", ref} -> send(stream, {:stream_chunk_ack, ref})
      after
        5_000 -> raise "missing long-stream chunk"
      end
    end

    send(server, :finish)

    receive do
      {:stream_end, ^stream} -> :ok
    after
      5_000 -> raise "missing FIN"
    end

    :ok = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 5_000)
    long = sample(scope)
    {:ok, receipt} = HTTP.ManagedTransport.retire(scope)
    :ok = HTTP.ManagedTransport.await_retired(receipt, 5_000)
    retired = sample(nil)
    :ssl.close(listener)

    receive do
      {:requests, 201} -> :ok
    after
      5_000 -> raise "unexpected request count"
    end

    result = %{
      status: "PASS_EMPIRICAL_ONLY",
      requests: 201,
      long_request_chunks: 1_000,
      profile:
        "OTP TLS, H1, raw stream, manual redirect, 2 connections/32 requests/0 pending, buffers 8192",
      runtime: List.to_string(:erlang.system_info(:system_version)),
      local: %{before: before, repeated: repeated, long: long, retired: retired},
      limitations:
        "One process/allocator/RSS sample per phase; different patch runtime; no GC/native frontier or universal population theorem."
    }

    File.write!("/tmp/http-fetch-97-stress.json", JSON.encode!(result))
    IO.puts(JSON.encode!(result))
  end

  defp fetch(port, scope, path),
    do:
      HTTP.fetch("https://localhost:#{port}#{path}",
        transport_scope: scope,
        redirect: :manual,
        decode_body: false,
        stream_response: true,
        telemetry: false,
        timeout: 60_000
      )

  defp serve(socket, parent, count) do
    case :ssl.recv(socket, 0, 5_000) do
      {:ok, request} ->
        if String.starts_with?(request, "GET /long ") do
          :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
          chunks(socket)
        else
          :ok = :ssl.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        end

        serve(socket, parent, count + 1)

      {:error, :closed} ->
        send(parent, {:requests, count})
    end
  end

  defp chunks(socket) do
    receive do
      :next ->
        :ok = :ssl.send(socket, "1\r\nx\r\n")
        chunks(socket)

      :finish ->
        :ok = :ssl.send(socket, "0\r\n\r\n")
    after
      5_000 -> raise "missing next credit"
    end
  end

  defp sample(scope) do
    snapshot = if scope, do: elem(HTTP.ManagedTransport.snapshot(scope, 1_000), 1), else: nil

    pids =
      if scope,
        do: [scope.coordinator | Map.values(:sys.get_state(scope.coordinator).children)],
        else: []

    queues = Enum.map(pids, fn pid -> {pid, Process.info(pid, :message_queue_len)} end)

    allocator_used =
      :erlang.system_info({:allocator_sizes, :eheap_alloc}) |> inspect(limit: :infinity)

    %{
      processes: :erlang.system_info(:process_count),
      ports: :erlang.system_info(:port_count),
      binary_bytes: :erlang.memory(:binary),
      process_bytes: :erlang.memory(:processes),
      total_bytes: :erlang.memory(:total),
      rss:
        File.read!("/proc/self/status")
        |> String.split("\n")
        |> Enum.find(&String.starts_with?(&1, "VmRSS:")),
      control_mailboxes: inspect(queues),
      heap_allocator_sizes: allocator_used,
      snapshot: snapshot
    }
  end
end

H1ControlStress.run()

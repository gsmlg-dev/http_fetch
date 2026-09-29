# Run through the umbrella or a clean consumer with HTTP_FETCH_GATE_URL set.
url = System.fetch_env!("HTTP_FETCH_GATE_URL")

backend =
  case System.get_env("HTTP_FETCH_GATE_BACKEND", "ssl") do
    "ssl" -> :ssl
    "ex_ssl" -> :ex_ssl
  end

mode = System.get_env("HTTP_FETCH_GATE_MODE", "smoke")

ssl =
  if String.starts_with?(url, "https"),
    do: [cacertfile: System.fetch_env!("HTTP_FETCH_GATE_CA")],
    else: []

opts = [
  http_version: if(String.starts_with?(url, "https"), do: :http2, else: :h2c),
  http2_profile: :native_v1,
  tls_backend: backend,
  ssl: ssl,
  timeout: 60_000
]

fetch = fn path, extra ->
  case HTTP.fetch(url <> path, Keyword.merge(opts, extra)) |> HTTP.Promise.await(65_000) do
    %HTTP.Response{status: 200} = response -> HTTP.Response.read_all(response)
    other -> raise "unexpected fetch result: #{inspect(other)}"
  end
end

# Completion precedes coordinator cleanup; wait for the actual zero-reservation
# condition before measuring a quiescent pool, with a finite failure deadline.
settle = fn ->
  deadline = System.monotonic_time(:millisecond) + 5_000

  poll = fn poll ->
    stats = HTTP.HTTP2.Pool.stats(Process.whereis(:http_fetch_http2_pool))

    if Enum.all?(stats, fn {_, entry} -> entry.streams == 0 end) do
      stats
    else
      if System.monotonic_time(:millisecond) >= deadline, do: raise("leaked pool reservations")

      receive do
      after
        5 -> :ok
      end

      poll.(poll)
    end
  end

  poll.(poll)
end

snapshot = fn ->
  stats = settle.()
  owners = DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor)

  samples =
    for {_, pid, _, _} <- owners do
      status = HTTP.HTTP2.ConnectionOwner.status(pid)
      {:message_queue_len, messages} = Process.info(pid, :message_queue_len)
      {:memory, heap} = Process.info(pid, :memory)
      {:binary, binaries} = Process.info(pid, :binary)
      retained = Enum.sum(for {_, size, _} <- binaries, do: size)

      if status.active_streams != 0 or status.protocol_streams != 0 or
           status.pending_upload_bytes != 0 or
           status.buffered_receive_bytes != 0 or messages > 16 or heap > 8_388_608 or
           retained > 2_097_152,
         do: raise("owner resource bound exceeded: #{inspect(status)}")

      %{
        mailbox: messages,
        heap_bytes: heap,
        binary_bytes: retained,
        protocol_streams: status.protocol_streams,
        active_streams: status.active_streams
      }
    end

  if map_size(stats) > 1 or length(owners) > 4, do: raise("pool resource bound exceeded")

  %{
    pool_keys: map_size(stats),
    owners: samples,
    beam_memory: :erlang.memory(:total),
    process_count: :erlang.system_info(:process_count)
  }
end

started = System.monotonic_time(:millisecond)

case mode do
  "smoke" ->
    for n <- 1..3, do: ^n = String.to_integer(fetch.("/#{n}", []) |> String.trim_leading("/"))

  "reuse" ->
    count = String.to_integer(System.get_env("HTTP_FETCH_GATE_COUNT", "10000"))

    for n <- 1..count do
      expected = "/reuse/#{n}"
      ^expected = fetch.(expected, [])
    end

  "transfer" ->
    size = 10 * 1024 * 1024
    bytes = :binary.copy("x", size)
    expected = "#{size}:#{Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)}"
    ^expected = fetch.("/upload", method: :post, body: bytes)

    for chunk_size <- [1024, 16384, 65536] do
      chunks =
        Stream.repeatedly(fn -> :binary.copy("x", chunk_size) end)
        |> Stream.take(div(size, chunk_size))

      {:ok, stream} = HTTP.Stream.from_enumerable(chunks)
      ^expected = fetch.("/upload", method: :post, body: stream, duplex: "half")
    end

    ^bytes = fetch.("/bytes/#{size}", [])

  "soak" ->
    duration = String.to_integer(System.get_env("HTTP_FETCH_GATE_SECONDS", "1800")) * 1_000
    deadline = started + duration
    # Deterministic sizes and operation sequence make workload reproduction exact.
    run = fn run, batch, baseline ->
      1..16
      |> Task.async_stream(
        fn n ->
          size = 1024 * (1 + rem(batch * 17 + n * 31, 128))
          bytes = :binary.copy("x", size)

          case rem(n, 3) do
            0 ->
              ^bytes = fetch.("/bytes/#{size}", [])

            1 ->
              expected = "#{size}:#{Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)}"
              ^expected = fetch.("/upload", method: :post, body: bytes)

            2 ->
              {:ok, stream} =
                HTTP.Stream.from_enumerable(
                  Stream.chunk_every(:binary.bin_to_list(bytes), 16_384)
                  |> Stream.map(&:erlang.list_to_binary/1)
                )

              expected = "#{size}:#{Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)}"
              ^expected = fetch.("/upload", method: :post, body: stream, duplex: "half")
          end

          :ok
        end,
        max_concurrency: 16,
        timeout: 65_000
      )
      |> Enum.each(fn {:ok, :ok} -> :ok end)

      sample = snapshot.()
      baseline = baseline || sample

      if sample.beam_memory > baseline.beam_memory + 134_217_728 or
           sample.process_count > baseline.process_count + 64,
         do: raise("soak global resource tolerance exceeded")

      if rem(batch, 100) == 0 do
        IO.puts(
          JSON.encode!(
            Map.merge(sample, %{
              gate: "soak_sample",
              batch: batch,
              elapsed_ms: System.monotonic_time(:millisecond) - started
            })
          )
        )
      end

      if System.monotonic_time(:millisecond) < deadline,
        do: run.(run, batch + 1, baseline),
        else:
          IO.puts(
            JSON.encode!(%{gate: "soak_workload", batches: batch, requests: batch * 16, seed: 0})
          )
    end

    run.(run, 1, nil)

  "concurrent" ->
    parent = self()
    slow_size = 6 * 1024 * 1024

    request = fn n, size ->
      case HTTP.fetch(url <> "/concurrent/#{n}/#{size}", opts) |> HTTP.Promise.await(65_000) do
        %HTTP.Response{status: 200} = response ->
          "100" = HTTP.Headers.get(response.headers, "x-gate-barrier")
          response

        other ->
          raise "unexpected barrier result: #{inspect(other)}"
      end
    end

    slow =
      Task.async(fn ->
        response = request.(0, slow_size)
        true = is_pid(response.stream)
        send(parent, {:slow_response_ready, self()})

        receive do
          :release_slow -> :ok
        after
          65_000 -> raise "slow consumer was not released"
        end

        slow_body = :binary.copy("x", slow_size)
        ^slow_body = HTTP.Response.read_all(response)
        :ok
      end)

    fast =
      for n <- 1..99 do
        Task.async(fn ->
          size = 1000 + n * 97
          response = request.(n, size)
          expected = :binary.copy("x", size)
          ^expected = HTTP.Response.read_all(response)
          :ok
        end)
      end

    receive do
      {:slow_response_ready, pid} when pid == slow.pid -> :ok
    after
      65_000 -> raise "100-stream peer barrier was not reached"
    end

    Enum.each(fast, fn task -> :ok = Task.await(task, 65_000) end)
    true = Process.alive?(slow.pid)

    during = HTTP.HTTP2.Pool.stats(Process.whereis(:http_fetch_http2_pool))
    one = Enum.sum(for {_, entry} <- during, do: entry.connections)
    1 = one

    paused_owners =
      for {_, pid, _, _} <-
            DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor) do
        status = HTTP.HTTP2.ConnectionOwner.status(pid)
        {:message_queue_len, mailbox} = Process.info(pid, :message_queue_len)
        {:memory, heap_bytes} = Process.info(pid, :memory)

        %{
          active_streams: status.active_streams,
          buffered_receive_bytes: status.buffered_receive_bytes,
          mailbox: mailbox,
          heap_bytes: heap_bytes
        }
      end

    IO.puts(
      JSON.encode!(%{
        gate: "concurrent_barrier",
        distinct_requests: 100,
        peer_barrier_count: 100,
        fast_completed_while_slow_paused: 99,
        slow_streamed: true,
        slow_bytes: slow_size,
        connections_during_pause: one,
        reservations_during_pause: Enum.sum(for {_, entry} <- during, do: entry.streams),
        owners_during_pause: paused_owners
      })
    )

    send(slow.pid, :release_slow)
    :ok = Task.await(slow, 65_000)
end

stats = settle.()
IO.puts(JSON.encode!(Map.put(snapshot.(), :gate, "resource_snapshot")))

IO.puts(
  JSON.encode!(%{
    result: "PASS",
    mode: mode,
    backend: backend,
    elapsed_ms: System.monotonic_time(:millisecond) - started,
    otp: System.otp_release(),
    elixir: System.version(),
    pool_keys: map_size(stats),
    connections: Enum.sum(for {_, v} <- stats, do: v.connections),
    reservations: Enum.sum(for {_, v} <- stats, do: v.streams),
    beam_memory: :erlang.memory(:total)
  })
)

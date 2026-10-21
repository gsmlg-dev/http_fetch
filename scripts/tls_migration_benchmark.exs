# Run from the umbrella root (lead owns execution):
# MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build mix run --no-compile scripts/tls_migration_benchmark.exs
# Optional bounded env: TLS_BENCH_WARMUP=3 TLS_BENCH_SAMPLES=30 TLS_BENCH_REUSE_MS=1000
# TLS_BENCH_TIMEOUT_MS=3000 TLS_BENCH_CLEANUP_MS=300 TLS_BENCH_PYTHON=python3
# Output: one JSON object prefixed TLS_MIGRATION_BENCHMARK= (Mix/logger may also print).
defmodule TLSMigrationBenchmark do
  @payload :binary.copy("Z", 1_048_576)
  @root Path.expand("..", __DIR__)
  @fixtures Path.join(@root, "apps/http_web_socket/test/support/fixtures")

  def run do
    settings = %{
      warmup: setting("WARMUP", 3, 1, 10),
      samples: setting("SAMPLES", 30, 10, 100),
      reuse_ms: setting("REUSE_MS", 1_000, 200, 5_000),
      timeout_ms: setting("TIMEOUT_MS", 3_000, 500, 5_000),
      cleanup_ms: setting("CLEANUP_MS", 300, 50, 1_000)
    }

    python =
      System.find_executable(System.get_env("TLS_BENCH_PYTHON", "python3")) ||
        raise "python3 missing"

    peer =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 1_000_000},
        args: [
          Path.join(__DIR__, "tls_migration_benchmark_peer.py"),
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key")
        ]
      ])

    try do
      ready = peer_read(peer)
      "ready" = ready["event"]
      true = ready["payload_sha256"] == sha(@payload)
      # Both backend baselines and all observer snapshots retain this same peer port.
      results = Enum.map([:ssl, :ex_ssl], &backend(&1, peer, ready["port"], settings))
      final = peer_call(peer, "stats")
      [] = final["errors"]
      expected = 2 * (4 * (settings.warmup + settings.samples) + 3)
      ^expected = final["requests"]
      validate_counts!(final, settings)

      report = %{
        schema: "http-fetch-tls-p0-v1",
        recorded_at: DateTime.to_iso8601(DateTime.utc_now()),
        source: source(),
        runtime: %{
          elixir: System.version(),
          otp: List.to_string(:erlang.system_info(:otp_release)),
          erts: List.to_string(:erlang.system_info(:version)),
          architecture: List.to_string(:erlang.system_info(:system_architecture)),
          schedulers: :erlang.system_info(:schedulers_online),
          applications:
            Enum.into([:http_fetch, :http_core, :http_runtime, :ex_ssl], %{}, fn app ->
              {app, to_string(Application.spec(app, :vsn))}
            end)
        },
        settings:
          Map.merge(settings, %{
            payload_bytes: byte_size(@payload),
            tls: "TLS1.3",
            verify: "verify_peer",
            alpn: "http/1.1",
            session_tickets: "disabled at peer",
            order: ["ssl", "ex_ssl"],
            concurrency: 1,
            idle_timeout_ms: 10_000
          }),
        peer: ready,
        results: results,
        final_peer_counters: final,
        caveats: [
          "Cold request timing includes connect, TLS, HTTP and body verification; it is not isolated client handshake latency.",
          "Peer handshake timing is server wrap_socket duration, including client scheduling; warmup excluded in summary.",
          "Throughput is sequential 1MiB application goodput over reused H1, including response acknowledgement and body verification; not raw TLS bandwidth.",
          "VM memory is BEAM allocation, not RSS; global process/port snapshots are noisy observations, not provider cleanup receipts. No forced global GC.",
          "ExSSL public completion is unsupported at this baseline; observer deltas cannot establish public cleanup. Completion wait summaries include the time to return unsupported/pending results and are not uniformly cleanup latency.",
          "Small bounded sample p99 is a nearest-rank order statistic, not a confidence estimate. No promotion budget or pass threshold is inferred."
        ]
      }

      IO.puts("TLS_MIGRATION_BENCHMARK=" <> JSON.encode!(report))
    after
      if Port.info(peer) do
        Port.command(peer, JSON.encode!(%{command: "stop"}) <> "\n")

        receive do
          {^peer, {:exit_status, _}} -> :ok
        after
          3_500 -> if Port.info(peer), do: Port.close(peer)
        end
      end
    end
  end

  defp backend(backend, peer, port, settings) do
    baseline = snapshot()

    opts = [
      tls_backend: backend,
      http_version: :http1,
      redirect: :manual,
      telemetry: false,
      timeout: settings.timeout_ms,
      connect_timeout: settings.timeout_ms,
      ssl: [
        verify: :verify_peer,
        cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
        versions: [:"tlsv1.3"],
        alpn_advertised_protocols: ["http/1.1"]
      ],
      socket_opts: [nodelay: true]
    ]

    cold = workload(backend, "cold", "small", opts, peer, port, settings)
    upload = workload(backend, "upload", "upload", opts, peer, port, settings)
    download = workload(backend, "download", "download", opts, peer, port, settings)
    reuse = workload(backend, "reuse", "small", opts, peer, port, settings)

    %{
      backend: backend,
      baseline: baseline,
      cold: cold,
      upload: upload,
      download: download,
      long_lived_reuse: reuse,
      after_workloads: snapshot()
    }
  end

  defp workload(backend, name, operation, opts, peer, port, settings) do
    reuse? = name != "cold"
    scope = "tls-benchmark-#{backend}-#{name}"

    opts =
      Keyword.merge(opts,
        http1_reuse: reuse?,
        http1_scope: scope,
        http1_pool_size: 1,
        http1_idle_timeout: 10_000
      )

    before = snapshot()
    peer_before = peer_call(peer, "stats")
    count = settings.warmup + settings.samples

    samples =
      for index <- 1..count do
        sample = request(backend, name, operation, opts, port, settings)

        # Spread reuse requests over a bounded interval; sample VM during the same live connection.
        if name == "reuse", do: Process.sleep(div(settings.reuse_ms, count))
        resource = if name == "reuse", do: snapshot(), else: nil
        Map.merge(sample, %{index: index, resource: resource})
      end

    ids = Enum.map(samples, & &1.connection)

    if reuse?,
      do: true = length(Enum.uniq(ids)) == 1,
      else: true = length(Enum.uniq(ids)) == count

    measured = Enum.drop(samples, settings.warmup)
    live = snapshot()
    close = if reuse?, do: request(backend, name, "close", opts, port, settings), else: nil
    if close, do: true = close.connection == hd(ids)
    # A finite observer interval, retaining the external peer throughout. Never equate
    # count recovery or peer closure with a RequestCompletion receipt.
    observe_start = now()

    observations =
      for _ <- 1..3 do
        Process.sleep(div(settings.cleanup_ms, 3))
        %{elapsed_us: now() - observe_start, vm: snapshot(), peer: peer_call(peer, "stats")}
      end

    peer_after = peer_call(peer, "stats")
    [] = peer_after["errors"]
    handshakes = peer_after["handshakes"] |> Enum.drop(length(peer_before["handshakes"]))
    expected_handshakes = if reuse?, do: 1, else: count
    ^expected_handshakes = length(handshakes)

    true =
      Enum.all?(
        handshakes,
        &(&1["tls"] == "TLSv1.3" and &1["alpn"] == "http/1.1" and &1["resumed"] == false)
      )

    handshake_measurements =
      if reuse?,
        do: [],
        else:
          handshakes
          |> Enum.drop(settings.warmup)
          |> Enum.map(& &1["server_accept_to_handshake_us"])

    timings = Enum.map(measured, & &1.elapsed_us)

    bytes =
      if operation in ["upload", "download"], do: byte_size(@payload) * settings.samples, else: 0

    %{
      workload: name,
      warmup_count: settings.warmup,
      measured_count: settings.samples,
      latency_us: summary(timings),
      completion_wait_us: summary(Enum.map(measured, & &1.completion_wait_us)),
      samples: samples,
      server_handshake_us: summary(handshake_measurements),
      application_goodput_mib_s:
        if(bytes > 0, do: bytes / 1_048_576 / (Enum.sum(timings) / 1_000_000), else: nil),
      before: before,
      connection_live: live,
      close_response: close,
      observer_limit_ms: settings.cleanup_ms,
      observer_samples: observations,
      observer_is_public_cleanup: false,
      peer_before: peer_before,
      peer_after: peer_after
    }
  end

  defp request(backend, workload, operation, opts, port, settings) do
    upload? = operation == "upload"

    expected =
      case operation do
        "download" -> @payload
        "upload" -> sha(@payload)
        _ -> "ok"
      end

    opts =
      Keyword.merge(opts,
        method: if(upload?, do: :post, else: :get),
        body: if(upload?, do: @payload, else: nil)
      )

    started = now()
    promise = HTTP.fetch("https://localhost:#{port}/#{backend}/#{workload}/#{operation}", opts)
    response = HTTP.Promise.await(promise, settings.timeout_ms + 1_500)

    case response do
      %HTTP.Response{status: 200, http_version: :http1} -> :ok
      other -> raise "unexpected response: #{inspect(other)}"
    end

    ^expected = HTTP.Response.read_all(response)
    elapsed = now() - started

    connection =
      HTTP.Headers.get(response.headers, "x-benchmark-connection") |> String.to_integer()

    cleanup_start = now()

    completion =
      HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), settings.cleanup_ms)

    %{
      elapsed_us: elapsed,
      connection: connection,
      completion_result: inspect(completion),
      completion_wait_us: now() - cleanup_start,
      completion_limit_ms: settings.cleanup_ms,
      public_cleanup_confirmed: completion == :ok
    }
  end

  defp snapshot do
    memory = :erlang.memory()

    %{
      monotonic_us: now(),
      process_count: :erlang.system_info(:process_count),
      port_count: :erlang.system_info(:port_count),
      binary_memory_bytes: memory[:binary],
      process_memory_bytes: memory[:processes],
      total_memory_bytes: memory[:total]
    }
  end

  defp summary([]), do: %{n: 0, p50: nil, p95: nil, p99: nil, min: nil, max: nil}

  defp summary(values) do
    sorted = Enum.sort(values)
    n = length(sorted)

    %{
      n: n,
      p50: Enum.at(sorted, ceil(n * 0.50) - 1),
      p95: Enum.at(sorted, ceil(n * 0.95) - 1),
      p99: Enum.at(sorted, ceil(n * 0.99) - 1),
      min: hd(sorted),
      max: List.last(sorted)
    }
  end

  defp validate_counts!(stats, settings) do
    count = settings.warmup + settings.samples

    for backend <- ["ssl", "ex_ssl"],
        {workload, operation} <- [
          {"cold", "small"},
          {"upload", "upload"},
          {"download", "download"},
          {"reuse", "small"}
        ] do
      ^count = stats["exchanges"]["/#{backend}/#{workload}/#{operation}"]
      if workload != "cold", do: 1 = stats["exchanges"]["/#{backend}/#{workload}/close"]
    end

    expected_upload = 2 * count * byte_size(@payload)
    ^expected_upload = stats["upload_bytes"]
  end

  defp source do
    {head, 0} = System.cmd("git", ["rev-parse", "HEAD"], cd: @root)
    {status, 0} = System.cmd("git", ["status", "--porcelain"], cd: @root)
    {patch, 0} = System.cmd("git", ["diff", "--no-ext-diff", "--binary", "HEAD", "--"], cd: @root)

    runtime_paths =
      ["apps/*/mix.exs", "apps/*/lib/**/*.ex"]
      |> Enum.flat_map(&Path.wildcard(Path.join(@root, &1)))
      |> Enum.map(&Path.relative_to(&1, @root))
      |> Enum.sort()

    paths = [
      "scripts/tls_migration_benchmark.exs",
      "scripts/tls_migration_benchmark_peer.py",
      "mix.lock",
      "apps/http_web_socket/test/support/fixtures/localhost.pem",
      "apps/http_web_socket/test/support/fixtures/localhost-ca.pem"
    ]

    %{
      head: String.trim(head),
      worktree_status: status,
      tracked_diff_head_sha256: sha(patch),
      runtime_source_file_count: length(runtime_paths),
      sha256:
        Map.new(Enum.uniq(paths ++ runtime_paths), fn path ->
          {path, sha(File.read!(Path.join(@root, path)))}
        end)
    }
  end

  defp setting(name, default, low, high) do
    value =
      System.get_env("TLS_BENCH_" <> name, Integer.to_string(default)) |> String.to_integer()

    if value < low or value > high, do: raise("TLS_BENCH_#{name} must be #{low}..#{high}")
    value
  end

  defp peer_call(peer, command) do
    true = Port.command(peer, JSON.encode!(%{command: command}) <> "\n")
    peer_read(peer)
  end

  defp peer_read(peer) do
    receive do
      {^peer, {:data, {:eol, line}}} -> JSON.decode!(line)
      {^peer, {:data, {:noeol, _}}} -> raise "peer JSON exceeds line budget"
      {^peer, {:exit_status, code}} -> raise "peer exited #{code}"
    after
      5_000 -> raise "peer control timeout"
    end
  end

  defp sha(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
  defp now, do: System.monotonic_time(:microsecond)
end

TLSMigrationBenchmark.run()

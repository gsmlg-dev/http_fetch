# Source-candidate P4 runner; invoked only by tls_migration_performance.py.
# No SSL.Socket destructuring, :sys inspection or provider-private resource probes.
# Live counts come from finite public snapshots. Confirmed whole-scope retirement
# proves enrolled logical resources ended; it does not certify native memory reclamation.
defmodule TLSMigrationPerformance do
  @payload :binary.copy("Z", 1_048_576)
  @chunk :binary.copy("U", 65_536)
  @timeout 15_000
  @provider_keys [:processes, :tcp_sockets, :generations, :observers, :data_resources]

  def run do
    config = System.fetch_env!("TLS_PERF_CONFIG") |> File.read!() |> JSON.decode!()

    try do
      report = execute(config)
      File.write!(config["output"], JSON.encode!(json_safe(report)))
    rescue
      error ->
        File.write!(config["output"], JSON.encode!(%{failures: [Exception.message(error)]}))
        reraise error, __STACKTRACE__
    end
  end

  defp execute(config) do
    cell = config["cell"]
    protocol = if cell["protocol"] == "h2", do: :http2, else: :http1
    backend = if config["backend"] == "ex_ssl", do: :ex_ssl, else: :ssl
    count = cell["concurrency"]
    origin = "https://localhost:#{config["peer"]["port"]}"
    effective = effective(config, count)
    scopes = open_scopes(count, origin, protocol, backend, cell["tls"])

    try do
      warmup = warmup(scopes, config, origin, "initial")
      baseline = vm()
      live = provider(scopes)
      started = now()

      {samples, resource_samples, cycles} =
        if cell["kind"] == "soak" do
          soak(scopes, config, origin, started)
        else
          samples = measure(scopes, config, origin, protocol, backend)
          {samples, [], 0}
        end

      wall = now() - started
      statuses = Enum.map(scopes, &public_snapshot/1)

      live =
        if cell["workload"] in ["cold", "cancel"],
          do: provider_from_samples(samples, count),
          else: live

      retirement = retire_all(scopes, backend)
      Process.sleep(2_000)
      after_retirement = vm()

      # Additional short generation/retirement probes establish plateau. They do
      # not replace/restart the fixed 30min set or remint its duration/cycles.
      {retirement_cycles, extra_warmup} =
        if cell["kind"] == "soak" do
          first = %{
            baseline: baseline,
            after_retirement: after_retirement,
            observation_ms: 2_000,
            retirement: retirement
          }

          {extra, warm} =
            Enum.map_reduce(1..2, [], fn cycle, all_warm ->
              peers = open_scopes(count, origin, protocol, backend, cell["tls"])

              try do
                warm = warmup(peers, config, origin, "retirement-#{cycle}")
                base = vm()
                proof = retire_all(peers, backend)
                Process.sleep(2_000)

                {%{
                   baseline: base,
                   after_retirement: vm(),
                   observation_ms: 2_000,
                   retirement: proof
                 }, all_warm ++ warm}
              after
                safe_retire(peers)
              end
            end)

          {[first | extra], warm}
        else
          {[], []}
        end

      warmup = warmup ++ extra_warmup

      %{
        phase: config["phase"],
        backend: config["backend"],
        source_sha256: config["source_sha256"],
        runtime: runtime(),
        effective: Map.put(effective, :warmup, length(warmup)),
        warmup: warmup,
        samples: samples,
        wall_us: wall,
        failures: [],
        baseline: baseline,
        live_resources: live,
        live_resources_proof_source:
          if(is_map(live), do: "HTTP.ManagedTransport.snapshot/2", else: nil),
        public_snapshots: statuses,
        retirement: retirement,
        observation_ms: 2_000,
        after_retirement: after_retirement,
        # Only the whole-scope public join attests that all enrolled logical
        # provider resources and the observer have ended. Never infer it from VM.
        provider_after_retirement:
          if(retirement.status == "confirmed", do: Map.new(@provider_keys, &{&1, 0}), else: nil),
        provider_after_retirement_proof_source:
          if(retirement.status == "confirmed",
            do: "HTTP.ManagedTransport.await_retired/2",
            else: nil
          ),
        duration_us: if(cell["kind"] == "soak", do: wall, else: nil),
        completed_cycles: cycles,
        resource_samples: resource_samples,
        retirement_cycles: retirement_cycles,
        evidence_gaps:
          if(is_map(live), do: [], else: ["public numerical provider snapshot unavailable"]) ++
            if(retirement.status == "confirmed",
              do: [],
              else: ["public whole-scope retirement unconfirmed"]
            )
      }
    after
      safe_retire(scopes)
    end
  end

  defp effective(config, count) do
    %{
      verify: "verify_peer",
      tls: config["cell"]["tls"],
      alpn: config["cell"]["protocol"],
      cipher_policy: "ecdhe-rsa-aes128gcm-tls12/aes128gcm-sha256-tls13",
      payload_bytes: byte_size(@payload),
      concurrency: count,
      pool_connections: count,
      warm_state: "fresh-scope-per-arm",
      forced_global_gc: false,
      idle_timeout_ms: 60_000,
      connect_timeout_ms: @timeout,
      request_timeout_ms: @timeout
    }
  end

  defp open(origin, protocol, backend, tls) do
    tls13 = tls == "TLSv1.3"
    version = if tls13, do: :"tlsv1.3", else: :"tlsv1.2"

    cipher = %{
      key_exchange: if(tls13, do: :any, else: :ecdhe_rsa),
      cipher: :aes_128_gcm,
      mac: :aead,
      prf: :sha256
    }

    fixtures = Path.expand("../apps/http_fetch/test/support/fixtures", __DIR__)

    ssl = [
      verify: :verify_peer,
      cacertfile: Path.join(fixtures, "localhost-ca.pem"),
      versions: [version],
      ciphers: [cipher],
      session_tickets: :disabled
    ]

    ssl = if protocol == :http1, do: ssl ++ [alpn_advertised_protocols: ["http/1.1"]], else: ssl

    case HTTP.ManagedTransport.open(
           origin: origin,
           connect_address: {127, 0, 0, 1},
           http_version: protocol,
           tls_backend: backend,
           max_connections: 1,
           max_requests: 1,
           max_pending: 0,
           idle_timeout: 60_000,
           ssl: ssl,
           socket_opts: [nodelay: true, sndbuf: 4096, recbuf: 4096, send_timeout: @timeout]
         ) do
      {:ok, scope} -> scope
      error -> raise "managed provider unavailable: #{inspect(error)}"
    end
  end

  defp open_scopes(count, origin, protocol, backend, tls) do
    Enum.reduce(1..count, [], fn _, scopes ->
      try do
        [open(origin, protocol, backend, tls) | scopes]
      rescue
        error ->
          safe_retire(scopes)
          reraise error, __STACKTRACE__
      end
    end)
    |> Enum.reverse()
  end

  defp warmup(scopes, config, origin, label) do
    for iteration <- 1..config["warmup"], {scope, lane} <- Enum.with_index(scopes) do
      id = "w-#{label}-#{iteration}-#{lane}"
      sample = exchange(scope, origin, id, "reuse")

      %{
        id: id,
        payload_ok: sample.payload_sha256 == sha("ok"),
        request_completion: sample.request_completion
      }
    end
  end

  defp measure(scopes, config, origin, protocol, backend) do
    count = length(scopes)
    # Cold/cancel warmup scopes are retired before samples; every measured request
    # owns a fresh scope/connection and its own explicit retirement proof.
    if config["cell"]["workload"] in ["cold", "cancel"], do: retire_all(scopes, backend)

    0..(config["samples"] - 1)
    |> Enum.chunk_every(count)
    |> Enum.flat_map(fn batch ->
      tasks =
        Enum.with_index(batch)
        |> Enum.map(fn {index, lane} ->
          Task.async(fn ->
            measure_sample(scopes, lane, index, config, origin, protocol, backend)
          end)
        end)

      Enum.map(tasks, &Task.await(&1, 2 * @timeout + 5_000))
    end)
  end

  defp measure_sample(scopes, lane, index, config, origin, protocol, backend) do
    operation = config["cell"]["workload"]
    fresh = operation in ["cold", "cancel"]

    scope =
      if fresh,
        do: open(origin, protocol, backend, config["cell"]["tls"]),
        else: Enum.at(scopes, lane)

    try do
      sample =
        if operation == "cancel",
          do: cancellation(scope, config, origin, "m-#{index}"),
          else: exchange(scope, origin, "m-#{index}", operation)

      snapshot = public_snapshot(scope)
      proof = if fresh, do: retire_all([scope], backend), else: nil

      proof =
        if operation == "cancel",
          do: Map.update!(proof, :elapsed_us, &(&1 + sample.cancellation_us)),
          else: proof

      sample =
        if operation == "cancel" do
          Map.put(sample, :after_cancel_public_snapshot, snapshot)
        else
          Map.merge(sample, %{
            public_snapshot: snapshot,
            public_snapshot_point: "response-complete-before-retirement"
          })
        end

      Map.put(sample, :cleanup, proof)
    after
      if fresh, do: safe_retire([scope])
    end
  end

  defp soak(scopes, config, origin, started), do: soak(scopes, config, origin, started, 0, [], [])

  defp soak(scopes, config, origin, started, cycle, samples, observations) do
    duration = config["soak_ms"] * 1_000
    target_cycles = config["samples"]

    if cycle >= target_cycles and now() - started >= duration do
      {samples |> Enum.reverse() |> List.flatten(), Enum.reverse(observations), cycle}
    else
      target = started + div(duration * cycle, target_cycles)
      if target > now(), do: Process.sleep(div(target - now(), 1_000))

      batch =
        Enum.with_index(scopes)
        |> Enum.map(fn {scope, lane} ->
          Task.async(fn -> exchange(scope, origin, "m-#{cycle}-#{lane}", "reuse") end)
        end)
        |> Enum.map(&Task.await(&1, @timeout + 2_000))

      statuses = Enum.map(scopes, &public_snapshot/1)

      live_connections =
        Enum.reduce(statuses, 0, fn value, sum -> sum + Map.get(value, :connections, 0) end)

      observation = %{
        elapsed_us: now() - started,
        vm: vm(),
        provider: provider(scopes),
        live_connections: live_connections,
        public_snapshots: statuses
      }

      soak(scopes, config, origin, started, cycle + 1, [batch | samples], [
        observation | observations
      ])
    end
  end

  defp exchange(scope, origin, id, operation) do
    upload = operation == "upload"
    started = now()

    promise =
      HTTP.fetch(origin <> "/perf/#{id}/#{operation}",
        transport_scope: scope,
        redirect: :manual,
        decode_body: false,
        stream_response: true,
        telemetry: false,
        timeout: @timeout,
        connect_timeout: @timeout,
        method: if(upload, do: :post, else: :get),
        body: if(upload, do: @payload, else: nil)
      )

    response = HTTP.Promise.await(promise, @timeout + 1_000)

    case response do
      %HTTP.Response{status: 200} -> :ok
      other -> raise "exchange failed: #{inspect(other)}"
    end

    actual = HTTP.Response.read_all(response)

    expected =
      if operation == "download", do: @payload, else: if(upload, do: sha(@payload), else: "ok")

    if actual != expected, do: raise("incorrect authenticated payload")
    elapsed = now() - started
    completion = HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 1_000)
    if completion != :ok, do: raise("public request completion: #{inspect(completion)}")

    connection =
      HTTP.Headers.get(response.headers, "x-performance-connection") |> String.to_integer()

    %{
      id: id,
      elapsed_us: elapsed,
      payload_sha256: sha(actual),
      request_completion: "confirmed",
      connection: connection,
      blocked: nil
    }
  end

  defp cancellation(scope, config, origin, id) do
    controller = HTTP.AbortController.new()
    # Bounded lazy producer: 512MiB upper bound, one shared immutable 64KiB chunk.
    # It cannot finish through the acknowledged H1 no-read/H2 zero-window gate.
    {:ok, stream} = HTTP.Stream.from_enumerable(Stream.map(1..8192, fn _ -> @chunk end))
    started = now()

    promise =
      HTTP.fetch(origin <> "/perf/#{id}/cancel",
        transport_scope: scope,
        redirect: :manual,
        decode_body: false,
        stream_response: true,
        telemetry: false,
        timeout: @timeout,
        connect_timeout: @timeout,
        method: :post,
        body: stream,
        duplex: "half",
        signal: controller
      )

    try do
      gate_path = Path.join(config["state_dir"], id <> "-gate.json")
      gate = wait_gate(gate_path, now() + 10_000_000)
      true = gate["peer_gate"]

      {:error, :cleanup_pending} =
        HTTP.RequestCompletion.await(HTTP.Promise.completion(promise), 0)

      live_snapshot = public_snapshot(scope)
      cancelled = now()
      result = HTTP.RequestCompletion.abort_and_await(HTTP.Promise.completion(promise), 1_000)
      # Release only after cancellation was requested; H1 peer then observes EOF
      # or reset, and H2 independently observes RST_STREAM/connection retirement.
      File.write!(Path.join(config["state_dir"], id <> "-release"), "release")
      if result != :ok, do: raise("public blocked cancel cleanup: #{inspect(result)}")

      case HTTP.Promise.await(promise, 1_000) do
        {:error, _} -> :ok
        _ -> raise "cancelled request produced successful response"
      end

      %{
        id: id,
        elapsed_us: now() - started,
        payload_sha256: nil,
        request_completion: "confirmed",
        connection: gate["connection"],
        cancellation_us: now() - cancelled,
        public_snapshot: live_snapshot,
        public_snapshot_point: "blocked-before-cancel",
        blocked: %{
          peer_gate: true,
          completion_pending: true,
          source: "peer-read-or-flow-control-gate"
        }
      }
    after
      if Process.alive?(controller), do: Agent.stop(controller)
      # Public producer stop, not a provider/private process probe.
      HTTP.Stream.error(stream, :aborted)
    end
  end

  defp wait_gate(path, deadline) do
    case File.read(path) do
      {:ok, value} ->
        JSON.decode!(value)

      {:error, :enoent} ->
        if now() >= deadline, do: raise("independent peer blocking gate timeout")
        Process.sleep(5)
        wait_gate(path, deadline)

      {:error, reason} ->
        raise "gate evidence read: #{inspect(reason)}"
    end
  end

  defp retire_all(scopes, _backend) do
    proofs =
      Enum.map(scopes, fn scope ->
        started = now()
        {:ok, receipt} = HTTP.ManagedTransport.retire(scope, mode: :abort)
        result = HTTP.ManagedTransport.await_retired(receipt, 1_000)

        %{
          status: if(result == :ok, do: "confirmed", else: inspect(result)),
          elapsed_us: now() - started,
          proof_source: "HTTP.ManagedTransport.await_retired/2",
          retired_data_resources: if(result == :ok, do: 0, else: nil),
          # The accepted public whole-scope join includes provider observer exit.
          observer_exited: if(result == :ok, do: true, else: nil)
        }
      end)

    %{
      status:
        if(Enum.all?(proofs, &(&1.status == "confirmed")), do: "confirmed", else: "unconfirmed"),
      elapsed_us: Enum.max(Enum.map(proofs, & &1.elapsed_us)),
      retired_data_resources:
        if(Enum.all?(proofs, &(&1.retired_data_resources == 0)), do: 0, else: nil),
      observer_exited: Enum.all?(proofs, &(&1.observer_exited == true)),
      per_connection: proofs
    }
  end

  defp safe_retire(scopes) do
    Enum.each(scopes, fn scope ->
      case HTTP.ManagedTransport.retire(scope, mode: :abort) do
        {:ok, receipt} -> HTTP.ManagedTransport.await_retired(receipt, 1_000)
        _ -> :ok
      end
    end)
  end

  defp public_snapshot(scope) do
    case HTTP.ManagedTransport.snapshot(scope, 1_000) do
      {:ok, snapshot} ->
        Map.take(snapshot, [
          :active_requests,
          :pending,
          :preparing_requests,
          :connections,
          :resources,
          :limits,
          :identity,
          :lifecycle,
          :provider_resources
        ])

      error ->
        %{snapshot_error: inspect(error)}
    end
  end

  # Retain the finite public census from every scope; missing/invalid numeric
  # evidence cannot be replaced with opaque handles or global VM totals.
  defp provider(scopes) do
    counts = Enum.map(scopes, &(public_snapshot(&1) |> Map.get(:provider_resources)))
    combine_counts(counts)
  end

  defp provider_from_samples(samples, count) do
    batches =
      samples
      |> Enum.chunk_every(count)
      |> Enum.map(fn batch ->
        batch |> Enum.map(&Map.get(&1.public_snapshot, :provider_resources)) |> combine_counts()
      end)

    if Enum.all?(batches, &is_map/1) do
      Map.new(hd(batches), fn {key, _} ->
        {key, Enum.max(Enum.map(batches, &Map.fetch!(&1, key)))}
      end)
    else
      nil
    end
  end

  defp combine_counts(counts) do
    keys = @provider_keys

    if counts != [] and
         Enum.all?(counts, fn c ->
           is_map(c) and Enum.all?(keys, &(is_integer(Map.get(c, &1)) and Map.fetch!(c, &1) >= 0))
         end) do
      Map.new(keys, fn key -> {key, Enum.sum(Enum.map(counts, &Map.fetch!(&1, key)))} end)
    else
      nil
    end
  end

  defp vm do
    memory = :erlang.memory()
    {rss, 0} = System.cmd("ps", ["-o", "rss=", "-p", List.to_string(:os.getpid())])

    %{
      process_count: :erlang.system_info(:process_count),
      port_count: :erlang.system_info(:port_count),
      process_memory_bytes: memory[:processes],
      binary_memory_bytes: memory[:binary],
      total_memory_bytes: memory[:total],
      rss_bytes: String.trim(rss) |> String.to_integer() |> Kernel.*(1024)
    }
  end

  defp runtime do
    {host, 0} = System.cmd("hostname", [])

    modules = [
      HTTP,
      HTTP.Promise,
      HTTP.Response,
      HTTP.RequestCompletion,
      HTTP.ManagedTransport,
      SSL,
      SSL.Lifecycle
    ]

    beams =
      Map.new(modules, fn module ->
        Code.ensure_loaded!(module)
        {^module, bytes, _path} = :code.get_object_code(module)
        {Atom.to_string(module), sha(bytes)}
      end)

    %{
      otp: List.to_string(:erlang.system_info(:otp_release)),
      elixir: System.version(),
      erts: List.to_string(:erlang.system_info(:version)),
      host: String.trim(host),
      architecture: List.to_string(:erlang.system_info(:system_architecture)),
      schedulers: :erlang.system_info(:schedulers_online),
      beam_sha256: beams
    }
  end

  defp json_safe(value) when value in [nil, true, false], do: value
  defp json_safe(value) when is_atom(value), do: Atom.to_string(value)
  defp json_safe(value) when is_list(value), do: Enum.map(value, &json_safe/1)

  defp json_safe(value) when is_map(value),
    do: Map.new(value, fn {key, entry} -> {to_string(key), json_safe(entry)} end)

  defp json_safe(value) when is_binary(value) or is_number(value), do: value
  defp json_safe(_), do: "unsupported-public-value"

  defp sha(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
  defp now, do: System.monotonic_time(:microsecond)
end

TLSMigrationPerformance.run()

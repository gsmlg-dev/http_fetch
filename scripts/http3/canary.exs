defmodule HTTP3Canary do
  alias HTTP.HTTP3.{ConnectionOwner, Pool}

  def run do
    seconds = System.get_env("HTTP3_CANARY_SECONDS", "86400") |> String.to_integer()
    if seconds < 1, do: raise("positive canary duration required")

    options = [
      http_version: :http3,
      ssl: [
        cacertfile: System.fetch_env!("HTTP3_PEER_CA_FILE"),
        reference_identity: {:dns_id, "example.test"}
      ],
      timeout: 30_000
    ]

    peers =
      for {name, variable} <- [
            {"aioquic-1.2.0", "HTTP3_AIOQUIC_PORT"},
            {"caddy-2.9.1", "HTTP3_CADDY_PORT"}
          ],
          do: {name, "https://127.0.0.1:#{System.fetch_env!(variable)}"}

    cycle(peers, options, 0)
    baseline = sample()
    started = System.monotonic_time(:millisecond)
    deadline = started + seconds * 1_000
    result = loop(peers, options, started, deadline, baseline, 0, baseline)
    elapsed = System.monotonic_time(:millisecond) - started
    assert(elapsed >= seconds * 1_000, "elapsed duration")

    IO.puts(
      "HTTP3 canary result: PASS seconds=#{div(elapsed, 1_000)} requests=#{result.requests} " <>
        "peak_memory=#{result.peak.memory} peak_processes=#{result.peak.processes} " <>
        "peak_owners=#{result.peak.owners} peak_endpoints=#{result.peak.endpoints} " <>
        "peak_connections=#{result.peak.connections} peak_mailbox=#{result.peak.mailbox} errors=0 " <>
        "commit=#{System.get_env("HTTP3_CANARY_SHA", "unrecorded")}"
    )
  end

  defp loop(peers, options, started, deadline, baseline, requests, peak) do
    if System.monotonic_time(:millisecond) >= deadline do
      %{requests: requests, peak: peak}
    else
      count = cycle(peers, options, requests)
      current = sample()
      assert(current.memory <= baseline.memory + 67_108_864, "memory growth exceeds 64MiB")
      assert(current.memory <= 268_435_456, "VM memory exceeds 256MiB")

      assert(
        current.processes <= baseline.processes + 100,
        "process retention exceeds baseline+100"
      )

      peak = Map.new(current, fn {key, value} -> {key, max(Map.fetch!(peak, key), value)} end)

      elapsed = System.monotonic_time(:millisecond) - started

      if rem(requests, 6_400) == 0,
        do:
          IO.puts(
            "HTTP3 canary elapsed_ms=#{elapsed} requests=#{requests + count} " <>
              "memory=#{current.memory} processes=#{current.processes}"
          )

      # Workload pacing; every acceptance assertion uses state or actual traffic.
      receive do
      after
        5_000 -> :ok
      end

      loop(peers, options, started, deadline, baseline, requests + count, peak)
    end
  end

  defp cycle(peers, options, cycle) do
    tasks =
      for {name, base} <- peers, n <- 1..32 do
        Task.async(fn ->
          body = :binary.copy(<<rem(cycle + n, 256), n, 0, 255>>, 4_096)

          result =
            HTTP.fetch(base <> "/echo", Keyword.merge(options, method: :put, body: body))
            |> HTTP.Promise.await()

          assert(
            match?(%HTTP.Response{http_version: :http3, status: 200}, result),
            "strict canary response #{inspect(result)}"
          )

          assert(HTTP.Response.get_header(result, "x-peer") == name, "peer identity")
          assert(HTTP.Response.text(result) == body, "canary byte integrity")
        end)
      end

    Task.await_many(tasks, 60_000)
    barrier(System.monotonic_time(:millisecond) + 5_000)
    64
  end

  defp barrier(deadline) do
    status = Pool.status(:http_fetch_http3_pool)

    settled =
      status.leases == 0 and status.pending == 0 and
        Enum.all?(owners(), fn owner ->
          try do
            value = ConnectionOwner.status(owner)

            value.lifecycle == :ready and value.requests == 0 and not value.pending and
              value.queued == 0 and value.continuations == 0
          catch
            :exit, _ -> true
          end
        end)

    if settled do
      :ok
    else
      assert(System.monotonic_time(:millisecond) < deadline, "request/lease cleanup")

      receive do
      after
        1 -> barrier(deadline)
      end
    end
  end

  defp sample do
    owners = owners()
    assert(length(owners) <= 20, "owner bound")
    native_processes = Enum.group_by(Process.list(), &initial_module/1)
    endpoints = Map.get(native_processes, Quic.Endpoint, [])
    connections = Map.get(native_processes, Quic.Connection, [])
    assert(length(endpoints) <= 20, "endpoint bound")
    assert(length(connections) <= 20, "native connection bound")
    mailboxes = Enum.map(owners ++ endpoints ++ connections, &mailbox/1)
    assert(Enum.all?(mailboxes, &(&1 <= 128)), "owner/native mailbox bound")

    for owner <- owners do
      assert(mailbox(owner) <= 128, "owner mailbox bound")
      state = :sys.get_state(owner)
      assert(map_size(state.session.requests) == 0, "session cleanup")
      assert(map_size(state.session.continuations) == 0, "session continuation cleanup")
      {:ok, native} = Quic.info(state.session.connection.handle)

      assert(
        native.resources.ready_bytes == 0 and native.resources.receive_buffered_bytes == 0,
        "native receive cleanup"
      )

      assert(mailbox(state.session.connection.handle.id) <= 128, "native mailbox bound")
      :erlang.garbage_collect(owner)
      :erlang.garbage_collect(state.session.connection.handle.id)
    end

    :erlang.garbage_collect(self())

    %{
      memory: :erlang.memory(:total),
      processes: :erlang.system_info(:process_count),
      owners: length(owners),
      endpoints: length(endpoints),
      connections: length(connections),
      mailbox: Enum.max(mailboxes, fn -> 0 end)
    }
  end

  defp initial_module(pid) do
    case :proc_lib.translate_initial_call(pid) do
      {module, _, _} -> module
      _ -> nil
    end
  end

  defp mailbox(pid) do
    {:message_queue_len, length} = Process.info(pid, :message_queue_len)
    length
  end

  defp owners do
    for {_, pid, _, _} <-
          DynamicSupervisor.which_children(:http_fetch_http3_connection_supervisor),
        is_pid(pid),
        do: pid
  end

  defp assert(true, _), do: :ok
  defp assert(false, message), do: raise(message)
end

HTTP3Canary.run()

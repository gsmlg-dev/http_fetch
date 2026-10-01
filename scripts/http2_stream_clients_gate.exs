# Public EventSource/Fetch acceptance. Run with the independent Python runner.
defmodule HTTPStreamClientsGate do
  alias HTTP.EventSource
  alias HTTP.EventSource.Event.{Error, Message, Open}

  @budgets %{
    owner_heap_bytes: 8_388_608,
    owner_binary_bytes: 2_097_152,
    owner_active_mailbox: 256,
    owner_quiescent_mailbox: 16,
    session_heap_bytes: 8_388_608,
    session_binary_bytes: 4_194_304,
    session_mailbox: 256,
    stream_heap_bytes: 8_388_608,
    stream_binary_bytes: 4_194_304,
    stream_mailbox: 256,
    monitor_heap_bytes: 65_536,
    monitor_binary_bytes: 65_536,
    monitor_workers: 8,
    owners: 4,
    stream_workers: 8,
    queue_bytes: 2_097_152,
    queue_events: 1_024
  }

  def run do
    url = System.fetch_env!("HTTP_STREAM_GATE_URL")
    backend = String.to_existing_atom(System.get_env("HTTP_STREAM_GATE_BACKEND", "ssl"))
    mode = System.get_env("HTTP_STREAM_GATE_MODE", "sse")
    count = String.to_integer(System.get_env("HTTP_STREAM_GATE_COUNT", "10000"))
    protocol = if String.starts_with?(url, "https"), do: :http2, else: :h2c

    opts = [
      http_version: protocol,
      http2_profile: :native_v1,
      connect_timeout: 30_000,
      tls_backend: backend,
      ssl:
        if(protocol == :http2,
          do: [cacertfile: System.fetch_env!("HTTP_STREAM_GATE_CA")],
          else: []
        ),
      reconnect_time: 1,
      max_reconnect_time: 10,
      max_queue_events: @budgets.queue_events,
      max_queue_bytes: @budgets.queue_bytes
    ]

    Process.put(:samples, [])

    IO.puts(
      JSON.encode!(%{
        kind: "frozen_budgets",
        budgets: @budgets,
        sampling: "at open, every 500 events, paused barrier, and quiescence"
      })
    )

    started = System.monotonic_time(:millisecond)

    case mode do
      "sse" -> sse(url, opts, protocol, count)
      "mixed" -> mixed(url, opts, protocol)
      "faults" -> faults(url, opts, protocol)
      "churn" -> numbered(url, "/sse/churn", opts, protocol, count, count - 1)
    end

    settle()
    sample([], true)
    samples = Process.get(:samples)

    IO.puts(
      JSON.encode!(%{
        result: "PASS",
        mode: mode,
        count: count,
        elapsed_ms: System.monotonic_time(:millisecond) - started,
        sampled_maxima: maxima(samples),
        samples: length(samples)
      })
    )
  end

  defp source(url, path, opts) do
    case EventSource.new(url <> path, opts) do
      %EventSource{} = source -> source
      other -> raise "new EventSource failed: #{inspect(other)}"
    end
  end

  defp opened(source, protocol) do
    receive do
      {EventSource, ^source, %Open{}} ->
        actual = EventSource.http_version(source)

        if actual != actual_protocol(protocol),
          do: raise("actual EventSource protocol #{inspect(actual)} != #{protocol}")

        sample([source])

      {EventSource, ^source, %Error{reason: reason}} ->
        raise "open failed: #{inspect(reason)}"
    after
      30_000 -> raise "EventSource open timeout"
    end
  end

  defp message(source) do
    receive do
      {EventSource, ^source, %Message{} = event} ->
        {event, nil}

      {EventSource, ^source, %Message{} = event, ref} ->
        {event, ref}

      {EventSource, ^source, %Error{reason: reason}} ->
        raise "unexpected EventSource error: #{inspect(reason)}"

      {EventSource, ^source, %Open{}} ->
        raise "unexpected duplicate Open"
    after
      30_000 -> raise "EventSource message timeout"
    end
  end

  defp numbered(url, path, opts, protocol, count, expected_eofs) do
    opts = Keyword.merge(opts, delivery: :ack, max_event_size: 4096)
    source = source(url, "#{path}?count=#{count}", opts)
    opened(source, protocol)
    receive_numbered(source, protocol, 1, count, 0, 1, expected_eofs)
    if EventSource.last_event_id(source) != Integer.to_string(count), do: raise("cursor mismatch")
    close(source)
  end

  defp receive_numbered(source, protocol, next, count, errors, opens, expected_eofs)
       when next > count do
    if errors != expected_eofs or opens != expected_eofs + 1,
      do: raise("wrong reconnect/open count: #{errors}/#{opens}")

    if EventSource.http_version(source) != actual_protocol(protocol),
      do: raise("reconnected protocol mismatch")
  end

  defp receive_numbered(source, protocol, next, count, errors, opens, expected_eofs) do
    receive do
      {EventSource, ^source, %Message{data: data, last_event_id: id, type: "message"}, ref}
      when is_reference(ref) ->
        if id != Integer.to_string(next) or data != "event-#{next}-λ",
          do: raise("ordered event mismatch at #{next}: #{inspect({id, data})}")

        :ok = EventSource.acknowledge(source, ref)

        if rem(next, 500) == 0, do: sample([source])
        receive_numbered(source, protocol, next + 1, count, errors, opens, expected_eofs)

      {EventSource, ^source, %Error{reason: :eof}} ->
        if errors >= expected_eofs, do: raise("extra EOF")
        receive_numbered(source, protocol, next, count, errors + 1, opens, expected_eofs)

      {EventSource, ^source, %Open{}} ->
        if EventSource.http_version(source) != actual_protocol(protocol),
          do: raise("reconnect protocol mismatch")

        receive_numbered(source, protocol, next, count, errors, opens + 1, expected_eofs)

      {EventSource, ^source, other} ->
        raise "unexpected numbered envelope: #{inspect(other)}"
    after
      30_000 -> raise "numbered workload timeout at #{next}"
    end
  end

  defp sse(url, opts, protocol, count) do
    numbered(url, "/sse/numbered", opts, protocol, count, 1)
    source = source(url, "/sse/semantics", opts)
    opened(source, protocol)
    "1" = fetch(url, "/control/semantics", opts)
    {%Message{type: "custom", data: "λ\nsecond", last_event_id: "7"}, nil} = message(source)
    {%Message{data: "reset", last_event_id: ""}, nil} = message(source)
    {%Message{data: "final", last_event_id: "done"}, nil} = message(source)

    receive do
      {EventSource, ^source, %Error{reason: :eof}} -> :ok
    after
      30_000 -> raise "missing semantics EOF"
    end

    wait(fn -> EventSource.ready_state(source) == EventSource.closed() end, "204 permanent stop")
    close(source)
    source = source(url, "/sse/large", opts)
    opened(source, protocol)
    {%Message{data: data, last_event_id: "1"}, nil} = message(source)
    expected = Enum.join(List.duplicate(String.duplicate("x", 64), 2048), "\n")
    if data != expected or byte_size(data) <= 65_535, do: raise("large event content mismatch")
    sample([source])
    close(source)
    source = source(url, "/sse/overflow", Keyword.put(opts, :max_event_size, 4096))
    opened(source, protocol)
    "1" = fetch(url, "/control/overflow", opts)

    receive do
      {EventSource, ^source, %Error{reason: :event_too_large}} -> :ok
    after
      30_000 -> raise "missing finite event bound rejection"
    end

    close(source)
    paused(url, opts, protocol)
  end

  defp paused(url, opts, protocol) do
    opts =
      Keyword.merge(opts,
        delivery: :ack,
        max_event_size: 4096,
        max_queue_events: 4,
        max_queue_bytes: 8192
      )

    source = source(url, "/sse/pressure?count=10000", opts)
    opened(source, protocol)
    {%Message{last_event_id: "1"}, ref} = message(source)
    if not is_reference(ref), do: raise("missing opaque application delivery reference")
    handle = EventSource.status(source).stream_handle
    wait(fn -> EventSource.status(source).raw_bytes > 0 end, "retained paused DATA")
    # Sibling Fetch is an observed progress barrier while the event remains unacknowledged.
    "/fetch/paused" = fetch(url, "/fetch/paused", opts)
    sample([source])
    status = EventSource.status(source)

    if status.queued_bytes > 8192 or status.queued_events > 4 or not status.inflight?,
      do: raise("paused acknowledged queue bound/state violation")

    if status.ready_state != EventSource.open() or status.stream_handle != handle or
         status.raw_bytes == 0,
       do: raise("paused source changed stream or lost pending DATA")

    IO.puts(JSON.encode!(%{kind: "paused_status", status: sanitize(status)}))

    receive do
      {EventSource, ^source, %Message{}, _} ->
        raise "second acknowledged delivery before ACK"

      {EventSource, ^source, %Error{reason: reason}} ->
        raise "paused source failed: #{inspect(reason)}"

      {EventSource, ^source, %Open{}} ->
        raise "paused source reconnected"
    after
      0 -> :ok
    end

    :ok = EventSource.acknowledge(source, ref)
    {%Message{last_event_id: "2", data: "event-2-λ"}, next_ref} = message(source)
    if not is_reference(next_ref), do: raise("missing resumed delivery reference")
    if EventSource.status(source).stream_handle != handle, do: raise("resume changed stream")

    close(source)
    "/fetch/after-pause" = fetch(url, "/fetch/after-pause", opts)
  end

  defp mixed(url, opts, protocol) do
    sources = for _ <- 1..3, do: source(url, "/sse/hold", opts)

    for source <- sources do
      opened(source, protocol)
      {%Message{last_event_id: "1"}, nil} = message(source)
    end

    for n <- 1..100 do
      expected = "/fetch/mixed-#{n}"
      ^expected = fetch(url, expected, opts)
    end

    sample(sources)
    [cancelled | live] = sources
    cancelled_id = EventSource.status(cancelled).stream_handle.id
    close(cancelled)
    expected_id = Integer.to_string(cancelled_id)
    ^expected_id = fetch(url, "/control/cancelled?stream=#{cancelled_id}", opts)

    IO.puts(
      JSON.encode!(%{
        kind: "cancellation_barrier",
        stream: cancelled_id,
        code: 8,
        protocol: actual_protocol(protocol),
        backend: opts[:tls_backend]
      })
    )

    "2" = fetch(url, "/control/held", opts)

    for source <- live do
      {%Message{last_event_id: "2", data: "event-2-λ"}, nil} = message(source)
      close(source)
    end
  end

  defp faults(url, opts, protocol) do
    reset = source(url, "/sse/reset", opts)
    opened(reset, protocol)
    {%Message{last_event_id: "1"}, nil} = message(reset)
    "1" = fetch(url, "/control/reset", opts)

    receive do
      {EventSource, ^reset, %Error{reason: {:http2, :reset, 8}}} -> :ok
    after
      30_000 -> raise "missing typed reset error"
    end

    opened(reset, protocol)
    {%Message{last_event_id: "2"}, nil} = message(reset)
    close(reset)
    goaway = source(url, "/sse/goaway", opts)
    opened(goaway, protocol)
    {%Message{last_event_id: "1"}, nil} = message(goaway)
    "1" = fetch(url, "/control/goaway", opts)
    "/fetch/replacement" = fetch(url, "/fetch/replacement", opts)
    {%Message{last_event_id: "2"}, nil} = message(goaway)

    receive do
      {EventSource, ^goaway, %Error{reason: :eof}} -> :ok
    after
      30_000 -> raise "missing accepted GOAWAY stream EOF"
    end

    opened(goaway, protocol)
    {%Message{last_event_id: "3"}, nil} = message(goaway)
    sample([goaway])
    close(goaway)
  end

  defp fetch(url, path, opts) do
    case HTTP.fetch(url <> path, Keyword.put(opts, :timeout, 30_000))
         |> HTTP.Promise.await(35_000) do
      %HTTP.Response{status: 200} = response -> HTTP.Response.read_all(response)
      other -> raise "sibling Fetch failed: #{inspect(other)}"
    end
  end

  defp close(source) do
    :ok = EventSource.close(source)
    # Synchronous close and this call form a local generation-settlement barrier.
    if EventSource.ready_state(source) != EventSource.closed(),
      do: raise("source failed to close")

    receive do
      {EventSource, ^source, %Message{} = event} ->
        raise "queued stale event after explicit close: #{inspect(event)}"

      {EventSource, ^source, %Message{} = event, _} ->
        raise "queued stale acknowledged event after close: #{inspect(event)}"
    after
      0 -> :ok
    end
  end

  defp wait(condition, label) do
    deadline = System.monotonic_time(:millisecond) + 10_000

    poll = fn poll ->
      if condition.() do
        :ok
      else
        if System.monotonic_time(:millisecond) >= deadline, do: raise("timeout: #{label}")

        receive do
        after
          5 -> :ok
        end

        poll.(poll)
      end
    end

    poll.(poll)
  end

  defp settle do
    wait(
      fn ->
        stats = HTTP.HTTP2.Pool.stats(Process.whereis(:http_fetch_http2_pool))
        workers = Task.Supervisor.children(:http_runtime_task_supervisor)

        Enum.all?(stats, fn {_, entry} -> entry.streams == 0 end) and workers == [] and
          Enum.all?(
            DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor),
            fn {_, pid, _, _} -> quiescent_owner?(pid) end
          )
      end,
      "zero streams, reservations and stream workers"
    )
  end

  defp quiescent_owner?(pid) do
    monitor = Process.monitor(pid)

    try do
      status = HTTP.HTTP2.ConnectionOwner.status(pid)
      status.active_streams == 0 and status.protocol_streams == 0
    catch
      :exit, {:normal, {GenServer, :call, [^pid, :status, _timeout]}} ->
        # A completed GOAWAY owner may terminate between the supervisor snapshot
        # and this final quiescence observation. Confirm that exact normal exit;
        # other exits and timeouts remain gate failures. Re-poll all resources.
        receive do
          {:DOWN, ^monitor, :process, ^pid, :normal} -> false
        after
          1_000 -> raise "unconfirmed normal owner termination"
        end
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp sample(sources, quiescent \\ false) do
    owners = DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor)
    workers = Task.Supervisor.children(:http_runtime_task_supervisor)
    monitors = owner_monitors()

    if length(owners) > @budgets.owners or length(workers) > @budgets.stream_workers or
         length(monitors) > @budgets.monitor_workers or (quiescent and monitors != []),
       do: raise("owner/worker bound exceeded")

    records =
      Enum.map(owners, fn {_, pid, _, _} -> resources(pid, :owner, quiescent) end) ++
        Enum.map(sources, fn source ->
          status = EventSource.status(source)
          check_queue(status)
          resources(source.pid, :session, quiescent)
        end) ++
        Enum.map(workers, &resources(&1, :stream, quiescent)) ++
        Enum.map(monitors, &resources(&1, :monitor, quiescent))

    sample = %{
      owners: length(owners),
      workers: length(workers),
      monitor_workers: length(monitors),
      processes: records
    }

    Process.put(:samples, [sample | Process.get(:samples)])
    IO.puts(JSON.encode!(Map.put(sample, :kind, "resource_sample")))
  end

  defp owner_monitors do
    Enum.filter(Process.list(), fn pid ->
      case Process.info(pid, :current_function) do
        {:current_function, {HTTP.OwnerMonitor, _, _}} -> true
        _ -> false
      end
    end)
  end

  defp check_queue(status) do
    if status.raw_bytes > 1_048_576 or status.raw_chunks > 128 or
         status.parser_bytes > 1_048_576 or status.parser_parts > 16_384,
       do: raise("raw/parser pending bound exceeded")

    for {key, value} <- status, is_integer(value) do
      case key do
        :queued_bytes -> if value > @budgets.queue_bytes, do: raise("event queue byte bound")
        :queued_events -> if value > @budgets.queue_events, do: raise("event queue count bound")
        _ -> :ok
      end
    end
  end

  defp resources(pid, role, quiescent) do
    case Process.info(pid, [:memory, :binary, :message_queue_len]) do
      nil ->
        %{role: role, heap_bytes: 0, binary_bytes: 0, mailbox: 0, exited: true}

      info ->
        memory = info[:memory]
        binaries = Enum.sum(for {_, bytes, _} <- info[:binary], do: bytes)
        mailbox = info[:message_queue_len]

        mailbox_limit =
          if role == :owner,
            do:
              if(quiescent,
                do: @budgets.owner_quiescent_mailbox,
                else: @budgets.owner_active_mailbox
              ),
            else: @budgets.session_mailbox

        if memory > @budgets[String.to_existing_atom("#{role}_heap_bytes")] or
             binaries > @budgets[String.to_existing_atom("#{role}_binary_bytes")] or
             mailbox > mailbox_limit,
           do: raise("#{role} resource bound exceeded: #{inspect({memory, binaries, mailbox})}")

        %{role: role, heap_bytes: memory, binary_bytes: binaries, mailbox: mailbox}
    end
  end

  defp maxima(samples) do
    for role <- [:owner, :session, :stream, :monitor], into: %{} do
      records = for sample <- samples, record <- sample.processes, record.role == role, do: record

      {role,
       Map.new(
         for key <- [:heap_bytes, :binary_bytes, :mailbox],
             do: {key, Enum.max(Enum.map(records, &Map.fetch!(&1, key)), fn -> 0 end)}
       )}
    end
  end

  defp sanitize(value) when is_pid(value) or is_reference(value), do: inspect(value)

  defp sanitize(value) when is_map(value),
    do: Map.new(value, fn {key, item} -> {key, sanitize(item)} end)

  defp sanitize(value) when is_tuple(value), do: value |> Tuple.to_list() |> Enum.map(&sanitize/1)
  defp sanitize(value), do: value

  defp actual_protocol(protocol) when protocol in [:http2, :h2c], do: :http2
end

HTTPStreamClientsGate.run()

Code.require_file("http2_metrics.exs", __DIR__)
# Public RFC 8441 acceptance; launched and independently audited by the Python runner.
defmodule HTTPWebSocketGate do
  alias HTTP.WebSocket, as: WS
  alias HTTP.WebSocket.ArrayBuffer
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}
  alias HTTP.EventSource, as: SSE

  @budgets %{
    owners: 4,
    workers: 8,
    sessions: 8,
    monitor_workers: 8,
    monitor_heap_bytes: 65_536,
    monitor_binary_bytes: 65_536,
    heap_bytes: 8_388_608,
    binary_bytes: 4_194_304,
    mailbox: 256,
    queue_bytes: 1_048_576,
    queue_events: 64,
    send_bytes: 1_048_576,
    send_frames: 16,
    control_frames: 16,
    raw_bytes: 1_048_576
  }

  def run do
    metrics = HTTP2GateMetrics.start()
    url = System.fetch_env!("HTTP_WS_GATE_URL")
    mode = System.fetch_env!("HTTP_WS_GATE_MODE")
    count = System.fetch_env!("HTTP_WS_GATE_COUNT") |> String.to_integer()
    tls? = String.starts_with?(url, "https:")

    opts = [
      http_version: if(tls?, do: :http2, else: :h2c),
      http2_profile: :native_v1,
      http2_scope: "ws-gate",
      tls_backend: String.to_existing_atom(System.fetch_env!("HTTP_WS_GATE_BACKEND")),
      ssl: if(tls?, do: [cacertfile: System.fetch_env!("HTTP_WS_GATE_CA")], else: []),
      timeout: 30_000,
      connect_timeout: 30_000,
      opening_timeout: 30_000,
      delivery: :ack,
      binary_type: :array_buffer,
      max_message_size: 262_144,
      max_queue_bytes: @budgets.queue_bytes,
      max_queue_events: @budgets.queue_events,
      max_send_queue: @budgets.send_bytes,
      max_send_frames: @budgets.send_frames,
      max_control_frames: @budgets.control_frames,
      max_frame_parts: 1024
    ]

    Process.put(:samples, [])
    Process.put(:sessions, [])
    Process.put(:soak_counts, %{ws_messages: 0, sse_messages: 0, sse_ticks: 0, fetch_requests: 0})

    IO.puts(
      JSON.encode!(%{
        kind: "frozen_budgets",
        budgets: @budgets,
        sampling:
          "open, every 500 messages, each 100 cycles, defined fault/pause barriers, final quiescence"
      })
    )

    started = System.monotonic_time(:millisecond)

    case mode do
      "echo" -> echo(url, opts, count)
      "churn" -> churn(url, opts, count)
      "mixed" -> mixed(url, opts)
      "faults" -> faults(url, opts)
      "soak" -> soak(url, opts)
    end

    settle()
    sample([], [], true)

    IO.puts(JSON.encode!(HTTP2GateMetrics.snapshot(metrics)))

    IO.puts(
      JSON.encode!(
        Map.merge(
          %{
            result: "PASS",
            acceptance: System.get_env("HTTP_WS_GATE_ACCEPTANCE", "true") == "true",
            completed: true,
            mode: mode,
            count: count,
            elapsed_ms: System.monotonic_time(:millisecond) - started,
            resource_samples: length(Process.get(:samples)),
            sampled_maxima: maxima()
          },
          Process.get(:soak_result, %{})
        )
      )
    )
  end

  defp socket(url, path, opts) do
    ws_url = String.replace_prefix(url, "http", "ws") <> path

    case WS.new(ws_url, [], opts) do
      %WS{} = socket ->
        track_session(socket)
        socket

      other ->
        raise "WebSocket constructor failed: #{inspect(other)}"
    end
  end

  defp opened(socket) do
    receive do
      {WS, ^socket, %Open{}} ->
        if WS.http_version(socket) != :http2 or WS.status(socket).fallback?,
          do: raise("public WebSocket did not open actual HTTP/2")

        sample([socket])

      {WS, ^socket, %Error{reason: reason}} ->
        raise "WebSocket open failed: #{inspect(reason)}"

      {WS, ^socket, %Close{} = close} ->
        raise "WebSocket closed before Open: #{inspect(close)}"
    after
      30_000 -> raise "WebSocket Open deadline"
    end
  end

  defp message(socket) do
    receive do
      {WS, ^socket, %Message{data: data}, ref} when is_reference(ref) ->
        {value(data), ref}

      {WS, ^socket, %Error{reason: reason}} ->
        raise "unexpected WebSocket Error: #{inspect(reason)}"

      {WS, ^socket, %Close{} = close} ->
        raise "unexpected WebSocket Close: #{inspect(close)}"
    after
      30_000 -> raise "WebSocket message deadline"
    end
  end

  defp value(%ArrayBuffer{data: data}), do: data
  defp value(data) when is_binary(data), do: data

  defp exchange(socket, payload, binary? \\ false) do
    :ok = WS.send(socket, if(binary?, do: WS.array_buffer(payload), else: payload))
    {^payload, ref} = message(socket)
    :ok = WS.acknowledge(socket, ref)
    :ok = WS.acknowledge(socket, ref)
  end

  defp clean_close(socket) do
    monitor = Process.monitor(socket.pid)
    :ok = WS.close(socket, 1000, "gate complete")
    close_event(socket, System.monotonic_time(:millisecond) + 10_000)

    receive do
      {:DOWN, ^monitor, :process, _pid, :normal} -> :ok
    after
      5_000 -> raise "closed WebSocket session survived"
    end
  end

  defp close_event(socket, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {WS, ^socket, %Message{}, ref} ->
        :ok = WS.acknowledge(socket, ref)
        close_event(socket, deadline)

      {WS, ^socket, %Close{code: 1000, was_clean: true}} ->
        :ok

      {WS, ^socket, %Close{} = close} ->
        raise "unclean Close: #{inspect(close)}"

      {WS, ^socket, %Error{reason: reason}} ->
        raise "Close Error: #{inspect(reason)}"
    after
      remaining -> raise "WebSocket Close deadline"
    end
  end

  defp echo(url, opts, count) do
    socket = socket(url, "/ws/echo?count=#{count + 1}", opts)
    opened(socket)

    for number <- 1..count do
      binary? = rem(number, 2) == 0
      payload = if binary?, do: <<number::64, 0, 255>>, else: "message-#{number}-λ"
      exchange(socket, payload, binary?)
      if rem(number, 500) == 0, do: sample([socket])
    end

    large = :binary.copy(<<0, 255, 17, 42>>, 32_768)
    exchange(socket, large, true)
    sample([socket])
    clean_close(socket)
  end

  defp churn(url, opts, count) do
    for cycle <- 1..count do
      socket = socket(url, "/ws/churn?count=1", opts)
      opened(socket)
      exchange(socket, "cycle-#{cycle}")
      clean_close(socket)

      if rem(cycle, 100) == 0 do
        settle()
        sample([])
      end
    end
  end

  defp mixed(url, opts) do
    sources =
      for _ <- 1..2 do
        source =
          SSE.new(url <> "/sse/hold", Keyword.merge(opts, delivery: :ack, max_event_size: 4096))

        track_session(source)

        receive do
          {SSE, ^source, %HTTP.EventSource.Event.Open{}} -> :ok
        after
          30_000 -> raise "mixed SSE Open deadline"
        end

        if SSE.http_version(source) != :http2, do: raise("mixed SSE actual protocol mismatch")
        {"sibling-1", ref} = sse_message(source)
        :ok = SSE.acknowledge(source, ref)
        source
      end

    live =
      for _ <- 1..2 do
        socket = socket(url, "/ws/echo?count=2", opts)
        opened(socket)
        exchange(socket, "before-cancel")
        socket
      end

    paused_opts =
      Keyword.merge(opts, max_message_size: 8192, max_queue_bytes: 32_768, max_queue_events: 4)

    paused = socket(url, "/ws/pressure?case=pressure&count=64", paused_opts)
    opened(paused)
    {first, ref} = message(paused)
    if not String.starts_with?(first, "pressure-1:"), do: raise("pressure event order")
    wait(fn -> WS.status(paused).raw_bytes > 0 end, "paused WS raw input")
    "/fetch/paused" = fetch(url, "/fetch/paused", opts)
    status = WS.status(paused)

    if status.queued_bytes > 32_768 or status.queued_events > 4 or not status.inflight?,
      do: raise("paused acknowledged WebSocket queue bound")

    sample([paused | live], sources)

    receive do
      {WS, ^paused, %Message{}, _} -> raise "delivery advanced before ACK"
      {WS, ^paused, %Error{reason: reason}} -> raise "paused WebSocket failed: #{inspect(reason)}"
    after
      0 -> :ok
    end

    :ok = WS.acknowledge(paused, ref)
    {second, second_ref} = message(paused)
    if not String.starts_with?(second, "pressure-2:"), do: raise("paused resume order")
    :ok = WS.acknowledge(paused, second_ref)
    clean_close(paused)
    [cancelled | survivors] = live
    clean_close(cancelled)
    for socket <- survivors, do: exchange(socket, "after-cancel")
    "2" = fetch(url, "/control/held", opts)

    for source <- sources do
      {"sibling-2", ref} = sse_message(source)
      :ok = SSE.acknowledge(source, ref)
      :ok = SSE.close(source)
    end

    for socket <- survivors, do: clean_close(socket)
    "/fetch/after-cancel" = fetch(url, "/fetch/after-cancel", opts)
    %{"active_ws" => 0, "active_sse" => 0} = fetch(url, "/peer/state", opts) |> JSON.decode!()
  end

  defp sse_message(source) do
    receive do
      {SSE, ^source, %HTTP.EventSource.Event.Message{data: data}, ref} ->
        {data, ref}

      {SSE, ^source, %HTTP.EventSource.Event.Error{reason: reason}} ->
        raise "mixed SSE Error: #{inspect(reason)}"
    after
      30_000 -> raise "mixed SSE message deadline"
    end
  end

  defp soak(url, opts) do
    seconds = System.fetch_env!("HTTP_WS_GATE_SECONDS") |> String.to_integer()

    state = %{
      sources: soak_sources(url, opts),
      sockets: soak_sockets(url, opts),
      cursor: 1,
      intervals: [],
      paused: nil,
      tick: 0
    }

    started = System.monotonic_time(:millisecond)

    state = soak_loop(url, opts, state, started, seconds)
    Enum.each(state.sockets, &clean_close/1)
    Enum.each(state.sources, &close_source/1)
    %{"active_ws" => 0, "active_sse" => 0} = fetch(url, "/peer/state", opts) |> JSON.decode!()

    Process.put(
      :soak_result,
      Map.merge(Process.get(:soak_counts), %{
        intervals: state.intervals,
        active_elapsed_ms: System.monotonic_time(:millisecond) - started
      })
    )
  end

  defp soak_sources(url, opts) do
    for _ <- 1..2 do
      source =
        SSE.new(url <> "/sse/hold", Keyword.merge(opts, delivery: :ack, max_event_size: 4096))

      track_session(source)

      receive do
        {SSE, ^source, %HTTP.EventSource.Event.Open{}} -> :ok
      after
        30_000 -> raise "soak SSE Open deadline"
      end

      if SSE.http_version(source) != :http2, do: raise("soak SSE protocol mismatch")
      soak_sse(source, 1)
      source
    end
  end

  defp soak_sockets(url, opts) do
    for case_name <- ["goaway", "cancel"] do
      socket = socket(url, "/ws/fault?case=#{case_name}", opts)
      opened(socket)
      socket
    end
  end

  defp soak_loop(url, opts, state, started, seconds) do
    elapsed = System.monotonic_time(:millisecond) - started

    if elapsed >= seconds * 1000 do
      if state.paused != nil or length(state.intervals) != 3,
        do: raise("incomplete soak intervals")

      state
    else
      state = soak_intervals(url, opts, state, elapsed, seconds)
      check_soak_pause(state.paused)
      [primary, secondary] = state.sockets
      tick = state.tick + 1
      soak_exchange(primary, "soak-tick:#{tick}")
      bump(:sse_ticks)
      soak_exchange(secondary, "soak-peer:#{tick}")
      Enum.each(state.sources, &soak_sse(&1, state.cursor + 1))
      path = "/fetch/soak-#{tick}"
      ^path = fetch(url, path, opts)
      bump(:fetch_requests)
      sockets = if state.paused, do: [elem(state.paused, 0) | state.sockets], else: state.sockets
      sample(sockets, state.sources)

      IO.puts(
        JSON.encode!(%{
          kind: "soak_progress",
          tick: tick,
          elapsed_ms: elapsed,
          sse_sessions: length(state.sources),
          ws_sessions: length(sockets),
          intervals: state.intervals
        })
      )

      remaining =
        min(1000, max(started + seconds * 1000 - System.monotonic_time(:millisecond), 0))

      receive do
      after
        remaining -> :ok
      end

      soak_loop(url, opts, %{state | tick: tick, cursor: state.cursor + 1}, started, seconds)
    end
  end

  defp soak_intervals(url, opts, state, elapsed, seconds) do
    cond do
      state.paused != nil and elapsed >= div(seconds * 1000, 4) + 3000 ->
        {paused, ref} = state.paused
        :ok = WS.acknowledge(paused, ref)
        {second, ref} = message(paused)
        if not String.starts_with?(second, "pressure-2:"), do: raise("soak paused resume order")
        :ok = WS.acknowledge(paused, ref)
        clean_close(paused)
        soak_intervals(url, opts, %{state | paused: nil}, elapsed, seconds)

      "slow-consumer" not in state.intervals and elapsed >= div(seconds * 1000, 4) ->
        pressure_opts =
          Keyword.merge(opts,
            max_message_size: 8192,
            max_queue_bytes: 32_768,
            max_queue_events: 4
          )

        paused = socket(url, "/ws/pressure?case=pressure&count=64", pressure_opts)
        opened(paused)
        {first, ref} = message(paused)
        if not String.starts_with?(first, "pressure-1:"), do: raise("soak pressure order")
        wait(fn -> WS.status(paused).raw_bytes > 0 end, "soak pressure retention")
        %{state | paused: {paused, ref}, intervals: state.intervals ++ ["slow-consumer"]}

      "cancellation" not in state.intervals and elapsed >= div(seconds * 1000, 2) ->
        [primary, cancelled] = state.sockets
        monitor = Process.monitor(cancelled.pid)
        Process.exit(cancelled.pid, :kill)

        receive do
          {:DOWN, ^monitor, :process, _pid, :killed} -> :ok
        after
          5000 -> raise "controlled WS cancellation deadline"
        end

        wait(
          fn ->
            fetch(url, "/peer/state", opts)
            |> JSON.decode!()
            |> Map.take(["active_ws", "active_sse"]) ==
              %{"active_ws" => 1, "active_sse" => 2}
          end,
          "controlled cancellation removed only its tunnel"
        )

        soak_exchange(primary, "soak-cancel-proof")
        "/fetch/soak-cancelled" = fetch(url, "/fetch/soak-cancelled", opts)
        bump(:fetch_requests)
        sample([primary], state.sources)
        replacement = socket(url, "/ws/echo", opts)
        opened(replacement)
        %{state | sockets: [primary, replacement], intervals: state.intervals ++ ["cancellation"]}

      "draining" not in state.intervals and elapsed >= div(seconds * 3000, 4) ->
        "1" = fetch(url, "/control/goaway", opts)
        [primary, secondary] = state.sockets
        soak_exchange(primary, "soak-tick:drain")
        bump(:sse_ticks)
        soak_exchange(secondary, "soak-peer:drain")
        Enum.each(state.sources, &soak_sse(&1, state.cursor + 1))
        "/fetch/soak-replacement" = fetch(url, "/fetch/soak-replacement", opts)
        bump(:fetch_requests)
        sample(state.sockets, state.sources)
        Enum.each(state.sockets, &clean_close/1)
        Enum.each(state.sources, &close_source/1)

        %{
          state
          | sources: soak_sources(url, opts),
            sockets: soak_sockets(url, opts),
            cursor: 1,
            intervals: state.intervals ++ ["draining"]
        }

      true ->
        state
    end
  end

  defp soak_exchange(socket, payload) do
    exchange(socket, payload)
    bump(:ws_messages)
  end

  defp check_soak_pause(nil), do: :ok

  defp check_soak_pause({socket, _ref}) do
    status = WS.status(socket)

    if status.queued_bytes > 32_768 or status.queued_events > 4 or not status.inflight?,
      do: raise("soak paused queue bound")

    receive do
      {WS, ^socket, %Message{}, _} -> raise "soak delivery advanced before ACK"
      {WS, ^socket, %Error{reason: reason}} -> raise "soak pressure Error: #{inspect(reason)}"
    after
      0 -> :ok
    end
  end

  defp soak_sse(source, cursor) do
    expected = "sibling-#{cursor}"
    {^expected, ref} = sse_message(source)
    if SSE.last_event_id(source) != Integer.to_string(cursor), do: raise("soak SSE cursor")
    :ok = SSE.acknowledge(source, ref)
    bump(:sse_messages)
  end

  defp bump(key),
    do: Process.put(:soak_counts, Map.update!(Process.get(:soak_counts), key, &(&1 + 1)))

  defp close_source(source) do
    monitor = Process.monitor(source.pid)
    :ok = SSE.close(source)

    receive do
      {:DOWN, ^monitor, :process, _pid, :normal} -> :ok
    after
      5000 -> raise "closed SSE session survived"
    end
  end

  defp track_session(session), do: Process.put(:sessions, [session | Process.get(:sessions)])

  defp faults(url, opts) do
    for {case_name, expected} <- [
          {"reject", {:unexpected_status, 403}},
          {"subprotocol", {:unexpected_protocol, "unrequested"}},
          {"extensions", {:unsupported_extensions, "permessage-deflate"}}
        ] do
      socket = socket(url, "/ws/fault?case=#{case_name}", opts)
      failure(socket, expected, 1006)
    end

    socket = socket(url, "/ws/fault?case=fragmented", opts)
    opened(socket)
    {"split-λ-end", ref} = message(socket)
    :ok = WS.acknowledge(socket, ref)
    "/fetch/pong-barrier" = fetch(url, "/fetch/pong-barrier", opts)
    clean_close(socket)

    for {case_name, expected, code, extra} <- [
          {"malformed", :unexpected_rsv, 1002, []},
          {"oversized", :message_too_big, 1009, []},
          {"parts", :too_many_frame_parts, 1009, [max_frame_parts: 32]}
        ] do
      socket = socket(url, "/ws/fault?case=#{case_name}", Keyword.merge(opts, extra))
      opened(socket)
      "1" = fetch(url, "/control/#{case_name}", opts)

      if case_name == "malformed" do
        {"first", ref} = message(socket)
        :ok = WS.acknowledge(socket, ref)
      end

      failure(socket, expected, code)
    end

    truncated = socket(url, "/ws/fault?case=truncated", opts)
    opened(truncated)
    "1" = fetch(url, "/control/truncate", opts)
    abnormal_close(truncated)
    reset = socket(url, "/ws/fault?case=reset", opts)
    opened(reset)
    exchange(reset, "before-reset")
    "1" = fetch(url, "/control/reset", opts)
    failure(reset, {:http2, :reset, 8}, 1006)
    goaway = socket(url, "/ws/fault?case=goaway", opts)
    opened(goaway)
    exchange(goaway, "before-goaway")
    "1" = fetch(url, "/control/goaway", opts)
    exchange(goaway, "after-goaway")
    "/fetch/replacement" = fetch(url, "/fetch/replacement", opts)
    clean_close(goaway)
    blocked = socket(url, "/ws/fault?case=blocked", Keyword.put(opts, :http2_scope, "blocked"))
    opened(blocked)
    large = :binary.copy("x", 131_072)
    :ok = WS.send(blocked, WS.array_buffer(large))
    blocked_opts = Keyword.put(opts, :http2_scope, "blocked")

    wait(
      fn ->
        fetch(url, "/peer/state", blocked_opts) |> JSON.decode!() |> Map.fetch!("withheld_bytes") ==
          65_535
      end,
      "both outbound H2 windows exhausted"
    )

    "1" = fetch(url, "/control/shrink", blocked_opts)
    if WS.buffered_amount(blocked) <= 0, do: raise("blocked upload falsely settled")
    sample([blocked])
    "1" = fetch(url, "/control/resume", blocked_opts)
    {^large, ref} = message(blocked)
    :ok = WS.acknowledge(blocked, ref)
    wait(fn -> WS.buffered_amount(blocked) == 0 end, "resumed buffered_amount settlement")
    clean_close(blocked)
    disabled_url = System.fetch_env!("HTTP_WS_GATE_DISABLED_URL")
    disabled = socket(disabled_url, "/ws/echo?count=1", opts)
    failure(disabled, :extended_connect_not_supported, 1006)
    "1" = fetch(disabled_url, "/control/enable", opts)
    later = socket(disabled_url, "/ws/echo?count=1", opts)
    opened(later)
    exchange(later, "after-enable")
    clean_close(later)
  end

  defp failure(socket, expected, code) do
    receive do
      {WS, ^socket, %Error{reason: ^expected}} ->
        :ok

      {WS, ^socket, %Error{reason: reason}} ->
        raise "wrong typed Error: #{inspect(reason)} != #{inspect(expected)}"

      {WS, ^socket, %Message{}, _} ->
        raise "unexpected message before fault"
    after
      30_000 -> raise "expected WebSocket Error #{inspect(expected)}"
    end

    receive do
      {WS, ^socket, %Close{code: ^code, was_clean: false}} -> :ok
      {WS, ^socket, %Close{} = close} -> raise "wrong fault Close: #{inspect(close)}"
    after
      10_000 -> raise "fault Close deadline"
    end
  end

  defp abnormal_close(socket) do
    receive do
      {WS, ^socket, %Close{code: 1006, was_clean: false}} -> :ok
      {WS, ^socket, %Close{} = close} -> raise "EOF falsely clean: #{inspect(close)}"
    after
      10_000 -> raise "EOF Close deadline"
    end
  end

  defp fetch(url, path, opts) do
    %HTTP.Response{status: 200} =
      response =
      HTTP.fetch(url <> path, Keyword.put(opts, :timeout, 30_000)) |> HTTP.Promise.await(35_000)

    HTTP.Response.read_all(response)
  end

  defp wait(condition, label) do
    deadline = System.monotonic_time(:millisecond) + 10_000

    poll = fn poll ->
      if condition.() do
        :ok
      else
        if System.monotonic_time(:millisecond) >= deadline, do: raise("deadline: #{label}")

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
        owners = DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor)

        Enum.all?(stats, fn {_, entry} -> entry.streams == 0 and entry.pending == 0 end) and
          workers == [] and
          owner_monitors() == [] and
          Enum.all?(owners, fn {_, pid, _, _} -> quiescent_owner?(pid) end)
      end,
      "zero protocol streams, pool reservations, pending admissions and runtime workers"
    )
  end

  defp quiescent_owner?(pid) do
    monitor = Process.monitor(pid)

    try do
      status = HTTP.HTTP2.ConnectionOwner.status(pid)
      status.active_streams == 0 and status.protocol_streams == 0
    catch
      :exit, {:normal, {GenServer, :call, [^pid, :status, _timeout]}} ->
        receive do
          {:DOWN, ^monitor, :process, ^pid, :normal} -> false
        after
          1_000 -> raise "unconfirmed normal owner termination"
        end
    after
      Process.demonitor(monitor, [:flush])
    end
  end

  defp sample(sockets, sources \\ [], quiescent \\ false) do
    owners = DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor)
    workers = Task.Supervisor.children(:http_runtime_task_supervisor)
    monitors = owner_monitors()
    sessions = Enum.filter(Process.get(:sessions), &Process.alive?(&1.pid))
    Process.put(:sessions, sessions)
    sockets = Enum.filter(sessions, &match?(%WS{}, &1)) ++ sockets
    sources = Enum.filter(sessions, &match?(%SSE{}, &1)) ++ sources

    if length(owners) > @budgets.owners or length(workers) > @budgets.workers or
         length(monitors) > @budgets.monitor_workers or length(sessions) > @budgets.sessions,
       do: raise("owner/worker count bound exceeded")

    for socket <- sockets, do: check_ws_budget(WS.status(socket))

    pids =
      Enum.uniq(
        Enum.map(owners, &elem(&1, 1)) ++
          workers ++ monitors ++ Enum.map(sockets ++ sources, & &1.pid)
      )

    records =
      for pid <- pids do
        case Process.info(pid, [:memory, :binary, :message_queue_len]) do
          nil ->
            %{heap_bytes: 0, binary_bytes: 0, mailbox: 0, exited: true}

          info ->
            record = %{
              role: if(pid in monitors, do: "owner_monitor", else: "owner_worker_or_session"),
              heap_bytes: info[:memory],
              binary_bytes: Enum.sum(for {_, size, _} <- info[:binary], do: size),
              mailbox: info[:message_queue_len]
            }

            check_process_budget(record, pid in monitors)

            record
        end
      end

    sample = %{
      owners: length(owners),
      workers: length(workers),
      monitor_workers: length(monitors),
      sessions: length(sessions),
      quiescent: quiescent,
      processes: records
    }

    Process.put(:samples, [sample | Process.get(:samples)])
    IO.puts(JSON.encode!(Map.put(sample, :kind, "resource_sample")))
  end

  defp check_process_budget(record, monitor?) do
    heap = if monitor?, do: @budgets.monitor_heap_bytes, else: @budgets.heap_bytes
    binary = if monitor?, do: @budgets.monitor_binary_bytes, else: @budgets.binary_bytes

    if record.heap_bytes > heap or record.binary_bytes > binary or
         record.mailbox > @budgets.mailbox,
       do: raise("process sampled budget exceeded: #{inspect(record)}")
  end

  defp owner_monitors do
    Enum.filter(Process.list(), fn pid ->
      case Process.info(pid, :current_function) do
        {:current_function, {HTTP.OwnerMonitor, _, _}} -> true
        _ -> false
      end
    end)
  end

  defp check_ws_budget(status) do
    if status.buffered_amount > @budgets.send_bytes or
         status.queued_bytes > @budgets.queue_bytes or
         status.queued_events > @budgets.queue_events or
         status.pending_send_frames > @budgets.send_frames or
         status.control_frames > @budgets.control_frames or
         status.raw_bytes > @budgets.raw_bytes,
       do: raise("WS queue/frame/raw budget exceeded: #{inspect(status)}")
  end

  defp maxima do
    records = for sample <- Process.get(:samples), record <- sample.processes, do: record

    Map.new(
      for key <- [:heap_bytes, :binary_bytes, :mailbox],
          do: {key, Enum.max(Enum.map(records, &Map.fetch!(&1, key)), fn -> 0 end)}
    )
  end
end

HTTPWebSocketGate.run()

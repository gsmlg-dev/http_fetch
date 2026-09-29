# Adapted from the G-T pinned ex_quic scripts/phase1/interop.exs client workload.
# All client operations use this repository adapter; the peer remains aioquic 1.2.0.
defmodule HTTP.Phase1.Independent do
  alias HTTP.QUIC.ExQuic, as: Adapter
  @alpn "ex-quic-phase1"
  @chunk 16_384
  @total 262_144
  @deadline 15_000

  def run do
    fixture = System.fetch_env!("HTTP_QUIC_TLS_FIXTURES")

    peer_script =
      Path.join(System.tmp_dir!(), "http-fetch-peer-#{System.unique_integer([:positive])}.py")

    source = System.fetch_env!("HTTP_QUIC_PEER_SCRIPT")
    File.write!(peer_script, File.read!(source) |> String.replace("phase1-streams", @alpn))
    Process.put(:peer_script, peer_script)
    tracer = start_boundary_trace()
    {:ok, endpoint} = endpoint("client", fixture)
    peer = peer("client", endpoint, fixture)

    try do
      result = await_handle("client", endpoint, peer, now() + @deadline, [])
      :ok = verify_boundary_trace(tracer)
      IO.puts(JSON.encode!(Map.put(result, :legacy_quic_calls, 0)))
      unless result.passed, do: raise("independent peer acceptance failed")
    after
      endpoint_monitor = Process.monitor(endpoint)
      Adapter.stop_endpoint(endpoint)

      receive do
        {:DOWN, ^endpoint_monitor, :process, ^endpoint, :normal} -> :ok
      after
        5_000 -> raise("endpoint cleanup timeout")
      end

      stop_peer(peer)
      send(tracer, :stop)
      File.rm!(peer_script)
      File.rm_rf!(peer_script <> ".venv")
    end
  end

  defp await_handle(role, endpoint, peer, deadline, events) do
    if now() >= deadline do
      fail(:handshake_deadline, events)
    else
      receive do
        {^peer, {:data, {:eol, line}}} when role == "client" ->
          case JSON.decode(line) do
            {:ok, %{"event" => "listening", "port" => port}} ->
              {:ok, handle} = Adapter.connect(endpoint, {{127, 0, 0, 1}, port})
              activate(role, handle, peer, deadline, [line | events])

            _ ->
              await_handle(role, endpoint, peer, deadline, [line | events])
          end

        {^peer, {:data, {:eol, line}}} ->
          await_handle(role, endpoint, peer, deadline, [line | events])

        {^peer, {:exit_status, code}} ->
          fail({:peer_exit, code}, events)
      after
        20 -> await_handle(role, endpoint, peer, deadline, events)
      end
    end
  end

  defp activate(role, handle, peer, deadline, peer_events) do
    :ok = Adapter.attach(handle, self())

    receive do
      {:quic_ready, ^handle, %{alpn: @alpn} = metadata} ->
        state = start_matrix(handle, role, metadata, peer_events)
        loop(state, peer, deadline)
    after
      20 ->
        if(now() >= deadline,
          do: fail(:ready_deadline, peer_events),
          else: activate(role, handle, peer, deadline, peer_events)
        )
    end
  end

  defp start_matrix(handle, role, metadata, peer_events) do
    bidi = open(handle, :bidi, 4)
    uni = open(handle, :uni, 3)
    {:ok, cancelled} = Adapter.open_stream(handle, :bidi)

    sends =
      Enum.map(bidi, &{&1, payload(&1.id), true}) ++
        Enum.map(uni, &{&1, "uni:" <> Integer.to_string(&1.id), false})

    %{
      handle: handle,
      role: role,
      started_at: now(),
      metadata: metadata,
      bidi: bidi,
      expected: Map.new(for bit <- 0..1, n <- 0..3, do: {bit + n * 4, payload(bit + n * 4)}),
      uni: uni,
      uni_fin_sent: false,
      sends: sends,
      echoes: [],
      opened: %{},
      bytes: %{},
      fins: MapSet.new(),
      cancelled: cancelled,
      cancelled_sent: false,
      bidi_started: MapSet.new(),
      peer_events: peer_events,
      highwaters: %{},
      reset_seen: false,
      peer_verified: false,
      reads: 0
    }
  end

  defp open(handle, kind, n),
    do:
      Enum.map(1..n, fn _ ->
        {:ok, s} = Adapter.open_stream(handle, kind)
        s
      end)

  defp loop(state, peer, deadline) do
    if now() >= deadline do
      fail(:transfer_deadline, state.peer_events, state)
    else
      sample = sample(state.handle)

      state = %{
        state
        | highwaters: Map.merge(state.highwaters, sample, fn _, a, b -> max(a, b) end)
      }

      state = admit(state, :sends) |> admit(:echoes)

      state =
        case state.sends do
          [first | rest] -> %{state | sends: rest ++ [first]}
          [] -> state
        end

      state = cancel_active_stream(state)

      {:ok, events} = Adapter.events(state.handle, 128)

      state =
        Enum.reduce(events, state, &event/2) |> drain_all() |> finish_uni() |> collect_peer(peer)

      if complete?(state),
        do: finish(state),
        else:
          (
            Process.sleep(5)
            loop(state, peer, deadline)
          )
    end
  end

  # A blocked admission remains queued; an unknown result stops this run because retrying it could duplicate bytes.
  defp admit(state, field) do
    {items, error, started} =
      Enum.reduce(Map.fetch!(state, field), {[], nil, state.bidi_started}, fn {stream, bytes,
                                                                               final},
                                                                              {acc, error,
                                                                               started} ->
        if not is_nil(error) or (bytes == <<>> and not final) do
          {acc, error, started}
        else
          n = min(@chunk, byte_size(bytes))
          <<part::binary-size(^n), rest::binary>> = bytes

          fin =
            final and rest == <<>> and
              (field != :sends or not bidi?(stream.id) or MapSet.size(started) == 4)

          case Adapter.send_stream(stream, part, fin, deadline: @deadline) do
            {:ok, _} ->
              started =
                if field == :sends and bidi?(stream.id) and part != <<>>,
                  do: MapSet.put(started, stream.id),
                  else: started

              remaining =
                if rest == <<>> and (not final or fin),
                  do: acc,
                  else: acc ++ [{stream, rest, final}]

              {remaining, nil, started}

            {:blocked, _} ->
              {acc ++ [{stream, bytes, final}], nil, started}

            {:unknown, ref} ->
              {acc ++ [{stream, bytes, final}], {:unknown, ref}, started}

            {:error, reason} ->
              {acc ++ [{stream, bytes, final}], reason, started}
          end
        end
      end)

    if error,
      do: throw({:harness_failure, error}),
      else: Map.put(%{state | bidi_started: started}, field, items)
  end

  defp cancel_active_stream(%{cancelled_sent: true} = state), do: state

  defp cancel_active_stream(state) do
    if MapSet.size(state.bidi_started) == 4 do
      case Adapter.send_stream(state.cancelled, "cancel") do
        {:ok, _} ->
          {:ok, _} = Adapter.reset_stream(state.cancelled, 0x51)
          %{state | cancelled_sent: true}

        {:blocked, _} ->
          state

        error ->
          raise("cancel admission #{inspect(error)}")
      end
    else
      state
    end
  end

  defp event({:stream_open, stream, _kind}, state),
    do: put_in(state, [:opened, stream.id], stream)

  defp event(_event, state), do: state

  defp drain_all(state),
    do: Enum.reduce(state.opened, state, fn {_, stream}, s -> drain(stream, s) end)

  defp drain(stream, state) do
    case Adapter.read(stream, 1024) do
      {:ok, items} ->
        state = Enum.reduce(items, state, &read_item(&1, stream, &2))
        %{state | reads: state.reads + 1}

      {:error, :would_block} ->
        state

      {:error, reason} ->
        throw({:harness_failure, {:read, reason}})
    end
  end

  defp read_item({:data, id, bytes}, stream, state) do
    state = update_in(state, [:bytes], &Map.update(&1, id, bytes, fn old -> old <> bytes end))

    if bidi?(id) and not local?(state.role, id),
      do: update_in(state, [:echoes], &(&1 ++ [{stream, bytes, false}])),
      else: state
  end

  defp read_item({:fin, id}, stream, state) do
    state = update_in(state, [:fins], &MapSet.put(&1, id))

    if bidi?(id) and not local?(state.role, id),
      do: update_in(state, [:echoes], &(&1 ++ [{stream, <<>>, true}])),
      else: state
  end

  defp read_item({:reset, id, 0x51, _}, _stream, state) do
    expected = if state.role == "client", do: 17, else: 16
    if id != expected, do: raise("unexpected reset #{id}")
    %{state | reset_seen: true}
  end

  defp finish_uni(%{uni_fin_sent: true} = state), do: state

  defp finish_uni(state) do
    remote_bit = if state.role == "client", do: 1, else: 0

    received =
      Enum.all?(0..2, fn n ->
        id = remote_bit + 2 + 4 * n
        state.bytes[id] == "uni:#{id}"
      end)

    sent = not Enum.any?(state.sends, fn {stream, _, _} -> not bidi?(stream.id) end)

    if received and sent do
      for stream <- state.uni, do: {:ok, _} = Adapter.send_stream(stream, <<>>, true)
      %{state | uni_fin_sent: true}
    else
      state
    end
  end

  defp collect_peer(state, peer) do
    receive do
      {^peer, {:data, {:eol, line}}} ->
        verified =
          case JSON.decode(line) do
            {:ok, %{"event" => "summary", "passed" => true}} -> true
            _ -> false
          end

        collect_peer(
          %{
            state
            | peer_events: [line | state.peer_events],
              peer_verified: state.peer_verified or verified
          },
          peer
        )

      {^peer, {:exit_status, code}} ->
        throw({:harness_failure, {:peer_exit, code}})
    after
      0 -> state
    end
  end

  defp complete?(state) do
    replies =
      Enum.all?(state.bidi, fn s ->
        state.bytes[s.id] == state.expected[s.id] and MapSet.member?(state.fins, s.id)
      end)

    remote_bit = if state.role == "client", do: 1, else: 0
    remote_bidi = for index <- 0..3, do: remote_bit + 4 * index
    remote_uni = for index <- 0..2, do: remote_bit + 2 + 4 * index

    remote_ok =
      Enum.all?(remote_bidi, fn id ->
        state.bytes[id] == state.expected[id] and
          MapSet.member?(state.fins, id)
      end) and
        Enum.all?(remote_uni, fn id ->
          state.bytes[id] == "uni:#{id}" and MapSet.member?(state.fins, id)
        end)

    replies and remote_ok and state.sends == [] and state.echoes == [] and
      state.peer_verified and state.reset_seen and state.uni_fin_sent and state.cancelled_sent
  end

  defp sample(handle) do
    {:ok, %{highwaters: r}} = Adapter.info(handle)

    r
    |> Map.put(:mailbox, Process.info(self(), :message_queue_len) |> elem(1))
  end

  defp finish(state) do
    h = state.highwaters

    ticket_parsed = state.role == "client" and h.application_crypto_bytes >= 89

    limits_ok =
      (state.role != "client" or ticket_parsed) and
        h.ready_bytes <= @chunk and h.receive_buffered_bytes <= @chunk and
        h.queued_bytes <= 1_048_576 and h.operations <= 256 and h.event_count <= 128 and
        h.recovery_packets <= 4096 and h.stream_records <= 1024 and h.pending_datagrams <= 64 and
        h.mailbox <= 128 and h.in_flight_sends <= 128 and
        h.io_queue_entries <= 128 and h.io_queue_bytes <= 1_048_576 and
        h.operation_result_bytes <= 8_388_608 and h.tracked_references <= 400 and
        h.mailbox_messages <= 128

    transfer_ms = now() - state.started_at
    handle = state.handle
    :ok = Adapter.close(handle)

    cleanup =
      receive do
        {:quic_closed, ^handle, _reason} -> true
      after
        5000 -> false
      end

    %{
      passed: limits_ok and cleanup,
      role: state.role,
      scenario: System.get_env("PHASE1_SCENARIO", "baseline"),
      seed: 28_092_026,
      transfer_ms: transfer_ms,
      alpn: state.metadata.alpn,
      highwaters: h,
      cleanup: cleanup,
      reads: state.reads,
      local_bidi_bytes: 4 * @total,
      remote_bidi_bytes: 4 * @total,
      remote_uni_streams: 3,
      reset_seen: state.reset_seen,
      cancelled_after_admission: state.cancelled_sent,
      bidi_started_before_cancel: MapSet.size(state.bidi_started),
      ticket_parsed: ticket_parsed,
      peer_events: state.peer_events
    }
  end

  defp payload(id),
    do: for(index <- 0..(div(@total, 8) - 1), into: <<>>, do: <<id::32, index::32>>)

  defp bidi?(id), do: Bitwise.band(id, 2) == 0
  defp local?("client", id), do: Bitwise.band(id, 1) == 0
  defp local?("server", id), do: Bitwise.band(id, 1) == 1
  defp now, do: System.monotonic_time(:millisecond)

  defp fail(reason, events, state \\ %{}),
    do: %{
      passed: false,
      failure: inspect(reason),
      peer_events: events,
      highwaters: Map.get(state, :highwaters, %{})
    }

  defp endpoint("client", f),
    do: Adapter.client("example.test", tls(f, "client"), streams: limits())

  defp limits,
    do: [
      max_data: @chunk,
      max_stream_data: @chunk,
      max_streams_bidi: 8,
      max_streams_uni: 3,
      max_buffer: @chunk,
      max_ready_bytes: @chunk,
      delivery: :manual
    ]

  defp peer("client", _ep, f),
    do:
      port("server", ["--cert", Path.join(f, "leaf.pem"), "--key", Path.join(f, "leaf-key.pem")])

  defp port(role, args) do
    venv = Process.get(:peer_script) <> ".venv"
    {_output, 0} = System.cmd("uv", ["venv", "--python", "3.12", venv])
    python = Path.join(venv, "bin/python")
    {_output, 0} = System.cmd("uv", ["pip", "install", "--python", python, "aioquic==1.2.0"])

    Port.open({:spawn_executable, python}, [
      :binary,
      :exit_status,
      :use_stdio,
      :stderr_to_stdout,
      {:line, 65_536},
      {:args,
       [
         Process.get(:peer_script),
         "--scenario",
         System.get_env("PHASE1_SCENARIO", "baseline"),
         "--seed",
         "28092026",
         "--role",
         role | args
       ]}
    ])
  end

  defp stop_peer(peer) do
    case Port.info(peer, :os_pid) do
      {:os_pid, pid} ->
        # Spawn Python directly, so this PID is the peer, not a launcher whose
        # child could outlive Port.close/1. Reap the exit before leaving.
        {_output, 0} = System.cmd("kill", ["-TERM", Integer.to_string(pid)])

        receive do
          {^peer, {:exit_status, _status}} -> :ok
        after
          5_000 -> raise("independent peer cleanup timeout")
        end

      nil ->
        :ok
    end
  end

  defp start_boundary_trace do
    tracer = spawn_link(fn -> trace_calls(0) end)

    for module <- [:quic, :quic_h3] do
      {:module, ^module} = Code.ensure_loaded(module)
      count = :erlang.trace_pattern({module, :_, :_}, true, [:local])
      true = count > 0
    end

    :erlang.trace(self(), true, [:call, :set_on_spawn, {:tracer, tracer}])
    tracer
  end

  defp trace_calls(count) do
    receive do
      {:trace, _pid, :call, _call} ->
        trace_calls(count + 1)

      {:report, owner} ->
        send(owner, {:legacy_calls, count})
        trace_calls(count)

      :stop ->
        :ok
    end
  end

  defp verify_boundary_trace(tracer) do
    ref = :erlang.trace_delivered(:all)

    receive do
      {:trace_delivered, :all, ^ref} -> :ok
    after
      5_000 -> raise("trace delivery timeout")
    end

    send(tracer, {:report, self()})

    receive do
      {:legacy_calls, 0} -> :ok
      {:legacy_calls, count} -> raise("legacy QUIC calls: #{count}")
    after
      5_000 -> raise("trace result timeout")
    end
  end

  defp tls(f, "client"),
    do: [
      cacerts: [der(Path.join(f, "root.pem"))],
      reference_identity: {:dns_id, "example.test"},
      alpn: [@alpn]
    ]

  defp der(p),
    do:
      (
        [{:Certificate, b, :not_encrypted}] = :public_key.pem_decode(File.read!(p))
        b
      )
end

HTTP.Phase1.Independent.run()

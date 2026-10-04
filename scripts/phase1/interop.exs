# Run after Q5: PHASE1_INTEROP_RUN=1 mix run scripts/phase1/interop.exs client|server
defmodule Quic.Phase1.Interop do
  @alpn "phase1-streams"
  @chunk 16_384
  @total 262_144
  @deadline 15_000

  def run([role]) when role in ["client", "server"] do
    fixture = Path.expand("../../apps/elixir_quic/test/fixtures/tls", __DIR__)
    {:ok, endpoint} = endpoint(role, fixture)
    peer = peer(role, endpoint, fixture)
    result = await_handle(role, endpoint, peer, now() + @deadline, [])
    routes = Quic.Endpoint.stats(endpoint).routes
    GenServer.stop(endpoint)
    external = cleanup_external()
    if Port.info(peer), do: Port.close(peer)

    result =
      Map.merge(result, %{
        routes_after_cleanup: routes,
        external: external,
        passed: result.passed and routes == 0
      })

    IO.puts(JSON.encode!(result))
    if result.passed, do: :ok, else: System.halt(1)
  end

  def run(_), do: raise("usage: mix run scripts/phase1/interop.exs client|server")

  defp await_handle(role, endpoint, peer, deadline, events) do
    if now() >= deadline do
      fail(:handshake_deadline, events)
    else
      receive do
        {:quic_accept, ^endpoint} when role == "server" ->
          {:ok, handle} = Quic.accept(endpoint)
          activate(role, handle, peer, deadline, events)

        {^peer, {:data, {:eol, line}}} when role == "client" ->
          case JSON.decode(line) do
            {:ok, %{"event" => "listening", "port" => port}} ->
              {:ok, handle} = Quic.connect(endpoint, {{127, 0, 0, 1}, port})
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
    :ok = Quic.attach(handle, self())

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
    {:ok, cancelled} = Quic.open_stream(handle, :bidi)

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
        {:ok, s} = Quic.open_stream(handle, kind)
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

      {:ok, events} = Quic.events(state.handle, 128)

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

          case Quic.send_stream(stream, part, fin, deadline: @deadline) do
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
      case Quic.send_stream(state.cancelled, "cancel") do
        {:ok, _} ->
          {:ok, _} = Quic.reset_stream(state.cancelled, 0x51)
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
    case Quic.read(stream, 1024) do
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
      for stream <- state.uni, do: {:ok, _} = Quic.send_stream(stream, <<>>, true)
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
    {:ok, %{highwaters: r}} = Quic.info(handle)

    r
    |> Map.put(:mailbox, Process.info(self(), :message_queue_len) |> elem(1))
    |> Map.put(:connection_mailbox, Process.info(handle.id, :message_queue_len) |> elem(1))
  end

  defp finish(state) do
    h = state.highwaters

    ticket_parsed = state.role == "client" and h.application_crypto_bytes >= 89

    limits_ok =
      (state.role != "client" or ticket_parsed) and
        h.ready_bytes <= @chunk and h.receive_buffered_bytes <= @chunk and
        h.queued_bytes <= 1_048_576 and h.operations <= 256 and h.event_count <= 128 and
        h.recovery_packets <= 4096 and h.stream_records <= 1024 and h.pending_datagrams <= 64 and
        h.mailbox <= 128 and h.connection_mailbox <= 128 and h.in_flight_sends <= 128 and
        h.io_queue_entries <= 128 and h.io_queue_bytes <= 1_048_576 and
        h.operation_result_bytes <= 8_388_608 and h.tracked_references <= 400 and
        h.mailbox_messages <= 128

    transfer_ms = now() - state.started_at
    monitor = Process.monitor(state.handle.id)
    :ok = Quic.close(state.handle)

    cleanup =
      receive do
        {:DOWN, ^monitor, :process, _, _} -> true
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

  defp endpoint("client", f), do: Quic.client(tls: tls(f, "client"), streams: limits())

  defp endpoint("server", f) do
    opts = [tls: tls(f, "server"), streams: limits()]

    if System.get_env("PHASE1_EXTERNAL") == "1" do
      {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, local} = :inet.sockname(socket)
      counters = :counters.new(2, [])

      sender = fn {ip, port}, bytes ->
        :counters.add(counters, 1, 1)
        :counters.add(counters, 2, byte_size(bytes))
        :gen_udp.send(socket, ip, port, bytes)
      end

      {:ok, endpoint} = Quic.listen(Keyword.put(opts, :io, {:external, local, sender}))

      pump =
        spawn_link(fn ->
          receive do
            {:start, ep} -> external_ingress(socket, ep)
          end
        end)

      :ok = :gen_udp.controlling_process(socket, pump)
      send(pump, {:start, endpoint})
      Process.put(:external_fixture, {pump, counters})
      {:ok, endpoint}
    else
      Quic.listen(opts)
    end
  end

  defp external_ingress(socket, endpoint) do
    receive do
      :stop -> :gen_udp.close(socket)
    after
      0 ->
        case :gen_udp.recv(socket, 0, 100) do
          {:ok, {ip, port, bytes}} ->
            if Process.alive?(endpoint),
              do:
                Quic.Endpoint.receive_datagram(
                  endpoint,
                  {ip, port},
                  bytes,
                  System.monotonic_time(:microsecond)
                )

            external_ingress(socket, endpoint)

          {:error, :timeout} ->
            external_ingress(socket, endpoint)
        end
    end
  end

  defp cleanup_external do
    case Process.get(:external_fixture) do
      nil ->
        false

      {pump, counters} ->
        monitor = Process.monitor(pump)
        send(pump, :stop)

        receive do
          {:DOWN, ^monitor, :process, ^pump, :normal} -> :ok
        after
          1000 -> raise("external fixture cleanup deadline")
        end

        %{sends: :counters.get(counters, 1), bytes: :counters.get(counters, 2), cleaned: true}
    end
  end

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

  defp peer("server", ep, f),
    do:
      port("client", [
        "--port",
        Integer.to_string(elem(Quic.local(ep), 1)),
        "--ca",
        Path.join(f, "root.pem")
      ])

  defp peer("client", _ep, f),
    do:
      port("server", ["--cert", Path.join(f, "leaf.pem"), "--key", Path.join(f, "leaf-key.pem")])

  defp port(role, args),
    do:
      Port.open({:spawn_executable, System.find_executable("uv")}, [
        :binary,
        :exit_status,
        :use_stdio,
        :stderr_to_stdout,
        {:line, 65_536},
        {:args,
         [
           "run",
           "--python",
           "3.12",
           "--with",
           "aioquic==1.2.0",
           "python",
           "scripts/phase1/peer.py",
           "--scenario",
           System.get_env("PHASE1_SCENARIO", "baseline"),
           "--seed",
           "28092026",
           "--role",
           role | args
         ]}
      ])

  defp tls(f, "server") do
    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(f, "leaf-key.pem")))

    [cert: [der(Path.join(f, "leaf.pem"))], key: {type, key}, alpn: [@alpn]]
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

if System.get_env("PHASE1_INTEROP_RUN") == "1", do: Quic.Phase1.Interop.run(System.argv())

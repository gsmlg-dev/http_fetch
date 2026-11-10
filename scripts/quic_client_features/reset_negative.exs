Code.require_file("relay.exs", __DIR__)

defmodule Quic.ClientFeatures.ResetNegative do
  @moduledoc false
  # Bounded draft-11 reliable-reset negative matrix against unmodified quic-go
  # v0.62.0 (`peer.go --mode matrix`). Every case owns one Cleanup scope and a
  # test-owned relay (relay.exs) that drops or reverses whole 1-RTT datagrams.
  # The orchestrator (`wire_gates.py`) checks the peer's application receipts
  # and its qlog frames against what this driver prints.
  alias Quic.ClientFeatures.Relay

  @fixture "apps/elixir_quic/test/fixtures/tls"
  @loopback {127, 0, 0, 1}

  def root do
    [{:Certificate, cert, :not_encrypted}] =
      @fixture |> Path.join("root.pem") |> File.read!() |> :public_key.pem_decode()

    cert
  end

  def now, do: System.monotonic_time(:millisecond)
  def emit(map), do: IO.puts(JSON.encode!(map))
  def sha(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  # Matches the peer's `pattern/2`.
  def pattern(offset, length),
    do: for(i <- offset..(offset + length - 1)//1, into: <<>>, do: <<rem(i, 251)>>)

  def wait(check, deadline, label) do
    case check.() do
      result when result in [false, nil] ->
        if now() >= deadline, do: raise("deadline exceeded: #{label}")
        current = Process.get(:connection)

        receive do
          {:quic_closed, ^current, reason} -> raise("connection closed: #{inspect(reason)}")
        after
          5 -> wait(check, deadline, label)
        end

      result ->
        result
    end
  end

  def expect!(ctx, label, actual, expected) do
    unless actual == expected do
      raise("#{ctx.case}/#{label}: expected #{inspect(expected)}, got #{inspect(actual)}")
    end

    emit(%{event: "assert", case: ctx.case, label: label, value: inspect(actual)})
  end

  def session(port, name, fun) do
    {:ok, _cleanup, lease} = Quic.Cleanup.new()
    relay = Relay.start(port)
    started = System.os_time(:nanosecond)

    {:ok, endpoint} =
      Quic.client(
        cleanup: lease,
        reliable_reset: true,
        tls: [
          reference_identity: {:dns_id, "example.test"},
          cacerts: [root()],
          alpn: ["ex-quic-m2"]
        ]
      )

    ctx = %{case: name, endpoint: endpoint, relay: relay}

    try do
      {:ok, connection} = Quic.connect(endpoint, {@loopback, relay.port})
      Process.put(:connection, connection)
      :ok = Quic.attach(connection, self())
      ctx = Map.put(ctx, :connection, connection)

      wait(
        fn -> match?({:ok, %{quic_confirmed: true}}, Quic.info(connection)) end,
        now() + 8000,
        "#{name} confirmation"
      )

      fun.(ctx)
    after
      stats = Relay.stop(relay)
      emit(%{event: "relay", case: name, peer_view: relay.peer_view, stats: stats})

      case Quic.Cleanup.retire(lease, {:abs_ms, now() + 5000}) do
        {:ok, receipt} ->
          emit(%{event: "cleanup", case: name, receipt: Map.drop(receipt, [:generation])})

        outcome ->
          raise("#{name}: cleanup unconfirmed: #{inspect(outcome)}")
      end

      emit(%{
        event: "case",
        case: name,
        peer_view: relay.peer_view,
        started_ns: started,
        finished_ns: System.os_time(:nanosecond)
      })
    end
  end

  def packets(ctx), do: Quic.Connection.status(ctx.connection.id).packets.application

  # Every ack-eliciting packet sent so far is acknowledged (nothing in flight)
  # and nothing is queued, so the peer holds everything this runtime sent,
  # including any reset frames. ACK-only packets are never acknowledged and
  # are therefore judged by bytes in flight, read from the connection state.
  def quiesce(ctx) do
    wait(
      fn ->
        {_, state} = :sys.get_state(ctx.connection.id)
        packets(ctx).queued == 0 and state.scheduler.recovery.congestion.bytes_in_flight == 0
      end,
      now() + 10_000,
      "#{ctx.case} quiescence"
    )
  end

  # Reads one stream until `done?` holds on {bytes, resets, fin}.
  def collect(ctx, stream, done?, label, ms \\ 8000) do
    Process.put({:collect, stream.id}, {<<>>, [], false})

    wait(
      fn ->
        {:ok, items} = Quic.read(stream, 16_384)

        state =
          Enum.reduce(items, Process.get({:collect, stream.id}), fn
            {:data, _, bytes}, {acc, resets, fin} -> {acc <> bytes, resets, fin}
            {:reset, _, code, final}, {acc, resets, fin} -> {acc, resets ++ [{code, final}], fin}
            {:fin, _}, {acc, resets, _} -> {acc, resets, true}
          end)

        Process.put({:collect, stream.id}, state)
        if done?.(state), do: state, else: false
      end,
      now() + ms,
      "#{ctx.case} #{label}"
    )
  end

  def report(ctx, stream) do
    {bytes, [], true} = collect(ctx, stream, fn {_, _, fin} -> fin end, "peer report")
    JSON.decode!(bytes)
  end

  # ------------------------------------------------------------ runtime -> peer

  # Prefix data and RESET_STREAM_AT are sent while the relay drops (or holds and
  # then reverses) every runtime->peer 1-RTT datagram; the peer application
  # must still read the complete reliable prefix followed by the reset code.
  def outgoing(port, name, relay_mode) do
    session(port, name, fn ctx ->
      {:ok, stream} = Quic.open_stream(ctx.connection, :bidi)
      header = "sink\n"
      payload = header <> pattern(0, 8000 - byte_size(header))
      :ok = Relay.mode(ctx.relay, :c2s, relay_mode)
      {:ok, _} = Quic.send_stream(stream, payload, false)
      {:ok, ref} = Quic.reset_stream_at(stream, 42, 6000)
      {:ok, ^ref} = Quic.reset_stream_at(stream, 42, 6000, ref: ref)
      admitted = System.os_time(:nanosecond)

      if relay_mode == :drop do
        Process.sleep(250)
        :ok = Relay.mode(ctx.relay, :c2s, :pass)
      end

      window_end = System.os_time(:nanosecond)

      peer = report(ctx, stream)
      quiesce(ctx)
      expect!(ctx, "peer_reset_code", {peer["reset_code"], peer["reset_remote"]}, {42, true})
      received = peer["bytes"]
      expect!(ctx, "peer_prefix_complete", received >= 6000 and received <= 8000, true)
      expect!(ctx, "peer_bytes_exact", peer["sha256"], sha(binary_part(payload, 0, received)))
      stats = Relay.stats(ctx.relay)

      if relay_mode == :drop do
        expect!(ctx, "relay_dropped", stats.c2s.dropped > 0, true)
      else
        expect!(ctx, "relay_reversed", Enum.any?(stats.c2s.holds, &(&1.count >= 2)), true)
      end

      emit(%{
        event: "outgoing",
        case: ctx.case,
        stream: stream.id,
        reliable_size: 6000,
        final_size: 8000,
        code: 42,
        peer_bytes: received,
        mode: if(relay_mode == :drop, do: "drop", else: "reverse"),
        admitted_ns: admitted,
        window_end_ns: window_end
      })
    end)
  end

  # ------------------------------------------------------------ peer -> runtime

  # quic-go writes 6000 prefix bytes, marks the reliable boundary, writes 2000
  # more and resets with code 43, while the relay drops (or reverses) every
  # peer->runtime 1-RTT datagram. The runtime must deliver exactly the prefix
  # (possibly more of the written bytes) and then exactly one reset.
  def incoming(port, name, relay_mode) do
    session(port, name, fn ctx ->
      {:ok, stream} = Quic.open_stream(ctx.connection, :bidi)
      armed = System.os_time(:nanosecond)
      :ok = Relay.mode(ctx.relay, :s2c, relay_mode)
      {:ok, _} = Quic.send_stream(stream, "reset 6000 8000 43\n", true)

      if relay_mode == :drop do
        Process.sleep(250)
        :ok = Relay.mode(ctx.relay, :s2c, :pass)
      end

      {bytes, resets, _} = collect(ctx, stream, fn {_, resets, _} -> resets != [] end, "reset")
      # Nothing may follow the single reset.
      Process.sleep(200)
      {:ok, []} = Quic.read(stream, 16_384)
      expect!(ctx, "single_reset", resets, [{43, 8000}])
      expect!(ctx, "prefix_complete", byte_size(bytes) >= 6000 and byte_size(bytes) <= 8000, true)
      expect!(ctx, "bytes_exact", bytes, pattern(0, byte_size(bytes)))
      stats = Relay.stats(ctx.relay)

      if relay_mode == :drop,
        do: expect!(ctx, "relay_dropped", stats.s2c.dropped > 0, true),
        else: expect!(ctx, "relay_reversed", Enum.any?(stats.s2c.holds, &(&1.count >= 2)), true)

      emit(%{
        event: "incoming",
        case: ctx.case,
        stream: stream.id,
        received: byte_size(bytes),
        sha256: sha(bytes),
        code: 43,
        final_size: 8000,
        mode: if(relay_mode == :drop, do: "drop", else: "reverse"),
        armed_ns: armed
      })
    end)
  end

  # ----------------------------------------------------------- STOP_SENDING

  # The peer reads 1000 bytes, then sends STOP_SENDING(77). The relay drops
  # runtime->peer datagrams, so quic-go never sees our ACK or answer and
  # retransmits STOP_SENDING; every answer must be the same RESET_STREAM_AT.
  # quic-go waits 1.5 s before STOP_SENDING so the drop is armed first even on
  # a slow host; the gate checks that ordering in quic-go's own trace.
  def stop_repeat(port) do
    session(port, "stop_repeat", fn ctx ->
      {:ok, stream} = Quic.open_stream(ctx.connection, :bidi, reliable_prefix: 1500)
      header = "stop 1000 77 1500\n"
      payload = header <> pattern(0, 2000 - byte_size(header))
      {:ok, _} = Quic.send_stream(stream, payload, false)
      quiesce(ctx)
      armed = System.os_time(:nanosecond)
      :ok = Relay.mode(ctx.relay, :c2s, :drop)
      peer = report(ctx, stream)
      expect!(ctx, "peer_stop_sent", peer["code"], 77)
      Process.sleep(1200)
      :ok = Relay.mode(ctx.relay, :c2s, :pass)
      quiesce(ctx)
      expect!(ctx, "relay_dropped", Relay.stats(ctx.relay).c2s.dropped > 0, true)

      emit(%{
        event: "stop_answer",
        case: ctx.case,
        stream: stream.id,
        code: 77,
        reliable_size: 1500,
        final_size: 2000,
        repeated: true,
        armed_ns: armed
      })
    end)
  end

  # Declared prefix 4096 but only 100 bytes admitted: the answer carries
  # reliable size == final size == 100. A local reset beyond the admitted
  # offset is refused and leaves the stream usable.
  def prefix_beyond_admitted(port) do
    session(port, "prefix_beyond_admitted", fn ctx ->
      {:ok, probe} = Quic.open_stream(ctx.connection, :bidi)
      {:ok, _} = Quic.send_stream(probe, "sink\n", false)

      expect!(
        ctx,
        "local_reset_beyond_admitted",
        Quic.reset_stream_at(probe, 1, 6),
        {:error, :invalid_reliable_size}
      )

      {:ok, _} = Quic.reset_stream_at(probe, 1, 5)
      {:ok, stream} = Quic.open_stream(ctx.connection, :bidi, reliable_prefix: 4096)
      header = "stop 50 78 0\n"
      payload = header <> pattern(0, 100 - byte_size(header))
      {:ok, _} = Quic.send_stream(stream, payload, false)
      peer = report(ctx, stream)
      expect!(ctx, "peer_stop_sent", peer["code"], 78)
      quiesce(ctx)

      emit(%{
        event: "stop_answer",
        case: ctx.case,
        stream: stream.id,
        code: 78,
        reliable_size: 100,
        final_size: 100,
        repeated: false
      })

      probe_report = report(ctx, probe)

      expect!(
        ctx,
        "refused_reset_left_stream_usable",
        {probe_report["bytes"], probe_report["reset_code"]},
        {5, 1}
      )
    end)
  end

  # ------------------------------------------------------- not negotiated

  # The peer does not advertise reset_stream_at: reset_stream_at is refused
  # (never downgraded) and a prefixed stream answers STOP_SENDING with an
  # ordinary RESET_STREAM.
  def not_negotiated(port) do
    session(port, "not_negotiated", fn ctx ->
      {:ok, info} = Quic.info(ctx.connection)

      expect!(ctx, "negotiation", info.reliable_reset, %{
        draft: 11,
        local: true,
        peer: false,
        negotiated: false
      })

      {:ok, plain} = Quic.open_stream(ctx.connection, :bidi)
      {:ok, _} = Quic.send_stream(plain, "sink\n", false)

      expect!(
        ctx,
        "reset_stream_at_refused",
        Quic.reset_stream_at(plain, 42, 5),
        {:error, :reliable_reset_not_negotiated}
      )

      {:ok, _} = Quic.send_stream(plain, "after-refusal", true)
      peer = report(ctx, plain)
      expect!(ctx, "stream_usable_after_refusal", {peer["bytes"], peer["fin"]}, {18, true})
      {:ok, stream} = Quic.open_stream(ctx.connection, :bidi, reliable_prefix: 13)
      header = "stop 50 79 0\n"
      {:ok, _} = Quic.send_stream(stream, header <> pattern(0, 100 - byte_size(header)), false)
      peer = report(ctx, stream)
      expect!(ctx, "peer_stop_sent", peer["code"], 79)
      quiesce(ctx)

      emit(%{
        event: "stop_answer",
        case: ctx.case,
        stream: stream.id,
        code: 79,
        reliable_size: 0,
        final_size: 100,
        repeated: false
      })
    end)
  end

  def run(port, "matrix") do
    outgoing(port, "outgoing_loss", :drop)
    outgoing(port, "outgoing_reorder", {:hold, 64, 150})
    incoming(port, "incoming_loss", :drop)
    incoming(port, "incoming_reorder", {:hold, 64, 150})
    stop_repeat(port)
    prefix_beyond_admitted(port)
    emit(%{event: "suite", suite: "matrix", passed: true})
  end

  def run(port, "not-negotiated") do
    not_negotiated(port)
    emit(%{event: "suite", suite: "not-negotiated", passed: true})
  end
end

[port, suite] = System.argv()
Quic.ClientFeatures.ResetNegative.run(String.to_integer(port), suite)

defmodule Quic.ClientFeatures.ResumptionNegative do
  @moduledoc false
  # Bounded R1 (resumption) and R2 (0-RTT) negative matrices for the client
  # role against unmodified quic-go v0.62.0 (`peer.go --mode matrix`). Every
  # case owns its Cleanup scope(s); the orchestrator (`wire_gates.py`) matches
  # every connection printed here with the peer's own TLS/QUIC observations
  # (handshake, ticket presentation, stream receipts) by client address.

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
  def address({{a, b, c, d}, port}), do: "#{a}.#{b}.#{c}.#{d}:#{port}"

  def wait(check, deadline, label) do
    case check.() do
      result when result in [false, nil] ->
        if now() >= deadline, do: raise("deadline exceeded: #{label}")

        receive do
          {:quic_closed, _, {:application, 0, _}} -> :ok
          {:quic_closed, _, reason} when reason in [:closed, :peer_closed] -> :ok
          {:quic_closed, _, reason} -> raise("#{label}: connection closed: #{inspect(reason)}")
        after
          5 -> :ok
        end

        wait(check, deadline, label)

      result ->
        result
    end
  end

  def expect!(name, label, actual, expected) do
    unless actual == expected do
      raise("#{name}/#{label}: expected #{inspect(expected)}, got #{inspect(actual)}")
    end

    emit(%{event: "assert", case: name, label: label, value: inspect(actual)})
  end

  # One endpoint = one Cleanup scope and one local address. `early: true`
  # additionally opts in to R2.
  def endpoint(name, early) do
    {:ok, _cleanup, lease} = Quic.Cleanup.new()

    {:ok, endpoint} =
      Quic.client(
        [
          cleanup: lease,
          resumption: [enabled: true, application_profile: "raw-r1-v1"],
          datagram: [max_frame_size: 1200],
          closing_timeout: 10,
          draining_timeout: 10,
          tls: [
            reference_identity: {:dns_id, "example.test"},
            cacerts: [root()],
            alpn: ["ex-quic-r1"]
          ]
        ] ++
          if(early,
            do: [early_data: [enabled: true, application_profile: "early-raw-v1"]],
            else: []
          )
      )

    local = address(Quic.local(endpoint))
    emit(%{event: "endpoint", case: name, local: local, early: early})
    %{case: name, endpoint: endpoint, lease: lease, local: local}
  end

  def retire(ep) do
    case Quic.Cleanup.retire(ep.lease, {:abs_ms, now() + 5000}) do
      {:ok, receipt} ->
        emit(%{
          event: "cleanup",
          case: ep.case,
          local: ep.local,
          receipt: Map.drop(receipt, [:generation])
        })

      outcome ->
        raise("#{ep.case}: cleanup unconfirmed: #{inspect(outcome)}")
    end
  end

  def scoped(name, fun) do
    emit(%{event: "case_start", case: name})
    fun.()
    emit(%{event: "case_end", case: name})
  end

  def tickets(ep), do: Quic.Endpoint.stats(ep.endpoint).resumption.tickets

  def connect(ep, port) do
    {:ok, connection} = Quic.connect(ep.endpoint, {@loopback, port})
    :ok = Quic.attach(connection, self())
    connection
  end

  def ready(ep, connection) do
    wait(fn -> Quic.ready(connection) == :ready end, now() + 10_000, "#{ep.case} ready")
    {:ok, info} = Quic.info(connection)
    info
  end

  # Exact echo of `payload` (prefixed with the peer's echo command) plus FIN.
  def echo(_ep, stream, payload, opts \\ []) do
    data = "echo\n" <> payload
    {:ok, _} = Quic.send_stream(stream, data, true, opts)
    data
  end

  def await_echo(ep, stream, data) do
    Process.put({:echo, stream.id}, {<<>>, false})

    wait(
      fn ->
        {:ok, items} = Quic.read(stream, 16_384)

        state =
          Enum.reduce(items, Process.get({:echo, stream.id}), fn
            {:data, _, bytes}, {acc, fin} -> {acc <> bytes, fin}
            {:fin, _}, {acc, _} -> {acc, true}
          end)

        Process.put({:echo, stream.id}, state)
        match?({_, true}, state)
      end,
      now() + 10_000,
      "#{ep.case} echo"
    )

    {echoed, true} = Process.get({:echo, stream.id})
    expect!(ep.case, "echo_exact/#{stream.id}", sha(echoed), sha(data))

    emit(%{
      event: "echo",
      case: ep.case,
      local: ep.local,
      bytes: byte_size(data),
      sha256: sha(data)
    })
  end

  def round_trip(ep, connection, payload) do
    {:ok, stream} = Quic.open_stream(connection, :bidi)
    data = echo(ep, stream, payload)
    await_echo(ep, stream, data)
  end

  def close(ep, connections) do
    connections |> List.wrap() |> Enum.each(&(:ok = Quic.close(&1)))
    wait(fn -> Quic.Endpoint.connections(ep.endpoint) == [] end, now() + 5000, "#{ep.case} close")
  end

  def record(ep, index, info, extra \\ %{}) do
    emit(
      Map.merge(
        %{
          event: "connection",
          case: ep.case,
          local: ep.local,
          index: index,
          resumed: info.resumption.resumed,
          early_data: info.resumption.early_data
        },
        extra
      )
    )
  end

  # A full handshake that leaves exactly the ticket(s) the peer issued.
  def prime(ep, port, index \\ 0) do
    connection = connect(ep, port)
    info = ready(ep, connection)
    round_trip(ep, connection, "#{ep.case}/prime/#{index}")
    wait(fn -> tickets(ep) > 0 end, now() + 3000, "#{ep.case} ticket")
    record(ep, index, info, %{tickets_after: tickets(ep)})
    close(ep, connection)
    info
  end

  def rotate(ep, port, index) do
    connection = connect(ep, port)
    ready(ep, connection)
    {:ok, stream} = Quic.open_stream(connection, :bidi)
    {:ok, _} = Quic.send_stream(stream, "rotate\n", true)
    Process.put({:echo, stream.id}, {<<>>, false})

    wait(
      fn ->
        {:ok, items} = Quic.read(stream, 16_384)

        Enum.any?(items, &match?({:fin, _}, &1)) or
          Enum.any?(items, &match?({:data, _, "rotated\n"}, &1))
      end,
      now() + 5000,
      "#{ep.case} rotate"
    )

    {:ok, info} = Quic.info(connection)
    record(ep, index, info, %{rotated: true})
    close(ep, connection)
  end

  # ------------------------------------------------------------------- R1

  # A ticket is bound to the remote server: the peer's second listener (same
  # process, same ticket keys, so it *could* decrypt it) never sees it, and the
  # first listener still resumes afterwards.
  def partition_by_remote([port_a, port_b]) do
    scoped("partition_by_remote", fn ->
      ep = endpoint("partition_by_remote", false)
      prime(ep, port_a, 0)
      expect!(ep.case, "tickets_before_other_server", tickets(ep) > 0, true)
      other = connect(ep, port_b)
      info = ready(ep, other)
      expect!(ep.case, "other_server_full_handshake", info.resumption.resumed, false)
      round_trip(ep, other, "other-server")
      record(ep, 1, info, %{listener: 1})
      close(ep, other)
      again = connect(ep, port_a)
      info = ready(ep, again)
      expect!(ep.case, "same_server_resumes", info.resumption.resumed, true)
      round_trip(ep, again, "same-server")
      record(ep, 2, info)
      close(ep, again)
      retire(ep)
    end)
  end

  # Tickets live only in the endpoint's memory: a new endpoint with identical
  # configuration starts without any ticket.
  def endpoint_restart([port | _]) do
    scoped("endpoint_restart", fn ->
      first = endpoint("endpoint_restart", false)
      prime(first, port, 0)
      retire(first)
      second = endpoint("endpoint_restart", false)
      expect!(second.case, "no_ticket_after_restart", tickets(second), 0)
      connection = connect(second, port)
      info = ready(second, connection)
      expect!(second.case, "restart_full_handshake", info.resumption.resumed, false)
      round_trip(second, connection, "after-restart")
      record(second, 1, info)
      close(second, connection)
      retire(second)
    end)
  end

  # The peer rotates its ticket keys (crypto/tls SetSessionTicketKeys): the
  # stale ticket is offered, cannot be decrypted and the handshake falls back
  # to a full one; the fresh ticket then resumes.
  def stale_ticket([port | _]) do
    scoped("stale_ticket", fn ->
      ep = endpoint("stale_ticket", false)
      prime(ep, port, 0)
      rotate(ep, port, 1)
      stale = connect(ep, port)
      info = ready(ep, stale)
      expect!(ep.case, "stale_ticket_full_handshake", info.resumption.resumed, false)
      round_trip(ep, stale, "stale")
      wait(fn -> tickets(ep) > 0 end, now() + 3000, "#{ep.case} fresh ticket")
      record(ep, 2, info)
      close(ep, stale)
      fresh = connect(ep, port)
      info = ready(ep, fresh)
      expect!(ep.case, "fresh_ticket_resumes", info.resumption.resumed, true)
      round_trip(ep, fresh, "fresh")
      record(ep, 3, info)
      close(ep, fresh)
      retire(ep)
    end)
  end

  # One stored ticket, two connections started back to back: exactly one
  # can claim it.
  def concurrent_single_use([port | _], early \\ false) do
    name = if early, do: "concurrent_early", else: "concurrent_single_use"

    scoped(name, fn ->
      ep = endpoint(name, early)
      prime(ep, port, 0)
      expect!(name, "one_ticket", tickets(ep), 1)

      {first, second, admitted} =
        paused(ep, fn ->
          first = connect(ep, port)
          second = connect(ep, port)
          expect!(name, "ticket_consumed", tickets(ep), 0)

          admitted =
            for connection <- [first, second] do
              case Quic.open_stream(connection, :bidi, early_data: :replayable) do
                {:ok, stream} when early ->
                  data = echo(ep, stream, "#{name}/early", early_data: :replayable)
                  {connection, {stream, data}}

                {:error, :not_established} ->
                  {connection, nil}
              end
            end

          {first, second, admitted}
        end)

      results =
        for {{connection, early_stream}, index} <- Enum.with_index(admitted, 1) do
          info = ready(ep, connection)

          case early_stream do
            {stream, data} -> await_echo(ep, stream, data)
            nil -> round_trip(ep, connection, "#{name}/after-ready/#{index}")
          end

          record(ep, index, info, %{early_admitted: early_stream != nil})
          {info.resumption.resumed, early_stream != nil, info.resumption.early_data}
        end

      expect!(name, "exactly_one_resumed", Enum.count(results, &elem(&1, 0)), 1)

      if early do
        expect!(name, "exactly_one_early", Enum.count(results, &elem(&1, 1)), 1)
        expect!(name, "early_accepted", Enum.find(results, &elem(&1, 1)) |> elem(2), :accepted)
      end

      close(ep, [first, second])
      retire(ep)
    end)
  end

  # Go's crypto/tls server prefers only P-256 (CurvePreferences) while this
  # runtime's key share is X25519: every handshake takes a HelloRetryRequest,
  # and the resumed one must rewrite its binder over the HRR transcript.
  def hrr_resumption([port | _]) do
    scoped("hrr_resumption", fn ->
      ep = endpoint("hrr_resumption", false)
      prime(ep, port, 0)
      connection = connect(ep, port)
      info = ready(ep, connection)
      expect!(ep.case, "resumed_after_hrr", info.resumption.resumed, true)
      round_trip(ep, connection, "hrr-resumed")
      record(ep, 1, info)
      close(ep, connection)
      retire(ep)
    end)
  end

  # ------------------------------------------------------------------- R2

  # Admit early stream + DATAGRAM, let the handshake reject them, prove the
  # old handle is stale, then explicitly re-send on a new stream epoch.
  def rejected_then_resend(ep, port, index, reason) do
    ref = make_ref()
    early = "echo\nearly/#{ep.case}/" <> :binary.copy("e", 200)

    {connection, stream} =
      paused(ep, fn ->
        connection = connect(ep, port)
        {:ok, stream} = Quic.open_stream(connection, :bidi, early_data: :replayable)
        {:ok, ^ref} = Quic.send_stream(stream, early, true, early_data: :replayable, ref: ref)
        {:ok, _} = Quic.send_datagram(connection, "early/#{ep.case}", early_data: :replayable)
        {connection, stream}
      end)

    info = ready(ep, connection)
    expect!(ep.case, "early_rejected", info.resumption.early_data, :rejected)

    expect!(
      ep.case,
      "outcome_rejected",
      Quic.operation_status(connection, ref).outcome,
      {:early_data, :rejected}
    )

    {:ok, events} = Quic.events(connection)
    expect!(ep.case, "rejection_event", {:early_data, ref, :rejected} in events, true)

    expect!(
      ep.case,
      "retained_ref",
      Quic.send_stream(stream, early, true, early_data: :replayable, ref: ref),
      {:ok, ref}
    )

    expect!(
      ep.case,
      "stale_epoch",
      Quic.send_stream(stream, "stale"),
      {:error, :stale_stream_epoch}
    )

    {:ok, replacement} = Quic.open_stream(connection, :bidi)
    expect!(ep.case, "new_epoch", replacement.epoch > stream.epoch, true)
    data = echo(ep, replacement, "resent/#{ep.case}/" <> :binary.copy("r", 200))
    await_echo(ep, replacement, data)

    record(ep, index, info, %{
      rejection: reason,
      early_sha256: sha(early),
      resent_sha256: sha(data)
    })

    close(ep, connection)
    info
  end

  def rejected_by_peer([port | _]) do
    scoped("rejected_by_peer", fn ->
      ep = endpoint("rejected_by_peer", true)
      prime(ep, port, 0)
      info = rejected_then_resend(ep, port, 1, "peer_policy")
      expect!(ep.case, "still_resumed", info.resumption.resumed, true)
      retire(ep)
    end)
  end

  def stale_ticket_early([port | _]) do
    scoped("stale_ticket_early", fn ->
      ep = endpoint("stale_ticket_early", true)
      prime(ep, port, 0)
      rotate(ep, port, 1)
      info = rejected_then_resend(ep, port, 2, "undecryptable_ticket")
      expect!(ep.case, "full_handshake", info.resumption.resumed, false)
      retire(ep)
    end)
  end

  def hrr_early([port | _]) do
    scoped("hrr_early", fn ->
      ep = endpoint("hrr_early", true)
      prime(ep, port, 0)
      info = rejected_then_resend(ep, port, 1, "hello_retry_request")
      expect!(ep.case, "still_resumed", info.resumption.resumed, true)
      retire(ep)
    end)
  end

  # Accepted 0-RTT across a Retry: the runtime requeues its early work for the
  # retried Initial and the peer still receives the exact early stream.
  def retry_early([port | _]) do
    scoped("retry_early", fn ->
      ep = endpoint("retry_early", true)
      prime(ep, port, 0)
      ref = make_ref()
      data = "echo\nretry/early/" <> :binary.copy("t", 300)

      {connection, stream} =
        paused(ep, fn ->
          connection = connect(ep, port)
          {:ok, stream} = Quic.open_stream(connection, :bidi, early_data: :replayable)
          {:ok, ^ref} = Quic.send_stream(stream, data, true, early_data: :replayable, ref: ref)
          {connection, stream}
        end)

      info = ready(ep, connection)
      expect!(ep.case, "early_accepted", info.resumption.early_data, :accepted)

      expect!(
        ep.case,
        "outcome_accepted",
        Quic.operation_status(connection, ref).outcome,
        {:early_data, :accepted}
      )

      await_echo(ep, stream, data)
      record(ep, 1, info, %{early_sha256: sha(data)})
      close(ep, connection)
      retire(ep)
    end)
  end

  # The remembered peer limits (8 bidi streams, 64 KiB connection/stream
  # credit) and the runtime's own early DATAGRAM allowance (64 items) bound
  # what is admitted before the handshake; excess stream bytes wait for 1-RTT
  # credit and are delivered exactly once.
  def quota_exhaustion([port | _]) do
    scoped("quota_exhaustion", fn ->
      ep = endpoint("quota_exhaustion", true)
      prime(ep, port, 0)
      opts = [early_data: :replayable]

      {connection, bulk, chunks, streams, ninth} =
        paused(ep, fn ->
          connection = connect(ep, port)
          datagrams = for index <- 1..64, do: Quic.send_datagram(connection, "d#{index}", opts)

          expect!(
            ep.case,
            "datagram_allowance",
            Enum.all?(datagrams, &match?({:ok, _}, &1)),
            true
          )

          expect!(
            ep.case,
            "datagram_exhausted",
            Quic.send_datagram(connection, "d65", opts),
            {:blocked, :early_datagram_limit}
          )

          # Stream 0 offers 80 KiB, beyond the remembered 64 KiB credit.
          {:ok, bulk} = Quic.open_stream(connection, :bidi, opts)
          chunks = ["echo\n" | List.duplicate(:binary.copy("q", 16_000), 5)]
          admissions = Enum.map(chunks, &Quic.send_stream(bulk, &1, false, opts))
          {admitted, [refused]} = Enum.split(admissions, -1)
          expect!(ep.case, "credit_admitted", Enum.all?(admitted, &match?({:ok, _}, &1)), true)

          expect!(
            ep.case,
            "credit_exhausted",
            refused,
            {:blocked, %{type: :data_blocked, value: 64_005}}
          )

          streams =
            for index <- 1..7 do
              {:ok, stream} = Quic.open_stream(connection, :bidi, opts)
              {stream, echo(ep, stream, "quota/#{index}", opts)}
            end

          ninth = Quic.open_stream(connection, :bidi, opts)

          expect!(
            ep.case,
            "ninth_early_stream_refused",
            ninth,
            {:blocked, %{type: :streams_blocked_bidi, value: 8}}
          )

          {connection, bulk, chunks, streams, ninth}
        end)

      info = ready(ep, connection)
      expect!(ep.case, "early_accepted", info.resumption.early_data, :accepted)
      # The refused tail is the application's to send again, now with 1-RTT credit.
      # Ordinary flow-control backpressure until the peer grants more credit.
      wait(
        fn -> match?({:ok, _}, Quic.send_stream(bulk, List.last(chunks), true)) end,
        now() + 10_000,
        "#{ep.case} refused tail"
      )

      data = IO.iodata_to_binary(chunks)
      Enum.each([{bulk, data} | streams], fn {stream, data} -> await_echo(ep, stream, data) end)
      record(ep, 1, info, %{ninth: inspect(ninth), bulk_sha256: sha(data)})
      close(ep, connection)
      retire(ep)
    end)
  end

  # Runs the early admissions while the peer is paused (SIGSTOP; the peer
  # binary is unchanged), so they deterministically precede its first flight.
  # Every connection opened inside must still be pending afterwards.
  def paused(ep, fun) do
    peer_signal("STOP")

    try do
      result = fun.()

      for %{pid: pid, generation: generation} <- Quic.Endpoint.connections(ep.endpoint) do
        handle = %Quic.Runtime.ConnectionHandle{id: pid, generation: generation}
        expect!(ep.case, "admitted_before_ready", Quic.ready(handle), :pending)
      end

      result
    after
      peer_signal("CONT")
    end
  end

  def peer_signal(signal) do
    case System.get_env("QUIC_PEER_PID") do
      nil -> raise("QUIC_PEER_PID is required to pause the independent peer")
      pid -> {_, 0} = System.cmd("kill", ["-#{signal}", pid])
    end
  end

  def run(ports, "r1") do
    partition_by_remote(ports)
    endpoint_restart(ports)
    stale_ticket(ports)
    concurrent_single_use(ports)
    emit(%{event: "suite", suite: "r1", passed: true})
  end

  def run(ports, "hrr") do
    hrr_resumption(ports)
    hrr_early(ports)
    emit(%{event: "suite", suite: "hrr", passed: true})
  end

  def run(ports, "r2") do
    quota_exhaustion(ports)
    stale_ticket_early(ports)
    concurrent_single_use(ports, true)
    emit(%{event: "suite", suite: "r2", passed: true})
  end

  def run(ports, "r2-rejected") do
    rejected_by_peer(ports)
    emit(%{event: "suite", suite: "r2-rejected", passed: true})
  end

  def run(ports, "r2-retry") do
    retry_early(ports)
    emit(%{event: "suite", suite: "r2-retry", passed: true})
  end
end

[ports, suite] = System.argv()
ports = ports |> String.split(",") |> Enum.map(&String.to_integer/1)
Quic.ClientFeatures.ResumptionNegative.run(ports, suite)

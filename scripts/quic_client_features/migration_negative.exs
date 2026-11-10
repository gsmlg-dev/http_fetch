defmodule Quic.ClientFeatures.MigrationNegative do
  @moduledoc false
  # Bounded M2 negative matrix driver against an independent peer. Every case
  # owns one Cleanup scope and prints its retained receipt; the orchestrator
  # (`wire_gates.py`) matches each printed phase against the peer's receipts.
  @fixture "apps/elixir_quic/test/fixtures/tls"
  @loopback {127, 0, 0, 1}

  def root do
    [{:Certificate, cert, :not_encrypted}] =
      @fixture |> Path.join("root.pem") |> File.read!() |> :public_key.pem_decode()

    cert
  end

  def now, do: System.monotonic_time(:millisecond)
  def bound(ms), do: {:abs_ms, now() + ms}

  def emit(map), do: IO.puts(JSON.encode!(map))

  def wait(check, deadline, label) do
    case check.() do
      false ->
        if now() >= deadline, do: raise("deadline exceeded: #{label}")

        current = Process.get(:connection)

        receive do
          {:quic_closed, ^current, reason} -> raise("connection closed: #{inspect(reason)}")
        after
          5 -> wait(check, deadline, label)
        end

      value ->
        value
    end
  end

  # ---------------------------------------------------------------- session

  def session(port, name, fun) do
    {:ok, cleanup, lease} = Quic.Cleanup.new()

    {:ok, endpoint} =
      Quic.client(
        cleanup: lease,
        tls: [
          reference_identity: {:dns_id, "example.test"},
          cacerts: [root()],
          alpn: ["ex-quic-m2"]
        ]
      )

    ctx = %{case: name, endpoint: endpoint, cleanup: cleanup, lease: lease}

    try do
      {:ok, connection} = Quic.connect(endpoint, {@loopback, port})
      Process.put(:connection, connection)
      :ok = Quic.attach(connection, self())
      fun.(Map.put(ctx, :connection, connection))
    after
      case Quic.Cleanup.retire(lease, bound(5000)) do
        {:ok, receipt} ->
          label = Process.delete(:case_label) || name
          emit(%{event: "cleanup", case: label, receipt: Map.drop(receipt, [:generation])})

        outcome ->
          raise("#{name}: cleanup unconfirmed: #{inspect(outcome)}")
      end
    end
  end

  def confirmed(ctx) do
    wait(
      fn ->
        match?({:ok, %{quic_confirmed: true}}, Quic.info(ctx.connection))
      end,
      now() + 8000,
      "#{ctx.case} confirmation"
    )

    ctx
  end

  def info(ctx) do
    {:ok, info} = Quic.info(ctx.connection)
    info
  end

  def settled(ctx) do
    wait(fn -> map_size(info(ctx).migration.paths) == 1 end, now() + 6000, "#{ctx.case} settle")
    ctx
  end

  def address({{a, b, c, d}, port}), do: "#{a}.#{b}.#{c}.#{d}:#{port}"

  def open(ctx) do
    {:ok, stream} = Quic.open_stream(ctx.connection, :bidi)
    Process.put({:received, ctx.case}, <<>>)
    Process.put({:expected, ctx.case}, <<>>)
    initial = address(info(ctx).local)
    Map.merge(ctx, %{stream: stream, initial: initial})
  end

  # Sends one phase, waits for the exact cumulative echo and prints it with
  # the local address the engine claims; the orchestrator requires the peer
  # to have observed exactly these bytes from exactly that source address.
  def exchange(ctx, phase, path, fin \\ false) do
    payload = "m2-negative/#{ctx.case}/#{phase}/" <> :binary.copy(<<0, 1, 255, 128>>, 300)
    {:ok, _} = Quic.send_stream(ctx.stream, payload, fin)
    expected = Process.get({:expected, ctx.case}) <> payload
    Process.put({:expected, ctx.case}, expected)

    echoed =
      wait(
        fn ->
          {:ok, events} = Quic.read(ctx.stream, 16_384)

          bytes =
            Enum.reduce(events, Process.get({:received, ctx.case}), fn
              {:data, _, bytes}, acc ->
                acc <> bytes

              {:fin, _}, acc ->
                Process.put({:fin, ctx.case}, true)
                acc
            end)

          Process.put({:received, ctx.case}, bytes)
          if bytes == expected, do: bytes, else: false
        end,
        now() + 5000,
        "#{ctx.case}/#{phase} echo"
      )

    if fin do
      wait(fn -> Process.get({:fin, ctx.case}, false) end, now() + 3000, "#{ctx.case} fin")
    end

    local = address(info(ctx).local)
    if path == :old and local != ctx.initial, do: raise("#{ctx.case}: left the old path")
    if path == :new and local == ctx.initial, do: raise("#{ctx.case}: still on the old path")

    emit(%{
      event: "phase",
      case: ctx.case,
      phase: phase,
      path: path,
      initial: ctx.initial,
      local: local,
      bytes: byte_size(echoed),
      sha256: Base.encode16(:crypto.hash(:sha256, echoed), case: :lower),
      fin: fin
    })

    ctx
  end

  def migrate(ctx, ref, local, ms \\ 4000),
    do: Quic.migrate(ctx.connection, local: local, ref: ref, deadline: bound(ms))

  def outcome(ctx, ref) do
    wait(
      fn ->
        case Quic.operation_status(ctx.connection, ref) do
          %{outcome: {:ok, _} = outcome} -> outcome
          %{outcome: {:error, _} = outcome} -> outcome
          _ -> false
        end
      end,
      now() + 6000,
      "#{ctx.case} migration outcome"
    )
  end

  def expect!(ctx, label, actual, expected) do
    unless actual == expected do
      raise("#{ctx.case}/#{label}: expected #{inspect(expected)}, got #{inspect(actual)}")
    end

    emit(%{event: "assert", case: ctx.case, label: label, value: inspect(actual)})
  end

  def peer_signal(signal) do
    case System.get_env("QUIC_PEER_PID") do
      nil -> raise("QUIC_PEER_PID is required to pause the independent peer")
      pid -> {_, 0} = System.cmd("kill", ["-#{signal}", pid])
    end
  end

  # ---------------------------------------------------------------- cases

  # Rejected admissions must not allocate a socket: the receipt is checked by
  # the orchestrator for exactly one IO actor and one native Port.
  def case_before_confirmation(port, attempt \\ 1) do
    name = "before_confirmation"

    result =
      session(port, name, fn ctx ->
        {handshaking, result} = race_confirmation(ctx, 0, now() + 5000)

        case result do
          {:error, :handshake_not_confirmed} ->
            emit(%{
              event: "assert",
              case: name,
              label: "preconfirmation",
              value: inspect({:not_established, handshaking, result})
            })

            ctx = confirmed(ctx) |> settled() |> open()
            expect!(ctx, "paths", map_size(info(ctx).migration.paths), 1)
            exchange(ctx, "after", :old, true)
            :ok

          {:ok, _} ->
            # Confirmation won the race; this attempt proves nothing and its
            # receipt is only checked for generic confirmed cleanup.
            Process.put(:case_label, "#{name}/raced#{attempt}")
            emit(%{event: "raced", case: name, attempt: attempt})
            :raced
        end
      end)

    cond do
      result == :ok -> :ok
      attempt < 5 -> case_before_confirmation(port, attempt + 1)
      true -> raise("#{name}: never observed an unconfirmed established connection")
    end
  end

  # Migrates in a tight loop from connect onward: while handshaking the call is
  # `:not_established`; the first other answer must arrive in the window after
  # the client handshake completes and before HANDSHAKE_DONE is received.
  defp race_confirmation(ctx, handshaking, deadline) do
    if now() >= deadline, do: raise("#{ctx.case}: preconfirmation deadline")

    case migrate(ctx, make_ref(), {@loopback, 0}) do
      {:error, :not_established} -> race_confirmation(ctx, handshaking + 1, deadline)
      result -> {handshaking, result}
    end
  end

  def case_bind_failure(port, name, local, reason) do
    session(port, name, fn ctx ->
      ctx = ctx |> confirmed() |> open() |> exchange("before", :old)
      ref = make_ref()
      expect!(ctx, "admission", migrate(ctx, ref, local), {:ok, ref})
      expect!(ctx, "retained", migrate(ctx, ref, local), {:ok, ref})

      expect!(
        ctx,
        "conflict",
        migrate(ctx, ref, {@loopback, 0}),
        {:error, :operation_ref_conflict}
      )

      expect!(ctx, "outcome", outcome(ctx, ref), {:error, {:bind_failed, reason}})
      expect!(ctx, "retained_after_outcome", migrate(ctx, ref, local), {:ok, ref})
      ctx = settled(ctx)
      expect!(ctx, "local", address(info(ctx).local), ctx.initial)
      exchange(ctx, "after", :old, true)
    end)
  end

  def case_bind_in_use(port) do
    {:ok, holder} = :gen_udp.open(0, ip: @loopback)
    {:ok, held} = :inet.port(holder)

    try do
      case_bind_failure(port, "bind_in_use", {@loopback, held}, :eaddrinuse)
    after
      :gen_udp.close(holder)
    end
  end

  # 192.0.2.1 is TEST-NET-1 (RFC 5737): never a local interface address.
  def case_bind_unavailable(port),
    do: case_bind_failure(port, "bind_unavailable", {{192, 0, 2, 1}, 0}, :eaddrnotavail)

  # The independent peer is paused (SIGSTOP) for the whole validation window so
  # the candidate probe can never be answered: two concurrent migrations race
  # (exactly one is admitted, the other is busy), the admitted one reaches its
  # deadline and falls back, and the resumed peer then serves the old path.
  def case_deadline_fallback_busy(port) do
    session(port, "deadline_fallback_busy", fn ctx ->
      ctx = ctx |> confirmed() |> open() |> exchange("before", :old)
      parent = self()
      refs = [make_ref(), make_ref()]
      peer_signal("STOP")

      results =
        try do
          gate = make_ref()

          tasks =
            for ref <- refs do
              Task.async(fn ->
                receive do
                  ^gate -> :ok
                end

                {ref, migrate(ctx, ref, {@loopback, 0}, 600)}
              end)
            end

          Enum.each(tasks, &send(&1.pid, gate))
          results = Enum.map(tasks, &Task.await(&1, 5000))
          _ = parent

          admitted = for {ref, {:ok, ref}} <- results, do: ref
          busy = for {ref, {:error, :migration_busy}} <- results, do: ref
          expect!(ctx, "concurrent", {length(admitted), length(busy)}, {1, 1})
          [ref] = admitted
          expect!(ctx, "outcome", outcome(ctx, ref), {:error, :validation_timeout})
          [busy_ref] = busy

          expect!(
            ctx,
            "busy_status",
            Map.take(Quic.operation_status(ctx.connection, busy_ref), [:status, :result]),
            %{status: :rejected, result: {:error, :migration_busy}}
          )

          results
        after
          peer_signal("CONT")
        end

      _ = results
      ctx = settled(ctx)
      expect!(ctx, "local", address(info(ctx).local), ctx.initial)
      ctx = exchange(ctx, "after", :old)

      # The released two-path budget admits a later migration on a live peer.
      ref = make_ref()
      expect!(ctx, "later_admission", migrate(ctx, ref, {@loopback, 0}), {:ok, ref})
      {:ok, _} = outcome(ctx, ref)
      ctx |> settled() |> exchange("migrated", :new, true)
    end)
  end

  def case_duplicate_ref(port) do
    session(port, "duplicate_ref", fn ctx ->
      ctx = ctx |> confirmed() |> open() |> exchange("before", :old)
      ref = make_ref()
      local = {@loopback, 0}
      expect!(ctx, "admission", migrate(ctx, ref, local), {:ok, ref})
      expect!(ctx, "retained", migrate(ctx, ref, local), {:ok, ref})
      {:ok, migrated} = outcome(ctx, ref)
      expect!(ctx, "retained_after_outcome", migrate(ctx, ref, local), {:ok, ref})

      expect!(
        ctx,
        "status",
        Map.take(Quic.operation_status(ctx.connection, ref), [:result, :outcome]),
        %{result: {:ok, ref}, outcome: {:ok, migrated}}
      )

      ctx = settled(ctx)
      expect!(ctx, "local", address(info(ctx).local), address(migrated))
      exchange(ctx, "after", :new, true)
    end)
  end

  def case_rejected(port, name, reason) do
    session(port, name, fn ctx ->
      ctx = ctx |> confirmed() |> open() |> exchange("before", :old)
      # Any spare CID the peer would issue arrives with its first 1-RTT flight.
      Process.sleep(200)
      ref = make_ref()
      expect!(ctx, "admission", migrate(ctx, ref, {@loopback, 0}), {:error, reason})
      expect!(ctx, "retained", migrate(ctx, ref, {@loopback, 0}), {:error, reason})
      expect!(ctx, "paths", map_size(info(ctx).migration.paths), 1)
      exchange(ctx, "after", :old, true)
    end)
  end

  # ------------------------------------------------------- owner death

  # Freezes `target` inside its own sys debug hook immediately before it handles
  # the first message matching `match`; the hook blocks in the target process.
  def freeze_on(target, match) do
    parent = self()
    tag = make_ref()

    hook = fn state, event, _proc ->
      message =
        case event do
          {:in, {:info, message}} -> message
          {:in, {:info, message}, _} -> message
          {:in, message} -> message
          {:in, message, _} -> message
          _ -> nil
        end

      if message != nil and match.(message) do
        send(parent, {:frozen, tag, message})

        receive do
          {:thaw, ^tag} -> :done
        end
      else
        state
      end
    end

    :ok = :sys.install(target, {hook, nil})
    tag
  end

  def frozen(tag) do
    receive do
      {:frozen, ^tag, message} -> message
    after
      6000 -> raise("transition never reached")
    end
  end

  def resources(ctx), do: :sys.get_state(ctx.cleanup.observer).resources

  # Kills the endpoint (the owner of both UDP actors, both native Ports and
  # the connection) and requires every enrolled resource to be joined.
  # A process frozen by `freeze_on/2` is released right after the kill, so the
  # pending transition message and the owner's DOWN are handled in that order.
  def kill_owner(ctx, transition, frozen \\ nil) do
    resources = resources(ctx)
    roles = resources |> Map.values() |> Enum.frequencies_by(& &1.role)
    expect!(ctx, "#{transition}/two_sockets", {roles[:io], roles[:port]}, {2, 2})

    joins =
      for {resource, _} <- resources do
        type = if is_port(resource), do: :port, else: :process
        {type, resource, :erlang.monitor(type, resource)}
      end

    # The public endpoint is linked to its caller; trap only this forced death.
    trapping = Process.flag(:trap_exit, true)
    Process.exit(ctx.endpoint, :kill)
    with {pid, tag} <- frozen, do: send(pid, {:thaw, tag})

    receive do
      {:EXIT, endpoint, :killed} when endpoint == ctx.endpoint -> :ok
    after
      3000 -> raise("#{ctx.case}: owner did not exit")
    end

    Process.flag(:trap_exit, trapping)

    Enum.each(joins, fn {type, resource, monitor} ->
      receive do
        {:DOWN, ^monitor, ^type, ^resource, _} -> :ok
      after
        3000 -> raise("#{ctx.case}: #{inspect(resource)} survived owner death")
      end

      if type == :port and :erlang.port_info(resource) != :undefined,
        do: raise("#{ctx.case}: native port still open")
    end)

    emit(%{event: "owner_death", case: ctx.case, transition: transition, joined: length(joins)})
  end

  def case_owner_death(port, "candidate_bound") do
    session(port, "owner_death/candidate_bound", fn ctx ->
      ctx = ctx |> confirmed() |> open() |> exchange("before", :old)
      connection = ctx.connection.id
      ref = make_ref()

      tag =
        freeze_on(connection, &match?({:quic_path_bound, _, ^ref, _, {:ok, _, _}}, &1))

      {:ok, ^ref} = migrate(ctx, ref, {@loopback, 0})
      frozen(tag)
      kill_owner(ctx, "candidate_bound", {connection, tag})
    end)
  end

  def case_owner_death(port, "probe_sent") do
    session(port, "owner_death/probe_sent", fn ctx ->
      ctx = ctx |> confirmed() |> open() |> exchange("before", :old)
      ref = make_ref()
      peer_signal("STOP")

      try do
        {:ok, ^ref} = migrate(ctx, ref, {@loopback, 0}, 5000)

        wait(
          fn ->
            state = :sys.get_state(ctx.connection.id) |> elem(1)

            match?(%{phase: :validating}, state.local_migration) and
              state.paths.paths[state.local_migration.id].challenges != []
          end,
          now() + 3000,
          "probe"
        )

        kill_owner(ctx, "probe_sent")
      after
        peer_signal("CONT")
      end
    end)
  end

  def case_owner_death(port, transition) when transition in ["validated", "old_retiring"] do
    session(port, "owner_death/#{transition}", fn ctx ->
      ctx = ctx |> confirmed() |> open() |> exchange("before", :old)

      message =
        if transition == "validated", do: :quic_select_local_path, else: :quic_retire_local_path

      tag = freeze_on(ctx.endpoint, &(is_tuple(&1) and elem(&1, 0) == message))
      ref = make_ref()
      {:ok, ^ref} = migrate(ctx, ref, {@loopback, 0})
      frozen(tag)
      # The connection is live: it has committed the validated candidate (and,
      # for old_retiring, requested old-socket retirement) before the owner dies.
      {_, state} = :sys.get_state(ctx.connection.id)
      phases = if transition == "validated", do: [:settling, :retiring], else: [:retiring]
      expect!(ctx, "#{transition}/phase", state.local_migration.phase in phases, true)

      expect!(
        ctx,
        "#{transition}/outcome",
        match?(%{outcome: {:ok, _}}, Quic.operation_status(ctx.connection, ref)),
        true
      )

      kill_owner(ctx, transition, {ctx.endpoint, tag})
    end)
  end

  def run([port, suite]) do
    port = String.to_integer(port)

    case suite do
      "matrix" ->
        case_before_confirmation(port)
        case_bind_in_use(port)
        case_bind_unavailable(port)
        case_deadline_fallback_busy(port)
        case_duplicate_ref(port)

        for transition <- ["candidate_bound", "probe_sent", "validated", "old_retiring"],
            do: case_owner_death(port, transition)

      "no-cid" ->
        case_rejected(port, "no_spare_cid", :no_unused_connection_id)

      "disabled" ->
        case_rejected(port, "peer_disabled", :peer_disabled_migration)
    end

    emit(%{event: "suite", suite: suite, passed: true})
  end
end

Quic.ClientFeatures.MigrationNegative.run(System.argv())

# Started by gate.py against the caller's already-prepared Mix build.
defmodule Quic.MigrationGate.Echo do
  @alpn "ex-quic-test"
  @max_bytes 32_768

  def init(connection, %{alpn: @alpn}, owner, backend) do
    token = System.unique_integer([:positive])
    send(owner, {:connection, connection})
    proof(owner, %{event: "connection_ready", connection: token, alpn: @alpn})

    %{
      connection: connection,
      owner: owner,
      backend: backend,
      token: token,
      streams: %{},
      completed_streams: %{},
      last_path: nil
    }
  end

  def event({:stream_open, stream, :bidi}, state) do
    unless map_size(state.streams) == 0, do: raise("unexpected additional stream")
    proof(state.owner, %{event: "stream_open", connection: state.token, stream_id: stream.id})
    %{state | streams: Map.put(state.streams, stream, <<>>)}
  end

  def event({:readable, stream}, %{completed_streams: completed} = state)
      when is_map_key(completed, stream),
      do: state

  def event({:readable, stream}, state) do
    {:ok, items} = apply(state.backend, :read, [stream, 16_384, [timeout: 1_000]])

    Enum.reduce(items, state, fn
      {:data, _id, bytes}, state ->
        if is_map_key(state.completed_streams, stream), do: raise("stream data after FIN")
        accumulated = Map.fetch!(state.streams, stream) <> bytes
        if byte_size(accumulated) > @max_bytes, do: raise("stream proof byte bound exceeded")
        {:ok, _ref} = apply(state.backend, :send_stream, [stream, bytes, false, [timeout: 1_000]])
        state = %{state | streams: Map.put(state.streams, stream, accumulated)}
        path_snapshot(state)

      {:fin, _id}, state ->
        if is_map_key(state.completed_streams, stream), do: raise("duplicate stream FIN")
        {:ok, _ref} = apply(state.backend, :send_stream, [stream, <<>>, true, [timeout: 1_000]])
        bytes = Map.fetch!(state.streams, stream)

        proof(state.owner, %{
          event: "stream_complete",
          connection: state.token,
          stream_id: stream.id,
          bytes: byte_size(bytes),
          sha256: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower),
          fin: true
        })

        %{state | completed_streams: Map.put(state.completed_streams, stream, true)}

      unexpected, _state ->
        raise("unexpected stream event: #{inspect(unexpected)}")
    end)
  end

  def event(:datagram_readable, state) do
    {:ok, messages} =
      apply(state.backend, :read_datagrams, [state.connection, 32, [timeout: 1_000]])

    Enum.each(messages, fn bytes ->
      {:ok, _ref} =
        apply(state.backend, :send_datagram, [state.connection, bytes, [timeout: 1_000]])
    end)

    state
  end

  def event({:reset, _, _}, _state), do: raise("stream reset")
  def event({:stopped, _, _}, _state), do: raise("stream stopped")
  def event(:tick, state), do: path_snapshot(state)
  def event(_, state), do: state

  # The peer may close between the event poll and this snapshot; the worker's
  # next poll then observes the close and checks its peer-close receipt.
  defp path_snapshot(state) do
    case apply(state.backend, :info, [state.connection]) do
      {:ok, %{migration: %{active_path: active, paths: paths}, resources: %{path_records: count}}} ->
        public = %{
          active_path: inspect(active),
          path_records: count,
          paths:
            Enum.map(paths, fn {id, path} ->
              %{
                id: inspect(id),
                local: address(path.local),
                remote: address(path.remote),
                validated: path.validated,
                mtu_validated: path.mtu_validated
              }
            end)
            |> Enum.sort_by(& &1.id)
        }

        if public != state.last_path do
          proof(
            state.owner,
            Map.merge(public, %{event: "public_path_info", connection: state.token})
          )
        end

        %{state | last_path: public}

      {:ok, _info} ->
        state

      {:error, :closed} ->
        state
    end
  end

  defp address({ip, port}), do: [ip |> :inet.ntoa() |> to_string(), port]

  defp proof(owner, event), do: send(owner, {:proof, event})
end

defmodule Quic.MigrationGate.Handler do
  @behaviour Abyss.QUIC.Handler

  def init(connection, metadata, owner),
    do: {:ok, Quic.MigrationGate.Echo.init(connection, metadata, owner, Abyss.QUIC)}

  def handle_event(event, state), do: {:ok, Quic.MigrationGate.Echo.event(event, state)}
end

defmodule Quic.MigrationGate do
  alias Quic.MigrationGate.Echo

  def run(argv) do
    {opts, [], []} = OptionParser.parse(argv, strict: [mode: :string, timeout_ms: :integer])
    mode = Keyword.fetch!(opts, :mode)
    timeout = Keyword.get(opts, :timeout_ms, 30_000)
    unless mode in ["standalone", "abyss"] and timeout > 0, do: raise("invalid gate options")
    deadline = System.monotonic_time(:millisecond) + timeout
    owner = self()
    {server, address} = start(mode)

    input =
      spawn_monitor(fn ->
        case IO.gets("") do
          "stop\n" -> send(owner, :stop)
          :eof -> send(owner, :stop)
          _ -> send(owner, :invalid_command)
        end
      end)

    emit(%{
      event: "listening",
      mode: mode,
      host: address |> elem(0) |> :inet.ntoa() |> to_string(),
      port: elem(address, 1)
    })

    try do
      loop(%{mode: mode, server: server, workers: %{}, handles: [], deadline: deadline})
    after
      try do
        if state = Process.get(:migration_gate_state), do: stop_workers(state)
      after
        {pid, monitor} = input
        if Process.alive?(pid), do: Process.exit(pid, :kill)
        Process.demonitor(monitor, [:flush])
        stop(mode, server)
      end
    end

    emit(%{event: "stopped", mode: mode})
  end

  defp start(mode) do
    fixture = Path.expand("../../apps/elixir_quic/test/fixtures/tls", __DIR__)

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    tls = [cert: [cert], key: {type, key}, alpn: ["ex-quic-test"]]
    limits = [max_frame_size: 1_200, max_items: 64, max_buffer_bytes: 65_536]

    case mode do
      "standalone" ->
        {:ok, server} =
          Quic.listen(acceptor: self(), tls: tls, datagram: limits, idle_timeout: 30_000)

        {server, Quic.local(server)}

      "abyss" ->
        {:ok, server} =
          Abyss.QUIC.start_link(
            handler: {Quic.MigrationGate.Handler, self()},
            alpn: ["ex-quic-test"],
            tls: tls,
            ip: {127, 0, 0, 1},
            port: 0,
            poll_interval: 2,
            callback_timeout: 1_000,
            quic_options: [datagram: limits, idle_timeout: 30_000]
          )

        {:ok, address} = Abyss.QUIC.local(server)
        {server, address}
    end
  end

  defp loop(state) do
    Process.put(:migration_gate_state, state)
    remaining = max(0, state.deadline - System.monotonic_time(:millisecond))

    receive do
      {:quic_accept, server} when state.mode == "standalone" and server == state.server ->
        loop(accept(state))

      {:connection, connection} ->
        loop(%{state | handles: Enum.uniq([connection | state.handles])})

      {:proof, event} ->
        emit(event)
        loop(state)

      {:DOWN, monitor, :process, pid, reason} ->
        case state.workers[pid] do
          ^monitor when reason == :normal ->
            loop(%{state | workers: Map.delete(state.workers, pid)})

          ^monitor ->
            raise("echo worker failed: #{inspect(reason)}")

          _ ->
            loop(state)
        end

      :stop ->
        :ok

      :invalid_command ->
        raise("expected stop command")

      _ ->
        loop(state)
    after
      remaining ->
        raise("migration gate runner deadline")
    end
  end

  defp accept(state) do
    case Quic.accept(state.server, timeout: 1_000) do
      {:ok, connection} ->
        owner = self()
        deadline = state.deadline

        {pid, monitor} =
          spawn_monitor(fn ->
            :ok = Quic.attach(connection, self(), timeout: 1_000)
            {:ok, metadata} = Quic.info(connection)
            worker(Echo.init(connection, metadata, owner, Quic), deadline)
          end)

        next = %{
          state
          | workers: Map.put(state.workers, pid, monitor),
            handles: [connection | state.handles]
        }

        Process.put(:migration_gate_state, next)
        accept(next)

      {:error, :would_block} ->
        state

      other ->
        raise("accept failed: #{inspect(other)}")
    end
  end

  defp worker(state, deadline) do
    if System.monotonic_time(:millisecond) >= deadline, do: raise("echo worker deadline")

    receive do
      {:quic_closed, connection, reason} when connection == state.connection ->
        closed(reason, state)
    after
      0 ->
        case Quic.events(state.connection, 32, timeout: 1_000) do
          {:ok, events} ->
            next = events |> Enum.reduce(state, &Echo.event/2) |> then(&Echo.event(:tick, &1))

            receive do
              {:quic_closed, connection, reason} when connection == state.connection ->
                closed(reason, next)
            after
              2 -> worker(next, deadline)
            end

          {:error, :closed} ->
            receive do
              {:quic_closed, connection, reason} when connection == state.connection ->
                closed(reason, state)
            after
              1_000 -> raise("closed connection without peer-close receipt")
            end

          # The connection exited while the pull was in flight (or the pull timed
          # out): a close shows up as its receipt, otherwise poll again under the
          # worker deadline.
          {:unknown, _ref} ->
            receive do
              {:quic_closed, connection, reason} when connection == state.connection ->
                closed(reason, state)
            after
              1_000 -> worker(state, deadline)
            end

          other ->
            raise("event poll failed: #{inspect(other)}")
        end
    end
  end

  defp closed(reason, state) do
    unless map_size(state.streams) == 1 and map_size(state.completed_streams) == 1,
      do: raise("connection closed before stream FIN")

    case reason do
      :peer_closed -> :ok
      {:application, 0, _reason} -> :ok
      other -> raise("connection closed unexpectedly: #{inspect(other)}")
    end
  end

  defp stop_workers(state) do
    Enum.each(state.handles, fn connection ->
      backend = if state.mode == "standalone", do: Quic, else: Abyss.QUIC
      apply(backend, :close, [connection, 0, <<>>, [timeout: 500]])
    end)

    Enum.each(state.workers, fn {pid, monitor} ->
      cleanup_monitor = Process.monitor(pid)
      if Process.alive?(pid), do: Process.exit(pid, :kill)

      receive do
        {:DOWN, ^cleanup_monitor, :process, ^pid, _} -> :ok
      after
        1_000 -> raise("owned echo worker did not stop")
      end

      Process.demonitor(monitor, [:flush])
    end)
  end

  defp stop("standalone", server) do
    if Process.alive?(server), do: GenServer.stop(server, :normal, 5_000)
  end

  defp stop("abyss", server) do
    if Process.alive?(server), do: Abyss.QUIC.stop(server, 5_000)
  end

  defp emit(event), do: IO.puts(JSON.encode!(event))
end

Quic.MigrationGate.run(System.argv())

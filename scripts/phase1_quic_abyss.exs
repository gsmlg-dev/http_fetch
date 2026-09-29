defmodule HTTP.Phase1.AbyssCollector do
  @behaviour Abyss.QUIC.Handler

  def init(connection, %{alpn: "ex-quic-phase1"}, owner) do
    send(owner, {:bound, connection, self()})
    {:ok, %{owner: owner, streams: %{}}}
  end

  def handle_event({:stream_open, stream, kind}, state) do
    entry = %{stream: stream, kind: kind, bytes: 0, hash: :crypto.hash_init(:sha256)}
    {:ok, put_in(state.streams[stream.id], entry)}
  end

  def handle_event(:tick, state) do
    # At most one 1 KiB read per stream per tick; retained application memory is
    # only incremental hashes, counters and handles, independent of transfer size.
    streams = Enum.reduce(state.streams, state.streams, &consume(&1, &2, state.owner))
    {:ok, %{state | streams: streams}}
  end

  def handle_event(_event, state), do: {:ok, state}

  def terminate(reason, _state), do: IO.inspect(reason, label: "handler_terminal")

  defp consume({id, entry}, streams, owner) do
    {:ok, items} = Abyss.QUIC.read(entry.stream, 1_024)

    Enum.reduce(items, streams, fn
      {:data, ^id, bytes}, acc ->
        update_in(acc[id], fn value ->
          %{
            value
            | bytes: value.bytes + byte_size(bytes),
              hash: :crypto.hash_update(value.hash, bytes)
          }
        end)

      {:fin, ^id}, acc ->
        value = Map.fetch!(acc, id)
        send(owner, {:collected, id, value.bytes, :crypto.hash_final(value.hash)})

        if value.kind == :bidi do
          {:ok, _ref} = Abyss.QUIC.send_stream(value.stream, "ok", true)
        end

        Map.delete(acc, id)

      {:reset, ^id, code, _size}, acc ->
        send(owner, {:reset, id, code})
        Map.delete(acc, id)
    end)
  end
end

defmodule HTTP.Phase1.AbyssJoint do
  alias HTTP.QUIC.ExQuic, as: Adapter

  def run do
    fixtures = System.fetch_env!("HTTP_QUIC_FIXTURES")
    [{type, key, :not_encrypted}] = pem(fixtures, "localhost.key")

    certificates =
      for {:Certificate, cert, :not_encrypted} <- pem(fixtures, "localhost.pem"), do: cert

    limits = [max_data: 16_384, max_stream_data: 16_384, max_buffer: 65_536]

    # TODO(upstream): gsmlg-dev/abyss#5 - support the published Quic facade.
    {:ok, listener} =
      Abyss.QUIC.start_link(
        handler: {HTTP.Phase1.AbyssCollector, self()},
        alpn: ["ex-quic-phase1"],
        tls: [cert: certificates, key: {type, key}],
        poll_interval: 2,
        quic_options: [streams: limits]
      )

    {:ok, client} =
      Adapter.client(
        "localhost",
        [cacertfile: Path.join(fixtures, "localhost-ca.pem"), alpn: ["ex-quic-phase1"]],
        streams: limits
      )

    try do
      {:ok, remote} = Abyss.QUIC.local(listener)
      {:ok, connection} = Adapter.connect(client, remote)
      :ok = Adapter.attach(connection, self())

      receive do
        {:quic_ready, ^connection, %{alpn: "ex-quic-phase1"}} -> :ok
      after
        5_000 -> raise("adapter readiness timeout")
      end

      worker =
        receive do
          {:bound, _server_connection, worker} -> worker
        after
          5_000 -> raise("Abyss handler was not bound")
        end

      worker_monitor = Process.monitor(worker)

      streams =
        for kind <- [:bidi, :bidi, :bidi, :bidi, :uni, :uni] do
          {:ok, stream} = Adapter.open_stream(connection, kind)
          stream
        end

      expected =
        Enum.map(streams, fn stream ->
          payload = :binary.copy(<<stream.id>>, 262_144)
          send_bytes(stream, payload, now() + 15_000, if(stream.id == 0, do: 16_384, else: 1_024))
          {stream.id, byte_size(payload), :crypto.hash(:sha256, payload)}
        end)

      for {id, bytes, digest} <- expected do
        receive do
          {:collected, ^id, ^bytes, ^digest} -> :ok
        after
          15_000 -> raise("Abyss stream digest/FIN missing for #{id}")
        end
      end

      for stream <- Enum.take(streams, 4), do: await_ack(stream, "", false, now() + 5_000)
      :ok = Adapter.close(connection)

      receive do
        {:DOWN, ^worker_monitor, :process, ^worker, _reason} -> :ok
      after
        5_000 -> raise("Abyss worker leaked")
      end

      IO.puts("PHASE1_ABYSS_JOINT_PASS streams=6 bytes=1572864 client_ack_fins=4")
    after
      stop_and_monitor(client, &Adapter.stop_endpoint/1)
      stop_and_monitor(listener, &Abyss.QUIC.stop/1)
    end
  end

  defp send_bytes(stream, bytes, deadline, chunk_size) do
    if now() >= deadline, do: raise("finite write deadline expired")
    size = min(chunk_size, byte_size(bytes))
    <<chunk::binary-size(size), rest::binary>> = bytes

    # Regression for gsmlg-dev/ex_quic#2, fixed by the pinned v0.2.1 engine.
    # Keep the sustained small-window workload and fail on uncertain outcomes.
    options = [ref: make_ref(), deadline: max(deadline - now(), 0)]

    case Adapter.send_stream(stream, chunk, rest == <<>>, options) do
      {:ok, _ref} ->
        if rest != <<>>, do: send_bytes(stream, rest, deadline, 1_024)

      {:blocked, _reason} ->
        # Slow public handler consumption replenishes credit. Only a definite
        # non-admission can repeat; every iteration shares the finite deadline.
        Process.sleep(2)
        send_bytes(stream, bytes, deadline, chunk_size)

      other ->
        receive do
          {:quic_closed, _, reason} -> IO.inspect(reason, label: "client_terminal")
        after
          0 -> :ok
        end

        raise("write failed or unknown: #{inspect(other)}")
    end
  end

  defp await_ack(stream, bytes, fin, deadline) do
    if now() >= deadline, do: raise("ack deadline expired")
    {:ok, items} = Adapter.read(stream, 1_024)

    {bytes, fin} =
      Enum.reduce(items, {bytes, fin}, fn
        {:data, _, data}, {acc, fin} -> {acc <> data, fin}
        {:fin, _}, {acc, _} -> {acc, true}
      end)

    if fin do
      "ok" = bytes
    else
      Process.sleep(2)
      await_ack(stream, bytes, fin, deadline)
    end
  end

  defp stop_and_monitor(pid, stop) do
    ref = Process.monitor(pid)
    stop.(pid)

    receive do
      {:DOWN, ^ref, :process, ^pid, :normal} -> :ok
    after
      5_000 -> raise("endpoint/listener cleanup timeout")
    end
  end

  defp pem(fixtures, name),
    do: fixtures |> Path.join(name) |> File.read!() |> :public_key.pem_decode()

  defp now, do: System.monotonic_time(:millisecond)
end

HTTP.Phase1.AbyssJoint.run()

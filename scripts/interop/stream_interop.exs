fixture = Path.expand("../../apps/elixir_quic/test/fixtures/tls", __DIR__)

der = fn name ->
  [{:Certificate, bytes, :not_encrypted}] =
    :public_key.pem_decode(File.read!(Path.join(fixture, name)))

  bytes
end

[{key_type, key, :not_encrypted}] =
  :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

server_tls = [cert: [der.("leaf.pem")], key: {key_type, key}, alpn: ["ex-quic-test"]]
ca = Path.join(fixture, "root.pem")

{:ok, endpoint} = Quic.Endpoint.start_link(role: :server, tls: server_tls, stream_observer: self())
{{127, 0, 0, 1}, port} = Quic.Endpoint.local(endpoint)

peer =
  Port.open(
    {:spawn_executable, System.find_executable("uv")},
    [:binary, :exit_status, :use_stdio, :stderr_to_stdout, {:line, 65_536},
     {:args, ["run", "--python", "3.12", "--with", "aioquic==1.2.0", "python",
       "scripts/interop/stream_peer.py", "--port", Integer.to_string(port), "--ca", ca,
       "--timeout", "5"]}]
  )

deadline = System.monotonic_time(:millisecond) + 10_000

collect = fn collect, seen ->
  if map_size(seen) == 2 do
    seen
  else
    receive do
      {:quic_stream, _pid, stream_id, events} ->
        IO.inspect({stream_id, events}, label: "STREAM_EVENT")
        collect.(collect, Map.put(seen, stream_id, events))
      {^peer, {:data, {:eol, line}}} ->
        IO.puts(line)
        collect.(collect, seen)
      {^peer, {:exit_status, _code}} ->
        collect.(collect, seen)
    after
      50 ->
        if System.monotonic_time(:millisecond) >= deadline,
          do: seen,
          else: collect.(collect, seen)
    end
  end
end

streams = collect.(collect, %{})
IO.inspect(Quic.Endpoint.stats(endpoint), label: "STREAM_ENDPOINT_STATS")
IO.inspect(Quic.Endpoint.connections(endpoint), label: "STREAM_ENDPOINT_CONNECTIONS")
expected = MapSet.new(["independent-stream-one", "independent-stream-two"])

received =
  streams
  |> Map.values()
  |> Enum.flat_map(fn events ->
    Enum.flat_map(events, fn
      {:data, _id, data} -> [data]
      _ -> []
    end)
  end)
  |> MapSet.new()

result = %{streams: streams, passed: MapSet.equal?(received, expected)}
IO.inspect(result, label: "STREAM_INTEROP_RESULT")
if Port.info(peer), do: Port.command(peer, "stop\n")
GenServer.stop(endpoint)
if result.passed, do: :ok, else: System.halt(1)

# Run with: mix run scripts/datagram/interop.exs client|server
defmodule Quic.Datagram.Interop do
  @deadline 15_000
  @peer_datagram "aioquic-datagram-h3"
  @peer_stream "aioquic-stream-h3"
  @engine_datagram "elixir-datagram-h3"
  @engine_stream "elixir-stream-h3"
  @peer_boundary :binary.copy(<<0xBC>>, 1100)
  @complete "elixir-complete-h3"

  def run([role]) when role in ["client", "server"] do
    fixture = Path.expand("../../apps/elixir_quic/test/fixtures/tls", __DIR__)
    {:ok, endpoint} = start_endpoint(role, fixture)
    peer = start_peer(role, endpoint, fixture)
    deadline = System.monotonic_time(:millisecond) + @deadline

    try do
      handle = await_handle(role, endpoint, peer, deadline)
      :ok = Quic.attach(handle, self())
      metadata = await_ready(handle, peer, deadline)

      {:ok, %{send_max_bytes: send_max, receive_max_bytes: receive_max}} =
        Quic.info(handle) |> datagram_info()

      unless send_max >= byte_size(@engine_datagram) and
               receive_max >= byte_size(@peer_datagram),
             do: raise("DATAGRAM transport parameter not negotiated")

      {:ok, _} = Quic.send_datagram(handle, @engine_datagram)
      {:ok, _} = Quic.send_datagram(handle, <<>>)
      {:ok, _} = Quic.send_datagram(handle, @engine_datagram)
      {:ok, _} = Quic.send_datagram(handle, :binary.copy(<<0xAB>>, send_max))
      {:ok, stream} = Quic.open_stream(handle, :bidi)
      {:ok, _} = Quic.send_stream(stream, @engine_stream, true)

      result =
        collect(handle, peer, deadline, %{
          datagrams: [],
          streams: %{},
          peer_verified: false,
          peer_boundary: nil,
          send_max: send_max
        })

      {:ok, _} = Quic.send_datagram(handle, @complete)
      await_peer_exit(peer, deadline)
      Quic.close(handle)
      IO.puts(JSON.encode!(%{role: role, alpn: metadata.alpn, passed: true, result: result}))
    after
      if Port.info(peer), do: Port.close(peer)
      GenServer.stop(endpoint)
    end
  end

  def run(_), do: raise("usage: mix run scripts/datagram/interop.exs client|server")

  defp datagram_info({:ok, %{datagram: datagram}}), do: {:ok, datagram}

  defp start_endpoint("server", fixture),
    do: Quic.listen(tls: tls("server", fixture), datagram: datagram_limits())

  defp start_endpoint("client", fixture) do
    {:ok, profile} = Quic.Profile.compile(:ordered, alpn: ["h3"])
    Quic.client(tls: tls("client", fixture), profile: profile, datagram: datagram_limits())
  end

  defp datagram_limits,
    do: [max_frame_size: 1200, max_items: 64, max_buffer_bytes: 65_536]

  defp tls("client", fixture),
    do: [
      cacerts: [der(Path.join(fixture, "root.pem"))],
      reference_identity: {:dns_id, "example.test"},
      alpn: ["h3"]
    ]

  defp tls("server", fixture) do
    [{key_type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    [cert: [der(Path.join(fixture, "leaf.pem"))], key: {key_type, key}, alpn: ["h3"]]
  end

  defp der(path) do
    [{:Certificate, bytes, :not_encrypted}] = :public_key.pem_decode(File.read!(path))
    bytes
  end

  defp start_peer("server", endpoint, fixture),
    do:
      peer_port([
        "--role",
        "client",
        "--port",
        Integer.to_string(elem(Quic.local(endpoint), 1)),
        "--ca",
        Path.join(fixture, "root.pem")
      ])

  defp start_peer("client", _endpoint, fixture),
    do:
      peer_port([
        "--role",
        "server",
        "--cert",
        Path.join(fixture, "leaf.pem"),
        "--key",
        Path.join(fixture, "leaf-key.pem")
      ])

  defp peer_port(args) do
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
         "scripts/datagram/peer.py" | args
       ]}
    ])
  end

  defp await_handle(role, endpoint, peer, deadline) do
    check_deadline!(deadline)

    receive do
      {:quic_accept, ^endpoint} when role == "server" ->
        {:ok, handle} = Quic.accept(endpoint)
        handle

      {^peer, {:data, {:eol, line}}} when role == "client" ->
        case JSON.decode(line) do
          {:ok, %{"event" => "listening", "port" => port}} ->
            {:ok, handle} = Quic.connect(endpoint, {{127, 0, 0, 1}, port})
            handle

          _ ->
            await_handle(role, endpoint, peer, deadline)
        end

      {^peer, {:data, {:eol, _line}}} ->
        await_handle(role, endpoint, peer, deadline)

      {^peer, {:exit_status, code}} ->
        raise("aioquic peer exited before connection: #{code}")
    after
      20 -> await_handle(role, endpoint, peer, deadline)
    end
  end

  defp await_ready(handle, peer, deadline) do
    check_deadline!(deadline)

    receive do
      {:quic_ready, ^handle, %{alpn: "h3"} = metadata} -> metadata
      {^peer, {:data, {:eol, _line}}} -> await_ready(handle, peer, deadline)
      {^peer, {:exit_status, code}} -> raise("aioquic peer exited before readiness: #{code}")
    after
      20 -> await_ready(handle, peer, deadline)
    end
  end

  defp collect(handle, peer, deadline, state) do
    check_deadline!(deadline)
    {:ok, events} = Quic.events(handle, 32)

    streams =
      Enum.reduce(events, state.streams, fn
        {:stream_open, stream, _kind}, acc -> Map.put(acc, stream.id, {stream, <<>>, false})
        _, acc -> acc
      end)

    streams =
      Enum.into(streams, %{}, fn {id, {stream, bytes, finished}} ->
        {:ok, items} = Quic.read(stream, 16_384)

        {bytes, finished} =
          Enum.reduce(items, {bytes, finished}, fn
            {:data, ^id, chunk}, {current, fin} -> {current <> chunk, fin}
            {:fin, ^id}, {current, _fin} -> {current, true}
          end)

        {id, {stream, bytes, finished}}
      end)

    {:ok, datagrams} = Quic.read_datagrams(handle, 32)
    state = %{state | streams: streams, datagrams: state.datagrams ++ datagrams}
    state = collect_peer(peer, state)

    stream_ok =
      map_size(streams) == 1 and
        Enum.any?(streams, fn {_, {_, bytes, fin}} -> fin and bytes == @peer_stream end)

    datagrams_ok =
      length(state.datagrams) == 4 and
        Enum.frequencies(state.datagrams) ==
          Enum.frequencies([<<>>, @peer_datagram, @peer_datagram, @peer_boundary])

    if datagrams_ok and stream_ok and state.peer_verified and
         state.peer_boundary == state.send_max do
      %{datagrams: 4, streams: 1, boundary_bytes: state.send_max, peer_verified: true}
    else
      Process.sleep(5)
      collect(handle, peer, deadline, state)
    end
  end

  defp collect_peer(peer, state) do
    receive do
      {^peer, {:data, {:eol, line}}} ->
        state =
          case JSON.decode(line) do
            {:ok, %{"event" => "verified", "boundary_bytes" => bytes}} ->
              %{state | peer_verified: true, peer_boundary: bytes}

            {:ok, %{"event" => "failure"}} ->
              raise("aioquic peer failed")

            _ ->
              state
          end

        collect_peer(peer, state)

      {^peer, {:exit_status, code}} when code != 0 ->
        raise("aioquic peer exited: #{code}")
    after
      0 -> state
    end
  end

  defp await_peer_exit(peer, deadline) do
    check_deadline!(deadline)

    receive do
      {^peer, {:data, {:eol, line}}} ->
        case JSON.decode(line) do
          {:ok, %{"event" => "result", "passed" => false}} -> raise("aioquic peer failed")
          _ -> await_peer_exit(peer, deadline)
        end

      {^peer, {:exit_status, 0}} ->
        :ok

      {^peer, {:exit_status, code}} ->
        raise("aioquic peer exited: #{code}")
    after
      20 -> await_peer_exit(peer, deadline)
    end
  end

  defp check_deadline!(deadline) do
    if System.monotonic_time(:millisecond) >= deadline,
      do: raise("DATAGRAM interop deadline")
  end
end

Quic.Datagram.Interop.run(System.argv())

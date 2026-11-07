# Public Abyss server against an independently pinned aioquic client. This also
# runs from a cold Hex consumer; source paths supply only this harness and fixtures.
defmodule AbyssDatagram.Interop do
  @alpn "h3"
  @peer_datagram "aioquic-datagram-h3"
  @peer_stream "aioquic-stream-h3"
  @engine_datagram "elixir-datagram-h3"
  @engine_stream "elixir-stream-h3"
  @peer_boundary :binary.copy(<<0xBC>>, 1197)
  @complete "elixir-complete-h3"

  @behaviour Abyss.QUIC.Handler

  def init(connection, metadata, {owner, verification}) do
    %{alpn: @alpn, datagram: %{send_max_bytes: 1197, receive_max_bytes: 1197}} = metadata
    send(owner, {:bound, connection, self()})

    for payload <- [@engine_datagram, <<>>, @engine_datagram, :binary.copy(<<0xAB>>, 1197)] do
      {:ok, _} = Abyss.QUIC.send_datagram(connection, payload)
    end

    {:ok, stream} = Abyss.QUIC.open_stream(connection, :bidi)
    {:ok, _} = Abyss.QUIC.send_stream(stream, @engine_stream, true)

    {:ok,
     %{
       connection: connection,
       owner: owner,
       verification: verification,
       datagrams: [],
       stream: nil,
       bytes: <<>>,
       fin: false,
       peer_verified: false,
       complete: false
     }}
  end

  def handle_event(event, state) do
    state = consume(event, state)
    expected = [<<>>, @peer_datagram, @peer_datagram, @peer_boundary]

    if not state.complete and state.peer_verified and state.fin and state.bytes == @peer_stream and
         Enum.frequencies(state.datagrams) == Enum.frequencies(expected) do
      {:ok, _} = Abyss.QUIC.send_datagram(state.connection, @complete)
      send(state.owner, :traffic_verified)
      {:ok, %{state | complete: true}}
    else
      {:ok, state}
    end
  end

  defp consume(:datagram_readable, state) do
    {:ok, payloads} = Abyss.QUIC.read_datagrams(state.connection, 4)
    datagrams = state.datagrams ++ payloads
    if length(datagrams) > 4, do: raise("unexpected extra DATAGRAMs")
    %{state | datagrams: datagrams}
  end

  defp consume({:stream_open, stream, :bidi}, %{stream: nil} = state),
    do: %{state | stream: stream}

  defp consume({:readable, stream}, %{stream: stream} = state) do
    {:ok, items} = Abyss.QUIC.read(stream, 1024)

    Enum.reduce(items, state, fn
      {:data, _, bytes}, current ->
        bytes = current.bytes <> bytes
        if byte_size(bytes) > byte_size(@peer_stream), do: raise("unexpected stream bytes")
        %{current | bytes: bytes}

      {:fin, _}, current ->
        %{current | fin: true}
    end)
  end

  defp consume(:tick, state) do
    %{state | peer_verified: Agent.get(state.verification, & &1)}
  end

  defp consume(_event, state), do: state

  def run do
    root = Path.expand("../..", __DIR__)
    fixture = Path.join(root, "test/fixtures/quic/server_flight")

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    {:ok, verification} = Agent.start_link(fn -> false end)

    {:ok, listener} =
      Abyss.QUIC.start_link(
        handler: {__MODULE__, {self(), verification}},
        alpn: [@alpn],
        tls: [cert: [cert], key: {type, key}],
        quic_options: [datagram: [max_frame_size: 1200, max_items: 4, max_buffer_bytes: 4096]]
      )

    {:ok, {_, port}} = Abyss.QUIC.local(listener)
    peer = start_peer(root, fixture, port)

    try do
      state =
        await(peer, System.monotonic_time(:millisecond) + 30_000, %{
          connection: nil,
          worker: nil,
          verification: verification,
          traffic: false,
          exited: false
        })

      monitor = Process.monitor(state.connection.id)
      :ok = Abyss.QUIC.stop(listener)

      receive do
        {:DOWN, ^monitor, :process, _, _} -> :ok
      after
        2000 -> raise("Abyss connection did not terminate")
      end

      IO.puts(
        JSON.encode!(%{
          gate: "abyss_quic_datagram",
          result: "PASS",
          alpn: @alpn,
          datagrams_per_direction: 4,
          streams_per_direction: 1,
          boundary_bytes: 1197,
          peer_exit: 0,
          connection_down: true
        })
      )
    after
      if Port.info(peer), do: Port.close(peer)
      if Process.alive?(listener), do: Abyss.QUIC.stop(listener)
      Agent.stop(verification)
    end
  end

  defp start_peer(root, fixture, port) do
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
         Path.expand("../../scripts/datagram/peer.py", root),
         "--role",
         "client",
         "--port",
         Integer.to_string(port),
         "--ca",
         Path.join(fixture, "root.pem"),
         "--boundary-bytes",
         "1197",
         "--max-datagram-size",
         "1232"
       ]}
    ])
  end

  defp await(_peer, _deadline, %{traffic: true, exited: true} = state), do: state

  defp await(peer, deadline, state) do
    remaining = deadline - System.monotonic_time(:millisecond)
    if remaining <= 0, do: raise("Abyss DATAGRAM traffic deadline expired")

    state =
      receive do
        {:bound, connection, worker} ->
          Process.monitor(worker)
          %{state | connection: connection, worker: worker}

        :traffic_verified ->
          %{state | traffic: true}

        {^peer, {:data, {:eol, line}}} ->
          case JSON.decode(line) do
            {:ok, %{"event" => "verified", "boundary_bytes" => 1197}} ->
              Agent.update(state.verification, fn _ -> true end)
              state

            {:ok, %{"event" => "failure"} = failure} ->
              raise("aioquic failure: #{inspect(failure)}")

            _ ->
              state
          end

        {^peer, {:exit_status, 0}} ->
          %{state | exited: true}

        {^peer, {:exit_status, code}} ->
          raise("aioquic exited with status #{code}")

        {:DOWN, _, :process, worker, reason} when worker == state.worker ->
          if not state.traffic,
            do: raise("Abyss handler exited before verification: #{inspect(reason)}")

          state
      after
        remaining -> raise("Abyss DATAGRAM traffic deadline expired")
      end

    await(peer, deadline, state)
  end
end

AbyssDatagram.Interop.run()

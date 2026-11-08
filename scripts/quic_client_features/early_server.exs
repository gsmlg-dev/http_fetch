defmodule Quic.ClientFeatures.EarlyServer do
  def now, do: System.monotonic_time(:millisecond)

  def run do
    fixture = "apps/elixir_quic/test/fixtures/tls"

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, endpoint} =
      Quic.listen(
        resumption: [enabled: true, application_profile: "raw-r2-v1"],
        early_data: [enabled: true, application_profile: "early-raw-v1"],
        datagram: [max_frame_size: 1200],
        tls: [cert: [cert], key: {type, key}, alpn: ["ex-quic-r1"]],
        closing_timeout: 10,
        draining_timeout: 10
      )

    endpoint_state = :sys.get_state(endpoint)
    io = endpoint_state.socket
    native = :sys.get_state(io).socket
    io_monitor = Process.monitor(io)
    native_monitor = :erlang.monitor(:port, native)
    IO.puts(JSON.encode!(%{event: "listening", port: elem(Quic.local(endpoint), 1)}))

    try do
      loop(endpoint, [], 0, now() + 25000)
    after
      GenServer.stop(endpoint)

      receive do
        {:DOWN, ^io_monitor, :process, ^io, _} -> :ok
      after
        5000 -> raise("IO retirement deadline")
      end

      receive do
        {:DOWN, ^native_monitor, :port, ^native, _} -> :ok
      after
        5000 -> raise("Port retirement deadline")
      end

      IO.puts(JSON.encode!(%{event: "server_cleanup", io_down: true, native_port_down: true}))
    end
  end

  def loop(endpoint, connections, completed, deadline) do
    if now() >= deadline, do: raise("resumption server deadline")

    Enum.each(Quic.Endpoint.connections(endpoint), fn %{pid: pid, generation: generation} ->
      {:ok, info} = Quic.Connection.info(pid, generation)

      if info.resumption.early_data == :accepted and not info.tls_complete and
           not Process.get(:early_barrier, false) do
        {_, state} = :sys.get_state(pid)

        if MapSet.size(state.scheduler.early_stream_ids) > 0 and
             state.scheduler.early_datagram_bytes > 0 do
          handle = %Quic.Runtime.ConnectionHandle{id: pid, generation: generation}
          :pending = Quic.ready(handle)
          :ok = Quic.attach(handle, self())
          {:ok, events} = Quic.events(handle)
          false = Enum.any?(events, &match?({:stream_open, _, _}, &1))
          stream = %Quic.Runtime.StreamHandle{connection: handle, id: 0}
          {:error, :invalid_operation} = Quic.read(stream, 16384)
          {:error, :invalid_operation} = Quic.read_datagrams(handle)

          IO.puts(
            JSON.encode!(%{
              event: "early_buffered",
              before_finished: true,
              ready: false,
              stream_bytes: state.scheduler.streams.ready_bytes,
              datagram_bytes: state.scheduler.early_datagram_bytes
            })
          )

          File.write!(System.fetch_env!("QUIC_EARLY_BARRIER"), "release Finished")
          Process.put(:early_barrier, true)
        end
      end
    end)

    connections =
      case Quic.accept(endpoint) do
        {:ok, handle} ->
          :ok = Quic.attach(handle, self())
          {:ok, info} = Quic.info(handle)

          IO.puts(
            JSON.encode!(%{
              event: "handshake",
              resumed: info.resumption.resumed,
              early: info.resumption.early_data == :accepted
            })
          )

          connections ++ [handle]

        {:error, :would_block} ->
          connections
      end

    completed =
      Enum.reduce(connections, completed, fn handle, completed ->
        case Quic.events(handle) do
          {:ok, events} ->
            Enum.reduce(events, completed, fn
              {:stream_open, stream, :bidi}, completed ->
                Process.put({:stream, handle}, stream)
                completed

              {:readable, stream}, completed ->
                {:ok, items} = Quic.read(stream, 16384)

                Enum.reduce(items, completed, fn
                  {:data, _, data}, count ->
                    {:ok, _} = Quic.send_stream(stream, data)
                    count

                  {:fin, _}, count ->
                    {:ok, _} = Quic.send_stream(stream, <<>>, true)
                    count + 1
                end)

              :datagram_readable, completed ->
                {:ok, datagrams} = Quic.read_datagrams(handle)
                Enum.each(datagrams, fn bytes -> {:ok, _} = Quic.send_datagram(handle, bytes) end)
                completed

              _, completed ->
                completed
            end)

          {:error, :closed} ->
            completed
        end
      end)

    if completed < 2 do
      receive do
        _ -> :ok
      after
        5 -> :ok
      end

      loop(endpoint, connections, completed, deadline)
    else
      # Exact second echo completion is the application barrier; no inferred quiet period.
      IO.puts(JSON.encode!(%{event: "server_complete", streams: completed}))
    end
  end
end

Quic.ClientFeatures.EarlyServer.run()

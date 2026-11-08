defmodule Quic.ClientFeatures.ResumptionServer do
  def now, do: System.monotonic_time(:millisecond)

  def run do
    fixture = "apps/elixir_quic/test/fixtures/tls"

    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf.pem")))

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {:ok, endpoint} =
      Quic.listen(
        resumption: [enabled: true, application_profile: "raw-r1-v1"],
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

    connections =
      case Quic.accept(endpoint) do
        {:ok, handle} ->
          :ok = Quic.attach(handle, self())
          {:ok, info} = Quic.info(handle)

          IO.puts(
            JSON.encode!(%{event: "handshake", resumed: info.resumption.resumed, early: false})
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

Quic.ClientFeatures.ResumptionServer.run()

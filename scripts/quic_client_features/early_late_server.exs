Code.require_file("relay.exs", __DIR__)

defmodule Quic.ClientFeatures.EarlyLateServer do
  @moduledoc false
  # R2 late receipt, server role. An unmodified quic-go v0.62.0 client
  # (`peer.go --mode client`) makes one full and two 0-RTT connections through
  # the test-owned relay, which withholds every standalone 0-RTT datagram and
  # delivers it only after the handshake: right after the client's first 1-RTT
  # datagram (delay 0) and one second later (delay 1000, beyond the three-PTO
  # early-key retention). The runtime must stay up, echo each stream exactly
  # once and never surface late duplicates.
  alias Quic.ClientFeatures.Relay

  @delays [0, 1000]
  def delays, do: if(System.get_env("LATE_DELAYS") == "none", do: [], else: @delays)

  def now, do: System.monotonic_time(:millisecond)
  def emit(map), do: IO.puts(JSON.encode!(map))

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
        tls: [cert: [cert], key: {type, key}, alpn: ["ex-quic-r1"]],
        closing_timeout: 10,
        draining_timeout: 10
      )

    io = :sys.get_state(endpoint).socket
    native = :sys.get_state(io).socket
    io_monitor = Process.monitor(io)
    native_monitor = :erlang.monitor(:port, native)
    relay = Relay.start(elem(Quic.local(endpoint), 1))
    :ok = Relay.late_zero_rtt(relay, delays())
    emit(%{event: "listening", port: relay.port, server_port: elem(Quic.local(endpoint), 1)})

    try do
      loop(
        endpoint,
        relay,
        %{connections: [], completed: 0, observed: %{}, deadlines: %{}},
        now() + 40_000
      )
    after
      stats = Relay.stop(relay)
      emit(%{event: "relay", stats: stats})
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

      emit(%{event: "server_cleanup", io_down: true, native_port_down: true})
    end
  end

  # After an episode was released, record whether that connection is still
  # established and whether its early read keys were retired. The keys retire
  # three PTO after the first 1-RTT packet (a runtime deadline observed from
  # connection state), which can exceed any fixed wait on a loaded host, so the
  # record waits until at least 200 ms after the release and until the keys are
  # gone or the observed deadline is two seconds past (bounded, fail-closed:
  # keys still present are recorded and rejected by the gate).
  def observe(acc, relay) do
    episodes = Relay.stats(relay).late

    episodes
    |> Enum.with_index(1)
    |> Enum.reduce(acc, fn {episode, index}, acc ->
      with false <- Map.has_key?(acc.observed, index),
           %Quic.Runtime.ConnectionHandle{id: pid} <- Enum.at(acc.connections, index),
           deadline when is_integer(deadline) <- Map.get(acc.deadlines, index),
           now = System.monotonic_time(:microsecond),
           true <- now >= episode.released_us + 200_000,
           {phase, data} <- connection_state(pid),
           early_keys = Map.has_key?(data.scheduler.keys, :early_data),
           true <- not early_keys or now >= deadline + 2_000_000 do
        record = %{
          event: "late_episode",
          connection: index,
          held: episode.held,
          delay_ms: episode.delay_ms,
          phase: phase,
          early_data: data.scheduler.early_status,
          early_keys_after: early_keys,
          key_deadline_seen: true,
          key_deadline_us: deadline,
          released_us: episode.released_us,
          observed_us: now,
          arrived_before_key_retirement: episode.released_us < deadline
        }

        emit(record)
        put_in(acc, [:observed, index], record)
      else
        _ -> acc
      end
    end)
  end

  # Remember each connection's early-key retirement deadline while it is set.
  def deadlines(acc) do
    acc.connections
    |> Enum.with_index()
    |> Enum.reduce(acc, fn {%Quic.Runtime.ConnectionHandle{id: pid}, index}, acc ->
      case early_key_deadline(pid) do
        deadline when is_integer(deadline) -> put_in(acc, [:deadlines, index], deadline)
        _ -> acc
      end
    end)
  end

  def connection_state(pid) do
    :sys.get_state(pid)
  catch
    :exit, _ -> :gone
  end

  def early_key_deadline(pid) do
    {_, data} = :sys.get_state(pid)
    data.scheduler.early_key_deadline
  catch
    :exit, _ -> nil
  end

  def loop(endpoint, relay, acc, deadline) do
    if now() >= deadline, do: raise("late receipt server deadline")

    acc =
      case Quic.accept(endpoint) do
        {:ok, handle} ->
          :ok = Quic.attach(handle, self())
          {:ok, info} = Quic.info(handle)

          emit(%{
            event: "handshake",
            index: length(acc.connections),
            resumed: info.resumption.resumed,
            early: info.resumption.early_data == :accepted
          })

          %{acc | connections: acc.connections ++ [handle]}

        {:error, :would_block} ->
          acc
      end

    acc = acc.connections |> Enum.reduce(acc, &serve/2) |> deadlines() |> observe(relay)

    if acc.completed < 3 or map_size(acc.observed) < length(delays()) do
      receive do
        _ -> :ok
      after
        5 -> :ok
      end

      loop(endpoint, relay, acc, deadline)
    else
      emit(%{event: "server_complete", streams: acc.completed})
    end
  end

  def serve(handle, acc) do
    case Quic.events(handle) do
      {:ok, events} ->
        Enum.reduce(events, acc, fn
          {:readable, stream}, acc ->
            # A readable event is an edge: drain the stream completely.
            stream
            |> drain([])
            |> Enum.reduce(acc, fn
              {:data, _, data}, acc ->
                {:ok, _} = Quic.send_stream(stream, data)
                acc

              {:fin, _}, acc ->
                {:ok, _} = Quic.send_stream(stream, <<>>, true)
                %{acc | completed: acc.completed + 1}
            end)

          _, acc ->
            acc
        end)

      # A client closes right after its echo; a pull racing that termination
      # returns closed or unknown, and the connection has nothing left to serve.
      {:error, :closed} ->
        acc

      {:unknown, _} ->
        acc
    end
  end

  def drain(stream, acc) do
    case Quic.read(stream, 16_384) do
      {:ok, []} -> acc
      {:ok, items} -> drain(stream, acc ++ items)
      {:error, :closed} -> acc
      {:unknown, _} -> acc
    end
  end
end

Quic.ClientFeatures.EarlyLateServer.run()

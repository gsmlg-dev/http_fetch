# Same loopback workload can run against the baseline and final checkout.
defmodule Abyss.SteadyLegacy do
  use Abyss.Handler

  def handle_data({ip, port, payload}, state) do
    :ok = Abyss.Transport.UDP.send(state.socket, ip, port, payload)
    {:close, state}
  end
end

defmodule Abyss.SteadyDatagram do
  @behaviour Abyss.DatagramHandler
  def init(_options, _context), do: {:ok, nil}
  def handle_datagram(datagram, state), do: {:ok, state, [{:reply, datagram.payload}]}
end

defmodule Abyss.Steady do
  def run(mode) do
    options = [
      port: 0,
      num_listeners: 1,
      num_connections: 32,
      transport_options: [ip: {127, 0, 0, 1}],
      connection_telemetry_sample_rate: 0
    ]

    options =
      case mode do
        "legacy" ->
          Keyword.put(options, :handler_module, Abyss.SteadyLegacy)

        policy ->
          Keyword.merge(options,
            datagram_handler: Abyss.SteadyDatagram,
            execution:
              Map.fetch!(
                %{"per_datagram" => :per_datagram, "endpoint" => :endpoint, "keyed" => :keyed},
                policy
              ),
            route_key: if(policy == "keyed", do: fn _ -> :one end, else: nil)
          )
      end

    baseline = :erlang.system_info(:process_count)
    {:ok, server} = Abyss.start_link(options)
    [listener] = server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()
    {_, port} = Abyss.Listener.listener_info(listener)
    {:ok, peer} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    payload = :binary.copy(<<42>>, 64)

    try do
      for _ <- 1..500, do: exchange(peer, port, payload)
      begin = System.monotonic_time(:microsecond)
      samples = for _ <- 1..3000, do: exchange(peer, port, payload)
      elapsed = System.monotonic_time(:microsecond) - begin
      ordered = Enum.sort(samples)
      {:message_queue_len, mailbox} = Process.info(listener, :message_queue_len)

      IO.inspect(
        %{
          mode: mode,
          count: 3000,
          payload_bytes: 64,
          offered: :sequential_request_response,
          warmup: 500,
          throughput_per_second: 3_000_000_000 / elapsed,
          latency_median_us: Enum.at(ordered, 1499),
          latency_p95_us: Enum.at(ordered, 2849),
          latency_p99_us: Enum.at(ordered, 2969),
          elapsed_us: elapsed,
          processes_before: baseline,
          processes_after_traffic: :erlang.system_info(:process_count),
          owner_mailbox_end: mailbox,
          kernel_drops: :unmeasured
        },
        label: "STEADY_PASS"
      )
    after
      :gen_udp.close(peer)
      Abyss.stop(server, 1000)
    end
  end

  defp exchange(peer, port, payload) do
    begin = System.monotonic_time(:microsecond)
    :ok = :gen_udp.send(peer, {127, 0, 0, 1}, port, payload)
    {:ok, {{127, 0, 0, 1}, ^port, ^payload}} = :gen_udp.recv(peer, 0, 2000)
    System.monotonic_time(:microsecond) - begin
  end
end

Abyss.Steady.run(System.get_env("ABYSS_STEADY_MODE", "legacy"))

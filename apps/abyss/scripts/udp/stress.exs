# Run in the fixture namespace or on loopback; never sends on an ambient link.
defmodule Abyss.UDPStressHandler do
  use Abyss.Handler

  def handle_data({_ip, _port, payload}, state) do
    <<id::32, _::binary>> = payload
    send(state.server_config.handler_options[:owner], {:work, self(), id})

    receive do
      :finish -> :ok
    end

    {:close, state}
  end
end

defmodule Abyss.UDPStress do
  def run do
    baseline = :erlang.system_info(:process_count)
    {:ok, sender} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])

    try do
      high =
        Enum.reduce(
          1..20,
          %{processes: baseline, mailbox: 0, retained: 0, active: 0, dropped: 0},
          fn epoch, high ->
            {:ok, server} =
              Abyss.start_link(
                handler_module: Abyss.UDPStressHandler,
                handler_options: [owner: self()],
                port: 0,
                num_connections: 2,
                max_packet_size: 1024,
                shutdown_timeout: 100
              )

            try do
              [listener] =
                server |> Abyss.Server.listener_pool_pid() |> Abyss.ListenerPool.listener_pids()

              {_, port} = Abyss.Listener.listener_info(listener)

              for id <- 1..2,
                  do:
                    :ok =
                      :gen_udp.send(
                        sender,
                        {127, 0, 0, 1},
                        port,
                        <<epoch::16, id::16, 0::size(992 * 8)>>
                      )

              pids =
                for _ <- 1..2 do
                  receive do
                    {:work, pid, _id} -> pid
                  after
                    1000 -> raise "admission readiness failed"
                  end
                end

              for id <- 1..200,
                  do:
                    :ok =
                      :gen_udp.send(
                        sender,
                        {127, 0, 0, 1},
                        port,
                        <<epoch::16, id::16, 0::size(992 * 8)>>
                      )

              :ok = Abyss.suspend(server)
              status = Abyss.Listener.status(listener)
              %{active_handlers: 2, pending_count: 0, pending_bytes: 0} = status
              true = status.starting <= 1
              true = status.retained_high_water <= 1024
              {:message_queue_len, mailbox} = Process.info(listener, :message_queue_len)

              high = %{
                processes: max(high.processes, :erlang.system_info(:process_count)),
                mailbox: max(high.mailbox, mailbox),
                retained: max(high.retained, status.retained_high_water),
                active: max(high.active, status.active_high_water),
                dropped: high.dropped + status.dropped
              }

              for pid <- pids, do: send(pid, :finish)
              :ok = Abyss.stop(server, 100)
              false = Process.alive?(server)
              high
            after
              if Process.alive?(server), do: Abyss.stop(server, 100)
            end
          end
        )

      final = :erlang.system_info(:process_count)
      true = high.processes <= baseline + 20

      IO.puts(
        "STRESS_PASS #{inspect(high)} baseline_processes=#{baseline} final_processes=#{final} epochs=20 payload_bytes=996 offered_per_epoch=202 ceiling=2 pending_count=0 pending_bytes=0 kernel_drops=unmeasured"
      )
    after
      :gen_udp.close(sender)
    end
  end
end

Abyss.UDPStress.run()

# Diagnostic only: bypasses Abyss socket hosting, writer and service supervision.
# From examples/quic_echo:
# ABYSS_PATH=../.. mix run --no-compile --no-deps-check --no-start ../../scripts/phase1/ack_range_repro.exs
# Two unchanged aioquic peers retain their original 25-second assertions.
# Expected on affected packages: :ack_range_limit and nonzero peer exits.

{:ok, _} = Application.ensure_all_started(:elixir_quic)
root = Path.expand("../..", __DIR__)
IO.inspect(Application.spec(:elixir_quic, :vsn), label: "ELIXIR_QUIC_VERSION")

recovery =
  Enum.reduce(0..255, Quic.Recovery.new(), fn number, recovery ->
    {:ok, next} = Quic.Recovery.note_received(recovery, :application, number * 2)
    next
  end)

IO.inspect(
  %{
    retained: length(recovery.spaces.application.ack_ranges),
    next: Quic.Recovery.note_received(recovery, :application, 512)
  },
  label: "SPARSE_RECEIVE_HISTORY"
)

source =
  File.read!(root <> "/examples/quic_echo/lib/handler.ex")
  |> String.replace("AbyssEchoExample.Handler", "DirectEchoDiagnostic")
  |> String.replace("@behaviour Abyss.QUIC.Handler", "")
  |> String.replace("@impl true", "")
  |> String.replace("Abyss.QUIC.", "Quic.")

Code.compile_string(source)

defmodule DirectDiagnostic do
  def accept(endpoint) do
    receive do
      {:quic_accept, ^endpoint} ->
        {:ok, connection} = Quic.accept(endpoint)

        spawn(fn ->
          :ok = Quic.attach(connection, self())
          {:ok, metadata} = Quic.info(connection)
          {:ok, state} = DirectEchoDiagnostic.init(connection, metadata, [])
          loop(connection, state)
        end)

        accept(endpoint)

      :stop ->
        :ok
    end
  end

  def loop(connection, state) do
    receive do
      {:quic_closed, _, reason} -> IO.inspect(reason, label: "DIRECT_CLOSE_REASON")
    after
      10 ->
        result =
          with {:ok, events} <- Quic.events(connection, 32) do
            Enum.reduce_while(events ++ [:tick], {:ok, state}, fn event, {:ok, app} ->
              case DirectEchoDiagnostic.handle_event(event, app) do
                {:ok, next} -> {:cont, {:ok, next}}
                other -> {:halt, other}
              end
            end)
          end

        case result do
          {:ok, next} ->
            loop(connection, next)

          other ->
            failure =
              case other do
                {:stop, reason, _} -> reason
                result -> result
              end

            IO.inspect(failure, label: "DIRECT_LOOP_FAILURE")

            receive do
              {:quic_closed, _, reason} -> IO.inspect(reason, label: "DIRECT_CLOSE_REASON")
            after
              1000 -> IO.puts("DIRECT_CLOSE_NOTIFICATION_ABSENT")
            end
        end
    end
  end
end

fixtures = root <> "/test/fixtures/quic/server_flight"

[{:Certificate, certificate, :not_encrypted}] =
  :public_key.pem_decode(File.read!(fixtures <> "/leaf.pem"))

[{type, key, :not_encrypted}] = :public_key.pem_decode(File.read!(fixtures <> "/leaf-key.pem"))

acceptor =
  spawn(fn ->
    receive do
      {:endpoint, endpoint} -> DirectDiagnostic.accept(endpoint)
    end
  end)

{:ok, endpoint} =
  Quic.listen(
    ip: {127, 0, 0, 1},
    port: 0,
    tls: [cert: [certificate], key: {type, key}, alpn: ["abyss-echo-v1"]],
    acceptor: acceptor
  )

send(acceptor, {:endpoint, endpoint})
{_, port} = Quic.local(endpoint)

tasks =
  for _ <- 1..2 do
    Task.async(fn ->
      {output, status} =
        System.cmd(
          "uv",
          [
            "run",
            "--offline",
            "--python",
            "3.12",
            "--with",
            "aioquic==1.2.0",
            "python",
            root <> "/scripts/phase1/peer.py",
            "--port",
            to_string(port),
            "--ca",
            fixtures <> "/root.pem",
            "--alpn",
            "abyss-echo-v1",
            "--mode",
            "echo"
          ],
          stderr_to_stdout: true
        )

      IO.write(output)
      status
    end)
  end

results = Enum.map(tasks, &Task.await(&1, 60_000))
IO.inspect(results, label: "DIRECT_TWO_ECHO_RESULT")
IO.inspect(Quic.Endpoint.stats(endpoint), label: "DIRECT_ENDPOINT_FINAL_STATS")
GenServer.stop(endpoint)
send(acceptor, :stop)
System.halt(if Enum.all?(results, &(&1 == 0)), do: 0, else: 1)

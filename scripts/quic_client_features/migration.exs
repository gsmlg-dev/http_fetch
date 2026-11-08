defmodule Quic.ClientFeatures.Migration do
  @fixture "apps/elixir_quic/test/fixtures/tls"
  def root do
    [{:Certificate, cert, :not_encrypted}] =
      @fixture |> Path.join("root.pem") |> File.read!() |> :public_key.pem_decode()

    cert
  end

  def now, do: System.monotonic_time(:millisecond)

  def wait(check, deadline) do
    case check.() do
      false ->
        if now() >= deadline, do: raise("deadline exceeded")

        receive do
          {:quic_closed, _, reason} -> raise("connection closed: #{inspect(reason)}")
        after
          5 -> wait(check, deadline)
        end

      value ->
        value
    end
  end

  def run(port) do
    {:ok, cleanup, lease} = Quic.Cleanup.new()

    {:ok, endpoint} =
      Quic.client(
        cleanup: lease,
        datagram: [max_frame_size: 1200],
        tls: [
          reference_identity: {:dns_id, "example.test"},
          cacerts: [root()],
          alpn: ["ex-quic-m2"]
        ]
      )

    try do
      {:ok, connection} = Quic.connect(endpoint, {{127, 0, 0, 1}, port})
      :ok = Quic.attach(connection, self())

      wait(
        fn ->
          case Quic.info(connection) do
            {:ok, %{quic_confirmed: true}} -> true
            _ -> false
          end
        end,
        now() + 8000
      )

      {:ok, stream} = Quic.open_stream(connection, :bidi)

      Enum.reduce(
        [{:initial, nil}, {:port, {127, 0, 0, 1}}, {:ip, {127, 0, 0, 2}}],
        <<>>,
        fn {phase, ip}, expected ->
          if ip do
            ref = make_ref()
            opts = [local: {ip, 0}, ref: ref, deadline: 4000]
            {:ok, ^ref} = Quic.migrate(connection, opts)
            {:ok, ^ref} = Quic.migrate(connection, opts)

            wait(
              fn ->
                case Quic.operation_status(connection, ref) do
                  %{outcome: {:ok, _}} ->
                    true

                  %{outcome: {:error, reason}} ->
                    raise(
                      "migration failed: #{inspect(reason)}, info: #{inspect(Quic.info(connection))}"
                    )

                  _ ->
                    false
                end
              end,
              now() + 5000
            )

            wait(
              fn ->
                {:ok, info} = Quic.info(connection)
                map_size(info.migration.paths) == 1
              end,
              now() + 6000
            )
          end

          payload = "migration/#{phase}/" <> :binary.copy(<<0, 1, 255, 128>>, 800)
          {:ok, _} = Quic.send_stream(stream, payload, phase == :ip)

          echoed =
            wait(
              fn ->
                {:ok, events} = Quic.read(stream, 16_384)
                previous = Process.get(:received, <<>>)

                bytes =
                  Enum.reduce(events, previous, fn
                    {:data, _, bytes}, acc ->
                      acc <> bytes

                    {:fin, _}, acc ->
                      Process.put(:fin, true)
                      acc
                  end)

                Process.put(:received, bytes)
                if bytes == expected <> payload, do: bytes, else: false
              end,
              now() + 5000
            )

          marker = "datagram/#{phase}"
          {:ok, _} = Quic.send_datagram(connection, marker)

          wait(
            fn ->
              {:ok, datagrams} = Quic.read_datagrams(connection)
              marker in datagrams
            end,
            now() + 2000
          )

          {:ok, info} = Quic.info(connection)

          IO.puts(
            JSON.encode!(%{
              event: "phase",
              phase: phase,
              local: inspect(info.local),
              paths: map_size(info.migration.paths),
              bytes: byte_size(echoed),
              sha256: Base.encode16(:crypto.hash(:sha256, echoed), case: :lower),
              fin: Process.get(:fin, false)
            })
          )

          echoed
        end
      )

      true = Process.get(:fin)
    after
      case Quic.Cleanup.retire(lease, {:abs_ms, now() + 5000}) do
        {:ok, receipt} ->
          IO.puts(JSON.encode!(%{event: "cleanup", receipt: Map.drop(receipt, [:generation])}))

        outcome ->
          raise("cleanup unconfirmed: #{inspect(outcome)}")
      end

      {:ok, _} = Quic.Cleanup.status(cleanup)
    end
  end
end

[port] = System.argv()
Quic.ClientFeatures.Migration.run(String.to_integer(port))

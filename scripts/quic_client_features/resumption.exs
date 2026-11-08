defmodule Quic.ClientFeatures.Resumption do
  def now, do: System.monotonic_time(:millisecond)

  def wait(fun, deadline) do
    case fun.() do
      value when value in [false, nil] ->
        if now() >= deadline, do: raise("resumption gate deadline")

        receive do
          {:quic_closed, _, {:application, 0, _}} -> wait(fun, deadline)
          {:quic_closed, _, reason} when reason in [:closed, :peer_closed] -> wait(fun, deadline)
          {:quic_closed, _, reason} -> raise("connection closed: #{inspect(reason)}")
        after
          5 -> wait(fun, deadline)
        end

      result ->
        result
    end
  end

  def run(port) do
    [{:Certificate, cert, :not_encrypted}] =
      :public_key.pem_decode(File.read!("apps/elixir_quic/test/fixtures/tls/root.pem"))

    {:ok, _handle, lease} = Quic.Cleanup.new()

    {:ok, endpoint} =
      Quic.client(
        cleanup: lease,
        resumption: [enabled: true, application_profile: "raw-r1-v1"],
        closing_timeout: 10,
        draining_timeout: 10,
        tls: [
          reference_identity: {:dns_id, "example.test"},
          cacerts: [cert],
          alpn: ["ex-quic-r1"]
        ]
      )

    try do
      for index <- 0..1 do
        {:ok, connection} = Quic.connect(endpoint, {{127, 0, 0, 1}, port})
        :ok = Quic.attach(connection, self())
        wait(fn -> Quic.ready(connection) == :ready end, now() + 8000)
        {:ok, info} = Quic.info(connection)
        true = info.resumption.resumed == (index == 1)
        :disabled = info.resumption.early_data
        {:ok, stream} = Quic.open_stream(connection, :bidi)
        payload = "resumption/#{index}/" <> :binary.list_to_bin(Enum.to_list(0..255))
        {:ok, _} = Quic.send_stream(stream, payload, true)
        Process.put(:bytes, <<>>)
        Process.put(:fin, false)

        wait(
          fn ->
            {:ok, items} = Quic.read(stream, 16_384)

            Enum.each(items, fn
              {:data, _, bytes} -> Process.put(:bytes, Process.get(:bytes) <> bytes)
              {:fin, _} -> Process.put(:fin, true)
            end)

            Process.get(:fin)
          end,
          now() + 5000
        )

        ^payload = Process.get(:bytes)
        wait(fn -> Quic.Endpoint.stats(endpoint).resumption.tickets > 0 end, now() + 2000)

        IO.puts(
          JSON.encode!(%{
            event: "handshake",
            index: index,
            resumed: info.resumption.resumed,
            early: false,
            bytes: byte_size(payload),
            fin: true
          })
        )

        :ok = Quic.close(connection)
        wait(fn -> Quic.Endpoint.connections(endpoint) == [] end, now() + 2000)
      end
    after
      {:ok, receipt} = Quic.Cleanup.retire(lease, {:abs_ms, now() + 5000})
      IO.puts(JSON.encode!(%{event: "cleanup", receipt: Map.drop(receipt, [:generation])}))
    end
  end
end

[port] = System.argv()
Quic.ClientFeatures.Resumption.run(String.to_integer(port))

defmodule Quic.ClientFeatures.Reset do
  def now, do: System.monotonic_time(:millisecond)

  def wait(fun, deadline) do
    case fun.() do
      result when result in [false, nil] ->
        if now() >= deadline, do: raise("reset gate deadline")

        receive do
          {:quic_closed, _, reason} -> raise("connection closed: #{inspect(reason)}")
        after
          5 -> wait(fun, deadline)
        end

      result ->
        result
    end
  end

  def run(port) do
    fixture = "apps/elixir_quic/test/fixtures/tls/root.pem"
    [{:Certificate, cert, :not_encrypted}] = :public_key.pem_decode(File.read!(fixture))
    {:ok, handle, lease} = Quic.Cleanup.new()

    {:ok, endpoint} =
      Quic.client(
        cleanup: lease,
        reliable_reset: true,
        tls: [
          reference_identity: {:dns_id, "example.test"},
          cacerts: [cert],
          alpn: ["ex-quic-m2"]
        ]
      )

    try do
      {:ok, connection} = Quic.connect(endpoint, {{127, 0, 0, 1}, port})
      :ok = Quic.attach(connection, self())

      wait(
        fn ->
          {:ok, info} = Quic.info(connection)
          info.quic_confirmed
        end,
        now() + 8000
      )

      {:ok, %{reliable_reset: %{negotiated: true, draft: 11}}} = Quic.info(connection)
      {:ok, stream} = Quic.open_stream(connection, :bidi)
      {:ok, _} = Quic.send_stream(stream, "client-header" <> :binary.copy("tail", 100), false)
      ref = make_ref()
      {:ok, ^ref} = Quic.reset_stream_at(stream, 42, 13, ref: ref)
      {:ok, ^ref} = Quic.reset_stream_at(stream, 42, 13, ref: ref)

      peer =
        wait(
          fn ->
            {:ok, events} = Quic.events(connection)

            Enum.find_value(events, fn
              {:stream_open, peer, :bidi} when peer.id == 1 -> peer
              _ -> false
            end)
          end,
          now() + 5000
        )

      wait(
        fn ->
          {:ok, events} = Quic.read(peer, 16_384)

          Enum.each(events, fn
            {:data, 1, bytes} ->
              Process.put(:bytes, Process.get(:bytes, <<>>) <> bytes)

            {:reset, 1, 43, final} when final in 13..24 ->
              Process.put(:reset, true)
              Process.put(:final, final)

            event ->
              raise("unexpected reset gate event: #{inspect(event)}")
          end)

          Process.get(:reset, false)
        end,
        now() + 5000
      )

      bytes = Process.get(:bytes)
      true = String.starts_with?(bytes, "server-header")
      true = byte_size(bytes) in 13..24
      {:ok, []} = Quic.read(peer, 16_384)

      IO.puts(
        JSON.encode!(%{
          event: "reliable_reset",
          passed: true,
          peer: "quic-go-v0.62.0",
          received_bytes: byte_size(bytes),
          prefix: "server-header",
          code: 43,
          final_size: Process.get(:final),
          duplicate_ref: true
        })
      )
    after
      {:ok, receipt} = Quic.Cleanup.retire(lease, {:abs_ms, now() + 5000})
      IO.puts(JSON.encode!(%{event: "cleanup", receipt: Map.drop(receipt, [:generation])}))
      {:ok, _} = Quic.Cleanup.status(handle)
    end
  end
end

[port] = System.argv()
Quic.ClientFeatures.Reset.run(String.to_integer(port))

defmodule HTTP3MigrationGate do
  @moduledoc false
  # Elixir driver for scripts/http3_migration/gate.py. Prints one JSON line per
  # client-side fact; the launcher correlates them with the quic-go peer's log.
  alias HTTP.WebSocket, as: WS
  alias HTTP.WebSocket.Event.{Open, Message, Close}

  def run do
    {:ok, _} = Application.ensure_all_started(:http_web_socket)
    port = System.fetch_env!("HTTP3_PEER_PORT") |> String.to_integer()
    url = "wss://127.0.0.1:#{port}/echo"

    options = [
      http_version: :http3,
      opening_timeout: 5_000,
      close_timeout: 3_000,
      write_timeout: 5_000,
      ssl: [
        cacertfile: System.fetch_env!("HTTP3_PEER_CA"),
        reference_identity: {:dns_id, "example.test"}
      ]
    ]

    socket = open(url, Keyword.put(options, :http3_reuse, false))
    exchange(socket, "initial", nil)

    {:ok, %{local: {{127, 0, 0, 1}, _} = port_local}} =
      WS.migrate(socket, local: {{127, 0, 0, 1}, 0}, timeout: 5_000)

    exchange(socket, "port", port_local)

    if System.get_env("HTTP3_MIGRATION_IP") == "1" do
      {:ok, %{local: {{127, 0, 0, 2}, _} = ip_local}} =
        WS.migrate(socket, local: {{127, 0, 0, 2}, 0}, timeout: 5_000)

      exchange(socket, "ip", ip_local)
    end

    close(socket, "migrated-done")
    emit(%{event: "positive_closed"})

    pooled = open(url, options)

    {:error, :not_exclusive_owner} =
      WS.migrate(pooled, local: {{127, 0, 0, 1}, 0}, timeout: 1_000)

    emit(%{event: "pooled_refusal", reason: "not_exclusive_owner"})
    exchange(pooled, "pooled", nil)
    close(pooled, "pooled-done")
    emit(%{event: "done"})
  end

  # One exact text and one large binary message in each direction per phase.
  # The binary payload spans many QUIC packets so the peer's per-source byte
  # counters can attribute it to a single path.
  defp exchange(socket, phase, local) do
    text = "h3-migration-#{phase}"
    seed = :erlang.phash2(phase)
    binary = :binary.copy(<<seed::32, 0, 1, 255, 128>>, 12_288)
    :ok = WS.send(socket, text)
    %Message{data: ^text} = event(socket)
    :ok = WS.send(socket, WS.array_buffer(binary))
    %Message{data: %HTTP.Blob{} = blob} = event(socket)
    true = HTTP.Blob.to_binary(blob) == binary

    emit(%{
      event: "phase",
      phase: phase,
      local: format(local),
      messages: [describe(text), describe(binary)]
    })
  end

  defp describe(data),
    do: %{
      bytes: byte_size(data),
      sha256: Base.encode16(:crypto.hash(:sha256, data), case: :lower)
    }

  defp format(nil), do: nil
  defp format({ip, port}), do: "#{:inet.ntoa(ip)}:#{port}"

  defp open(url, options) do
    %WS{} = socket = WS.new(url, [], options)
    %Open{} = event(socket)
    true = WS.http_version(socket) == :http3
    socket
  end

  defp close(socket, reason) do
    :ok = WS.close(socket, 1000, reason)
    %Close{code: 1000, reason: ^reason, was_clean: true} = event(socket)
    :ok = HTTP.ClientCompletion.await(WS.completion(socket), 6_000)
  end

  defp emit(map), do: IO.puts(JSON.encode!(map))

  defp event(socket) do
    receive do
      {WS, ^socket, event} ->
        event

      {WS, ^socket, event, ref} ->
        WS.acknowledge(socket, ref)
        event
    after
      8_000 -> raise "event timeout: #{inspect(WS.status(socket))}"
    end
  end
end

HTTP3MigrationGate.run()

defmodule HTTP3SessionGate do
  alias QuicHttp3.Session

  def run do
    port = System.fetch_env!("HTTP3_PEER_PORT") |> String.to_integer()
    {:ok, session} = Session.new()

    {:ok, session} =
      Session.connect(session, {127, 0, 0, 1}, port,
        tls: [
          cacertfile: "apps/elixir_quic/test/fixtures/tls/root.pem",
          reference_identity: {:dns_id, "example.test"}
        ]
      )

    try do
      handle = session.connection.handle

      receive do
        {:quic_ready, ^handle, %{peer_authenticated: true, alpn: "h3"}} -> :ok
        {:quic_closed, ^handle, reason} -> raise "peer closed: #{inspect(reason)}"
      after
        5_000 -> raise "authenticated HTTP/3 readiness timeout"
      end

      {:ok, session} = Session.open(session)
      body = :binary.copy(<<0, 1, 13, 10, 255>>, 12_345)

      fields = [
        {":method", "POST"},
        {":scheme", "https"},
        {":authority", "example.test"},
        {":path", "/"},
        {"content-length", Integer.to_string(byte_size(body))}
      ]

      {:ok, session, ref} = Session.request(session, fields, body, [])
      {session, events} = poll(session, ref, now() + 5_000, [])
      chunks = for {:data, ^ref, bytes} <- events, do: bytes
      if IO.iodata_to_binary(chunks) != body, do: raise("HTTP/3 body integrity failure")
      if map_size(session.requests) != 0, do: raise("terminal request retained")

      if not Enum.any?(events, fn
           {:headers, ^ref, fields} -> {":status", "200"} in fields
           _ -> false
         end),
         do: raise("missing final response headers")

      IO.puts("HTTP/3 companion independent aioquic DATA/integrity/cleanup result: PASS")
    after
      QuicHttp3.Transport.Quic.cleanup(session.connection)
    end
  end

  defp poll(session, ref, deadline, events) do
    if now() >= deadline, do: raise("HTTP/3 response deadline expired")
    {:ok, next, batch} = Session.poll(session, 32)
    events = events ++ batch

    if {:done, ref} in batch do
      {next, events}
    else
      receive do
        {:quic_closed, _, reason} -> raise "HTTP/3 peer closed: #{inspect(reason)}"
      after
        5 -> :ok
      end

      poll(next, ref, deadline, events)
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end

HTTP3SessionGate.run()

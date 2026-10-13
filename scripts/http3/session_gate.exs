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
      tiny? = System.get_env("HTTP3_TINY_WINDOW") == "1"

      body =
        if tiny?,
          do: :binary.copy(<<0, 1, 13, 10, 255, 17, 42, 128>>, 131_072),
          else: :binary.copy(<<0, 1, 13, 10, 255>>, 12_345)

      fields = [
        {":method", "POST"},
        {":scheme", "https"},
        {":authority", "example.test"},
        {":path", if(tiny?, do: "/tiny-upload", else: "/")},
        {"content-length", Integer.to_string(byte_size(body))}
      ]

      {session, ref} =
        if tiny? do
          {:ok, session, ref} = Session.request(session, fields, :stream, [])

          session =
            for <<chunk::binary-size(16_384) <- body>>, reduce: session do
              session ->
                admit(Session.send_data(session, ref, chunk, false, []), nil)
            end

          {admit(Session.send_data(session, ref, <<>>, true, []), nil), ref}
        else
          {:ok, session, ref} = Session.request(session, fields, body, [])
          {session, ref}
        end

      {session, events} = poll(session, ref, now() + 5_000, [])
      chunks = for {:data, ^ref, bytes} <- events, do: bytes

      expected =
        if tiny?, do: Base.encode16(:crypto.hash(:sha256, body), case: :lower), else: body

      if IO.iodata_to_binary(chunks) != expected, do: raise("HTTP/3 body integrity failure")
      if map_size(session.requests) != 0, do: raise("terminal request retained")

      if not Enum.any?(events, fn
           {:headers, ^ref, fields} -> {":status", "200"} in fields
           _ -> false
         end),
         do: raise("missing final response headers")

      if tiny? do
        {:headers, ^ref, headers} = Enum.find(events, &match?({:headers, ^ref, _}, &1))

        if {"x-request-headers", "1"} not in headers or {"x-request-fins", "1"} not in headers,
          do: raise("HTTP/3 upload request or FIN replay")

        IO.puts(
          "HTTP/3 1MiB upload / 16KiB chunks / 16KiB peer window / original deadlines / exact digest / one request FIN: PASS"
        )
      end

      IO.puts("HTTP/3 companion independent aioquic DATA/integrity/cleanup result: PASS")
    after
      QuicHttp3.Transport.Quic.cleanup(session.connection)
    end
  end

  defp admit({:ok, session}, _deadline), do: session

  defp admit({:blocked, session, _reason}, deadline) do
    original = deadline || session.work.deadline

    if session.work.deadline != original or session.pending.deadline != original,
      do: raise("HTTP/3 admission deadline changed")

    receive do
      {:quic_closed, _, reason} -> raise "HTTP/3 peer closed: #{inspect(reason)}"
    after
      1 -> :ok
    end

    admit(Session.resume(session), original)
  end

  defp admit({:unknown, session, _ref}, deadline),
    do: admit(Session.resume(session), deadline || session.work.deadline)

  defp admit(failure, _deadline),
    do: raise("HTTP/3 upload admission failed: #{inspect(failure, limit: 5)}")

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

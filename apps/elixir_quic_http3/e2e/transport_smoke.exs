defmodule QuicHttp3.E2E.TransportSmoke do
  @moduledoc false

  alias QuicHttp3.{Frame, Qpack}
  alias QuicHttp3.Transport.Quic, as: Adapter

  @timeout_ms 3_000
  @read_limit 16_384

  def run do
    {server_tls, client_tls} = credentials()

    {:ok, server} =
      Quic.listen(tls: server_tls, datagram: [max_frame_size: 1200], acceptor: self())

    try do
      {:ok, client} =
        Adapter.connect(elem(Quic.local(server), 0), elem(Quic.local(server), 1),
          tls: client_tls,
          datagram: [max_frame_size: 1200]
        )

      try do
        :ok = Quic.attach(client.handle, self())
        await(fn -> Adapter.ready(client, 0) end, :ready)
        wait_accept(server)
        {:ok, accepted} = Quic.accept(server)
        :ok = Quic.attach(accepted, self())
        await(fn -> Quic.ready(accepted) end, :ready)

        {:ok, %{alpn: "h3", peer_authenticated: true}} = Quic.info(client.handle)
        {:ok, %{alpn: "h3"}} = Quic.info(accepted)

        {:ok, stream} = Adapter.open_stream(client, :bidi, [])

        {:ok, request_headers} =
          Qpack.encode_header_block([
            {":method", "GET"},
            {":scheme", "https"},
            {":authority", "example.test"},
            {":path", "/smoke"}
          ])

        request = Frame.encode!(:headers, request_headers) <> Frame.encode!(:data, "ping")
        {:ok, _ref} = Adapter.send_stream(stream, request, true, [])

        incoming = await_stream(accepted)
        assert_payload(read_all(fn -> Quic.read(incoming, @read_limit) end), request, :request)

        assert_frames(
          request,
          [
            {":method", "GET"},
            {":scheme", "https"},
            {":authority", "example.test"},
            {":path", "/smoke"}
          ],
          "ping"
        )

        {:ok, response_headers} = Qpack.encode_header_block([{":status", "200"}])
        response = Frame.encode!(:headers, response_headers) <> Frame.encode!(:data, "pong")
        {:ok, _ref} = Quic.send_stream(incoming, response, true)

        assert_payload(
          read_all(fn -> Adapter.read(stream, @read_limit, []) end),
          response,
          :response
        )

        assert_frames(response, [{":status", "200"}], "pong")

        {:ok, _ref} = Adapter.send_datagram(client, "h3-datagram", [])
        await(fn -> Quic.read_datagrams(accepted, 1) end, {:ok, ["h3-datagram"]})

        IO.puts(
          "HTTP/3 transport smoke passed: verified h3 TLS, request, response, FIN and DATAGRAM over local UDP"
        )
      after
        if Process.alive?(client.endpoint), do: Adapter.stop_endpoint(client.endpoint)
      end
    after
      if Process.alive?(server), do: GenServer.stop(server, :normal, @timeout_ms)
    end
  end

  defp credentials do
    fixture = Path.expand("../../elixir_quic/test/fixtures/tls", __DIR__)

    cert = fn name ->
      [{:Certificate, der, :not_encrypted}] =
        :public_key.pem_decode(File.read!(Path.join(fixture, name)))

      der
    end

    [{type, key, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(fixture, "leaf-key.pem")))

    {[cert: [cert.("leaf.pem")], key: {type, key}, alpn: ["h3"]],
     [cacerts: [cert.("root.pem")], reference_identity: {:dns_id, "example.test"}, alpn: ["h3"]]}
  end

  defp wait_accept(server) do
    receive do
      {:quic_accept, ^server} -> :ok
    after
      @timeout_ms -> raise "QUIC server did not announce an accepted connection"
    end
  end

  defp await_stream(connection) do
    await(
      fn ->
        case Quic.events(connection, 16) do
          {:ok, events} ->
            Enum.find_value(events, :pending, fn
              {:stream_open, stream, :bidi} -> stream
              _ -> nil
            end)

          other ->
            other
        end
      end,
      fn result -> match?(%Quic.Runtime.StreamHandle{}, result) end
    )
  end

  defp read_all(read), do: read_all(read, <<>>, deadline())

  defp read_all(read, bytes, deadline) do
    case read.() do
      {:ok, items} ->
        {bytes, finished?} =
          Enum.reduce(items, {bytes, false}, fn
            {:data, _offset, data}, {acc, fin} -> {acc <> data, fin}
            {:fin, _offset}, {acc, _fin} -> {acc, true}
          end)

        if byte_size(bytes) > @read_limit, do: raise("stream exceeded smoke read limit")

        if finished? do
          bytes
        else
          pause(deadline)
          read_all(read, bytes, deadline)
        end

      other ->
        raise "stream read failed: #{inspect(other)}"
    end
  end

  defp assert_payload(received, expected, name) do
    if received != expected, do: raise("#{name} stream bytes differ")
  end

  defp assert_frames(bytes, expected_headers, expected_data) do
    {:ok, %{type: 1, payload: header_block}, rest} = Frame.decode(bytes)
    {:ok, ^expected_headers} = Qpack.decode_header_block(header_block)
    {:ok, %{type: 0, payload: ^expected_data}, <<>>} = Frame.decode(rest)
  end

  defp await(fun, expected) when not is_function(expected),
    do: await(fun, &(&1 == expected))

  defp await(fun, match?), do: await(fun, match?, deadline())

  defp await(fun, match?, deadline) do
    result = fun.()

    if match?.(result) do
      result
    else
      if result in [:pending, {:ok, []}],
        do: pause(deadline),
        else: raise("unexpected QUIC result: #{inspect(result)}")

      await(fun, match?, deadline)
    end
  end

  defp deadline, do: System.monotonic_time(:millisecond) + @timeout_ms

  defp pause(deadline) do
    if System.monotonic_time(:millisecond) >= deadline,
      do: raise("QUIC smoke timed out"),
      else: Process.sleep(10)
  end
end

QuicHttp3.E2E.TransportSmoke.run()
